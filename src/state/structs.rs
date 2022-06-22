// structs.rs - structures of main state
//
// simple-irc-server - simple IRC server
// Copyright (C) 2022  Mateusz Szpakowski
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

use flagset::{flags, FlagSet};
use futures::{future::Fuse, future::FutureExt};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::ops::Drop;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot;
use tokio::time;
use tokio_util::codec::Framed;
use tracing::*;

use crate::command::*;
use crate::config::*;
use crate::utils::*;

#[derive(Debug)]
pub(super) struct User {
    pub(super) hostname: String,
    pub(super) sender: UnboundedSender<String>,
    // quit_sender - used by KILL command.
    pub(super) quit_sender: Option<oneshot::Sender<(String, String)>>,
    pub(super) name: String,
    pub(super) realname: String,
    pub(super) source: String, // IRC source for mask matching
    pub(super) modes: UserModes,
    pub(super) away: Option<String>,
    pub(super) channels: HashSet<String>,
    pub(super) invited_to: HashSet<String>, // invited in channels
    pub(super) last_activity: u64,
    pub(super) signon: u64,
    pub(super) history_entry: NickHistoryEntry,
}

impl User {
    pub(super) fn new(
        config: &MainConfig,
        user_state: &ConnUserState,
        sender: UnboundedSender<String>,
        quit_sender: oneshot::Sender<(String, String)>,
    ) -> User {
        let mut user_modes = config.default_user_modes;
        user_modes.registered = user_modes.registered || user_state.registered;
        let now_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        User {
            hostname: user_state.hostname.clone(),
            sender,
            quit_sender: Some(quit_sender),
            name: user_state.name.as_ref().unwrap().clone(),
            realname: user_state.realname.as_ref().unwrap().clone(),
            source: user_state.source.clone(),
            modes: user_modes,
            away: None,
            channels: HashSet::new(),
            invited_to: HashSet::new(),
            last_activity: now_ts,
            signon: now_ts,
            history_entry: NickHistoryEntry {
                username: user_state.name.as_ref().unwrap().clone(),
                hostname: user_state.hostname.clone(),
                realname: user_state.realname.as_ref().unwrap().clone(),
                signon: now_ts,
            },
        }
    }

    // update nick - mainly source
    pub(super) fn update_nick(&mut self, user_state: &ConnUserState) {
        self.source = user_state.source.clone();
    }

    // update nick - mainly source
    #[cfg(feature = "dns_lookup")]
    pub(super) fn update_hostname(&mut self, user_state: &ConnUserState) {
        self.hostname = user_state.hostname.clone();
        self.source = user_state.source.clone();
    }

    pub(super) fn send_message(
        &self,
        msg: &Message<'_>,
        source: &str,
    ) -> Result<(), SendError<String>> {
        self.sender.send(msg.to_string_with_source(source))
    }

    pub(super) fn send_msg_display<T: fmt::Display>(
        &self,
        source: &str,
        t: T,
    ) -> Result<(), SendError<String>> {
        self.sender.send(format!(":{} {}", source, t))
    }
}

#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub(super) struct ChannelUserModes {
    pub(super) founder: bool,
    pub(super) protected: bool,
    pub(super) voice: bool,
    pub(super) operator: bool,
    pub(super) half_oper: bool,
}

impl ChannelUserModes {
    pub(super) fn new_for_created_channel() -> Self {
        ChannelUserModes {
            founder: true,
            protected: false,
            voice: false,
            operator: true,
            half_oper: false,
        }
    }

    pub(super) fn is_protected(&self) -> bool {
        self.founder || self.protected
    }

    pub(super) fn is_operator(&self) -> bool {
        self.founder || self.protected || self.operator
    }
    pub(super) fn is_half_operator(&self) -> bool {
        self.founder || self.protected || self.operator || self.half_oper
    }
    // if only half operator - no protected, no founder and no operator
    pub(super) fn is_only_half_operator(&self) -> bool {
        !self.founder && !self.protected && !self.operator && self.half_oper
    }
    pub(super) fn is_voice(&self) -> bool {
        self.founder || self.protected || self.operator || self.half_oper || self.voice
    }
}

flags! {
    pub(super) enum PrivMsgTargetType: u8 {
        Channel = 0b1,
        ChannelFounder = 0b10,
        ChannelProtected = 0b100,
        ChannelOper = 0b1000,
        ChannelHalfOper = 0b10000,
        ChannelVoice = 0b100000,
        ChannelAll = 0b111111,
        ChannelAllSpecial = 0b111110,
    }
}

impl ChannelUserModes {
    pub(super) fn to_string(self, caps: &CapState) -> String {
        let mut out = String::new();
        if self.founder {
            out.push('~');
        }
        // after put the highest user mode, put other if caps multi-prefix is enabled.
        if (caps.multi_prefix || out.is_empty()) && self.protected {
            out.push('&');
        }
        if (caps.multi_prefix || out.is_empty()) && self.operator {
            out.push('@');
        }
        if (caps.multi_prefix || out.is_empty()) && self.half_oper {
            out.push('%');
        }
        if (caps.multi_prefix || out.is_empty()) && self.voice {
            out.push('+');
        }
        out
    }
}

// get target type for PRIVMSG and channel name
pub(super) fn get_privmsg_target_type(target: &str) -> (FlagSet<PrivMsgTargetType>, &str) {
    use PrivMsgTargetType::*;
    let mut out = Channel.into();
    let mut amp_count = 0;
    let mut last_amp = false;
    let mut out_str = "";
    for (i, c) in target.bytes().enumerate() {
        match c {
            b'~' => out |= Channel | ChannelFounder,
            b'&' => out |= Channel | ChannelProtected,
            b'@' => out |= Channel | ChannelOper,
            b'%' => out |= Channel | ChannelHalfOper,
            b'+' => out |= Channel | ChannelVoice,
            b'#' => {
                // if global channel
                if i + 1 < target.len() {
                    out_str = &target[i..];
                } else {
                    out &= !ChannelAll;
                }
                break;
            }
            _ => {
                if last_amp {
                    // only one ampersand - then not protected
                    if amp_count < 2 {
                        out &= !ChannelProtected;
                    }
                    out_str = &target[i - 1..];
                } else {
                    out &= !ChannelAll;
                }
                break;
            }
        }
        if c == b'&' {
            // if not last character then count ampersand, otherwise is not channel
            if i + 1 < target.len() {
                last_amp = true;
                amp_count += 1;
            } else {
                out &= !ChannelAll;
            }
        } else {
            last_amp = false;
        }
    }
    (out, out_str)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ChannelTopic {
    pub(super) topic: String,
    pub(super) nick: String,
    pub(super) set_time: u64,
}

impl ChannelTopic {
    pub(super) fn new(topic: String) -> Self {
        ChannelTopic {
            topic,
            nick: String::new(),
            set_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    pub(super) fn new_with_nick(topic: String, nick: String) -> Self {
        ChannelTopic {
            topic,
            nick,
            set_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BanInfo {
    pub(super) set_time: u64,
    pub(super) who: String,
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub(super) struct ChannelDefaultModes {
    pub(super) operators: HashSet<String>,
    pub(super) half_operators: HashSet<String>,
    pub(super) voices: HashSet<String>,
    pub(super) founders: HashSet<String>,
    pub(super) protecteds: HashSet<String>,
}

impl ChannelDefaultModes {
    // create new channel default modes from ChannelModes and clean up this ChannelModes.
    pub(super) fn new_from_modes_and_cleanup(modes: &mut ChannelModes) -> Self {
        ChannelDefaultModes {
            operators: modes.operators.take().unwrap_or_default(),
            half_operators: modes.half_operators.take().unwrap_or_default(),
            voices: modes.voices.take().unwrap_or_default(),
            founders: modes.founders.take().unwrap_or_default(),
            protecteds: modes.protecteds.take().unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Channel {
    pub(super) topic: Option<ChannelTopic>,
    pub(super) modes: ChannelModes,
    pub(super) default_modes: ChannelDefaultModes,
    pub(super) ban_info: HashMap<String, BanInfo>,
    pub(super) users: HashMap<String, ChannelUserModes>,
    pub(super) creation_time: u64,
    // if channel is preconfigured - it comes from configuration
    pub(super) preconfigured: bool,
}

impl Channel {
    pub(super) fn new_on_user_join(user_nick: String) -> Channel {
        let mut users = HashMap::new();
        users.insert(
            user_nick.clone(),
            ChannelUserModes::new_for_created_channel(),
        );
        Channel {
            topic: None,
            ban_info: HashMap::new(),
            default_modes: ChannelDefaultModes::default(),
            modes: ChannelModes::new_for_channel(user_nick),
            users,
            creation_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            preconfigured: false,
        }
    }

    pub(super) fn add_user(&mut self, user_nick: &String) {
        let mut chum = ChannelUserModes::default();
        // apply default modes for user in channel
        if self.default_modes.half_operators.contains(user_nick) {
            chum.half_oper = true;
            let mut half_ops = self.modes.half_operators.take().unwrap_or_default();
            half_ops.insert(user_nick.clone());
            self.modes.half_operators = Some(half_ops);
        }
        if self.default_modes.operators.contains(user_nick) {
            chum.operator = true;
            let mut ops = self.modes.operators.take().unwrap_or_default();
            ops.insert(user_nick.clone());
            self.modes.operators = Some(ops);
        }
        if self.default_modes.founders.contains(user_nick) {
            chum.founder = true;
            let mut founders = self.modes.founders.take().unwrap_or_default();
            founders.insert(user_nick.clone());
            self.modes.founders = Some(founders);
        }
        if self.default_modes.voices.contains(user_nick) {
            chum.voice = true;
            let mut voices = self.modes.voices.take().unwrap_or_default();
            voices.insert(user_nick.clone());
            self.modes.voices = Some(voices);
        }
        if self.default_modes.protecteds.contains(user_nick) {
            chum.protected = true;
            let mut protecteds = self.modes.protecteds.take().unwrap_or_default();
            protecteds.insert(user_nick.clone());
            self.modes.protecteds = Some(protecteds);
        }
        self.users.insert(user_nick.clone(), chum);
    }

    pub(super) fn rename_user(&mut self, old_nick: &String, nick: String) {
        let oldchumode = self.users.remove(old_nick).unwrap();
        self.users.insert(nick.clone(), oldchumode);
        self.modes.rename_user(old_nick, nick);
    }

    // remove user from channel - and from lists
    pub(super) fn remove_user(&mut self, nick: &str) {
        self.remove_operator(nick);
        self.remove_half_operator(nick);
        self.remove_founder(nick);
        self.remove_voice(nick);
        self.remove_protected(nick);
        self.users.remove(nick);
    }

    // add/remove user from list
    pub(super) fn add_operator(&mut self, nick: &str) {
        let mut ops = self.modes.operators.take().unwrap_or_default();
        ops.insert(nick.to_string());
        self.modes.operators = Some(ops);
        self.users.get_mut(nick).unwrap().operator = true;
    }
    pub(super) fn remove_operator(&mut self, nick: &str) {
        let mut ops = self.modes.operators.take().unwrap_or_default();
        ops.remove(nick);
        self.modes.operators = Some(ops);
        self.users.get_mut(nick).unwrap().operator = false;
    }
    pub(super) fn add_half_operator(&mut self, nick: &str) {
        let mut half_ops = self.modes.half_operators.take().unwrap_or_default();
        half_ops.insert(nick.to_string());
        self.modes.half_operators = Some(half_ops);
        self.users.get_mut(nick).unwrap().half_oper = true;
    }
    pub(super) fn remove_half_operator(&mut self, nick: &str) {
        let mut half_ops = self.modes.half_operators.take().unwrap_or_default();
        half_ops.remove(nick);
        self.modes.half_operators = Some(half_ops);
        self.users.get_mut(nick).unwrap().half_oper = false;
    }
    pub(super) fn add_voice(&mut self, nick: &str) {
        let mut voices = self.modes.voices.take().unwrap_or_default();
        voices.insert(nick.to_string());
        self.modes.voices = Some(voices);
        self.users.get_mut(nick).unwrap().voice = true;
    }
    pub(super) fn remove_voice(&mut self, nick: &str) {
        let mut voices = self.modes.voices.take().unwrap_or_default();
        voices.remove(nick);
        self.modes.voices = Some(voices);
        self.users.get_mut(nick).unwrap().voice = false;
    }
    pub(super) fn add_founder(&mut self, nick: &str) {
        let mut founders = self.modes.founders.take().unwrap_or_default();
        founders.insert(nick.to_string());
        self.modes.founders = Some(founders);
        self.users.get_mut(nick).unwrap().founder = true;
    }
    pub(super) fn remove_founder(&mut self, nick: &str) {
        let mut founders = self.modes.founders.take().unwrap_or_default();
        founders.remove(nick);
        self.modes.founders = Some(founders);
        self.users.get_mut(nick).unwrap().founder = false;
    }
    pub(super) fn add_protected(&mut self, nick: &str) {
        let mut protecteds = self.modes.protecteds.take().unwrap_or_default();
        protecteds.insert(nick.to_string());
        self.modes.protecteds = Some(protecteds);
        self.users.get_mut(nick).unwrap().protected = true;
    }
    pub(super) fn remove_protected(&mut self, nick: &str) {
        let mut protecteds = self.modes.protecteds.take().unwrap_or_default();
        protecteds.remove(nick);
        self.modes.protecteds = Some(protecteds);
        self.users.get_mut(nick).unwrap().protected = false;
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct NickHistoryEntry {
    pub(super) username: String,
    pub(super) hostname: String,
    pub(super) realname: String,
    pub(super) signon: u64,
}

#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct CapState {
    pub(super) multi_prefix: bool,
}

impl fmt::Display for CapState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.multi_prefix {
            f.write_str("multi-prefix")
        } else {
            Ok(())
        }
    }
}

impl CapState {
    pub(super) fn apply_cap(&mut self, cap: &str) -> bool {
        match cap {
            "multi-prefix" => self.multi_prefix = true,
            _ => return false,
        };
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnUserState {
    pub(super) ip_addr: IpAddr,
    pub(super) hostname: String,
    pub(super) name: Option<String>,
    pub(super) realname: Option<String>,
    pub(super) nick: Option<String>,
    pub(super) source: String, // IRC source for mask matching
    pub(super) password: Option<String>,
    pub(super) authenticated: bool,
    pub(super) registered: bool,
}

impl ConnUserState {
    pub(super) fn new(ip_addr: IpAddr) -> ConnUserState {
        let mut source = "@".to_string();
        source.push_str(&ip_addr.to_string());
        ConnUserState {
            ip_addr,
            hostname: ip_addr.to_string(),
            name: None,
            realname: None,
            nick: None,
            source,
            password: None,
            authenticated: false,
            registered: false,
        }
    }

    pub(super) fn client_name(&self) -> &str {
        if let Some(ref n) = self.nick {
            n
        } else if let Some(ref n) = self.name {
            n
        } else {
            &self.hostname
        }
    }

    pub(super) fn update_source(&mut self) {
        let mut s = String::new();
        // generate source - nick!username@host
        if let Some(ref nick) = self.nick {
            s.push_str(nick);
            s.push('!');
        }
        if let Some(ref name) = self.name {
            s.push('~'); // username is defined same user
            s.push_str(name);
        }
        s.push('@');
        s.push_str(&self.hostname);
        self.source = s;
    }

    #[cfg(feature = "dns_lookup")]
    pub(super) fn set_hostname(&mut self, hostname: String) {
        self.hostname = hostname;
        self.update_source();
    }
    pub(super) fn set_name(&mut self, name: String) {
        self.name = Some(name);
        self.update_source();
    }
    pub(super) fn set_nick(&mut self, nick: String) {
        self.nick = Some(nick);
        self.update_source();
    }
}

#[derive(Debug)]
pub(crate) struct ConnState {
    // use BufferedLineStream to avoid deadlocks when sending is not still finished.
    pub(super) stream: BufferedLineStream,
    pub(super) sender: Option<UnboundedSender<String>>,
    pub(super) receiver: UnboundedReceiver<String>,
    // sender and receiver used for sending ping task for
    pub(super) ping_sender: Option<UnboundedSender<()>>,
    // ping_receiver - process method receives ping and sent ping to client.
    pub(super) ping_receiver: UnboundedReceiver<()>,
    // timeout_sender - sender to send timeout - it will sent by pong_client_timeout
    pub(super) timeout_sender: Arc<UnboundedSender<()>>,
    // timeout_receiver - process method receives that
    pub(super) timeout_receiver: UnboundedReceiver<()>,
    pub(super) pong_notifier: Option<oneshot::Sender<()>>,
    // quit receiver - receive KILL from other user.
    pub(super) quit_receiver: Fuse<oneshot::Receiver<(String, String)>>,
    // quit_sender - quit sender to send KILL - sender will be later taken after
    // correct authentication and it will be stored in User structure.
    pub(super) quit_sender: Option<oneshot::Sender<(String, String)>>,
    // receiver for dns lookup
    pub(super) dns_lookup_receiver: Fuse<oneshot::Receiver<Option<String>>>,
    #[cfg(feature = "dns_lookup")]
    pub(super) dns_lookup_sender: Option<oneshot::Sender<Option<String>>>,

    pub(super) user_state: ConnUserState,

    pub(super) caps_negotation: bool, // if caps negotation process
    pub(super) caps: CapState,
    pub(super) quit: Arc<AtomicI32>,
    pub(super) conns_count: Arc<AtomicUsize>,
}

impl ConnState {
    pub(super) fn new(
        ip_addr: IpAddr,
        stream: Framed<DualTcpStream, IRCLinesCodec>,
        conns_count: Arc<AtomicUsize>,
    ) -> ConnState {
        let (sender, receiver) = unbounded_channel();
        let (ping_sender, ping_receiver) = unbounded_channel();
        let (timeout_sender, timeout_receiver) = unbounded_channel();
        let (quit_sender, quit_receiver) = oneshot::channel();
        #[cfg(feature = "dns_lookup")]
        let (dns_lookup_sender, dns_lookup_receiver) = oneshot::channel();
        #[cfg(not(feature = "dns_lookup"))]
        let (_, dns_lookup_receiver) = oneshot::channel();

        ConnState {
            stream: BufferedLineStream::new(stream),
            sender: Some(sender),
            receiver,
            user_state: ConnUserState::new(ip_addr),
            ping_sender: Some(ping_sender),
            ping_receiver,
            timeout_sender: Arc::new(timeout_sender),
            timeout_receiver,
            pong_notifier: None,
            quit_sender: Some(quit_sender),
            quit_receiver: quit_receiver.fuse(),
            #[cfg(feature = "dns_lookup")]
            dns_lookup_sender: Some(dns_lookup_sender),
            dns_lookup_receiver: dns_lookup_receiver.fuse(),
            caps_negotation: false,
            caps: CapState::default(),
            quit: Arc::new(AtomicI32::new(0)),
            conns_count,
        }
    }

    pub(crate) fn is_quit(&self) -> bool {
        self.quit.load(Ordering::SeqCst) != 0
    }

    pub(super) fn run_ping_waker(&mut self, config: &MainConfig) {
        if self.ping_sender.is_some() {
            tokio::spawn(ping_client_waker(
                Duration::from_secs(config.ping_timeout),
                self.quit.clone(),
                self.ping_sender.take().unwrap(),
            ));
        } else {
            panic!("Ping waker ran!"); // unexpected!
        }
    }

    // run pong timeout process - that send timeout aftet some time.
    pub(super) fn run_pong_timeout(&mut self, config: &MainConfig) {
        let (pong_notifier, pong_receiver) = oneshot::channel();
        self.pong_notifier = Some(pong_notifier);
        tokio::spawn(pong_client_timeout(
            time::timeout(Duration::from_secs(config.pong_timeout), pong_receiver),
            self.quit.clone(),
            self.timeout_sender.clone(),
        ));
    }

    #[cfg(feature = "dns_lookup")]
    pub(super) fn run_dns_lookup(&mut self) {
        super::dns_lookup(
            self.dns_lookup_sender.take().unwrap(),
            self.user_state.ip_addr,
        );
    }

    pub(crate) fn is_secure(&self) -> bool {
        self.stream.get_ref().is_secure()
    }
}

impl Drop for ConnState {
    fn drop(&mut self) {
        self.conns_count.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn ping_client_waker(d: Duration, quit: Arc<AtomicI32>, sender: UnboundedSender<()>) {
    time::sleep(d).await;
    let mut intv = time::interval(d);
    while quit.load(Ordering::SeqCst) == 0 {
        intv.tick().await;
        sender.send(()).unwrap();
    }
}

async fn pong_client_timeout(
    tmo: time::Timeout<oneshot::Receiver<()>>,
    quit: Arc<AtomicI32>,
    sender: Arc<UnboundedSender<()>>,
) {
    if tmo.await.is_err() {
        // do not send if client already quits from IRC server.
        if quit.load(Ordering::SeqCst) == 0 {
            sender.send(()).unwrap();
        }
    }
}

pub(super) struct VolatileState {
    pub(super) users: HashMap<String, User>,
    pub(super) channels: HashMap<String, Channel>,
    pub(super) wallops_users: HashSet<String>,
    pub(super) invisible_users_count: usize,
    pub(super) operators_count: usize,
    pub(super) max_users_count: usize,
    pub(super) nick_histories: HashMap<String, Vec<NickHistoryEntry>>,
    pub(super) quit_sender: Option<oneshot::Sender<String>>,
    pub(super) quit_receiver: Option<Fuse<oneshot::Receiver<String>>>,
}

impl VolatileState {
    pub(super) fn new_from_config(config: &MainConfig) -> VolatileState {
        let mut channels = HashMap::new();
        if let Some(ref cfg_channels) = config.channels {
            // create new channels from configuration
            cfg_channels.iter().for_each(|c| {
                let mut ch_modes = c.modes.clone();
                let def_ch_modes = ChannelDefaultModes::new_from_modes_and_cleanup(&mut ch_modes);

                channels.insert(
                    c.name.clone(),
                    Channel {
                        topic: c.topic.as_ref().map(|x| ChannelTopic::new(x.clone())),
                        ban_info: HashMap::new(),
                        default_modes: def_ch_modes,
                        modes: ch_modes,
                        users: HashMap::new(),
                        creation_time: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        preconfigured: true,
                    },
                );
            });
        }

        let (quit_sender, quit_receiver) = oneshot::channel();
        VolatileState {
            users: HashMap::new(),
            channels,
            wallops_users: HashSet::new(),
            invisible_users_count: 0,
            operators_count: 0,
            max_users_count: 0,
            nick_histories: HashMap::new(),
            quit_sender: Some(quit_sender),
            quit_receiver: Some(quit_receiver.fuse()),
        }
    }

    // add user to volatile state - includes stats likes invisible users count, etc.
    pub(super) fn add_user(&mut self, unick: &str, user: User) {
        if user.modes.invisible {
            self.invisible_users_count += 1;
        }
        if user.modes.wallops {
            self.wallops_users.insert(unick.to_string());
        }
        if user.modes.is_local_oper() {
            self.operators_count += 1;
        }
        self.users.insert(unick.to_string(), user);
        if self.users.len() > self.max_users_count {
            self.max_users_count = self.users.len();
        }
    }

    // remove user from channel and remove channel from user.
    // remove same channel if no more users at channel.
    pub(super) fn remove_user_from_channel<'a>(&mut self, channel: &'a str, nick: &'a str) {
        if let Some(chanobj) = self.channels.get_mut(channel) {
            chanobj.remove_user(nick);
            if chanobj.users.is_empty() && !chanobj.preconfigured {
                info!("Channel {} has been removed", channel);
                self.channels.remove(channel);
            }
        }
        if let Some(user) = self.users.get_mut(nick) {
            user.channels.remove(channel);
        }
    }

    // remove user - including stats like invisible users.
    pub(super) fn remove_user(&mut self, nick: &str) {
        if let Some(user) = self.users.remove(nick) {
            if user.modes.is_local_oper() {
                self.operators_count -= 1;
            }
            if user.modes.invisible {
                self.invisible_users_count -= 1;
            }
            self.wallops_users.remove(nick);
            user.channels.iter().for_each(|chname| {
                self.remove_user_from_channel(chname, nick);
            });
            self.insert_to_nick_history(&nick.to_string(), user.history_entry);
        }
    }

    // used to maintain nick history that is read by WHOWAS command.
    pub(super) fn insert_to_nick_history(&mut self, old_nick: &String, nhe: NickHistoryEntry) {
        if !self.nick_histories.contains_key(old_nick) {
            self.nick_histories.insert(old_nick.to_string(), vec![]);
        }
        let nick_hist = self.nick_histories.get_mut(old_nick).unwrap();
        nick_hist.push(nhe);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::iter::FromIterator;

    #[test]
    fn test_user_new() {
        let mut config = MainConfig::default();
        config.default_user_modes = UserModes {
            invisible: true,
            oper: false,
            local_oper: false,
            registered: true,
            wallops: false,
        };
        let user_state = ConnUserState {
            ip_addr: "127.0.0.1".parse().unwrap(),
            hostname: "bobby.com".to_string(),
            name: Some("mati1".to_string()),
            realname: Some("Matthew Somebody".to_string()),
            nick: Some("matix".to_string()),
            source: "matix!mati1@bobby.com".to_string(),
            password: None,
            authenticated: true,
            registered: true,
        };
        let (sender, _) = unbounded_channel();
        let (quit_sender, _) = oneshot::channel();
        let user = User::new(&config, &user_state, sender, quit_sender);

        let user_nick = user_state.nick.clone().unwrap();
        assert_eq!(user_state.hostname, user.hostname);
        assert_eq!(user_state.source, user.source);
        assert_eq!(user_state.realname.unwrap(), user.realname);
        assert_eq!(user_state.name.unwrap(), user.name);
        assert_eq!(user_state.nick.unwrap(), user_nick);
        assert_eq!(config.default_user_modes, user.modes);

        assert_eq!(
            NickHistoryEntry {
                username: user.name.clone(),
                hostname: user.hostname.clone(),
                realname: user.realname.clone(),
                signon: user.signon
            },
            user.history_entry
        );
    }

    #[test]
    fn test_channel_user_modes() {
        let chum = ChannelUserModes {
            founder: false,
            protected: false,
            voice: false,
            operator: false,
            half_oper: false,
        };
        assert!(!chum.is_protected());
        assert!(!chum.is_operator());
        assert!(!chum.is_half_operator());
        assert!(!chum.is_only_half_operator());
        assert!(!chum.is_voice());

        let chum = ChannelUserModes {
            founder: true,
            protected: false,
            voice: false,
            operator: false,
            half_oper: false,
        };
        assert!(chum.is_protected());
        assert!(chum.is_operator());
        assert!(chum.is_half_operator());
        assert!(!chum.is_only_half_operator());
        assert!(chum.is_voice());

        let chum = ChannelUserModes {
            founder: false,
            protected: true,
            voice: false,
            operator: false,
            half_oper: false,
        };
        assert!(chum.is_protected());
        assert!(chum.is_operator());
        assert!(chum.is_half_operator());
        assert!(!chum.is_only_half_operator());
        assert!(chum.is_voice());

        let chum = ChannelUserModes {
            founder: false,
            protected: false,
            voice: false,
            operator: true,
            half_oper: false,
        };
        assert!(!chum.is_protected());
        assert!(chum.is_operator());
        assert!(chum.is_half_operator());
        assert!(!chum.is_only_half_operator());
        assert!(chum.is_voice());

        let chum = ChannelUserModes {
            founder: false,
            protected: false,
            voice: false,
            operator: true,
            half_oper: true,
        };
        assert!(!chum.is_protected());
        assert!(chum.is_operator());
        assert!(chum.is_half_operator());
        assert!(!chum.is_only_half_operator());
        assert!(chum.is_voice());

        let chum = ChannelUserModes {
            founder: false,
            protected: false,
            voice: false,
            operator: false,
            half_oper: true,
        };
        assert!(!chum.is_protected());
        assert!(!chum.is_operator());
        assert!(chum.is_half_operator());
        assert!(chum.is_only_half_operator());
        assert!(chum.is_voice());

        let chum = ChannelUserModes {
            founder: false,
            protected: false,
            voice: true,
            operator: false,
            half_oper: false,
        };
        assert!(!chum.is_protected());
        assert!(!chum.is_operator());
        assert!(!chum.is_half_operator());
        assert!(!chum.is_only_half_operator());
        assert!(chum.is_voice());
    }

    #[test]
    fn test_channel_user_modes_to_string() {
        let chum = ChannelUserModes {
            founder: true,
            protected: true,
            voice: false,
            operator: true,
            half_oper: false,
        };
        assert_eq!(
            "~",
            chum.to_string(&CapState {
                multi_prefix: false
            })
        );
        assert_eq!("~&@", chum.to_string(&CapState { multi_prefix: true }));

        let chum = ChannelUserModes {
            founder: false,
            protected: false,
            voice: true,
            operator: false,
            half_oper: true,
        };
        assert_eq!(
            "%",
            chum.to_string(&CapState {
                multi_prefix: false
            })
        );
        assert_eq!("%+", chum.to_string(&CapState { multi_prefix: true }));
    }

    #[test]
    fn test_get_privmsg_target_type() {
        use PrivMsgTargetType::*;
        assert_eq!((Channel.into(), "#abc"), get_privmsg_target_type("#abc"));
        assert_eq!((Channel.into(), "&abc"), get_privmsg_target_type("&abc"));
        assert_eq!(
            (Channel | ChannelFounder, "#abc"),
            get_privmsg_target_type("~#abc")
        );
        assert_eq!(
            (Channel | ChannelFounder, "&abc"),
            get_privmsg_target_type("~&abc")
        );
        assert_eq!(
            (Channel | ChannelProtected, "#abc"),
            get_privmsg_target_type("&#abc")
        );
        assert_eq!(
            (Channel | ChannelProtected, "&abc"),
            get_privmsg_target_type("&&abc")
        );
        assert_eq!(
            (Channel | ChannelVoice, "#abc"),
            get_privmsg_target_type("+#abc")
        );
        assert_eq!(
            (Channel | ChannelVoice, "&abc"),
            get_privmsg_target_type("+&abc")
        );
        assert_eq!(
            (Channel | ChannelHalfOper, "#abc"),
            get_privmsg_target_type("%#abc")
        );
        assert_eq!(
            (Channel | ChannelHalfOper, "&abc"),
            get_privmsg_target_type("%&abc")
        );
        assert_eq!(
            (Channel | ChannelVoice | ChannelFounder, "#abc"),
            get_privmsg_target_type("+~#abc")
        );
        assert_eq!(
            (Channel | ChannelVoice | ChannelFounder, "&abc"),
            get_privmsg_target_type("+~&abc")
        );
        assert_eq!(
            (Channel | ChannelOper, "#abc"),
            get_privmsg_target_type("@#abc")
        );
        assert_eq!(
            (Channel | ChannelOper, "&abc"),
            get_privmsg_target_type("@&abc")
        );
        assert_eq!(
            (Channel | ChannelOper | ChannelProtected, "#abc"),
            get_privmsg_target_type("&@#abc")
        );
        assert_eq!(
            (Channel | ChannelOper | ChannelProtected, "&abc"),
            get_privmsg_target_type("&@&abc")
        );
        assert_eq!(
            (FlagSet::new(0).unwrap(), ""),
            get_privmsg_target_type("abc")
        );
        assert_eq!((FlagSet::new(0).unwrap(), ""), get_privmsg_target_type("#"));
        assert_eq!((FlagSet::new(0).unwrap(), ""), get_privmsg_target_type("&"));
    }

    #[test]
    fn test_channel_default_modes_new_from_modes_and_cleanup() {
        let mut chm = ChannelModes::default();
        chm.founders = Some(["founder".to_string()].into());
        chm.protecteds = Some(["protected".to_string()].into());
        chm.operators = Some(["operator".to_string()].into());
        chm.half_operators = Some(["half_operator".to_string()].into());
        chm.voices = Some(["voice".to_string()].into());
        let exp_chdm = ChannelDefaultModes {
            founders: ["founder".to_string()].into(),
            protecteds: ["protected".to_string()].into(),
            operators: ["operator".to_string()].into(),
            half_operators: ["half_operator".to_string()].into(),
            voices: ["voice".to_string()].into(),
        };
        let chdm = ChannelDefaultModes::new_from_modes_and_cleanup(&mut chm);
        assert_eq!(exp_chdm, chdm);
        assert_eq!(ChannelModes::default(), chm);

        let mut chm = ChannelModes::default();
        chm.operators = Some(["operator".to_string()].into());
        chm.half_operators = Some(["half_operator".to_string()].into());
        chm.voices = Some(["voice".to_string()].into());
        let exp_chdm = ChannelDefaultModes {
            founders: HashSet::new(),
            protecteds: HashSet::new(),
            operators: ["operator".to_string()].into(),
            half_operators: ["half_operator".to_string()].into(),
            voices: ["voice".to_string()].into(),
        };
        let chdm = ChannelDefaultModes::new_from_modes_and_cleanup(&mut chm);
        assert_eq!(exp_chdm, chdm);
        assert_eq!(ChannelModes::default(), chm);
    }

    #[test]
    fn test_channel_new() {
        let channel = Channel::new_on_user_join("dizzy".to_string());
        assert_eq!(
            Channel {
                topic: None,
                modes: ChannelModes::new_for_channel("dizzy".to_string()),
                default_modes: ChannelDefaultModes::default(),
                ban_info: HashMap::new(),
                users: [(
                    "dizzy".to_string(),
                    ChannelUserModes::new_for_created_channel()
                )]
                .into(),
                creation_time: channel.creation_time,
                preconfigured: false
            },
            channel
        );
    }

    #[test]
    fn test_channel_join_remove_user() {
        let mut channel = Channel::new_on_user_join("runner".to_string());
        channel.default_modes.founders.insert("fasty".to_string());
        channel
            .default_modes
            .protecteds
            .insert("quicker".to_string());
        channel.default_modes.operators.insert("leader".to_string());
        channel
            .default_modes
            .half_operators
            .insert("rover".to_string());
        channel.default_modes.voices.insert("cyclist".to_string());
        channel.add_user(&"fasty".to_string());
        channel.add_user(&"quicker".to_string());
        channel.add_user(&"leader".to_string());
        channel.add_user(&"rover".to_string());
        channel.add_user(&"cyclist".to_string());
        channel.add_user(&"doer".to_string());

        let mut exp_channel = Channel::new_on_user_join("runner".to_string());
        exp_channel.default_modes = channel.default_modes.clone();
        exp_channel.users.insert(
            "fasty".to_string(),
            ChannelUserModes {
                founder: true,
                protected: false,
                operator: false,
                half_oper: false,
                voice: false,
            },
        );
        exp_channel.users.insert(
            "quicker".to_string(),
            ChannelUserModes {
                founder: false,
                protected: true,
                operator: false,
                half_oper: false,
                voice: false,
            },
        );
        exp_channel.users.insert(
            "leader".to_string(),
            ChannelUserModes {
                founder: false,
                protected: false,
                operator: true,
                half_oper: false,
                voice: false,
            },
        );
        exp_channel.users.insert(
            "rover".to_string(),
            ChannelUserModes {
                founder: false,
                protected: false,
                operator: false,
                half_oper: true,
                voice: false,
            },
        );
        exp_channel.users.insert(
            "cyclist".to_string(),
            ChannelUserModes {
                founder: false,
                protected: false,
                operator: false,
                half_oper: false,
                voice: true,
            },
        );
        exp_channel
            .users
            .insert("doer".to_string(), ChannelUserModes::default());
        exp_channel.modes.founders = Some(["fasty".to_string(), "runner".to_string()].into());
        exp_channel.modes.protecteds = Some(["quicker".to_string()].into());
        exp_channel.modes.operators = Some(["leader".to_string(), "runner".to_string()].into());
        exp_channel.modes.half_operators = Some(["rover".to_string()].into());
        exp_channel.modes.voices = Some(["cyclist".to_string()].into());

        assert_eq!(exp_channel, channel);

        channel.remove_user(&"doer".to_string());
        exp_channel.users.remove(&"doer".to_string());
        assert_eq!(exp_channel, channel);

        channel.remove_user(&"cyclist".to_string());
        exp_channel.users.remove(&"cyclist".to_string());
        exp_channel.modes.voices = Some(HashSet::new());
        assert_eq!(exp_channel, channel);

        channel.remove_user(&"rover".to_string());
        exp_channel.users.remove(&"rover".to_string());
        exp_channel.modes.half_operators = Some(HashSet::new());
        assert_eq!(exp_channel, channel);

        channel.remove_user(&"leader".to_string());
        exp_channel.users.remove(&"leader".to_string());
        exp_channel.modes.operators = Some(["runner".to_string()].into());
        assert_eq!(exp_channel, channel);

        channel.remove_user(&"quicker".to_string());
        exp_channel.users.remove(&"quicker".to_string());
        exp_channel.modes.protecteds = Some(HashSet::new());
        assert_eq!(exp_channel, channel);

        channel.remove_user(&"fasty".to_string());
        exp_channel.users.remove(&"fasty".to_string());
        exp_channel.modes.founders = Some(["runner".to_string()].into());
        assert_eq!(exp_channel, channel);
    }

    #[test]
    fn test_channel_rename_user() {
        let mut channel = Channel::new_on_user_join("dizzy".to_string());
        channel.rename_user(&"dizzy".to_string(), "diggy".to_string());
        assert_eq!(
            Channel {
                topic: None,
                modes: ChannelModes::new_for_channel("diggy".to_string()),
                default_modes: ChannelDefaultModes::default(),
                ban_info: HashMap::new(),
                users: [(
                    "diggy".to_string(),
                    ChannelUserModes::new_for_created_channel()
                )]
                .into(),
                creation_time: channel.creation_time,
                preconfigured: false
            },
            channel
        );
    }

    #[test]
    fn test_channel_add_remove_mode() {
        let mut channel = Channel::new_on_user_join("dizzy".to_string());

        let mut exp_channel = Channel {
            topic: None,
            modes: ChannelModes::new_for_channel("dizzy".to_string()),
            default_modes: ChannelDefaultModes::default(),
            ban_info: HashMap::new(),
            users: [
                (
                    "dizzy".to_string(),
                    ChannelUserModes::new_for_created_channel(),
                ),
                ("inventor".to_string(), ChannelUserModes::default()),
                ("guru".to_string(), ChannelUserModes::default()),
                ("halfguru".to_string(), ChannelUserModes::default()),
                ("vip".to_string(), ChannelUserModes::default()),
                ("talker".to_string(), ChannelUserModes::default()),
            ]
            .into(),
            creation_time: channel.creation_time,
            preconfigured: false,
        };

        channel
            .users
            .insert("inventor".to_string(), ChannelUserModes::default());
        channel
            .users
            .insert("guru".to_string(), ChannelUserModes::default());
        channel
            .users
            .insert("halfguru".to_string(), ChannelUserModes::default());
        channel
            .users
            .insert("vip".to_string(), ChannelUserModes::default());
        channel
            .users
            .insert("talker".to_string(), ChannelUserModes::default());

        channel.add_founder("inventor");
        exp_channel.modes.founders = Some(["dizzy".to_string(), "inventor".to_string()].into());
        exp_channel.users.insert(
            "inventor".to_string(),
            ChannelUserModes {
                founder: true,
                protected: false,
                operator: false,
                half_oper: false,
                voice: false,
            },
        );
        assert_eq!(exp_channel, channel);

        channel.remove_founder("inventor");
        exp_channel.modes.founders = Some(["dizzy".to_string()].into());
        exp_channel
            .users
            .insert("inventor".to_string(), ChannelUserModes::default());
        assert_eq!(exp_channel, channel);

        channel.add_operator("guru");
        exp_channel.modes.operators = Some(["dizzy".to_string(), "guru".to_string()].into());
        exp_channel.users.insert(
            "guru".to_string(),
            ChannelUserModes {
                founder: false,
                protected: false,
                operator: true,
                half_oper: false,
                voice: false,
            },
        );
        assert_eq!(exp_channel, channel);

        channel.remove_operator("guru");
        exp_channel.modes.operators = Some(["dizzy".to_string()].into());
        exp_channel
            .users
            .insert("guru".to_string(), ChannelUserModes::default());
        assert_eq!(exp_channel, channel);

        channel.add_half_operator("halfguru");
        exp_channel.modes.half_operators = Some(["halfguru".to_string()].into());
        exp_channel.users.insert(
            "halfguru".to_string(),
            ChannelUserModes {
                founder: false,
                protected: false,
                operator: false,
                half_oper: true,
                voice: false,
            },
        );
        assert_eq!(exp_channel, channel);

        channel.remove_half_operator("halfguru");
        exp_channel.modes.half_operators = Some(HashSet::new());
        exp_channel
            .users
            .insert("halfguru".to_string(), ChannelUserModes::default());
        assert_eq!(exp_channel, channel);

        channel.add_protected("vip");
        exp_channel.modes.protecteds = Some(["vip".to_string()].into());
        exp_channel.users.insert(
            "vip".to_string(),
            ChannelUserModes {
                founder: false,
                protected: true,
                operator: false,
                half_oper: false,
                voice: false,
            },
        );
        assert_eq!(exp_channel, channel);

        channel.remove_protected("vip");
        exp_channel.modes.protecteds = Some(HashSet::new());
        exp_channel
            .users
            .insert("vip".to_string(), ChannelUserModes::default());
        assert_eq!(exp_channel, channel);

        channel.add_voice("talker");
        exp_channel.modes.voices = Some(["talker".to_string()].into());
        exp_channel.users.insert(
            "talker".to_string(),
            ChannelUserModes {
                founder: false,
                protected: false,
                operator: false,
                half_oper: false,
                voice: true,
            },
        );
        assert_eq!(exp_channel, channel);

        channel.remove_voice("talker");
        exp_channel.modes.voices = Some(HashSet::new());
        exp_channel
            .users
            .insert("talker".to_string(), ChannelUserModes::default());
        assert_eq!(exp_channel, channel);
    }

    #[test]
    fn test_conn_user_state() {
        let mut cus = ConnUserState::new("192.168.1.7".parse().unwrap());
        assert_eq!(
            ConnUserState {
                ip_addr: "192.168.1.7".parse().unwrap(),
                hostname: "192.168.1.7".to_string(),
                name: None,
                realname: None,
                nick: None,
                source: "@192.168.1.7".to_string(),
                password: None,
                authenticated: false,
                registered: false
            },
            cus
        );
        assert_eq!("192.168.1.7", cus.client_name());
        cus.set_name("boro".to_string());
        assert_eq!(
            ConnUserState {
                ip_addr: "192.168.1.7".parse().unwrap(),
                hostname: "192.168.1.7".to_string(),
                name: Some("boro".to_string()),
                realname: None,
                nick: None,
                source: "~boro@192.168.1.7".to_string(),
                password: None,
                authenticated: false,
                registered: false
            },
            cus
        );
        assert_eq!("boro", cus.client_name());
        cus.set_nick("buru".to_string());
        assert_eq!(
            ConnUserState {
                ip_addr: "192.168.1.7".parse().unwrap(),
                hostname: "192.168.1.7".to_string(),
                name: Some("boro".to_string()),
                realname: None,
                nick: Some("buru".to_string()),
                source: "buru!~boro@192.168.1.7".to_string(),
                password: None,
                authenticated: false,
                registered: false
            },
            cus
        );
        assert_eq!("buru", cus.client_name());

        let mut cus = ConnUserState::new("192.168.1.7".parse().unwrap());
        assert_eq!(
            ConnUserState {
                ip_addr: "192.168.1.7".parse().unwrap(),
                hostname: "192.168.1.7".to_string(),
                name: None,
                realname: None,
                nick: None,
                source: "@192.168.1.7".to_string(),
                password: None,
                authenticated: false,
                registered: false
            },
            cus
        );
        assert_eq!("192.168.1.7", cus.client_name());
        cus.set_nick("boro".to_string());
        assert_eq!(
            ConnUserState {
                ip_addr: "192.168.1.7".parse().unwrap(),
                hostname: "192.168.1.7".to_string(),
                nick: Some("boro".to_string()),
                realname: None,
                name: None,
                source: "boro!@192.168.1.7".to_string(),
                password: None,
                authenticated: false,
                registered: false
            },
            cus
        );
        assert_eq!("boro", cus.client_name());
        cus.set_name("buru".to_string());
        assert_eq!(
            ConnUserState {
                ip_addr: "192.168.1.7".parse().unwrap(),
                hostname: "192.168.1.7".to_string(),
                nick: Some("boro".to_string()),
                realname: None,
                name: Some("buru".to_string()),
                source: "boro!~buru@192.168.1.7".to_string(),
                password: None,
                authenticated: false,
                registered: false
            },
            cus
        );
        assert_eq!("boro", cus.client_name());
    }

    #[test]
    fn test_volatile_state_new() {
        let mut config = MainConfig::default();
        config.channels = Some(vec![
            ChannelConfig {
                name: "#gooddays".to_string(),
                topic: Some("About good days".to_string()),
                modes: ChannelModes::default(),
            },
            ChannelConfig {
                name: "#pets".to_string(),
                topic: Some("About pets".to_string()),
                modes: ChannelModes::default(),
            },
            ChannelConfig {
                name: "&cactuses".to_string(),
                topic: None,
                modes: ChannelModes::default(),
            },
        ]);
        let state = VolatileState::new_from_config(&config);
        assert_eq!(
            HashMap::from([
                (
                    "#gooddays".to_string(),
                    Channel {
                        topic: Some(ChannelTopic::new("About good days".to_string())),
                        modes: ChannelModes::default(),
                        default_modes: ChannelDefaultModes::default(),
                        ban_info: HashMap::new(),
                        users: HashMap::new(),
                        creation_time: state.channels.get("#gooddays").unwrap().creation_time,
                        preconfigured: true
                    }
                ),
                (
                    "#pets".to_string(),
                    Channel {
                        topic: Some(ChannelTopic::new("About pets".to_string())),
                        modes: ChannelModes::default(),
                        default_modes: ChannelDefaultModes::default(),
                        ban_info: HashMap::new(),
                        users: HashMap::new(),
                        creation_time: state.channels.get("#pets").unwrap().creation_time,
                        preconfigured: true
                    }
                ),
                (
                    "&cactuses".to_string(),
                    Channel {
                        topic: None,
                        modes: ChannelModes::default(),
                        default_modes: ChannelDefaultModes::default(),
                        ban_info: HashMap::new(),
                        users: HashMap::new(),
                        creation_time: state.channels.get("&cactuses").unwrap().creation_time,
                        preconfigured: true
                    }
                )
            ]),
            state.channels
        );
    }

    #[test]
    fn test_volatile_remove_user_from_channel() {
        let mut config = MainConfig::default();
        config.channels = Some(vec![ChannelConfig {
            name: "#something".to_string(),
            topic: None,
            modes: ChannelModes::default(),
        }]);
        let mut state = VolatileState::new_from_config(&config);
        let user_state = ConnUserState {
            ip_addr: "127.0.0.1".parse().unwrap(),
            hostname: "bobby.com".to_string(),
            name: Some("matix".to_string()),
            realname: Some("Matthew Somebody".to_string()),
            nick: Some("matixi".to_string()),
            source: "matixi!matix@bobby.com".to_string(),
            password: None,
            authenticated: true,
            registered: true,
        };
        let (sender, _) = unbounded_channel();
        let (quit_sender, _) = oneshot::channel();
        let user = User::new(&config, &user_state, sender, quit_sender);
        state.add_user(&user_state.nick.clone().unwrap(), user);

        // create channels and add channel to user structure
        [("#matixichan", "matixi"), ("#tulipchan", "matixi")]
            .iter()
            .for_each(|(chname, nick)| {
                state.channels.insert(
                    chname.to_string(),
                    Channel::new_on_user_join(nick.to_string()),
                );
                state
                    .users
                    .get_mut(&nick.to_string())
                    .unwrap()
                    .channels
                    .insert(chname.to_string());
            });
        state
            .channels
            .get_mut(&"#something".to_string())
            .unwrap()
            .users
            .insert("matixi".to_string(), ChannelUserModes::default());
        state
            .users
            .get_mut("matixi")
            .unwrap()
            .channels
            .insert("#something".to_string());

        state.remove_user_from_channel("#something", "matixi");
        assert!(state.channels.contains_key("#something"));
        assert_eq!(
            HashMap::new(),
            state.channels.get("#something").unwrap().users
        );
        state.remove_user_from_channel("#matixichan", "matixi");
        assert!(!state.channels.contains_key("#matixichan"));
        state.remove_user_from_channel("#tulipan", "matixi");
        assert!(!state.channels.contains_key("#tulipan"));
    }

    #[test]
    fn test_volatile_state_add_remove_user() {
        let mut config = MainConfig::default();
        config.channels = Some(vec![ChannelConfig {
            name: "#something".to_string(),
            topic: None,
            modes: ChannelModes::default(),
        }]);
        let mut state = VolatileState::new_from_config(&config);

        let user_state = ConnUserState {
            ip_addr: "127.0.0.1".parse().unwrap(),
            hostname: "bobby.com".to_string(),
            name: Some("matix".to_string()),
            realname: Some("Matthew Somebody".to_string()),
            nick: Some("matixi".to_string()),
            source: "matixi!matix@bobby.com".to_string(),
            password: None,
            authenticated: true,
            registered: true,
        };
        let (sender, _) = unbounded_channel();
        let (quit_sender, _) = oneshot::channel();
        let user = User::new(&config, &user_state, sender, quit_sender);
        state.add_user(&user_state.nick.clone().unwrap(), user);
        assert_eq!(1, state.max_users_count);

        let user_state = ConnUserState {
            ip_addr: "127.0.0.1".parse().unwrap(),
            hostname: "flowers.com".to_string(),
            name: Some("tulip".to_string()),
            realname: Some("Tulipan".to_string()),
            nick: Some("tulipan".to_string()),
            source: "tulipan!tulip@flowers.com".to_string(),
            password: None,
            authenticated: true,
            registered: true,
        };
        let (sender, _) = unbounded_channel();
        let (quit_sender, _) = oneshot::channel();
        let user = User::new(&config, &user_state, sender, quit_sender);
        state.add_user(&user_state.nick.clone().unwrap(), user);
        assert_eq!(2, state.max_users_count);

        let user_state = ConnUserState {
            ip_addr: "127.0.0.1".parse().unwrap(),
            hostname: "digger.com".to_string(),
            name: Some("greggy".to_string()),
            realname: Some("Gregory Digger".to_string()),
            nick: Some("greg".to_string()),
            source: "greg!greggy@digger.com".to_string(),
            password: None,
            authenticated: true,
            registered: true,
        };
        let (sender, _) = unbounded_channel();
        let (quit_sender, _) = oneshot::channel();
        let mut user = User::new(&config, &user_state, sender, quit_sender);
        user.modes.invisible = true;
        state.add_user(&user_state.nick.clone().unwrap(), user);
        assert_eq!(3, state.max_users_count);
        assert_eq!(1, state.invisible_users_count);

        let user_state = ConnUserState {
            ip_addr: "127.0.0.1".parse().unwrap(),
            hostname: "miller.com".to_string(),
            name: Some("johnny".to_string()),
            realname: Some("John Miller".to_string()),
            nick: Some("john".to_string()),
            source: "john!johnny@miller.com".to_string(),
            password: None,
            authenticated: true,
            registered: true,
        };
        let (sender, _) = unbounded_channel();
        let (quit_sender, _) = oneshot::channel();
        let mut user = User::new(&config, &user_state, sender, quit_sender);
        user.modes.wallops = true;
        state.add_user(&user_state.nick.clone().unwrap(), user);
        assert_eq!(4, state.max_users_count);
        assert_eq!(1, state.invisible_users_count);
        assert_eq!(HashSet::from(["john".to_string()]), state.wallops_users);

        let user_state = ConnUserState {
            ip_addr: "127.0.0.1".parse().unwrap(),
            hostname: "guru.com".to_string(),
            name: Some("admin".to_string()),
            realname: Some("Great Admin".to_string()),
            nick: Some("admini".to_string()),
            source: "admini!admin@guru.com".to_string(),
            password: None,
            authenticated: true,
            registered: true,
        };
        let (sender, _) = unbounded_channel();
        let (quit_sender, _) = oneshot::channel();
        let mut user = User::new(&config, &user_state, sender, quit_sender);
        user.modes.oper = true;
        state.add_user(&user_state.nick.clone().unwrap(), user);
        assert_eq!(5, state.max_users_count);
        assert_eq!(1, state.invisible_users_count);
        assert_eq!(1, state.operators_count);

        assert_eq!(
            HashSet::from([
                "matixi".to_string(),
                "tulipan".to_string(),
                "greg".to_string(),
                "john".to_string(),
                "admini".to_string()
            ]),
            HashSet::from_iter(state.users.keys().cloned())
        );
        assert_eq!(
            HashSet::from([
                "matix".to_string(),
                "tulip".to_string(),
                "greggy".to_string(),
                "johnny".to_string(),
                "admin".to_string()
            ]),
            HashSet::from_iter(state.users.values().map(|u| u.name.clone()))
        );
        assert_eq!(
            HashSet::from([
                "Matthew Somebody".to_string(),
                "Tulipan".to_string(),
                "Gregory Digger".to_string(),
                "John Miller".to_string(),
                "Great Admin".to_string()
            ]),
            HashSet::from_iter(state.users.values().map(|u| u.realname.clone()))
        );

        // create channels and add channel to user structure
        [
            ("#matixichan", "matixi"),
            ("#tulipchan", "tulipan"),
            ("#gregchan", "greg"),
            ("#johnchan", "john"),
            ("#guruchan", "admini"),
        ]
        .iter()
        .for_each(|(chname, nick)| {
            state.channels.insert(
                chname.to_string(),
                Channel::new_on_user_join(nick.to_string()),
            );
            state
                .users
                .get_mut(&nick.to_string())
                .unwrap()
                .channels
                .insert(chname.to_string());
        });
        state
            .channels
            .get_mut("#something")
            .unwrap()
            .users
            .insert("john".to_string(), ChannelUserModes::default());
        state
            .users
            .get_mut("john")
            .unwrap()
            .channels
            .insert("#something".to_string());

        // removing users
        state.remove_user("matixi");
        assert_eq!(5, state.max_users_count);
        assert_eq!(1, state.invisible_users_count);
        assert_eq!(1, state.operators_count);
        assert_eq!(HashSet::from(["john".to_string()]), state.wallops_users);

        assert_eq!(
            HashSet::from([
                "tulipan".to_string(),
                "greg".to_string(),
                "john".to_string(),
                "admini".to_string()
            ]),
            HashSet::from_iter(state.users.keys().cloned())
        );
        assert_eq!(
            HashSet::from([
                "tulip".to_string(),
                "greggy".to_string(),
                "johnny".to_string(),
                "admin".to_string()
            ]),
            HashSet::from_iter(state.users.values().map(|u| u.name.clone()))
        );
        assert!(!state.channels.contains_key("#matixichan"));

        state.remove_user("greg");
        assert_eq!(5, state.max_users_count);
        assert_eq!(0, state.invisible_users_count);
        assert_eq!(1, state.operators_count);
        assert_eq!(HashSet::from(["john".to_string()]), state.wallops_users);

        assert_eq!(
            HashSet::from([
                "tulipan".to_string(),
                "john".to_string(),
                "admini".to_string()
            ]),
            HashSet::from_iter(state.users.keys().cloned())
        );
        assert_eq!(
            HashSet::from([
                "tulip".to_string(),
                "johnny".to_string(),
                "admin".to_string()
            ]),
            HashSet::from_iter(state.users.values().map(|u| u.name.clone()))
        );
        assert!(!state.channels.contains_key("#gregchan"));

        state.remove_user("john");
        assert_eq!(5, state.max_users_count);
        assert_eq!(0, state.invisible_users_count);
        assert_eq!(1, state.operators_count);
        assert_eq!(HashSet::new(), state.wallops_users);

        assert_eq!(
            HashSet::from(["tulipan".to_string(), "admini".to_string()]),
            HashSet::from_iter(state.users.keys().cloned())
        );
        assert_eq!(
            HashSet::from(["tulip".to_string(), "admin".to_string()]),
            HashSet::from_iter(state.users.values().map(|u| u.name.clone()))
        );
        assert!(!state.channels.contains_key("#johnchan"));
        assert!(state.channels.contains_key("#something"));

        state.remove_user("admini");
        assert_eq!(5, state.max_users_count);
        assert_eq!(0, state.invisible_users_count);
        assert_eq!(0, state.operators_count);
        assert_eq!(HashSet::new(), state.wallops_users);
        assert_eq!(
            HashSet::from(["tulipan".to_string()]),
            HashSet::from_iter(state.users.keys().cloned())
        );
        assert_eq!(
            HashSet::from(["tulip".to_string()]),
            HashSet::from_iter(state.users.values().map(|u| u.name.clone()))
        );
        assert!(!state.channels.contains_key("#guruchan"));
    }

    #[test]
    fn test_volatile_state_insert_to_nick_history() {
        let config = MainConfig::default();
        let mut state = VolatileState::new_from_config(&config);
        state.insert_to_nick_history(
            &"mati".to_string(),
            NickHistoryEntry {
                username: "mati1".to_string(),
                hostname: "gugg.com".to_string(),
                realname: "Mati1".to_string(),
                signon: 12344555555,
            },
        );
        state.insert_to_nick_history(
            &"mati".to_string(),
            NickHistoryEntry {
                username: "mati2".to_string(),
                hostname: "bip.com".to_string(),
                realname: "Mati2".to_string(),
                signon: 12377411100,
            },
        );
        assert_eq!(
            HashMap::from([(
                "mati".to_string(),
                vec![
                    NickHistoryEntry {
                        username: "mati1".to_string(),
                        hostname: "gugg.com".to_string(),
                        realname: "Mati1".to_string(),
                        signon: 12344555555
                    },
                    NickHistoryEntry {
                        username: "mati2".to_string(),
                        hostname: "bip.com".to_string(),
                        realname: "Mati2".to_string(),
                        signon: 12377411100
                    }
                ]
            )]),
            state.nick_histories
        );
    }
}
