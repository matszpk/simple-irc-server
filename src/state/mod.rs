// mod.rs - main state
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

use std::ops::Drop;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::File;
use std::io;
#[cfg(feature = "tls_rustls")]
use std::io::BufReader;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::net::{IpAddr, SocketAddr};
use std::error::Error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, oneshot};
use tokio_stream::StreamExt;
use tokio::net::TcpListener;
#[cfg(any(feature = "tls_rustls", feature = "tls_openssl"))]
use tokio::net::TcpStream;
use tokio_util::codec::{Framed, LinesCodecError};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::mpsc::error::SendError;
use tokio::task::JoinHandle;
use tokio::time;
use futures::{SinkExt, future::Fuse, future::FutureExt};
use chrono::prelude::*;
use flagset::{flags, FlagSet};
#[cfg(feature = "tls_rustls")]
use rustls;
#[cfg(feature = "tls_rustls")]
use rustls_pemfile;
#[cfg(feature = "tls_rustls")]
use tokio_rustls::rustls::{Certificate, PrivateKey};
#[cfg(feature = "tls_rustls")]
use tokio_rustls::TlsAcceptor;
#[cfg(feature = "tls_openssl")]
use openssl::ssl::{Ssl, SslAcceptor, SslFiletype, SslMethod};
#[cfg(feature = "tls_openssl")]
use tokio_openssl::SslStream;
#[cfg(feature = "dns_lookup")]
use trust_dns_resolver::{TokioHandle, TokioAsyncResolver};
#[cfg(feature = "dns_lookup")]
use lazy_static::lazy_static;
use tracing::*;

use crate::config::*;
use crate::reply::*;
use crate::command::*;
use crate::utils::*;

use Reply::*;

#[derive(Debug)]
struct User {
    hostname: String,
    sender: UnboundedSender<String>,
    // quit_sender - used by KILL command.
    quit_sender: Option<oneshot::Sender<(String, String)>>,
    name: String,
    realname: String,
    nick: String,
    source: String, // IRC source for mask matching
    modes: UserModes,
    away: Option<String>,
    channels: HashSet<String>,
    invited_to: HashSet<String>,    // invited in channels
    last_activity: u64,
    signon: u64,
    history_entry: NickHistoryEntry
}

impl User {
    fn new(config: &MainConfig, user_state: &ConnUserState, sender: UnboundedSender<String>,
            quit_sender: oneshot::Sender<(String, String)>) -> User {
        let mut user_modes = config.default_user_modes;
        user_modes.registered = user_modes.registered || user_state.registered;
        let now_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        User{ hostname: user_state.hostname.clone(), sender,
                quit_sender: Some(quit_sender),
                name: user_state.name.as_ref().unwrap().clone(),
                realname: user_state.realname.as_ref().unwrap().clone(),
                nick: user_state.nick.as_ref().unwrap().clone(),
                source: user_state.source.clone(),
                modes: user_modes, away: None,
                channels: HashSet::new(), invited_to: HashSet::new(),
                last_activity: now_ts, signon: now_ts,
                history_entry: NickHistoryEntry{
                    username: user_state.name.as_ref().unwrap().clone(),
                    hostname: user_state.hostname.clone(),
                    realname: user_state.realname.as_ref().unwrap().clone(),
                    signon: now_ts } }
    }
    
    // update nick - mainly source
    fn update_nick(&mut self, user_state: &ConnUserState) {
        if let Some(ref nick) = user_state.nick { self.nick = nick.clone(); }
        self.source = user_state.source.clone();
    }
    
    // update nick - mainly source
    #[cfg(feature = "dns_lookup")]
    fn update_hostname(&mut self, user_state: &ConnUserState) {
        self.nick = user_state.hostname.clone();
        self.source = user_state.source.clone();
    }
    
    fn send_message(&self, msg: &Message<'_>, source: &str)
                -> Result<(), SendError<String>> {
        self.sender.send(msg.to_string_with_source(source))
    }
    
    fn send_msg_display<T: fmt::Display>(&self, source: &str, t :T)
                -> Result<(), SendError<String>> {
        self.sender.send(format!(":{} {}", source, t))
    }
}

#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
struct ChannelUserModes {
    founder: bool,
    protected: bool,
    voice: bool,
    operator: bool,
    half_oper: bool,
}

impl ChannelUserModes {
    fn new_for_created_channel() -> Self {
        ChannelUserModes{ founder: true, protected: false, voice: false,
                operator: true, half_oper: false }
    }
    
    fn is_protected(&self) -> bool {
        self.founder || self.protected
    }
    
    fn is_operator(&self) -> bool {
        self.founder || self.protected || self.operator
    }
    fn is_half_operator(&self) -> bool {
        self.founder || self.protected || self.operator || self.half_oper
    }
    // if only half operator - no protected, no founder and no operator
    fn is_only_half_operator(&self) -> bool {
        !self.founder && !self.protected && !self.operator && self.half_oper
    }
    fn is_voice(&self) -> bool {
        self.founder || self.protected || self.operator || self.half_oper || self.voice
    }
}

flags! {
    enum PrivMsgTargetType: u8 {
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
    fn to_string(&self, caps: &CapState) -> String {
        let mut out = String::new();
        if self.founder { out.push('~'); }
        // after put the highest user mode, put other if caps multi-prefix is enabled.
        if (caps.multi_prefix || out.is_empty()) && self.protected { out.push('&'); }
        if (caps.multi_prefix || out.is_empty()) && self.operator { out.push('@'); }
        if (caps.multi_prefix || out.is_empty()) && self.half_oper { out.push('%'); }
        if (caps.multi_prefix || out.is_empty()) && self.voice { out.push('+'); }
        out
    }
}

// get target type for PRIVMSG and channel name
fn get_privmsg_target_type(target: &str) -> (FlagSet<PrivMsgTargetType>, &str) {
    use PrivMsgTargetType::*;
    let mut out = Channel.into();
    let mut amp_count = 0;
    let mut last_amp = false;
    let mut out_str = "";
    for (i,c) in target.bytes().enumerate() {
        match c {
            b'~' => out |= Channel|ChannelFounder,
            b'&' => out |= Channel|ChannelProtected,
            b'@' => out |= Channel|ChannelOper,
            b'%' => out |= Channel|ChannelHalfOper,
            b'+' => out |= Channel|ChannelVoice,
            b'#' => {
                // if global channel
                if i+1 < target.len() { out_str = &target[i..]; }
                else { out &= !ChannelAll; }
                break;
            }
            _ => {
                if last_amp {
                    // only one ampersand - then not protected
                    if amp_count < 2 { out &= !ChannelProtected; }
                    out_str = &target[i-1..];
                } else { out &= !ChannelAll; }
                break;
            }
        }
        if c == b'&' {
            // if not last character then count ampersand, otherwise is not channel
            if i+1 < target.len() {
                last_amp = true;
                amp_count += 1;
            } else { out &= !ChannelAll; }
         } else { last_amp = false; }
    }
    (out, out_str)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChannelTopic {
    topic: String,
    nick: String,
    set_time: u64
}

impl ChannelTopic{
    fn new(topic: String) -> Self {
        ChannelTopic{ topic, nick: String::new(),
            set_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() }
    }
    
    fn new_with_nick(topic: String, nick: String) -> Self {
        ChannelTopic{ topic, nick,
            set_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BanInfo {
    set_time: u64,
    who: String,
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
struct ChannelDefaultModes {
    operators: HashSet<String>,
    half_operators: HashSet<String>,
    voices: HashSet<String>,
    founders: HashSet<String>,
    protecteds: HashSet<String>,
}

impl ChannelDefaultModes {
    // create new channel default modes from ChannelModes and clean up this ChannelModes.
    fn new_from_modes_and_cleanup(modes: &mut ChannelModes) -> Self {
        ChannelDefaultModes{
            operators: modes.operators.take().unwrap_or_default(),
            half_operators: modes.half_operators.take().unwrap_or_default(),
            voices: modes.voices.take().unwrap_or_default(),
            founders: modes.founders.take().unwrap_or_default(),
            protecteds: modes.protecteds.take().unwrap_or_default() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Channel {
    name: String,
    topic: Option<ChannelTopic>,
    modes: ChannelModes,
    default_modes: ChannelDefaultModes,
    ban_info: HashMap<String, BanInfo>,
    users: HashMap<String, ChannelUserModes>,
    creation_time: u64,
    // if channel is preconfigured - it comes from configuration
    preconfigured: bool,
}

impl Channel {
    fn new(name: String, user_nick: String) -> Channel {
        let mut users = HashMap::new();
        users.insert(user_nick.clone(), ChannelUserModes::new_for_created_channel());
        Channel{ name, topic: None, ban_info: HashMap::new(),
            default_modes: ChannelDefaultModes::default(),
            modes: ChannelModes::new_for_channel(user_nick), users,
            creation_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            preconfigured: false }
    }
    
    fn add_user(&mut self, user_nick: &String) {
        let mut chum = ChannelUserModes::default();
        // apply default modes for user in channel
        if self.default_modes.half_operators.contains(user_nick) {
            chum.half_oper = true;
            let mut half_ops = self.modes.half_operators.take()
                    .unwrap_or_default();
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
            let mut protecteds = self.modes.protecteds.take()
                    .unwrap_or_default();
            protecteds.insert(user_nick.clone());
            self.modes.protecteds = Some(protecteds);
        }
        self.users.insert(user_nick.clone(), chum);
    }
    
    fn rename_user(&mut self, old_nick: &String, nick: String) {
        let oldchumode = self.users.remove(old_nick).unwrap();
        self.users.insert(nick.clone(), oldchumode);
        self.modes.rename_user(old_nick, nick.clone());
    }
    
    // remove user from channel - and from lists
    fn remove_user(&mut self, nick: &str) {
        self.remove_operator(nick);
        self.remove_half_operator(nick);
        self.remove_founder(nick);
        self.remove_voice(nick);
        self.remove_protected(nick);
        self.users.remove(nick);
    }
    
    // add/remove user from list
    fn add_operator(&mut self, nick: &str) {
        let mut ops = self.modes.operators.take().unwrap_or_default();
        ops.insert(nick.to_string());
        self.modes.operators = Some(ops);
        self.users.get_mut(nick).unwrap().operator = true;
    }
    fn remove_operator(&mut self, nick: &str) {
        let mut ops = self.modes.operators.take().unwrap_or_default();
        ops.remove(nick);
        self.modes.operators = Some(ops);
        self.users.get_mut(nick).unwrap().operator = false;
    }
    fn add_half_operator(&mut self, nick: &str) {
        let mut half_ops = self.modes.half_operators.take().unwrap_or_default();
        half_ops.insert(nick.to_string());
        self.modes.half_operators = Some(half_ops);
        self.users.get_mut(nick).unwrap().half_oper = true;
    }
    fn remove_half_operator(&mut self, nick: &str) {
        let mut half_ops = self.modes.half_operators.take().unwrap_or_default();
        half_ops.remove(nick);
        self.modes.half_operators = Some(half_ops);
        self.users.get_mut(nick).unwrap().half_oper = false;
    }
    fn add_voice(&mut self, nick: &str) {
        let mut voices = self.modes.voices.take().unwrap_or_default();
        voices.insert(nick.to_string());
        self.modes.voices = Some(voices);
        self.users.get_mut(nick).unwrap().voice = true;
    }
    fn remove_voice(&mut self, nick: &str) {
        let mut voices = self.modes.voices.take().unwrap_or_default();
        voices.remove(nick);
        self.modes.voices = Some(voices);
        self.users.get_mut(nick).unwrap().voice = false;
    }
    fn add_founder(&mut self, nick: &str) {
        let mut founders = self.modes.founders.take().unwrap_or_default();
        founders.insert(nick.to_string());
        self.modes.founders = Some(founders);
        self.users.get_mut(nick).unwrap().founder = true;
    }
    fn remove_founder(&mut self, nick: &str) {
        let mut founders = self.modes.founders.take().unwrap_or_default();
        founders.remove(nick);
        self.modes.founders = Some(founders);
        self.users.get_mut(nick).unwrap().founder = false;
    }
    fn add_protected(&mut self, nick: &str) {
        let mut protecteds = self.modes.protecteds.take().unwrap_or_default();
        protecteds.insert(nick.to_string());
        self.modes.protecteds = Some(protecteds);
        self.users.get_mut(nick).unwrap().protected = true;
    }
    fn remove_protected(&mut self, nick: &str) {
        let mut protecteds = self.modes.protecteds.take().unwrap_or_default();
        protecteds.remove(nick);
        self.modes.protecteds = Some(protecteds);
        self.users.get_mut(nick).unwrap().protected = false;
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NickHistoryEntry {
    username: String,
    hostname: String,
    realname: String,
    signon: u64,
}

#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct CapState {
    multi_prefix: bool,
}

impl fmt::Display for CapState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.multi_prefix {
            f.write_str("multi-prefix")
        } else { Ok(()) }
    }
}

impl CapState {
    fn apply_cap(&mut self, cap: &str) -> bool {
        match cap {
            "multi-prefix" => self.multi_prefix = true,
            _ => return false,
        };
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnUserState {
    ip_addr: IpAddr,
    hostname: String,
    name: Option<String>,
    realname: Option<String>,
    nick: Option<String>,
    source: String, // IRC source for mask matching
    password: Option<String>,
    authenticated: bool,
    registered: bool,
}

impl ConnUserState {
    fn new(ip_addr: IpAddr) -> ConnUserState {
        let mut source = "@".to_string();
        source.push_str(&ip_addr.to_string());
        ConnUserState{ ip_addr, hostname: ip_addr.to_string(),
            name: None, realname: None, nick: None, source, password: None,
            authenticated: false, registered: false }
    }
    
    fn client_name<'a>(&'a self) -> &'a str {
        if let Some(ref n) = self.nick { &n }
        else if let Some(ref n) = self.name { &n }
        else { &self.hostname }
    }
    
    fn update_source(&mut self) {
        let mut s = String::new();
        // generate source - nick!username@host
        if let Some(ref nick) = self.nick {
            s.push_str(&nick);
            s.push('!');
        }
        if let Some(ref name) = self.name {
            s.push('~');  // username is defined same user
            s.push_str(&name);
        }
        s.push('@');
        s.push_str(&self.hostname);
        self.source = s;
    }
    
    #[cfg(feature = "dns_lookup")]
    fn set_hostname(&mut self, hostname: String) {
        self.hostname = hostname;
        self.update_source();
    }
    fn set_name(&mut self, name: String) {
        self.name = Some(name);
        self.update_source();
    }
    fn set_nick(&mut self, nick: String) {
        self.nick = Some(nick);
        self.update_source();
    }
}

#[derive(Debug)]
pub(crate) struct ConnState {
    stream: Framed<DualTcpStream, IRCLinesCodec>,
    sender: Option<UnboundedSender<String>>,
    receiver: UnboundedReceiver<String>,
    // sender and receiver used for sending ping task for 
    ping_sender: Option<UnboundedSender<()>>,
    // ping_receiver - process method receives ping and sent ping to client.
    ping_receiver: UnboundedReceiver<()>,
    // timeout_sender - sender to send timeout - it will sent by pong_client_timeout
    timeout_sender: Arc<UnboundedSender<()>>,
    // timeout_receiver - process method receives that
    timeout_receiver: UnboundedReceiver<()>,
    pong_notifier: Option<oneshot::Sender<()>>,
    // quit receiver - receive KILL from other user.
    quit_receiver: Fuse<oneshot::Receiver<(String, String)>>,
    // quit_sender - quit sender to send KILL - sender will be later taken after
    // correct authentication and it will be stored in User structure.
    quit_sender: Option<oneshot::Sender<(String, String)>>,
    // receiver for dns lookup
    dns_lookup_receiver: Fuse<oneshot::Receiver<Option<String>>>,
    #[cfg(feature = "dns_lookup")]
    dns_lookup_sender: Option<oneshot::Sender<Option<String>>>,
    
    user_state: ConnUserState,
    
    caps_negotation: bool,  // if caps negotation process
    caps: CapState,
    quit: Arc<AtomicI32>,
    conns_count: Arc<AtomicUsize>
}

impl ConnState {
    fn new(ip_addr: IpAddr, stream: Framed<DualTcpStream, IRCLinesCodec>,
            conns_count: Arc<AtomicUsize>) -> ConnState {
        let (sender, receiver) = unbounded_channel();
        let (ping_sender, ping_receiver) = unbounded_channel();
        let (timeout_sender, timeout_receiver) = unbounded_channel();
        let (quit_sender, quit_receiver) = oneshot::channel();
        #[cfg(feature = "dns_lookup")]
        let (dns_lookup_sender, dns_lookup_receiver) = oneshot::channel();
        #[cfg(not(feature = "dns_lookup"))]
        let (_, dns_lookup_receiver) = oneshot::channel();
        
        ConnState{ stream, sender: Some(sender), receiver,
            user_state: ConnUserState::new(ip_addr),
            ping_sender: Some(ping_sender), ping_receiver,
            timeout_sender: Arc::new(timeout_sender), timeout_receiver,
            pong_notifier: None,
            quit_sender: Some(quit_sender),
            quit_receiver: quit_receiver.fuse(),
            #[cfg(feature = "dns_lookup")]
            dns_lookup_sender: Some(dns_lookup_sender),
            dns_lookup_receiver: dns_lookup_receiver.fuse(),
            caps_negotation: false, caps: CapState::default(),
            quit: Arc::new(AtomicI32::new(0)),
            conns_count }
    }
    
    pub(crate) fn is_quit(&self) -> bool {
        self.quit.load(Ordering::SeqCst) != 0
    }
    
    fn run_ping_waker(&mut self, config: &MainConfig) {
        if self.ping_sender.is_some() {
            tokio::spawn(ping_client_waker(Duration::from_secs(config.ping_timeout),
                    self.quit.clone(), self.ping_sender.take().unwrap()));
        } else {
            panic!("Ping waker ran!"); // unexpected!
        }
    }
    
    // run pong timeout process - that send timeout aftet some time.
    fn run_pong_timeout(&mut self, config: &MainConfig) {
        let (pong_notifier, pong_receiver) = oneshot::channel();
        self.pong_notifier = Some(pong_notifier);
        tokio::spawn(pong_client_timeout(
                time::timeout(Duration::from_secs(config.pong_timeout), pong_receiver),
                    self.quit.clone(), self.timeout_sender.clone()));
    }
    
    #[cfg(feature = "dns_lookup")]
    fn run_dns_lookup(&mut self) {
        dns_lookup(self.dns_lookup_sender.take().unwrap(), self.user_state.ip_addr);
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

async fn pong_client_timeout(tmo: time::Timeout<oneshot::Receiver<()>>,
                    quit: Arc<AtomicI32>, sender: Arc<UnboundedSender<()>>) {
    if let Err(_) = tmo.await {
        // do not send if client already quits from IRC server.
        if quit.load(Ordering::SeqCst) == 0 {
            sender.send(()).unwrap();
        }
    }
}

struct VolatileState {
    users: HashMap<String, User>,
    channels: HashMap<String, Channel>,
    wallops_users: HashSet<String>,
    invisible_users_count: usize,
    operators_count: usize,
    max_users_count: usize,
    nick_histories: HashMap<String, Vec<NickHistoryEntry>>,
    quit_sender: Option<oneshot::Sender<String>>,
    quit_receiver: Option<oneshot::Receiver<String>>
}

impl VolatileState {
    fn new_from_config(config: &MainConfig) -> VolatileState {
        let mut channels = HashMap::new();
        if let Some(ref cfg_channels) = config.channels {
            // create new channels from configuration
            cfg_channels.iter().for_each(|c| {
                let mut ch_modes = c.modes.clone();
                let def_ch_modes = ChannelDefaultModes::new_from_modes_and_cleanup(
                            &mut ch_modes);
                
                channels.insert(c.name.clone(), Channel{ name: c.name.clone(), 
                    topic: c.topic.as_ref().map(|x| ChannelTopic::new(x.clone())),
                    ban_info: HashMap::new(), default_modes: def_ch_modes,
                    modes: ch_modes, users: HashMap::new(),
                    creation_time: SystemTime::now().duration_since(UNIX_EPOCH)
                            .unwrap().as_secs(),
                    preconfigured: true });
            });
        }
        
        let (quit_sender, quit_receiver) = oneshot::channel();
        VolatileState{ users: HashMap::new(), channels, wallops_users: HashSet::new(),
                invisible_users_count: 0, operators_count: 0 , max_users_count: 0,
                nick_histories: HashMap::new(),
                quit_sender: Some(quit_sender), quit_receiver: Some(quit_receiver) }
    }
    
    // add user to volatile state - includes stats likes invisible users count, etc.
    fn add_user(&mut self, user: User) {
        if user.modes.invisible {
            self.invisible_users_count += 1;
        }
        if user.modes.wallops {
            self.wallops_users.insert(user.nick.clone());
        }
        if user.modes.is_local_oper() {
            self.operators_count += 1;
        }
        self.users.insert(user.nick.clone(), user);
        if self.users.len() > self.max_users_count {
            self.max_users_count = self.users.len();
        }
    }
    
    // remove user from channel and remove channel from user.
    // remove same channel if no more users at channel.
    fn remove_user_from_channel<'a>(&mut self, channel: &'a str, nick: &'a str) {
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
    fn remove_user(&mut self, nick: &str) {
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
            self.insert_to_nick_history(&nick.to_string(), user.history_entry.clone());
        }
    }
    
    // used to maintain nick history that is read by WHOWAS command.
    fn insert_to_nick_history(&mut self, old_nick: &String, nhe: NickHistoryEntry) {
        if !self.nick_histories.contains_key(old_nick) {
            self.nick_histories.insert(old_nick.to_string(), vec![]);
        }
        let nick_hist = self.nick_histories.get_mut(old_nick).unwrap();
        nick_hist.push(nhe);
    }
}

pub(crate) struct MainState {
    config: MainConfig,
    // key is user name
    user_config_idxs: HashMap<String, usize>,
    // key is oper name
    oper_config_idxs: HashMap<String, usize>,
    conns_count: Arc<AtomicUsize>,
    state: RwLock<VolatileState>,
    created: String,
}

impl MainState {
    pub(crate) fn new_from_config(config: MainConfig) -> MainState {
        // create indexes for configured users and operators.
        let mut user_config_idxs = HashMap::new();
        if let Some(ref users) = config.users {
            users.iter().enumerate().for_each(|(i,u)| { 
                user_config_idxs.insert(u.name.clone(), i); });
        }
        let mut oper_config_idxs = HashMap::new();
        if let Some(ref opers) = config.operators {
            opers.iter().enumerate().for_each(|(i,o)| {
                oper_config_idxs.insert(o.name.clone(), i); });
        }
        let state = RwLock::new(VolatileState::new_from_config(&config));
        MainState{ config, user_config_idxs, oper_config_idxs, state,
                conns_count: Arc::new(AtomicUsize::new(0)),
                created: Local::now().to_rfc2822() }
    }
    
    // try to register connection state - print error if too many connections.
    pub(crate) fn register_conn_state(&self, ip_addr: IpAddr,
                    stream: Framed<DualTcpStream, IRCLinesCodec>) -> Option<ConnState> {
        if let Some(max_conns) = self.config.max_connections {
            // increment counter of connections count.
            if self.conns_count.fetch_add(1, Ordering::SeqCst) < max_conns {
                Some(ConnState::new(ip_addr, stream, self.conns_count.clone()))
            } else {
                self.conns_count.fetch_sub(1, Ordering::SeqCst);
                error!("Too many connections for IP {}", ip_addr);
                None
            }
        } else {
            self.conns_count.fetch_add(1, Ordering::SeqCst);
            Some(ConnState::new(ip_addr, stream, self.conns_count.clone()))
        }
    }
    
    pub(crate) async fn remove_user(&self, conn_state: &ConnState)  {
        if let Some(ref nick) = conn_state.user_state.nick {
            let mut state = self.state.write().await;
            state.remove_user(nick);
        }
    }
    
    pub(crate) async fn process(&self, conn_state: &mut ConnState) -> Result<(), String> {
        // use conversion error to string to avoid problems with thread safety
        let res = self.process_internal(conn_state).await.map_err(|e| e.to_string());
        conn_state.stream.flush().await.map_err(|e| e.to_string())?;
        res
    }
    
    pub(crate) async fn get_quit_receiver(&self) -> oneshot::Receiver<String> {
        let mut state = self.state.write().await;
        state.quit_receiver.take().unwrap()
    }
    
    async fn process_internal(&self, conn_state: &mut ConnState)
                -> Result<(), Box<dyn Error>> {
        tokio::select! {
            Some(msg) = conn_state.receiver.recv() => {
                conn_state.stream.feed(msg).await?;
                Ok(())
            },
            Some(_) = conn_state.ping_receiver.recv() => {
                self.feed_msg(&mut conn_state.stream, "PING :LALAL").await?;
                conn_state.run_pong_timeout(&self.config);
                Ok(())
            }
            Some(_) = conn_state.timeout_receiver.recv() => {
                info!("Pong timeout for {}", conn_state.user_state.source);
                self.feed_msg(&mut conn_state.stream,
                            "ERROR :Pong timeout, connection will be closed.").await?;
                conn_state.quit.store(1, Ordering::SeqCst);
                Ok(())
            }
            Ok((killer, comment)) = &mut conn_state.quit_receiver => {
                info!("User {} killed by {}: {}", conn_state.user_state.source,
                            killer, comment);
                self.feed_msg(&mut conn_state.stream,
                        format!("ERROR :User killed by {}: {}", killer, comment)).await?;
                conn_state.quit.store(1, Ordering::SeqCst);
                Ok(())
            }
            Ok(hostname_opt) = &mut conn_state.dns_lookup_receiver => {
                #[cfg(feature = "dns_lookup")]
                if let Some(hostname) = hostname_opt {
                    conn_state.user_state.set_hostname(hostname);
                    if let Some(nick) = &conn_state.user_state.nick {
                        let mut state = self.state.write().await;
                        if let Some(user) = state.users.get_mut(nick) {
                            user.update_hostname(&conn_state.user_state);
                        }
                    }
                }
                #[cfg(not(feature = "dns_lookup"))]
                info!("Unexpected dns lookup: {:?}", hostname_opt);
                Ok(())
            }
            
            msg_str_res = conn_state.stream.next() => {
                let msg = match msg_str_res {
                    Some(Ok(ref msg_str)) => {
                        // try parse message from this line.
                        match Message::from_shared_str(&msg_str) {
                            Ok(msg) => msg,
                            Err(e) => {
                                match e {
                                    MessageError::Empty => {
                                        return Ok(())   // ignore empties
                                    }
                                    MessageError::WrongSource => {
                                        self.feed_msg(&mut conn_state.stream,
                                            "ERROR :Wrong source").await?;
                                    }
                                    MessageError::NoCommand => {
                                        self.feed_msg(&mut conn_state.stream,
                                            "ERROR :No command supplied").await?;
                                    }
                                }
                                return Err(Box::new(e));
                            }
                        }
                    }
                    // if line is longer than max line length.
                    Some(Err(LinesCodecError::MaxLineLengthExceeded)) => {
                        let client = conn_state.user_state.client_name();
                        self.feed_msg(&mut conn_state.stream,
                                    ErrInputTooLong417{ client }).await?;
                        return Ok(())
                    },
                    Some(Err(e)) => return Err(Box::new(e)),
                    // if end of stream
                    None => {
                        conn_state.quit.store(1, Ordering::SeqCst);
                        return Err(Box::new(io::Error::new(
                            io::ErrorKind::UnexpectedEof, "unexpected eof")))
                    }
                };
                
                let cmd = match Command::from_message(&msg) {
                    Ok(cmd) => cmd,
                    // handle errors while parsing command.
                    Err(e) => {
                        use crate::CommandError::*;
                        let client = conn_state.user_state.client_name();
                        match e {
                            UnknownCommand(ref cmd_name) => {
                                self.feed_msg(&mut conn_state.stream,
                                        ErrUnknownCommand421{ client,
                                        command: cmd_name }).await?;
                            }
                            UnknownSubcommand(_, _)|ParameterDoesntMatch(_, _)|
                                    WrongParameter(_, _) => {
                                self.feed_msg(&mut conn_state.stream,
                                        format!("ERROR :{}", e.to_string())).await?;
                            }
                            NeedMoreParams(command) => {
                                self.feed_msg(&mut conn_state.stream,
                                        ErrNeedMoreParams461{ client,
                                        command: command.name }).await?;
                            }
                            UnknownMode(_, modechar, ref channel) => {
                                self.feed_msg(&mut conn_state.stream,
                                        ErrUnknownMode472{ client,
                                        modechar, channel: channel }).await?;
                            }
                            UnknownUModeFlag(_) => {
                                self.feed_msg(&mut conn_state.stream,
                                        ErrUmodeUnknownFlag501{ client })
                                        .await?;
                            }
                            InvalidModeParam{ ref target, modechar, ref param,
                                    ref description } => {
                                self.feed_msg(&mut conn_state.stream,
                                        ErrInvalidModeParam696{ client,
                                        target, modechar, param, description }).await?;
                            }
                        }
                        return Err(Box::new(e));
                    }
                };
                
                use crate::Command::*;
                // if user not authenticated
                match cmd {
                    CAP{ .. } | AUTHENTICATE{ } | PASS{ .. } | NICK{ .. } |
                            USER{ .. } | QUIT{ } => {},
                    _ => {
                        // expect CAP, AUTHENTICATE, PASS, NICK, USER, QUIT -
                        // other commands need authenication.
                        if !conn_state.user_state.authenticated {
                            self.feed_msg(&mut conn_state.stream, ErrNotRegistered451{         
                                    client: conn_state.user_state.client_name() }).await?;
                            return Ok(())
                        }
                    }
                }
                
                match cmd {
                    CAP{ subcommand, caps, version } =>
                        self.process_cap(conn_state, subcommand, caps, version).await,
                    AUTHENTICATE{ } =>
                        self.process_authenticate(conn_state).await,
                    PASS{ password } =>
                        self.process_pass(conn_state, password).await,
                    NICK{ nickname } =>
                        self.process_nick(conn_state, nickname, &msg).await,
                    USER{ username, hostname, servername, realname } =>
                        self.process_user(conn_state, username, hostname,
                                servername, realname).await,
                    PING{ token } => self.process_ping(conn_state, token).await,
                    PONG{ token } => self.process_pong(conn_state, token).await,
                    OPER{ name, password } =>
                        self.process_oper(conn_state, name, password).await,
                    QUIT{ } => self.process_quit(conn_state).await,
                    JOIN{ channels, keys } =>
                        self.process_join(conn_state, channels, keys).await,
                    PART{ channels, reason } =>
                        self.process_part(conn_state, channels, reason).await,
                    TOPIC{ channel, topic } =>
                        self.process_topic(conn_state, channel, topic, &msg).await,
                    NAMES{ channels } =>
                        self.process_names(conn_state, channels).await,
                    LIST{ channels, server } =>
                        self.process_list(conn_state, channels, server).await,
                    INVITE{ nickname, channel } =>
                        self.process_invite(conn_state, nickname, channel, &msg).await,
                    KICK{ channel, users, comment } =>
                        self.process_kick(conn_state, channel, users, comment).await,
                    MOTD{ target } =>
                        self.process_motd(conn_state, target).await,
                    VERSION{ target } =>
                        self.process_version(conn_state, target).await,
                    ADMIN{ target } =>
                        self.process_admin(conn_state, target).await,
                    CONNECT{ target_server, port, remote_server } =>
                        self.process_connect(conn_state, target_server, port,
                                remote_server).await,
                    LUSERS{ } => self.process_lusers(conn_state).await,
                    TIME{ server } =>
                        self.process_time(conn_state, server).await,
                    STATS{ query, server } =>
                        self.process_stats(conn_state, query, server).await,
                    LINKS{ remote_server, server_mask } =>
                        self.process_links(conn_state, remote_server, server_mask).await,
                    HELP{ subject } =>
                        self.process_help(conn_state, subject).await,
                    INFO{ } => self.process_info(conn_state).await,
                    MODE{ target, modes } =>
                        self.process_mode(conn_state, target, modes).await,
                    PRIVMSG{ targets, text } =>
                        self.process_privmsg(conn_state, targets, text).await,
                    NOTICE{ targets, text } =>
                        self.process_notice(conn_state, targets, text).await,
                    WHO{ mask } => self.process_who(conn_state, mask).await,
                    WHOIS{ target, nickmasks } =>
                        self.process_whois(conn_state, target, nickmasks).await,
                    WHOWAS{ nickname, count, server } =>
                        self.process_whowas(conn_state, nickname, count, server).await,
                    KILL{ nickname, comment } =>
                        self.process_kill(conn_state, nickname, comment).await,
                    REHASH{ } => self.process_rehash(conn_state).await,
                    RESTART{ } => self.process_restart(conn_state).await,
                    SQUIT{ server, comment } =>
                        self.process_squit(conn_state, server, comment).await,
                    AWAY{ text } =>
                        self.process_away(conn_state, text).await,
                    USERHOST{ nicknames } =>
                        self.process_userhost(conn_state, nicknames).await, 
                    WALLOPS{ .. } =>
                        self.process_wallops(conn_state, &msg).await,
                }
            },
        }
    }
    
    // helper to feed messages
    async fn feed_msg<T: fmt::Display>(&self,
            stream: &mut Framed<DualTcpStream, IRCLinesCodec>, t: T)
            -> Result<(), LinesCodecError> {
        stream.feed(format!(":{} {}", self.config.name, t)).await
    }
    
    // helper to feed messages
    async fn feed_msg_source<T: fmt::Display>(&self,
            stream: &mut Framed<DualTcpStream, IRCLinesCodec>, source: &str, t: T)
            -> Result<(), LinesCodecError> {
        stream.feed(format!(":{} {}", source, t)).await
    }
}

// main process to handle commands from client.
async fn user_state_process(main_state: Arc<MainState>,
            stream: DualTcpStream, addr: SocketAddr) {
    let line_stream = Framed::new(stream, IRCLinesCodec::new_with_max_length(2000));
    if let Some(mut conn_state) = main_state.register_conn_state(addr.ip(), line_stream) {
        #[cfg(feature = "dns_lookup")]
        if main_state.config.dns_lookup {
            conn_state.run_dns_lookup();
        }
        #[cfg(not(feature = "dns_lookup"))]
        if main_state.config.dns_lookup {
            error!("DNS lookup is not enabled!");
        }
        
        while !conn_state.is_quit() {
            if let Err(e) = main_state.process(&mut conn_state).await {
                error!("Error for {}: {}", conn_state.user_state.source, e);
            }
        }
        info!("User {} gone from from server", conn_state.user_state.source);
        main_state.remove_user(&conn_state).await;
    }
}

#[cfg(feature = "tls_rustls")]
async fn user_state_process_tls(main_state: Arc<MainState>, stream: TcpStream,
            acceptor: TlsAcceptor, addr: SocketAddr) {
    match acceptor.accept(stream).await {
        Ok(tls_stream) => user_state_process(main_state,
                DualTcpStream::SecureStream(tls_stream), addr).await,
        Err(e) => error!("Can't accept TLS connection: {}", e),
    }
}

#[cfg(feature = "tls_openssl")]
async fn user_state_process_tls_prepare(stream: TcpStream, acceptor: Arc<SslAcceptor>)
        -> Result<SslStream<TcpStream>, String> {
    let ssl = Ssl::new(acceptor.context()).map_err(|e| e.to_string())?;
    let mut tls_stream = SslStream::new(ssl, stream).map_err(|e| e.to_string())?;
    use std::pin::Pin;
    Pin::new(&mut tls_stream).accept().await.map_err(|e| e.to_string())?;
    Ok(tls_stream)
}

#[cfg(feature = "tls_openssl")]
async fn user_state_process_tls(main_state: Arc<MainState>, stream: TcpStream,
            acceptor: Arc<SslAcceptor>, addr: SocketAddr) {
    match user_state_process_tls_prepare(stream, acceptor).await {
        Ok(stream) => user_state_process(main_state,
                DualTcpStream::SecureStream(stream), addr).await,
        Err(e) => error!("Can't accept TLS connection: {}", e),
    };
}

pub(crate) fn initialize_logging(config: &MainConfig) {
    use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};
    let s = tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()
        .add_directive(config.log_level.into()))
        .with_span_events(FmtSpan::FULL)
        .with_file(true).with_line_number(true).with_thread_ids(true)
        // disable ansi color for files
        .with_ansi(config.log_file.is_none());
    if let Some(ref log_file) = config.log_file {
        if let Ok(f) = File::create(log_file) {
            s.with_writer(f).init();
        } else {
            error!("No log file {}", log_file);
            s.init()
        }
    } else { s.init(); }
}

#[cfg(feature = "dns_lookup")]
lazy_static! {
    static ref DNS_RESOLVER: std::sync::RwLock<Option<Arc::<TokioAsyncResolver>>> =
                std::sync::RwLock::new(None);
}

#[cfg(feature = "dns_lookup")]
fn initialize_dns_resolver() {
    let mut r = DNS_RESOLVER.write().unwrap();
    if r.is_none() {
        *r = Some(Arc::new({
            // for windows or linux
            #[cfg(any(unix, windows))]
            { // use the system resolver configuration
                TokioAsyncResolver::from_system_conf(TokioHandle)
            }

            // for other
            #[cfg(not(any(unix, windows)))]
            {
                // Directly reference the config types
                use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

                // Get a new resolver with the google nameservers as
                // the upstream recursive resolvers
                TokioAsyncResolver::tokio(
                    ResolverConfig::google(),
                    ResolverOpts::default())
            }
        }.expect("failed to create resolver")));
    }
}

#[cfg(feature = "dns_lookup")]
fn dns_lookup(sender: oneshot::Sender<Option<String>>, ip: IpAddr) {
    let r = DNS_RESOLVER.read().unwrap();
    let resolver = (*r).clone().unwrap();
    tokio::spawn(dns_lookup_process(resolver.clone(), sender, ip));
}

#[cfg(feature = "dns_lookup")]
async fn dns_lookup_process(resolver: Arc<TokioAsyncResolver>,
                sender: oneshot::Sender<Option<String>>, ip: IpAddr) {
    let r = match resolver.reverse_lookup(ip).await {
        Ok(lookup) => {
            if let Some(x) = lookup.iter().next() {
                let namex = x.to_string();
                let name = if namex.as_bytes()[namex.len()-1] == b'.' {
                    namex[..namex.len()-1].to_string()
                } else { namex };
                sender.send(Some(name))
            } else { sender.send(None) }
        }
        Err(_) => { sender.send(None) }
    };
    if r.is_err() {
        error!("Error while sending dns lookup");
    }
}

// main routine to run server
pub(crate) async fn run_server(config: MainConfig) ->
        Result<(Arc<MainState>, JoinHandle<()>), Box<dyn Error>> {
    #[cfg(feature = "dns_lookup")]
    if config.dns_lookup {
        initialize_dns_resolver();
    }
    let listener = TcpListener::bind((config.listen, config.port)).await?;
    let cloned_tls = config.tls.clone();
    let main_state = Arc::new(MainState::new_from_config(config));
    let main_state_to_return = main_state.clone();
    let handle = if cloned_tls.is_some() {
        
        #[cfg(feature = "tls_rustls")]
        {
        let config = {
            let tlsconfig = cloned_tls.unwrap();
            let certs = rustls_pemfile::certs(
                    &mut BufReader::new(File::open(tlsconfig.cert_file.clone())?))
                    .map(|mut certs| certs.drain(..).map(Certificate).collect())?;
            let mut keys: Vec<PrivateKey> = rustls_pemfile::pkcs8_private_keys(
                    &mut BufReader::new(File::open(tlsconfig.cert_key_file.clone())?))
                    .map(|mut keys| keys.drain(..).map(PrivateKey).collect())?;
            
            rustls::ServerConfig::builder().with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(certs, keys.remove(0))
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?
        };
            
        let acceptor = TlsAcceptor::from(Arc::new(config));
        tokio::spawn(async move {
            let mut quit_receiver = main_state.get_quit_receiver().await;
            let mut do_quit = false;
            while !do_quit {
                tokio::select! {
                    res = listener.accept() => {
                        match res {
                            Ok((stream, addr)) => {
                                tokio::spawn(user_state_process_tls(main_state.clone(),
                                        stream, acceptor.clone(), addr));
                            }
                            Err(e) => { error!("Accept connection error: {}", e); }
                        };
                    }
                    Ok(msg) = &mut quit_receiver => {
                        info!("Server quit: {}", msg);
                        do_quit = true;
                    }
                };
            }
        })
        }
        
        #[cfg(feature = "tls_openssl")]
        {
        let tlsconfig = cloned_tls.unwrap();
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        acceptor.set_private_key_file(tlsconfig.cert_key_file, SslFiletype::PEM)?;
        acceptor.set_certificate_chain_file(tlsconfig.cert_file)?;
        let acceptor = Arc::new(acceptor.build());
        
        tokio::spawn(async move {
            let mut quit_receiver = main_state.get_quit_receiver().await;
            let mut do_quit = false;
            while !do_quit {
                tokio::select! {
                    res = listener.accept() => {
                        match res {
                            Ok((stream, addr)) => {
                                tokio::spawn(user_state_process_tls(main_state.clone(),
                                        stream, acceptor.clone(), addr));
                            }
                            Err(e) => { error!("Accept connection error: {}", e); }
                        };
                    }
                    Ok(msg) = &mut quit_receiver => {
                        info!("Server quit: {}", msg);
                        do_quit = true;
                    }
                };
            }
        })
        }
       
        
        #[cfg(not(any(feature = "tls_rustls", feature = "tls_openssl")))]
        tokio::spawn(async move {
            error!("Unsupported TLS")
        })
    } else {
        tokio::spawn(async move {
            let mut quit_receiver = main_state.get_quit_receiver().await;
            let mut do_quit = false;
            while !do_quit {
                tokio::select! {
                    res = listener.accept() => {
                        match res {
                            Ok((stream, addr)) => {
                                tokio::spawn(user_state_process(main_state.clone(),
                                        DualTcpStream::PlainStream(stream), addr)); }
                            Err(e) => { error!("Accept connection error: {}", e); }
                        };
                    }
                    Ok(msg) = &mut quit_receiver => {
                        info!("Server quit: {}", msg);
                        do_quit = true;
                    }
                };
            }
        })
    };
    Ok((main_state_to_return, handle))
}

#[cfg(test)]
mod test {
    use std::iter::FromIterator;
    use tokio::net::TcpStream;
    use super::*;
    
    #[test]
    fn test_user_new() {
        let mut config = MainConfig::default();
        config.default_user_modes = UserModes{ invisible: true, oper: false,
                local_oper: false, registered: true, wallops: false };
        let user_state = ConnUserState{
            ip_addr: "127.0.0.1".parse().unwrap(),
            hostname: "bobby.com".to_string(),
            name: Some("mati1".to_string()),
            realname: Some("Matthew Somebody".to_string()),
            nick: Some("matix".to_string()),
            source: "matix!mati1@bobby.com".to_string(),
            password: None, authenticated: true, registered: true };
        let (sender, _) = unbounded_channel();
        let (quit_sender, _) = oneshot::channel();
        let user = User::new(&config, &user_state, sender, quit_sender);
        
        assert_eq!(user_state.hostname, user.hostname);
        assert_eq!(user_state.source, user.source);
        assert_eq!(user_state.realname.unwrap(), user.realname);
        assert_eq!(user_state.name.unwrap(), user.name);
        assert_eq!(user_state.nick.unwrap(), user.nick);
        assert_eq!(config.default_user_modes, user.modes);
        
        assert_eq!(NickHistoryEntry{ username: user.name.clone(),
            hostname: user.hostname.clone(), realname: user.realname.clone(),
            signon: user.signon }, user.history_entry);
    }
    
    #[test]
    fn test_channel_user_modes() {
        let chum = ChannelUserModes{ founder: false, protected: false, voice: false,
                operator: false, half_oper: false };
        assert!(!chum.is_protected());
        assert!(!chum.is_operator());
        assert!(!chum.is_half_operator());
        assert!(!chum.is_only_half_operator());
        assert!(!chum.is_voice());
        
        let chum = ChannelUserModes{ founder: true, protected: false, voice: false,
                operator: false, half_oper: false };
        assert!(chum.is_protected());
        assert!(chum.is_operator());
        assert!(chum.is_half_operator());
        assert!(!chum.is_only_half_operator());
        assert!(chum.is_voice());
        
        let chum = ChannelUserModes{ founder: false, protected: true, voice: false,
                operator: false, half_oper: false };
        assert!(chum.is_protected());
        assert!(chum.is_operator());
        assert!(chum.is_half_operator());
        assert!(!chum.is_only_half_operator());
        assert!(chum.is_voice());
        
        let chum = ChannelUserModes{ founder: false, protected: false, voice: false,
                operator: true, half_oper: false };
        assert!(!chum.is_protected());
        assert!(chum.is_operator());
        assert!(chum.is_half_operator());
        assert!(!chum.is_only_half_operator());
        assert!(chum.is_voice());
        
        let chum = ChannelUserModes{ founder: false, protected: false, voice: false,
                operator: true, half_oper: true };
        assert!(!chum.is_protected());
        assert!(chum.is_operator());
        assert!(chum.is_half_operator());
        assert!(!chum.is_only_half_operator());
        assert!(chum.is_voice());
        
        let chum = ChannelUserModes{ founder: false, protected: false, voice: false,
                operator: false, half_oper: true };
        assert!(!chum.is_protected());
        assert!(!chum.is_operator());
        assert!(chum.is_half_operator());
        assert!(chum.is_only_half_operator());
        assert!(chum.is_voice());
        
        let chum = ChannelUserModes{ founder: false, protected: false, voice: true,
                operator: false, half_oper: false };
        assert!(!chum.is_protected());
        assert!(!chum.is_operator());
        assert!(!chum.is_half_operator());
        assert!(!chum.is_only_half_operator());
        assert!(chum.is_voice());
    }
    
    #[test]
    fn test_channel_user_modes_to_string() {
        let chum = ChannelUserModes{ founder: true, protected: true, voice: false,
                operator: true, half_oper: false };
        assert_eq!("~", chum.to_string(&CapState{ multi_prefix: false }));
        assert_eq!("~&@", chum.to_string(&CapState{ multi_prefix: true }));
        
        let chum = ChannelUserModes{ founder: false, protected: false, voice: true,
                operator: false, half_oper: true };
        assert_eq!("%", chum.to_string(&CapState{ multi_prefix: false }));
        assert_eq!("%+", chum.to_string(&CapState{ multi_prefix: true }));
    }
    
    #[test]
    fn test_get_privmsg_target_type() {
        use PrivMsgTargetType::*;
        assert_eq!((Channel.into(), "#abc"), get_privmsg_target_type("#abc"));
        assert_eq!((Channel.into(), "&abc"), get_privmsg_target_type("&abc"));
        assert_eq!((Channel | ChannelFounder, "#abc"), get_privmsg_target_type("~#abc"));
        assert_eq!((Channel | ChannelFounder, "&abc"), get_privmsg_target_type("~&abc"));
        assert_eq!((Channel | ChannelProtected, "#abc"), get_privmsg_target_type("&#abc"));
        assert_eq!((Channel | ChannelProtected, "&abc"), get_privmsg_target_type("&&abc"));
        assert_eq!((Channel | ChannelVoice, "#abc"), get_privmsg_target_type("+#abc"));
        assert_eq!((Channel | ChannelVoice, "&abc"), get_privmsg_target_type("+&abc"));
        assert_eq!((Channel | ChannelHalfOper, "#abc"), get_privmsg_target_type("%#abc"));
        assert_eq!((Channel | ChannelHalfOper, "&abc"), get_privmsg_target_type("%&abc"));
        assert_eq!((Channel | ChannelVoice | ChannelFounder, "#abc"),
                    get_privmsg_target_type("+~#abc"));
        assert_eq!((Channel | ChannelVoice | ChannelFounder, "&abc"),
                    get_privmsg_target_type("+~&abc"));
        assert_eq!((Channel | ChannelOper, "#abc"), get_privmsg_target_type("@#abc"));
        assert_eq!((Channel | ChannelOper, "&abc"), get_privmsg_target_type("@&abc"));
        assert_eq!((Channel | ChannelOper | ChannelProtected, "#abc"),
                    get_privmsg_target_type("&@#abc"));
        assert_eq!((Channel | ChannelOper | ChannelProtected, "&abc"),
                    get_privmsg_target_type("&@&abc"));
        assert_eq!((FlagSet::new(0).unwrap(), ""), get_privmsg_target_type("abc"));
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
        let exp_chdm = ChannelDefaultModes{
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
        let exp_chdm = ChannelDefaultModes{
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
        let channel = Channel::new("#bobby".to_string(), "dizzy".to_string());
        assert_eq!(Channel{ name: "#bobby".to_string(), topic: None,
            modes: ChannelModes::new_for_channel("dizzy".to_string()),
            default_modes: ChannelDefaultModes::default(),
            ban_info: HashMap::new(), users:
                [("dizzy".to_string(), ChannelUserModes::new_for_created_channel())].into(),
            creation_time: channel.creation_time, preconfigured: false }, channel);
    }
    
    #[test]
    fn test_channel_join_remove_user() {
        let mut channel = Channel::new("#bicycles".to_string(), "runner".to_string());
        channel.default_modes.founders.insert("fasty".to_string());
        channel.default_modes.protecteds.insert("quicker".to_string());
        channel.default_modes.operators.insert("leader".to_string());
        channel.default_modes.half_operators.insert("rover".to_string());
        channel.default_modes.voices.insert("cyclist".to_string());
        channel.add_user(&"fasty".to_string());
        channel.add_user(&"quicker".to_string());
        channel.add_user(&"leader".to_string());
        channel.add_user(&"rover".to_string());
        channel.add_user(&"cyclist".to_string());
        channel.add_user(&"doer".to_string());
        
        let mut exp_channel = Channel::new("#bicycles".to_string(), "runner".to_string());
        exp_channel.default_modes = channel.default_modes.clone();
        exp_channel.users.insert("fasty".to_string(), ChannelUserModes{ founder: true,
                protected: false, operator: false, half_oper: false, voice: false });
        exp_channel.users.insert("quicker".to_string(), ChannelUserModes{ founder: false,
                protected: true, operator: false, half_oper: false, voice: false });
        exp_channel.users.insert("leader".to_string(), ChannelUserModes{ founder: false,
                protected: false, operator: true, half_oper: false, voice: false });
        exp_channel.users.insert("rover".to_string(), ChannelUserModes{ founder: false,
                protected: false, operator: false, half_oper: true, voice: false });
        exp_channel.users.insert("cyclist".to_string(), ChannelUserModes{ founder: false,
                protected: false, operator: false, half_oper: false, voice: true });
        exp_channel.users.insert("doer".to_string(), ChannelUserModes::default());
        exp_channel.modes.founders = Some(["fasty".to_string(),
                    "runner".to_string()].into());
        exp_channel.modes.protecteds= Some(["quicker".to_string()].into());
        exp_channel.modes.operators = Some(["leader".to_string(),
                    "runner".to_string()].into());
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
        let mut channel = Channel::new("#bobby".to_string(), "dizzy".to_string());
        channel.rename_user(&"dizzy".to_string(), "diggy".to_string());
        assert_eq!(Channel{ name: "#bobby".to_string(), topic: None,
            modes: ChannelModes::new_for_channel("diggy".to_string()),
            default_modes: ChannelDefaultModes::default(),
            ban_info: HashMap::new(), users:
                [("diggy".to_string(), ChannelUserModes::new_for_created_channel())].into(),
            creation_time: channel.creation_time, preconfigured: false }, channel);
    }
    
    #[test]
    fn test_channel_add_remove_mode() {
        let mut channel = Channel::new("#bobby".to_string(), "dizzy".to_string());
        
        let mut exp_channel = Channel{ name: "#bobby".to_string(), topic: None,
            modes: ChannelModes::new_for_channel("dizzy".to_string()),
            default_modes: ChannelDefaultModes::default(),
            ban_info: HashMap::new(), users: [("dizzy".to_string(), 
                        ChannelUserModes::new_for_created_channel()),
                    ("inventor".to_string(), ChannelUserModes::default()),
                    ("guru".to_string(), ChannelUserModes::default()),
                    ("halfguru".to_string(), ChannelUserModes::default()),
                    ("vip".to_string(), ChannelUserModes::default()),
                    ("talker".to_string(), ChannelUserModes::default())].into(),
            creation_time: channel.creation_time, preconfigured: false };
        
        channel.users.insert("inventor".to_string(), ChannelUserModes::default());
        channel.users.insert("guru".to_string(), ChannelUserModes::default());
        channel.users.insert("halfguru".to_string(), ChannelUserModes::default());
        channel.users.insert("vip".to_string(), ChannelUserModes::default());
        channel.users.insert("talker".to_string(), ChannelUserModes::default());
        
        channel.add_founder("inventor");
        exp_channel.modes.founders =
                Some([ "dizzy".to_string(), "inventor".to_string()].into());
        exp_channel.users.insert("inventor".to_string(), ChannelUserModes{ founder: true,
                protected: false, operator: false, half_oper: false, voice: false });
        assert_eq!(exp_channel, channel);
        
        channel.remove_founder("inventor");
        exp_channel.modes.founders = Some([ "dizzy".to_string()].into());
        exp_channel.users.insert("inventor".to_string(), ChannelUserModes::default());
        assert_eq!(exp_channel, channel);
        
        channel.add_operator("guru");
        exp_channel.modes.operators =
                Some([ "dizzy".to_string(), "guru".to_string()].into());
        exp_channel.users.insert("guru".to_string(), ChannelUserModes{ founder: false,
                protected: false, operator: true, half_oper: false, voice: false });
        assert_eq!(exp_channel, channel);
        
        channel.remove_operator("guru");
        exp_channel.modes.operators = Some([ "dizzy".to_string()].into());
        exp_channel.users.insert("guru".to_string(), ChannelUserModes::default());
        assert_eq!(exp_channel, channel);
        
        channel.add_half_operator("halfguru");
        exp_channel.modes.half_operators = Some(["halfguru".to_string()].into());
        exp_channel.users.insert("halfguru".to_string(), ChannelUserModes{ founder: false,
                protected: false, operator: false, half_oper: true, voice: false });
        assert_eq!(exp_channel, channel);
        
        channel.remove_half_operator("halfguru");
        exp_channel.modes.half_operators = Some(HashSet::new());
        exp_channel.users.insert("halfguru".to_string(), ChannelUserModes::default());
        assert_eq!(exp_channel, channel);
        
        channel.add_protected("vip");
        exp_channel.modes.protecteds = Some(["vip".to_string()].into());
        exp_channel.users.insert("vip".to_string(), ChannelUserModes{ founder: false,
                protected: true, operator: false, half_oper: false, voice: false });
        assert_eq!(exp_channel, channel);
        
        channel.remove_protected("vip");
        exp_channel.modes.protecteds = Some(HashSet::new());
        exp_channel.users.insert("vip".to_string(), ChannelUserModes::default());
        assert_eq!(exp_channel, channel);
        
        channel.add_voice("talker");
        exp_channel.modes.voices = Some(["talker".to_string()].into());
        exp_channel.users.insert("talker".to_string(), ChannelUserModes{ founder: false,
                protected: false, operator: false, half_oper: false, voice: true });
        assert_eq!(exp_channel, channel);
        
        channel.remove_voice("talker");
        exp_channel.modes.voices = Some(HashSet::new());
        exp_channel.users.insert("talker".to_string(), ChannelUserModes::default());
        assert_eq!(exp_channel, channel);
    }
    
    #[test]
    fn test_conn_user_state() {
        let mut cus = ConnUserState::new("192.168.1.7".parse().unwrap());
        assert_eq!(ConnUserState{ ip_addr: "192.168.1.7".parse().unwrap(),
                hostname: "192.168.1.7".to_string(), name: None,
                realname: None, nick: None, source: "@192.168.1.7".to_string(),
                password: None, authenticated: false, registered: false }, cus);
        assert_eq!("192.168.1.7", cus.client_name());
        cus.set_name("boro".to_string());
        assert_eq!(ConnUserState{ ip_addr: "192.168.1.7".parse().unwrap(),
                hostname: "192.168.1.7".to_string(),
                name: Some("boro".to_string()),
                realname: None, nick: None, source: "~boro@192.168.1.7".to_string(),
                password: None, authenticated: false, registered: false }, cus);
        assert_eq!("boro", cus.client_name());
        cus.set_nick("buru".to_string());
        assert_eq!(ConnUserState{ ip_addr: "192.168.1.7".parse().unwrap(),
                hostname: "192.168.1.7".to_string(),
                name: Some("boro".to_string()),
                realname: None, nick: Some("buru".to_string()),
                source: "buru!~boro@192.168.1.7".to_string(),
                password: None, authenticated: false, registered: false }, cus);
        assert_eq!("buru", cus.client_name());
        
        let mut cus = ConnUserState::new("192.168.1.7".parse().unwrap());
        assert_eq!(ConnUserState{ ip_addr: "192.168.1.7".parse().unwrap(),
                hostname: "192.168.1.7".to_string(), name: None,
                realname: None, nick: None, source: "@192.168.1.7".to_string(),
                password: None, authenticated: false, registered: false }, cus);
        assert_eq!("192.168.1.7", cus.client_name());
        cus.set_nick("boro".to_string());
        assert_eq!(ConnUserState{ ip_addr: "192.168.1.7".parse().unwrap(),
                hostname: "192.168.1.7".to_string(),
                nick: Some("boro".to_string()),
                realname: None, name: None, source: "boro!@192.168.1.7".to_string(),
                password: None, authenticated: false, registered: false }, cus);
        assert_eq!("boro", cus.client_name());
        cus.set_name("buru".to_string());
        assert_eq!(ConnUserState{ ip_addr: "192.168.1.7".parse().unwrap(),
                hostname: "192.168.1.7".to_string(),
                nick: Some("boro".to_string()),
                realname: None, name: Some("buru".to_string()),
                source: "boro!~buru@192.168.1.7".to_string(),
                password: None, authenticated: false, registered: false }, cus);
        assert_eq!("boro", cus.client_name());
    }
    
    #[test]
    fn test_volatile_state_new() {
        let mut config = MainConfig::default();
        config.channels = Some(vec![
            ChannelConfig{ name: "#gooddays".to_string(),
                topic: Some("About good days".to_string()),
                modes: ChannelModes::default() },
            ChannelConfig{ name: "#pets".to_string(),
                topic: Some("About pets".to_string()),
                modes: ChannelModes::default() },
            ChannelConfig{ name: "&cactuses".to_string(), topic: None,
                modes: ChannelModes::default() } ]);
        let state = VolatileState::new_from_config(&config);
        assert_eq!(HashMap::from([("#gooddays".to_string(),
                    Channel{ name: "#gooddays".to_string(),
                        topic: Some(ChannelTopic::new("About good days".to_string())),
                        modes: ChannelModes::default(),
                        default_modes: ChannelDefaultModes::default(),
                        ban_info: HashMap::new(), users: HashMap::new(),
                        creation_time: state.channels.get("#gooddays")
                                    .unwrap().creation_time,
                        preconfigured: true }),
                    ("#pets".to_string(),
                    Channel{ name: "#pets".to_string(),
                        topic: Some(ChannelTopic::new("About pets".to_string())),
                        modes: ChannelModes::default(),
                        default_modes: ChannelDefaultModes::default(),
                        ban_info: HashMap::new(), users: HashMap::new(),
                        creation_time: state.channels.get("#pets")
                                    .unwrap().creation_time,
                        preconfigured: true }),
                    ("&cactuses".to_string(),
                    Channel{ name: "&cactuses".to_string(), topic: None,
                        modes: ChannelModes::default(),
                        default_modes: ChannelDefaultModes::default(),
                        ban_info: HashMap::new(), users: HashMap::new(),
                        creation_time: state.channels.get("&cactuses")
                                    .unwrap().creation_time,
                        preconfigured: true })]),
                state.channels);
    }
    
    #[test]
    fn test_volatile_remove_user_from_channel() {
        let mut config = MainConfig::default();
        config.channels = Some(vec![
            ChannelConfig{ name: "#something".to_string(), topic: None,
                        modes: ChannelModes::default() } ]);
        let mut state = VolatileState::new_from_config(&config);
        let user_state = ConnUserState{ ip_addr: "127.0.0.1".parse().unwrap(),
            hostname: "bobby.com".to_string(),
            name: Some("matix".to_string()),
            realname: Some("Matthew Somebody".to_string()),
            nick: Some("matixi".to_string()),
            source: "matixi!matix@bobby.com".to_string(),
            password: None, authenticated: true, registered: true };
        let (sender, _) = unbounded_channel();
        let (quit_sender, _) = oneshot::channel();
        let user = User::new(&config, &user_state, sender, quit_sender);
        state.add_user(user);
        
        // create channels and add channel to user structure
        [("#matixichan", "matixi"), ("#tulipchan", "matixi")].iter()
            .for_each(|(chname, nick)| {
            state.channels.insert(chname.to_string(),
                    Channel::new(chname.to_string(), nick.to_string()));
            state.users.get_mut(&nick.to_string()).unwrap().channels.insert(
                        chname.to_string());
        });
        state.channels.get_mut(&"#something".to_string()).unwrap().users
                .insert("matixi".to_string(), ChannelUserModes::default());
        state.users.get_mut("matixi").unwrap().channels.insert("#something".to_string());
        
        state.remove_user_from_channel("#something", "matixi");
        assert!(state.channels.contains_key("#something"));
        assert_eq!(HashMap::new(), state.channels.get("#something").unwrap().users);
        state.remove_user_from_channel("#matixichan", "matixi");
        assert!(!state.channels.contains_key("#matixichan"));
        state.remove_user_from_channel("#tulipan", "matixi");
        assert!(!state.channels.contains_key("#tulipan"));
    }
    
    #[test]
    fn test_volatile_state_add_remove_user() {
        let mut config = MainConfig::default();
        config.channels = Some(vec![
            ChannelConfig{ name: "#something".to_string(), topic: None,
                        modes: ChannelModes::default() } ]);
        let mut state = VolatileState::new_from_config(&config);
        
        let user_state = ConnUserState{ ip_addr: "127.0.0.1".parse().unwrap(),
            hostname: "bobby.com".to_string(),
            name: Some("matix".to_string()),
            realname: Some("Matthew Somebody".to_string()),
            nick: Some("matixi".to_string()),
            source: "matixi!matix@bobby.com".to_string(),
            password: None, authenticated: true, registered: true };
        let (sender, _) = unbounded_channel();
        let (quit_sender, _) = oneshot::channel();
        let user = User::new(&config, &user_state, sender, quit_sender);
        state.add_user(user);
        assert_eq!(1, state.max_users_count);
        
        let user_state = ConnUserState{ ip_addr: "127.0.0.1".parse().unwrap(),
            hostname: "flowers.com".to_string(),
            name: Some("tulip".to_string()),
            realname: Some("Tulipan".to_string()),
            nick: Some("tulipan".to_string()),
            source: "tulipan!tulip@flowers.com".to_string(),
            password: None, authenticated: true, registered: true };
        let (sender, _) = unbounded_channel();
        let (quit_sender, _) = oneshot::channel();
        let user = User::new(&config, &user_state, sender, quit_sender);
        state.add_user(user);
        assert_eq!(2, state.max_users_count);
        
        let user_state = ConnUserState{ ip_addr: "127.0.0.1".parse().unwrap(),
            hostname: "digger.com".to_string(),
            name: Some("greggy".to_string()),
            realname: Some("Gregory Digger".to_string()),
            nick: Some("greg".to_string()),
            source: "greg!greggy@digger.com".to_string(),
            password: None, authenticated: true, registered: true };
        let (sender, _) = unbounded_channel();
        let (quit_sender, _) = oneshot::channel();
        let mut user = User::new(&config, &user_state, sender, quit_sender);
        user.modes.invisible = true;
        state.add_user(user);
        assert_eq!(3, state.max_users_count);
        assert_eq!(1, state.invisible_users_count);
        
        let user_state = ConnUserState{ ip_addr: "127.0.0.1".parse().unwrap(),
            hostname: "miller.com".to_string(),
            name: Some("johnny".to_string()),
            realname: Some("John Miller".to_string()),
            nick: Some("john".to_string()),
            source: "john!johnny@miller.com".to_string(),
            password: None, authenticated: true, registered: true };
        let (sender, _) = unbounded_channel();
        let (quit_sender, _) = oneshot::channel();
        let mut user = User::new(&config, &user_state, sender, quit_sender);
        user.modes.wallops = true;
        state.add_user(user);
        assert_eq!(4, state.max_users_count);
        assert_eq!(1, state.invisible_users_count);
        assert_eq!(HashSet::from(["john".to_string()]), state.wallops_users);
        
        let user_state = ConnUserState{ ip_addr: "127.0.0.1".parse().unwrap(),
            hostname: "guru.com".to_string(),
            name: Some("admin".to_string()),
            realname: Some("Great Admin".to_string()),
            nick: Some("admini".to_string()),
            source: "admini!admin@guru.com".to_string(),
            password: None, authenticated: true, registered: true };
        let (sender, _) = unbounded_channel();
        let (quit_sender, _) = oneshot::channel();
        let mut user = User::new(&config, &user_state, sender, quit_sender);
        user.modes.oper = true;
        state.add_user(user);
        assert_eq!(5, state.max_users_count);
        assert_eq!(1, state.invisible_users_count);
        assert_eq!(1, state.operators_count);
        
        assert_eq!(HashSet::from(["matixi".to_string(), "tulipan".to_string(),
                    "greg".to_string(), "john".to_string(), "admini".to_string()]),
                    HashSet::from_iter(state.users.keys().cloned()));
        assert_eq!(HashSet::from(["matix".to_string(), "tulip".to_string(),
                    "greggy".to_string(), "johnny".to_string(), "admin".to_string()]),
                    HashSet::from_iter(state.users.values().map(|u| u.name.clone())));
        assert_eq!(HashSet::from(["Matthew Somebody".to_string(), "Tulipan".to_string(),
                    "Gregory Digger".to_string(), "John Miller".to_string(),
                    "Great Admin".to_string()]),
                    HashSet::from_iter(state.users.values().map(|u| u.realname.clone())));
        
        // create channels and add channel to user structure
        [("#matixichan", "matixi"), ("#tulipchan", "tulipan"),
         ("#gregchan", "greg"), ("#johnchan", "john"), ("#guruchan", "admini")].iter()
            .for_each(|(chname, nick)| {
            state.channels.insert(chname.to_string(),
                    Channel::new(chname.to_string(), nick.to_string()));
            state.users.get_mut(&nick.to_string()).unwrap().channels.insert(
                        chname.to_string());
        });
        state.channels.get_mut("#something").unwrap().users.insert("john".to_string(),
                        ChannelUserModes::default());
        state.users.get_mut("john").unwrap().channels.insert("#something".to_string());
        
        // removing users
        state.remove_user("matixi");
        assert_eq!(5, state.max_users_count);
        assert_eq!(1, state.invisible_users_count);
        assert_eq!(1, state.operators_count);
        assert_eq!(HashSet::from(["john".to_string()]), state.wallops_users);
        
        assert_eq!(HashSet::from(["tulipan".to_string(),
                    "greg".to_string(), "john".to_string(), "admini".to_string()]),
                    HashSet::from_iter(state.users.keys().cloned()));
        assert_eq!(HashSet::from(["tulip".to_string(),
                    "greggy".to_string(), "johnny".to_string(), "admin".to_string()]),
                    HashSet::from_iter(state.users.values().map(|u| u.name.clone())));
        assert!(!state.channels.contains_key("#matixichan"));
        
        state.remove_user("greg");
        assert_eq!(5, state.max_users_count);
        assert_eq!(0, state.invisible_users_count);
        assert_eq!(1, state.operators_count);
        assert_eq!(HashSet::from(["john".to_string()]), state.wallops_users);
        
        assert_eq!(HashSet::from(["tulipan".to_string(), "john".to_string(),
                    "admini".to_string()]), HashSet::from_iter(state.users.keys().cloned()));
        assert_eq!(HashSet::from(["tulip".to_string(), "johnny".to_string(),
                    "admin".to_string()]),
                    HashSet::from_iter(state.users.values().map(|u| u.name.clone())));
        assert!(!state.channels.contains_key("#gregchan"));
        
        state.remove_user("john");
        assert_eq!(5, state.max_users_count);
        assert_eq!(0, state.invisible_users_count);
        assert_eq!(1, state.operators_count);
        assert_eq!(HashSet::new(), state.wallops_users);
        
        assert_eq!(HashSet::from(["tulipan".to_string(), "admini".to_string()]),
                    HashSet::from_iter(state.users.keys().cloned()));
        assert_eq!(HashSet::from(["tulip".to_string(), "admin".to_string()]),
                    HashSet::from_iter(state.users.values().map(|u| u.name.clone())));
        assert!(!state.channels.contains_key("#johnchan"));
        assert!(state.channels.contains_key("#something"));
        
        state.remove_user("admini");
        assert_eq!(5, state.max_users_count);
        assert_eq!(0, state.invisible_users_count);
        assert_eq!(0, state.operators_count);
        assert_eq!(HashSet::new(), state.wallops_users);
        assert_eq!(HashSet::from(["tulipan".to_string()]),
                    HashSet::from_iter(state.users.keys().cloned()));
        assert_eq!(HashSet::from(["tulip".to_string()]),
                    HashSet::from_iter(state.users.values().map(|u| u.name.clone())));
        assert!(!state.channels.contains_key("#guruchan"));
    }
    
    #[test]
    fn test_volatile_state_insert_to_nick_history() {
        let config = MainConfig::default();
        let mut state = VolatileState::new_from_config(&config);
        state.insert_to_nick_history(&"mati".to_string(), NickHistoryEntry{
                username: "mati1".to_string(), hostname: "gugg.com".to_string(),
                realname: "Mati1".to_string(), signon: 12344555555 });
        state.insert_to_nick_history(&"mati".to_string(), NickHistoryEntry{
                username: "mati2".to_string(), hostname: "bip.com".to_string(),
                realname: "Mati2".to_string(), signon: 12377411100 });
        assert_eq!(HashMap::from([("mati".to_string(), vec![NickHistoryEntry{
                username: "mati1".to_string(), hostname: "gugg.com".to_string(),
                realname: "Mati1".to_string(), signon: 12344555555 },
                NickHistoryEntry{
                username: "mati2".to_string(), hostname: "bip.com".to_string(),
                realname: "Mati2".to_string(), signon: 12377411100 }])]),
                state.nick_histories);
    }
    
    use std::sync::atomic::AtomicU16;
    
    static PORT_COUNTER: AtomicU16 = AtomicU16::new(7888);
    //use std::sync::Once;
    //static LOGGING_START: Once = Once::new();
    
    pub(crate) async fn run_test_server(config: MainConfig)
            -> (Arc<MainState>, JoinHandle<()>, u16) {
        //LOGGING_START.call_once(|| {
        //    initialize_logging(&MainConfig::default());
        //});
        let mut config = config;
        config.port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let port = config.port;
        let (main_state, handle) = run_server(config).await.unwrap();
        (main_state, handle, port)
    }
    
    pub(crate) async fn quit_test_server(main_state: Arc<MainState>,
                        handle: JoinHandle<()>) {
        main_state.state.write().await.quit_sender.take().unwrap()
                .send("Test".to_string()).unwrap();
        handle.await.unwrap();
    }
    
    pub(crate) async fn connect_to_test(port: u16)
                    -> Framed<TcpStream, IRCLinesCodec> {
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        Framed::new(stream, IRCLinesCodec::new_with_max_length(2000))
    }
    
    pub(crate) async fn login_to_test<'a>(port: u16, nick: &'a str, name: &'a str,
                realname: &'a str) -> Framed<TcpStream, IRCLinesCodec> {
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut line_stream = Framed::new(stream, IRCLinesCodec::new_with_max_length(2000));
        line_stream.send(format!("NICK {}", nick)).await.unwrap();
        line_stream.send(format!("USER {} 8 * :{}", name, realname)).await.unwrap();
        line_stream
    }
    
    pub(crate) async fn login_to_test_and_skip<'a>(port: u16, nick: &'a str, name: &'a str,
                realname: &'a str) -> Framed<TcpStream, IRCLinesCodec> {
        let mut line_stream = login_to_test(port, nick, name, realname).await;
        for _ in 0..18 { line_stream.next().await.unwrap().unwrap(); }
        line_stream
    }
    
    #[cfg(any(feature = "tls_rustls", feature="openssl"))]
    use std::path::PathBuf;
    
    #[cfg(any(feature = "tls_rustls", feature="openssl"))]
    fn get_cert_file_path() -> String {
        let mut path = PathBuf::new();
        path.push(env!("CARGO_MANIFEST_DIR"));
        path.push("test_data");
        path.push("cert.crt");
        path.to_string_lossy().to_string()
    }
    
    #[cfg(any(feature = "tls_rustls", feature="openssl"))]
    fn get_cert_key_file_path() -> String {
        let mut path = PathBuf::new();
        path.push(env!("CARGO_MANIFEST_DIR"));
        path.push("test_data");
        path.push("cert_key.crt");
        path.to_string_lossy().to_string()
    }
    
    #[cfg(any(feature = "tls_rustls", feature="openssl"))]
    pub(crate) async fn run_test_tls_server(config: MainConfig)
            -> (Arc<MainState>, JoinHandle<()>, u16) {
        //LOGGING_START.call_once(|| {
        //    initialize_logging(&MainConfig::default());
        //});
        let mut config = config;
        config.tls = Some(TLSConfig{ cert_file: get_cert_file_path(),
            cert_key_file: get_cert_key_file_path() });
        config.port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let port = config.port;
        let (main_state, handle) = run_server(config).await.unwrap();
        (main_state, handle, port)
    }

    #[cfg(feature = "tls_rustls")]
    use std::convert::TryFrom;
    #[cfg(feature = "tls_rustls")]
    use tokio_rustls::TlsConnector;
    
    #[cfg(feature = "tls_rustls")]
    pub(crate) async fn connect_to_test_tls(port: u16)
                -> Framed<tokio_rustls::client::TlsStream<TcpStream>, IRCLinesCodec> {
        let mut certs: Vec<Certificate> = rustls_pemfile::certs(
                &mut BufReader::new(File::open(get_cert_file_path()).unwrap()))
                .map(|mut certs| certs.drain(..).map(Certificate).collect()).unwrap();
        let dnsname = rustls::client::ServerName::try_from("localhost").unwrap();
        
        let mut cert_store = rustls::RootCertStore{ roots: vec![] };
        cert_store.add(&certs.remove(0)).unwrap();
        let config = Arc::new(rustls::ClientConfig::builder()
                    .with_safe_defaults()
                    .with_root_certificates(cert_store)
                    .with_no_client_auth());
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        Framed::new(TlsConnector::from(config).connect(dnsname, stream).await.unwrap(),
                        IRCLinesCodec::new_with_max_length(2000))
    }
    
    #[cfg(feature = "tls_rustls")]
    pub(crate) async fn login_to_test_tls<'a>(port: u16,
                nick: &'a str, name: &'a str, realname: &'a str)
                -> Framed<tokio_rustls::client::TlsStream<TcpStream>, IRCLinesCodec> {
        let mut line_stream = connect_to_test_tls(port).await;
        line_stream.send(format!("NICK {}", nick)).await.unwrap();
        line_stream.send(format!("USER {} 8 * :{}", name, realname)).await.unwrap();
        line_stream
    }
    
    #[cfg(feature = "tls_rustls")]
    pub(crate) async fn login_to_test_tls_and_skip<'a>(port: u16,
                nick: &'a str, name: &'a str, realname: &'a str)
                -> Framed<tokio_rustls::client::TlsStream<TcpStream>, IRCLinesCodec> {
        let mut line_stream = login_to_test_tls(port, nick, name, realname).await;
        for _ in 0..18 { line_stream.next().await.unwrap().unwrap(); }
        line_stream
    }
    
    #[cfg(feature = "tls_openssl")]
    use openssl::ssl::SslConnector;
    
    #[cfg(feature = "tls_openssl")]
    pub(crate) async fn connect_to_test_tls(port: u16)
                -> Framed<SslStream<TcpStream>, IRCLinesCodec> {
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.set_ca_file(get_cert_file_path()).unwrap();
        
        let ssl = connector.build().configure().unwrap().into_ssl("localhost").unwrap();
        
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut tls_stream = SslStream::new(ssl, stream).unwrap();
        use std::pin::Pin;
        Pin::new(&mut tls_stream).connect().await.unwrap();
        Framed::new(tls_stream, IRCLinesCodec::new_with_max_length(2000))
    }
    
    #[cfg(feature = "tls_openssl")]
    pub(crate) async fn login_to_test_tls<'a>(port: u16,
                nick: &'a str, name: &'a str, realname: &'a str)
                -> Framed<SslStream<TcpStream>, IRCLinesCodec> {
        let mut line_stream = connect_to_test_tls(port).await;
        line_stream.send(format!("NICK {}", nick)).await.unwrap();
        line_stream.send(format!("USER {} 8 * :{}", name, realname)).await.unwrap();
        line_stream
    }
    
    #[cfg(feature = "tls_openssl")]
    pub(crate) async fn login_to_test_tls_and_skip<'a>(port: u16,
                nick: &'a str, name: &'a str, realname: &'a str)
                -> Framed<SslStream<TcpStream>, IRCLinesCodec> {
        let mut line_stream = login_to_test_tls(port, nick, name, realname).await;
        for _ in 0..18 { line_stream.next().await.unwrap().unwrap(); }
        line_stream
    }
    
    #[tokio::test]
    async fn test_server_command0() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;
        
        {
            let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let mut line_stream = Framed::new(stream,
                        IRCLinesCodec::new_with_max_length(10000));
            line_stream.send("POG :welcome".to_string()).await.unwrap();
            assert_eq!(":irc.irc 421 127.0.0.1 POG :Unknown command".to_string(),
                        line_stream.next().await.unwrap().unwrap());
            line_stream.send("".to_string()).await.unwrap();
            line_stream.send("    ".to_string()).await.unwrap();
            line_stream.send(":welcome".to_string()).await.unwrap();
            assert_eq!(":irc.irc ERROR :No command supplied".to_string(),
                        line_stream.next().await.unwrap().unwrap());
            line_stream.send(":@! PING :welcome".to_string()).await.unwrap();
            assert_eq!(":irc.irc ERROR :Wrong source".to_string(),
                        line_stream.next().await.unwrap().unwrap());
            line_stream.send("PART aaa".to_string()).await.unwrap();
            assert_eq!(":irc.irc ERROR :Wrong parameter 0 in command 'PART'".to_string(),
                        line_stream.next().await.unwrap().unwrap());
            line_stream.send("PING :welcome".to_string()).await.unwrap();
            assert_eq!(":irc.irc 451 127.0.0.1 :You have not registered".to_string(),
                        line_stream.next().await.unwrap().unwrap());
            line_stream.send("CAP XXX".to_string()).await.unwrap();
            assert_eq!(":irc.irc ERROR :Unknown subcommand 'XXX' in command 'CAP'"
                        .to_string(), line_stream.next().await.unwrap().unwrap());
            line_stream.send("PRIVMSG".to_string()).await.unwrap();
            assert_eq!(":irc.irc 461 127.0.0.1 PRIVMSG :Not enough parameters".to_string(),
                        line_stream.next().await.unwrap().unwrap());
            line_stream.send("MODE lol +T".to_string()).await.unwrap();
            assert_eq!(":irc.irc 501 127.0.0.1 :Unknown MODE flag".to_string(),
                        line_stream.next().await.unwrap().unwrap());
            line_stream.send("MODE #bum +T".to_string()).await.unwrap();
            assert_eq!(":irc.irc 472 127.0.0.1 T :is unknown mode char for #bum"
                        .to_string(), line_stream.next().await.unwrap().unwrap());
            line_stream.send("MODE #bum +l xxx".to_string()).await.unwrap();
            assert_eq!(":irc.irc 696 127.0.0.1 #bum l xxx :invalid digit found in string"
                        .to_string(), line_stream.next().await.unwrap().unwrap());
            let mut toolong = String::new();
            for _ in 0..4000 { toolong.push('c'); }
            line_stream.send(toolong).await.unwrap();
            assert_eq!(":irc.irc 417 127.0.0.1 :Input line was too long".to_string(),
                        line_stream.next().await.unwrap().unwrap());
        }
        
        quit_test_server(main_state, handle).await;
    }
    
    #[tokio::test]
    async fn test_server_authentication() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;
        
        {
            let mut line_stream = login_to_test(port, "mati", "mat", "MatiSzpaki").await;
            assert_eq!(":irc.irc 001 mati :Welcome to the IRCnetwork \
                    Network, mati!~mat@127.0.0.1".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(concat!(":irc.irc 002 mati :Your host is irc.irc, running \
                    version ", env!("CARGO_PKG_NAME"), "-",
                    env!("CARGO_PKG_VERSION")).to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(format!(":irc.irc 003 mati :This server was created {}",
                    main_state.created),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(concat!(":irc.irc 004 mati irc.irc ", env!("CARGO_PKG_NAME"), "-",
                    env!("CARGO_PKG_VERSION"), " Oiorw Iabehiklmnopqstv"),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 005 mati AWAYLEN=1000 CASEMAPPING=ascii \
                    CHANMODES=Iabehiklmnopqstv CHANNELLEN=1000 CHANTYPES=&# EXCEPTS=e FNC \
                    HOSTLEN=1000 INVEX=I KEYLEN=1000 :are supported by this server"
                    .to_string(), line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 005 mati KICKLEN=1000 LINELEN=2000 MAXLIST=beI:1000 \
                    MAXNICKLEN=200 MAXPARA=500 MAXTARGETS=500 MODES=500 NETWORK=IRCnetwork \
                    NICKLEN=200 PREFIX=(qaohv)~&@%+ :are supported by this server"
                    .to_string(), line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 005 mati SAFELIST STATUSMSG=~&@%+ TOPICLEN=1000 USERLEN=200 \
                    USERMODES=Oiorw :are supported by this server".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 251 mati :There are 1 users and 0 invisible \
                    on 1 servers".to_string(), line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 252 mati 0 :operator(s) online".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 253 mati 0 :unknown connection(s)".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 254 mati 0 :channels formed".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 255 mati :I have 1 clients and 1 servers".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 265 mati 1 1 :Current local users 1, max 1".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 266 mati 1 1 :Current global users 1, max 1".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 375 mati :- irc.irc Message of the day - ".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 372 mati :Hello, world!".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 376 mati :End of /MOTD command.".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 221 mati +".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            
            let state = main_state.state.read().await;
            assert_eq!(HashSet::from([ "mati".to_string() ]),
                        HashSet::from_iter(state.users.keys().cloned()));
            assert_eq!(HashSet::from([ "mat".to_string() ]),
                        HashSet::from_iter(state.users.values().map(|u| u.name.clone())));
            assert_eq!(HashSet::from([ "MatiSzpaki".to_string() ]),
                    HashSet::from_iter(state.users.values().map(|u| u.realname.clone())));
            
            line_stream.send("CAP LIST".to_string()).await.unwrap();
            assert_eq!(":irc.irc CAP * LIST :".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            
            line_stream.send("QUIT :Bye".to_string()).await.unwrap();
            assert_eq!(":irc.irc ERROR: Closing connection".to_string(),
                    line_stream.next().await.unwrap().unwrap());
        }
        time::sleep(Duration::from_millis(50)).await;
        {   // after close
            let state = main_state.state.read().await;
            assert_eq!(HashSet::new(), HashSet::from_iter(state.users.keys().cloned()));
        }
        
        quit_test_server(main_state, handle).await;
    }
    
    #[cfg(any(feature = "tls_rustls", feature = "tls_openssl"))]
    #[tokio::test]
    async fn test_server_tls_first() {
        let (main_state, handle, port) = run_test_tls_server(MainConfig::default()).await;
        {
            let mut line_stream = login_to_test_tls(port, "mati", "mat",
                            "MatiSzpaki").await;
            assert_eq!(":irc.irc 001 mati :Welcome to the IRCnetwork \
                    Network, mati!~mat@127.0.0.1".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(concat!(":irc.irc 002 mati :Your host is irc.irc, running \
                    version ", env!("CARGO_PKG_NAME"), "-",
                    env!("CARGO_PKG_VERSION")).to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(format!(":irc.irc 003 mati :This server was created {}",
                    main_state.created),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(concat!(":irc.irc 004 mati irc.irc ", env!("CARGO_PKG_NAME"), "-",
                    env!("CARGO_PKG_VERSION"), " Oiorw Iabehiklmnopqstv"),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 005 mati AWAYLEN=1000 CASEMAPPING=ascii \
                    CHANMODES=Iabehiklmnopqstv CHANNELLEN=1000 CHANTYPES=&# EXCEPTS=e FNC \
                    HOSTLEN=1000 INVEX=I KEYLEN=1000 :are supported by this server"
                    .to_string(), line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 005 mati KICKLEN=1000 LINELEN=2000 MAXLIST=beI:1000 \
                    MAXNICKLEN=200 MAXPARA=500 MAXTARGETS=500 MODES=500 NETWORK=IRCnetwork \
                    NICKLEN=200 PREFIX=(qaohv)~&@%+ :are supported by this server"
                    .to_string(), line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 005 mati SAFELIST STATUSMSG=~&@%+ TOPICLEN=1000 USERLEN=200 \
                    USERMODES=Oiorw :are supported by this server".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 251 mati :There are 1 users and 0 invisible \
                    on 1 servers".to_string(), line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 252 mati 0 :operator(s) online".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 253 mati 0 :unknown connection(s)".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 254 mati 0 :channels formed".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 255 mati :I have 1 clients and 1 servers".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 265 mati 1 1 :Current local users 1, max 1".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 266 mati 1 1 :Current global users 1, max 1".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 375 mati :- irc.irc Message of the day - ".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 372 mati :Hello, world!".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 376 mati :End of /MOTD command.".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 221 mati +".to_string(),
                    line_stream.next().await.unwrap().unwrap());
        }
        
        quit_test_server(main_state, handle).await;
    }
    
    #[cfg(any(feature = "tls_rustls", feature = "tls_openssl"))]
    #[tokio::test]
    async fn test_server_timeouts() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;
        
        {
            let mut line_stream = login_to_test_and_skip(
                            port, "mati", "mat", "MatiSzpaki").await;
            
            line_stream.send("PING :bumbum".to_string()).await.unwrap();
            assert_eq!(":irc.irc PONG irc.irc :bumbum".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            time::pause();
            time::advance(Duration::from_millis(119900)).await;
            time::resume();
            assert_eq!(":irc.irc PING :LALAL".to_string(), 
                    line_stream.next().await.unwrap().unwrap());
            line_stream.send("PONG :LALAL".to_string()).await.unwrap();
            
            // test timeout
            time::pause();
            time::advance(Duration::from_millis(119900)).await;
            time::resume();
            assert_eq!(":irc.irc PING :LALAL".to_string(), 
                    line_stream.next().await.unwrap().unwrap());
            time::pause();
            time::advance(Duration::from_millis(19900)).await;
            time::resume();
            assert_eq!(":irc.irc ERROR :Pong timeout, connection will \
                be closed.".to_string(), line_stream.next().await.unwrap().unwrap());
        }
        
        quit_test_server(main_state, handle).await;
    }
}

mod conn_cmds;
mod channel_cmds;
mod srv_query_cmds;
mod rest_cmds;
