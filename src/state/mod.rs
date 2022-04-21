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
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::net::IpAddr;
use std::error::Error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, oneshot};
use tokio_stream::StreamExt;
use tokio::net::TcpStream;
use tokio_util::codec::{Framed, LinesCodecError};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver,UnboundedSender};
use tokio::sync::mpsc::error::SendError;
use tokio::time;
use futures::SinkExt;
use chrono::prelude::*;
use flagset::{flags, FlagSet};

use crate::config::*;
use crate::reply::*;
use crate::command::*;
use crate::utils::*;

use Reply::*;

#[derive(Debug)]
struct User {
    hostname: String,
    sender: UnboundedSender<String>,
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
        user_modes.registered = user_state.registered;
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
    
    fn update_nick(&mut self, user_state: &ConnUserState) {
        if let Some(ref nick) = user_state.nick { self.nick = nick.clone(); }
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
        if (caps.multi_prefix || out.len() == 0) && self.protected { out.push('&'); }
        if (caps.multi_prefix || out.len() == 0) && self.operator { out.push('@'); }
        if (caps.multi_prefix || out.len() == 0) && self.half_oper { out.push('%'); }
        if (caps.multi_prefix || out.len() == 0) && self.voice { out.push('+'); }
        out
    }
}

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
                if i+1 < target.len() { out_str = &target[i..]; }
                else { out &= !ChannelAll; }
                break;
            }
            _ => {
                if last_amp {
                    if amp_count < 2 { out &= !ChannelProtected; }
                    out_str = &target[i-1..];
                } else { out &= !ChannelAll; }
                break;
            }
        }
        if c == b'&' {
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
}

impl Channel {
    fn new(name: String, user_nick: String) -> Channel {
        let mut users = HashMap::new();
        users.insert(user_nick.clone(), ChannelUserModes::new_for_created_channel());
        Channel{ name, topic: None, ban_info: HashMap::new(),
            default_modes: ChannelDefaultModes::default(),
            modes: ChannelModes::new_for_channel(user_nick), users,
            creation_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() }
    }
    
    fn rename_user(&mut self, old_nick: &String, nick: String) {
        let oldchumode = self.users.remove(old_nick).unwrap();
        self.users.insert(nick.clone(), oldchumode);
        self.modes.rename_user(old_nick, nick.clone());
    }
    
    fn remove_user(&mut self, nick: &str) {
        self.remove_operator(nick);
        self.remove_half_operator(nick);
        self.remove_founder(nick);
        self.remove_voice(nick);
        self.remove_protected(nick);
        self.users.remove(nick);
    }
    
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

#[derive(Copy, Clone, Debug)]
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

impl Default for CapState {
    fn default() -> Self {
        CapState{ multi_prefix: false }
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

#[derive(Debug, Clone)]
pub(crate) struct ConnUserState {
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
        ConnUserState{ hostname: ip_addr.to_string(),
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
        if let Some(ref nick) = self.nick {
            s.push_str(&nick);
        }
        if let Some(ref name) = self.name {
            s.push_str("!~");
            s.push_str(&name);
        }
        s.push('@');
        s.push_str(&self.hostname);
        self.source = s;
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
    stream: Framed<TcpStream, IRCLinesCodec>,
    sender: Option<UnboundedSender<String>>,
    receiver: UnboundedReceiver<String>,
    // sender and receiver used for sending ping task for 
    ping_sender: Option<UnboundedSender<()>>,
    ping_receiver: UnboundedReceiver<()>,
    timeout_sender: Arc<UnboundedSender<()>>,
    timeout_receiver: UnboundedReceiver<()>,
    pong_notifier: Option<oneshot::Sender<()>>,
    quit_receiver: oneshot::Receiver<(String, String)>,
    quit_sender: Option<oneshot::Sender<(String, String)>>,
    
    user_state: ConnUserState,
    
    caps_negotation: bool,  // if caps negotation process
    caps: CapState,
    quit: Arc<AtomicI32>,
    conns_count: Arc<AtomicUsize>
}

impl ConnState {
    fn new(ip_addr: IpAddr, stream: Framed<TcpStream, IRCLinesCodec>,
            conns_count: Arc<AtomicUsize>) -> ConnState {
        let (sender, receiver) = unbounded_channel();
        let (ping_sender, ping_receiver) = unbounded_channel();
        let (timeout_sender, timeout_receiver) = unbounded_channel();
        let (quit_sender, quit_receiver) = oneshot::channel();
        ConnState{ stream, sender: Some(sender), receiver,
            user_state: ConnUserState::new(ip_addr),
            ping_sender: Some(ping_sender), ping_receiver,
            timeout_sender: Arc::new(timeout_sender), timeout_receiver,
            pong_notifier: None, quit_sender: Some(quit_sender), quit_receiver,
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
            panic!("Ping waker ran!");
        }
    }
    
    fn run_pong_timeout(&mut self, config: &MainConfig) {
        let (pong_notifier, pong_receiver) = oneshot::channel();
        self.pong_notifier = Some(pong_notifier);
        tokio::spawn(pong_client_timeout(
                time::timeout(Duration::from_secs(config.pong_timeout), pong_receiver),
                    self.quit.clone(), self.timeout_sender.clone()));
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
            cfg_channels.iter().for_each(|c| {
                let mut ch_modes = c.modes.clone();
                let def_ch_modes = ChannelDefaultModes::new_from_modes_and_cleanup(
                            &mut ch_modes);
                
                channels.insert(c.name.clone(), Channel{ name: c.name.clone(), 
                    topic: c.topic.as_ref().map(|x| ChannelTopic::new(x.clone())),
                    ban_info: HashMap::new(), default_modes: def_ch_modes,
                    modes: ch_modes, users: HashMap::new(),
                    creation_time: SystemTime::now().duration_since(UNIX_EPOCH)
                            .unwrap().as_secs() });
            });
        }
        
        let (quit_sender, quit_receiver) = oneshot::channel();
        VolatileState{ users: HashMap::new(), channels, wallops_users: HashSet::new(),
                invisible_users_count: 0, operators_count: 0 , max_users_count: 0,
                nick_histories: HashMap::new(),
                quit_sender: Some(quit_sender), quit_receiver: Some(quit_receiver) }
    }
    
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
                self.channels.get_mut(chname).unwrap().remove_user(nick);
            });
        }
    }
    
    fn insert_to_nick_history<'a>(&mut self, old_nick: &'a String, nhe: NickHistoryEntry) {
        if self.nick_histories.contains_key(old_nick) {
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
    
    pub(crate) fn register_conn_state(&self, ip_addr: IpAddr,
                    stream: Framed<TcpStream, IRCLinesCodec>) -> Option<ConnState> {
        if let Some(max_conns) = self.config.max_connections {
            if self.conns_count.fetch_add(1, Ordering::SeqCst) < max_conns {
                Some(ConnState::new(ip_addr, stream, self.conns_count.clone()))
            } else {
                self.conns_count.fetch_sub(1, Ordering::SeqCst);
                eprintln!("Too many connections");
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
    
    pub(crate) async fn process(&self, conn_state: &mut ConnState)
                -> Result<(), String> {
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
                self.feed_msg(&mut conn_state.stream,
                            "ERROR :Pong timeout, connection will be closed.").await?;
                conn_state.quit.store(1, Ordering::SeqCst);
                Ok(())
            }
            Ok((killer, comment)) = &mut conn_state.quit_receiver => {
                self.feed_msg(&mut conn_state.stream,
                        format!("ERROR :User killed by {}: {}", killer, comment)).await?;
                conn_state.quit.store(1, Ordering::SeqCst);
                Ok(())
            }
            msg_str_res = conn_state.stream.next() => {
                
                let msg = match msg_str_res {
                    Some(Ok(ref msg_str)) => {
                        match Message::from_shared_str(&msg_str) {
                            Ok(msg) => msg,
                            Err(e) => {
                                match e {
                                    MessageError::Empty => {
                                        self.feed_msg(&mut conn_state.stream,
                                            "ERROR :Empty message").await?;
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
                    Some(Err(LinesCodecError::MaxLineLengthExceeded)) => {
                        let client = conn_state.user_state.client_name();
                        self.feed_msg(&mut conn_state.stream,
                                    ErrInputTooLong417{ client }).await?;
                        return Ok(())
                    },
                    Some(Err(e)) => return Err(Box::new(e)),
                    // if end of stream
                    None => return Ok(()),
                };
                
                let cmd = match Command::from_message(&msg) {
                    Ok(cmd) => cmd,
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
                            UnknownMode(_, modechar) => {
                                self.feed_msg(&mut conn_state.stream,
                                        ErrUnknownMode472{ client,
                                        modechar }).await?;
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
                        self.feed_msg(&mut conn_state.stream, ErrNotRegistered451{         
                                    client: conn_state.user_state.client_name() }).await?;
                        return Ok(())
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
                    WALLOPS{ text } =>
                        self.process_wallops(conn_state, text, &msg).await,
                }
            },
        }
    }
    
    async fn feed_msg<T: fmt::Display>(&self,
            stream: &mut Framed<TcpStream, IRCLinesCodec>, t: T)
            -> Result<(), LinesCodecError> {
        stream.feed(format!(":{} {}", self.config.name, t)).await
    }
    
    async fn feed_msg_source<T: fmt::Display>(&self,
            stream: &mut Framed<TcpStream, IRCLinesCodec>, source: &str, t: T)
            -> Result<(), LinesCodecError> {
        stream.feed(format!(":{} {}", source, t)).await
    }
}

#[cfg(test)]
mod test {
    use super::*;
    
    #[test]
    fn test_user_new() {
        let mut config = MainConfig::default();
        config.default_user_modes = UserModes{ invisible: true, oper: false,
                local_oper: false, registered: true, wallops: false };
        let user_state = ConnUserState{
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
            creation_time: channel.creation_time }, channel);
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
            creation_time: channel.creation_time }, channel);
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
            creation_time: channel.creation_time };
        
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
}

mod conn_cmds;
mod channel_cmds;
mod srv_query_cmds;
mod rest_cmds;
