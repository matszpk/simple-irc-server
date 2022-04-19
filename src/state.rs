// state.rs - main state
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

use std::ops::{Deref, DerefMut, Drop};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::net::IpAddr;
use std::error::Error;
use std::iter::FromIterator;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::convert::TryFrom;
use tokio::sync::{RwLock, oneshot};
use tokio_stream::StreamExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{Framed, LinesCodec, LinesCodecError};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver,UnboundedSender};
use tokio::sync::mpsc::error::SendError;
use tokio::time;
use futures::SinkExt;
use chrono::prelude::*;
use const_table::const_table;
use flagset::{flags, FlagSet};

use crate::config::*;
use crate::reply::*;
use crate::command::*;
use crate::utils::*;

use Reply::*;

#[const_table]
pub(crate) enum SupportTokenInt {
    SupportTokenIntValue{ name: &'static str, value: usize },
    AWAYLEN = SupportTokenIntValue{ name: "AWAYLEN", value: 1000 },
    CHANNELLEN = SupportTokenIntValue{ name: "CHANNELLEN", value: 1000 },
    HOSTLEN = SupportTokenIntValue{ name: "HOSTLEN", value: 1000 },
    KEYLEN = SupportTokenIntValue{ name: "KEYLEN", value: 1000 },
    KICKLEN = SupportTokenIntValue{ name: "KICKLEN", value: 1000 },
    LINELEN = SupportTokenIntValue{ name: "LINELEN", value: 2000 },
    MAXNICKLEN = SupportTokenIntValue{ name: "MAXNICKLEN", value: 200 },
    MAXPARA = SupportTokenIntValue{ name: "MAXPARA", value: 500 },
    MAXTARGETS = SupportTokenIntValue{ name: "MAXTARGETS", value: 500 },
    MODES = SupportTokenIntValue{ name: "MODES", value: 500 },
    NICKLEN = SupportTokenIntValue{ name: "NICKLEN", value: 200 },
    TOPICLEN = SupportTokenIntValue{ name: "TOPICLEN", value: 1000 },
    USERLEN = SupportTokenIntValue{ name: "USERLEN", value: 200 },
}

impl ToString for SupportTokenIntValue {
    fn to_string(&self) -> String {
        let mut s = self.name.to_string();
        s.push('=');
        s.push_str(&self.value.to_string());
        s
    }
}

#[const_table]
pub(crate) enum SupportTokenString {
    SupportTokenStringValue{ name: &'static str, value: &'static str },
    CASEMAPPING = SupportTokenStringValue{ name: "CASEMAPPING", value: "ascii" },
    CHANMODES = SupportTokenStringValue{ name: "CHANMODES", value: "Iabehiklmnopqstv" },
    CHANTYPES = SupportTokenStringValue{ name: "CHANTYPES", value: "&#" },
    EXCEPTS = SupportTokenStringValue{ name: "EXCEPTS", value: "e" },
    INVEX = SupportTokenStringValue{ name: "INVEX", value: "I" },
    MAXLIST = SupportTokenStringValue{ name: "MAXLIST", value: "beI:1000" },
    PREFIX = SupportTokenStringValue{ name: "PREFIX", value: "(qaohv)~&@%+" },
    STATUSMSG = SupportTokenStringValue{ name: "STATUSMSG", value: "~&@%+" },
    USERMODES = SupportTokenStringValue{ name: "USERMODES", value: "Oiorw" },
}

impl ToString for SupportTokenStringValue {
    fn to_string(&self) -> String {
        let mut s = self.name.to_string();
        s.push('=');
        s.push_str(&self.value);
        s
    }
}

#[const_table]
pub(crate) enum SupportTokenBool {
    SupportTokenBoolValue{ name: &'static str },
    FNC = SupportTokenBoolValue{ name: "FNC" },
    SAFELIST = SupportTokenBoolValue{ name: "SAFELIST" },
}

struct User {
    hostname: String,
    sender: UnboundedSender<String>,
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
    fn new(config: &MainConfig, user_state: &ConnUserState, registered: bool,
            sender: UnboundedSender<String>) -> User {
        let mut user_modes = config.default_user_modes;
        user_modes.registered = registered;
        let now_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        User{ hostname: user_state.hostname.clone(), sender,
                name: user_state.name.as_ref().unwrap().clone(),
                realname: user_state.realname.as_ref().unwrap().clone(),
                nick: user_state.name.as_ref().unwrap().clone(),
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

#[derive(Copy, Clone, PartialEq, Eq)]
enum OperatorType {
    NoOper,
    Oper,
    HalfOper,
}

#[derive(Copy, Clone, Default)]
struct ChannelUserModes {
    founder: bool,
    protected: bool,
    voice: bool,
    operator: bool,
    half_oper: bool,
}

impl ChannelUserModes {
    fn new_for_created_channel() -> Self {
        ChannelUserModes{ founder: false, protected: false, voice: false,
                operator: true, half_oper: false }
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
    fn to_string(&self, cap_state: &CapState) -> String {
        let mut out = String::new();
        if self.founder { out.push('~'); }
        if self.protected { out.push('&'); }
        if self.operator { out.push('@'); }
        if self.half_oper { out.push('%'); }
        if self.voice { out.push('+'); }
        out
    }
}

fn get_privmsg_target_type(target: &str) -> (FlagSet<PrivMsgTargetType>, &str) {
    use PrivMsgTargetType::*;
    let mut out = FlagSet::<PrivMsgTargetType>::new_truncated(0);
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
            last_amp = true;
            amp_count += 1;
         } else { last_amp = false; }
    }
    (out, out_str)
}

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

struct BanInfo {
    set_time: u64,
    who: String,
}

#[derive(Default, Clone)]
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

struct Channel {
    name: String,
    topic: Option<ChannelTopic>,
    modes: ChannelModes,
    default_modes: ChannelDefaultModes,
    ban_info: HashMap<String, BanInfo>,
    users: HashMap<String, ChannelUserModes>,
}

impl Channel {
    fn new(name: String, user_nick: String) -> Channel {
        let mut users = HashMap::new();
        users.insert(user_nick.clone(), ChannelUserModes::new_for_created_channel());
        Channel{ name, topic: None, ban_info: HashMap::new(),
            default_modes: ChannelDefaultModes::default(),
            modes: ChannelModes::new_for_channel(user_nick), users }
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

struct NickHistoryEntry {
    username: String,
    hostname: String,
    realname: String,
    signon: u64,
}

#[derive(Copy, Clone)]
pub(crate) struct CapState {
    multi_prefix: bool,
}

impl fmt::Display for CapState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.multi_prefix {
            f.write_str("multi_prefix")
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
        ConnState{ stream, sender: Some(sender), receiver,
            user_state: ConnUserState::new(ip_addr),
            ping_sender: Some(ping_sender), ping_receiver,
            timeout_sender: Arc::new(timeout_sender), timeout_receiver,
            pong_notifier: None,
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
                    modes: ch_modes, users: HashMap::new() });
            });
        }
        
        VolatileState{ users: HashMap::new(), channels, wallops_users: HashSet::new(),
                invisible_users_count: 0, operators_count: 0 , max_users_count: 0,
                nick_histories: HashMap::new() }
    }
    
    fn remove_user(&mut self, nick: &str) {
        if let Some(user) = self.users.remove(nick) {
            if user.modes.local_oper || user.modes.oper {
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
    
    pub(crate) async fn process(&self, conn_state: &mut ConnState)
                -> Result<(), String> {
        // use conversion error to string to avoid problems with thread safety
        let res = self.process_internal(conn_state).await.map_err(|e| e.to_string());
        conn_state.stream.flush().await.map_err(|e| e.to_string())?;
        res
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
    
    async fn process_cap<'a>(&self, conn_state: &mut ConnState, subcommand: CapCommand,
            caps: Option<Vec<&'a str>>, version: Option<u32>) -> Result<(), Box<dyn Error>> {
        match subcommand {
            CapCommand::LS => {
                conn_state.caps_negotation = true;
                self.feed_msg(&mut conn_state.stream, "CAP * LS :multi-prefix").await
            }
            CapCommand::LIST => {
                self.feed_msg(&mut conn_state.stream,
                        &format!("CAP * LIST :{}", conn_state.caps)).await
                }
            CapCommand::REQ => {
                conn_state.caps_negotation = true;
                if let Some(cs) = caps {
                    let mut new_caps = conn_state.caps;
                    if cs.iter().all(|c| new_caps.apply_cap(c)) {
                        conn_state.caps = new_caps;
                        self.feed_msg(&mut conn_state.stream,
                            format!("CAP * ACK :{}", cs.join(" "))).await
                    } else {    // NAK
                        self.feed_msg(&mut conn_state.stream,
                            format!("CAP * NAK :{}", cs.join(" "))).await
                    }
                } else { Ok(()) }
            }
            CapCommand::END => {
                conn_state.caps_negotation = false;
                if !conn_state.user_state.authenticated {
                    self.authenticate(conn_state).await?;
                }
                Ok(()) }
        }?;
        Ok(())
    }
    
    async fn send_isupport(&self, conn_state: &mut ConnState) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        // support tokens
        let mut tokens = vec![ format!("NETWORK={}", self.config.network) ];
        if let Some(max_joins) = self.config.max_joins {
            tokens.push(format!("CHANLIMIT=&#:{}", max_joins));
            tokens.push(format!("MAXCHANNELS={}", max_joins));
        }
        let inf_range = 0 as u32..;
        inf_range.map_while(|i| {
            let t: Result<SupportTokenString, _> = TryFrom::try_from(i as u32);
            t.ok() }).for_each(|t| { tokens.push(t.to_string()); });
        let inf_range = 0 as u32..;
        inf_range.map_while(|i| {
            let t: Result<SupportTokenInt, _> = TryFrom::try_from(i as u32);
            t.ok() }).for_each(|t| { tokens.push(t.to_string()); });
        let inf_range = 0 as u32..;
        inf_range.map_while(|i| {
            let t: Result<SupportTokenBool, _> = TryFrom::try_from(i as u32);
            t.ok() }).for_each(|t| { tokens.push(t.name.to_string()); });
        
        tokens.sort();
        
        for toks in tokens.chunks(10) {
            self.feed_msg(&mut conn_state.stream,
                RplISupport005{ client, tokens: &toks.join(" ") }).await?;
        }
        Ok(())
    }
    
    async fn authenticate(&self, conn_state: &mut ConnState)
        -> Result<(), Box<dyn Error>> {
        let (auth_opt, registered) = {
            if !conn_state.caps_negotation {
                let user_state = &mut conn_state.user_state;
                if let Some(ref nick) = user_state.nick {
                    if let Some(ref name) = user_state.name {
                        let mut registered = false;
                        let password_opt = if let Some(uidx) =
                                    self.user_config_idxs.get(name) {
                            // match user mask
                            if let Some(ref users) = self.config.users {
                                if let Some(ref mask) = users[*uidx].mask {
                                    if match_wildcard(&mask, &user_state.source) {
                                        registered = true;
                                        users[*uidx].password.as_ref()
                                    } else {
                                        self.feed_msg(&mut conn_state.stream,
                                            "ERROR: user mask doesn't match").await?;
                                        return Ok(());
                                    }
                                } else {
                                    registered = true;
                                    users[*uidx].password.as_ref()
                                }
                            } else { None }
                        } else { None }
                            .or(self.config.password.as_ref());
                        
                        if let Some(password) = password_opt {
                            let good = if let Some(ref entered_pwd) = user_state.password {
                                *entered_pwd == *password
                            } else { false };
                            
                            user_state.authenticated = good;
                            (Some(good), registered)
                        } else { (Some(true), registered) }
                    } else { (None, false) }
                } else { (None, false) }
            } else { (None, false) }
        };
        
        if let Some(good) = auth_opt {
            if good {
                let user_modes = {   // add new user to hash map
                    let user_state = &conn_state.user_state;
                    let mut state = self.state.write().await;
                    let user = User::new(&self.config, &user_state, registered,
                                conn_state.sender.take().unwrap());
                    let umode_str = user.modes.to_string();
                    state.users.insert(user_state.nick.as_ref().unwrap().clone(),
                        user);
                    umode_str
                };
                
                {
                    let user_state = &conn_state.user_state;
                    let client = user_state.client_name();
                    // welcome
                    self.feed_msg(&mut conn_state.stream, RplWelcome001{ client,
                        networkname: &self.config.network,
                                nick: user_state.name.as_deref().unwrap_or_default(),
                                user: user_state.name.as_deref().unwrap_or_default(),
                                host: &user_state.hostname }).await?;
                    self.feed_msg(&mut conn_state.stream, RplYourHost002{ client,
                            servername: &self.config.name,
                            version: concat!(env!("CARGO_PKG_NAME"), "-",
                                    env!("CARGO_PKG_VERSION")) }).await?;
                    self.feed_msg(&mut conn_state.stream, RplCreated003{ client,
                            datetime: &self.created }).await?;
                    self.feed_msg(&mut conn_state.stream, RplMyInfo004{ client,
                            servername: &self.config.name,
                            version: concat!(env!("CARGO_PKG_NAME"), "-",
                                    env!("CARGO_PKG_VERSION")),
                            avail_user_modes: "Oiorw",
                            avail_chmodes: "Iabehiklmnopqstv",
                            avail_chmodes_with_params: None }).await?;
                    
                    self.send_isupport(conn_state).await?;
                }
                
                self.process_lusers(conn_state).await?;
                self.process_motd(conn_state, None).await?;
                
                // mode
                let client = conn_state.user_state.client_name();
                self.feed_msg(&mut conn_state.stream,
                        RplUModeIs221{ client, user_modes: &user_modes }).await?;
                
                // run ping waker for this connection
                conn_state.run_ping_waker(&self.config);
            } else {
                let client = conn_state.user_state.client_name();
                conn_state.quit.store(1, Ordering::SeqCst);
                self.feed_msg(&mut conn_state.stream, ErrPasswdMismatch464{ client }).await?;
            }
        }
        Ok(())
    }
    
    async fn process_authenticate(&self, conn_state: &mut ConnState)
            -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        
        self.feed_msg(&mut conn_state.stream, ErrUnknownCommand421{ client,
                command: "AUTHENTICATE" }).await?;
        Ok(())
    }
    
    async fn process_pass<'a>(&self, conn_state: &mut ConnState, pass: &'a str)
            -> Result<(), Box<dyn Error>> {
        if !conn_state.user_state.authenticated {
            conn_state.user_state.password = Some(pass.to_string());
            self.authenticate(conn_state).await?;
        } else {
            let client = conn_state.user_state.client_name();
            self.feed_msg(&mut conn_state.stream, ErrAlreadyRegistered462{ client }).await?;
        }
        Ok(())
    }
    
    async fn process_nick<'a>(&self, conn_state: &mut ConnState, nick: &'a str,
                msg: &'a Message<'a>) -> Result<(), Box<dyn Error>> {
        if !conn_state.user_state.authenticated {
            conn_state.user_state.set_nick(nick.to_string());
            self.authenticate(conn_state).await?;
        } else {
            let mut state = self.state.write().await;
            let old_nick = conn_state.user_state.nick.as_ref().unwrap().to_string();
            if nick != old_nick {
                let nick_str = nick.to_string();
                if !state.users.get(&nick_str).is_some() {
                    let mut user = state.users.remove(&old_nick).unwrap();
                    conn_state.user_state.set_nick(nick_str.clone());
                    user.update_nick(&conn_state.user_state);
                    for ch in &user.channels {
                        state.channels.get_mut(&ch.clone()).unwrap().rename_user(
                                    &old_nick, nick_str.clone());
                    }
                    state.users.insert(nick_str.clone(), user);
                    // wallops users
                    if state.wallops_users.contains(&old_nick) {
                        state.wallops_users.remove(&old_nick);
                        state.wallops_users.insert(nick_str);
                    }
                    
                    for (_,u) in &state.users {
                        if !u.modes.invisible || u.nick == nick {
                            u.send_message(msg, &conn_state.user_state.source)?;
                        }
                    }
                } else {    // if nick in use
                    let client = conn_state.user_state.client_name();
                    self.feed_msg(&mut conn_state.stream,
                            ErrNicknameInUse433{ client, nick }).await?;
                }
            }
        }
        Ok(())
    }
    
    async fn process_user<'a>(&self, conn_state: &mut ConnState, username: &'a str,
            _: &'a str, _: &'a str, realname: &'a str)
            -> Result<(), Box<dyn Error>> {
        if !conn_state.user_state.authenticated {
            conn_state.user_state.set_name(username.to_string());
            conn_state.user_state.realname = Some(realname.to_string());
            self.authenticate(conn_state).await?;
        } else {
            let client = conn_state.user_state.client_name();
            self.feed_msg(&mut conn_state.stream, ErrAlreadyRegistered462{ client }).await?;
        }
        Ok(())
    }
    
    async fn process_ping<'a>(&self, conn_state: &mut ConnState, token: &'a str)
            -> Result<(), Box<dyn Error>> {
        self.feed_msg(&mut conn_state.stream, format!("PONG {} {} :{}", self.config.name,
                    self.config.name, token)).await?;
        Ok(())
    }
    
    async fn process_pong<'a>(&self, conn_state: &mut ConnState, token: &'a str)
            -> Result<(), Box<dyn Error>> {
        if let Some(notifier) = conn_state.pong_notifier.take() {
            notifier.send(()).map_err(|_| "pong notifier error".to_string())?;
        }
        Ok(())
    }
    
    async fn process_oper<'a>(&self, conn_state: &mut ConnState, nick: &'a str,
            password: &'a str) -> Result<(), Box<dyn Error>> {
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        let client = conn_state.user_state.client_name();
        
        if let Some(oper_idx) = self.oper_config_idxs.get(nick) {
            let mut state = self.state.write().await;
            let mut user = state.users.get_mut(user_nick).unwrap();
            let op_cfg_opt = self.config.operators.as_ref().unwrap().get(*oper_idx);
            let op_config = op_cfg_opt.as_ref().unwrap();
            
            if op_config.password != password {
                self.feed_msg(&mut conn_state.stream,
                        ErrPasswdMismatch464{ client }).await?;
            }
            if let Some(ref op_mask) = op_config.mask {
                if match_wildcard(&op_mask, &conn_state.user_state.source) {
                    self.feed_msg(&mut conn_state.stream,
                            ErrNoOperHost491{ client }).await?;
                }
            }
            user.modes.oper = true;
            state.operators_count += 1;
        } else {
            self.feed_msg(&mut conn_state.stream, ErrNoOperHost491{ client }).await?;
        }
        Ok(())
    }
    
    async fn process_quit(&self, conn_state: &mut ConnState)
            -> Result<(), Box<dyn Error>> {
        conn_state.quit.store(1, Ordering::SeqCst);
        self.feed_msg(&mut conn_state.stream, "ERROR: Closing connection").await?;
        Ok(())
    }
    
    async fn process_join<'a>(&self, conn_state: &mut ConnState, channels: Vec<&'a str>,
            keys_opt: Option<Vec<&'a str>>) -> Result<(), Box<dyn Error>> {
        let mut statem = self.state.write().await;
        let mut state = statem.deref_mut();
        let user_nick = conn_state.user_state.nick.as_ref().unwrap().clone();
        let mut join_count = state.users.get(&user_nick).unwrap().channels.len();
        
        let mut joined_created = vec![];
        
        {
        let client = conn_state.user_state.client_name();
        let mut user = state.users.get_mut(user_nick.as_str()).unwrap();
        for (i, chname_str) in channels.iter().enumerate() {
            let (join, create) = if let Some(channel) =
                                state.channels.get(&chname_str.to_string()) {
                // if already created
                let do_join = if let Some(key) = &channel.modes.key {
                    if let Some(ref keys) = keys_opt {
                        key == keys[i]
                    } else {
                        self.feed_msg(&mut conn_state.stream, ErrBadChannelKey475{
                            client, channel: chname_str }).await?;
                        false
                    }
                } else { true };
                
                let do_join = do_join && {
                    if !channel.modes.banned(&conn_state.user_state.source) {
                        true
                    } else {
                        self.feed_msg(&mut conn_state.stream, ErrBannedFromChan474{
                            client, channel: chname_str }).await?;
                        false
                    }
                };
                
                let do_join = do_join && {
                     if !channel.modes.invite_only ||
                        user.invited_to.contains(&channel.name) ||
                        channel.modes.invite_exception.as_ref().map_or(false,
                            |e| e.iter().any(|e|
                                match_wildcard(&e, &conn_state.user_state.source))) {
                        true
                    } else {
                        self.feed_msg(&mut conn_state.stream, ErrBannedFromChan474{
                            client, channel: chname_str }).await?;
                        false
                    }
                };
                
                let do_join = do_join && {
                    let not_full = if let Some(client_limit) = channel.modes.client_limit {
                        channel.users.len() < client_limit
                    } else { true };
                    if not_full { true } else {
                        self.feed_msg(&mut conn_state.stream, ErrChannelIsFull471{
                            client, channel: chname_str }).await?;
                        false
                    }
                };
                
                if do_join { (true, false)
                } else { (false, false) }
            } else { // if new channel
                (true, true)
            };
            
            let do_join = if let Some(max_joins) = self.config.max_joins {
                if join_count >= max_joins {
                    self.feed_msg(&mut conn_state.stream, ErrTooManyChannels405{
                            client, channel: chname_str }).await?;
                }
                join_count < max_joins
            } else { true };
            
            if do_join {
                joined_created.push((join, create));
                join_count += 1;
            }
        }
        
        for ((join, create), chname_str) in joined_created.iter().zip(channels.iter()) {
            let chname = chname_str.to_string();
            
            if *join {
                user.channels.insert(chname_str.to_string());
                if *create {
                    state.channels.insert(chname.clone(), Channel::new(
                                chname.clone(), user_nick.clone()));
                } else {
                    let chanobj = state.channels.get_mut(&chname).unwrap();
                    let mut chum = ChannelUserModes::default();
                    if chanobj.default_modes.half_operators.contains(&user_nick) {
                        chum.half_oper = true;
                        let mut half_ops = chanobj.modes.half_operators.take()
                                .unwrap_or_default();
                        half_ops.insert(user_nick.clone());
                        chanobj.modes.half_operators = Some(half_ops);
                    }
                    if chanobj.default_modes.operators.contains(&user_nick) {
                        chum.operator = true;
                        let mut ops = chanobj.modes.operators.take().unwrap_or_default();
                        ops.insert(user_nick.clone());
                        chanobj.modes.operators = Some(ops);
                    }
                    if chanobj.default_modes.founders.contains(&user_nick) {
                        chum.founder = true;
                        let mut founders = chanobj.modes.founders.take().unwrap_or_default();
                        founders.insert(user_nick.clone());
                        chanobj.modes.founders = Some(founders);
                    }
                    if chanobj.default_modes.voices.contains(&user_nick) {
                        chum.voice = true;
                        let mut voices = chanobj.modes.voices.take().unwrap_or_default();
                        voices.insert(user_nick.clone());
                        chanobj.modes.voices = Some(voices);
                    }
                    if chanobj.default_modes.protecteds.contains(&user_nick) {
                        chum.protected = true;
                        let mut protecteds = chanobj.modes.protecteds.take()
                                .unwrap_or_default();
                        protecteds.insert(user_nick.clone());
                        chanobj.modes.protecteds = Some(protecteds);
                    }
                    chanobj.users.insert(user_nick.clone(), chum);
                }
            }
        }
        if join_count!=0 {
            user.last_activity = SystemTime::now().duration_since(UNIX_EPOCH)
                        .unwrap().as_secs();
        }
        }
        
        // sending messages
        {
        let user = state.users.get(user_nick.as_str()).unwrap();
        for ((join, _), chname_str) in joined_created.iter().zip(channels.iter()) {
            if *join {
                let chanobj = state.channels.get(&chname_str.to_string()).unwrap();
                let join_msg = "JOIN ".to_string() + chname_str;
                {
                    let client = conn_state.user_state.client_name();
                    self.feed_msg_source(&mut conn_state.stream,
                                &conn_state.user_state.source, join_msg.as_str()).await?;
                    if let Some(ref topic) = chanobj.topic {
                        self.feed_msg(&mut conn_state.stream, RplTopic332{ client,
                                channel: chname_str, topic: &topic.topic }).await?;
                    }
                }
                self.send_names_from_channel(conn_state, chanobj,
                                &state.users, &user).await?;
                
                for (nick, _) in &chanobj.users {
                    if nick != user_nick.as_str() {
                        state.users.get(&nick.clone()).unwrap().send_msg_display(
                            &conn_state.user_state.source, join_msg.as_str())?;
                    }
                }
            }
        }
        }
        
        Ok(())
    }
    
    async fn process_part<'a>(&self, conn_state: &mut ConnState, channels: Vec<&'a str>,
            reason: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        let mut statem = self.state.write().await;
        let mut state = statem.deref_mut();
        let user_nick = conn_state.user_state.nick.as_ref().unwrap().clone();
        
        let mut removed_from = vec![];
        let mut something_done = false;
        
        for channel in &channels {
            if let Some(chanobj) = state.channels.get_mut(channel.clone()) {
                let do_it = if chanobj.users.contains_key(&user_nick) {
                    chanobj.remove_user(&user_nick);
                    removed_from.push(true);
                    something_done = true;
                    true
                } else {
                    self.feed_msg(&mut conn_state.stream,
                                ErrNotOnChannel442{ client, channel }).await?;
                    removed_from.push(false);
                    false
                };
                
                // send message
                if do_it {
                    let part_msg = if let Some(r) = reason {
                        format!("PART {} :{}", channel, r)
                    } else {
                        format!("PART {}", channel)
                    };
                    for (nick, _) in &chanobj.users {
                        state.users.get(&nick.clone()).unwrap().send_msg_display(
                                    &conn_state.user_state.source, part_msg.as_str())?;
                    }
                }
            } else {
                self.feed_msg(&mut conn_state.stream,
                                ErrNoSuchChannel403{ client, channel }).await?;
                removed_from.push(false);
            }
        }
        
        let user_nick = conn_state.user_state.nick.as_ref().unwrap().clone();
        let mut user = state.users.get_mut(user_nick.as_str()).unwrap();
        for channel in &channels {
            user.channels.remove(&channel.to_string());
        }
        if something_done {
            user.last_activity = SystemTime::now().duration_since(UNIX_EPOCH)
                        .unwrap().as_secs();
        }
        Ok(())
    }
    
    async fn process_topic<'a>(&self, conn_state: &mut ConnState, channel: &'a str,
            topic_opt: Option<&'a str>, msg: &'a Message<'a>) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        
        if let Some(topic) = topic_opt {
            let mut state = self.state.write().await;
            let user_nick = conn_state.user_state.nick.as_ref().unwrap();
            
            let do_change_topic = if let Some(chanobj) = state.channels.get(channel) {
                let user = state.users.get(user_nick).unwrap();
                
                if chanobj.users.contains_key(user_nick) {
                    if !chanobj.modes.protected_topic || chanobj.users.get(user_nick)
                                .unwrap().operator {
                        true
                    } else {
                        self.feed_msg(&mut conn_state.stream,
                                    ErrChanOpPrivsNeeded482{ client, channel }).await?;
                        false
                    }
                } else {
                    self.feed_msg(&mut conn_state.stream,
                                ErrNotOnChannel442{ client, channel }).await?;
                    false
                }
            } else {
                self.feed_msg(&mut conn_state.stream,
                                ErrNoSuchChannel403{ client, channel }).await?;
                false
            };
            
            if do_change_topic {
                let chanobj = state.channels.get_mut(channel).unwrap();
                if topic.len() != 0 {
                    chanobj.topic = Some(ChannelTopic::new_with_nick(
                        topic.to_string(), user_nick.clone()));
                } else {
                    chanobj.topic = None
                }
            }
            if do_change_topic {
                let chanobj = state.channels.get(channel).unwrap();
                for (cu, _) in &chanobj.users {
                    state.users.get(cu).unwrap().send_message(msg,
                                &conn_state.user_state.source)?;
                }
            }
        } else {
            // read
            let state = self.state.read().await;
            if let Some(chanobj) = state.channels.get(channel) {
                let user_nick = conn_state.user_state.nick.as_ref().unwrap();
                let user = state.users.get(user_nick).unwrap();
                
                if chanobj.users.contains_key(user_nick) {
                    if let Some(ref topic) = chanobj.topic {
                        self.feed_msg(&mut conn_state.stream, RplTopic332{ client,
                            channel, topic: &topic.topic }).await?;
                        self.feed_msg(&mut conn_state.stream, RplTopicWhoTime333{ client,
                            channel, nick: &topic.nick, setat: topic.set_time }).await?;
                    } else {
                        self.feed_msg(&mut conn_state.stream, RplNoTopic331{ client,
                            channel }).await?;
                    }
                } else {
                    self.feed_msg(&mut conn_state.stream,
                                ErrNotOnChannel442{ client, channel }).await?;
                }
            } else {
                self.feed_msg(&mut conn_state.stream,
                                ErrNoSuchChannel403{ client, channel }).await?;
            }
        }
        Ok(())
    }
    
    async fn send_names_from_channel(&self, conn_state: &mut ConnState,
                channel: &Channel, users: &HashMap<String, User>, conn_user: &User)
                -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        
        let in_channel = channel.users.contains_key(&conn_user.nick);
        if !channel.modes.secret || in_channel {
            const NAMES_COUNT: usize = 20;
            let symbol = if channel.modes.secret { "=" } else { "@" };
            
            let mut name_chunk = vec![];
            name_chunk.reserve(NAMES_COUNT);
            
            for n in &channel.users {
                let user = users.get(n.0.as_str()).unwrap();
                if !user.modes.invisible || in_channel {
                    name_chunk.push(NameReplyStruct{
                        prefix: n.1.to_string(&conn_state.caps), nick: &user.nick });
                }
                if name_chunk.len() == NAMES_COUNT {
                    self.feed_msg(&mut conn_state.stream, RplNameReply353{ client, symbol,
                                channel: &channel.name, replies: &name_chunk }).await?;
                    name_chunk.clear();
                }
            }
            if name_chunk.len() != 0 {   // last chunk
                self.feed_msg(&mut conn_state.stream, RplNameReply353{ client, symbol,
                                channel: &channel.name, replies: &name_chunk }).await?;
            }
        }
        Ok(())
    }
    
    async fn process_names<'a>(&self, conn_state: &mut ConnState, channels: Vec<&'a str>)
            -> Result<(), Box<dyn Error>> {
        let state = self.state.read().await;
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        let user = state.users.get(user_nick).unwrap();
        
        if channels.len() != 0 { 
            for c in channels.iter().filter_map(|c| state.channels.get(c.clone())) {
                self.send_names_from_channel(conn_state, &c, &state.users, &user).await?;
            }
        } else {
            for c in state.channels.values() {
                self.send_names_from_channel(conn_state, &c, &state.users, &user).await?;
            }
        }
        Ok(())
    }
    
    async fn process_list<'a>(&self, conn_state: &mut ConnState, channels: Vec<&'a str>,
            server: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        
        if server.is_some() {
            self.feed_msg(&mut conn_state.stream, ErrUnknownError400{ client,
                    command: "LIST", subcommand: None, info: "Server unsupported" }).await?;
        } else {
            let state = self.state.read().await;
            self.feed_msg(&mut conn_state.stream, RplListStart321{ client }).await?;
            let mut count = 0;
            for ch in channels.iter().filter_map(|ch| {
                    state.channels.get(&ch.to_string()).filter(|ch| !ch.modes.secret)
                }) {
                self.feed_msg(&mut conn_state.stream, RplList322{ client,
                        channel: &ch.name, client_count: ch.users.len(),
                        topic: ch.topic.as_ref().map(|x| &x.topic)
                            .unwrap_or(&String::new()) }).await?;
                count += 1;
            }
            if count == 0 {
                for ch in state.channels.values().filter(|ch| !ch.modes.secret) {
                    self.feed_msg(&mut conn_state.stream, RplList322{ client,
                        channel: &ch.name, client_count: ch.users.len(),
                        topic: ch.topic.as_ref().map(|x| &x.topic)
                            .unwrap_or(&String::new()) }).await?;
                }
            }
            self.feed_msg(&mut conn_state.stream, RplListEnd323{ client }).await?;
        }
        Ok(())
    }
    
    async fn process_invite<'a>(&self, conn_state: &mut ConnState, nickname: &'a str,
            channel: &'a str, msg: &'a Message<'a>) -> Result<(), Box<dyn Error>> {
        let mut state = self.state.write().await;
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        let user = state.users.get(user_nick).unwrap();
        let client = conn_state.user_state.client_name();
        
        let do_invite = if let Some(ref chanobj) = state.channels.get(channel) {
            if chanobj.users.contains_key(user_nick) {
                if chanobj.modes.invite_only {
                    if !chanobj.users.get(user_nick).unwrap().operator {
                        self.feed_msg(&mut conn_state.stream,
                                    ErrChanOpPrivsNeeded482{ client, channel }).await?;
                        false
                    } else { true }
                } else { true }
            } else {
                self.feed_msg(&mut conn_state.stream,
                                    ErrNotOnChannel442{ client, channel }).await?;
                false
            }
        } else {
            self.feed_msg(&mut conn_state.stream,
                            ErrNoSuchChannel403{ client, channel }).await?;
            false
        };
        
        if do_invite {
            // check user
            if let Some(invited) = state.users.get_mut(nickname) {
                invited.invited_to.insert(channel.to_string());
                self.feed_msg(&mut conn_state.stream, RplInviting341{ client,
                                nick: nickname, channel }).await?;
                invited.send_message(msg, &conn_state.user_state.source)?;
            } else {
                self.feed_msg(&mut conn_state.stream,
                                ErrNoSuchNick401{ client, nick: nickname }).await?;
            }
        }
        Ok(())
    }
    
    async fn process_kick<'a>(&self, conn_state: &mut ConnState, channel: &'a str,
            kick_users: Vec<&'a str>, comment: Option<&'a str>)
            -> Result<(), Box<dyn Error>> {
        let mut statem = self.state.write().await;
        let mut state = statem.deref_mut();
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        let user = state.users.get(user_nick).unwrap();
        let client = conn_state.user_state.client_name();
        
        let mut kicked = vec![];
        
        if let Some(chanobj) = state.channels.get_mut(channel) {
            if chanobj.users.contains_key(user_nick) {
                if chanobj.users.get(user_nick).unwrap().operator {
                    for kick_user in &kick_users {
                        let ku = kick_user.to_string();
                        if let Some(chum) = chanobj.users.get(&ku) {
                            if !chum.protected {
                                chanobj.remove_user(&ku);
                                kicked.push(kick_user);
                            } else {
                                self.feed_msg(&mut conn_state.stream, ErrCannotDoCommand972{
                                    client }).await?;
                            }
                        } else {
                            self.feed_msg(&mut conn_state.stream, ErrUserNotInChannel441{
                                    client, nick: kick_user, channel }).await?;
                        }
                    }
                } else {
                    self.feed_msg(&mut conn_state.stream,
                                ErrChanOpPrivsNeeded482{ client, channel }).await?;
                }
            } else {
                self.feed_msg(&mut conn_state.stream,
                                ErrNotOnChannel442{ client, channel }).await?;
            }
        } else {
            self.feed_msg(&mut conn_state.stream,
                        ErrNoSuchChannel403{ client, channel }).await?;
        }
        
        {
            let chanobj = state.channels.get(channel).unwrap();
            for ku in &kicked {
                let kick_msg = format!("KICK {} {} :{}", channel, ku,
                                comment.unwrap_or("Kicked"));
                for (nick, _) in &chanobj.users {
                    state.users.get(&nick.to_string()).unwrap().send_msg_display(
                            &conn_state.user_state.source, kick_msg.clone())?;
                }
                state.users.get_mut(&ku.to_string()).unwrap().channels
                    .remove(&channel.to_string());
            }
        }
        Ok(())
    }
    
    async fn process_motd<'a>(&self, conn_state: &mut ConnState, target: Option<&'a str>)
            -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        
        if target.is_some() {
            self.feed_msg(&mut conn_state.stream, ErrUnknownError400{ client,
                    command: "MOTD", subcommand: None, info: "Server unsupported" }).await?;
        } else {
            self.feed_msg(&mut conn_state.stream, RplMotdStart375{ client,
                    server: &self.config.name }).await?;
            self.feed_msg(&mut conn_state.stream, RplMotd372{ client,
                    motd: &self.config.motd }).await?;
            self.feed_msg(&mut conn_state.stream, RplEndOfMotd376{ client }).await?;
        }
        Ok(())
    }
    
    async fn process_version<'a>(&self, conn_state: &mut ConnState,
            target: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        if target.is_some() {
            let client = conn_state.user_state.client_name();
            self.feed_msg(&mut conn_state.stream, ErrUnknownError400{ client,
                    command: "VERSION", subcommand: None, info: "Server unsupported" }).await?;
        } else {
            self.send_isupport(conn_state).await?;
            let client = conn_state.user_state.client_name();
            self.feed_msg(&mut conn_state.stream, RplVersion351{ client,
                version: concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION")),
                server: &self.config.name, comments: "simple IRC server" }).await?;
        }
        Ok(())
    }
    
    async fn process_admin<'a>(&self, conn_state: &mut ConnState,
            target: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        if target.is_some() {
            self.feed_msg(&mut conn_state.stream, ErrUnknownError400{ client,
                    command: "ADMIN", subcommand: None, info: "Server unsupported" }).await?;
        } else {
            self.feed_msg(&mut conn_state.stream, RplAdminMe256{ client,
                    server: &self.config.name }).await?;
            self.feed_msg(&mut conn_state.stream, RplAdminLoc1257{ client,
                    info: &self.config.admin_info }).await?;
            if let Some(ref info2) = self.config.admin_info2 {
                self.feed_msg(&mut conn_state.stream, RplAdminLoc2258{ client,
                        info: info2 }).await?;
            }
            if let Some(ref email) = self.config.admin_email {
                self.feed_msg(&mut conn_state.stream, RplAdminEmail259{ client,
                        email: email }).await?;
            }
        }
        Ok(())
    }
    
    async fn process_connect<'a>(&self, conn_state: &mut ConnState, target_server: &'a str,
            port: Option<u16>, remote_server: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_lusers(&self, conn_state: &mut ConnState)
            -> Result<(), Box<dyn Error>> {
        let state = self.state.read().await;
        let client = conn_state.user_state.client_name();
        self.feed_msg(&mut conn_state.stream, RplLUserClient251{ client, 
                users_num: state.users.len() - state.invisible_users_count,
                inv_users_num: state.invisible_users_count, servers_num: 1 }).await?;
        self.feed_msg(&mut conn_state.stream, RplLUserOp252{ client,
                ops_num: state.operators_count }).await?;
        self.feed_msg(&mut conn_state.stream, RplLUserUnknown253{ client,
                conns_num: 0 }).await?;
        self.feed_msg(&mut conn_state.stream, RplLUserChannels254{ client,
                channels_num: state.channels.len() }).await?;
        self.feed_msg(&mut conn_state.stream, RplLUserMe255{ client,
                clients_num: state.users.len(), servers_num: 1 }).await?;
        self.feed_msg(&mut conn_state.stream, RplLocalUsers265{ client,
                clients_num: state.users.len(),
                max_clients_num: state.max_users_count }).await?;
        self.feed_msg(&mut conn_state.stream, RplGlobalUsers266{ client,
                clients_num: state.users.len(),
                max_clients_num: state.max_users_count }).await?;
        Ok(())
    }
    
    async fn process_time<'a>(&self, conn_state: &mut ConnState, server: Option<&'a str>)
            -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        
        if server.is_some() {
            self.feed_msg(&mut conn_state.stream, ErrUnknownError400{ client,
                    command: "TIME", subcommand: None, info: "Server unsupported" }).await?;
        } else {
            let time = Local::now();
            self.feed_msg(&mut conn_state.stream, RplTime391{ client,
                server: &self.config.name, timestamp: time.timestamp() as u64,
                    ts_offset: "", human_readable: time.to_rfc2822().as_str() }).await?;
        }
        Ok(())
    }
    
    async fn process_stats<'a>(&self, conn_state: &mut ConnState, query: char,
            server: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_links<'a>(&self, conn_state: &mut ConnState,
            remote_server: Option<&'a str>, server_mask: Option<&'a str>)
            -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        self.feed_msg(&mut conn_state.stream, RplLinks364{ client,
                server: &self.config.name, mask: &self.config.name, 
                hop_count: 0, server_info: &self.config.info }).await?;
        self.feed_msg(&mut conn_state.stream, RplEndOfLinks365{ client, mask: "*" }).await?;
        Ok(())
    }
    
    async fn process_help<'a>(&self, conn_state: &mut ConnState, nick: &'a str)
            -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_info(&self, conn_state: &mut ConnState)
            -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        
        self.feed_msg(&mut conn_state.stream, RplInfo371{ client, info:
            concat!(env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION")) }).await?;
        self.feed_msg(&mut conn_state.stream, RplEndOfInfo374{ client }).await?;
        Ok(())
    }
    
    async fn process_mode_channel<'a>(&self, conn_state: &mut ConnState,
            chanobj: &mut Channel, target: &'a str, modes: Vec<(&'a str, Vec<&'a str>)>,
            if_op: bool) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        //
        for (mchars, margs) in modes {
            let mut margs_it = margs.iter();
            let mut mode_set = false;
            for mchar in mchars.chars() {
                match mchar {
                    'i'|'m'|'t'|'n'|'s'|'l'|'k'|'o'|'v'|'h'|'q'|'a' => {
                        if !if_op {
                            self.feed_msg(&mut conn_state.stream,
                                ErrChanOpPrivsNeeded482{ client,
                                        channel: target }).await?;
                        }
                    }
                    _ => (),
                }
            
                match mchar {
                    '+' => mode_set = true,
                    '-' => mode_set = false,
                    'b' => {
                        if let Some(bmask) = margs_it.next() {
                            if if_op {
                                let mut ban = chanobj.modes.ban.take()
                                        .unwrap_or_default();
                                let norm_bmask = normalize_sourcemask(bmask);
                                if mode_set {
                                    ban.insert(norm_bmask.clone());
                                    chanobj.ban_info.insert(norm_bmask.clone(), BanInfo{
                                        who: conn_state.user_state.nick
                                                .as_ref().unwrap().to_string(),
                                        set_time: SystemTime::now()
                                            .duration_since(UNIX_EPOCH).unwrap().as_secs() });
                                } else {
                                    ban.remove(&norm_bmask);
                                    chanobj.ban_info.remove(&norm_bmask);
                                }
                                chanobj.modes.ban = Some(ban);
                            } else {
                                self.feed_msg(&mut conn_state.stream, ErrChanOpPrivsNeeded482{
                                        client, channel: target }).await?;
                            }
                        } else { // print
                            if let Some(ban) = &chanobj.modes.ban {
                                for b in ban {
                                    if let Some(ban_info) = chanobj.ban_info
                                            .get(&b.clone()) {
                                        self.feed_msg(&mut conn_state.stream,
                                            RplBanList367{ client, channel: target, mask: &b,
                                                who: &ban_info.who,
                                                set_ts: ban_info.set_time }).await?;
                                    } else {
                                        self.feed_msg(&mut conn_state.stream,
                                            RplBanList367{ client, channel: target,
                                            mask: &b, who: "", set_ts: 0 }).await?;
                                    }
                                }
                            }
                            self.feed_msg(&mut conn_state.stream,  RplEndOfBanList368{
                                    client, channel: target }).await?;
                        }
                    },
                    'e' => {
                        if let Some(emask) = margs_it.next() {
                            if if_op {
                                let mut exp = chanobj.modes.exception.take()
                                        .unwrap_or_default();
                                if mode_set {
                                    exp.insert(normalize_sourcemask(emask));
                                } else {
                                    exp.remove(&normalize_sourcemask(emask));
                                }
                                chanobj.modes.exception = Some(exp);
                            } else {
                                self.feed_msg(&mut conn_state.stream, ErrChanOpPrivsNeeded482{
                                        client, channel: target }).await?;
                            }
                        } else { // print
                            if let Some(exception) = &chanobj.modes.exception {
                                for e in exception {
                                    self.feed_msg(&mut conn_state.stream, RplExceptList348{
                                        client, channel: target, mask: &e }).await?;
                                }
                            }
                            self.feed_msg(&mut conn_state.stream, 
                                RplEndOfExceptList349{ client,
                                        channel: target }).await?;
                        }
                    },
                    'I' => {
                        if let Some(imask) = margs_it.next() {
                            if if_op {
                                let mut exp = chanobj.modes.invite_exception.take()
                                        .unwrap_or_default();
                                if mode_set {
                                    exp.insert(normalize_sourcemask(imask));
                                } else {
                                    exp.remove(&normalize_sourcemask(imask));
                                }
                                chanobj.modes.invite_exception = Some(exp);
                            } else {
                                self.feed_msg(&mut conn_state.stream, ErrChanOpPrivsNeeded482{
                                        client, channel: target }).await?;
                            }
                        } else { // print
                            if let Some(inv_ex) = &chanobj.modes.invite_exception {
                                for e in inv_ex {
                                    self.feed_msg(&mut conn_state.stream, RplInviteList346{
                                        client, channel: target, mask: &e }).await?;
                                }
                            }
                            self.feed_msg(&mut conn_state.stream, 
                                RplEndOfInviteList347{ client,
                                        channel: target }).await?;
                        }
                    },
                    'o'|'v'|'h'|'q'|'a' => {
                        let arg = margs_it.next().unwrap();
                        if chanobj.users.contains_key(&arg.to_string()) {
                            match mchar {
                                'o' => {
                                    if if_op {
                                        if mode_set {
                                            chanobj.add_operator(&arg);
                                        } else {
                                            chanobj.remove_operator(&arg);
                                        }
                                    }
                                },
                                'v' => {
                                    if if_op {
                                        if mode_set {
                                            chanobj.add_voice(&arg);
                                        } else {
                                            chanobj.remove_voice(&arg);
                                        }
                                    }
                                },
                                'h' => {
                                    if if_op {
                                        if mode_set {
                                            chanobj.add_half_operator(&arg);
                                        } else {
                                            chanobj.remove_half_operator(&arg);
                                        }
                                    }
                                },
                                'q' => {
                                    if if_op {
                                        if mode_set {
                                            chanobj.add_founder(&arg);
                                        } else {
                                            chanobj.remove_founder(&arg);
                                        }
                                    }
                                },
                                'a' => {
                                    if if_op {
                                        if mode_set {
                                            chanobj.add_protected(&arg);
                                        } else {
                                            chanobj.remove_protected(&arg);
                                        }
                                    }
                                },
                                _ => {},
                            }
                        } else {
                            self.feed_msg(&mut conn_state.stream, ErrNotOnChannel442{ client,
                                    channel: target }).await?;
                        }
                    },
                    'l' => { 
                        let arg = margs_it.next().unwrap();
                        if if_op {
                            chanobj.modes.client_limit = if mode_set {
                                Some(arg.parse::<usize>().unwrap())
                            } else { None };
                        }
                    },
                    'k' => { 
                        let arg = margs_it.next().unwrap();
                        if if_op { chanobj.modes.key =
                            if mode_set { Some(arg.to_string()) } else { None }; }
                    },
                    'i' => if if_op { chanobj.modes.invite_only = mode_set; },
                    'm' => if if_op { chanobj.modes.moderated = mode_set; },
                    't' => if if_op { chanobj.modes.protected_topic = mode_set; },
                    'n' => if if_op {
                            chanobj.modes.no_external_messages = mode_set; },
                    's' => if if_op { chanobj.modes.secret = mode_set; },
                    _ => (),
                }
            }
        }
        Ok(())
    }
    
    async fn process_mode_user<'a>(&self, conn_state: &mut ConnState,
            state: &mut VolatileState, target: &'a str,
            modes: Vec<(&'a str, Vec<&'a str>)>) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        let mut user = state.users.get_mut(target).unwrap();
        let user_nick = target;
        for (mchars, _) in modes {
            let mut mode_set = false;
            for mchar in mchars.chars() {
                match mchar {
                    '+' => mode_set = true,
                    '-' => mode_set = false,
                    'i' => {
                        if mode_set {
                            if !user.modes.invisible {
                                user.modes.invisible = true;
                                state.invisible_users_count += 1;
                            }
                        } else {
                            if user.modes.invisible {
                                user.modes.invisible = false;
                                state.invisible_users_count -= 1;
                            }
                        }
                    },
                    'r' => {
                        if mode_set {
                            if !user.modes.registered {
                                if conn_state.user_state.registered {
                                    user.modes.registered = true;
                                } else {
                                    self.feed_msg(&mut conn_state.stream,
                                        ErrNoPrivileges481{ client }).await?;
                                }
                            }
                        } else {
                            if user.modes.registered {
                                user.modes.registered = false;
                                self.feed_msg(&mut conn_state.stream,
                                    ErrYourConnRestricted484{ client }).await?;
                            }
                        }
                    },
                    'w' => {
                        if mode_set {
                            if !user.modes.wallops {
                                state.wallops_users.insert(user_nick.to_string());
                                user.modes.wallops = true;
                            }
                        } else {
                            if user.modes.wallops {
                                state.wallops_users.remove(&user_nick.to_string());
                                user.modes.wallops = false;
                            }
                        }
                    },
                    'o' => {
                        if mode_set {
                            if !user.modes.oper {
                                if self.oper_config_idxs.contains_key(user_nick) {
                                    user.modes.oper = true;
                                    if !user.modes.local_oper {
                                        state.operators_count += 1;
                                    }
                                } else {
                                    self.feed_msg(&mut conn_state.stream,
                                        ErrNoPrivileges481{ client }).await?;
                                }
                            }
                        } else {
                            if user.modes.oper {
                                user.modes.oper = false;
                                if !user.modes.local_oper {
                                    state.operators_count -= 1;
                                }
                            }
                        }
                    },
                    'O' => {
                        if mode_set {
                            if !user.modes.local_oper {
                                if self.oper_config_idxs.contains_key(user_nick) {
                                    user.modes.oper = true;
                                    if !user.modes.oper {
                                        state.operators_count += 1;
                                    }
                                } else {
                                    self.feed_msg(&mut conn_state.stream,
                                        ErrNoPrivileges481{ client }).await?;
                                }
                            }
                        } else {
                            if user.modes.oper {
                                user.modes.oper = false;
                                if !user.modes.oper {
                                    state.operators_count -= 1;
                                }
                            }
                        }
                    },
                    _ => (),
                }
            }
        }
        Ok(())
    }
    
    async fn process_mode<'a>(&self, conn_state: &mut ConnState, target: &'a str,
            modes: Vec<(&'a str, Vec<&'a str>)>) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        let mut statem = self.state.write().await;
        let mut state = statem.deref_mut();
        
        if validate_channel(target).is_ok() {
            let user = state.users.get(target).unwrap();
            // channel
            if let Some(chanobj) = state.channels.get_mut(target) {
                let (if_op, error) = if let Some(ref chum) = chanobj.users.get(user_nick) {
                    (chum.operator, false)
                } else {
                    self.feed_msg(&mut conn_state.stream, ErrNotOnChannel442{ client,
                            channel: target }).await?;
                    (false, true)
                };
                if !error {
                    self.process_mode_channel(conn_state, chanobj, target,
                            modes, if_op).await?;
                }
            } else {
                self.feed_msg(&mut conn_state.stream, ErrNoSuchChannel403{ client,
                            channel: target }).await?;
            }
        } else {
            // user
            if user_nick == target {
                self.process_mode_user(conn_state, state, target, modes).await?;
            } else if state.users.contains_key(target) {
                self.feed_msg(&mut conn_state.stream,
                        ErrUsersDontMatch502{ client }).await?;
            } else {
                self.feed_msg(&mut conn_state.stream,
                        ErrNoSuchNick401{ client, nick: target }).await?;
            }
        }
        Ok(())
    }
    
    async fn process_privmsg_notice<'a>(&self, conn_state: &mut ConnState,
            targets: Vec<&'a str>, text: &'a str,
            notice: bool) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        
        let mut something_done = false;
        {
        let state = self.state.read().await;
        let user = state.users.get(user_nick).unwrap();
        
        for target in HashSet::<&&str>::from_iter(targets.iter()) {
            let msg_str = if notice {
                format!("NOTICE {} :{}", target, text)
            } else { format!("PRIVMSG {} :{}", target, text) };
            let (target_type, chan_str) = get_privmsg_target_type(target);
            if target_type.contains(PrivMsgTargetType::Channel) { // to channel
                if let Some(chanobj) = state.channels.get(chan_str) {
                    let chanuser_mode = chanobj.users.get(user_nick);
                    let can_send = {
                        if (!chanobj.modes.no_external_messages &&
                                    !chanobj.modes.secret) ||
                                chanuser_mode.is_some() {
                            true
                        } else {
                            if !notice {
                                self.feed_msg(&mut conn_state.stream, ErrCannotSendToChain404{
                                        client, channel: chan_str }).await?;
                            }
                            false
                        }
                    };
                    let can_send = can_send && {
                        if !chanobj.modes.banned(&conn_state.user_state.source) {
                            true
                        } else {
                            if !notice {
                                self.feed_msg(&mut conn_state.stream, ErrCannotSendToChain404{
                                        client, channel: chan_str }).await?;
                            }
                            false
                        }
                    };
                    let can_send = can_send && {
                        if !chanobj.modes.moderated ||
                            chanuser_mode.map_or(false, |chum| chum.voice) {
                            true
                        } else {
                            if !notice {
                                self.feed_msg(&mut conn_state.stream, ErrCannotSendToChain404{
                                        client, channel: chan_str }).await?;
                            }
                            false
                        }
                    };
                    
                    if can_send {
                        use PrivMsgTargetType::*;
                        if !(target_type & ChannelAllSpecial).is_empty() {
                            // to special
                            if !(target_type & ChannelFounder).is_empty() {
                                if let Some(ref founders) = chanobj.modes.founders {
                                    founders.iter().try_for_each(|u|
                                        state.users.get(u).unwrap().send_msg_display(
                                                &conn_state.user_state.source, &msg_str))?;
                                }
                            }
                            if !(target_type & ChannelProtected).is_empty() {
                                if let Some(ref protecteds) = chanobj.modes.protecteds {
                                    protecteds.iter().try_for_each(|u|
                                        state.users.get(u).unwrap().send_msg_display(
                                                &conn_state.user_state.source, &msg_str))?;
                                }
                            }
                            if !(target_type & ChannelOper).is_empty() {
                                if let Some(ref operators) = chanobj.modes.operators {
                                    operators.iter().try_for_each(|u|
                                        state.users.get(u).unwrap().send_msg_display(
                                                &conn_state.user_state.source, &msg_str))?;
                                }
                            }
                            if !(target_type & ChannelHalfOper).is_empty() {
                                if let Some(ref half_ops) = chanobj.modes.half_operators {
                                    half_ops.iter().try_for_each(|u|
                                        state.users.get(u).unwrap().send_msg_display(
                                                &conn_state.user_state.source, &msg_str))?;
                                }
                            }
                            if !(target_type & ChannelVoice).is_empty() {
                                if let Some(ref voices) = chanobj.modes.voices {
                                    voices.iter().try_for_each(|u|
                                        state.users.get(u).unwrap().send_msg_display(
                                                &conn_state.user_state.source, &msg_str))?;
                                }
                            }
                        } else {
                            chanobj.users.keys().try_for_each(|u|
                                state.users.get(u).unwrap().send_msg_display(
                                        &conn_state.user_state.source, &msg_str))?;
                        }
                        something_done = true;
                    }
                } else {
                    if !notice {
                        self.feed_msg(&mut conn_state.stream,
                                ErrNoSuchChannel403{ client, channel: chan_str }).await?;
                    }
                }
            } else {    // to user
                if let Some(cur_user) = state.users.get(*target) {
                    cur_user.send_msg_display(&conn_state.user_state.source, msg_str)?;
                    if !notice {
                        if let Some(ref away) = cur_user.away {
                            self.feed_msg(&mut conn_state.stream, RplAway301{ client,
                                        nick: target, message: &away }).await?;
                        }
                    }
                    something_done = true;
                } else {
                    if !notice {
                        self.feed_msg(&mut conn_state.stream, ErrNoSuchNick401{ client,
                                        nick: target }).await?;
                    }
                }
            }
        }
        }
        
        {
            if something_done {
                let mut state = self.state.write().await;
                let mut user = state.users.get_mut(user_nick).unwrap();
                user.last_activity = SystemTime::now().duration_since(UNIX_EPOCH)
                        .unwrap().as_secs();
            }
        }
        Ok(())
    }
    
    async fn process_privmsg<'a>(&self, conn_state: &mut ConnState, targets: Vec<&'a str>,
            text: &'a str) -> Result<(), Box<dyn Error>> {
        self.process_privmsg_notice(conn_state, targets, text, false).await
    }
    
    async fn process_notice<'a>(&self, conn_state: &mut ConnState, targets: Vec<&'a str>,
            text: &'a str) -> Result<(), Box<dyn Error>> {
        self.process_privmsg_notice(conn_state, targets, text, true).await
    }
    
    async fn send_who_info<'a>(&self, conn_state: &mut ConnState,
            channel: Option<(&'a str, &ChannelUserModes)>,
            user: &User, cmd_user: &User) -> Result<(), Box<dyn Error>> {
        if !user.modes.invisible || !user.channels.is_disjoint(&cmd_user.channels) {
            let client = conn_state.user_state.client_name();
            let mut flags = String::new();
            if user.away.is_some() { flags.push('G');
            } else { flags.push('H'); }
            if user.modes.local_oper || user.modes.oper {
                flags.push('*');
            }
            if let Some((_, ref chum)) = channel {
                flags += &chum.to_string(&conn_state.caps);
            }
            self.feed_msg(&mut conn_state.stream, RplWhoReply352{ client,
                channel: channel.map(|(c,_)| c).unwrap_or("*"), username: &user.name,
                host: &user.hostname, server: &self.config.name, nick: &user.nick,
                flags: &flags, hopcount: 0, realname: &user.realname}).await?;
        }
        Ok(())
    }
    
    async fn process_who<'a>(&self, conn_state: &mut ConnState, mask: &'a str)
            -> Result<(), Box<dyn Error>> {
        let state = self.state.read().await;
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        let user = state.users.get(user_nick).unwrap();
        
        if mask.contains('*') || mask.contains('?') {
            for (_, u) in &state.users {
                if match_wildcard(mask, &u.nick) || match_wildcard(mask, &u.source) ||
                    match_wildcard(mask, &u.realname) {
                    self.send_who_info(conn_state, None, &u, &user).await?;
                }
            }
        } else if validate_channel(mask).is_ok() {
            if let Some(channel) = state.channels.get(mask) {
                for (u, chum) in &channel.users {
                    self.send_who_info(conn_state, Some((&channel.name, chum)),
                        state.users.get(u).unwrap(), &user).await?;
                }
            }
        } else if validate_username(mask).is_ok() {
            if let Some(ref arg_user) = state.users.get(mask) {
                self.send_who_info(conn_state, None, arg_user, &user).await?;
            }
        }
        let client = conn_state.user_state.client_name();
        self.feed_msg(&mut conn_state.stream, RplEndOfWho315{ client, mask }).await?;
        Ok(())
    }
    
    async fn process_whois<'a>(&self, conn_state: &mut ConnState, target: Option<&'a str>,
            nickmasks: Vec<&'a str>) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        
        if target.is_some() {
            self.feed_msg(&mut conn_state.stream, ErrUnknownError400{ client,
                    command: "WHOIS", subcommand: None, info: "Server unsupported" }).await?;
        } else {
            let state = self.state.read().await;
            let user_nick = conn_state.user_state.nick.as_ref().unwrap();
            let user = state.users.get(user_nick).unwrap();
            
            let mut nicks = HashSet::<String>::new();
            let mut real_nickmasks = vec![];
            
            nickmasks.iter().for_each(|nickmask| {
                if nickmask.contains('*') || nickmask.contains('?') {
                    // wildcard
                    real_nickmasks.push(nickmask);
                } else {
                    if state.users.contains_key(&nickmask.to_string()) {
                        nicks.insert(nickmask.to_string());
                    }
                }
            });
            
            state.users.keys().for_each(|nick| {
                if real_nickmasks.iter().any(|mask| match_wildcard(mask, nick)) {
                    nicks.insert(nick.to_string());
                }
            });
            
            for nick in nicks {
                let arg_user = state.users.get(&nick).unwrap();
                if arg_user.modes.invisible &&
                    arg_user.channels.is_disjoint(&user.channels) { continue; }
                
                if arg_user.modes.registered {
                    self.feed_msg(&mut conn_state.stream, RplWhoIsRegNick307{ client,
                            nick: &nick }).await?;
                }
                self.feed_msg(&mut conn_state.stream, RplWhoIsUser311{ client,
                        nick: &nick, username: &user.name, host: &user.hostname,
                        realname: &user.realname }).await?;
                self.feed_msg(&mut conn_state.stream, RplWhoIsServer312{ client,
                        nick: &nick, server: &self.config.name,
                        server_info: &self.config.info }).await?;
                if arg_user.modes.oper || arg_user.modes.local_oper {
                    self.feed_msg(&mut conn_state.stream, RplWhoIsOperator313{ client,
                            nick: &nick }).await?;
                }
                // channels
                let channel_replies = arg_user.channels.iter()
                    .filter_map(|chname| {
                    let ch = state.channels.get(chname).unwrap();
                    if !ch.modes.secret {
                        Some(WhoIsChannelStruct{ prefix: Some(ch.users.get(&arg_user.nick)
                            .unwrap().to_string(&conn_state.caps)).clone(),
                            channel: &ch.name })
                    } else { None }
                    }).collect::<Vec<_>>();
                
                for chr_chunk in channel_replies.chunks(30) {
                    self.feed_msg(&mut conn_state.stream, RplWhoIsChannels319{ client,
                            nick: &nick, channels: &chr_chunk }).await?;
                }
                
                self.feed_msg(&mut conn_state.stream, RplwhoIsIdle317{ client,
                        nick: &nick, secs: SystemTime::now().duration_since(UNIX_EPOCH)
                            .unwrap().as_secs() - user.last_activity,
                        signon: user.signon }).await?;
                if user.modes.oper || user.modes.local_oper {
                    self.feed_msg(&mut conn_state.stream, RplWhoIsHost378{ client,
                            nick: &nick, host_info: &user.hostname }).await?;
                    self.feed_msg(&mut conn_state.stream, RplWhoIsModes379{ client,
                            nick: &nick, modes: &user.modes.to_string() }).await?;
                }
            }
            self.feed_msg(&mut conn_state.stream, RplEndOfWhoIs318{ client,
                nick: &nickmasks.join(",") }).await?;
        }
        Ok(())
    }
    
    async fn process_whowas<'a>(&self, conn_state: &mut ConnState, nickname: &'a str,
            count: Option<usize>, server: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        
        if server.is_some() {
            self.feed_msg(&mut conn_state.stream, ErrUnknownError400{ client,
                    command: "WHOWAS", subcommand: None, info: "Server unsupported" }).await?;
        } else {
            let state = self.state.read().await;
            if let Some(hist) = state.nick_histories.get(&nickname.to_string()) {
                let hist_count = if let Some(c) = count {
                    if c > 0 { c } else { hist.len() }
                } else { hist.len() };
                for entry in hist.iter().rev().take(hist_count) {
                    self.feed_msg(&mut conn_state.stream, RplWhoWasUser314{ client,
                            nick: &nickname, username: &entry.username,
                            host: &entry.hostname, realname: &entry.realname }).await?;
                    self.feed_msg(&mut conn_state.stream, RplWhoIsServer312{ client,
                            nick: &nickname, server: &self.config.name,
                            server_info: &format!("Logged in at {}",
                                DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(
                                        entry.signon as i64, 0), Utc)) }).await?;
                }
            } else {
                self.feed_msg(&mut conn_state.stream, ErrWasNoSuchNick406{ client,
                    nick: nickname }).await?;
            }
            self.feed_msg(&mut conn_state.stream, RplEndOfWhoWas369{ client,
                    nick: nickname }).await?;
        }
        Ok(())
    }
    
    async fn process_kill<'a>(&self, conn_state: &mut ConnState, nickname: &'a str,
            comment: &'a str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_rehash(&self, conn_state: &mut ConnState)
            -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_restart(&self, conn_state: &mut ConnState)
            -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_squit<'a>(&self, conn_state: &mut ConnState, server: &'a str,
            comment: &'a str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_away<'a>(&self, conn_state: &mut ConnState, text: Option<&'a str>)
            -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        let mut state = self.state.write().await;
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        let mut user = state.users.get_mut(user_nick).unwrap();
        if let Some(t) = text {
            user.away = Some(t.to_string());
            self.feed_msg(&mut conn_state.stream, RplNowAway306{ client }).await?;
        } else {
            user.away = None;
            self.feed_msg(&mut conn_state.stream, RplUnAway305{ client }).await?;
        }
        Ok(())
    }
    
    async fn process_userhost<'a>(&self, conn_state: &mut ConnState,
            nicknames: Vec<&'a str>) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        let state = self.state.read().await;
        
        for nicks in nicknames.chunks(20) {
            let replies = nicks.iter().map(|nick| {
                let user = state.users.get(&nick.to_string()).unwrap();
                format!("{}=+~{}@{}", nick, user.name, user.hostname)
            }).collect::<Vec<_>>();
            self.feed_msg(&mut conn_state.stream, RplUserHost302{ client,
                    replies: &replies }).await?;
        }
        Ok(())
    }
    
    async fn process_wallops<'a>(&self, conn_state: &mut ConnState, text: &'a str,
            msg: &'a Message<'a>) -> Result<(), Box<dyn Error>> {
        let state = self.state.read().await;
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        let user = state.users.get(user_nick).unwrap();
        
        if user.modes.local_oper || user.modes.oper {
            state.wallops_users.iter().try_for_each(|wu| state.users.get(wu).unwrap()
                .send_message(msg, &conn_state.user_state.source))?;
        } else {
            let client = conn_state.user_state.client_name();
            self.feed_msg(&mut conn_state.stream, ErrNoPrivileges481{ client }).await?;
        }
        Ok(())
    }
}
