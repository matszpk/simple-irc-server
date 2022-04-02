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

use std::ops::Deref;
use std::cell::{RefCell};
use std::pin::Pin;
use std::collections::HashMap;
use std::fmt;
use std::rc::{Rc, Weak};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::net::IpAddr;
use std::error::Error;
use std::time::Duration;
use std::convert::TryFrom;
use tokio::sync::{Mutex, RwLock, oneshot};
use tokio_stream::StreamExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{Framed, LinesCodec, LinesCodecError};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver,UnboundedSender};
use tokio::time;
use futures::SinkExt;
use chrono::prelude::*;
use const_table::const_table;

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
    CHANMODES = SupportTokenStringValue{ name: "CHANMODES", value: "Ibehiklmnopstv" },
    CHANTYPES = SupportTokenStringValue{ name: "CHANTYPES", value: "&#" },
    EXCEPTS = SupportTokenStringValue{ name: "EXCEPTS", value: "e" },
    INVEX = SupportTokenStringValue{ name: "INVEX", value: "I" },
    MAXLIST = SupportTokenStringValue{ name: "MAXLISt", value: "beI:1000" },
    PREFIX = SupportTokenStringValue{ name: "PREFIX", value: "(ohv)@%+" },
    STATUSMSG = SupportTokenStringValue{ name: "STATUSMSG", value: "@%+" },
    USERMODES = SupportTokenStringValue{ name: "CHANMODES", value: "Oiorw" },
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

struct UserModifiable {
    name: String,
    realname: String,
    nick: String,
    source: String, // IRC source for mask matching
    modes: UserModes,
    away: Option<String>,
    // user state
    operator: bool,
    channels: HashMap<String, Weak<Channel>>,
}

impl UserModifiable {
    fn update_nick(&mut self, user_state: &ConnUserState) {
        if let Some(ref nick) = user_state.nick { self.nick = nick.clone(); }
        self.source = user_state.source.clone();
    }
}

struct User {
    hostname: String,
    sender: UnboundedSender<String>,
    modifiable: RefCell<UserModifiable>,
}

impl User {
    fn new(config: &MainConfig, user_state: &ConnUserState, registered: bool,
            sender: UnboundedSender<String>) -> User {
        let mut user_modes = config.default_user_modes;
        user_modes.registered = registered;
        User{ hostname: user_state.hostname.clone(), sender,
                modifiable: RefCell::new(UserModifiable{
                    name: user_state.name.as_ref().unwrap().clone(),
                    realname: user_state.realname.as_ref().unwrap().clone(),
                    nick: user_state.name.as_ref().unwrap().clone(),
                    source: user_state.source.clone(),
                    modes: user_modes, operator: false, away: None,
                    channels: HashMap::new() }) }
    }
}

enum OperatorType {
    NoOper,
    Oper,
    HalfOper,
}

struct ChannelUserMode {
    founder: bool,
    protected: bool,
    voice: bool,
    oper_type: OperatorType,
}

struct ChannelUser {
    user: Rc<User>,
    mode: RefCell<ChannelUserMode>,
}

struct Channel {
    name: String,
    topic: String,
    modes: ChannelModes,
    users: HashMap<String, ChannelUser>,
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
            s.push('!');
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
}

impl ConnState {
    fn new(ip_addr: IpAddr, stream: Framed<TcpStream, IRCLinesCodec>) -> ConnState {
        let (sender, receiver) = unbounded_channel();
        let (ping_sender, ping_receiver) = unbounded_channel();
        let (timeout_sender, timeout_receiver) = unbounded_channel();
        ConnState{ stream, sender: Some(sender), receiver,
            user_state: ConnUserState::new(ip_addr),
            ping_sender: Some(ping_sender), ping_receiver,
            timeout_sender: Arc::new(timeout_sender), timeout_receiver,
            pong_notifier: None,
            caps_negotation: false, caps: CapState::default(),
            quit: Arc::new(AtomicI32::new(0)) }
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
    users: HashMap<String, Rc<User>>,
    channels: HashMap<String, Rc<Channel>>,
}

impl VolatileState {
    fn new_from_config(config: &MainConfig) -> VolatileState {
        let mut channels = HashMap::new();
        if let Some(ref cfg_channels) = config.channels {
            cfg_channels.iter().for_each(|c| {
                channels.insert(c.name.clone(), Rc::new(Channel{ name: c.name.clone(), 
                    topic: c.topic.clone(), modes: c.modes.clone(),
                    users: HashMap::new() }));
            });
        }
        
        VolatileState{ users: HashMap::new(), channels }
    }
}

pub(crate) struct MainState {
    config: MainConfig,
    // key is user name
    user_config_idxs: HashMap<String, usize>,
    // key is oper name
    oper_config_idxs: HashMap<String, usize>,
    state: RwLock<VolatileState>,
    created: String,
}

impl MainState {
    fn new_from_config(config: MainConfig) -> MainState {
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
                created: Local::now().to_rfc2822() }
    }
    
    pub(crate) async fn process(&self, conn_state: &mut ConnState)
                -> Result<(), Box<dyn Error>> {
        let res = self.process_internal(conn_state).await;
        conn_state.stream.flush().await?;
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
                match cmd {
                    CAP{ subcommand, caps, version } =>
                        self.process_cap(conn_state, subcommand, caps, version).await,
                    AUTHENTICATE{ } =>
                        self.process_authenticate(conn_state).await,
                    PASS{ password } =>
                        self.process_pass(conn_state, password).await,
                    NICK{ nickname } =>
                        self.process_nick(conn_state, nickname).await,
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
                        self.process_topic(conn_state, channel, topic).await,
                    NAMES{ channels } =>
                        self.process_names(conn_state, channels).await,
                    LIST{ channels, server } =>
                        self.process_list(conn_state, channels, server).await,
                    INVITE{ nickname, channel } =>
                        self.process_invite(conn_state, nickname, channel).await,
                    KICK{ channel, user, comment } =>
                        self.process_kick(conn_state, channel, user, comment).await,
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
                        self.process_wallops(conn_state, text).await,
                }
            },
        }
    }
    
    async fn feed_msg<T: fmt::Display>(&self,
            stream: &mut Framed<TcpStream, IRCLinesCodec>, t: T)
            -> Result<(), LinesCodecError> {
        stream.feed(format!(":{} {}", self.config.name, t)).await
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
                    let user = Rc::new(User::new(&self.config, &user_state, registered,
                                conn_state.sender.take().unwrap()));
                    state.users.insert(user_state.nick.as_ref().unwrap().clone(),
                        user.clone());
                    let umode_str = user.modifiable.borrow().modes.to_string();
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
                            avail_chmodes: "Ibehiklmnopstv",
                            avail_chmodes_with_params: None }).await?;
                    
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
    
    async fn process_nick<'a>(&self, conn_state: &mut ConnState, nick: &'a str)
            -> Result<(), Box<dyn Error>> {
        if !conn_state.user_state.authenticated {
            conn_state.user_state.set_nick(nick.to_string());
            self.authenticate(conn_state).await?;
        } else {
            let mut state = self.state.write().await;
            let old_nick = conn_state.user_state.nick.as_ref().unwrap().to_string();
            if nick != old_nick {
                let nick_str = nick.to_string();
                if !state.users.get(&nick_str).is_some() {
                    let user = state.users.remove(&old_nick).unwrap();
                    conn_state.user_state.set_nick(nick_str.clone());
                    user.modifiable.borrow_mut().update_nick(&conn_state.user_state);
                    state.users.insert(nick_str, user);
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
        Ok(())
    }
    
    async fn process_quit(&self, conn_state: &mut ConnState)
            -> Result<(), Box<dyn Error>> {
        conn_state.quit.store(1, Ordering::SeqCst);
        self.feed_msg(&mut conn_state.stream, "ERROR: Closing connection").await?;
        Ok(())
    }
    
    async fn process_join<'a>(&self, conn_state: &mut ConnState, channels: Vec<&'a str>,
            keys: Option<Vec<&'a str>>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_part<'a>(&self, conn_state: &mut ConnState, channels: Vec<&'a str>,
            reason: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_topic<'a>(&self, conn_state: &mut ConnState, channel: &'a str,
            topic: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_names<'a>(&self, conn_state: &mut ConnState, channels: Vec<&'a str>)
            -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_list<'a>(&self, conn_state: &mut ConnState, channels: Vec<&'a str>,
            server: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_invite<'a>(&self, conn_state: &mut ConnState, nickname: &'a str,
            channel: &'a str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_kick<'a>(&self, conn_state: &mut ConnState, channel: &'a str,
            user: &'a str, comment: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_motd<'a>(&self, conn_state: &mut ConnState, target: Option<&'a str>)
            -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        
        self.feed_msg(&mut conn_state.stream, RplMotdStart375{ client,
                server: &self.config.name }).await?;
        self.feed_msg(&mut conn_state.stream, RplMotd372{ client,
                motd: &self.config.motd }).await?;
        self.feed_msg(&mut conn_state.stream, RplEndOfMotd376{ client }).await?;
        Ok(())
    }
    
    async fn process_version<'a>(&self, conn_state: &mut ConnState,
            target: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_admin<'a>(&self, conn_state: &mut ConnState,
            target: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_connect<'a>(&self, conn_state: &mut ConnState, target_server: &'a str,
            port: Option<u16>, remote_server: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_lusers(&self, conn_state: &mut ConnState)
            -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_time<'a>(&self, conn_state: &mut ConnState, server: Option<&'a str>)
            -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_stats<'a>(&self, conn_state: &mut ConnState, query: char,
            server: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_links<'a>(&self, conn_state: &mut ConnState,
            remote_server: Option<&'a str>, server_mask: Option<&'a str>)
            -> Result<(), Box<dyn Error>> {
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
    
    async fn process_mode<'a>(&self, conn_state: &mut ConnState, target: &'a str,
            modes: Vec<(&'a str, Vec<&'a str>)>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_privmsg<'a>(&self, conn_state: &mut ConnState, targets: Vec<&'a str>,
            text: &'a str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_notice<'a>(&self, conn_state: &mut ConnState, targets: Vec<&'a str>,
            text: &'a str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_who<'a>(&self, conn_state: &mut ConnState, mask: &'a str)
            -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_whois<'a>(&self, conn_state: &mut ConnState, target: Option<&'a str>,
            nickmasks: Vec<&'a str>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_whowas<'a>(&self, conn_state: &mut ConnState, nickname: &'a str,
            count: Option<usize>, server: Option<&'a str>) -> Result<(), Box<dyn Error>> {
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
    
    async fn process_away<'a>(&self, conn_state: &mut ConnState, server: Option<&'a str>)
            -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_userhost<'a>(&self, conn_state: &mut ConnState,
            nicknames: Vec<&'a str>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_wallops<'a>(&self, conn_state: &mut ConnState, text: &'a str)
            -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}
