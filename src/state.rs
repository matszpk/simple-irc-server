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
use std::rc::{Rc,Weak};
use std::sync::Arc;
use std::net::{IpAddr};
use std::error::Error;
use tokio::sync::{Mutex,RwLock};
use tokio_stream::StreamExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{Framed, LinesCodec, LinesCodecError};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{UnboundedReceiver,UnboundedSender};
use futures::SinkExt;
use chrono::prelude::*;

use crate::config::*;
use crate::reply::*;
use crate::command::*;
use crate::utils::*;

use Reply::*;

struct UserModifiable {
    name: Option<String>,
    realname: Option<String>,
    nick: Option<String>,
    source: String, // IRC source for mask matching
    modes: UserModes,
    away: Option<String>,
    // user state
    operator: bool,
    channels: HashMap<String, Weak<Channel>>,
    password: Option<String>,
    authenticated: bool,
}

impl UserModifiable {
    fn update_source(&mut self, u: &User) {
        let mut s = String::new();
        if let Some(ref nick) = self.nick {
            s.push_str(&nick);
        }
        if let Some(ref name) = self.name {
            s.push('!');
            s.push_str(&name);
        }
        s.push('@');
        s.push_str(&u.hostname);
        self.source = s;
    }
    
    fn set_name(&mut self, name: String, u: &User) {
        self.name = Some(name);
        self.update_source(u);
    }
    fn set_nick(&mut self, nick: String, u: &User) {
        self.nick = Some(nick);
        self.update_source(u);
    }
}

struct User {
    ip_addr: IpAddr,
    hostname: String,
    sender: UnboundedSender<String>,
    modifiable: RefCell<UserModifiable>,
}

impl User {
    fn client_name<'a>(&'a self, modifiable: &'a UserModifiable) -> &'a str {
        if let Some(ref n) = modifiable.nick { &n }
        else if let Some(ref n) = modifiable.name { &n }
        else { &self.hostname }
    }
    
    fn match_mask(&self, mask: &str) -> bool {
        match_wildcard(&self.modifiable.borrow().source, mask)
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

pub(crate) struct ConnState {
    stream: Framed<TcpStream, IRCLinesCodec>,
    user: Arc<User>,
    receiver: UnboundedReceiver<String>,
    caps_negotation: bool,  // if caps negotation process
    caps: CapState,
    quit: bool,
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
    
    pub(crate) async fn process(&mut self, conn_state: &mut ConnState)
                -> Result<(), Box<dyn Error>> {
        let res = self.process_internal(conn_state).await;
        conn_state.stream.flush().await?;
        res
    }

    async fn process_internal(&mut self, conn_state: &mut ConnState)
                -> Result<(), Box<dyn Error>> {
        tokio::select! {
            Some(msg) = conn_state.receiver.recv() => {
                conn_state.stream.feed(msg).await?;
                Ok(())
            },
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
                        let modifiable = conn_state.user.modifiable.borrow();
                        let client = conn_state.user.client_name(modifiable.deref());
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
    
    async fn process_cap<'a>(&mut self, conn_state: &mut ConnState, subcommand: CapCommand,
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
                Ok(()) }
        }?;
        Ok(())
    }
    
    async fn authenticate(&mut self, conn_state: &mut ConnState)
        -> Result<(), Box<dyn Error>> {
        let auth_opt = { 
            if !conn_state.caps_negotation {
                let mut modifiable = conn_state.user.modifiable.borrow_mut();
                if let Some(ref nick) = modifiable.nick {
                    if let Some(ref name) = modifiable.name {
                        let password_opt = if let Some(uidx) = self.user_config_idxs.get(name) {
                            // match user mask
                            if let Some(ref users) = self.config.users {
                                if let Some(ref mask) = users[*uidx].mask {
                                    if match_wildcard(&mask, &modifiable.source) {
                                        users[*uidx].password.as_ref()
                                    } else {
                                        self.feed_msg(&mut conn_state.stream,
                                            "ERROR: user mask doesn't match").await?;
                                        return Ok(());
                                    }
                                } else { users[*uidx].password.as_ref() }
                            } else { None }
                        } else { None }
                            .or(self.config.password.as_ref());
                        
                        if let Some(password) = password_opt {
                            let good = if let Some(ref entered_pwd) = modifiable.password {
                                *entered_pwd == *password
                            } else { false };
                            
                            modifiable.authenticated = good;
                            Some(good)
                        } else { Some(true) }
                    } else { None }
                } else { None }
            } else { None }
        };
        
        if let Some(good) = auth_opt {
            let modifiable = conn_state.user.modifiable.borrow();
            let client = conn_state.user.client_name(modifiable.deref());
            if good {
                // welcome
                self.feed_msg(&mut conn_state.stream, RplWelcome001{ client,
                    networkname: &self.config.network,
                            nick: modifiable.name.as_deref().unwrap_or_default(),
                            user: modifiable.name.as_deref().unwrap_or_default(),
                            host: &conn_state.user.hostname }).await?;
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
            } else {
                self.feed_msg(&mut conn_state.stream, ErrPasswdMismatch464{ client }).await?;
            }
        }
        Ok(())
    }
    
    async fn process_authenticate(&mut self, conn_state: &mut ConnState)
            -> Result<(), Box<dyn Error>> {
        let modifiable = conn_state.user.modifiable.borrow();
        let client = conn_state.user.client_name(modifiable.deref());
        
        self.feed_msg(&mut conn_state.stream, ErrUnknownCommand421{ client,
                command: "AUTHENTICATE" }).await?;
        Ok(())
    }
    
    async fn process_pass<'a>(&mut self, conn_state: &mut ConnState, pass: &'a str)
            -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_nick<'a>(&mut self, conn_state: &mut ConnState, nick: &'a str)
            -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_user<'a>(&mut self, conn_state: &mut ConnState, username: &'a str,
            hostname: &'a str, servername: &'a str, realname: &'a str)
            -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_ping<'a>(&mut self, conn_state: &mut ConnState, token: &'a str)
            -> Result<(), Box<dyn Error>> {
        self.feed_msg(&mut conn_state.stream, format!("PONG {} :{}", self.config.name,
                    token)).await?;
        Ok(())
    }
    
    async fn process_oper<'a>(&mut self, conn_state: &mut ConnState, nick: &'a str,
            password: &'a str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_quit(&mut self, conn_state: &mut ConnState)
            -> Result<(), Box<dyn Error>> {
        conn_state.quit = true;
        self.feed_msg(&mut conn_state.stream, "ERROR: Closing connection").await?;
        Ok(())
    }
    
    async fn process_join<'a>(&mut self, conn_state: &mut ConnState, channels: Vec<&'a str>,
            keys: Option<Vec<&'a str>>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_part<'a>(&mut self, conn_state: &mut ConnState, channels: Vec<&'a str>,
            reason: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_topic<'a>(&mut self, conn_state: &mut ConnState, channel: &'a str,
            topic: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_names<'a>(&mut self, conn_state: &mut ConnState, channels: Vec<&'a str>)
            -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_list<'a>(&mut self, conn_state: &mut ConnState, channels: Vec<&'a str>,
            server: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_invite<'a>(&mut self, conn_state: &mut ConnState, nickname: &'a str,
            channel: &'a str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_kick<'a>(&mut self, conn_state: &mut ConnState, channel: &'a str,
            user: &'a str, comment: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_motd<'a>(&mut self, conn_state: &mut ConnState, target: Option<&'a str>)
            -> Result<(), Box<dyn Error>> {
        let modifiable = conn_state.user.modifiable.borrow();
        let client = conn_state.user.client_name(modifiable.deref());
        
        self.feed_msg(&mut conn_state.stream, RplMotdStart375{ client,
                server: &self.config.name }).await?;
        self.feed_msg(&mut conn_state.stream, RplMotd372{ client,
                motd: &self.config.motd }).await?;
        self.feed_msg(&mut conn_state.stream, RplEndOfMotd376{ client }).await?;
        Ok(())
    }
    
    async fn process_version<'a>(&mut self, conn_state: &mut ConnState,
            target: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_admin<'a>(&mut self, conn_state: &mut ConnState,
            target: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_connect<'a>(&mut self, conn_state: &mut ConnState, target_server: &'a str,
            port: Option<u16>, remote_server: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_lusers(&mut self, conn_state: &mut ConnState)
            -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_time<'a>(&mut self, conn_state: &mut ConnState, server: Option<&'a str>)
            -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_stats<'a>(&mut self, conn_state: &mut ConnState, query: char,
            server: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_links<'a>(&mut self, conn_state: &mut ConnState,
            remote_server: Option<&'a str>, server_mask: Option<&'a str>)
            -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_help<'a>(&mut self, conn_state: &mut ConnState, nick: &'a str)
            -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_info(&mut self, conn_state: &mut ConnState)
            -> Result<(), Box<dyn Error>> {
        let modifiable = conn_state.user.modifiable.borrow();
        let client = conn_state.user.client_name(modifiable.deref());
        
        self.feed_msg(&mut conn_state.stream, RplInfo371{ client, info:
            concat!(env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION")) }).await?;
        self.feed_msg(&mut conn_state.stream, RplEndOfInfo374{ client }).await?;
        Ok(())
    }
    
    async fn process_mode<'a>(&mut self, conn_state: &mut ConnState, target: &'a str,
            modes: Vec<(&'a str, Vec<&'a str>)>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_privmsg<'a>(&mut self, conn_state: &mut ConnState, targets: Vec<&'a str>,
            text: &'a str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_notice<'a>(&mut self, conn_state: &mut ConnState, targets: Vec<&'a str>,
            text: &'a str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_who<'a>(&mut self, conn_state: &mut ConnState, mask: &'a str)
            -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_whois<'a>(&mut self, conn_state: &mut ConnState, target: Option<&'a str>,
            nickmasks: Vec<&'a str>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_whowas<'a>(&mut self, conn_state: &mut ConnState, nickname: &'a str,
            count: Option<usize>, server: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_kill<'a>(&mut self, conn_state: &mut ConnState, nickname: &'a str,
            comment: &'a str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_rehash(&mut self, conn_state: &mut ConnState)
            -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_restart(&mut self, conn_state: &mut ConnState)
            -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_squit<'a>(&mut self, conn_state: &mut ConnState, server: &'a str,
            comment: &'a str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_away<'a>(&mut self, conn_state: &mut ConnState, server: Option<&'a str>)
            -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_userhost<'a>(&mut self, conn_state: &mut ConnState,
            nicknames: Vec<&'a str>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_wallops<'a>(&mut self, conn_state: &mut ConnState, text: &'a str)
            -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}
