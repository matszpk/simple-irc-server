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

use std::cell::Cell;
use std::pin::Pin;
use std::collections::HashMap;
use std::fmt;
use std::marker::Unpin;
use std::rc::{Rc,Weak};
use std::sync::Arc;
use std::net::{IpAddr};
use std::error::Error;
use tokio::sync::{Mutex,RwLock};
use tokio_stream::StreamExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{Framed, LinesCodec};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{UnboundedReceiver,UnboundedSender};
use futures::SinkExt;
use futures::sink;
use async_trait::async_trait;

use crate::config::*;
use crate::reply::*;
use crate::command::*;
use crate::utils::*;

#[async_trait]
pub(crate) trait SendReply: SinkExt<String> + Unpin + Send {
    async fn send_reply<'a>(&mut self, reply: Reply<'a>) -> sink::Send<'_, Self, String>;
}

#[async_trait]
impl<S: SinkExt<String> + Unpin + Send> SendReply for S {
    async fn send_reply<'a>(&mut self, reply: Reply<'a>) -> sink::Send<'_, Self, String> {
        self.send(reply.to_string())
    }
}

struct User {
    name: String,
    nick: Cell<String>,
    realname: String,
    modes: Cell<UserModes>,
    ip_addr: IpAddr,
    hostname: String,
    channels: HashMap<String, Weak<Channel>>,
    sender: UnboundedSender<String>,
    // user state
    operator: bool,
    away: Option<String>,
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
    mode: Cell<ChannelUserMode>,
}

struct Channel {
    name: String,
    topic: String,
    modes: ChannelModes,
    users: HashMap<String, ChannelUser>,
}

pub(crate) struct ConnState {
    stream: Framed<TcpStream, IRCLinesCodec>,
    user: Option<Arc<User>>,
    receiver: UnboundedReceiver<String>,
}

impl ConnState {
    /*async fn read_command(&mut self) -> Command {
        Command::QUIT{}
    }*/
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
    state: RwLock<VolatileState>,
}

impl MainState {
    fn new_from_config(config: MainConfig) -> MainState {
        let state = RwLock::new(VolatileState::new_from_config(&config));
        MainState{ config, state }
    }
}

impl MainState {
    pub(crate) async fn process(&mut self, conn_state: &mut ConnState)
                -> Result<(), Box<dyn Error>> {
        tokio::select! {
            Some(msg) = conn_state.receiver.recv() => {
                conn_state.stream.send(msg).await?;
                Ok(())
            },
            msg_str_res = conn_state.stream.next() => {
                
                let cmd = match msg_str_res {
                    Some(Ok(ref msg_str)) => Command::from_message(
                                &Message::from_shared_str(&msg_str)?)?,
                    Some(Err(e)) => return Err(Box::new(e)),
                    // if end of stream
                    None => return Ok(()),
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
                    PING{ } => self.process_ping(conn_state).await,
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
    
    async fn process_cap<'a>(&mut self, conn_state: &mut ConnState, subcommand: CapCommand,
            caps: Option<Vec<&'a str>>, version: Option<u32>) -> Result<(), Box<dyn Error>> {
        conn_state.stream.send_reply(Reply::RplUnAway305{ client: "aaaa" });
        Ok(())
    }
    
    async fn process_authenticate<'a>(&mut self, conn_state: &mut ConnState)
            -> Result<(), Box<dyn Error>> {
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
    
    async fn process_user<'a>(&mut self, conn_state: &mut ConnState, usernama: &'a str,
            hostname: &'a str, servername: &'a str, realname: &'a str)
            -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_ping<'a>(&mut self, conn_state: &mut ConnState)
            -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_oper<'a>(&mut self, conn_state: &mut ConnState, nick: &'a str,
            password: &'a str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_quit<'a>(&mut self, conn_state: &mut ConnState)
            -> Result<(), Box<dyn Error>> {
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
    
    async fn process_lusers<'a>(&mut self, conn_state: &mut ConnState)
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
    
    async fn process_info<'a>(&mut self, conn_state: &mut ConnState)
            -> Result<(), Box<dyn Error>> {
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
    
    async fn process_rehash<'a>(&mut self, conn_state: &mut ConnState)
            -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    async fn process_restart<'a>(&mut self, conn_state: &mut ConnState)
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
