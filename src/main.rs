// main.rs - main program
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

mod config;
mod reply;
mod command;
mod utils;

use std::cell::Cell;
use std::collections::HashMap;
use std::fmt;
use std::rc::{Rc,Weak};
use std::sync::Arc;
use std::net::{IpAddr, TcpStream};
use std::error::Error;
use clap;
use clap::Parser;
use tokio;
use tokio::sync::RwLock;
use tokio_util::codec::Framed;

use config::*;
use reply::*;
use command::*;
use utils::*;

//

struct User {
    name: String,
    nick: Cell<String>,
    realname: String,
    modes: Cell<UserModes>,
    ip_addr: IpAddr,
    hostname: String,
    channels: HashMap<String, Weak<Channel>>,
    stream: Arc<Framed<TcpStream, IRCLinesCodec>>,
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
    users: HashMap<String,ChannelUser>,
}

struct ConnState {
    stream: Arc<Framed<TcpStream, IRCLinesCodec>>,
    user: Option<Arc<User>>,
}

#[derive(Copy, Clone, Debug)]
enum MainStateError {
    NoSuchUser,
}

impl fmt::Display for MainStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MainStateError::NoSuchUser => write!(f, "No such user"),
        }
    }
}

impl Error for MainStateError {
}

struct VolatileState {
    users: HashMap<String, Rc<User>>,
    channels: HashMap<String, Rc<Channel>>,
}

struct MainState {
    config: MainConfig,
    state: RwLock<VolatileState>,
}

impl MainState {
    fn process_command<'a>(&mut self, conn_state: &mut ConnState,
                    cmd: Command) {
        use crate::Command::*;
        match cmd {
            CAP{ subcommand, caps, version } =>
                self.process_cap(conn_state, subcommand, caps, version),
            AUTHENTICATE{ } =>
                self.process_authenticate(conn_state),
            PASS{ password } =>
                self.process_pass(conn_state, password),
            NICK{ nickname } =>
                self.process_nick(conn_state, nickname),
            USER{ username, hostname, servername, realname } =>
                self.process_user(conn_state, username, hostname, servername, realname),
            PING{ } => self.process_ping(conn_state),
            OPER{ name, password } =>
                self.process_oper(conn_state, name, password),
            QUIT{ } => self.process_quit(conn_state),
            JOIN{ channels, keys } =>
                self.process_join(conn_state, channels, keys),
            PART{ channels, reason } =>
                self.process_part(conn_state, channels, reason),
            TOPIC{ channel, topic } =>
                self.process_topic(conn_state, channel, topic),
            NAMES{ channels } =>
                self.process_names(conn_state, channels),
            LIST{ channels, server } =>
                self.process_list(conn_state, channels, server),
            INVITE{ nickname, channel } =>
                self.process_invite(conn_state, nickname, channel),
            KICK{ channel, user, comment } =>
                self.process_kick(conn_state, channel, user, comment),
            MOTD{ target } =>
                self.process_motd(conn_state, target),
            VERSION{ target } =>
                self.process_version(conn_state, target),
            ADMIN{ target } =>
                self.process_admin(conn_state, target),
            CONNECT{ target_server, port, remote_server } =>
                self.process_connect(conn_state, target_server, port, remote_server),
            LUSERS{ } => self.process_lusers(conn_state),
            TIME{ server } =>
                self.process_time(conn_state, server),
            STATS{ query, server } =>
                self.process_stats(conn_state, query, server),
            LINKS{ remote_server, server_mask } =>
                self.process_links(conn_state, remote_server, server_mask),
            HELP{ subject } =>
                self.process_help(conn_state, subject),
            INFO{ } => self.process_info(conn_state),
            MODE{ target, modes } =>
                self.process_mode(conn_state, target, modes),
            PRIVMSG{ targets, text } =>
                self.process_privmsg(conn_state, targets, text),
            NOTICE{ targets, text } =>
                self.process_notice(conn_state, targets, text),
            WHO{ mask } => self.process_who(conn_state, mask),
            WHOIS{ target, nickmasks } =>
                self.process_whois(conn_state, target, nickmasks),
            WHOWAS{ nickname, count, server } =>
                self.process_whowas(conn_state, nickname, count, server),
            KILL{ nickname, comment } =>
                self.process_kill(conn_state, nickname, comment),
            REHASH{ } => self.process_rehash(conn_state),
            RESTART{ } => self.process_restart(conn_state),
            SQUIT{ server, comment } =>
                self.process_squit(conn_state, server, comment),
            AWAY{ text } =>
                self.process_away(conn_state, text),
            USERHOST{ nicknames } =>
                self.process_userhost(conn_state, nicknames), 
            WALLOPS{ text } =>
                self.process_wallops(conn_state, text),
        }
    }
    
    fn process_cap<'a>(&mut self, conn_state: &mut ConnState, subcommand: CapCommand,
            caps: Option<Vec<&'a str>>, version: Option<u32>) {
    }
    
    fn process_authenticate<'a>(&mut self, conn_state: &mut ConnState) {
    }
    
    fn process_pass<'a>(&mut self, conn_state: &mut ConnState, pass: &'a str) {
    }
    
    fn process_nick<'a>(&mut self, conn_state: &mut ConnState, nick: &'a str) {
    }
    
    fn process_user<'a>(&mut self, conn_state: &mut ConnState, usernama: &'a str,
            hostname: &'a str, servername: &'a str, realname: &'a str) {
    }
    
    fn process_ping<'a>(&mut self, conn_state: &mut ConnState) {
    }
    
    fn process_oper<'a>(&mut self, conn_state: &mut ConnState, nick: &'a str,
            password: &'a str) {
    }
    
    fn process_quit<'a>(&mut self, conn_state: &mut ConnState) {
    }
    
    fn process_join<'a>(&mut self, conn_state: &mut ConnState, channels: Vec<&'a str>,
            keys: Option<Vec<&'a str>>) {
    }
    
    fn process_part<'a>(&mut self, conn_state: &mut ConnState, channels: Vec<&'a str>,
            reason: Option<&'a str>) {
    }
    
    fn process_topic<'a>(&mut self, conn_state: &mut ConnState, channel: &'a str,
            topic: Option<&'a str>) {
    }
    
    fn process_names<'a>(&mut self, conn_state: &mut ConnState, channels: Vec<&'a str>) {
    }
    
    fn process_list<'a>(&mut self, conn_state: &mut ConnState, channels: Vec<&'a str>,
            server: Option<&'a str>) {
    }
    
    fn process_invite<'a>(&mut self, conn_state: &mut ConnState, nickname: &'a str,
            channel: &'a str) {
    }
    
    fn process_kick<'a>(&mut self, conn_state: &mut ConnState, channel: &'a str,
            user: &'a str, comment: Option<&'a str>) {
    }
    
    fn process_motd<'a>(&mut self, conn_state: &mut ConnState, target: Option<&'a str>) {
    }
    
    fn process_version<'a>(&mut self, conn_state: &mut ConnState, target: Option<&'a str>) {
    }
    
    fn process_admin<'a>(&mut self, conn_state: &mut ConnState, target: Option<&'a str>) {
    }
    
    fn process_connect<'a>(&mut self, conn_state: &mut ConnState, target_server: &'a str,
            port: Option<u16>, remote_server: Option<&'a str>) {
    }
    
    fn process_lusers<'a>(&mut self, conn_state: &mut ConnState) {
    }
    
    fn process_time<'a>(&mut self, conn_state: &mut ConnState, server: Option<&'a str>) {
    }
    
    fn process_stats<'a>(&mut self, conn_state: &mut ConnState, query: char,
            server: Option<&'a str>) {
    }
    
    fn process_links<'a>(&mut self, conn_state: &mut ConnState,
            remote_server: Option<&'a str>, server_mask: Option<&'a str>) {
    }
    
    fn process_help<'a>(&mut self, conn_state: &mut ConnState, nick: &'a str) {
    }
    
    fn process_info<'a>(&mut self, conn_state: &mut ConnState) {
    }
    
    fn process_mode<'a>(&mut self, conn_state: &mut ConnState, target: &'a str,
            modes: Vec<(&'a str, Vec<&'a str>)>) {
    }
    
    fn process_privmsg<'a>(&mut self, conn_state: &mut ConnState, targets: Vec<&'a str>,
            text: &'a str) {
    }
    
    fn process_notice<'a>(&mut self, conn_state: &mut ConnState, targets: Vec<&'a str>,
            text: &'a str) {
    }
    
    fn process_who<'a>(&mut self, conn_state: &mut ConnState, mask: &'a str) {
    }
    
    fn process_whois<'a>(&mut self, conn_state: &mut ConnState, target: Option<&'a str>,
            nickmasks: Vec<&'a str>) {
    }
    
    fn process_whowas<'a>(&mut self, conn_state: &mut ConnState, nickname: &'a str,
            count: Option<usize>, server: Option<&'a str>) {
    }
    
    fn process_kill<'a>(&mut self, conn_state: &mut ConnState, nickname: &'a str,
            comment: &'a str) {
    }
    
    fn process_rehash<'a>(&mut self, conn_state: &mut ConnState) {
    }
    
    fn process_restart<'a>(&mut self, conn_state: &mut ConnState) {
    }
    
    fn process_squit<'a>(&mut self, conn_state: &mut ConnState, server: &'a str,
            comment: &'a str) {
    }
    
    fn process_away<'a>(&mut self, conn_state: &mut ConnState, server: Option<&'a str>) {
    }
    
    fn process_userhost<'a>(&mut self, conn_state: &mut ConnState,
            nicknames: Vec<&'a str>) {
    }
    
    fn process_wallops<'a>(&mut self, conn_state: &mut ConnState, text: &'a str) {
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let config = MainConfig::new(cli)?;
    println!("Hello, world!");
    Ok(())
}
