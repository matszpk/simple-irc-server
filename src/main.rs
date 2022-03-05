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

use std::net::IpAddr;
use std::error::Error;
use clap;
use clap::Parser;
use toml;
use tokio;
use serde_derive::{Serialize, Deserialize};
use dashmap::DashMap;

#[derive(clap::Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(short, long, help="Configuration file path")]
    config: Option<String>,
    #[clap(short, long, help="Listen bind address")]
    listen: Option<String>,
    #[clap(short, long, help="Listen port")]
    port: Option<u16>,
    #[clap(short='n', long, help="Server name")]
    name: Option<String>,
    #[clap(short='N', long, help="Network")]
    network: Option<String>,
    #[clap(short, long, help="DNS lookup if client connects")]
    dns_lookup: bool,
    #[clap(short='C', long, help="TLS certificate file")]
    tls_cert_file: Option<String>,
    #[clap(short='K', long, help="TLS certificate key file")]
    tls_cert_key_file: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct TLSConfig {
    cert_file: String,
    cert_key_file: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct OperatorConfig {
    name: String,
    password: String,
    mask: Option<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct UserModes {
    invisible: bool,
    oper: bool,
    local_oper: bool,
    registered: bool,
    wallops: bool,
}

impl Default for UserModes {
    fn default() -> Self {
        UserModes{ invisible: false, oper: false, local_oper: false,
                registered: false, wallops: false }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct ChannelModes {
    ban: Option<Vec<String>>,
    exception: Option<Vec<String>>,
    client_limit: Option<usize>,
    invite_exception: Option<Vec<String>>,
    key: Option<String>,
    moderated: bool,
    secret: bool,
    protected_topic: bool,
    no_external_messages: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct ChannelConfig {
    name: String,
    topic: String,
    modes: ChannelModes,
}

#[derive(Serialize, Deserialize, Debug)]
struct UserConfig {
    name: String,
    nick: String,
    password: String,
}

/// Main configuration structure.
#[derive(Serialize, Deserialize, Debug)]
struct MainConfig {
    name: String,
    admin_info: String,
    admin_info2: Option<String>,
    info: String,
    listen: IpAddr,
    port: u16,
    network: String,
    max_connections: usize,
    max_joins: usize,
    max_nickname: usize,
    ping_timeout: usize,
    pong_timeout: usize,
    dns_lookup: bool,
    default_user_modes: UserModes,
    tls: Option<TLSConfig>,
    operators: Vec<OperatorConfig>,
    users: Vec<UserConfig>,
    channels: Vec<ChannelConfig>,
}

impl Default for MainConfig {
    fn default() -> Self {
        MainConfig{ name: "irc".to_string(),
            admin_info: "ircadmin is IRC admin".to_string(),
            admin_info2: None,
            info: "This is IRC server".to_string(),
            listen: "127.0.0.1".parse().unwrap(),
            port: 6667,
            network: "IRCnetwork".to_string(),
            max_connections: 0,
            max_joins: 0,
            max_nickname: 0,
            ping_timeout: 180,
            pong_timeout: 60,
            dns_lookup: false,
            channels: vec![],
            operators: vec![],
            users: vec![],
            default_user_modes: UserModes::default(),
            tls: None }
    }
}

struct User {
    name: String,
    nick: String,
    modes: UserModes,
    ip_addr: IpAddr,
    hostname: String,
}

enum OperatorType {
    NoOper,
    Oper,
    HalfOper,
}

struct ChannelUser<'a> {
    user: &'a User,
    founder: bool,
    protected: bool,
    voice: bool,
    oper_type: OperatorType,
}

struct Channel<'a> {
    name: String,
    topic: String,
    modes: ChannelModes,
    users: Vec<ChannelUser<'a>>,
}

struct MainState<'a> {
    users: DashMap<String, User>,
    channels: DashMap<String, Channel<'a>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    println!("Hello, world!");
    Ok(())
}
