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

use toml;
use std::net::IpAddr;
use serde_derive::{Serialize, Deserialize};

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
    modes: ChannelModes,
    topic: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct UserConfig {
    name: String, 
    password: String,
}

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

fn main() {
    println!("Hello, world!");
}
