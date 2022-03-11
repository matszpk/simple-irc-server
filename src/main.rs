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

use std::fmt;
use std::rc::Rc;
use std::fs::File;
use std::io::Read;
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
    listen: Option<IpAddr>,
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

impl MainConfig {
    fn new_config(cli: Cli) -> Result<MainConfig, Box<dyn Error>> {
        let config_path = cli.config.as_deref().unwrap_or("simple-irc-server.toml");
        let mut config_file = File::open(config_path)?;
        let mut config_str = String::new();
        config_file.read_to_string(&mut config_str)?;
        // modify configuration by CLI options
        {
            let mut config: MainConfig = toml::from_str(&config_str)?;
            if let Some(addr) = cli.listen {
                config.listen = addr;
            }
            if let Some(port) = cli.port {
                config.port = port;
            }
            if let Some(name) = cli.name {
                config.name = name;
            }
            if let Some(network) = cli.network {
                config.network = network;
            }
            config.dns_lookup |= config.dns_lookup;
            
            // get indicator to check later
            let (have_cert, have_cert_key) = (cli.tls_cert_file.is_some(),
                    cli.tls_cert_key_file.is_some());
            
            if let Some(tls_cert_file) = cli.tls_cert_file {
                if let Some(tls_cert_key_file) = cli.tls_cert_key_file {
                    config.tls = Some(TLSConfig{ cert_file: tls_cert_file,
                                cert_key_file: tls_cert_key_file });
                }
            }
            // both config are required
            if !config.tls.is_some() && (have_cert ^ have_cert_key) {
                panic!("TLS certifcate file and certificate
                        key file together are required");
            }
            Ok(config)
        }
    }
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

struct Message<'a> {
    source: &'a str,
    command: &'a str,
    params: Vec<&'a str>,
}

impl<'a> Message<'a> {
    fn from_shared_str(s: &'a str) -> Result<Self, String> {
        Ok(Message{ source: &s[..], command: &s[..], params: vec![] })
    }
}

struct WhoIsChannelStruct<'a> {
    prefix: Option<&'a str>,
    channel: &'a str,
}

struct NameReplyStruct<'a> {
    prefix: Option<&'a str>,
    nick: &'a str,
}

enum Reply<'a> {
    RplWelcome001{ client: &'a str, networkname: &'a str, nick: &'a str,
            user: &'a str, host: &'a str },
    RplYourHost002{ client: &'a str, servername: &'a str, version: &'a str },
    RplCreated003{ client: &'a str, datetime: &'a str },
    RplMyInfo004{ client: &'a str, servername: &'a str, avail_user_modes: &'a str,
            avail_channel_modes: &'a str },
    RplISupport005{ client: &'a str, tokens: &'a str },
    RplBounce010{ client: &'a str, hostname: &'a str, port: u16, info: &'a str },
    RplUModeIs221{ client: &'a str, user_modes: &'a str },
    RplLUserClient251{ client: &'a str, users_num: usize, inv_users_num: usize,
            servers_num: usize },
    RplLUserOp252{ client: &'a str, ops_num: usize },
    RplLUserUnknown253{ client: &'a str, conns: &'a str },
    RplLUserChannels254{ client: &'a str, channels: &'a str },
    RplLUserMe255{ client: &'a str, clients_num: usize, servers_num: usize },
    RplAdminMe256{ client: &'a str, server: &'a str },
    RplAdminLoc1257{ client: &'a str, info: &'a str },
    RplAdminLoc2258{ client: &'a str, info: &'a str },
    RplAdminEmail259{ client: &'a str, email: &'a str },
    RplTryAgain263{ client: &'a str, command: &'a str },
    RplLocalUsers265{ client: &'a str, clients_num: usize, max_clients_num: usize },
    RplGlobalUsers265{ client: &'a str, clients_num: usize, max_clients_num: usize },
    RplWhoIsCertFP276{ client: &'a str, nick: &'a str },
    RplNone300{ },
    RplAway301{ client: &'a str, nick: &'a str, message: &'a str },
    RplUserHost302{ client: &'a str, replies: Option<&'a [&'a str]> },
    RplUnAway305{ client: &'a str },
    RplNoAway306{ client: &'a str },
    RplWhoReply352{ client: &'a str, channel: &'a str, username: &'a str, host: &'a str,
            server: &'a str, nick: &'a str, flags: &'a str,
            hopcount: usize, realname: &'a str },
    RplEndOfWho315{ client: &'a str, mask: &'a str },
    RplWhoIsRegNick307{ client: &'a str, nick: &'a str },
    RplWhoIsUser311{ client: &'a str, nick: &'a str, host: &'a str, realname: &'a str },
    RplWhoIsServer312{ client: &'a str, nick: &'a str, server: &'a str,
            server_info: &'a str },
    RplWhoIsOperator313{ client: &'a str, nick: &'a str },
    RplWhoWasUser314{ client: &'a str, nick: &'a str, username: &'a str, host: &'a str,
            realname: &'a str },
    RplwhoIsIdle317{ client: &'a str, nick: &'a str, secs: u64, signon: u64 },
    RplEndOfWhoIs318{ client: &'a str, nick: &'a str },
    RplWhoIsChannels319{ client: &'a str, nick: &'a str,
            channels: &'a [WhoIsChannelStruct<'a>] }, 
    RplWhoIsSpecial320{ client: &'a str, nick: &'a str, special_info: &'a str },
    RplListStart321{ client: &'a str },
    RplList322{ client: &'a str, channel: &'a str, client_count: usize, topic: &'a str },
    RplListEnd323{ client: &'a str },
    RplChannelModeIs324{ client: &'a str, channel: &'a str, modestring: &'a str,
            mode_args: &'a [&'a str] },
    RplCreationTime329{ client: &'a str, channel: &'a str, creation_time: &'a str },
    RplWhoIsAccount330{ client: &'a str, nick: &'a str, account: &'a str },
    RplNoTopic331{ client: &'a str, nick: &'a str },
    RplTopic332{ client: &'a str, nick: &'a str, topic: &'a str },
    RplTopicWhoTime333{ client: &'a str, nick: &'a str, setat: u64 },
    RplWhoIsActually338P1{ client: &'a str, nick: &'a str },
    RplWhoIsActually338P2{ client: &'a str, nick: &'a str, host_ip: &'a str },
    RplWhoIsActually338P3{ client: &'a str, nick: &'a str,
            username: &'a str, hostname: &'a str },
    RplInviting341{ client: &'a str, nick: &'a str, channel: &'a str },
    RplInviteList346{ client: &'a str, channel: &'a str, mask: &'a str },
    RplEndOfInviteList347{ client: &'a str, channel: &'a str },
    RplExceptList348{ client: &'a str, channel: &'a str, mask: &'a str },
    RplEndOfExceptList349{ client: &'a str, channel: &'a str },
    RplVersion351{ client: &'a str, version: &'a str, server: &'a str,
            comments: &'a str },
    RplNameReply353{ client: &'a str, symbol: &'a str, channel: &'a str,
            replies: &'a[NameReplyStruct<'a>] },
    RplEndOfNames366{ client: &'a str, channel: &'a str },
    RplBanList367{ client: &'a str, channel: &'a str, mask: &'a str,
            who: &'a str, set_ts: u64 },
    RplEndOfBanList368{ client: &'a str, channel: &'a str },
    RplEndOfWhoWas369{ client: &'a str, nick: &'a str },
    RplInfo371{ client: &'a str, info: &'a str },
    RplEndOfInfo374{ client: &'a str },
    RplMotdStart375{ client: &'a str, server: &'a str },
    RplMotd372{ client: &'a str, motd: &'a str },
    RplEndOfMotd376{ client: &'a str },
    RplWhoIsHost378{ client: &'a str, nick: &'a str, host_info: &'a str },
    RplWhoIsModes379{ client: &'a str, nick: &'a str, modes: &'a str },
    RplYouReoper381{ client: &'a str },
    RplRehashing382{ client: &'a str, config_file: &'a str },
    RplTime391{ client: &'a str, server: &'a str, timestamp: u64, ts_offset: &'a str,
            human_readable: &'a str },
    ErrUnknownError400{ client: &'a str, command: &'a str, subcommand: Option<&'a str>,
            info: &'a str },
    ErrNoSuchNick401{ client: &'a str, nick: &'a str },
    ErrNoSuchServer402{ client: &'a str, server: &'a str },
    ErrNoSuchChannel403{ client: &'a str, channel: &'a str },
    ErrCannotSendToChain404{ client: &'a str, channel: &'a str },
    ErrTooManyChannels405{ client: &'a str, channel: &'a str },
    ErrNoOrigin409{ client: &'a str },
    ErrInputTooLong417{ client: &'a str },
    ErrNoMotd422{ client: &'a str },
    ErrErroneusNickname432{ client: &'a str, nick: &'a str },
    ErrNicknameInUse433{ client: &'a str, nick: &'a str },
    ErrUserNotInChannel441{ client: &'a str, nick: &'a str, channel: &'a str },
    ErrNotOnChannel442{ client: &'a str, channel: &'a str },
    ErrUserOnChannel443{ client: &'a str, nick: &'a str, channel: &'a str },
    ErrNotRegistered451{ client: &'a str },
    ErrNeedMoreParams461{ client: &'a str, command: &'a str },
    ErrAlreadyRegistered462{ client: &'a str },
    ErrPasswdMismatch464{ client: &'a str },
    ErrYoureBannedCreep465{ client: &'a str },
    ErrChannelIsFull471{ client: &'a str, channel: &'a str },
    ErrUnknownMode472{ client: &'a str, modechar: char },
    ErrBannedFromChan474{ client: &'a str, channel: &'a str },
    ErrBadChannelKey475{ client: &'a str, channel: &'a str },
    ErrBadChanMask476{ channel: &'a str },
    ErrNoPrivileges481{ client: &'a str },
    ErrChanOpPrivsNeeded482{ client: &'a str, channel: &'a str },
    ErrCantKillServer483{ client: &'a str },
    ErrNoOperhost482{ client: &'a str },
    ErrUmodeUnknownFlag501{ client: &'a str },
    ErrUsersDontMatch502{ client: &'a str },
    ErrHelpNotFound524{ client: &'a str, subject: &'a str },
    ErrInvalidKey525{ client: &'a str, target_chan: &'a str },
    RplStartTls670{ client: &'a str },
    RplWhoIsSecure671{ client: &'a str, nick: &'a str },
    ErrStartTls691{ client: &'a str },
    ErrInvalidModeParam696{ client: &'a str, target: &'a str },
    RplHelpStart704{ client: &'a str, subject: &'a str, line: &'a str },
    RplHelpTxt705{ client: &'a str, subject: &'a str, line: &'a str },
    RplEndOfHelp706{ client: &'a str, subject: &'a str, line: &'a str },
    ErrNoPrivs723{ client: &'a str, privil: &'a str },
    RplLoggedIn900{ client: &'a str, nick: &'a str, user: &'a str, host: &'a str,
            account: &'a str, username: &'a str },
    RplLoggedOut901{ client: &'a str, nick: &'a str, host: &'a str },
    ErrNickLocked902{ client: &'a str },
    RplSaslSuccess903{ client: &'a str },
    ErrSaslFail904{ client: &'a str },
    ErrSaslTooLong905{ client: &'a str },
    ErrSaslAborted906{ client: &'a str },
    ErrSaslAlready907{ client: &'a str },
    RplSaslMechs908{ client: &'a str, mechasnisms: &'a str },
}

use Reply::*;

impl<'a> fmt::Display for Reply<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RplWelcome001{ client, networkname, nick, user, host } => {
                write!(f, "{} :Welcome to the {} Network, {}!{}@{}",
                    client, networkname, nick, user, host) }
            RplYourHost002{ client, servername, version } => {
                write!(f, "{} :Your host is {}, running version {}",
                    client, servername, version) }
            RplCreated003{ client, datetime } => {
                write!(f, "{} :This server was created {}", client, datetime) }
            RplMyInfo004{ client, servername, avail_user_modes,
                    avail_channel_modes } => { Ok(()) }
            RplISupport005{ client, tokens } => { Ok(()) }
            RplBounce010{ client, hostname, port, info } => { Ok(()) }
            RplUModeIs221{ client, user_modes } => { Ok(()) }
            RplLUserClient251{ client, users_num, inv_users_num, servers_num } => { Ok(()) }
            RplLUserOp252{ client, ops_num } => { Ok(()) }
            RplLUserUnknown253{ client, conns } => { Ok(()) }
            RplLUserChannels254{ client, channels } => { Ok(()) }
            RplLUserMe255{ client, clients_num, servers_num } => { Ok(()) }
            RplAdminMe256{ client, server } => { Ok(()) }
            RplAdminLoc1257{ client, info } => { Ok(()) }
            RplAdminLoc2258{ client, info } => { Ok(()) }
            RplAdminEmail259{ client, email } => { Ok(()) }
            RplTryAgain263{ client, command } => { Ok(()) }
            RplLocalUsers265{ client, clients_num, max_clients_num } => { Ok(()) }
            RplGlobalUsers265{ client, clients_num, max_clients_num } => { Ok(()) }
            RplWhoIsCertFP276{ client, nick } => { Ok(()) }
            RplNone300{ } => { Ok(()) }
            RplAway301{ client, nick, message } => { Ok(()) }
            RplUserHost302{ client, replies } => { Ok(()) }
            RplUnAway305{ client } => { Ok(()) }
            RplNoAway306{ client } => { Ok(()) }
            RplWhoReply352{ client, channel, username, host, server, nick, flags,
                    hopcount, realname } => { Ok(()) }
            RplEndOfWho315{ client, mask } => { Ok(()) }
            RplWhoIsRegNick307{ client, nick } => { Ok(()) }
            RplWhoIsUser311{ client, nick, host, realname } => { Ok(()) }
            RplWhoIsServer312{ client, nick, server, server_info } => { Ok(()) }
            RplWhoIsOperator313{ client, nick } => { Ok(()) }
            RplWhoWasUser314{ client, nick, username, host, realname } => { Ok(()) }
            RplwhoIsIdle317{ client, nick, secs, signon } => { Ok(()) }
            RplEndOfWhoIs318{ client, nick } => { Ok(()) }
            RplWhoIsChannels319{ client, nick, channels } => { Ok(()) }
            RplWhoIsSpecial320{ client, nick, special_info } => { Ok(()) }
            RplListStart321{ client } => { Ok(()) }
            RplList322{ client, channel, client_count, topic } => { Ok(()) }
            RplListEnd323{ client } => { Ok(()) }
            RplChannelModeIs324{ client, channel, modestring, mode_args } => { Ok(()) }
            RplCreationTime329{ client, channel, creation_time } => { Ok(()) }
            RplWhoIsAccount330{ client, nick, account } => { Ok(()) }
            RplNoTopic331{ client, nick } => { Ok(()) }
            RplTopic332{ client, nick, topic } => { Ok(()) }
            RplTopicWhoTime333{ client, nick, setat } => { Ok(()) }
            RplWhoIsActually338P1{ client, nick } => { Ok(()) }
            RplWhoIsActually338P2{ client, nick, host_ip } => { Ok(()) }
            RplWhoIsActually338P3{ client, nick, username, hostname } => { Ok(()) }
            RplInviting341{ client, nick, channel } => { Ok(()) }
            RplInviteList346{ client, channel, mask } => { Ok(()) }
            RplEndOfInviteList347{ client, channel } => { Ok(()) }
            RplExceptList348{ client, channel, mask } => { Ok(()) }
            RplEndOfExceptList349{ client, channel } => { Ok(()) }
            RplVersion351{ client, version, server, comments } => { Ok(()) }
            RplNameReply353{ client, symbol, channel, replies } => { Ok(()) }
            RplEndOfNames366{ client, channel } => { Ok(()) }
            RplBanList367{ client, channel, mask, who, set_ts } => { Ok(()) }
            RplEndOfBanList368{ client, channel } => { Ok(()) }
            RplEndOfWhoWas369{ client, nick } => { Ok(()) }
            RplInfo371{ client, info } => { Ok(()) }
            RplEndOfInfo374{ client } => { Ok(()) }
            RplMotdStart375{ client, server } => { Ok(()) }
            RplMotd372{ client, motd } => { Ok(()) }
            RplEndOfMotd376{ client } => { Ok(()) }
            RplWhoIsHost378{ client, nick, host_info } => { Ok(()) }
            RplWhoIsModes379{ client, nick, modes } => { Ok(()) }
            RplYouReoper381{ client } => { Ok(()) }
            RplRehashing382{ client, config_file } => { Ok(()) }
            RplTime391{ client, server, timestamp, ts_offset, human_readable } => { Ok(()) }
            ErrUnknownError400{ client, command, subcommand, info } => { Ok(()) }
            ErrNoSuchNick401{ client, nick } => { Ok(()) }
            ErrNoSuchServer402{ client, server } => { Ok(()) }
            ErrNoSuchChannel403{ client, channel } => { Ok(()) }
            ErrCannotSendToChain404{ client, channel } => { Ok(()) }
            ErrTooManyChannels405{ client, channel } => { Ok(()) }
            ErrNoOrigin409{ client } => { Ok(()) }
            ErrInputTooLong417{ client } => { Ok(()) }
            ErrNoMotd422{ client } => { Ok(()) }
            ErrErroneusNickname432{ client, nick } => { Ok(()) }
            ErrNicknameInUse433{ client, nick } => { Ok(()) }
            ErrUserNotInChannel441{ client, nick, channel } => { Ok(()) }
            ErrNotOnChannel442{ client, channel } => { Ok(()) }
            ErrUserOnChannel443{ client, nick, channel } => { Ok(()) }
            ErrNotRegistered451{ client } => { Ok(()) }
            ErrNeedMoreParams461{ client, command } => { Ok(()) }
            ErrAlreadyRegistered462{ client } => { Ok(()) }
            ErrPasswdMismatch464{ client } => { Ok(()) }
            ErrYoureBannedCreep465{ client } => { Ok(()) }
            ErrChannelIsFull471{ client, channel } => { Ok(()) }
            ErrUnknownMode472{ client, modechar } => { Ok(()) }
            ErrBannedFromChan474{ client, channel } => { Ok(()) }
            ErrBadChannelKey475{ client, channel } => { Ok(()) }
            ErrBadChanMask476{ channel } => { Ok(()) }
            ErrNoPrivileges481{ client } => { Ok(()) }
            ErrChanOpPrivsNeeded482{ client, channel } => { Ok(()) }
            ErrCantKillServer483{ client } => { Ok(()) }
            ErrNoOperhost482{ client } => { Ok(()) }
            ErrUmodeUnknownFlag501{ client } => { Ok(()) }
            ErrUsersDontMatch502{ client } => { Ok(()) }
            ErrHelpNotFound524{ client, subject } => { Ok(()) }
            ErrInvalidKey525{ client, target_chan } => { Ok(()) }
            RplStartTls670{ client } => { Ok(()) }
            RplWhoIsSecure671{ client, nick } => { Ok(()) }
            ErrStartTls691{ client } => { Ok(()) }
            ErrInvalidModeParam696{ client, target } => { Ok(()) }
            RplHelpStart704{ client, subject, line } => { Ok(()) }
            RplHelpTxt705{ client, subject, line } => { Ok(()) }
            RplEndOfHelp706{ client, subject, line } => { Ok(()) }
            ErrNoPrivs723{ client, privil } => { Ok(()) }
            RplLoggedIn900{ client, nick, user, host, account, username } => { Ok(()) }
            RplLoggedOut901{ client, nick, host } => { Ok(()) }
            ErrNickLocked902{ client } => { Ok(()) }
            RplSaslSuccess903{ client } => { Ok(()) }
            ErrSaslFail904{ client } => { Ok(()) }
            ErrSaslTooLong905{ client } => { Ok(()) }
            ErrSaslAborted906{ client } => { Ok(()) }
            ErrSaslAlready907{ client } => { Ok(()) }
            RplSaslMechs908{ client, mechasnisms } => { Ok(()) }
        }
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

struct ChannelUser {
    user: Rc<User>,
    founder: bool,
    protected: bool,
    voice: bool,
    oper_type: OperatorType,
}

struct Channel {
    name: String,
    topic: String,
    modes: ChannelModes,
    users: Vec<ChannelUser>,
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

struct MainState {
    config: MainConfig,
    users: DashMap<String, User>,
    channels: DashMap<String, Channel>,
}

impl MainState {
    pub fn check_password(username: &str, password: &str) -> Result<bool, MainStateError> {
        Ok(false)
    }
    
    pub fn set_nickname(username: &str, nickname: &str) -> Result<(), MainStateError> {
        Ok(())
    }
    
    pub fn begin_user(username: &str, realname: &str) -> Result<(), MainStateError> {
        Ok(())
    }
    
    pub fn set_oper(username: &str, password: &str) -> Result<bool, MainStateError> {
        Ok(false)
    }
    
    pub fn join_to_channel(username: &str, channels: Vec<(&str, &str)>) ->
                Result<bool, MainStateError> {
        Ok(false)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let config = MainConfig::new_config(cli)?;
    println!("Hello, world!");
    Ok(())
}
