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
use std::net::{IpAddr, TcpStream};
use std::error::Error;
use clap;
use bytes::{BufMut, BytesMut};
use clap::Parser;
use toml;
use tokio;
use tokio_util::codec::{Framed, LinesCodec, Decoder, Encoder};
use serde_derive::{Serialize, Deserialize};
use dashmap::DashMap;
use validator::{Validate,ValidationError};
use const_table::const_table;

#[derive(clap::Parser, Clone)]
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

fn validate_username(username: &str) -> Result<(), ValidationError> {
    if !username.contains('.') && !username.contains(':') && !username.contains(',') {
        Ok(())
    } else {
        Err(ValidationError::new("Username must not contains '.', ',' or ':'."))
    }
}

fn validate_channel(channel: &str) -> Result<(), ValidationError> {
    if channel.len() != 0 && !channel.contains(':') && !channel.contains(',') &&
        (channel.as_bytes()[0] == b'#' || channel.as_bytes()[0] == b'&') {
        Ok(())
    } else {
        Err(ValidationError::new("Channel name must have '#' or '&' at start and \
                must not contains ',' or ':'."))
    }
}

#[derive(PartialEq, Eq, Serialize, Deserialize, Debug)]
struct TLSConfig {
    cert_file: String,
    cert_key_file: String,
}

#[derive(PartialEq, Eq, Serialize, Deserialize, Debug, Validate)]
struct OperatorConfig {
    #[validate(custom = "validate_username")]
    name: String,
    #[validate(length(min = 6))]
    password: String,
    mask: Option<String>,
}

#[derive(PartialEq, Eq, Serialize, Deserialize, Debug)]
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

#[derive(PartialEq, Eq, Serialize, Deserialize, Debug, Validate)]
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

#[derive(PartialEq, Eq, Serialize, Deserialize, Debug, Validate)]
struct ChannelConfig {
    #[validate(custom = "validate_channel")]
    name: String,
    topic: String,
    #[validate]
    modes: ChannelModes,
}

#[derive(PartialEq, Eq, Serialize, Deserialize, Debug, Validate)]
struct UserConfig {
    #[validate(custom = "validate_username")]
    name: String,
    #[validate(custom = "validate_username")]
    nick: String,
    #[validate(length(min = 6))]
    password: String,
}

/// Main configuration structure.
#[derive(PartialEq, Eq, Serialize, Deserialize, Debug, Validate)]
struct MainConfig {
    #[validate(contains = ".")]
    name: String,
    admin_info: String,
    admin_info2: Option<String>,
    info: String,
    listen: IpAddr,
    port: u16,
    network: String,
    max_connections: Option<usize>,
    max_joins: Option<usize>,
    max_nickname_len: usize,
    ping_timeout: usize,
    pong_timeout: usize,
    dns_lookup: bool,
    default_user_modes: UserModes,
    tls: Option<TLSConfig>,
    #[validate]
    operators: Option<Vec<OperatorConfig>>,
    #[validate]
    users: Option<Vec<UserConfig>>,
    #[validate]
    channels: Option<Vec<ChannelConfig>>,
}

impl MainConfig {
    fn new(cli: Cli) -> Result<MainConfig, Box<dyn Error>> {
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
            config.dns_lookup = config.dns_lookup || cli.dns_lookup;
            
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
            if (have_cert && !have_cert_key) || (!have_cert && have_cert_key) {
                return Err(Box::new(clap::error::Error::raw(
                        clap::ErrorKind::ValueValidation,
                        "TLS certifcate file and certificate \
                        key file together are required")));
            }
            if let Err(e) = config.validate() {
                Err(Box::new(e))
            } else { Ok(config) }
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
            max_connections: None,
            max_joins: None,
            max_nickname_len: 20,
            ping_timeout: 120,
            pong_timeout: 20,
            dns_lookup: false,
            channels: None,
            operators: None,
            users: None,
            default_user_modes: UserModes::default(),
            tls: None }
    }
}

// special LinesCodec for IRC - encode with "\r\n".

struct IRCLinesCodec(LinesCodec);

impl IRCLinesCodec {
    pub fn new() -> IRCLinesCodec {
        IRCLinesCodec(LinesCodec::new())
    }
}

impl<T: AsRef<str>> Encoder<T> for IRCLinesCodec {
    type Error = <LinesCodec as Encoder<T>>::Error;

    fn encode(&mut self, line: T, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let line = line.as_ref();
        buf.reserve(line.len() + 1);
        buf.put(line.as_bytes());
        // put "\r\n"
        buf.put_u8(b'\r');
        buf.put_u8(b'\n');
        Ok(())
    }
}

impl Decoder for IRCLinesCodec {
    type Item = <LinesCodec as Decoder>::Item;
    type Error = <LinesCodec as Decoder>::Error;
    
    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<String>, Self::Error> {
        self.0.decode(buf)
    }
}

//

#[derive(Clone, Copy, Debug)]
enum MessageError {
    Empty,
    WrongSource,
    NoCommand,
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageError::Empty => write!(f, "Message is empty"),
            MessageError::WrongSource => write!(f, "Wrong source syntax"),
            MessageError::NoCommand => write!(f, "No command"),
        }
    }
}

impl Error for MessageError {
}

#[derive(PartialEq, Eq, Debug)]
struct Message<'a> {
    source: Option<&'a str>,
    command: &'a str,
    params: Vec<&'a str>,
}

fn validate_source(s: &str) -> bool {
    if s.contains(':') {
        false
    } else {
        let excl = s.find('!');
        let atchar = s.find('@');
        if let Some(excl_pos) = excl {
            if let Some(atchar_pos) = atchar {
                return excl_pos < atchar_pos;
            }
        }
        true
    }
}

impl<'a> Message<'a> {
    fn from_shared_str(input: &'a str) -> Result<Self, MessageError> {
        let trimmed = input.trim_start();
        
        if trimmed.len() != 0 {
            // start_pos after ':' if exists - to skip ':' before source
            let start_pos = if trimmed.bytes().next() == Some(b':') { 1 } else { 0 };
            let (rest, last_param) =
            if let Some((rest, lp)) = trimmed[start_pos..].split_once(':') {
                // get rest. add first character length to rest length.
                (&trimmed[0..rest.len() + start_pos], Some(lp))
            } else {
                (trimmed, None)
            };
            
            let mut rest_words = rest.split_ascii_whitespace();
            // find source
            let source = if rest.bytes().next() == Some(b':') {
                let s = &rest_words.next().unwrap()[1..];
                if !validate_source(s) {
                    return Err(MessageError::WrongSource);
                }
                Some(s)
            } else { None };
            let command = if let Some(cmd) = rest_words.next() { cmd }
            else { return Err(MessageError::NoCommand); };
            
            let mut params = rest_words.collect::<Vec<_>>();
            if let Some(lp) = last_param {
                params.push(lp);    // add last parameter
            }
            
            Ok(Message{ source, command, params })
        } else {
            Err(MessageError::Empty)
        }
    }
}

#[const_table]
pub enum CommandId {
    CommandName{ name: &'static str },
    CAPId = CommandName{ name: "CAP" },
    AUTHENTICATEId = CommandName{ name: "AUTHENTICATE" },
    PASSId = CommandName{ name: "PASS" },
    NICKId = CommandName{ name: "NICK" },
    USERId = CommandName{ name: "USER" },
    PINGId = CommandName{ name: "PING" },
    OPERId = CommandName{ name: "OPER" },
    QUITId = CommandName{ name: "QUIT" },
    JOINId = CommandName{ name: "JOIN" },
    PARTId = CommandName{ name: "PART" },
    TOPICId = CommandName{ name: "TOPIC" },
    NAMESId = CommandName{ name: "NAMES" },
    LISTId = CommandName{ name: "LIST" },
    INVITEId = CommandName{ name: "INVITE" },
    KICKId = CommandName{ name: "KICK" },
    MOTDId = CommandName{ name: "MOTD" },
    VERSIONId = CommandName{ name: "VERSION" },
    ADMINId = CommandName{ name: "ADMIN" },
    CONNECTId = CommandName{ name: "CONNECT" },
    LUSERSId = CommandName{ name: "LUSERS" },
    TIMEId = CommandName{ name: "TIME" },
    STATSId = CommandName{ name: "STATS" },
    HELPId = CommandName{ name: "HELP" },
    INFOId = CommandName{ name: "INFO" },
    MODEId = CommandName{ name: "MODE" },
    PRIVMSGId = CommandName{ name: "PRIVMSG" },
    NOTICEId = CommandName{ name: "NOTICE" },
    WHOId = CommandName{ name: "WHO" },
    WHOISId = CommandName{ name: "WHOIS" },
    KILLId = CommandName{ name: "KILL" },
    REHASHId = CommandName{ name: "REHASH" },
    RESTARTId = CommandName{ name: "RESTART" },
    SQUITId = CommandName{ name: "SQUIT" },
    AWAYId = CommandName{ name: "AWAY" },
    USERHOSTId = CommandName{ name: "USERHOST" }, 
    WALLOPSId = CommandName{ name: "WALLOPS" },
}

use CommandId::*;

#[derive(Clone, Debug)]
enum CommandError {
    UnknownCommand(String),
    UnknownSubcommand(CommandId, String),
    NeedMoreParams(CommandId),
    ParameterDoesntMatch(CommandId, usize),
    WrongParameter(CommandId, usize),
}

use CommandError::*;

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnknownCommand(s) =>
                write!(f, "Unknown command '{}'", s),
            UnknownSubcommand(cmd, scmd) =>
                write!(f, "Unknown subcommand '{}' in command '{}'", scmd, cmd.name),
            NeedMoreParams(s) =>
                write!(f, "Command '{}' needs more parameters", s.name),
            ParameterDoesntMatch(s, i) =>
                write!(f, "Parameter {} doesn't match for command '{}'", i, s.name),
            WrongParameter(s, i) =>
                write!(f, "Wrong parameter {} in command '{}'", i, s.name),
        }
    }
}

impl Error for CommandError {
}

#[derive(PartialEq, Eq, Debug)]
enum CapCommand {
    LS, LIST, REQ,
}

#[derive(PartialEq, Eq, Debug)]
enum Command<'a> {
    CAP{ subcommand: CapCommand, caps: Option<Vec<&'a str>>, version: Option<u32> },
    AUTHENTICATE{ },
    PASS{ password: &'a str },
    NICK{ nickname: &'a str },
    USER{ username: &'a str, hostname: &'a str, servername: &'a str, realname: &'a str },
    PING{ },
    OPER{ name: &'a str, password: &'a str },
    QUIT{ },
    JOIN{ channels: Vec<&'a str>, keys: Option<Vec<&'a str>> },
    PART{ channels: Vec<&'a str>, reason: Option<&'a str> },
    TOPIC{ channel: &'a str, topic: Option<&'a str> },
    NAMES{ channels: Vec<&'a str> },
    LIST{ channels: Vec<&'a str>, server: Option<&'a str> },
    INVITE{ nickname: &'a str, channel: &'a str },
    KICK{ channel: &'a str, user: &'a str, comment: Option<&'a str> },
    MOTD{ target: Option<&'a str> },
    VERSION{ target: Option<&'a str> },
    ADMIN{ target: Option<&'a str> },
    CONNECT{ target_server: &'a str, port: Option<u16>, remote_server: Option<&'a str> },
    LUSERS{ },
    TIME{ server: Option<&'a str> },
    STATS{ query: char, server: Option<&'a str> },
    HELP{ subject: &'a str },
    INFO{ },
    MODE{ target: &'a str, modestring: Option<&'a str>, mode_args: Option<Vec<&'a str>> },
    PRIVMSG{ targets: Vec<&'a str>, text: &'a str },
    NOTICE{ targets: Vec<&'a str>, text: &'a str },
    WHO{ mask: &'a str },
    WHOIS{ target: Option<&'a str>, nickmask: &'a str },
    KILL{ nickname: &'a str, comment: &'a str },
    REHASH{ },
    RESTART{ },
    SQUIT{ server: &'a str, comment: &'a str },
    AWAY{ text: Option<&'a str> },
    USERHOST{ nicknames: Vec<&'a str> }, 
    WALLOPS{ text: &'a str },
}

use Command::*;

fn validate_server<E: Error>(s: &str, e: E) -> Result<(), E> {
    if s.contains('.') { Ok(()) }
    else { Err(e) }
}

fn validate_server_mask<E: Error>(s: &str, e: E) -> Result<(), E>  {
    if s.contains('.') | s.contains('*') { Ok(()) }
    else { Err(e) }
}

fn validate_usermodes<'a, E: Error>(modestring: &Option<&'a str>,
                    mode_args: &Option<Vec<&'a str>>, e: E) -> Result<(), E> {
    if let Some(modestring) = modestring {
        if let Some(args) = mode_args {
            if args.len() != 0 { return Err(e); }
        }
        if modestring.len() != 0 {
            if modestring.find(|c|
                c!='+' && c!='-' && c!='i' && c!='o' &&
                    c!='O' && c!='t' && c!='w').is_some() {
                Err(e)
            } else { Ok(()) }
        } else { // if empty
            Err(e)
        }
    } else {
        Ok(())
    }
}

fn validate_channelmodes<'a, E: Error>(modestring: &Option<&'a str>,
                    mode_args: &Option<Vec<&'a str>>, e: E) -> Result<(), E> {
    if let Some(modestring) = modestring {
        if modestring.len() != 0 {
            if modestring.find(|c|
                c!='+' && c!='-' && c!='b' && c!='e' && c!='l' && c!='i' && c!='I' &&
                    c!='k' && c!='m' && c!='t' && c!='n').is_some() {
                return Err(e);
            }
            // check list
            let mut many_param_type_lists = 0;
            let mut req_args = 0;
            modestring.chars().for_each(|c| {
                match c {
                    'b' => many_param_type_lists += 1,
                    'e' => many_param_type_lists += 1,
                    'I' => many_param_type_lists += 1,
                    'k' => req_args += 1,
                    'l' => req_args += 1,
                    _ => (),
                };
            });
            if many_param_type_lists > 1 {
                return Err(e);
            }
            if let Some(args) = mode_args {
                if args.len() < req_args {
                    return Err(e);
                }
            } else if req_args != 0 {
                return Err(e);
            }
            Ok(())
        } else { // if empty
            Err(e)
        }
    } else {
        Ok(())
    }
}

impl<'a> Command<'a> {
    fn parse_from_message(message: &Message<'a>) -> Result<Self, CommandError> {
        match message.command {
            "CAP" => {
                if message.params.len() >= 1 {
                    let mut param_it = message.params.iter();
                    let subcommand = match *param_it.next().unwrap() {
                        "LS" => CapCommand::LS,
                        "LIST" => CapCommand::LIST,
                        "REQ" => CapCommand::REQ,
                        _ => return Err(UnknownSubcommand(
                                    CAPId, message.params[0].to_string()))
                    };
                    
                    let (caps, version) = if subcommand == CapCommand::REQ {
                        (param_it.next().map(|x| x.split_ascii_whitespace().
                                    collect::<Vec<_>>()),
                        None)
                    } else if subcommand == CapCommand::LS {
                        let v = if let Some(s) = param_it.next() {
                            if let Ok(value) = s.parse() { Some(value) }
                            else { return Err(WrongParameter(CAPId, 1)); }
                        } else { None };
                        (None, v)
                    } else { (None, None) };
                    
                    Ok(CAP{ subcommand, caps, version })
                } else {
                    Err(NeedMoreParams(CAPId)) }
            },
            "AUTHENTICATE" => Ok(AUTHENTICATE{}),
            "PASS" => {
                if message.params.len() >= 1 {
                    Ok(PASS{ password: message.params[0] })
                } else {
                    Err(NeedMoreParams(PASSId)) }
            }
            "NICK" => {
                if message.params.len() >= 1 {
                    Ok(NICK{ nickname: message.params[0] })
                } else {
                    Err(NeedMoreParams(NICKId)) }
            }
            "USER" => {
                if message.params.len() >= 4 {
                    Ok(USER{ username: message.params[0],
                        hostname: message.params[1],
                        servername: message.params[2],
                        realname: message.params[3] })
                } else {
                    Err(NeedMoreParams(USERId)) }
            }
            "PING" => Ok(PING{}),
            "OPER" => {
                if message.params.len() >= 2 {
                    Ok(OPER{ name: message.params[0],
                        password: message.params[1] })
                } else {
                    Err(NeedMoreParams(OPERId)) }
            }
            "QUIT" => Ok(QUIT{}),
            "JOIN" => {
                if message.params.len() >= 1 {
                    let mut param_it = message.params.iter();
                    let channels = param_it.next().unwrap().split(',').collect::<Vec<_>>();
                    let keys_opt = param_it.next().map(|x|
                        x.split(',').collect::<Vec<_>>());
                    if let Some(ref keys) = keys_opt {
                        if keys.len() != channels.len() {
                            return Err(ParameterDoesntMatch(
                                    JOINId, 1)); }
                    }
                    Ok(JOIN{ channels, keys: keys_opt })
                } else {
                    Err(NeedMoreParams(JOINId)) }
            }
            "PART" => {
                if message.params.len() >= 1 {
                    let mut param_it = message.params.iter();
                    let channels = param_it.next().unwrap().split(',').collect::<Vec<_>>();
                    let reason = param_it.next().map(|x| *x);
                    Ok(PART{ channels, reason })
                } else {
                    Err(NeedMoreParams(PARTId)) }
            }
            "TOPIC" => {
                if message.params.len() >= 1 {
                    let mut param_it = message.params.iter();
                    let channel = param_it.next().unwrap();
                    let topic = param_it.next().map(|x| *x);
                    Ok(TOPIC{ channel, topic })
                } else {
                    Err(NeedMoreParams(TOPICId)) }
            }
            "NAMES" => {
                if message.params.len() >= 1 {
                    Ok(NAMES{ channels: message.params[0].split(',').collect::<Vec<_>>() })
                } else {
                    Err(NeedMoreParams(NAMESId)) }
            }
            "LIST" => {
                if message.params.len() >= 1 {
                    let mut param_it = message.params.iter();
                    let channels = param_it.next().unwrap().split(',').collect::<Vec<_>>();
                    let server = param_it.next().map(|x| *x);
                    Ok(LIST{ channels, server })
                } else {
                    Err(NeedMoreParams(LISTId)) }
            }
            "INVITE" => {
                if message.params.len() >= 2 {
                    Ok(INVITE{ nickname: message.params[0],
                        channel: message.params[1] })
                } else {
                    Err(NeedMoreParams(INVITEId)) }
            }
            "KICK" => {
                if message.params.len() >= 2 {
                    let mut param_it = message.params.iter();
                    let channel = param_it.next().unwrap();
                    let user = param_it.next().unwrap();
                    let comment = param_it.next().map(|x| *x);
                    Ok(KICK{ channel, user, comment })
                } else {
                    Err(NeedMoreParams(KICKId)) }
            }
            "MOTD" => {
                Ok(MOTD{ target: message.params.iter().next().map(|x| *x) })
            }
            "VERSION" => {
                Ok(VERSION{ target: message.params.iter().next().map(|x| *x) })
            }
            "ADMIN" => {
                Ok(ADMIN{ target: message.params.iter().next().map(|x| *x) })
            }
            "CONNECT" => {
                if message.params.len() >= 1 {
                    let mut param_it = message.params.iter();
                    let target_server = param_it.next().unwrap();
                    let port = param_it.next().map(|x| x.parse()).transpose();
                    let remote_server = param_it.next().map(|x| *x);
                    match port {
                        Err(_) => {
                            Err(WrongParameter(CONNECTId, 1))
                        }
                        Ok(p) => Ok(CONNECT{ target_server, port: p, remote_server })
                    }
                } else {
                    Err(NeedMoreParams(CONNECTId)) }
            }
            "LUSERS" => Ok(LUSERS{}),
            "TIME" => {
                Ok(TIME{ server: message.params.iter().next().map(|x| *x) })
            }
            "STATS" => {
                if message.params.len() >= 1 {
                    let mut param_it = message.params.iter();
                    let query_str = param_it.next().unwrap();
                    let server = param_it.next().map(|x| *x);
                    
                    if query_str.len() == 1 {
                        Ok(STATS{ query: query_str.chars().next().unwrap(), server })
                    } else {
                        Err(WrongParameter(STATSId, 0))
                    }
                } else {
                    Err(NeedMoreParams(STATSId)) }
            }
            "HELP" => {
                if message.params.len() >= 1 {
                    Ok(HELP{ subject: message.params[0] })
                } else {
                    Err(NeedMoreParams(HELPId)) }
            }
            "INFO" => Ok(INFO{}),
            "MODE" => {
                if message.params.len() >= 1 {
                    let mut param_it = message.params.iter();
                    let target = param_it.next().unwrap();
                    let modestring = param_it.next().map(|x| *x);
                    let mode_args = if modestring.is_some() {
                        Some(param_it.map(|x| *x).collect::<Vec<_>>())
                    } else { None };
                    Ok(MODE{ target, modestring, mode_args })
                } else {
                    Err(NeedMoreParams(MODEId)) }
            }
            "PRIVMSG" => {
                if message.params.len() >= 2 {
                    Ok(PRIVMSG{ targets: message.params[0].split(',').collect::<Vec<_>>(),
                        text: message.params[1] })
                } else {
                    Err(NeedMoreParams(PRIVMSGId)) }
            }
            "NOTICE" => {
                if message.params.len() >= 2 {
                    Ok(NOTICE{ targets: message.params[0].split(',').collect::<Vec<_>>(),
                        text: message.params[1] })
                } else {
                    Err(NeedMoreParams(NOTICEId)) }
            }
            "WHO" => {
                if message.params.len() >= 1 {
                    Ok(WHO{ mask: message.params[0] })
                } else {
                    Err(NeedMoreParams(WHOId)) }
            }
            "WHOIS" => {
                if message.params.len() >= 1 {
                    if message.params.len() >= 2 {
                       Ok(WHOIS{ target: Some(message.params[0]),
                            nickmask: message.params[1] })
                    } else {
                        Ok(WHOIS{ target: None, nickmask: message.params[0] })
                    }
                } else {
                    Err(NeedMoreParams(WHOISId)) }
            }
            "KILL" => {
                if message.params.len() >= 2 {
                    Ok(KILL{ nickname: message.params[0],
                        comment: message.params[1] })
                } else {
                    Err(NeedMoreParams(KILLId)) }
            }
            "REHASH" => Ok(REHASH{}),
            "RESTART" => Ok(RESTART{}),
            "SQUIT" => {
                if message.params.len() >= 2 {
                    Ok(SQUIT{ server: message.params[0],
                        comment: message.params[1] })
                } else {
                    Err(NeedMoreParams(SQUITId)) }
            }
            "AWAY" => {
                Ok(AWAY{ text: message.params.iter().next().map(|x| *x) })
            }
            "USERHOST" => {
                if message.params.len() >= 1 {
                    Ok(USERHOST{ nicknames: message.params[0]
                            .split(',').collect::<Vec<_>>() })
                } else {
                    Err(NeedMoreParams(USERHOSTId)) }
            }
            "WALLOPS" => {
                if message.params.len() >= 1 {
                    Ok(WALLOPS{ text: message.params[0] })
                } else {
                    Err(NeedMoreParams(WALLOPSId)) }
            }
            s => Err(UnknownCommand(s.to_string())),
        }
    }
    
    fn from_message(message: &Message<'a>) -> Result<Self, CommandError> {
        match Self::parse_from_message(message) {
            Ok(x) => {
                match x.validate() {
                    Ok(()) => Ok(x),
                    Err(e) => Err(e)
                }
            }
            Err(e) => Err(e)
        }
    }
    
    fn validate(&self) -> Result<(), CommandError> {
        match self {
            CAP { subcommand, caps, version } => {
                if let Some(cs) = caps {
                    cs.iter().try_for_each(|x| {
                        match *x {
                            "multi-prefix"|"tls"|"sasl" => Ok(()),
                            _ => Err(WrongParameter(CAPId, 1))
                        }
                    })
                } else if let Some(v) = version {
                    if *v < 302 { Err(WrongParameter(CAPId, 1)) }
                    else { Ok(()) }
                } else { Ok(()) }
            }
            NICK{ nickname } => {
                validate_username(nickname)
                    .map_err(|_| WrongParameter(NICKId, 0)) }
            USER{ username, hostname, servername, realname } => {
                validate_username(username)
                    .map_err(|_| WrongParameter(USERId, 0)) }
            OPER{ name, password } => {
                validate_username(name)
                    .map_err(|_| WrongParameter(OPERId, 0)) }
            JOIN{ channels, keys } => {
                channels.iter().try_for_each(|ch| validate_channel(ch))
                    .map_err(|_| WrongParameter(JOINId, 0)) }
            PART{ channels, reason } => {
                channels.iter().try_for_each(|ch| validate_channel(ch))
                    .map_err(|_| WrongParameter(PARTId, 0)) }
            TOPIC{ channel, topic } => {
                validate_channel(channel)
                    .map_err(|_| WrongParameter(TOPICId, 0))}
            NAMES{ channels } => {
                channels.iter().try_for_each(|ch| validate_channel(ch))
                    .map_err(|_| WrongParameter(NAMESId, 0)) }
            LIST{ channels, server } => {
                channels.iter().try_for_each(|ch| validate_channel(ch))
                    .map_err(|_| WrongParameter(LISTId, 0))}
            INVITE{ nickname, channel } => {
                validate_username(nickname)
                    .map_err(|_| WrongParameter(INVITEId, 0)) }
            KICK{ channel, user, comment } => {
                validate_channel(channel)
                    .map_err(|_| WrongParameter(KICKId, 0))?;
                validate_username(user)
                    .map_err(|_| WrongParameter(KICKId, 1)) }
            MOTD{ target } => {
                if let Some(t) = target {
                    validate_server_mask(t, WrongParameter(MOTDId, 0))?;
                }
                Ok(())
            }
            VERSION{ target } => {
                if let Some(t) = target {
                    validate_server_mask(t, WrongParameter(VERSIONId, 0))?;
                }
                Ok(())
            }
            ADMIN{ target } => {
                if let Some(t) = target {
                    validate_server_mask(t,WrongParameter(ADMINId, 0))?;
                }
                Ok(())
            }
            CONNECT{ target_server, port, remote_server } => {
                validate_server(target_server, WrongParameter(CONNECTId, 0))?;
                if let Some(s) = remote_server {
                    validate_server(s, WrongParameter(CONNECTId, 1))?;
                }
                Ok(())
            }
            TIME{ server } => {
                if let Some(s) = server {
                    validate_server(s, WrongParameter(TIMEId, 0))?;
                }
                Ok(())
            }
            STATS{ query, server } => {
                match query {
                    'c'|'h'|'i'|'k'|'l'|'m'|'o'|'u'|'y' => {
                        if let Some(s) = server {
                            validate_server(s, WrongParameter(STATSId, 1))?;
                        }
                    }
                    _ => return Err(WrongParameter(STATSId, 0)),
                };
                Ok(())
            }
            MODE{ target, modestring, mode_args } => {
                if validate_username(target).is_ok() {
                    validate_usermodes(modestring, mode_args,
                        WrongParameter(MODEId, 1))
                } else if validate_channel(target).is_ok() {
                    validate_channelmodes(modestring, mode_args,
                        WrongParameter(MODEId, 1))
                } else { Err(WrongParameter(MODEId, 0)) }
            }
            PRIVMSG{ targets, text } => {
                targets.iter().try_for_each(|n| validate_username(n).or(
                    validate_channel(n)))
                    .map_err(|_| WrongParameter(PRIVMSGId, 0)) }
            NOTICE{ targets, text } => {
                targets.iter().try_for_each(|n| validate_username(n).or(
                    validate_channel(n)))
                    .map_err(|_| WrongParameter(PRIVMSGId, 0)) }
            //WHO{ mask } => { Ok(()) }
            WHOIS{ target, nickmask } => {
                let next_param_idx = if let Some(t) = target {
                    validate_server(t, WrongParameter(WHOISId, 0))?;
                    1
                } else { 0 };
                validate_username(nickmask)
                    .map_err(|_| WrongParameter(WHOISId,
                        next_param_idx))
            }
            KILL{ nickname, comment } => {
                validate_username(nickname)
                    .map_err(|_| WrongParameter(KILLId, 0)) }
            SQUIT{ server, comment } => {
                validate_server(server, WrongParameter(SQUITId, 0))?;
                Ok(())
            }
            USERHOST{ nicknames } => {
                nicknames.iter().try_for_each(|n| validate_username(n))
                    .map_err(|_| WrongParameter(USERHOSTId, 0)) }
            _ => Ok(())
        }
    }
}

// replies

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
    RplMyInfo004{ client: &'a str, servername: &'a str, version: &'a str,
            avail_user_modes: &'a str, avail_chmodes: &'a str,
            avail_chmodes_with_params: Option<&'a str> },
    RplISupport005{ client: &'a str, tokens: &'a str },
    RplBounce010{ client: &'a str, hostname: &'a str, port: u16, info: &'a str },
    RplUModeIs221{ client: &'a str, user_modes: &'a str },
    RplLUserClient251{ client: &'a str, users_num: usize, inv_users_num: usize,
            servers_num: usize },
    RplLUserOp252{ client: &'a str, ops_num: usize },
    RplLUserUnknown253{ client: &'a str, conns_num: usize },
    RplLUserChannels254{ client: &'a str, channels_num: usize },
    RplLUserMe255{ client: &'a str, clients_num: usize, servers_num: usize },
    RplAdminMe256{ client: &'a str, server: &'a str },
    RplAdminLoc1257{ client: &'a str, info: &'a str },
    RplAdminLoc2258{ client: &'a str, info: &'a str },
    RplAdminEmail259{ client: &'a str, email: &'a str },
    RplTryAgain263{ client: &'a str, command: &'a str },
    RplLocalUsers265{ client: &'a str, clients_num: usize, max_clients_num: usize },
    RplGlobalUsers266{ client: &'a str, clients_num: usize, max_clients_num: usize },
    RplWhoIsCertFP276{ client: &'a str, nick: &'a str, fingerprint: &'a str },
    RplNone300{ },
    RplAway301{ client: &'a str, nick: &'a str, message: &'a str },
    RplUserHost302{ client: &'a str, replies: &'a [&'a str] },
    RplUnAway305{ client: &'a str },
    RplNoAway306{ client: &'a str },
    RplWhoReply352{ client: &'a str, channel: &'a str, username: &'a str, host: &'a str,
            server: &'a str, nick: &'a str, flags: &'a str,
            hopcount: usize, realname: &'a str },
    RplEndOfWho315{ client: &'a str, mask: &'a str },
    RplWhoIsRegNick307{ client: &'a str, nick: &'a str },
    RplWhoIsUser311{ client: &'a str, nick: &'a str, username: &'a str, host: &'a str,
            realname: &'a str },
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
    RplNoTopic331{ client: &'a str, channel: &'a str },
    RplTopic332{ client: &'a str, channel: &'a str, topic: &'a str },
    RplTopicWhoTime333{ client: &'a str, channel: &'a str, nick: &'a str, setat: u64 },
    RplWhoIsActually338P1{ client: &'a str, nick: &'a str },
    RplWhoIsActually338P2{ client: &'a str, nick: &'a str, host_ip: &'a str },
    RplWhoIsActually338P3{ client: &'a str, nick: &'a str,
            username: &'a str, hostname: &'a str, ip: &'a str },
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
    ErrUnknownCommand421{ client: &'a str, command: &'a str },
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
    ErrInviteOnlyChan473{ client: &'a str, channel: &'a str },
    ErrBannedFromChan474{ client: &'a str, channel: &'a str },
    ErrBadChannelKey475{ client: &'a str, channel: &'a str },
    ErrBadChanMask476{ channel: &'a str },
    ErrNoPrivileges481{ client: &'a str },
    ErrChanOpPrivsNeeded482{ client: &'a str, channel: &'a str },
    ErrCantKillServer483{ client: &'a str },
    ErrNoOperhost491{ client: &'a str },
    ErrUmodeUnknownFlag501{ client: &'a str },
    ErrUsersDontMatch502{ client: &'a str },
    ErrHelpNotFound524{ client: &'a str, subject: &'a str },
    ErrInvalidKey525{ client: &'a str, target_chan: &'a str },
    RplStartTls670{ client: &'a str },
    RplWhoIsSecure671{ client: &'a str, nick: &'a str },
    ErrStartTls691{ client: &'a str },
    ErrInvalidModeParam696{ client: &'a str, target: &'a str, modechar: char,
        param: &'a str, description: &'a str },
    RplHelpStart704{ client: &'a str, subject: &'a str, line: &'a str },
    RplHelpTxt705{ client: &'a str, subject: &'a str, line: &'a str },
    RplEndOfHelp706{ client: &'a str, subject: &'a str, line: &'a str },
    ErrNoPrivs723{ client: &'a str, privil: &'a str },
    RplLoggedIn900{ client: &'a str, nick: &'a str, user: &'a str, host: &'a str,
            account: &'a str, username: &'a str },
    RplLoggedOut901{ client: &'a str, nick: &'a str, user: &'a str, host: &'a str },
    ErrNickLocked902{ client: &'a str },
    RplSaslSuccess903{ client: &'a str },
    ErrSaslFail904{ client: &'a str },
    ErrSaslTooLong905{ client: &'a str },
    ErrSaslAborted906{ client: &'a str },
    ErrSaslAlready907{ client: &'a str },
    RplSaslMechs908{ client: &'a str, mechanisms: &'a str },
}

use Reply::*;

impl<'a> fmt::Display for Reply<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RplWelcome001{ client, networkname, nick, user, host } => {
                write!(f, "001 {} :Welcome to the {} Network, {}!{}@{}",
                    client, networkname, nick, user, host) }
            RplYourHost002{ client, servername, version } => {
                write!(f, "002 {} :Your host is {}, running version {}",
                    client, servername, version) }
            RplCreated003{ client, datetime } => {
                write!(f, "003 {} :This server was created {}", client, datetime) }
            RplMyInfo004{ client, servername, version, avail_user_modes,
                    avail_chmodes, avail_chmodes_with_params } => {
                if let Some(p) = avail_chmodes_with_params {
                    write!(f, "004 {} {} {} {} {} {}", client, servername, version,
                        avail_user_modes, avail_chmodes, p)
                } else {
                    write!(f, "004 {} {} {} {} {}", client, servername, version,
                        avail_user_modes, avail_chmodes) } }
            RplISupport005{ client, tokens } => {
                write!(f, "005 {} {} :are supported by this server", client, tokens) }
            RplBounce010{ client, hostname, port, info } => {
                write!(f, "010 {} {} {} :{}", client, hostname, port, info) }
            RplUModeIs221{ client, user_modes } => {
                write!(f, "221 {} {}", client, user_modes) }
            RplLUserClient251{ client, users_num, inv_users_num, servers_num } => {
                write!(f, "251 {} :There are {} users and {} invisible on {} servers",
                    client, users_num, inv_users_num, servers_num) }
            RplLUserOp252{ client, ops_num } => {
                write!(f, "252 {} {} :operator(s) online", client, ops_num) }
            RplLUserUnknown253{ client, conns_num } => {
                write!(f, "253 {} {} :unknown connection(s)", client, conns_num) }
            RplLUserChannels254{ client, channels_num } => {
                write!(f, "254 {} {} :channels formed", client, channels_num) }
            RplLUserMe255{ client, clients_num, servers_num } => {
                write!(f, "255 {} :I have {} clients and {} servers", client, clients_num,
                    servers_num) }
            RplAdminMe256{ client, server } => {
                write!(f, "256 {} {} :Administrative info", client, server) }
            RplAdminLoc1257{ client, info } => {
                write!(f, "257 {} :{}", client, info) }
            RplAdminLoc2258{ client, info } => {
                write!(f, "258 {} :{}", client, info) }
            RplAdminEmail259{ client, email } => {
                write!(f, "259 {} :{}", client, email) }
            RplTryAgain263{ client, command } => {
                write!(f, "263 {} {} :Please wait a while and try again.", client, command) }
            RplLocalUsers265{ client, clients_num, max_clients_num } => {
                write!(f, "265 {} {} {} :Current local users {}, max {}", client,
                    clients_num, max_clients_num, clients_num, max_clients_num) }
            RplGlobalUsers266{ client, clients_num, max_clients_num } => {
                write!(f, "266 {} {} {} :Current global users {}, max {}", client,
                    clients_num, max_clients_num, clients_num, max_clients_num) }
            RplWhoIsCertFP276{ client, nick, fingerprint } => {
                write!(f, "276 {} {} :has client certificate fingerprint {}", client, nick,
                    fingerprint) }
            RplNone300{ } => { write!(f, "300 It is none") }
            RplAway301{ client, nick, message } => {
                write!(f, "301 {} {} :{}", client, nick, message) }
            RplUserHost302{ client, replies } => {
                write!(f, "302 {} :{}", client, replies.iter()
                    .map(|x| x.to_string()).collect::<Vec::<_>>().join(" ")) }
            RplUnAway305{ client } => {
                write!(f, "305 {} :You are no longer marked as being away", client) }
            RplNoAway306{ client } => {
                write!(f, "306 {} :You have been marked as being away", client) }
            RplWhoReply352{ client, channel, username, host, server, nick, flags,
                    hopcount, realname } => {
                write!(f, "352 {} {} {} {} {} {} {} :{} {}", client, channel, username, host,
                    server, nick, flags, hopcount, realname) }
            RplEndOfWho315{ client, mask } => {
                write!(f, "315 {} {} :End of WHO list", client, mask) }
            RplWhoIsRegNick307{ client, nick } => {
                write!(f, "307 {} {} :has identified for this nick", client, nick) }
            RplWhoIsUser311{ client, nick, username, host, realname } => {
                write!(f, "311 {} {} {} {} * :{}", client, nick, username, host, realname) }
            RplWhoIsServer312{ client, nick, server, server_info } => {
                write!(f, "312 {} {} {} :{}", client, nick, server, server_info) }
            RplWhoIsOperator313{ client, nick } => {
                write!(f, "313 {} {} :is an IRC operator", client, nick) }
            RplWhoWasUser314{ client, nick, username, host, realname } => {
                write!(f, "314 {} {} {} {} * :{}", client, nick, username, host, realname) }
            RplwhoIsIdle317{ client, nick, secs, signon } => {
                write!(f, "317 {} {} {} {} :seconds idle, signon time",
                    client, nick, secs, signon) }
            RplEndOfWhoIs318{ client, nick } => {
                write!(f, "318 {} {} :End of /WHOIS list", client, nick) }
            RplWhoIsChannels319{ client, nick, channels } => {
                write!(f, "319 {} {} :{}", client, nick, channels.iter().map(|c| {
                    if let Some(prefix) = c.prefix {
                        prefix.to_string() + c.channel
                    } else { c.channel.to_string() }
                }).collect::<Vec<_>>().join(" ")) }
            RplWhoIsSpecial320{ client, nick, special_info } => {
                write!(f, "320 {} {} :{}", client, nick, special_info) }
            RplListStart321{ client } => {
                write!(f, "321 {} Channel :Users  Name", client) }
            RplList322{ client, channel, client_count, topic } => {
                write!(f, "322 {} {} {} :{}", client, channel, client_count, topic) }
            RplListEnd323{ client } => {
                write!(f, "323 {} :End of /LIST", client) }
            RplChannelModeIs324{ client, channel, modestring, mode_args } => {
                write!(f, "324 {} {} {} {}", client, channel, modestring, mode_args.iter()
                    .map(|a| a.to_string()).collect::<Vec<_>>().join(" ")) }
            RplCreationTime329{ client, channel, creation_time } => {
                write!(f, "329 {} {} {}", client, channel, creation_time) }
            RplWhoIsAccount330{ client, nick, account } => {
                write!(f, "330 {} {} {} :is logged in as", client, nick, account) }
            RplNoTopic331{ client, channel } => {
                write!(f, "331 {} {} :No topic is set", client, channel) }
            RplTopic332{ client, channel, topic } => {
                write!(f, "332 {} {} :{}", client, channel, topic) }
            RplTopicWhoTime333{ client, channel, nick, setat } => {
                write!(f, "333 {} {} {} {}", client, channel, nick, setat) }
            RplWhoIsActually338P1{ client, nick } => {
                write!(f, "338 {} {} :is actually ...", client, nick) }
            RplWhoIsActually338P2{ client, nick, host_ip } => {
                write!(f, "338 {} {} {} :Is actually using host", client, nick, host_ip) }
            RplWhoIsActually338P3{ client, nick, username, hostname, ip } => {
                write!(f, "338 {} {} {}@{} {} :Is actually using host", client, nick,
                    username, hostname, ip) }
            RplInviting341{ client, nick, channel } => {
                write!(f, "341 {} {} {}", client, nick, channel) }
            RplInviteList346{ client, channel, mask } => {
                write!(f, "346 {} {} {}", client, channel, mask) }
            RplEndOfInviteList347{ client, channel } => {
                write!(f, "347 {} {} :End of channel invite list", client, channel) }
            RplExceptList348{ client, channel, mask } => {
                write!(f, "348 {} {} {}", client, channel, mask) }
            RplEndOfExceptList349{ client, channel } => {
                write!(f, "349 {} {} :End of channel exception list", client, channel) }
            RplVersion351{ client, version, server, comments } => {
                write!(f, "351 {} {} {} :{}", client, version, server, comments) }
            RplNameReply353{ client, symbol, channel, replies } => {
                write!(f, "353 {} {} {} :{}", client, symbol, channel,
                    replies.iter().map(|r| {
                        if let Some(prefix) = r.prefix {
                            prefix.to_string() + r.nick
                        } else { r.nick.to_string() }
                    }).collect::<Vec<_>>().join(" ")) }
            RplEndOfNames366{ client, channel } => {
                write!(f, "366 {} {} :End of /NAMES list", client, channel) }
            RplBanList367{ client, channel, mask, who, set_ts } => {
                write!(f, "367 {} {} {} {} {}", client, channel, mask, who, set_ts) }
            RplEndOfBanList368{ client, channel } => {
                write!(f, "368 {} {} :End of channel ban list", client, channel) }
            RplEndOfWhoWas369{ client, nick } => {
                write!(f, "369 {} {} :End of WHOWAS", client, nick) }
            RplInfo371{ client, info } => {
                write!(f, "371 {} :{}", client, info) }
            RplEndOfInfo374{ client } => {
                write!(f, "374 {} :End of INFO list", client) }
            RplMotdStart375{ client, server } => {
                write!(f, "375 {} :- {} Message of the day - ", client, server) }
            RplMotd372{ client, motd } => {
                write!(f, "372 {} :{}", client, motd) }
            RplEndOfMotd376{ client } => {
                write!(f, "376 {} :End of /MOTD command." , client) }
            RplWhoIsHost378{ client, nick, host_info } => {
                write!(f, "378 {} {} :is connecting from {}", client, nick, host_info) }
            RplWhoIsModes379{ client, nick, modes } => {
                write!(f, "379 {} {} :is using modes {}", client, nick, modes) }
            RplYouReoper381{ client } => {
                write!(f, "381 {} :You are now an IRC operator", client) }
            RplRehashing382{ client, config_file } => {
                write!(f, "382 {} {} :Rehashing", client, config_file) }
            RplTime391{ client, server, timestamp, ts_offset, human_readable } => {
                write!(f, "391 {} {} {} {} :{}", client, server, timestamp, ts_offset,
                    human_readable) }
            ErrUnknownError400{ client, command, subcommand, info } => {
                if let Some(sc) = subcommand {
                    write!(f, "400 {} {} {} :{}", client, command, sc, info)
                } else {
                    write!(f, "400 {} {} :{}", client, command, info)
                } }
            ErrNoSuchNick401{ client, nick } => {
                write!(f, "401 {} {} :No such nick/channel", client, nick) }
            ErrNoSuchServer402{ client, server } => {
                write!(f, "402 {} {} :No such server", client, server) }
            ErrNoSuchChannel403{ client, channel } => {
                write!(f, "403 {} {} :No such channel", client, channel) }
            ErrCannotSendToChain404{ client, channel } => {
                write!(f, "404 {} {} :Cannot send to channel", client, channel) }
            ErrTooManyChannels405{ client, channel } => {
                write!(f, "405 {} {} :You have joined too many channels", client, channel) }
            ErrNoOrigin409{ client } => {
                write!(f, "409 {} :No origin specified", client) }
            ErrInputTooLong417{ client } => {
                write!(f, "417 {} :Input line was too long", client) }
            ErrUnknownCommand421{ client, command } => {
                write!(f, "421 {} {} :Unknown command", client, command) }
            ErrNoMotd422{ client } => {
                write!(f, "422 {} :MOTD File is missing", client) }
            ErrErroneusNickname432{ client, nick } => {
                write!(f, "432 {} {} :Erroneus nickname", client, nick) }
            ErrNicknameInUse433{ client, nick } => {
                write!(f, "433 {} {} :Nickname is already in use", client, nick) }
            ErrUserNotInChannel441{ client, nick, channel } => {
                write!(f, "441 {} {} {} :They aren't on that channel", client, nick, channel) }
            ErrNotOnChannel442{ client, channel } => {
                write!(f, "442 {} {} :You're not on that channel", client, channel) }
            ErrUserOnChannel443{ client, nick, channel } => {
                write!(f, "443 {} {} {} :is already on channel", client, nick, channel) }
            ErrNotRegistered451{ client } => {
                write!(f, "451 {} :You have not registered", client) }
            ErrNeedMoreParams461{ client, command } => {
                write!(f, "461 {} {} :Not enough parameters", client, command) }
            ErrAlreadyRegistered462{ client } => {
                write!(f, "462 {} :You may not reregister", client) }
            ErrPasswdMismatch464{ client } => {
                write!(f, "464 {} :Password incorrect", client) }
            ErrYoureBannedCreep465{ client } => {
                write!(f, "465 {} :You are banned from this server.", client) }
            ErrChannelIsFull471{ client, channel } => {
                write!(f, "471 {} {} :Cannot join channel (+l)", client, channel) }
            ErrUnknownMode472{ client, modechar } => {
                write!(f, "472 {} {} :is unknown mode char to me", client, modechar) }
            ErrInviteOnlyChan473{ client, channel } => {
                write!(f, "473 {} {} :Cannot join channel (+i)", client, channel) }
            ErrBannedFromChan474{ client, channel } => {
                write!(f, "474 {} {} :Cannot join channel (+b)", client, channel) }
            ErrBadChannelKey475{ client, channel } => {
                write!(f, "475 {} {} :Cannot join channel (+k)", client, channel) }
            ErrBadChanMask476{ channel } => {
                write!(f, "476 {} :Bad Channel Mask", channel) }
            ErrNoPrivileges481{ client } => {
                write!(f, "481 {} :Permission Denied- You're not an IRC operator", client) }
            ErrChanOpPrivsNeeded482{ client, channel } => {
                write!(f, "482 {} {} :You're not channel operator", client, channel) }
            ErrCantKillServer483{ client } => {
                write!(f, "483 {} :You cant kill a server!", client) }
            ErrNoOperhost491{ client } => {
                write!(f, "491 {} :No O-lines for your host", client) }
            ErrUmodeUnknownFlag501{ client } => {
                write!(f, "501 {} :Unknown MODE flag", client) }
            ErrUsersDontMatch502{ client } => {
                write!(f, "502 {} :Cant change mode for other users", client) }
            ErrHelpNotFound524{ client, subject } => {
                write!(f, "524 {} {} :No help available on this topic", client, subject) }
            ErrInvalidKey525{ client, target_chan } => {
                write!(f, "525 {} {} :Key is not well-formed", client, target_chan) }
            RplStartTls670{ client } => {
                write!(f, "670 {} :STARTTLS successful, proceed with TLS handshake", client) }
            RplWhoIsSecure671{ client, nick } => {
                write!(f, "671 {} {} :is using a secure connection", client, nick) }
            ErrStartTls691{ client } => {
                write!(f, "691 {} :STARTTLS failed (Wrong moon phase)", client) }
            ErrInvalidModeParam696{ client, target, modechar, param, description } => {
                write!(f, "696 {} {} {} {} :{}", client, target, modechar, param, description) }
            RplHelpStart704{ client, subject, line } => {
                write!(f, "704 {} {} :{}", client, subject, line) }
            RplHelpTxt705{ client, subject, line } => {
                write!(f, "705 {} {} :{}", client, subject, line) }
            RplEndOfHelp706{ client, subject, line } => {
                write!(f, "706 {} {} :{}", client, subject, line) }
            ErrNoPrivs723{ client, privil } => {
                write!(f, "723 {} {} :Insufficient oper privileges.", client, privil) }
            RplLoggedIn900{ client, nick, user, host, account, username } => {
                write!(f, "900 {} {}!{}@{} {} :You are now logged in as {}", client, nick,
                    user, host, account, username) }
            RplLoggedOut901{ client, nick, user, host } => {
                write!(f, "901 {} {}!{}@{} :You are now logged out", client, nick,
                    user, host) }
            ErrNickLocked902{ client } => {
                write!(f, "902 {} :You must use a nick assigned to you", client) }
            RplSaslSuccess903{ client } => {
                write!(f, "903 {} :SASL authentication successful", client) }
            ErrSaslFail904{ client } => {
                write!(f, "904 {} :SASL authentication failed", client) }
            ErrSaslTooLong905{ client } => {
                write!(f, "905 {} :SASL message too long", client) }
            ErrSaslAborted906{ client } => {
                write!(f, "906 {} :SASL authentication aborted", client) }
            ErrSaslAlready907{ client } => {
                write!(f, "907 {} :You have already authenticated using SASL", client) }
            RplSaslMechs908{ client, mechanisms } => {
                write!(f, "908 {} {} :are available SASL mechanisms", client, mechanisms) }
        }
    }
}

struct User {
    name: String,
    nick: String,
    modes: UserModes,
    ip_addr: IpAddr,
    hostname: String,
    output: Framed<TcpStream, LinesCodec>,
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
    users: DashMap<String, Rc<User>>,
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

#[cfg(test)]
mod test {
    use super::*;
    
    use std::env::temp_dir;
    use std::fs;
    use std::path::Path;
    
    struct TempFileHandle {
        path: String
    }
    
    impl TempFileHandle {
        fn new(path: &str) -> TempFileHandle {
            TempFileHandle{ path: temp_dir().join(path)
                    .to_string_lossy().to_string() }
        }
    }
    
    impl Drop for TempFileHandle {
        fn drop(&mut self) {
            fs::remove_file(self.path.as_str()).unwrap();
        }
    }
    
    #[test]
    fn test_mainconfig_new() {
        let file_handle = TempFileHandle::new("temp_config.toml");
        let cli = Cli{ config: Some(file_handle.path.clone()),
            listen: None, port: None, name: None, network: None,
            dns_lookup: false, tls_cert_file: None, tls_cert_key_file: None };
        
        fs::write(file_handle.path.as_str(), 
            r##"
name = "irci.localhost"
admin_info = "IRCI is local IRC server"
admin_info2 = "IRCI is good server"
info = "This is IRCI server"
listen = "127.0.0.1"
port = 6667
network = "IRCInetwork"
max_connections = 4000
max_joins = 10
max_nickname_len = 20
ping_timeout = 100
pong_timeout = 30
dns_lookup = false

[default_user_modes]
invisible = false
oper = false
local_oper = false
registered = true
wallops = false

[tls]
cert_file = "cert.crt"
cert_key_file = "cert_key.crt"

[[operators]]
name = "matiszpaki"
password = "fbg9rt0g5rtygh"

[[channels]]
name = "#channel1"
topic = "Some topic"
[channels.modes]
ban = [ 'baddi@*', 'baddi2@*' ]
exception = [ 'bobby@*', 'mati@*' ]
moderated = false
secret = false
protected_topic = false
no_external_messages = false

[[users]]
name = "lucas"
nick = "luckboy"
password = "luckyluke"

[[channels]]
name = "#channel2"
topic = "Some topic 2"
[channels.modes]
key = "hokus pokus"
ban = []
exception = []
invite_exception = [ "nomi@buru.com", "pampam@zerox.net" ]
moderated = true
client_limit = 200
secret = false
protected_topic = true
no_external_messages = false
"##).unwrap();
        let result = MainConfig::new(cli.clone()).map_err(|e| e.to_string());
        assert_eq!(Ok(MainConfig{
            name: "irci.localhost".to_string(),
            admin_info: "IRCI is local IRC server".to_string(),
            admin_info2: Some("IRCI is good server".to_string()),
            info: "This is IRCI server".to_string(),
            listen: "127.0.0.1".parse().unwrap(),
            port: 6667,
            network: "IRCInetwork".to_string(),
            max_connections: Some(4000),
            max_joins: Some(10),
            max_nickname_len: 20,
            ping_timeout: 100,
            pong_timeout: 30,
            dns_lookup: false,
            tls: Some(TLSConfig{ cert_file: "cert.crt".to_string(),
                cert_key_file: "cert_key.crt".to_string() }),
            default_user_modes: UserModes {
                invisible: false, oper: false, local_oper: false,
                registered: true, wallops: false,
            },
            operators: Some(vec![
                OperatorConfig{ name: "matiszpaki".to_string(),
                    password: "fbg9rt0g5rtygh".to_string(), mask: None }
            ]),
            users: Some(vec![
                UserConfig{ name: "lucas".to_string(), nick: "luckboy".to_string(),
                    password: "luckyluke".to_string() }
            ]),
            channels: Some(vec![
                ChannelConfig{
                    name: "#channel1".to_string(),
                    topic: "Some topic".to_string(),
                    modes: ChannelModes{ key: None,
                        ban: Some(vec![ "baddi@*".to_string(), "baddi2@*".to_string()]),
                        exception: Some(vec![ "bobby@*".to_string(), "mati@*".to_string() ]),
                        invite_exception: None,
                        client_limit: None,
                        moderated: false, secret: false, protected_topic: false,
                        no_external_messages: false },
                },
                ChannelConfig{
                    name: "#channel2".to_string(),
                    topic: "Some topic 2".to_string(),
                    modes: ChannelModes{ key: Some("hokus pokus".to_string()),
                        ban: Some(vec![]),
                        exception: Some(vec![]),
                        invite_exception: Some(
                            vec![ "nomi@buru.com".to_string(),
                                "pampam@zerox.net".to_string() ]),
                        client_limit: Some(200),
                        moderated: true, secret: false, protected_topic: true,
                        no_external_messages: false },
                },
            ]),
        }), result);
        
        let cli2 = Cli{ config: Some(file_handle.path.clone()),
            listen: Some("192.168.1.4".parse().unwrap()), port: Some(6668),
            name: Some("ircer.localhost".to_string()),
            network: Some("SomeNetwork".to_string()),
            dns_lookup: true, tls_cert_file: Some("some_cert.crt".to_string()),
            tls_cert_key_file: Some("some_key.crt".to_string()) };
            
        let result = MainConfig::new(cli2).map_err(|e| e.to_string());
        assert_eq!(Ok(MainConfig{
            name: "ircer.localhost".to_string(),
            admin_info: "IRCI is local IRC server".to_string(),
            admin_info2: Some("IRCI is good server".to_string()),
            info: "This is IRCI server".to_string(),
            listen: "192.168.1.4".parse().unwrap(),
            port: 6668,
            network: "SomeNetwork".to_string(),
            max_connections: Some(4000),
            max_joins: Some(10),
            max_nickname_len: 20,
            ping_timeout: 100,
            pong_timeout: 30,
            dns_lookup: true,
            tls: Some(TLSConfig{ cert_file: "some_cert.crt".to_string(),
                cert_key_file: "some_key.crt".to_string() }),
            default_user_modes: UserModes {
                invisible: false, oper: false, local_oper: false,
                registered: true, wallops: false,
            },
            operators: Some(vec![
                OperatorConfig{ name: "matiszpaki".to_string(),
                    password: "fbg9rt0g5rtygh".to_string(), mask: None }
            ]),
            users: Some(vec![
                UserConfig{ name: "lucas".to_string(), nick: "luckboy".to_string(),
                    password: "luckyluke".to_string() }
            ]),
            channels: Some(vec![
                ChannelConfig{
                    name: "#channel1".to_string(),
                    topic: "Some topic".to_string(),
                    modes: ChannelModes{ key: None,
                        ban: Some(vec![ "baddi@*".to_string(), "baddi2@*".to_string()]),
                        exception: Some(vec![ "bobby@*".to_string(), "mati@*".to_string() ]),
                        invite_exception: None,
                        client_limit: None,
                        moderated: false, secret: false, protected_topic: false,
                        no_external_messages: false },
                },
                ChannelConfig{
                    name: "#channel2".to_string(),
                    topic: "Some topic 2".to_string(),
                    modes: ChannelModes{ key: Some("hokus pokus".to_string()),
                        ban: Some(vec![]),
                        exception: Some(vec![]),
                        invite_exception: Some(
                            vec![ "nomi@buru.com".to_string(),
                                "pampam@zerox.net".to_string() ]),
                        client_limit: Some(200),
                        moderated: true, secret: false, protected_topic: true,
                        no_external_messages: false },
                },
            ]),
        }), result);
        
        let cli2 = Cli{ config: Some(file_handle.path.clone()),
            listen: Some("192.168.1.4".parse().unwrap()), port: Some(6668),
            name: Some("ircer.localhost".to_string()),
            network: Some("SomeNetwork".to_string()),
            dns_lookup: true, tls_cert_file: Some("some_cert.crt".to_string()),
            tls_cert_key_file: None };
        let result = MainConfig::new(cli2).map_err(|e| e.to_string());
        assert_eq!(Err("error: TLS certifcate file and certificate key file together \
                are required".to_string()), result);
        
        // next testcase
        fs::write(file_handle.path.as_str(), 
            r##"
name = "irci.localhost"
admin_info = "IRCI is local IRC server"
admin_info2 = "IRCI is good server"
info = "This is IRCI server"
listen = "127.0.0.1"
port = 6667
network = "IRCInetwork"
max_nickname_len = 20
ping_timeout = 100
pong_timeout = 30
dns_lookup = false

[default_user_modes]
invisible = false
oper = false
local_oper = false
registered = true
wallops = false

[[channels]]
name = "#channel1"
topic = "Some topic"
[channels.modes]
ban = [ 'baddi@*', 'baddi2@*' ]
exception = [ 'bobby@*', 'mati@*' ]
moderated = false
secret = false
protected_topic = false
no_external_messages = false

[[channels]]
name = "#channel2"
topic = "Some topic 2"
[channels.modes]
moderated = true
secret = false
protected_topic = true
no_external_messages = false
"##).unwrap();
        let result = MainConfig::new(cli.clone()).map_err(|e| e.to_string());
        assert_eq!(Ok(MainConfig{
            name: "irci.localhost".to_string(),
            admin_info: "IRCI is local IRC server".to_string(),
            admin_info2: Some("IRCI is good server".to_string()),
            info: "This is IRCI server".to_string(),
            listen: "127.0.0.1".parse().unwrap(),
            port: 6667,
            network: "IRCInetwork".to_string(),
            max_connections: None,
            max_joins: None,
            max_nickname_len: 20,
            ping_timeout: 100,
            pong_timeout: 30,
            dns_lookup: false,
            tls: None,
            default_user_modes: UserModes {
                invisible: false, oper: false, local_oper: false,
                registered: true, wallops: false,
            },
            operators: None,
            users: None,
            channels: Some(vec![
                ChannelConfig{
                    name: "#channel1".to_string(),
                    topic: "Some topic".to_string(),
                    modes: ChannelModes{ key: None,
                        ban: Some(vec![ "baddi@*".to_string(), "baddi2@*".to_string()]),
                        exception: Some(vec![ "bobby@*".to_string(), "mati@*".to_string() ]),
                        invite_exception: None,
                        client_limit: None,
                        moderated: false, secret: false, protected_topic: false,
                        no_external_messages: false },
                },
                ChannelConfig{
                    name: "#channel2".to_string(),
                    topic: "Some topic 2".to_string(),
                    modes: ChannelModes{ key: None,
                        ban: None,
                        exception: None,
                        invite_exception: None,
                        client_limit: None,
                        moderated: true, secret: false, protected_topic: true,
                        no_external_messages: false },
                },
            ]),
        }), result);
        
        // error
        fs::write(file_handle.path.as_str(), 
            r##"
name = "ircilocalhost"
admin_info = "IRCI is local IRC server"
admin_info2 = "IRCI is good server"
info = "This is IRCI server"
listen = "127.0.0.1"
port = 6667
network = "IRCInetwork"
max_connections = 4000
max_joins = 10
max_nickname_len = 20
ping_timeout = 100
pong_timeout = 30
dns_lookup = false

[default_user_modes]
invisible = false
oper = false
local_oper = false
registered = true
wallops = false

[tls]
cert_file = "cert.crt"
cert_key_file = "cert_key.crt"

[[operators]]
name = "matiszpaki"
password = "fbg9rt0g5rtygh"

[[channels]]
name = "#channel1"
topic = "Some topic"
[channels.modes]
ban = [ 'baddi@*', 'baddi2@*' ]
exception = [ 'bobby@*', 'mati@*' ]
moderated = false
secret = false
protected_topic = false
no_external_messages = false

[[users]]
name = "lucas"
nick = "luckboy"
password = "luckyluke"

[[channels]]
name = "#channel2"
topic = "Some topic 2"
[channels.modes]
key = "hokus pokus"
ban = []
exception = []
invite_exception = [ "nomi@buru.com", "pampam@zerox.net" ]
moderated = true
client_limit = 200
secret = false
protected_topic = true
no_external_messages = false
"##).unwrap();
        let result = MainConfig::new(cli.clone()).map_err(|e| e.to_string());
        // because sorting of ValidationErrors changes order we check to cases
        assert!(Err("name: Validation error: contains [{\"value\": String(\"ircilocalhost\"), \
\"needle\": String(\".\")}]".to_string()) == result ||
                Err("name: Validation error: contains [{\"needle\": String(\".\"), \
\"value\": String(\"ircilocalhost\")}]".to_string()) == result);

        fs::write(file_handle.path.as_str(), 
            r##"
name = "irci.localhost"
admin_info = "IRCI is local IRC server"
admin_info2 = "IRCI is good server"
info = "This is IRCI server"
listen = "127.0.0.1"
port = 6667
network = "IRCInetwork"
max_connections = 4000
max_joins = 10
max_nickname_len = 20
ping_timeout = 100
pong_timeout = 30
dns_lookup = false

[default_user_modes]
invisible = false
oper = false
local_oper = false
registered = true
wallops = false

[tls]
cert_file = "cert.crt"
cert_key_file = "cert_key.crt"

[[operators]]
name = "matis.zpaki"
password = "fbg9rt0g5rtygh"

[[channels]]
name = "#channel1"
topic = "Some topic"
[channels.modes]
ban = [ 'baddi@*', 'baddi2@*' ]
exception = [ 'bobby@*', 'mati@*' ]
moderated = false
secret = false
protected_topic = false
no_external_messages = false

[[users]]
name = "lucas"
nick = "luckboy"
password = "luckyluke"

[[channels]]
name = "#channel2"
topic = "Some topic 2"
[channels.modes]
key = "hokus pokus"
ban = []
exception = []
invite_exception = [ "nomi@buru.com", "pampam@zerox.net" ]
moderated = true
client_limit = 200
secret = false
protected_topic = true
no_external_messages = false
"##).unwrap();
        let result = MainConfig::new(cli.clone()).map_err(|e| e.to_string());
        assert_eq!(Err("operators[0].name: Validation error: Username must not \
contains '.', ',' or ':'. [{\"value\": String(\"matis.zpaki\")}]".to_string()), result);

        fs::write(file_handle.path.as_str(), 
            r##"
name = "irci.localhost"
admin_info = "IRCI is local IRC server"
admin_info2 = "IRCI is good server"
info = "This is IRCI server"
listen = "127.0.0.1"
port = 6667
network = "IRCInetwork"
max_connections = 4000
max_joins = 10
max_nickname_len = 20
ping_timeout = 100
pong_timeout = 30
dns_lookup = false

[default_user_modes]
invisible = false
oper = false
local_oper = false
registered = true
wallops = false

[tls]
cert_file = "cert.crt"
cert_key_file = "cert_key.crt"

[[operators]]
name = "matis:zpaki"
password = "fbg9rt0g5rtygh"

[[channels]]
name = "#channel1"
topic = "Some topic"
[channels.modes]
ban = [ 'baddi@*', 'baddi2@*' ]
exception = [ 'bobby@*', 'mati@*' ]
moderated = false
secret = false
protected_topic = false
no_external_messages = false

[[users]]
name = "lucas"
nick = "luckboy"
password = "luckyluke"

[[channels]]
name = "#channel2"
topic = "Some topic 2"
[channels.modes]
key = "hokus pokus"
ban = []
exception = []
invite_exception = [ "nomi@buru.com", "pampam@zerox.net" ]
moderated = true
client_limit = 200
secret = false
protected_topic = true
no_external_messages = false
"##).unwrap();
        let result = MainConfig::new(cli.clone()).map_err(|e| e.to_string());
        assert_eq!(Err("operators[0].name: Validation error: Username must not \
contains '.', ',' or ':'. [{\"value\": String(\"matis:zpaki\")}]".to_string()), result);

        fs::write(file_handle.path.as_str(), 
            r##"
name = "irci.localhost"
admin_info = "IRCI is local IRC server"
admin_info2 = "IRCI is good server"
info = "This is IRCI server"
listen = "127.0.0.1"
port = 6667
network = "IRCInetwork"
max_connections = 4000
max_joins = 10
max_nickname_len = 20
ping_timeout = 100
pong_timeout = 30
dns_lookup = false

[default_user_modes]
invisible = false
oper = false
local_oper = false
registered = true
wallops = false

[tls]
cert_file = "cert.crt"
cert_key_file = "cert_key.crt"

[[operators]]
name = "matiszpaki"
password = "fbg9rt0g5rtygh"

[[channels]]
name = "#channel1"
topic = "Some topic"
[channels.modes]
ban = [ 'baddi@*', 'baddi2@*' ]
exception = [ 'bobby@*', 'mati@*' ]
moderated = false
secret = false
protected_topic = false
no_external_messages = false

[[users]]
name = "lucas"
nick = "luckboy"
password = "luckyluke"

[[channels]]
name = "^channel2"
topic = "Some topic 2"
[channels.modes]
key = "hokus pokus"
ban = []
exception = []
invite_exception = [ "nomi@buru.com", "pampam@zerox.net" ]
moderated = true
client_limit = 200
secret = false
protected_topic = true
no_external_messages = false
"##).unwrap();
        let result = MainConfig::new(cli.clone()).map_err(|e| e.to_string());
        assert_eq!(Err("channels[1].name: Validation error: Channel name must have '#' or \
'&' at start and must not contains ',' or ':'. [{\"value\": String(\"^channel2\")}]"
        .to_string()), result);
        
        fs::write(file_handle.path.as_str(), 
            r##"
name = "irci.localhost"
admin_info = "IRCI is local IRC server"
admin_info2 = "IRCI is good server"
info = "This is IRCI server"
listen = "127.0.0.1"
port = 6667
network = "IRCInetwork"
max_connections = 4000
max_joins = 10
max_nickname_len = 20
ping_timeout = 100
pong_timeout = 30
dns_lookup = false

[default_user_modes]
invisible = false
oper = false
local_oper = false
registered = true
wallops = false

[tls]
cert_file = "cert.crt"
cert_key_file = "cert_key.crt"

[[operators]]
name = "matiszpaki"
password = "fbg9rt0g5rtygh"

[[channels]]
name = "#channel1"
topic = "Some topic"
[channels.modes]
ban = [ 'baddi@*', 'baddi2@*' ]
exception = [ 'bobby@*', 'mati@*' ]
moderated = false
secret = false
protected_topic = false
no_external_messages = false

[[users]]
name = "lucas"
nick = "luckboy"
password = "luckyluke"

[[channels]]
name = "#cha:nnel2"
topic = "Some topic 2"
[channels.modes]
key = "hokus pokus"
ban = []
exception = []
invite_exception = [ "nomi@buru.com", "pampam@zerox.net" ]
moderated = true
client_limit = 200
secret = false
protected_topic = true
no_external_messages = false
"##).unwrap();
        let result = MainConfig::new(cli.clone()).map_err(|e| e.to_string());
        assert_eq!(Err("channels[1].name: Validation error: Channel name must have '#' or \
'&' at start and must not contains ',' or ':'. \
[{\"value\": String(\"#cha:nnel2\")}]".to_string()), result);
    }
    
    #[test]
    fn test_irc_lines_codec() {
        let mut codec = IRCLinesCodec::new();
        let mut buf = BytesMut::new();
        codec.encode("my line", &mut buf).unwrap();
        assert_eq!("my line\r\n".as_bytes(), buf);
        let mut buf = BytesMut::from("my line 2\n");
        assert_eq!(codec.decode(&mut buf).map_err(|e| e.to_string()),
                Ok(Some("my line 2".to_string())));
        assert_eq!(buf, BytesMut::new());
        let mut buf = BytesMut::from("my line 2\r\n");
        assert_eq!(codec.decode(&mut buf).map_err(|e| e.to_string()),
                Ok(Some("my line 2".to_string())));
        assert_eq!(buf, BytesMut::new());
    }
    
    #[test]
    fn test_message_from_shared_str() {
        assert_eq!(Ok(Message{ source: None, command: "QUIT", params: vec![] }),
                Message::from_shared_str("QUIT").map_err(|e| e.to_string()));
        assert_eq!(Ok(Message{ source: None, command: "QUIT", params: vec![] }),
                Message::from_shared_str("   QUIT").map_err(|e| e.to_string()));
        assert_eq!(Ok(Message{ source: Some("source"), command: "QUIT", params: vec![] }),
                Message::from_shared_str(":source QUIT").map_err(|e| e.to_string()));
        assert_eq!(Ok(Message{ source: None, command: "USER",
            params: vec!["guest", "0", "*", "Ronnie Reagan"] }),
                Message::from_shared_str("USER guest 0 * :Ronnie Reagan")
                    .map_err(|e| e.to_string()));
        assert_eq!(Ok(Message{ source: None, command: "USER",
            params: vec!["guest", "0", "*", "Benny"] }),
                Message::from_shared_str("USER guest 0 * Benny")
                    .map_err(|e| e.to_string()));
        assert_eq!(Ok(Message{ source: None, command: "PRIVMSG",
            params: vec!["bobby", ":-). Hello guy!"] }),
                Message::from_shared_str("PRIVMSG bobby ::-). Hello guy!")
                    .map_err(|e| e.to_string()));
        assert_eq!(Ok(Message{ source: Some("mati!mat@gg.com"),
                command: "QUIT", params: vec![] }),
                Message::from_shared_str(":mati!mat@gg.com QUIT")
                    .map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong source syntax".to_string()),
                Message::from_shared_str(":mati@mat!gg.com QUIT")
                        .map_err(|e| e.to_string()));
    }
    
    #[test]
    fn test_command_from_message() {
        assert_eq!(Ok(CAP{ subcommand: CapCommand::LS, caps: None, version: None }),
            Command::from_message(&Message{ source: None, command: "CAP",
                params: vec![ "LS" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(CAP{ subcommand: CapCommand::LS, caps: None, version: Some(302) }),
            Command::from_message(&Message{ source: None, command: "CAP",
                params: vec![ "LS", "302" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(CAP{ subcommand: CapCommand::LS, caps: None, version: Some(303) }),
            Command::from_message(&Message{ source: None, command: "CAP",
                params: vec![ "LS", "303" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 1 in command 'CAP'".to_string()),
            Command::from_message(&Message{ source: None, command: "CAP",
                params: vec![ "LS", "301" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 1 in command 'CAP'".to_string()),
            Command::from_message(&Message{ source: None, command: "CAP",
                params: vec![ "LS", "xxx" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(CAP{ subcommand: CapCommand::LIST, caps: None, version: None }),
            Command::from_message(&Message{ source: None, command: "CAP",
                params: vec![ "LIST" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(CAP{ subcommand: CapCommand::REQ, version: None,
            caps: Some(vec!["multi-prefix", "tls"]) }),
            Command::from_message(&Message{ source: None, command: "CAP",
                params: vec![ "REQ", "multi-prefix tls" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 1 in command 'CAP'".to_string()),
            Command::from_message(&Message{ source: None, command: "CAP",
                params: vec![ "REQ", "multi-prefix tlsx" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Unknown subcommand 'LSS' in command 'CAP'".to_string()),
            Command::from_message(&Message{ source: None, command: "CAP",
                params: vec![ "LSS" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Command 'CAP' needs more parameters".to_string()),
            Command::from_message(&Message{ source: None, command: "CAP",
                params: vec![] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(AUTHENTICATE{}),
            Command::from_message(&Message{ source: None, command: "AUTHENTICATE",
                params: vec![] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(PASS{ password: "secret" }),
            Command::from_message(&Message{ source: None, command: "PASS",
                params: vec![ "secret" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Command 'PASS' needs more parameters".to_string()),
            Command::from_message(&Message{ source: None, command: "PASS",
                params: vec![] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(NICK{ nickname: "lucky" }),
            Command::from_message(&Message{ source: None, command: "NICK",
                params: vec![ "lucky" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'NICK'".to_string()),
            Command::from_message(&Message{ source: None, command: "NICK",
                params: vec![ "luc.ky" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'NICK'".to_string()),
            Command::from_message(&Message{ source: None, command: "NICK",
                params: vec![ "luc,ky" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'NICK'".to_string()),
            Command::from_message(&Message{ source: None, command: "NICK",
                params: vec![ "luc:ky" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Command 'NICK' needs more parameters".to_string()),
            Command::from_message(&Message{ source: None, command: "NICK",
                params: vec![] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(USER{ username: "chris", hostname: "0", servername: "*",
                realname: "Chris Wood" }),
            Command::from_message(&Message{ source: None, command: "USER",
                params: vec![ "chris", "0", "*", "Chris Wood" ] })
                .map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'USER'".to_string()),
            Command::from_message(&Message{ source: None, command: "USER",
                params: vec![ "chr:is", "0", "*", "Chris Wood" ] })
                .map_err(|e| e.to_string()));
        assert_eq!(Err("Command 'USER' needs more parameters".to_string()),
            Command::from_message(&Message{ source: None, command: "USER",
                params: vec![ "chris", "0", "*" ] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(PING{}),
            Command::from_message(&Message{ source: None, command: "PING",
                params: vec![] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(OPER{ name: "guru", password: "mythebestday" }),
            Command::from_message(&Message{ source: None, command: "OPER",
                params: vec![ "guru", "mythebestday" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'OPER'".to_string()),
            Command::from_message(&Message{ source: None, command: "OPER",
                params: vec![ "gu:ru", "mythebestday" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Command 'OPER' needs more parameters".to_string()),
            Command::from_message(&Message{ source: None, command: "OPER",
                params: vec![ "guru" ] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(QUIT{}),
            Command::from_message(&Message{ source: None, command: "QUIT",
                params: vec![] }).map_err(|e| e.to_string()));
    }
    
    #[test]
    fn test_replies() {
        assert_eq!("001 <client> :Welcome to the <networkname> Network, <nick>!<user>@<host>",
            format!("{}", RplWelcome001{ client: "<client>", networkname: "<networkname>",
                nick: "<nick>", user: "<user>", host: "<host>" }));
        assert_eq!("002 <client> :Your host is <servername>, running version <version>",
            format!("{}", RplYourHost002{ client: "<client>", servername: "<servername>",
                version: "<version>" }));
        assert_eq!("003 <client> :This server was created <datetime>",
            format!("{}", RplCreated003{ client: "<client>", datetime: "<datetime>" }));
        assert_eq!("004 <client> <servername> <version> <available user modes> \
                    <available channel modes> <channel modes with a parameter>",
            format!("{}", RplMyInfo004{ client: "<client>", servername: "<servername>",
            version: "<version>", avail_user_modes: "<available user modes>",
            avail_chmodes: "<available channel modes>",
            avail_chmodes_with_params: Some("<channel modes with a parameter>") }));
        assert_eq!("004 <client> <servername> <version> <available user modes> \
                    <available channel modes>",
            format!("{}", RplMyInfo004{ client: "<client>", servername: "<servername>",
            version: "<version>", avail_user_modes: "<available user modes>",
            avail_chmodes: "<available channel modes>",
            avail_chmodes_with_params: None }));
        assert_eq!("005 <client> <1-13 tokens> :are supported by this server",
            format!("{}", RplISupport005{ client: "<client>", tokens: "<1-13 tokens>" }));
        assert_eq!("010 <client> <hostname> 6667 :<info>",
            format!("{}", RplBounce010{ client: "<client>", hostname: "<hostname>",
                port: 6667, info: "<info>" }));
        assert_eq!("221 <client> <user modes>",
            format!("{}", RplUModeIs221{ client: "<client>", user_modes: "<user modes>" }));
        assert_eq!("251 <client> :There are 3 users and 4 invisible on 5 servers",
            format!("{}", RplLUserClient251{ client: "<client>", users_num: 3,
                inv_users_num: 4, servers_num: 5 }));
        assert_eq!("252 <client> 6 :operator(s) online",
            format!("{}", RplLUserOp252{ client: "<client>", ops_num: 6 }));
        assert_eq!("253 <client> 7 :unknown connection(s)",
            format!("{}", RplLUserUnknown253{ client: "<client>", conns_num: 7 }));
        assert_eq!("254 <client> 8 :channels formed",
            format!("{}", RplLUserChannels254{ client: "<client>", channels_num: 8 }));
        assert_eq!("255 <client> :I have 3 clients and 6 servers",
            format!("{}", RplLUserMe255{ client: "<client>", clients_num: 3,
                servers_num: 6 }));
        assert_eq!("256 <client> <server> :Administrative info",
            format!("{}", RplAdminMe256{ client: "<client>", server: "<server>" }));
        assert_eq!("257 <client> :<info>",
            format!("{}", RplAdminLoc1257{ client: "<client>", info: "<info>" }));
        assert_eq!("258 <client> :<info>",
            format!("{}", RplAdminLoc2258{ client: "<client>", info: "<info>" }));
        assert_eq!("259 <client> :<info>",
            format!("{}", RplAdminEmail259{ client: "<client>", email: "<info>" }));
        assert_eq!("263 <client> <command> :Please wait a while and try again.",
            format!("{}", RplTryAgain263{ client: "<client>", command: "<command>" }));
        assert_eq!("265 <client> 4 7 :Current local users 4, max 7",
            format!("{}", RplLocalUsers265{ client: "<client>", clients_num: 4,
                max_clients_num: 7 }));
        assert_eq!("266 <client> 7 10 :Current global users 7, max 10",
            format!("{}", RplGlobalUsers266{ client: "<client>", clients_num: 7,
                max_clients_num: 10 }));
        assert_eq!("276 <client> <nick> :has client certificate fingerprint <fingerprint>",
            format!("{}", RplWhoIsCertFP276{ client: "<client>", nick: "<nick>",
                fingerprint: "<fingerprint>" }));
        assert_eq!("300 It is none", format!("{}", RplNone300{}));
        assert_eq!("301 <client> <nick> :<message>",
            format!("{}", RplAway301{ client: "<client>", nick: "<nick>",
                message: "<message>" }));
        assert_eq!("302 <client> :",
            format!("{}", RplUserHost302{ client: "<client>", replies: &vec![] }));
        assert_eq!("302 <client> :<reply1> <reply2> <reply3>",
            format!("{}", RplUserHost302{ client: "<client>",
                replies: &vec![ "<reply1>", "<reply2>", "<reply3>"] }));
        assert_eq!("305 <client> :You are no longer marked as being away",
            format!("{}", RplUnAway305{ client: "<client>" }));
        assert_eq!("306 <client> :You have been marked as being away",
            format!("{}", RplNoAway306{ client: "<client>" }));
        assert_eq!("352 <client> <channel> <username> <host> <server> <nick> \
                <flags> :2 <realname>",
            format!("{}", RplWhoReply352{ client: "<client>", channel: "<channel>",
                username: "<username>", host: "<host>", server: "<server>", nick: "<nick>",
                flags: "<flags>", hopcount: 2, realname: "<realname>" }));
        assert_eq!("315 <client> <mask> :End of WHO list",
            format!("{}", RplEndOfWho315{ client: "<client>", mask: "<mask>" }));
        assert_eq!("307 <client> <nick> :has identified for this nick",
            format!("{}", RplWhoIsRegNick307{ client: "<client>", nick: "<nick>" }));
        assert_eq!("311 <client> <nick> <username> <host> * :<realname>",
            format!("{}", RplWhoIsUser311{ client: "<client>", nick: "<nick>",
                host: "<host>", username: "<username>", realname: "<realname>" }));
        assert_eq!("312 <client> <nick> <server> :<server info>",
            format!("{}", RplWhoIsServer312{ client: "<client>", nick: "<nick>",
                server: "<server>", server_info: "<server info>" }));
        assert_eq!("313 <client> <nick> :is an IRC operator",
            format!("{}", RplWhoIsOperator313{ client: "<client>", nick: "<nick>" }));
        assert_eq!("314 <client> <nick> <username> <host> * :<realname>",
            format!("{}", RplWhoWasUser314{ client: "<client>", nick: "<nick>",
                username: "<username>", host: "<host>", realname: "<realname>" }));
        assert_eq!("317 <client> <nick> 134 548989343 :seconds idle, signon time",
            format!("{}", RplwhoIsIdle317{ client: "<client>", nick: "<nick>",
                secs: 134, signon: 548989343 }));
        assert_eq!("318 <client> <nick> :End of /WHOIS list",
            format!("{}", RplEndOfWhoIs318{ client: "<client>", nick: "<nick>" }));
        assert_eq!("319 <client> <nick> :prefix1<channel1> <channel2> prefix3<channel3>",
            format!("{}", RplWhoIsChannels319{ client: "<client>", nick: "<nick>",
                channels: &vec![
                    WhoIsChannelStruct{ prefix: Some("prefix1"), channel: "<channel1>" },
                    WhoIsChannelStruct{ prefix: None, channel: "<channel2>" },
                    WhoIsChannelStruct{ prefix: Some("prefix3"), channel: "<channel3>" }]}));
        assert_eq!("320 <client> <nick> :special info",
            format!("{}", RplWhoIsSpecial320{ client: "<client>", nick: "<nick>",
                special_info: "special info" }));
        assert_eq!("321 <client> Channel :Users  Name",
            format!("{}", RplListStart321{ client: "<client>" }));
        assert_eq!("322 <client> <channel> 47 :<topic>",
            format!("{}", RplList322{ client: "<client>", channel: "<channel>",
                client_count: 47, topic: "<topic>" }));
        assert_eq!("323 <client> :End of /LIST",
            format!("{}", RplListEnd323{ client: "<client>" }));
        assert_eq!("324 <client> <channel> <modestring> <modearg1> <modearg2>",
            format!("{}", RplChannelModeIs324{ client: "<client>", channel: "<channel>",
                modestring: "<modestring>",
                mode_args: &vec![ "<modearg1>", "<modearg2>" ] }));
        assert_eq!("329 <client> <channel> <creationtime>",
            format!("{}", RplCreationTime329{ client: "<client>", channel: "<channel>",
                creation_time: "<creationtime>" }));
        assert_eq!("330 <client> <nick> <account> :is logged in as",
            format!("{}", RplWhoIsAccount330{ client: "<client>", nick: "<nick>",
                account: "<account>" }));
        assert_eq!("331 <client> <channel> :No topic is set",
            format!("{}", RplNoTopic331{ client: "<client>", channel: "<channel>" }));
        assert_eq!("332 <client> <channel> :<topic>",
            format!("{}", RplTopic332{ client: "<client>", channel: "<channel>",
                topic: "<topic>" }));
        assert_eq!("333 <client> <channel> <nick> 38329311",
            format!("{}", RplTopicWhoTime333{ client: "<client>", channel: "<channel>",
                nick: "<nick>", setat: 38329311 }));
        assert_eq!("338 <client> <nick> :is actually ...",
            format!("{}", RplWhoIsActually338P1{ client: "<client>", nick: "<nick>" }));
        assert_eq!("338 <client> <nick> <host|ip> :Is actually using host",
            format!("{}", RplWhoIsActually338P2{ client: "<client>", nick: "<nick>",
                host_ip: "<host|ip>" }));
        assert_eq!("338 <client> <nick> <username>@<hostname> <ip> :Is actually using host",
            format!("{}", RplWhoIsActually338P3{ client: "<client>", nick: "<nick>",
                username: "<username>", hostname: "<hostname>", ip: "<ip>" }));
        assert_eq!("341 <client> <nick> <channel>",
            format!("{}", RplInviting341{ client: "<client>", nick: "<nick>",
                channel: "<channel>" }));
        assert_eq!("346 <client> <channel> <mask>",
            format!("{}", RplInviteList346{ client: "<client>", channel: "<channel>",
                mask: "<mask>" }));
        assert_eq!("347 <client> <channel> :End of channel invite list",
            format!("{}", RplEndOfInviteList347{ client: "<client>",
                channel: "<channel>" }));
        assert_eq!("348 <client> <channel> <mask>",
            format!("{}", RplExceptList348{ client: "<client>", channel: "<channel>",
                mask: "<mask>" }));
        assert_eq!("349 <client> <channel> :End of channel exception list",
            format!("{}", RplEndOfExceptList349{ client: "<client>",
                channel: "<channel>" }));
        assert_eq!("351 <client> <version> <server> :<comments>",
            format!("{}", RplVersion351{ client: "<client>", version: "<version>",
                server: "<server>", comments: "<comments>" }));
        assert_eq!("353 <client> <symbol> <channel> :<prefix1><nick1> <nick2>",
            format!("{}", RplNameReply353{ client: "<client>", symbol: "<symbol>",
                channel: "<channel>", replies: &vec![
                    NameReplyStruct{ prefix: Some("<prefix1>"), nick: "<nick1>" },
                    NameReplyStruct{ prefix: None, nick: "<nick2>" }] }));
        assert_eq!("366 <client> <channel> :End of /NAMES list",
            format!("{}", RplEndOfNames366{ client: "<client>", channel: "<channel>" }));
        assert_eq!("367 <client> <channel> <mask> <who> 3894211355",
            format!("{}", RplBanList367{ client: "<client>", channel: "<channel>",
                mask: "<mask>", who: "<who>", set_ts: 3894211355 }));
        assert_eq!("368 <client> <channel> :End of channel ban list",
            format!("{}", RplEndOfBanList368{ client: "<client>", channel: "<channel>" }));
        assert_eq!("369 <client> <nick> :End of WHOWAS",
            format!("{}", RplEndOfWhoWas369{ client: "<client>", nick: "<nick>" }));
        assert_eq!("371 <client> :<info>",
            format!("{}", RplInfo371{ client: "<client>", info: "<info>" }));
        assert_eq!("374 <client> :End of INFO list",
            format!("{}", RplEndOfInfo374{ client: "<client>" }));
        assert_eq!("375 <client> :- <server> Message of the day - ",
            format!("{}", RplMotdStart375{ client: "<client>", server: "<server>" }));
        assert_eq!("372 <client> :<motd>",
            format!("{}", RplMotd372{ client: "<client>", motd: "<motd>" }));
        assert_eq!("376 <client> :End of /MOTD command.",
            format!("{}", RplEndOfMotd376{ client: "<client>" }));
        assert_eq!("378 <client> <nick> :is connecting from *@localhost 127.0.0.1",
            format!("{}", RplWhoIsHost378{ client: "<client>", nick: "<nick>",
                host_info: "*@localhost 127.0.0.1" }));
        assert_eq!("379 <client> <nick> :is using modes +ailosw",
            format!("{}", RplWhoIsModes379{ client: "<client>", nick: "<nick>",
                modes: "+ailosw" }));
        assert_eq!("381 <client> :You are now an IRC operator",
            format!("{}", RplYouReoper381{ client: "<client>" }));
        assert_eq!("382 <client> <config file> :Rehashing",
            format!("{}", RplRehashing382{ client: "<client>",
                config_file: "<config file>" }));
        assert_eq!("391 <client> <server> 485829211 <TS offset> :<human-readable time>",
            format!("{}", RplTime391{ client: "<client>", server: "<server>",
                timestamp: 485829211, ts_offset: "<TS offset>",
                human_readable: "<human-readable time>" }));
        assert_eq!("400 <client> <command> :<info>",
            format!("{}", ErrUnknownError400{ client: "<client>", command: "<command>",
                subcommand: None, info: "<info>" }));
        assert_eq!("400 <client> <command> <subcommand> :<info>",
            format!("{}", ErrUnknownError400{ client: "<client>", command: "<command>",
                subcommand: Some("<subcommand>"), info: "<info>" }));
        assert_eq!("401 <client> <nickname> :No such nick/channel",
            format!("{}", ErrNoSuchNick401{ client: "<client>", nick: "<nickname>" }));
        assert_eq!("402 <client> <server name> :No such server",
            format!("{}", ErrNoSuchServer402{ client: "<client>",
                server: "<server name>" }));
        assert_eq!("403 <client> <channel> :No such channel",
            format!("{}", ErrNoSuchChannel403{ client: "<client>", channel: "<channel>" }));
        assert_eq!("404 <client> <channel> :Cannot send to channel",
            format!("{}", ErrCannotSendToChain404{ client: "<client>",
                channel: "<channel>" }));
        assert_eq!("405 <client> <channel> :You have joined too many channels",
            format!("{}", ErrTooManyChannels405{ client: "<client>",
                channel: "<channel>" }));
        assert_eq!("409 <client> :No origin specified",
            format!("{}", ErrNoOrigin409{ client: "<client>" }));
        assert_eq!("417 <client> :Input line was too long",
            format!("{}", ErrInputTooLong417{ client: "<client>" }));
        assert_eq!("421 <client> <command> :Unknown command",
            format!("{}", ErrUnknownCommand421{ client: "<client>",
                command: "<command>" }));
        assert_eq!("422 <client> :MOTD File is missing",
            format!("{}", ErrNoMotd422{ client: "<client>" }));
        assert_eq!("432 <client> <nick> :Erroneus nickname",
            format!("{}", ErrErroneusNickname432{ client: "<client>", nick: "<nick>" }));
        assert_eq!("433 <client> <nick> :Nickname is already in use",
            format!("{}", ErrNicknameInUse433{ client: "<client>", nick: "<nick>" }));
        assert_eq!("441 <client> <nick> <channel> :They aren't on that channel",
            format!("{}", ErrUserNotInChannel441{ client: "<client>", nick: "<nick>",
                channel: "<channel>" }));
        assert_eq!("442 <client> <channel> :You're not on that channel",
            format!("{}", ErrNotOnChannel442{ client: "<client>", channel: "<channel>" }));
        assert_eq!("443 <client> <nick> <channel> :is already on channel",
            format!("{}", ErrUserOnChannel443{ client: "<client>", nick: "<nick>",
                channel: "<channel>" }));
        assert_eq!("451 <client> :You have not registered",
            format!("{}", ErrNotRegistered451{ client: "<client>" }));
        assert_eq!("461 <client> <command> :Not enough parameters",
            format!("{}", ErrNeedMoreParams461{ client: "<client>",command: "<command>" }));
        assert_eq!("462 <client> :You may not reregister",
            format!("{}", ErrAlreadyRegistered462{ client: "<client>" }));
        assert_eq!("464 <client> :Password incorrect",
            format!("{}", ErrPasswdMismatch464{ client: "<client>" }));
        assert_eq!("465 <client> :You are banned from this server.",
            format!("{}", ErrYoureBannedCreep465{ client: "<client>" }));
        assert_eq!("471 <client> <channel> :Cannot join channel (+l)",
            format!("{}", ErrChannelIsFull471{ client: "<client>", channel: "<channel>" }));
        assert_eq!("472 <client> x :is unknown mode char to me",
            format!("{}", ErrUnknownMode472{ client: "<client>", modechar: 'x' }));
        assert_eq!("473 <client> <channel> :Cannot join channel (+i)",
            format!("{}", ErrInviteOnlyChan473{ client: "<client>", channel: "<channel>" }));
        assert_eq!("474 <client> <channel> :Cannot join channel (+b)",
            format!("{}", ErrBannedFromChan474{ client: "<client>", channel: "<channel>" }));
        assert_eq!("475 <client> <channel> :Cannot join channel (+k)",
            format!("{}", ErrBadChannelKey475{ client: "<client>", channel: "<channel>" }));
        assert_eq!("476 <channel> :Bad Channel Mask",
            format!("{}", ErrBadChanMask476{ channel: "<channel>" }));
        assert_eq!("481 <client> :Permission Denied- You're not an IRC operator",
            format!("{}", ErrNoPrivileges481{ client: "<client>" }));
        assert_eq!("482 <client> <channel> :You're not channel operator",
            format!("{}", ErrChanOpPrivsNeeded482{ client: "<client>",
                channel: "<channel>" }));
        assert_eq!("483 <client> :You cant kill a server!",
            format!("{}", ErrCantKillServer483{ client: "<client>" }));
        assert_eq!("491 <client> :No O-lines for your host",
            format!("{}", ErrNoOperhost491{ client: "<client>" }));
        assert_eq!("501 <client> :Unknown MODE flag",
            format!("{}", ErrUmodeUnknownFlag501{ client: "<client>" }));
        assert_eq!("502 <client> :Cant change mode for other users",
            format!("{}", ErrUsersDontMatch502{ client: "<client>" }));
        assert_eq!("524 <client> <subject> :No help available on this topic",
            format!("{}", ErrHelpNotFound524{ client: "<client>", subject: "<subject>" }));
        assert_eq!("525 <client> <target chan> :Key is not well-formed",
            format!("{}", ErrInvalidKey525{ client: "<client>",
                target_chan: "<target chan>" }));
        assert_eq!("670 <client> :STARTTLS successful, proceed with TLS handshake",
            format!("{}", RplStartTls670{ client: "<client>" }));
        assert_eq!("671 <client> <nick> :is using a secure connection",
            format!("{}", RplWhoIsSecure671{ client: "<client>", nick: "<nick>" }));
        assert_eq!("691 <client> :STARTTLS failed (Wrong moon phase)",
            format!("{}", ErrStartTls691{ client: "<client>" }));
        assert_eq!("696 <client> <target chan/user> x <parameter> :<description>",
            format!("{}", ErrInvalidModeParam696{ client: "<client>",
                target: "<target chan/user>", modechar: 'x', param: "<parameter>",
                description: "<description>" }));
        assert_eq!("704 <client> <subject> :<first line of help section>",
            format!("{}", RplHelpStart704{ client: "<client>", subject: "<subject>",
                line: "<first line of help section>" }));
        assert_eq!("705 <client> <subject> :<line of help text>",
            format!("{}", RplHelpTxt705{ client: "<client>", subject: "<subject>",
                line: "<line of help text>" }));
        assert_eq!("706 <client> <subject> :<last line of help text>",
            format!("{}", RplEndOfHelp706{ client: "<client>", subject: "<subject>",
                line: "<last line of help text>" }));
        assert_eq!("723 <client> <priv> :Insufficient oper privileges.",
            format!("{}", ErrNoPrivs723{ client: "<client>", privil: "<priv>" }));
        assert_eq!("900 <client> <nick>!<user>@<host> <account> \
            :You are now logged in as <username>",
            format!("{}", RplLoggedIn900{ client: "<client>", nick: "<nick>",
                user: "<user>", host: "<host>", account: "<account>",
                username: "<username>" }));
        assert_eq!("901 <client> <nick>!<user>@<host> :You are now logged out",
            format!("{}", RplLoggedOut901{ client: "<client>", nick: "<nick>",
                user: "<user>", host: "<host>" }));
        assert_eq!("902 <client> :You must use a nick assigned to you",
            format!("{}", ErrNickLocked902{ client: "<client>" }));
        assert_eq!("903 <client> :SASL authentication successful",
            format!("{}", RplSaslSuccess903{ client: "<client>" }));
        assert_eq!("904 <client> :SASL authentication failed",
            format!("{}", ErrSaslFail904{ client: "<client>" }));
        assert_eq!("905 <client> :SASL message too long",
            format!("{}", ErrSaslTooLong905{ client: "<client>" }));
        assert_eq!("906 <client> :SASL authentication aborted",
            format!("{}", ErrSaslAborted906{ client: "<client>" }));
        assert_eq!("907 <client> :You have already authenticated using SASL",
            format!("{}", ErrSaslAlready907{ client: "<client>" }));
        assert_eq!("908 <client> <mechanisms> :are available SASL mechanisms",
            format!("{}", RplSaslMechs908{ client: "<client>",
                mechanisms: "<mechanisms>" }));
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let config = MainConfig::new(cli)?;
    println!("Hello, world!");
    Ok(())
}
