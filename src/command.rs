// command.rs - commands
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
use std::error::Error;
use const_table::const_table;

use crate::config::{validate_username, validate_channel};

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
    LINKSId = CommandName{ name: "LINKS" },
    HELPId = CommandName{ name: "HELP" },
    INFOId = CommandName{ name: "INFO" },
    MODEId = CommandName{ name: "MODE" },
    PRIVMSGId = CommandName{ name: "PRIVMSG" },
    NOTICEId = CommandName{ name: "NOTICE" },
    WHOId = CommandName{ name: "WHO" },
    WHOISId = CommandName{ name: "WHOIS" },
    WHOWASId = CommandName{ name: "WHOWAS" },
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
    WrongModeArguments(CommandId),
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
            WrongModeArguments(s) =>
                write!(f, "Wrong mode arguments in command '{}'", s.name),
        }
    }
}

impl Error for CommandError {
}

#[derive(PartialEq, Eq, Debug)]
enum CapCommand {
    LS, LIST, REQ, END
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
    LINKS{ remote_server: Option<&'a str>, server_mask: Option<&'a str> },
    HELP{ subject: &'a str },
    INFO{ },
    MODE{ target: &'a str, modes: Vec<(&'a str, Vec<&'a str>)> },
    PRIVMSG{ targets: Vec<&'a str>, text: &'a str },
    NOTICE{ targets: Vec<&'a str>, text: &'a str },
    WHO{ mask: &'a str },
    WHOIS{ target: Option<&'a str>, nickmasks: Vec<&'a str> },
    WHOWAS{ nickname: &'a str, count: Option<usize>, server: Option<&'a str> },
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

fn validate_usermodes<'a, E: Error>(modes: &Vec<(&'a str, Vec<&'a str>)>)
                -> Result<(), CommandError> {
    let mut param_idx = 1;
    modes.iter().try_for_each(|(ms, margs)| {
        if ms.len() != 0 {
            if ms.find(|c|
                c!='+' && c!='-' && c!='i' && c!='o' &&
                    c!='O' && c!='r' && c!='w').is_some() {
                Err(WrongParameter(MODEId, param_idx))
            } else if margs.len() != 0 {
                Err(WrongParameter(MODEId, param_idx))
            } else {
                param_idx += 1;
                Ok(())
            }
        } else { // if empty
            Err(WrongParameter(MODEId, param_idx))
        }
    })
}

fn validate_channelmodes<'a, E: Error>(modes: &Vec<(&'a str, Vec<&'a str>)>)
                -> Result<(), CommandError> {
    let mut param_idx = 1;
    modes.iter().try_for_each(|(ms, margs)| {
        if ms.len() != 0 {
            // check characters except last character
            let mut char_count = 0;
            let mut last_char = ' ';
            let mut chars_it = ms.chars();
            while let Some(c) = chars_it.next() {
                last_char = c;
                char_count += 1;
            }
            
            let mut mode_set = false;
            ms.chars().take(char_count-1).try_for_each(|c| {
                if c!='+' && c!='-' && c!='b' && c!='e' && c!='i' && c!='I' &&
                    c!='m' && c!='t' && c!='n' && c!='s' && c!='p' {
                    return Err(WrongParameter(MODEId, param_idx));
                }
                if (c=='k' || c=='l') && mode_set {
                    return Err(WrongParameter(MODEId, param_idx));
                }
                if c!='+' { mode_set = true; }
                else if c!='-' { mode_set = false; }
                Ok(())
            })?;
            param_idx += 1;
            
            if margs.len() != 0 {
                match last_char {
                    // operator, half-op, voice
                    'o'|'h'|'v' => {
                        if margs.len() == 1 && validate_username(margs[0]).is_ok() {
                            param_idx += 1;
                        } else {
                            return Err(WrongParameter(MODEId, param_idx));
                        }
                    }
                    // limit
                    'l' => {
                        if mode_set {
                            if margs.len() == 1 {
                                if margs[0].parse::<usize>().is_err() {
                                    return Err(WrongParameter(MODEId, param_idx));
                                }
                                param_idx += 1;
                            } else {
                                return Err(WrongParameter(MODEId, param_idx));
                            }
                        } else {
                            return Err(WrongParameter(MODEId, param_idx));
                        }
                    }
                    // key
                    'k' => {
                        if mode_set {
                            if margs.len() != 1 {
                                return Err(WrongParameter(MODEId, param_idx));
                            }
                            param_idx += 1;
                        } else {
                            return Err(WrongParameter(MODEId, param_idx));
                        }
                    }
                    // lists
                    'b'|'e'|'I' => { param_idx += margs.len(); }
                    _ => { return Err(WrongParameter(MODEId, param_idx)); }
                }
            } else {
                match last_char {
                    'l'|'k' => {
                        if mode_set { return Err(WrongParameter(MODEId, param_idx)); }
                    }
                    'b'|'e'|'i'|'I'|'m'|'t'|'n'|'s'|'p' => { }
                    _ => { return Err(WrongParameter(MODEId, param_idx)); }
                }
            }
            
            Ok(())
        } else { // if empty
            Err(WrongParameter(MODEId, param_idx))
        }
    })
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
                        "END" => CapCommand::END,
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
            "LINKS" => {
                if message.params.len() == 2 {
                    Ok(LINKS{ remote_server: Some(message.params[0]),
                        server_mask: Some(message.params[1]) })
                } else if message.params.len() == 1 {
                    Ok(LINKS{ remote_server: None,
                        server_mask: Some(message.params[0]) })
                } else {
                    Ok(LINKS{ remote_server: None, server_mask: None }) }
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
                    let mut modes = vec![];
                    let mut param_it = message.params.iter();
                    let target = param_it.next().unwrap();
                    if let Some(s) = param_it.next() {
                        if s.starts_with("+") || s.starts_with("-") {
                            
                            let mut modestring = *s;
                            let mut mode_args = vec![];
                            while let Some(s) = param_it.next() {
                                if s.starts_with("+") || s.starts_with("-") {
                                    modes.push((modestring, mode_args));
                                    modestring = *s;
                                    mode_args = vec![];
                                } else {
                                    mode_args.push(*s);
                                }
                            }
                            modes.push((modestring, mode_args));
                            
                        } else {
                            return Err(WrongParameter(MODEId, 1));
                        }
                    }
                    Ok(MODE{ target, modes })
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
                            nickmasks: message.params[1].split(',').collect::<Vec<_>>() })
                    } else {
                        Ok(WHOIS{ target: None, nickmasks:
                            message.params[0].split(',').collect::<Vec<_>>() })
                    }
                } else {
                    Err(NeedMoreParams(WHOISId)) }
            }
            "WHOWAS" => {
                if message.params.len() >= 1 {
                    let mut param_it = message.params.iter();
                    let nickname = param_it.next().unwrap();
                    let count = param_it.next().map(|x| x.parse()).transpose();
                    let server = param_it.next().map(|x| *x);
                    match count {
                        Err(_) => {
                            Err(WrongParameter(WHOWASId, 1))
                        }
                        Ok(c) => Ok(WHOWAS{ nickname, count: c, server })
                    }
                } else {
                    Err(NeedMoreParams(WHOWASId)) }
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
                    Ok(USERHOST{ nicknames: message.params.clone() })
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
                    .map_err(|_| WrongParameter(LISTId, 0))?;
                if let Some(srv) = server {
                    validate_server(srv, WrongParameter(LISTId, 1))?;
                }
                Ok(())
            }
            INVITE{ nickname, channel } => {
                validate_username(nickname)
                    .map_err(|_| WrongParameter(INVITEId, 0))?;
                validate_channel(channel)
                    .map_err(|_| WrongParameter(INVITEId, 1))
                }
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
            LINKS{ remote_server, server_mask } => {
                if let Some(s) = remote_server {
                    validate_server(s, WrongParameter(LINKSId, 0))?;
                    if let Some(sm) = server_mask {
                        validate_server_mask(sm, WrongParameter(LINKSId, 1))?;
                    }
                } else if let Some(sm) = server_mask {
                    validate_server_mask(sm, WrongParameter(LINKSId, 0))?;
                }
                Ok(())
            }
            MODE{ target, modes } => {
                /*if validate_channel(target).is_ok() {
                    validate_channelmodes(modestring, mode_args,
                        WrongParameter(MODEId, 1),
                        WrongModeArguments(MODEId))
                } else if validate_username(target).is_ok() {
                    validate_usermodes(modestring, mode_args,
                        WrongParameter(MODEId, 1))
                } else { Err(WrongParameter(MODEId, 0)) }*/
                Ok(())
            }
            PRIVMSG{ targets, text } => {
                targets.iter().try_for_each(|n| validate_username(n).or(
                    validate_channel(n)))
                    .map_err(|_| WrongParameter(PRIVMSGId, 0)) }
            NOTICE{ targets, text } => {
                targets.iter().try_for_each(|n| validate_username(n).or(
                    validate_channel(n)))
                    .map_err(|_| WrongParameter(NOTICEId, 0)) }
            //WHO{ mask } => { Ok(()) }
            WHOIS{ target, nickmasks } => {
                let next_param_idx = if let Some(t) = target {
                    validate_server(t, WrongParameter(WHOISId, 0))?;
                    1
                } else { 0 };
                nickmasks.iter().try_for_each(|n| validate_username(n))
                    .map_err(|_| WrongParameter(WHOISId, next_param_idx))
            }
            WHOWAS{ nickname, count, server } => {
                validate_username(nickname).map_err(|_| WrongParameter(WHOWASId, 0))?;
                if let Some(s) = server {
                    validate_server(s, WrongParameter(WHOWASId, 2))?;
                }
                Ok(())
            }
            KILL{ nickname, comment } => {
                validate_username(nickname)
                    .map_err(|_| WrongParameter(KILLId, 0)) }
            SQUIT{ server, comment } => {
                validate_server(server, WrongParameter(SQUITId, 0))?;
                Ok(())
            }
            USERHOST{ nicknames } => {
                nicknames.iter().enumerate().try_for_each(|(i,n)| validate_username(n)
                            .map_err(|_| WrongParameter(USERHOSTId, i)))
            }
            _ => Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    
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
        assert_eq!(Ok(CAP{ subcommand: CapCommand::END, caps: None, version: None }),
            Command::from_message(&Message{ source: None, command: "CAP",
                params: vec![ "END" ] }).map_err(|e| e.to_string()));
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
        
        assert_eq!(Ok(JOIN{ channels: vec![ "#cats", "&fruits", "#software" ],
                        keys: None }),
            Command::from_message(&Message{ source: None, command: "JOIN",
                params: vec![ "#cats,&fruits,#software" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(JOIN{ channels: vec![ "#cats", "&fruits", "#software" ],
                    keys: Some(vec![ "mycat", "apple", "wesnoth" ]) }),
            Command::from_message(&Message{ source: None, command: "JOIN",
                params: vec![ "#cats,&fruits,#software", "mycat,apple,wesnoth" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'JOIN'".to_string()),
            Command::from_message(&Message{ source: None, command: "JOIN",
                params: vec![ "#cats,&fru:its,#software" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'JOIN'".to_string()),
            Command::from_message(&Message{ source: None, command: "JOIN",
                params: vec![ "#cats,fruits,#software" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(JOIN{ channels: vec![ "#cats", "&fru.its", "#software" ],
                        keys: None }),
            Command::from_message(&Message{ source: None, command: "JOIN",
                params: vec![ "#cats,&fru.its,#software" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Parameter 1 doesn't match for command 'JOIN'".to_string()),
            Command::from_message(&Message{ source: None, command: "JOIN",
                params: vec![ "#cats,&fruits,#software,#countries",
                    "mycat,apple,wesnoth" ] }) .map_err(|e| e.to_string()));
        assert_eq!(Err("Parameter 1 doesn't match for command 'JOIN'".to_string()),
            Command::from_message(&Message{ source: None, command: "JOIN",
                params: vec![ "#cats,&fruits,#software",
                    "mycat,apple,wesnoth,zizi" ] }) .map_err(|e| e.to_string()));
        assert_eq!(Err("Command 'JOIN' needs more parameters".to_string()),
            Command::from_message(&Message{ source: None, command: "JOIN",
                params: vec![] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(PART{ channels: vec![ "#dogs", "&juices", "#hardware" ],
                        reason: None }),
            Command::from_message(&Message{ source: None, command: "PART",
                params: vec![ "#dogs,&juices,#hardware" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(PART{ channels: vec![ "#dogs", "&juices", "#hardware" ],
                        reason: Some("I don't like these channels") }),
            Command::from_message(&Message{ source: None, command: "PART",
                params: vec![ "#dogs,&juices,#hardware",
                    "I don't like these channels" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'PART'".to_string()),
            Command::from_message(&Message{ source: None, command: "PART",
                params: vec![ "#dogs,&juices,#har:dware",
                    "I don't like these channels" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Command 'PART' needs more parameters".to_string()),
            Command::from_message(&Message{ source: None, command: "PART",
                params: vec![] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(TOPIC{ channel: "#gizmo", topic: None }),
            Command::from_message(&Message{ source: None, command: "TOPIC",
                params: vec![ "#gizmo" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(TOPIC{ channel: "#gizmo", topic: Some("Some creatures") }),
            Command::from_message(&Message{ source: None, command: "TOPIC",
                params: vec![ "#gizmo", "Some creatures" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'TOPIC'".to_string()),
            Command::from_message(&Message{ source: None, command: "TOPIC",
                params: vec![ "#giz:mo" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Command 'TOPIC' needs more parameters".to_string()),
            Command::from_message(&Message{ source: None, command: "TOPIC",
                params: vec![] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(NAMES{ channels: vec![ "#dogs", "&juices", "#hardware" ] }),
            Command::from_message(&Message{ source: None, command: "NAMES",
                params: vec![ "#dogs,&juices,#hardware" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'NAMES'".to_string()),
            Command::from_message(&Message{ source: None, command: "NAMES",
                params: vec![ "#dogs,&juices,#hard:ware" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Command 'NAMES' needs more parameters".to_string()),
            Command::from_message(&Message{ source: None, command: "NAMES",
                params: vec![] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(LIST{ channels: vec![ "#dogs", "&juices", "#hardware" ],
                        server: None }),
            Command::from_message(&Message{ source: None, command: "LIST",
                params: vec![ "#dogs,&juices,#hardware" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(LIST{ channels: vec![ "#dogs", "&juices", "#hardware" ],
                        server: Some("funny.checkbox.org") }),
            Command::from_message(&Message{ source: None, command: "LIST",
                params: vec![ "#dogs,&juices,#hardware",
                    "funny.checkbox.org" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'LIST'".to_string()),
            Command::from_message(&Message{ source: None, command: "LIST",
                params: vec![ "#dogs,&juices,#har:dware",
                    "funny.checkbox.org" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 1 in command 'LIST'".to_string()),
            Command::from_message(&Message{ source: None, command: "LIST",
                params: vec![ "#dogs,&juices,#hardware",
                    "fnny" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Command 'LIST' needs more parameters".to_string()),
            Command::from_message(&Message{ source: None, command: "LIST",
                params: vec![] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(INVITE{ nickname: "greg", channel: "#plants" }),
            Command::from_message(&Message{ source: None, command: "INVITE",
                params: vec![ "greg", "#plants" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'INVITE'".to_string()),
            Command::from_message(&Message{ source: None, command: "INVITE",
                params: vec![ "gr:eg", "#plants" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 1 in command 'INVITE'".to_string()),
            Command::from_message(&Message{ source: None, command: "INVITE",
                params: vec![ "greg", "_plants" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Command 'INVITE' needs more parameters".to_string()),
            Command::from_message(&Message{ source: None, command: "INVITE",
                params: vec![ "greg" ] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(KICK{ channel: "#toolkits", user: "mickey", comment: None }),
            Command::from_message(&Message{ source: None, command: "KICK",
                params: vec![ "#toolkits", "mickey" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(KICK{ channel: "#toolkits", user: "mickey",
                comment: Some("Mickey is not polite") }),
            Command::from_message(&Message{ source: None, command: "KICK",
                params: vec![ "#toolkits", "mickey", "Mickey is not polite" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'KICK'".to_string()),
            Command::from_message(&Message{ source: None, command: "KICK",
                params: vec![ "@toolkits", "mickey" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 1 in command 'KICK'".to_string()),
            Command::from_message(&Message{ source: None, command: "KICK",
                params: vec![ "#toolkits", "mic:key" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Command 'KICK' needs more parameters".to_string()),
            Command::from_message(&Message{ source: None, command: "KICK",
                params: vec![ "#toolkits" ] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(MOTD{ target: None }),
            Command::from_message(&Message{ source: None, command: "MOTD",
                params: vec![] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(MOTD{ target: Some("bubu.com") }),
            Command::from_message(&Message{ source: None, command: "MOTD",
                params: vec![ "bubu.com" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(MOTD{ target: Some("*com") }),
            Command::from_message(&Message{ source: None, command: "MOTD",
                params: vec![ "*com" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'MOTD'".to_string()),
            Command::from_message(&Message{ source: None, command: "MOTD",
                params: vec![ "bubucom" ] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(VERSION{ target: None }),
            Command::from_message(&Message{ source: None, command: "VERSION",
                params: vec![] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(VERSION{ target: Some("bubu.com") }),
            Command::from_message(&Message{ source: None, command: "VERSION",
                params: vec![ "bubu.com" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(VERSION{ target: Some("*com") }),
            Command::from_message(&Message{ source: None, command: "VERSION",
                params: vec![ "*com" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'VERSION'".to_string()),
            Command::from_message(&Message{ source: None, command: "VERSION",
                params: vec![ "bubucom" ] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(ADMIN{ target: None }),
            Command::from_message(&Message{ source: None, command: "ADMIN",
                params: vec![] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(ADMIN{ target: Some("bubu.com") }),
            Command::from_message(&Message{ source: None, command: "ADMIN",
                params: vec![ "bubu.com" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(ADMIN{ target: Some("*com") }),
            Command::from_message(&Message{ source: None, command: "ADMIN",
                params: vec![ "*com" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'ADMIN'".to_string()),
            Command::from_message(&Message{ source: None, command: "ADMIN",
                params: vec![ "bubucom" ] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(CONNECT{ target_server: "chat.purple.com", port: None,
            remote_server: None }),
            Command::from_message(&Message{ source: None, command: "CONNECT",
                params: vec![ "chat.purple.com" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(CONNECT{ target_server: "chat.purple.com", port: Some(6670),
            remote_server: None }),
            Command::from_message(&Message{ source: None, command: "CONNECT",
                params: vec![ "chat.purple.com", "6670" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(CONNECT{ target_server: "chat.purple.com", port: Some(6670),
            remote_server: Some("chat.broker.com") }),
            Command::from_message(&Message{ source: None, command: "CONNECT",
                params: vec![ "chat.purple.com", "6670", "chat.broker.com" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'CONNECT'".to_string()),
            Command::from_message(&Message{ source: None, command: "CONNECT",
                params: vec![ "chatpurplecom" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 1 in command 'CONNECT'".to_string()),
            Command::from_message(&Message{ source: None, command: "CONNECT",
                params: vec![ "chat.purple.com", "xxxaa" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 1 in command 'CONNECT'".to_string()),
            Command::from_message(&Message{ source: None, command: "CONNECT",
                params: vec![ "chat.purple.com", "6670", "chatbrokercom" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Err("Command 'CONNECT' needs more parameters".to_string()),
            Command::from_message(&Message{ source: None, command: "CONNECT",
                params: vec![] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(LUSERS{}),
            Command::from_message(&Message{ source: None, command: "LUSERS",
                params: vec![] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(TIME{ server: None }),
            Command::from_message(&Message{ source: None, command: "TIME",
                params: vec![] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(TIME{ server: Some("bubu.com") }),
            Command::from_message(&Message{ source: None, command: "TIME",
                params: vec![ "bubu.com" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'TIME'".to_string()),
            Command::from_message(&Message{ source: None, command: "TIME",
                params: vec![ "*com" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'TIME'".to_string()),
            Command::from_message(&Message{ source: None, command: "TIME",
                params: vec![ "bubucom" ] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(STATS{ query: 'c', server: None }),
            Command::from_message(&Message{ source: None, command: "STATS",
                params: vec![ "c" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(STATS{ query: 'l', server: None }),
            Command::from_message(&Message{ source: None, command: "STATS",
                params: vec![ "l" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(STATS{ query: 'o', server: None }),
            Command::from_message(&Message{ source: None, command: "STATS",
                params: vec![ "o" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(STATS{ query: 'o', server: Some("chat.fruits.com") }),
            Command::from_message(&Message{ source: None, command: "STATS",
                params: vec![ "o", "chat.fruits.com" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'STATS'".to_string()),
            Command::from_message(&Message{ source: None, command: "STATS",
                params: vec![ "z" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 1 in command 'STATS'".to_string()),
            Command::from_message(&Message{ source: None, command: "STATS",
                params: vec![ "o", "chatfruitscom" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Command 'STATS' needs more parameters".to_string()),
            Command::from_message(&Message{ source: None, command: "STATS",
                params: vec![] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(LINKS{ remote_server: None, server_mask: Some("*.gigo.net") }),
            Command::from_message(&Message{ source: None, command: "LINKS",
                params: vec![ "*.gigo.net" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(LINKS{ remote_server: Some("first.proxy.net"),
                server_mask: Some("*.gigo.net") }),
            Command::from_message(&Message{ source: None, command: "LINKS",
                params: vec![ "first.proxy.net", "*.gigo.net" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'LINKS'".to_string()),
            Command::from_message(&Message{ source: None, command: "LINKS",
                params: vec![ "gigonet" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 1 in command 'LINKS'".to_string()),
            Command::from_message(&Message{ source: None, command: "LINKS",
                params: vec![ "first.proxy.net", "gigonet" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'LINKS'".to_string()),
            Command::from_message(&Message{ source: None, command: "LINKS",
                params: vec![ "firstproxynet", "*.gigo.net" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Ok(LINKS{ remote_server: None, server_mask: None }),
            Command::from_message(&Message{ source: None, command: "LINKS",
                params: vec![] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(HELP{ subject: "PING Message" }),
            Command::from_message(&Message{ source: None, command: "HELP",
                params: vec![ "PING Message" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Command 'HELP' needs more parameters".to_string()),
            Command::from_message(&Message{ source: None, command: "HELP",
                params: vec![] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(INFO{}),
            Command::from_message(&Message{ source: None, command: "INFO",
                params: vec![] }).map_err(|e| e.to_string()));
        
        /*assert_eq!(Ok(MODE{ target: "andy", modestring: Some("+ow"),
            mode_args: Some(vec![]) }),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "andy", "+ow" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(MODE{ target: "andy", modestring: Some("+oOr-iw"),
            mode_args: Some(vec![]) }),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "andy", "+oOr-iw" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 1 in command 'MODE'".to_string()),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "teddy", "+otOr" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(MODE{ target: "#chasis", modestring: Some("+ntpsm"),
            mode_args: Some(vec![]) }),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "#chasis", "+ntpsm" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(MODE{ target: "#chasis", modestring: Some("+b"),
            mode_args: Some(vec![ "*@192.168.1.7", "*.fixers.com" ]) }),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "#chasis", "+b", "*@192.168.1.7", "*.fixers.com" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Ok(MODE{ target: "#chasis", modestring: Some("-b"),
            mode_args: Some(vec![ "*@192.168.1.3", "*.fixers.com" ]) }),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "#chasis", "-b", "*@192.168.1.3", "*.fixers.com" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Ok(MODE{ target: "#chasis", modestring: Some("+e"),
            mode_args: Some(vec![ "*@192.168.1.7", "*.fixers.com" ]) }),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "#chasis", "+e", "*@192.168.1.7", "*.fixers.com" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Ok(MODE{ target: "#chasis", modestring: Some("-e"),
            mode_args: Some(vec![ "*@192.168.1.3", "*.fixers.com" ]) }),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "#chasis", "-e", "*@192.168.1.3", "*.fixers.com" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Ok(MODE{ target: "#chasis", modestring: Some("+I"),
            mode_args: Some(vec![ "*@192.168.1.7", "*.fixers.com" ]) }),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "#chasis", "+I", "*@192.168.1.7", "*.fixers.com" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Ok(MODE{ target: "#chasis", modestring: Some("-I"),
            mode_args: Some(vec![ "*@192.168.1.3", "*.fixers.com" ]) }),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "#chasis", "-I", "*@192.168.1.3", "*.fixers.com" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Ok(MODE{ target: "#chasis", modestring: Some("+b"),
            mode_args: Some(vec![]) }),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "#chasis", "+b" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Ok(MODE{ target: "#chasis", modestring: Some("+l"),
            mode_args: Some(vec![ "123" ]) }),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "#chasis", "+l", "123" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Ok(MODE{ target: "#chasis", modestring: Some("-l"),
            mode_args: Some(vec![]) }),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "#chasis", "-l" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Ok(MODE{ target: "#chasis", modestring: Some("+k"),
            mode_args: Some(vec![ "secretpassword" ]) }),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "#chasis", "+k", "secretpassword" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Ok(MODE{ target: "#chasis", modestring: Some("-k"),
            mode_args: Some(vec![]) }),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "#chasis", "-k" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Ok(MODE{ target: "#chasis", modestring: Some("-bl+i"),
            mode_args: Some(vec![ "*@192.168.0.1" ]) }),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "#chasis", "-bl+i", "*@192.168.0.1" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Ok(MODE{ target: "#chasis", modestring: Some("+o"),
            mode_args: Some(vec![ "barry" ]) }),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "#chasis", "+o", "barry" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Ok(MODE{ target: "#chasis", modestring: Some("-o"),
            mode_args: Some(vec![ "barry" ]) }),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "#chasis", "-o", "barry" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Ok(MODE{ target: "#chasis", modestring: Some("+v"),
            mode_args: Some(vec![ "burry" ]) }),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "#chasis", "+v", "burry" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Ok(MODE{ target: "#chasis", modestring: Some("-v"),
            mode_args: Some(vec![ "burry" ]) }),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "#chasis", "-v", "burry" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Ok(MODE{ target: "andy", modestring: None, mode_args: None }),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "andy" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong mode arguments in command 'MODE'".to_string()),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "#chasis", "+l" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong mode arguments in command 'MODE'".to_string()),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "#chasis", "+k" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong mode arguments in command 'MODE'".to_string()),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "#chasis", "+o" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong mode arguments in command 'MODE'".to_string()),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "#chasis", "-o" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong mode arguments in command 'MODE'".to_string()),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "#chasis", "+v" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong mode arguments in command 'MODE'".to_string()),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![ "#chasis", "-v" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Command 'MODE' needs more parameters".to_string()),
            Command::from_message(&Message{ source: None, command: "MODE",
                params: vec![] }).map_err(|e| e.to_string()));*/
        
        assert_eq!(Ok(PRIVMSG{ targets: vec![ "bobby", "andy" ], text: "Hello, guys" }),
            Command::from_message(&Message{ source: None, command: "PRIVMSG",
                params: vec![ "bobby,andy" , "Hello, guys" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Ok(PRIVMSG{ targets: vec![ "#graphics", "&musics" ],
                text: "Hello, guys" }),
            Command::from_message(&Message{ source: None, command: "PRIVMSG",
                params: vec![ "#graphics,&musics" , "Hello, guys" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Ok(PRIVMSG{ targets: vec![ "#graphics", "&musics", "jimmy" ],
                text: "Hello, cruel world!" }),
            Command::from_message(&Message{ source: None, command: "PRIVMSG",
                params: vec![ "#graphics,&musics,jimmy" , "Hello, cruel world!" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'PRIVMSG'".to_string()),
            Command::from_message(&Message{ source: None, command: "PRIVMSG",
                params: vec![ "#graphics,&musics,ji.mmy", "Hello, cruel world!" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Err("Command 'PRIVMSG' needs more parameters".to_string()),
            Command::from_message(&Message{ source: None, command: "PRIVMSG",
                params: vec![ "#graphics,&musics,jimmy" ] })
                    .map_err(|e| e.to_string()));
        
        assert_eq!(Ok(NOTICE{ targets: vec![ "bobby", "andy" ], text: "Hello, guys" }),
            Command::from_message(&Message{ source: None, command: "NOTICE",
                params: vec![ "bobby,andy" , "Hello, guys" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Ok(NOTICE{ targets: vec![ "#graphics", "&musics" ],
                text: "Hello, guys" }),
            Command::from_message(&Message{ source: None, command: "NOTICE",
                params: vec![ "#graphics,&musics" , "Hello, guys" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Ok(NOTICE{ targets: vec![ "#graphics", "&musics", "jimmy" ],
                text: "Hello, cruel world!" }),
            Command::from_message(&Message{ source: None, command: "NOTICE",
                params: vec![ "#graphics,&musics,jimmy" , "Hello, cruel world!" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'NOTICE'".to_string()),
            Command::from_message(&Message{ source: None, command: "NOTICE",
                params: vec![ "#graphics,&musics,ji.mmy", "Hello, cruel world!" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Err("Command 'NOTICE' needs more parameters".to_string()),
            Command::from_message(&Message{ source: None, command: "NOTICE",
                params: vec![ "#graphics,&musics,jimmy" ] })
                    .map_err(|e| e.to_string()));
        
        assert_eq!(Ok(WHO{ mask: "bla*bla" }),
            Command::from_message(&Message{ source: None, command: "WHO",
                params: vec![ "bla*bla" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Command 'WHO' needs more parameters".to_string()),
            Command::from_message(&Message{ source: None, command: "WHO",
                params: vec![] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(WHOIS{ target: None, nickmasks: vec![ "alice", "eliz", "garry" ] }),
            Command::from_message(&Message{ source: None, command: "WHOIS",
                params: vec![ "alice,eliz,garry" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(WHOIS{ target: Some("coco.net"),
                nickmasks: vec![ "alice", "eliz", "garry" ] }),
            Command::from_message(&Message{ source: None, command: "WHOIS",
                params: vec![ "coco.net", "alice,eliz,garry" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'WHOIS'".to_string()),
            Command::from_message(&Message{ source: None, command: "WHOIS",
                params: vec![ "alice,el:iz,garry" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'WHOIS'".to_string()),
            Command::from_message(&Message{ source: None, command: "WHOIS",
                params: vec![ "coconet", "alice,eliz,garry" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 1 in command 'WHOIS'".to_string()),
            Command::from_message(&Message{ source: None, command: "WHOIS",
                params: vec![ "coco.net", "alice,eliz,ga:rry" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Err("Command 'WHOIS' needs more parameters".to_string()),
            Command::from_message(&Message{ source: None, command: "WHOIS",
                params: vec![] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(WHOWAS{ nickname: "mat", count: None, server: None }),
            Command::from_message(&Message{ source: None, command: "WHOWAS",
                params: vec![ "mat" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(WHOWAS{ nickname: "mat", count: Some(10), server: None }),
            Command::from_message(&Message{ source: None, command: "WHOWAS",
                params: vec![ "mat", "10" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(WHOWAS{ nickname: "mat", count: Some(10),
                server: Some("some.where.net") }),
            Command::from_message(&Message{ source: None, command: "WHOWAS",
                params: vec![ "mat", "10", "some.where.net" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'WHOWAS'".to_string()),
            Command::from_message(&Message{ source: None, command: "WHOWAS",
                params: vec![ "mat:" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 1 in command 'WHOWAS'".to_string()),
            Command::from_message(&Message{ source: None, command: "WHOWAS",
                params: vec![ "mat", "XX" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 2 in command 'WHOWAS'".to_string()),
            Command::from_message(&Message{ source: None, command: "WHOWAS",
                params: vec![ "mat", "10", "somewherenet" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Err("Command 'WHOWAS' needs more parameters".to_string()),
            Command::from_message(&Message{ source: None, command: "WHOWAS",
                params: vec![] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(KILL{ nickname: "bobby", comment: "Killed!" }),
            Command::from_message(&Message{ source: None, command: "KILL",
                params: vec![ "bobby", "Killed!" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'KILL'".to_string()),
            Command::from_message(&Message{ source: None, command: "KILL",
                params: vec![ "bob:by", "Killed!" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Command 'KILL' needs more parameters".to_string()),
            Command::from_message(&Message{ source: None, command: "KILL",
                params: vec![ "bobby" ] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(REHASH{}),
            Command::from_message(&Message{ source: None, command: "REHASH",
                params: vec![] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(RESTART{}),
            Command::from_message(&Message{ source: None, command: "RESTART",
                params: vec![] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(SQUIT{ server: "somewhere.dot.com", comment: "Killed!" }),
            Command::from_message(&Message{ source: None, command: "SQUIT",
                params: vec![ "somewhere.dot.com", "Killed!" ] })
                    .map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'SQUIT'".to_string()),
            Command::from_message(&Message{ source: None, command: "SQUIT",
                params: vec![ "bobxxx", "Killed!" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Command 'SQUIT' needs more parameters".to_string()),
            Command::from_message(&Message{ source: None, command: "SQUIT",
                params: vec![ "somewhere.dot.com" ] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(AWAY{ text: None }),
            Command::from_message(&Message{ source: None, command: "AWAY",
                params: vec![] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(AWAY{ text: Some("I will make rest") }),
            Command::from_message(&Message{ source: None, command: "AWAY",
                params: vec![ "I will make rest" ] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(USERHOST{ nicknames: vec![ "bobby" ] }),
            Command::from_message(&Message{ source: None, command: "USERHOST",
                params: vec![ "bobby" ] }).map_err(|e| e.to_string()));
        assert_eq!(Ok(USERHOST{ nicknames: vec![ "bobby", "jimmy" ] }),
            Command::from_message(&Message{ source: None, command: "USERHOST",
                params: vec![ "bobby", "jimmy" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 0 in command 'USERHOST'".to_string()),
            Command::from_message(&Message{ source: None, command: "USERHOST",
                params: vec![ "bo:bby", "jimmy" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 1 in command 'USERHOST'".to_string()),
            Command::from_message(&Message{ source: None, command: "USERHOST",
                params: vec![ "bobby", "ji:mmy" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 2 in command 'USERHOST'".to_string()),
            Command::from_message(&Message{ source: None, command: "USERHOST",
                params: vec![ "bobby", "damon", "ji:mmy" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Command 'USERHOST' needs more parameters".to_string()),
            Command::from_message(&Message{ source: None, command: "USERHOST",
                params: vec![] }).map_err(|e| e.to_string()));
        
        assert_eq!(Ok(WALLOPS{ text: "This is some message" }),
            Command::from_message(&Message{ source: None, command: "WALLOPS",
                params: vec![ "This is some message" ] }).map_err(|e| e.to_string()));
        assert_eq!(Err("Command 'WALLOPS' needs more parameters".to_string()),
            Command::from_message(&Message{ source: None, command: "WALLOPS",
                params: vec![] }).map_err(|e| e.to_string()));
    }
}
