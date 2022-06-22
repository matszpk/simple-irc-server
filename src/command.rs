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

use const_table::const_table;
use std::error::Error;
use std::fmt;

use crate::utils::*;

#[derive(Clone, Copy, Debug)]
pub(crate) enum MessageError {
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

impl Error for MessageError {}

#[derive(PartialEq, Eq, Debug)]
pub(crate) struct Message<'a> {
    source: Option<&'a str>,
    command: &'a str,
    params: Vec<&'a str>,
}

impl<'a> Message<'a> {
    pub(crate) fn from_shared_str(input: &'a str) -> Result<Self, MessageError> {
        let trimmed = input.trim_start();

        if !trimmed.is_empty() {
            // start_pos after ':' if exists - to skip ':' before source
            let start_pos = if trimmed.bytes().next() == Some(b':') {
                1
            } else {
                0
            };
            let (rest, last_param) = if let Some((rest, lp)) = trimmed[start_pos..].split_once(':')
            {
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
                Some(s) // return source
            } else {
                None
            };
            // get command name
            let command = if let Some(cmd) = rest_words.next() {
                cmd
            } else {
                return Err(MessageError::NoCommand);
            };

            // get command's parameters
            let mut params = rest_words.collect::<Vec<_>>();
            if let Some(lp) = last_param {
                params.push(lp); // add last parameter
            }

            Ok(Message {
                source,
                command,
                params,
            })
        } else {
            Err(MessageError::Empty)
        }
    }

    // convert message to string with custom source.
    pub(crate) fn to_string_with_source(&self, source: &str) -> String {
        let mut out = ":".to_string();
        out += source;
        out.push(' ');
        out += self.command;
        if !self.params.is_empty() {
            // join with other and join parameters together except last parameter
            self.params[..self.params.len() - 1].iter().for_each(|s| {
                out.push(' ');
                out += s;
            });
            let last = self.params[self.params.len() - 1];
            // if last parameter have ':', spaces then add it as last (:last param).
            if last.find(|c| c == ':' || c == ' ' || c == '\t').is_some() || last.is_empty() {
                out += " :";
            } else {
                out.push(' ');
            }
            out += last;
        }
        out
    }
}

// Needed command ids for command error.
#[allow(clippy::enum_variant_names)]
#[const_table]
pub(crate) enum CommandId {
    CommandName {
        pub(crate) name: &'static str,
    },
    CAPId = CommandName { name: "CAP" },
    _AUTHENTICATEId = CommandName {
        name: "AUTHENTICATE",
    },
    PASSId = CommandName { name: "PASS" },
    NICKId = CommandName { name: "NICK" },
    USERId = CommandName { name: "USER" },
    PINGId = CommandName { name: "PING" },
    PONGId = CommandName { name: "PONG" },
    OPERId = CommandName { name: "OPER" },
    _QUITId = CommandName { name: "QUIT" },
    JOINId = CommandName { name: "JOIN" },
    PARTId = CommandName { name: "PART" },
    TOPICId = CommandName { name: "TOPIC" },
    NAMESId = CommandName { name: "NAMES" },
    LISTId = CommandName { name: "LIST" },
    INVITEId = CommandName { name: "INVITE" },
    KICKId = CommandName { name: "KICK" },
    MOTDId = CommandName { name: "MOTD" },
    VERSIONId = CommandName { name: "VERSION" },
    ADMINId = CommandName { name: "ADMIN" },
    CONNECTId = CommandName { name: "CONNECT" },
    _LUSERSId = CommandName { name: "LUSERS" },
    TIMEId = CommandName { name: "TIME" },
    STATSId = CommandName { name: "STATS" },
    LINKSId = CommandName { name: "LINKS" },
    _HELPId = CommandName { name: "HELP" },
    _INFOId = CommandName { name: "INFO" },
    MODEId = CommandName { name: "MODE" },
    PRIVMSGId = CommandName { name: "PRIVMSG" },
    NOTICEId = CommandName { name: "NOTICE" },
    WHOId = CommandName { name: "WHO" },
    WHOISId = CommandName { name: "WHOIS" },
    WHOWASId = CommandName { name: "WHOWAS" },
    KILLId = CommandName { name: "KILL" },
    _REHASHId = CommandName { name: "REHASH" },
    _RESTARTId = CommandName { name: "RESTART" },
    SQUITId = CommandName { name: "SQUIT" },
    _AWAYId = CommandName { name: "AWAY" },
    USERHOSTId = CommandName { name: "USERHOST" },
    WALLOPSId = CommandName { name: "WALLOPS" },
    ISONId = CommandName { name: "ISON" },
    _DIEId = CommandName { name: "DIE" },
}

use CommandId::*;

#[derive(Clone, Debug)]
pub(crate) enum CommandError {
    UnknownCommand(String),
    UnknownSubcommand(CommandId, String),
    NeedMoreParams(CommandId),
    ParameterDoesntMatch(CommandId, usize),
    WrongParameter(CommandId, usize),
    UnknownMode(usize, char, String),
    UnknownUModeFlag(usize),
    InvalidModeParam {
        target: String,
        modechar: char,
        param: String,
        description: String,
    },
}

use CommandError::*;

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnknownCommand(s) => write!(f, "Unknown command '{}'", s),
            UnknownSubcommand(cmd, scmd) => {
                write!(f, "Unknown subcommand '{}' in command '{}'", scmd, cmd.name)
            }
            NeedMoreParams(s) => write!(f, "Command '{}' needs more parameters", s.name),
            ParameterDoesntMatch(s, i) => {
                write!(f, "Parameter {} doesn't match for command '{}'", i, s.name)
            }
            WrongParameter(s, i) => write!(f, "Wrong parameter {} in command '{}'", i, s.name),
            UnknownMode(i, c, ch) => write!(f, "Unknown mode {} in parameter {} for {}", c, i, ch),
            UnknownUModeFlag(i) => write!(f, "Unknown umode flag in parameter {}", i),
            InvalidModeParam {
                modechar,
                param,
                target,
                description,
            } => write!(
                f,
                "Invalid mode parameter: {} {} {} {}",
                target, modechar, param, description
            ),
        }
    }
}

impl Error for CommandError {}

#[allow(clippy::upper_case_acronyms)]
#[derive(PartialEq, Eq, Debug)]
pub(crate) enum CapCommand {
    LS,
    LIST,
    REQ,
    END,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(PartialEq, Eq, Debug)]
pub(crate) enum Command<'a> {
    CAP {
        subcommand: CapCommand,
        caps: Option<Vec<&'a str>>,
        version: Option<u32>,
    },
    AUTHENTICATE {},
    PASS {
        password: &'a str,
    },
    NICK {
        nickname: &'a str,
    },
    USER {
        username: &'a str,
        hostname: &'a str,
        servername: &'a str,
        realname: &'a str,
    },
    PING {
        token: &'a str,
    },
    PONG {
        token: &'a str,
    },
    OPER {
        name: &'a str,
        password: &'a str,
    },
    QUIT {},
    JOIN {
        channels: Vec<&'a str>,
        keys: Option<Vec<&'a str>>,
    },
    PART {
        channels: Vec<&'a str>,
        reason: Option<&'a str>,
    },
    TOPIC {
        channel: &'a str,
        topic: Option<&'a str>,
    },
    NAMES {
        channels: Vec<&'a str>,
    },
    LIST {
        channels: Vec<&'a str>,
        server: Option<&'a str>,
    },
    INVITE {
        nickname: &'a str,
        channel: &'a str,
    },
    KICK {
        channel: &'a str,
        users: Vec<&'a str>,
        comment: Option<&'a str>,
    },
    MOTD {
        target: Option<&'a str>,
    },
    VERSION {
        target: Option<&'a str>,
    },
    ADMIN {
        target: Option<&'a str>,
    },
    CONNECT {
        target_server: &'a str,
        port: Option<u16>,
        remote_server: Option<&'a str>,
    },
    LUSERS {},
    TIME {
        server: Option<&'a str>,
    },
    STATS {
        query: char,
        server: Option<&'a str>,
    },
    LINKS {
        remote_server: Option<&'a str>,
        server_mask: Option<&'a str>,
    },
    HELP {
        subject: Option<&'a str>,
    },
    INFO {},
    MODE {
        target: &'a str,
        modes: Vec<(&'a str, Vec<&'a str>)>,
    },
    PRIVMSG {
        targets: Vec<&'a str>,
        text: &'a str,
    },
    NOTICE {
        targets: Vec<&'a str>,
        text: &'a str,
    },
    WHO {
        mask: &'a str,
    },
    WHOIS {
        target: Option<&'a str>,
        nickmasks: Vec<&'a str>,
    },
    WHOWAS {
        nickname: &'a str,
        count: Option<usize>,
        server: Option<&'a str>,
    },
    KILL {
        nickname: &'a str,
        comment: &'a str,
    },
    REHASH {},
    RESTART {},
    SQUIT {
        server: &'a str,
        comment: &'a str,
    },
    AWAY {
        text: Option<&'a str>,
    },
    USERHOST {
        nicknames: Vec<&'a str>,
    },
    WALLOPS {
        text: &'a str,
    },
    ISON {
        nicknames: Vec<&'a str>,
    },
    DIE {
        message: Option<&'a str>,
    },
}

use Command::*;

pub(crate) const NUM_COMMANDS: usize = 41;

impl<'a> Command<'a> {
    pub(crate) fn index(&self) -> usize {
        match self {
            CAP { .. } => 0,
            AUTHENTICATE { .. } => 1,
            PASS { .. } => 2,
            NICK { .. } => 3,
            USER { .. } => 4,
            PING { .. } => 5,
            PONG { .. } => 6,
            OPER { .. } => 7,
            QUIT { .. } => 8,
            JOIN { .. } => 9,
            PART { .. } => 10,
            TOPIC { .. } => 11,
            NAMES { .. } => 12,
            LIST { .. } => 13,
            INVITE { .. } => 14,
            KICK { .. } => 15,
            MOTD { .. } => 16,
            VERSION { .. } => 17,
            ADMIN { .. } => 18,
            CONNECT { .. } => 19,
            LUSERS { .. } => 20,
            TIME { .. } => 21,
            STATS { .. } => 22,
            LINKS { .. } => 23,
            HELP { .. } => 24,
            INFO { .. } => 25,
            MODE { .. } => 26,
            PRIVMSG { .. } => 27,
            NOTICE { .. } => 28,
            WHO { .. } => 29,
            WHOIS { .. } => 30,
            WHOWAS { .. } => 31,
            KILL { .. } => 32,
            REHASH { .. } => 33,
            RESTART { .. } => 34,
            SQUIT { .. } => 35,
            AWAY { .. } => 36,
            USERHOST { .. } => 37,
            WALLOPS { .. } => 38,
            ISON { .. } => 39,
            DIE { .. } => 40,
        }
    }

    // parse command from message. for internal use
    fn parse_from_message(message: &Message<'a>) -> Result<Self, CommandError> {
        match message.command.to_ascii_uppercase().as_str() {
            "CAP" => {
                if !message.params.is_empty() {
                    let mut param_it = message.params.iter();
                    let subcommand = match param_it.next().unwrap().to_ascii_uppercase().as_str() {
                        "LS" => CapCommand::LS,
                        "LIST" => CapCommand::LIST,
                        "REQ" => CapCommand::REQ,
                        "END" => CapCommand::END,
                        _ => return Err(UnknownSubcommand(CAPId, message.params[0].to_string())),
                    };

                    // get capabilities list and version
                    let (caps, version) = if subcommand == CapCommand::REQ {
                        // subcommand REQ have capabilities list.
                        (
                            param_it
                                .next()
                                .map(|x| x.split_ascii_whitespace().collect::<Vec<_>>()),
                            None,
                        )
                    } else if subcommand == CapCommand::LS {
                        // subcommand LS can have version
                        let v = if let Some(s) = param_it.next() {
                            if let Ok(value) = s.parse() {
                                Some(value)
                            } else {
                                return Err(WrongParameter(CAPId, 1));
                            }
                        } else {
                            None
                        };
                        (None, v)
                    } else {
                        (None, None)
                    };

                    Ok(CAP {
                        subcommand,
                        caps,
                        version,
                    })
                } else {
                    Err(NeedMoreParams(CAPId))
                }
            }
            "AUTHENTICATE" => Ok(AUTHENTICATE {}),
            "PASS" => {
                if !message.params.is_empty() {
                    Ok(PASS {
                        password: message.params[0],
                    })
                } else {
                    Err(NeedMoreParams(PASSId))
                }
            }
            "NICK" => {
                if !message.params.is_empty() {
                    Ok(NICK {
                        nickname: message.params[0],
                    })
                } else {
                    Err(NeedMoreParams(NICKId))
                }
            }
            "USER" => {
                if message.params.len() >= 4 {
                    Ok(USER {
                        username: message.params[0],
                        hostname: message.params[1],
                        servername: message.params[2],
                        realname: message.params[3],
                    })
                } else {
                    Err(NeedMoreParams(USERId))
                }
            }
            "PING" => {
                if !message.params.is_empty() {
                    Ok(PING {
                        token: message.params[0],
                    })
                } else {
                    Err(NeedMoreParams(PINGId))
                }
            }
            "PONG" => {
                if !message.params.is_empty() {
                    Ok(PONG {
                        token: message.params[0],
                    })
                } else {
                    Err(NeedMoreParams(PONGId))
                }
            }
            "OPER" => {
                if message.params.len() >= 2 {
                    Ok(OPER {
                        name: message.params[0],
                        password: message.params[1],
                    })
                } else {
                    Err(NeedMoreParams(OPERId))
                }
            }
            "QUIT" => Ok(QUIT {}),
            "JOIN" => {
                if !message.params.is_empty() {
                    let mut param_it = message.params.iter();
                    // channels are separated by ','
                    let channels = param_it.next().unwrap().split(',').collect::<Vec<_>>();
                    // keys are separated by ','
                    let keys_opt = param_it.next().map(|x| x.split(',').collect::<Vec<_>>());
                    if let Some(ref keys) = keys_opt {
                        if keys.len() != channels.len() {
                            return Err(ParameterDoesntMatch(JOINId, 1));
                        }
                    }
                    Ok(JOIN {
                        channels,
                        keys: keys_opt,
                    })
                } else {
                    Err(NeedMoreParams(JOINId))
                }
            }
            "PART" => {
                if !message.params.is_empty() {
                    let mut param_it = message.params.iter();
                    // channels are separated by ','
                    let channels = param_it.next().unwrap().split(',').collect::<Vec<_>>();
                    let reason = param_it.next().copied();
                    Ok(PART { channels, reason })
                } else {
                    Err(NeedMoreParams(PARTId))
                }
            }
            "TOPIC" => {
                if !message.params.is_empty() {
                    let mut param_it = message.params.iter();
                    let channel = param_it.next().unwrap();
                    let topic = param_it.next().copied();
                    Ok(TOPIC { channel, topic })
                } else {
                    Err(NeedMoreParams(TOPICId))
                }
            }
            "NAMES" => {
                if !message.params.is_empty() {
                    // channels are separated by ','
                    Ok(NAMES {
                        channels: message.params[0].split(',').collect::<Vec<_>>(),
                    })
                } else {
                    Ok(NAMES { channels: vec![] })
                }
            }
            "LIST" => {
                if !message.params.is_empty() {
                    let mut param_it = message.params.iter();
                    // channels are separated by ','
                    let channels = param_it.next().unwrap().split(',').collect::<Vec<_>>();
                    let server = param_it.next().copied();
                    Ok(LIST { channels, server })
                } else {
                    Ok(LIST {
                        channels: vec![],
                        server: None,
                    })
                }
            }
            "INVITE" => {
                if message.params.len() >= 2 {
                    Ok(INVITE {
                        nickname: message.params[0],
                        channel: message.params[1],
                    })
                } else {
                    Err(NeedMoreParams(INVITEId))
                }
            }
            "KICK" => {
                if message.params.len() >= 2 {
                    let mut param_it = message.params.iter();
                    let channel = param_it.next().unwrap();
                    // users are separated by ','
                    let users = param_it.next().unwrap().split(',').collect::<Vec<_>>();
                    let comment = param_it.next().copied();
                    Ok(KICK {
                        channel,
                        users,
                        comment,
                    })
                } else {
                    Err(NeedMoreParams(KICKId))
                }
            }
            "MOTD" => Ok(MOTD {
                target: message.params.get(0).copied(),
            }),
            "VERSION" => Ok(VERSION {
                target: message.params.get(0).copied(),
            }),
            "ADMIN" => Ok(ADMIN {
                target: message.params.get(0).copied(),
            }),
            "CONNECT" => {
                if !message.params.is_empty() {
                    let mut param_it = message.params.iter();
                    let target_server = param_it.next().unwrap();
                    let port = param_it.next().map(|x| x.parse()).transpose();
                    let remote_server = param_it.next().copied();
                    // check whether port is number
                    match port {
                        Err(_) => Err(WrongParameter(CONNECTId, 1)),
                        Ok(p) => Ok(CONNECT {
                            target_server,
                            port: p,
                            remote_server,
                        }),
                    }
                } else {
                    Err(NeedMoreParams(CONNECTId))
                }
            }
            "LUSERS" => Ok(LUSERS {}),
            "TIME" => Ok(TIME {
                server: message.params.get(0).copied(),
            }),
            "STATS" => {
                if !message.params.is_empty() {
                    let mut param_it = message.params.iter();
                    let query_str = param_it.next().unwrap();
                    let server = param_it.next().copied();

                    if query_str.len() == 1 {
                        Ok(STATS {
                            query: query_str.chars().next().unwrap(),
                            server,
                        })
                    } else {
                        Err(WrongParameter(STATSId, 0))
                    }
                } else {
                    Err(NeedMoreParams(STATSId))
                }
            }
            "LINKS" => {
                if message.params.len() == 2 {
                    Ok(LINKS {
                        remote_server: Some(message.params[0]),
                        server_mask: Some(message.params[1]),
                    })
                } else if message.params.len() == 1 {
                    Ok(LINKS {
                        remote_server: None,
                        server_mask: Some(message.params[0]),
                    })
                } else {
                    Ok(LINKS {
                        remote_server: None,
                        server_mask: None,
                    })
                }
            }
            "HELP" => {
                if !message.params.is_empty() {
                    Ok(HELP {
                        subject: Some(message.params[0]),
                    })
                } else {
                    Ok(HELP { subject: None })
                }
            }
            "INFO" => Ok(INFO {}),
            "MODE" => {
                if !message.params.is_empty() {
                    let mut modes = vec![];
                    let mut param_it = message.params.iter();
                    let target = param_it.next().unwrap();
                    if let Some(s) = param_it.next() {
                        if s.starts_with('+') || s.starts_with('-') {
                            let mut modestring = *s;
                            let mut mode_args = vec![];
                            // collect mode arguments until next mode string.
                            for s in param_it {
                                if s.starts_with('+') || s.starts_with('-') {
                                    // push modestring and mode arguments to modes
                                    modes.push((modestring, mode_args));
                                    // next mode string
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
                    Ok(MODE { target, modes })
                } else {
                    Err(NeedMoreParams(MODEId))
                }
            }
            "PRIVMSG" => {
                if message.params.len() >= 2 {
                    // targets are separated by ','
                    Ok(PRIVMSG {
                        targets: message.params[0].split(',').collect::<Vec<_>>(),
                        text: message.params[1],
                    })
                } else {
                    Err(NeedMoreParams(PRIVMSGId))
                }
            }
            "NOTICE" => {
                if message.params.len() >= 2 {
                    // targets are separated by ','
                    Ok(NOTICE {
                        targets: message.params[0].split(',').collect::<Vec<_>>(),
                        text: message.params[1],
                    })
                } else {
                    Err(NeedMoreParams(NOTICEId))
                }
            }
            "WHO" => {
                if !message.params.is_empty() {
                    Ok(WHO {
                        mask: message.params[0],
                    })
                } else {
                    Err(NeedMoreParams(WHOId))
                }
            }
            "WHOIS" => {
                if !message.params.is_empty() {
                    if message.params.len() >= 2 {
                        // nickmasks are separated by ','
                        Ok(WHOIS {
                            target: Some(message.params[0]),
                            nickmasks: message.params[1].split(',').collect::<Vec<_>>(),
                        })
                    } else {
                        Ok(WHOIS {
                            target: None,
                            nickmasks: message.params[0].split(',').collect::<Vec<_>>(),
                        })
                    }
                } else {
                    Err(NeedMoreParams(WHOISId))
                }
            }
            "WHOWAS" => {
                if !message.params.is_empty() {
                    let mut param_it = message.params.iter();
                    let nickname = param_it.next().unwrap();
                    let count = param_it.next().map(|x| x.parse()).transpose();
                    let server = param_it.next().copied();
                    // check whether count is number
                    match count {
                        Err(_) => Err(WrongParameter(WHOWASId, 1)),
                        Ok(c) => Ok(WHOWAS {
                            nickname,
                            count: c,
                            server,
                        }),
                    }
                } else {
                    Err(NeedMoreParams(WHOWASId))
                }
            }
            "KILL" => {
                if message.params.len() >= 2 {
                    Ok(KILL {
                        nickname: message.params[0],
                        comment: message.params[1],
                    })
                } else {
                    Err(NeedMoreParams(KILLId))
                }
            }
            "REHASH" => Ok(REHASH {}),
            "RESTART" => Ok(RESTART {}),
            "SQUIT" => {
                if message.params.len() >= 2 {
                    Ok(SQUIT {
                        server: message.params[0],
                        comment: message.params[1],
                    })
                } else {
                    Err(NeedMoreParams(SQUITId))
                }
            }
            "AWAY" => Ok(AWAY {
                text: message.params.get(0).copied(),
            }),
            "USERHOST" => {
                if !message.params.is_empty() {
                    Ok(USERHOST {
                        nicknames: message.params.clone(),
                    })
                } else {
                    Err(NeedMoreParams(USERHOSTId))
                }
            }
            "WALLOPS" => {
                if !message.params.is_empty() {
                    Ok(WALLOPS {
                        text: message.params[0],
                    })
                } else {
                    Err(NeedMoreParams(WALLOPSId))
                }
            }
            "ISON" => {
                if !message.params.is_empty() {
                    Ok(ISON {
                        nicknames: message.params.clone(),
                    })
                } else {
                    Err(NeedMoreParams(ISONId))
                }
            }
            "DIE" => {
                if !message.params.is_empty() {
                    Ok(DIE {
                        message: Some(message.params[0]),
                    })
                } else {
                    Ok(DIE { message: None })
                }
            }
            s => Err(UnknownCommand(s.to_string())),
        }
    }

    // get Command from message
    pub(crate) fn from_message(message: &Message<'a>) -> Result<Self, CommandError> {
        match Self::parse_from_message(message) {
            Ok(x) => {
                // and validate command parameters
                match x.validate() {
                    Ok(()) => Ok(x),
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }

    fn validate(&self) -> Result<(), CommandError> {
        match self {
            CAP { version, .. } => {
                if let Some(v) = version {
                    if *v < 302 {
                        Err(WrongParameter(CAPId, 1))
                    } else {
                        Ok(())
                    }
                } else {
                    Ok(())
                }
            }
            NICK { nickname } => validate_username(nickname).map_err(|_| WrongParameter(NICKId, 0)),
            USER { username, .. } => {
                validate_username(username).map_err(|_| WrongParameter(USERId, 0))
            }
            OPER { name, .. } => validate_username(name).map_err(|_| WrongParameter(OPERId, 0)),
            JOIN { channels, .. } => channels
                .iter()
                .try_for_each(|ch| validate_channel(ch))
                .map_err(|_| WrongParameter(JOINId, 0)),
            PART { channels, .. } => channels
                .iter()
                .try_for_each(|ch| validate_channel(ch))
                .map_err(|_| WrongParameter(PARTId, 0)),
            TOPIC { channel, .. } => {
                validate_channel(channel).map_err(|_| WrongParameter(TOPICId, 0))
            }
            NAMES { channels } => channels
                .iter()
                .try_for_each(|ch| validate_channel(ch))
                .map_err(|_| WrongParameter(NAMESId, 0)),
            LIST { channels, server } => {
                channels
                    .iter()
                    .try_for_each(|ch| validate_channel(ch))
                    .map_err(|_| WrongParameter(LISTId, 0))?;
                if let Some(srv) = server {
                    validate_server(srv, WrongParameter(LISTId, 1))?;
                }
                Ok(())
            }
            INVITE { nickname, channel } => {
                validate_username(nickname).map_err(|_| WrongParameter(INVITEId, 0))?;
                validate_channel(channel).map_err(|_| WrongParameter(INVITEId, 1))
            }
            KICK { channel, users, .. } => {
                validate_channel(channel).map_err(|_| WrongParameter(KICKId, 0))?;
                users
                    .iter()
                    .try_for_each(|u| validate_username(u))
                    .map_err(|_| WrongParameter(KICKId, 1))
            }
            MOTD { target } => {
                if let Some(t) = target {
                    validate_server_mask(t, WrongParameter(MOTDId, 0))?;
                }
                Ok(())
            }
            VERSION { target } => {
                if let Some(t) = target {
                    validate_server_mask(t, WrongParameter(VERSIONId, 0))?;
                }
                Ok(())
            }
            ADMIN { target } => {
                if let Some(t) = target {
                    validate_server_mask(t, WrongParameter(ADMINId, 0))?;
                }
                Ok(())
            }
            CONNECT {
                target_server,
                remote_server,
                ..
            } => {
                validate_server(target_server, WrongParameter(CONNECTId, 0))?;
                if let Some(s) = remote_server {
                    validate_server(s, WrongParameter(CONNECTId, 1))?;
                }
                Ok(())
            }
            TIME { server } => {
                if let Some(s) = server {
                    validate_server(s, WrongParameter(TIMEId, 0))?;
                }
                Ok(())
            }
            STATS { query, server } => {
                match query {
                    // check query
                    'c' | 'h' | 'i' | 'k' | 'l' | 'm' | 'o' | 'u' | 'y' => {
                        if let Some(s) = server {
                            validate_server(s, WrongParameter(STATSId, 1))?;
                        }
                    }
                    _ => return Err(WrongParameter(STATSId, 0)),
                };
                Ok(())
            }
            LINKS {
                remote_server,
                server_mask,
            } => {
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
            MODE { target, modes } => {
                if validate_channel(target).is_ok() {
                    validate_channelmodes(target, modes)
                } else if validate_username(target).is_ok() {
                    validate_usermodes(modes)
                } else {
                    Err(WrongParameter(MODEId, 0))
                }
            }
            PRIVMSG { targets, .. } => {
                targets.iter().try_for_each(|n| {
                    validate_username(n)
                        // in PRIVMSG we can use prefixed channels
                        .map_err(|_| WrongParameter(PRIVMSGId, 0))
                        .or_else(|_| validate_prefixed_channel(n, WrongParameter(PRIVMSGId, 0)))
                })
            }
            NOTICE { targets, .. } => {
                targets.iter().try_for_each(|n| {
                    validate_username(n)
                        // in NOTICE we can use prefixed channels
                        .map_err(|_| WrongParameter(NOTICEId, 0))
                        .or_else(|_| validate_prefixed_channel(n, WrongParameter(NOTICEId, 0)))
                })
            }
            //WHO{ mask } => { Ok(()) }
            WHOIS { target, nickmasks } => {
                let next_param_idx = if let Some(t) = target {
                    validate_server(t, WrongParameter(WHOISId, 0))?;
                    1
                } else {
                    0
                };
                nickmasks
                    .iter()
                    .try_for_each(|n| validate_username(n))
                    .map_err(|_| WrongParameter(WHOISId, next_param_idx))
            }
            WHOWAS {
                nickname, server, ..
            } => {
                validate_username(nickname).map_err(|_| WrongParameter(WHOWASId, 0))?;
                if let Some(s) = server {
                    validate_server(s, WrongParameter(WHOWASId, 2))?;
                }
                Ok(())
            }
            KILL { nickname, .. } => {
                validate_username(nickname).map_err(|_| WrongParameter(KILLId, 0))
            }
            SQUIT { server, .. } => {
                validate_server(server, WrongParameter(SQUITId, 0))?;
                Ok(())
            }
            USERHOST { nicknames } => nicknames.iter().enumerate().try_for_each(|(i, n)| {
                validate_username(n).map_err(|_| WrongParameter(USERHOSTId, i))
            }),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_message_from_shared_str() {
        assert_eq!(
            Ok(Message {
                source: None,
                command: "QUIT",
                params: vec![]
            }),
            Message::from_shared_str("QUIT").map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(Message {
                source: None,
                command: "QUIT",
                params: vec![]
            }),
            Message::from_shared_str("   QUIT").map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(Message {
                source: Some("source"),
                command: "QUIT",
                params: vec![]
            }),
            Message::from_shared_str(":source QUIT").map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(Message {
                source: None,
                command: "USER",
                params: vec!["guest", "0", "*", "Ronnie Reagan"]
            }),
            Message::from_shared_str("USER guest 0 * :Ronnie Reagan").map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(Message {
                source: None,
                command: "USER",
                params: vec!["guest", "0", "*", "Benny"]
            }),
            Message::from_shared_str("USER guest 0 * Benny").map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(Message {
                source: None,
                command: "PRIVMSG",
                params: vec!["bobby", ":-). Hello guy!"]
            }),
            Message::from_shared_str("PRIVMSG bobby ::-). Hello guy!").map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(Message {
                source: Some("mati!mat@gg.com"),
                command: "QUIT",
                params: vec![]
            }),
            Message::from_shared_str(":mati!mat@gg.com QUIT").map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong source syntax".to_string()),
            Message::from_shared_str(":mati@mat!gg.com QUIT").map_err(|e| e.to_string())
        );
    }

    #[test]
    fn test_command_from_message() {
        assert_eq!(
            Ok(CAP {
                subcommand: CapCommand::LS,
                caps: None,
                version: None
            }),
            Command::from_message(&Message {
                source: None,
                command: "CAP",
                params: vec!["LS"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(CAP {
                subcommand: CapCommand::LS,
                caps: None,
                version: Some(302)
            }),
            Command::from_message(&Message {
                source: None,
                command: "CAP",
                params: vec!["LS", "302"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(CAP {
                subcommand: CapCommand::LS,
                caps: None,
                version: Some(303)
            }),
            Command::from_message(&Message {
                source: None,
                command: "CAP",
                params: vec!["LS", "303"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 1 in command 'CAP'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "CAP",
                params: vec!["LS", "301"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 1 in command 'CAP'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "CAP",
                params: vec!["LS", "xxx"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(CAP {
                subcommand: CapCommand::LIST,
                caps: None,
                version: None
            }),
            Command::from_message(&Message {
                source: None,
                command: "CAP",
                params: vec!["LIST"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(CAP {
                subcommand: CapCommand::REQ,
                version: None,
                caps: Some(vec!["multi-prefix", "tls"])
            }),
            Command::from_message(&Message {
                source: None,
                command: "CAP",
                params: vec!["REQ", "multi-prefix tls"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(CAP {
                subcommand: CapCommand::END,
                caps: None,
                version: None
            }),
            Command::from_message(&Message {
                source: None,
                command: "CAP",
                params: vec!["END"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(CAP {
                subcommand: CapCommand::REQ,
                version: None,
                caps: Some(vec!["multi-prefix", "tlsx"])
            }),
            Command::from_message(&Message {
                source: None,
                command: "CAP",
                params: vec!["REQ", "multi-prefix tlsx"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Unknown subcommand 'LSS' in command 'CAP'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "CAP",
                params: vec!["LSS"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Command 'CAP' needs more parameters".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "CAP",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(AUTHENTICATE {}),
            Command::from_message(&Message {
                source: None,
                command: "AUTHENTICATE",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(PASS { password: "secret" }),
            Command::from_message(&Message {
                source: None,
                command: "PASS",
                params: vec!["secret"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Command 'PASS' needs more parameters".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "PASS",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(NICK { nickname: "lucky" }),
            Command::from_message(&Message {
                source: None,
                command: "NICK",
                params: vec!["lucky"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'NICK'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "NICK",
                params: vec!["luc.ky"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'NICK'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "NICK",
                params: vec!["luc,ky"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'NICK'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "NICK",
                params: vec!["luc:ky"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Command 'NICK' needs more parameters".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "NICK",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(USER {
                username: "chris",
                hostname: "0",
                servername: "*",
                realname: "Chris Wood"
            }),
            Command::from_message(&Message {
                source: None,
                command: "USER",
                params: vec!["chris", "0", "*", "Chris Wood"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'USER'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "USER",
                params: vec!["chr:is", "0", "*", "Chris Wood"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Command 'USER' needs more parameters".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "USER",
                params: vec!["chris", "0", "*"]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(PING { token: "xxxaaa" }),
            Command::from_message(&Message {
                source: None,
                command: "PING",
                params: vec!["xxxaaa"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Command 'PING' needs more parameters".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "PING",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(OPER {
                name: "guru",
                password: "mythebestday"
            }),
            Command::from_message(&Message {
                source: None,
                command: "OPER",
                params: vec!["guru", "mythebestday"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'OPER'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "OPER",
                params: vec!["gu:ru", "mythebestday"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Command 'OPER' needs more parameters".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "OPER",
                params: vec!["guru"]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(QUIT {}),
            Command::from_message(&Message {
                source: None,
                command: "QUIT",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(JOIN {
                channels: vec!["#cats", "&fruits", "#software"],
                keys: None
            }),
            Command::from_message(&Message {
                source: None,
                command: "JOIN",
                params: vec!["#cats,&fruits,#software"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(JOIN {
                channels: vec!["#cats", "&fruits", "#software"],
                keys: Some(vec!["mycat", "apple", "wesnoth"])
            }),
            Command::from_message(&Message {
                source: None,
                command: "JOIN",
                params: vec!["#cats,&fruits,#software", "mycat,apple,wesnoth"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'JOIN'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "JOIN",
                params: vec!["#cats,&fru:its,#software"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'JOIN'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "JOIN",
                params: vec!["#cats,fruits,#software"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(JOIN {
                channels: vec!["#cats", "&fru.its", "#software"],
                keys: None
            }),
            Command::from_message(&Message {
                source: None,
                command: "JOIN",
                params: vec!["#cats,&fru.its,#software"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Parameter 1 doesn't match for command 'JOIN'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "JOIN",
                params: vec!["#cats,&fruits,#software,#countries", "mycat,apple,wesnoth"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Parameter 1 doesn't match for command 'JOIN'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "JOIN",
                params: vec!["#cats,&fruits,#software", "mycat,apple,wesnoth,zizi"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Command 'JOIN' needs more parameters".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "JOIN",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(PART {
                channels: vec!["#dogs", "&juices", "#hardware"],
                reason: None
            }),
            Command::from_message(&Message {
                source: None,
                command: "PART",
                params: vec!["#dogs,&juices,#hardware"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(PART {
                channels: vec!["#dogs", "&juices", "#hardware"],
                reason: Some("I don't like these channels")
            }),
            Command::from_message(&Message {
                source: None,
                command: "PART",
                params: vec!["#dogs,&juices,#hardware", "I don't like these channels"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'PART'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "PART",
                params: vec!["#dogs,&juices,#har:dware", "I don't like these channels"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Command 'PART' needs more parameters".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "PART",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(TOPIC {
                channel: "#gizmo",
                topic: None
            }),
            Command::from_message(&Message {
                source: None,
                command: "TOPIC",
                params: vec!["#gizmo"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(TOPIC {
                channel: "#gizmo",
                topic: Some("Some creatures")
            }),
            Command::from_message(&Message {
                source: None,
                command: "TOPIC",
                params: vec!["#gizmo", "Some creatures"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'TOPIC'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "TOPIC",
                params: vec!["#giz:mo"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Command 'TOPIC' needs more parameters".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "TOPIC",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(NAMES {
                channels: vec!["#dogs", "&juices", "#hardware"]
            }),
            Command::from_message(&Message {
                source: None,
                command: "NAMES",
                params: vec!["#dogs,&juices,#hardware"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(NAMES { channels: vec![] }),
            Command::from_message(&Message {
                source: None,
                command: "NAMES",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'NAMES'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "NAMES",
                params: vec!["#dogs,&juices,#hard:ware"]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(LIST {
                channels: vec!["#dogs", "&juices", "#hardware"],
                server: None
            }),
            Command::from_message(&Message {
                source: None,
                command: "LIST",
                params: vec!["#dogs,&juices,#hardware"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(LIST {
                channels: vec!["#dogs", "&juices", "#hardware"],
                server: Some("funny.checkbox.org")
            }),
            Command::from_message(&Message {
                source: None,
                command: "LIST",
                params: vec!["#dogs,&juices,#hardware", "funny.checkbox.org"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(LIST {
                channels: vec![],
                server: None
            }),
            Command::from_message(&Message {
                source: None,
                command: "LIST",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'LIST'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "LIST",
                params: vec!["#dogs,&juices,#har:dware", "funny.checkbox.org"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 1 in command 'LIST'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "LIST",
                params: vec!["#dogs,&juices,#hardware", "fnny"]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(INVITE {
                nickname: "greg",
                channel: "#plants"
            }),
            Command::from_message(&Message {
                source: None,
                command: "INVITE",
                params: vec!["greg", "#plants"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'INVITE'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "INVITE",
                params: vec!["gr:eg", "#plants"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 1 in command 'INVITE'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "INVITE",
                params: vec!["greg", "_plants"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Command 'INVITE' needs more parameters".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "INVITE",
                params: vec!["greg"]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(KICK {
                channel: "#toolkits",
                users: vec!["mickey"],
                comment: None
            }),
            Command::from_message(&Message {
                source: None,
                command: "KICK",
                params: vec!["#toolkits", "mickey"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(KICK {
                channel: "#toolkits",
                users: vec!["mickey", "lola"],
                comment: None
            }),
            Command::from_message(&Message {
                source: None,
                command: "KICK",
                params: vec!["#toolkits", "mickey,lola"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(KICK {
                channel: "#toolkits",
                users: vec!["mickey"],
                comment: Some("Mickey is not polite")
            }),
            Command::from_message(&Message {
                source: None,
                command: "KICK",
                params: vec!["#toolkits", "mickey", "Mickey is not polite"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'KICK'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "KICK",
                params: vec!["@toolkits", "mickey"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 1 in command 'KICK'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "KICK",
                params: vec!["#toolkits", "mic:key"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Command 'KICK' needs more parameters".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "KICK",
                params: vec!["#toolkits"]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(MOTD { target: None }),
            Command::from_message(&Message {
                source: None,
                command: "MOTD",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(MOTD {
                target: Some("bubu.com")
            }),
            Command::from_message(&Message {
                source: None,
                command: "MOTD",
                params: vec!["bubu.com"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(MOTD {
                target: Some("*com")
            }),
            Command::from_message(&Message {
                source: None,
                command: "MOTD",
                params: vec!["*com"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'MOTD'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "MOTD",
                params: vec!["bubucom"]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(VERSION { target: None }),
            Command::from_message(&Message {
                source: None,
                command: "VERSION",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(VERSION {
                target: Some("bubu.com")
            }),
            Command::from_message(&Message {
                source: None,
                command: "VERSION",
                params: vec!["bubu.com"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(VERSION {
                target: Some("*com")
            }),
            Command::from_message(&Message {
                source: None,
                command: "VERSION",
                params: vec!["*com"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'VERSION'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "VERSION",
                params: vec!["bubucom"]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(ADMIN { target: None }),
            Command::from_message(&Message {
                source: None,
                command: "ADMIN",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(ADMIN {
                target: Some("bubu.com")
            }),
            Command::from_message(&Message {
                source: None,
                command: "ADMIN",
                params: vec!["bubu.com"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(ADMIN {
                target: Some("*com")
            }),
            Command::from_message(&Message {
                source: None,
                command: "ADMIN",
                params: vec!["*com"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'ADMIN'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "ADMIN",
                params: vec!["bubucom"]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(CONNECT {
                target_server: "chat.purple.com",
                port: None,
                remote_server: None
            }),
            Command::from_message(&Message {
                source: None,
                command: "CONNECT",
                params: vec!["chat.purple.com"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(CONNECT {
                target_server: "chat.purple.com",
                port: Some(6670),
                remote_server: None
            }),
            Command::from_message(&Message {
                source: None,
                command: "CONNECT",
                params: vec!["chat.purple.com", "6670"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(CONNECT {
                target_server: "chat.purple.com",
                port: Some(6670),
                remote_server: Some("chat.broker.com")
            }),
            Command::from_message(&Message {
                source: None,
                command: "CONNECT",
                params: vec!["chat.purple.com", "6670", "chat.broker.com"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'CONNECT'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "CONNECT",
                params: vec!["chatpurplecom"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 1 in command 'CONNECT'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "CONNECT",
                params: vec!["chat.purple.com", "xxxaa"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 1 in command 'CONNECT'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "CONNECT",
                params: vec!["chat.purple.com", "6670", "chatbrokercom"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Command 'CONNECT' needs more parameters".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "CONNECT",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(LUSERS {}),
            Command::from_message(&Message {
                source: None,
                command: "LUSERS",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(TIME { server: None }),
            Command::from_message(&Message {
                source: None,
                command: "TIME",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(TIME {
                server: Some("bubu.com")
            }),
            Command::from_message(&Message {
                source: None,
                command: "TIME",
                params: vec!["bubu.com"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'TIME'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "TIME",
                params: vec!["*com"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'TIME'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "TIME",
                params: vec!["bubucom"]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(STATS {
                query: 'c',
                server: None
            }),
            Command::from_message(&Message {
                source: None,
                command: "STATS",
                params: vec!["c"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(STATS {
                query: 'l',
                server: None
            }),
            Command::from_message(&Message {
                source: None,
                command: "STATS",
                params: vec!["l"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(STATS {
                query: 'o',
                server: None
            }),
            Command::from_message(&Message {
                source: None,
                command: "STATS",
                params: vec!["o"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(STATS {
                query: 'o',
                server: Some("chat.fruits.com")
            }),
            Command::from_message(&Message {
                source: None,
                command: "STATS",
                params: vec!["o", "chat.fruits.com"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'STATS'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "STATS",
                params: vec!["z"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 1 in command 'STATS'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "STATS",
                params: vec!["o", "chatfruitscom"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Command 'STATS' needs more parameters".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "STATS",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(LINKS {
                remote_server: None,
                server_mask: Some("*.gigo.net")
            }),
            Command::from_message(&Message {
                source: None,
                command: "LINKS",
                params: vec!["*.gigo.net"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(LINKS {
                remote_server: Some("first.proxy.net"),
                server_mask: Some("*.gigo.net")
            }),
            Command::from_message(&Message {
                source: None,
                command: "LINKS",
                params: vec!["first.proxy.net", "*.gigo.net"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'LINKS'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "LINKS",
                params: vec!["gigonet"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 1 in command 'LINKS'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "LINKS",
                params: vec!["first.proxy.net", "gigonet"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'LINKS'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "LINKS",
                params: vec!["firstproxynet", "*.gigo.net"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(LINKS {
                remote_server: None,
                server_mask: None
            }),
            Command::from_message(&Message {
                source: None,
                command: "LINKS",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(HELP {
                subject: Some("PING Message")
            }),
            Command::from_message(&Message {
                source: None,
                command: "HELP",
                params: vec!["PING Message"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(HELP {
                subject: Some("PONG Message")
            }),
            Command::from_message(&Message {
                source: None,
                command: "HELP",
                params: vec!["PONG Message"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(HELP { subject: None }),
            Command::from_message(&Message {
                source: None,
                command: "HELP",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(INFO {}),
            Command::from_message(&Message {
                source: None,
                command: "INFO",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(MODE {
                target: "andy",
                modes: vec![]
            }),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["andy"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(MODE {
                target: "#engines",
                modes: vec![]
            }),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#engines"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(MODE {
                target: "andy",
                modes: vec![("+ow", vec![])]
            }),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["andy", "+ow"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(MODE {
                target: "andy",
                modes: vec![("+oOr-iw", vec![])]
            }),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["andy", "+oOr-iw"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(MODE {
                target: "andy",
                modes: vec![("+oOr", vec![]), ("-iw", vec![])]
            }),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["andy", "+oOr", "-iw"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Unknown umode flag in parameter 1".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["teddy", "+otOr"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Unknown umode flag in parameter 1".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["teddy", "+otOr", "bbb"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(MODE {
                target: "#chasis",
                modes: vec![("+ntsm", vec![])]
            }),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "+ntsm"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(MODE {
                target: "#chasis",
                modes: vec![("+b", vec!["*@192.168.1.7"])]
            }),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "+b", "*@192.168.1.7"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(MODE {
                target: "#chasis",
                modes: vec![("-b", vec!["*@192.168.1.7"])]
            }),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "-b", "*@192.168.1.7"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(MODE {
                target: "#chasis",
                modes: vec![
                    ("+b", vec!["*@192.168.1.7"]),
                    ("+e", vec!["*@192.168.1.3"]),
                    ("+I", vec!["*@192.168.1.9"])
                ]
            }),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec![
                    "#chasis",
                    "+b",
                    "*@192.168.1.7",
                    "+e",
                    "*@192.168.1.3",
                    "+I",
                    "*@192.168.1.9"
                ]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(MODE {
                target: "#chasis",
                modes: vec![
                    ("-b", vec!["*@192.168.1.7"]),
                    ("-e", vec!["*@192.168.1.3"]),
                    ("-I", vec!["*@192.168.1.9"])
                ]
            }),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec![
                    "#chasis",
                    "-b",
                    "*@192.168.1.7",
                    "-e",
                    "*@192.168.1.3",
                    "-I",
                    "*@192.168.1.9"
                ]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(MODE {
                target: "#chasis",
                modes: vec![
                    ("-mb", vec!["*@192.168.1.7"]),
                    ("-ne", vec!["*@192.168.1.3"]),
                    ("-tI", vec!["*@192.168.1.9"])
                ]
            }),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec![
                    "#chasis",
                    "-mb",
                    "*@192.168.1.7",
                    "-ne",
                    "*@192.168.1.3",
                    "-tI",
                    "*@192.168.1.9"
                ]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(MODE {
                target: "#chasis",
                modes: vec![("+b", vec![])]
            }),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "+b"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(MODE {
                target: "#chasis",
                modes: vec![("+l", vec!["123"])]
            }),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "+l", "123"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(MODE {
                target: "#chasis",
                modes: vec![("-l", vec![])]
            }),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "-l"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(MODE {
                target: "#chasis",
                modes: vec![("+k", vec!["secret"])]
            }),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "+k", "secret"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(MODE {
                target: "#chasis",
                modes: vec![("-k", vec![])]
            }),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "-k"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(MODE {
                target: "#chasis",
                modes: vec![("-bl+i", vec!["*@192.168.0.1"])]
            }),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "-bl+i", "*@192.168.0.1"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(MODE {
                target: "#chasis",
                modes: vec![("+o", vec!["barry"])]
            }),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "+o", "barry"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(MODE {
                target: "#chasis",
                modes: vec![("-o", vec!["barry"])]
            }),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "-o", "barry"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(MODE {
                target: "#chasis",
                modes: vec![("+h", vec!["barry"])]
            }),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "+h", "barry"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(MODE {
                target: "#chasis",
                modes: vec![("-h", vec!["barry"])]
            }),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "-h", "barry"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(MODE {
                target: "#chasis",
                modes: vec![("+v", vec!["barry"])]
            }),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "+v", "barry"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(MODE {
                target: "#chasis",
                modes: vec![("-v", vec!["barry"])]
            }),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "-v", "barry"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(MODE {
                target: "andy",
                modes: vec![]
            }),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["andy"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Invalid mode parameter: #chasis l  No argument".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "+l"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Invalid mode parameter: #chasis k  No argument".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "+k"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Invalid mode parameter: #chasis o  No argument".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "+o"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Invalid mode parameter: #chasis o  No argument".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "-o"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Invalid mode parameter: #chasis h  No argument".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "+h"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Invalid mode parameter: #chasis h  No argument".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "-h"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Invalid mode parameter: #chasis v  No argument".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "+v"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Invalid mode parameter: #chasis v  No argument".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "-v"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err(
                "Invalid mode parameter: #chasis l xxx invalid digit found in \
                string"
                    .to_string()
            ),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "+l", "xxx"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Invalid mode parameter: #chasis l 145 \
                Unexpected argument"
                .to_string()),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "-l", "145"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Invalid mode parameter: #chasis k 145 \
                Unexpected argument"
                .to_string()),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "-k", "145"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Invalid mode parameter: #chasis o  No argument".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec!["#chasis", "-bl+oi", "*@192.168.0.1"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Command 'MODE' needs more parameters".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "MODE",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(PRIVMSG {
                targets: vec!["bobby", "andy"],
                text: "Hello, guys"
            }),
            Command::from_message(&Message {
                source: None,
                command: "PRIVMSG",
                params: vec!["bobby,andy", "Hello, guys"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(PRIVMSG {
                targets: vec!["#graphics", "&musics"],
                text: "Hello, guys"
            }),
            Command::from_message(&Message {
                source: None,
                command: "PRIVMSG",
                params: vec!["#graphics,&musics", "Hello, guys"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(PRIVMSG {
                targets: vec!["#graphics", "&musics", "jimmy"],
                text: "Hello, cruel world!"
            }),
            Command::from_message(&Message {
                source: None,
                command: "PRIVMSG",
                params: vec!["#graphics,&musics,jimmy", "Hello, cruel world!"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(PRIVMSG {
                targets: vec!["%#graphics", "~&musics", "jimmy"],
                text: "Hello, cruel world!"
            }),
            Command::from_message(&Message {
                source: None,
                command: "PRIVMSG",
                params: vec!["%#graphics,~&musics,jimmy", "Hello, cruel world!"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(PRIVMSG {
                targets: vec!["@#graphics", "&&musics", "jimmy"],
                text: "Hello, cruel world!"
            }),
            Command::from_message(&Message {
                source: None,
                command: "PRIVMSG",
                params: vec!["@#graphics,&&musics,jimmy", "Hello, cruel world!"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(PRIVMSG {
                targets: vec!["@+#graphics", "&&musics", "jimmy"],
                text: "Hello, cruel world!"
            }),
            Command::from_message(&Message {
                source: None,
                command: "PRIVMSG",
                params: vec!["@+#graphics,&&musics,jimmy", "Hello, cruel world!"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(PRIVMSG {
                targets: vec!["+#graphics", "+&musics", "jimmy"],
                text: "Hello, cruel world!"
            }),
            Command::from_message(&Message {
                source: None,
                command: "PRIVMSG",
                params: vec!["+#graphics,+&musics,jimmy", "Hello, cruel world!"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'PRIVMSG'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "PRIVMSG",
                params: vec!["#graphics,&musics,ji.mmy", "Hello, cruel world!"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Command 'PRIVMSG' needs more parameters".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "PRIVMSG",
                params: vec!["#graphics,&musics,jimmy"]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(NOTICE {
                targets: vec!["bobby", "andy"],
                text: "Hello, guys"
            }),
            Command::from_message(&Message {
                source: None,
                command: "NOTICE",
                params: vec!["bobby,andy", "Hello, guys"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(NOTICE {
                targets: vec!["#graphics", "&musics"],
                text: "Hello, guys"
            }),
            Command::from_message(&Message {
                source: None,
                command: "NOTICE",
                params: vec!["#graphics,&musics", "Hello, guys"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(NOTICE {
                targets: vec!["#graphics", "&musics", "jimmy"],
                text: "Hello, cruel world!"
            }),
            Command::from_message(&Message {
                source: None,
                command: "NOTICE",
                params: vec!["#graphics,&musics,jimmy", "Hello, cruel world!"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'NOTICE'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "NOTICE",
                params: vec!["#graphics,&musics,ji.mmy", "Hello, cruel world!"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Command 'NOTICE' needs more parameters".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "NOTICE",
                params: vec!["#graphics,&musics,jimmy"]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(WHO { mask: "bla*bla" }),
            Command::from_message(&Message {
                source: None,
                command: "WHO",
                params: vec!["bla*bla"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Command 'WHO' needs more parameters".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "WHO",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(WHOIS {
                target: None,
                nickmasks: vec!["alice", "eliz", "garry"]
            }),
            Command::from_message(&Message {
                source: None,
                command: "WHOIS",
                params: vec!["alice,eliz,garry"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(WHOIS {
                target: Some("coco.net"),
                nickmasks: vec!["alice", "eliz", "garry"]
            }),
            Command::from_message(&Message {
                source: None,
                command: "WHOIS",
                params: vec!["coco.net", "alice,eliz,garry"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'WHOIS'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "WHOIS",
                params: vec!["alice,el:iz,garry"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'WHOIS'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "WHOIS",
                params: vec!["coconet", "alice,eliz,garry"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 1 in command 'WHOIS'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "WHOIS",
                params: vec!["coco.net", "alice,eliz,ga:rry"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Command 'WHOIS' needs more parameters".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "WHOIS",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(WHOWAS {
                nickname: "mat",
                count: None,
                server: None
            }),
            Command::from_message(&Message {
                source: None,
                command: "WHOWAS",
                params: vec!["mat"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(WHOWAS {
                nickname: "mat",
                count: Some(10),
                server: None
            }),
            Command::from_message(&Message {
                source: None,
                command: "WHOWAS",
                params: vec!["mat", "10"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(WHOWAS {
                nickname: "mat",
                count: Some(10),
                server: Some("some.where.net")
            }),
            Command::from_message(&Message {
                source: None,
                command: "WHOWAS",
                params: vec!["mat", "10", "some.where.net"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'WHOWAS'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "WHOWAS",
                params: vec!["mat:"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 1 in command 'WHOWAS'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "WHOWAS",
                params: vec!["mat", "XX"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 2 in command 'WHOWAS'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "WHOWAS",
                params: vec!["mat", "10", "somewherenet"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Command 'WHOWAS' needs more parameters".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "WHOWAS",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(KILL {
                nickname: "bobby",
                comment: "Killed!"
            }),
            Command::from_message(&Message {
                source: None,
                command: "KILL",
                params: vec!["bobby", "Killed!"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'KILL'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "KILL",
                params: vec!["bob:by", "Killed!"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Command 'KILL' needs more parameters".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "KILL",
                params: vec!["bobby"]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(REHASH {}),
            Command::from_message(&Message {
                source: None,
                command: "REHASH",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(RESTART {}),
            Command::from_message(&Message {
                source: None,
                command: "RESTART",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(SQUIT {
                server: "somewhere.dot.com",
                comment: "Killed!"
            }),
            Command::from_message(&Message {
                source: None,
                command: "SQUIT",
                params: vec!["somewhere.dot.com", "Killed!"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'SQUIT'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "SQUIT",
                params: vec!["bobxxx", "Killed!"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Command 'SQUIT' needs more parameters".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "SQUIT",
                params: vec!["somewhere.dot.com"]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(AWAY { text: None }),
            Command::from_message(&Message {
                source: None,
                command: "AWAY",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(AWAY {
                text: Some("I will make rest")
            }),
            Command::from_message(&Message {
                source: None,
                command: "AWAY",
                params: vec!["I will make rest"]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(USERHOST {
                nicknames: vec!["bobby"]
            }),
            Command::from_message(&Message {
                source: None,
                command: "USERHOST",
                params: vec!["bobby"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(USERHOST {
                nicknames: vec!["bobby", "jimmy"]
            }),
            Command::from_message(&Message {
                source: None,
                command: "USERHOST",
                params: vec!["bobby", "jimmy"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 0 in command 'USERHOST'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "USERHOST",
                params: vec!["bo:bby", "jimmy"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 1 in command 'USERHOST'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "USERHOST",
                params: vec!["bobby", "ji:mmy"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Wrong parameter 2 in command 'USERHOST'".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "USERHOST",
                params: vec!["bobby", "damon", "ji:mmy"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Command 'USERHOST' needs more parameters".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "USERHOST",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(WALLOPS {
                text: "This is some message"
            }),
            Command::from_message(&Message {
                source: None,
                command: "WALLOPS",
                params: vec!["This is some message"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Err("Command 'WALLOPS' needs more parameters".to_string()),
            Command::from_message(&Message {
                source: None,
                command: "WALLOPS",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );

        assert_eq!(
            Ok(DIE {
                message: Some("This is some message")
            }),
            Command::from_message(&Message {
                source: None,
                command: "DIE",
                params: vec!["This is some message"]
            })
            .map_err(|e| e.to_string())
        );
        assert_eq!(
            Ok(DIE { message: None }),
            Command::from_message(&Message {
                source: None,
                command: "DIE",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );

        // case-insensitivness
        assert_eq!(
            Ok(RESTART {}),
            Command::from_message(&Message {
                source: None,
                command: "reStaRt",
                params: vec![]
            })
            .map_err(|e| e.to_string())
        );
    }

    #[test]
    fn test_message_to_string_with_source() {
        assert_eq!(
            ":buru USER guest 0 * :Ronnie Reagan".to_string(),
            Message {
                source: None,
                command: "USER",
                params: vec!["guest", "0", "*", "Ronnie Reagan"]
            }
            .to_string_with_source("buru")
        );
        assert_eq!(
            ":buru USER guest 0 * :".to_string(),
            Message {
                source: None,
                command: "USER",
                params: vec!["guest", "0", "*", ""]
            }
            .to_string_with_source("buru")
        );
        assert_eq!(
            ":sonny INVITE mati1 #xxx".to_string(),
            Message {
                source: Some("xxxx"),
                command: "INVITE",
                params: vec!["mati1", "#xxx"]
            }
            .to_string_with_source("sonny")
        );
    }
}
