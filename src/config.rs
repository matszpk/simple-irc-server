// config.rs - configuration
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

use serde::Deserializer;
use serde_derive::Deserialize;
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::str::FromStr;
use validator::Validate;

use crate::utils::match_wildcard;
use crate::utils::validate_channel;
use crate::utils::validate_password_hash;
use crate::utils::validate_username;

#[derive(clap::Parser, Clone)]
#[clap(author, version, about, long_about = None)]
pub(crate) struct Cli {
    #[clap(short, long, help = "Generate password hash")]
    pub(crate) gen_password_hash: bool,
    #[clap(short = 'P', long, help = "Password for generated password hash")]
    pub(crate) password: Option<String>,
    #[clap(short, long, help = "Configuration file path")]
    config: Option<String>,
    #[clap(short, long, help = "Listen bind address")]
    listen: Option<IpAddr>,
    #[clap(short, long, help = "Listen port")]
    port: Option<u16>,
    #[clap(short = 'n', long, help = "Server name")]
    name: Option<String>,
    #[clap(short = 'N', long, help = "Network")]
    network: Option<String>,
    #[clap(short, long, help = "DNS lookup if client connects")]
    dns_lookup: bool,
    #[clap(short = 'C', long, help = "TLS certificate file")]
    tls_cert_file: Option<String>,
    #[clap(short = 'K', long, help = "TLS certificate key file")]
    tls_cert_key_file: Option<String>,
    #[clap(short = 'L', long, help = "Log file path")]
    log_file: Option<String>,
}

#[derive(PartialEq, Eq, Deserialize, Debug, Clone)]
pub(crate) struct TLSConfig {
    pub(crate) cert_file: String,
    pub(crate) cert_key_file: String,
}

#[derive(PartialEq, Eq, Deserialize, Debug, Validate)]
pub(crate) struct OperatorConfig {
    #[validate(custom = "validate_username")]
    pub(crate) name: String,
    #[validate(custom = "validate_password_hash")]
    pub(crate) password: String,
    pub(crate) mask: Option<String>,
}

#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Debug, Default)]
pub(crate) struct UserModes {
    pub(crate) invisible: bool,
    pub(crate) oper: bool,
    pub(crate) local_oper: bool,
    pub(crate) registered: bool,
    pub(crate) wallops: bool,
}

impl fmt::Display for UserModes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = '+'.to_string();
        if self.invisible {
            s.push('i');
        }
        if self.oper {
            s.push('o');
        }
        if self.local_oper {
            s.push('O');
        }
        if self.registered {
            s.push('r');
        }
        if self.wallops {
            s.push('w');
        }
        f.write_str(&s)
    }
}

impl UserModes {
    pub(crate) fn is_local_oper(&self) -> bool {
        self.local_oper || self.oper
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize, Debug, Validate, Default)]
pub(crate) struct ChannelModes {
    // If channel modes we use Option to avoid unnecessary field definition if list
    // in this field should be. The administrator can omit fields for empty lists.
    pub(crate) ban: Option<HashSet<String>>,
    pub(crate) exception: Option<HashSet<String>>,
    pub(crate) client_limit: Option<usize>,
    pub(crate) invite_exception: Option<HashSet<String>>,
    pub(crate) key: Option<String>,
    pub(crate) operators: Option<HashSet<String>>,
    pub(crate) half_operators: Option<HashSet<String>>,
    pub(crate) voices: Option<HashSet<String>>,
    pub(crate) founders: Option<HashSet<String>>,
    pub(crate) protecteds: Option<HashSet<String>>,
    pub(crate) invite_only: bool,
    pub(crate) moderated: bool,
    pub(crate) secret: bool,
    pub(crate) protected_topic: bool,
    pub(crate) no_external_messages: bool,
}

impl ChannelModes {
    // create new channel modes for new channel created by user. By default,
    // user that created channel is founder and operator in this channel.
    pub(crate) fn new_for_channel(user_nick: String) -> Self {
        ChannelModes {
            operators: Some([user_nick.clone()].into()),
            founders: Some([user_nick].into()),
            ..ChannelModes::default()
        }
    }

    pub(crate) fn banned(&self, source: &str) -> bool {
        self.ban
            .as_ref()
            .map_or(false, |b| b.iter().any(|b| match_wildcard(b, source)))
            && (!self
                .exception
                .as_ref()
                .map_or(false, |e| e.iter().any(|e| match_wildcard(e, source))))
    }

    // rename user - just rename nick in lists.
    pub(crate) fn rename_user(&mut self, old_nick: &String, nick: String) {
        if let Some(ref mut operators) = self.operators {
            if operators.remove(old_nick) {
                operators.insert(nick.clone());
            }
        }
        if let Some(ref mut half_operators) = self.half_operators {
            if half_operators.remove(old_nick) {
                half_operators.insert(nick.clone());
            }
        }
        if let Some(ref mut voices) = self.voices {
            if voices.remove(old_nick) {
                voices.insert(nick.clone());
            }
        }
        if let Some(ref mut founders) = self.founders {
            if founders.remove(old_nick) {
                founders.insert(nick.clone());
            }
        }
        if let Some(ref mut protecteds) = self.protecteds {
            if protecteds.remove(old_nick) {
                protecteds.insert(nick);
            }
        }
    }
}

impl fmt::Display for ChannelModes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = '+'.to_string();
        if self.invite_only {
            s.push('i');
        }
        if self.moderated {
            s.push('m');
        }
        if self.secret {
            s.push('s');
        }
        if self.protected_topic {
            s.push('t');
        }
        if self.no_external_messages {
            s.push('n');
        }
        if self.key.is_some() {
            s.push('k');
        }
        if self.client_limit.is_some() {
            s.push('l');
        }
        if let Some(ref k) = self.key {
            s.push(' ');
            s += k;
        }
        if let Some(l) = self.client_limit {
            s.push(' ');
            s += &l.to_string();
        }
        if let Some(ref ban) = self.ban {
            ban.iter().for_each(|b| {
                s += " +b ";
                s += b;
            });
        }
        if let Some(ref exception) = self.exception {
            exception.iter().for_each(|e| {
                s += " +e ";
                s += e;
            });
        }
        if let Some(ref invite_exception) = self.invite_exception {
            invite_exception.iter().for_each(|i| {
                s += " +I ";
                s += i;
            });
        }

        if let Some(ref founders) = self.founders {
            founders.iter().for_each(|q| {
                s += " +q ";
                s += q;
            });
        }
        if let Some(ref protecteds) = self.protecteds {
            protecteds.iter().for_each(|a| {
                s += " +a ";
                s += a;
            });
        }
        if let Some(ref operators) = self.operators {
            operators.iter().for_each(|o| {
                s += " +o ";
                s += o;
            });
        }
        if let Some(ref half_operators) = self.half_operators {
            half_operators.iter().for_each(|h| {
                s += " +h ";
                s += h;
            });
        }
        if let Some(ref voices) = self.voices {
            voices.iter().for_each(|v| {
                s += " +v ";
                s += v;
            });
        }
        f.write_str(&s)
    }
}

#[derive(PartialEq, Eq, Deserialize, Debug, Validate)]
pub(crate) struct ChannelConfig {
    #[validate(custom = "validate_channel")]
    pub(crate) name: String,
    pub(crate) topic: Option<String>,
    #[validate]
    pub(crate) modes: ChannelModes,
}

#[derive(PartialEq, Eq, Deserialize, Debug, Validate)]
pub(crate) struct UserConfig {
    #[validate(custom = "validate_username")]
    pub(crate) name: String,
    #[validate(custom = "validate_username")]
    pub(crate) nick: String,
    #[validate(length(min = 6))]
    #[validate(custom = "validate_password_hash")]
    pub(crate) password: Option<String>,
    pub(crate) mask: Option<String>,
}

/// Main configuration structure.
#[derive(PartialEq, Eq, Deserialize, Debug, Validate)]
pub(crate) struct MainConfig {
    #[validate(contains = ".")]
    pub(crate) name: String,
    pub(crate) admin_info: String,
    pub(crate) admin_info2: Option<String>,
    pub(crate) admin_email: Option<String>,
    pub(crate) info: String,
    pub(crate) motd: String,
    pub(crate) listen: IpAddr,
    pub(crate) port: u16,
    pub(crate) network: String,
    #[validate(custom = "validate_password_hash")]
    pub(crate) password: Option<String>,
    pub(crate) max_connections: Option<usize>,
    pub(crate) max_joins: Option<usize>,
    pub(crate) ping_timeout: u64,
    pub(crate) pong_timeout: u64,
    pub(crate) dns_lookup: bool,
    pub(crate) default_user_modes: UserModes,
    pub(crate) log_file: Option<String>,
    #[serde(deserialize_with = "tracing_log_level_deserialize")]
    pub(crate) log_level: tracing::Level,
    pub(crate) tls: Option<TLSConfig>,
    // If MainConfig modes we use Option to avoid unnecessary field definition if list
    // in this field should be. The administrator can omit fields for empty lists.
    #[validate]
    pub(crate) operators: Option<Vec<OperatorConfig>>,
    #[validate]
    pub(crate) users: Option<Vec<UserConfig>>,
    #[validate]
    pub(crate) channels: Option<Vec<ChannelConfig>>,
}

struct TracingLevelVisitor;

impl<'de> serde::de::Visitor<'de> for TracingLevelVisitor {
    type Value = tracing::Level;
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("TracingLevel")
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        tracing::Level::from_str(v).map_err(|e| serde::de::Error::custom(e))
    }
}

fn tracing_log_level_deserialize<'de, D: Deserializer<'de>>(
    ds: D,
) -> Result<tracing::Level, D::Error> {
    ds.deserialize_str(TracingLevelVisitor)
}

impl MainConfig {
    // create new main config from command line.
    pub(crate) fn new(cli: Cli) -> Result<MainConfig, Box<dyn Error>> {
        // get config path.
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
            if let Some(log_file) = cli.log_file {
                config.log_file = Some(log_file)
            }
            config.dns_lookup = config.dns_lookup || cli.dns_lookup;

            // get indicator to check later
            let (have_cert, have_cert_key) =
                (cli.tls_cert_file.is_some(), cli.tls_cert_key_file.is_some());

            if let Some(tls_cert_file) = cli.tls_cert_file {
                if let Some(tls_cert_key_file) = cli.tls_cert_key_file {
                    config.tls = Some(TLSConfig {
                        cert_file: tls_cert_file,
                        cert_key_file: tls_cert_key_file,
                    });
                }
            }
            // both config are required
            if (have_cert && !have_cert_key) || (!have_cert && have_cert_key) {
                return Err(Box::new(clap::error::Error::raw(
                    clap::ErrorKind::ValueValidation,
                    "TLS certifcate file and certificate \
                        key file together are required",
                )));
            }
            if let Err(e) = config.validate() {
                Err(Box::new(e))
            } else if !config.validate_nicknames() {
                Err(Box::new(clap::error::Error::raw(
                    clap::ErrorKind::ValueValidation,
                    "Wrong nikname lengths",
                )))
            } else {
                Ok(config)
            }
        }
    }

    fn validate_nicknames(&self) -> bool {
        if let Some(ref users) = self.users {
            !users.iter().any(|u| u.nick.len() > 200)
        } else {
            true
        }
    }
}

impl Default for MainConfig {
    fn default() -> Self {
        MainConfig {
            name: "irc.irc".to_string(),
            admin_info: "ircadmin is IRC admin".to_string(),
            admin_info2: None,
            admin_email: None,
            info: "This is IRC server".to_string(),
            listen: "127.0.0.1".parse().unwrap(),
            port: 6667,
            network: "IRCnetwork".to_string(),
            password: None,
            motd: "Hello, world!".to_string(),
            max_connections: None,
            max_joins: None,
            ping_timeout: 120,
            pong_timeout: 20,
            dns_lookup: false,
            channels: None,
            operators: None,
            users: None,
            default_user_modes: UserModes::default(),
            tls: None,
            log_file: None,
            log_level: tracing::Level::INFO,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::env::temp_dir;
    use std::fs;

    struct TempFileHandle {
        path: String,
    }

    impl TempFileHandle {
        fn new(path: &str) -> TempFileHandle {
            TempFileHandle {
                path: temp_dir().join(path).to_string_lossy().to_string(),
            }
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
        let cli = Cli {
            config: Some(file_handle.path.clone()),
            gen_password_hash: false,
            password: None,
            listen: None,
            port: None,
            name: None,
            network: None,
            dns_lookup: false,
            tls_cert_file: None,
            tls_cert_key_file: None,
            log_file: None,
        };

        fs::write(
            file_handle.path.as_str(),
            r##"
name = "irci.localhost"
admin_info = "IRCI is local IRC server"
admin_info2 = "IRCI is good server"
info = "This is IRCI server"
listen = "127.0.0.1"
port = 6667
password = "VgWezXctjWvsY6V7gzSQPnluUuAwq06m5IxwcIg3OfBIMM+zWCJntk8HEZDgh4ctFei3bqt1r0O1VIyOV7dL+w"
network = "IRCInetwork"
max_connections = 4000
max_joins = 10
ping_timeout = 100
pong_timeout = 30
motd = "Hello, guys!"
dns_lookup = false
log_level = "INFO"

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
password = "u1hG814j88zYGsEZoKba2op9ems63On/QsqWWTFvEkUWaZFkzcr4Bri/sUIG5+u01qbfQ+GWF+PMXNFIPCJdag"

[[channels]]
name = "#channel1"
topic = "Some topic"
[channels.modes]
ban = [ 'baddi@*', 'baddi2@*' ]
exception = [ 'bobby@*', 'mati@*' ]
moderated = false
invite_only = false
secret = false
protected_topic = false
no_external_messages = false

[[users]]
name = "lucas"
nick = "luckboy"
password = "DGEKj3C60CRBF+eQQF9HCmt26ofniR373G54P9D2FsxzSXzq639lUsgEeQRlMtutYUf/nWnYSOKWIVyeMtK+ug"

[[channels]]
name = "#channel2"
topic = "Some topic 2"
[channels.modes]
key = "hokus pokus"
ban = []
exception = []
invite_exception = [ "nomi@buru.com", "pampam@zerox.net" ]
operators = [ "banny", "rorry" ]
moderated = true
invite_only = true
client_limit = 200
secret = false
protected_topic = true
no_external_messages = false
"##,
        )
        .unwrap();
        let result = MainConfig::new(cli.clone()).map_err(|e| e.to_string());
        assert_eq!(
            Ok(MainConfig {
                name: "irci.localhost".to_string(),
                admin_info: "IRCI is local IRC server".to_string(),
                admin_info2: Some("IRCI is good server".to_string()),
                admin_email: None,
                info: "This is IRCI server".to_string(),
                listen: "127.0.0.1".parse().unwrap(),
                port: 6667,
                password: Some(
                    "VgWezXctjWvsY6V7gzSQPnluUuAwq06m5IxwcIg3OfBIMM+zWCJntk8HEZDgh\
                        4ctFei3bqt1r0O1VIyOV7dL+w"
                        .to_string()
                ),
                motd: "Hello, guys!".to_string(),
                network: "IRCInetwork".to_string(),
                max_connections: Some(4000),
                max_joins: Some(10),
                ping_timeout: 100,
                pong_timeout: 30,
                dns_lookup: false,
                log_file: None,
                log_level: tracing::Level::INFO,
                tls: Some(TLSConfig {
                    cert_file: "cert.crt".to_string(),
                    cert_key_file: "cert_key.crt".to_string()
                }),
                default_user_modes: UserModes {
                    invisible: false,
                    oper: false,
                    local_oper: false,
                    registered: true,
                    wallops: false,
                },
                operators: Some(vec![OperatorConfig {
                    name: "matiszpaki".to_string(),
                    password: "u1hG814j88zYGsEZoKba2op9ems63On/QsqWWTFvEkUWaZFkzcr\
                        4Bri/sUIG5+u01qbfQ+GWF+PMXNFIPCJdag"
                        .to_string(),
                    mask: None
                }]),
                users: Some(vec![UserConfig {
                    name: "lucas".to_string(),
                    nick: "luckboy".to_string(),
                    password: Some(
                        "DGEKj3C60CRBF+eQQF9HCmt26ofniR373G54P9D2FsxzSXzq639l\
                            UsgEeQRlMtutYUf/nWnYSOKWIVyeMtK+ug"
                            .to_string()
                    ),
                    mask: None
                }]),
                channels: Some(vec![
                    ChannelConfig {
                        name: "#channel1".to_string(),
                        topic: Some("Some topic".to_string()),
                        modes: ChannelModes {
                            key: None,
                            ban: Some(["baddi@*".to_string(), "baddi2@*".to_string()].into()),
                            exception: Some(["bobby@*".to_string(), "mati@*".to_string()].into()),
                            invite_exception: None,
                            operators: None,
                            half_operators: None,
                            voices: None,
                            founders: None,
                            protecteds: None,
                            client_limit: None,
                            invite_only: false,
                            moderated: false,
                            secret: false,
                            protected_topic: false,
                            no_external_messages: false
                        },
                    },
                    ChannelConfig {
                        name: "#channel2".to_string(),
                        topic: Some("Some topic 2".to_string()),
                        modes: ChannelModes {
                            key: Some("hokus pokus".to_string()),
                            ban: Some([].into()),
                            exception: Some([].into()),
                            invite_exception: Some(
                                ["nomi@buru.com".to_string(), "pampam@zerox.net".to_string()]
                                    .into()
                            ),
                            operators: Some(["banny".to_string(), "rorry".to_string()].into()),
                            half_operators: None,
                            voices: None,
                            founders: None,
                            protecteds: None,
                            client_limit: Some(200),
                            invite_only: true,
                            moderated: true,
                            secret: false,
                            protected_topic: true,
                            no_external_messages: false
                        },
                    },
                ]),
            }),
            result
        );

        let cli2 = Cli {
            config: Some(file_handle.path.clone()),
            gen_password_hash: false,
            password: None,
            listen: Some("192.168.1.4".parse().unwrap()),
            port: Some(6668),
            name: Some("ircer.localhost".to_string()),
            network: Some("SomeNetwork".to_string()),
            dns_lookup: true,
            tls_cert_file: Some("some_cert.crt".to_string()),
            tls_cert_key_file: Some("some_key.crt".to_string()),
            log_file: Some("irc.log".to_string()),
        };

        let result = MainConfig::new(cli2).map_err(|e| e.to_string());
        assert_eq!(
            Ok(MainConfig {
                name: "ircer.localhost".to_string(),
                admin_info: "IRCI is local IRC server".to_string(),
                admin_info2: Some("IRCI is good server".to_string()),
                admin_email: None,
                info: "This is IRCI server".to_string(),
                listen: "192.168.1.4".parse().unwrap(),
                port: 6668,
                password: Some(
                    "VgWezXctjWvsY6V7gzSQPnluUuAwq06m5IxwcIg3OfBIMM+zWCJntk8HEZDgh\
                        4ctFei3bqt1r0O1VIyOV7dL+w"
                        .to_string()
                ),
                motd: "Hello, guys!".to_string(),
                network: "SomeNetwork".to_string(),
                max_connections: Some(4000),
                max_joins: Some(10),
                ping_timeout: 100,
                pong_timeout: 30,
                dns_lookup: true,
                log_file: Some("irc.log".to_string()),
                log_level: tracing::Level::INFO,
                tls: Some(TLSConfig {
                    cert_file: "some_cert.crt".to_string(),
                    cert_key_file: "some_key.crt".to_string()
                }),
                default_user_modes: UserModes {
                    invisible: false,
                    oper: false,
                    local_oper: false,
                    registered: true,
                    wallops: false,
                },
                operators: Some(vec![OperatorConfig {
                    name: "matiszpaki".to_string(),
                    password: "u1hG814j88zYGsEZoKba2op9ems63On/QsqWWTFvEkUWaZFkzcr\
                        4Bri/sUIG5+u01qbfQ+GWF+PMXNFIPCJdag"
                        .to_string(),
                    mask: None
                }]),
                users: Some(vec![UserConfig {
                    name: "lucas".to_string(),
                    nick: "luckboy".to_string(),
                    password: Some(
                        "DGEKj3C60CRBF+eQQF9HCmt26ofniR373G54P9D2FsxzSXzq639l\
                            UsgEeQRlMtutYUf/nWnYSOKWIVyeMtK+ug"
                            .to_string()
                    ),
                    mask: None
                }]),
                channels: Some(vec![
                    ChannelConfig {
                        name: "#channel1".to_string(),
                        topic: Some("Some topic".to_string()),
                        modes: ChannelModes {
                            key: None,
                            ban: Some(["baddi@*".to_string(), "baddi2@*".to_string()].into()),
                            exception: Some(["bobby@*".to_string(), "mati@*".to_string()].into()),
                            invite_exception: None,
                            operators: None,
                            half_operators: None,
                            voices: None,
                            founders: None,
                            protecteds: None,
                            client_limit: None,
                            invite_only: false,
                            moderated: false,
                            secret: false,
                            protected_topic: false,
                            no_external_messages: false
                        },
                    },
                    ChannelConfig {
                        name: "#channel2".to_string(),
                        topic: Some("Some topic 2".to_string()),
                        modes: ChannelModes {
                            key: Some("hokus pokus".to_string()),
                            ban: Some([].into()),
                            exception: Some([].into()),
                            invite_exception: Some(
                                ["nomi@buru.com".to_string(), "pampam@zerox.net".to_string()]
                                    .into()
                            ),
                            operators: Some(["banny".to_string(), "rorry".to_string()].into()),
                            half_operators: None,
                            voices: None,
                            founders: None,
                            protecteds: None,
                            client_limit: Some(200),
                            invite_only: true,
                            moderated: true,
                            secret: false,
                            protected_topic: true,
                            no_external_messages: false
                        },
                    },
                ]),
            }),
            result
        );

        let cli2 = Cli {
            config: Some(file_handle.path.clone()),
            gen_password_hash: false,
            password: None,
            listen: Some("192.168.1.4".parse().unwrap()),
            port: Some(6668),
            name: Some("ircer.localhost".to_string()),
            network: Some("SomeNetwork".to_string()),
            dns_lookup: true,
            tls_cert_file: Some("some_cert.crt".to_string()),
            tls_cert_key_file: None,
            log_file: None,
        };
        let result = MainConfig::new(cli2).map_err(|e| e.to_string());
        assert_eq!(
            Err(
                "error: TLS certifcate file and certificate key file together \
                are required"
                    .to_string()
            ),
            result
        );

        // next testcase
        fs::write(
            file_handle.path.as_str(),
            r##"
name = "irci.localhost"
admin_info = "IRCI is local IRC server"
admin_info2 = "IRCI is good server"
info = "This is IRCI server"
listen = "127.0.0.1"
port = 6667
motd = "Hello, guys!"
network = "IRCInetwork"
ping_timeout = 100
pong_timeout = 30
dns_lookup = false
log_file = "log.log"
log_level = "INFO"

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
invite_only = false
secret = false
protected_topic = false
no_external_messages = false

[[channels]]
name = "#channel2"
topic = "Some topic 2"
[channels.modes]
moderated = true
secret = false
invite_only = false
protected_topic = true
no_external_messages = false
"##,
        )
        .unwrap();
        let result = MainConfig::new(cli.clone()).map_err(|e| e.to_string());
        assert_eq!(
            Ok(MainConfig {
                name: "irci.localhost".to_string(),
                admin_info: "IRCI is local IRC server".to_string(),
                admin_info2: Some("IRCI is good server".to_string()),
                admin_email: None,
                info: "This is IRCI server".to_string(),
                listen: "127.0.0.1".parse().unwrap(),
                port: 6667,
                password: None,
                motd: "Hello, guys!".to_string(),
                network: "IRCInetwork".to_string(),
                max_connections: None,
                max_joins: None,
                ping_timeout: 100,
                pong_timeout: 30,
                dns_lookup: false,
                log_file: Some("log.log".to_string()),
                log_level: tracing::Level::INFO,
                tls: None,
                default_user_modes: UserModes {
                    invisible: false,
                    oper: false,
                    local_oper: false,
                    registered: true,
                    wallops: false,
                },
                operators: None,
                users: None,
                channels: Some(vec![
                    ChannelConfig {
                        name: "#channel1".to_string(),
                        topic: Some("Some topic".to_string()),
                        modes: ChannelModes {
                            key: None,
                            ban: Some(["baddi@*".to_string(), "baddi2@*".to_string()].into()),
                            exception: Some(["bobby@*".to_string(), "mati@*".to_string()].into()),
                            invite_exception: None,
                            operators: None,
                            half_operators: None,
                            voices: None,
                            founders: None,
                            protecteds: None,
                            client_limit: None,
                            invite_only: false,
                            moderated: false,
                            secret: false,
                            protected_topic: false,
                            no_external_messages: false
                        },
                    },
                    ChannelConfig {
                        name: "#channel2".to_string(),
                        topic: Some("Some topic 2".to_string()),
                        modes: ChannelModes {
                            key: None,
                            ban: None,
                            exception: None,
                            invite_exception: None,
                            operators: None,
                            half_operators: None,
                            voices: None,
                            founders: None,
                            protecteds: None,
                            client_limit: None,
                            invite_only: false,
                            moderated: true,
                            secret: false,
                            protected_topic: true,
                            no_external_messages: false
                        },
                    },
                ]),
            }),
            result
        );

        // error
        fs::write(
            file_handle.path.as_str(),
            r##"
name = "ircilocalhost"
admin_info = "IRCI is local IRC server"
admin_info2 = "IRCI is good server"
info = "This is IRCI server"
listen = "127.0.0.1"
port = 6667
motd = "Hello, guys!"
network = "IRCInetwork"
max_connections = 4000
max_joins = 10
ping_timeout = 100
pong_timeout = 30
dns_lookup = false
log_level = "INFO"

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
password = "VgWezXctjWvsY6V7gzSQPnluUuAwq06m5IxwcIg3OfBIMM+zWCJntk8HEZDgh4ctFei3bqt1r0O1VIyOV7dL+w"

[[channels]]
name = "#channel1"
topic = "Some topic"
[channels.modes]
ban = [ 'baddi@*', 'baddi2@*' ]
exception = [ 'bobby@*', 'mati@*' ]
moderated = false
invite_only = false
secret = false
protected_topic = false
no_external_messages = false

[[users]]
name = "lucas"
nick = "luckboy"
password = "u1hG814j88zYGsEZoKba2op9ems63On/QsqWWTFvEkUWaZFkzcr4Bri/sUIG5+u01qbfQ+GWF+PMXNFIPCJdag"

[[channels]]
name = "#channel2"
topic = "Some topic 2"
[channels.modes]
key = "hokus pokus"
ban = []
exception = []
invite_exception = [ "nomi@buru.com", "pampam@zerox.net" ]
moderated = true
invite_only = true
client_limit = 200
secret = false
protected_topic = true
no_external_messages = false
"##,
        )
        .unwrap();
        let result = MainConfig::new(cli.clone()).map_err(|e| e.to_string());
        // because sorting of ValidationErrors changes order we check to cases
        assert!(
            Err(
                "name: Validation error: contains [{\"value\": String(\"ircilocalhost\"), \
\"needle\": String(\".\")}]"
                    .to_string()
            ) == result
                || Err(
                    "name: Validation error: contains [{\"needle\": String(\".\"), \
\"value\": String(\"ircilocalhost\")}]"
                        .to_string()
                ) == result
        );

        fs::write(
            file_handle.path.as_str(),
            r##"
name = "irci.localhost"
admin_info = "IRCI is local IRC server"
admin_info2 = "IRCI is good server"
info = "This is IRCI server"
listen = "127.0.0.1"
port = 6667
motd = "Hello, guys!"
network = "IRCInetwork"
max_connections = 4000
max_joins = 10
ping_timeout = 100
pong_timeout = 30
dns_lookup = false
log_level = "INFO"

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
password = "u1hG814j88zYGsEZoKba2op9ems63On/QsqWWTFvEkUWaZFkzcr4Bri/sUIG5+u01qbfQ+GWF+PMXNFIPCJdag"

[[channels]]
name = "#channel1"
topic = "Some topic"
[channels.modes]
ban = [ 'baddi@*', 'baddi2@*' ]
exception = [ 'bobby@*', 'mati@*' ]
moderated = false
secret = false
invite_only = false
protected_topic = false
no_external_messages = false

[[users]]
name = "lucas"
nick = "luckboy"
password = "DGEKj3C60CRBF+eQQF9HCmt26ofniR373G54P9D2FsxzSXzq639lUsgEeQRlMtutYUf/nWnYSOKWIVyeMtK+ug"

[[channels]]
name = "#channel2"
topic = "Some topic 2"
[channels.modes]
key = "hokus pokus"
ban = []
exception = []
invite_exception = [ "nomi@buru.com", "pampam@zerox.net" ]
moderated = true
invite_only = true
client_limit = 200
secret = false
protected_topic = true
no_external_messages = false
"##,
        )
        .unwrap();
        let result = MainConfig::new(cli.clone()).map_err(|e| e.to_string());
        assert_eq!(
            Err("operators[0].name: Validation error: Username must not \
contains '.', ',' or ':'. [{\"value\": String(\"matis.zpaki\")}]"
                .to_string()),
            result
        );

        fs::write(
            file_handle.path.as_str(),
            r##"
name = "irci.localhost"
admin_info = "IRCI is local IRC server"
admin_info2 = "IRCI is good server"
info = "This is IRCI server"
listen = "127.0.0.1"
port = 6667
motd = "Hello, guys!"
network = "IRCInetwork"
max_connections = 4000
max_joins = 10
ping_timeout = 100
pong_timeout = 30
dns_lookup = false
log_level = "INFO"

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
password = "u1hG814j88zYGsEZoKba2op9ems63On/QsqWWTFvEkUWaZFkzcr4Bri/sUIG5+u01qbfQ+GWF+PMXNFIPCJdag"

[[channels]]
name = "#channel1"
topic = "Some topic"
[channels.modes]
ban = [ 'baddi@*', 'baddi2@*' ]
exception = [ 'bobby@*', 'mati@*' ]
moderated = false
invite_only = false
secret = false
protected_topic = false
no_external_messages = false

[[users]]
name = "lucas"
nick = "luckboy"
password = "DGEKj3C60CRBF+eQQF9HCmt26ofniR373G54P9D2FsxzSXzq639lUsgEeQRlMtutYUf/nWnYSOKWIVyeMtK+ug"

[[channels]]
name = "#channel2"
topic = "Some topic 2"
[channels.modes]
key = "hokus pokus"
ban = []
exception = []
invite_exception = [ "nomi@buru.com", "pampam@zerox.net" ]
moderated = true
invite_only = true
client_limit = 200
secret = false
protected_topic = true
no_external_messages = false
"##,
        )
        .unwrap();
        let result = MainConfig::new(cli.clone()).map_err(|e| e.to_string());
        assert_eq!(
            Err("operators[0].name: Validation error: Username must not \
contains '.', ',' or ':'. [{\"value\": String(\"matis:zpaki\")}]"
                .to_string()),
            result
        );

        fs::write(
            file_handle.path.as_str(),
            r##"
name = "irci.localhost"
admin_info = "IRCI is local IRC server"
admin_info2 = "IRCI is good server"
info = "This is IRCI server"
listen = "127.0.0.1"
port = 6667
motd = "Hello, guys!"
network = "IRCInetwork"
max_connections = 4000
max_joins = 10
ping_timeout = 100
pong_timeout = 30
dns_lookup = false
log_level = "INFO"

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
password = "u1hG814j88zYGsEZoKba2op9ems63On/QsqWWTFvEkUWaZFkzcr4Bri/sUIG5+u01qbfQ+GWF+PMXNFIPCJdag"

[[channels]]
name = "#channel1"
topic = "Some topic"
[channels.modes]
ban = [ 'baddi@*', 'baddi2@*' ]
exception = [ 'bobby@*', 'mati@*' ]
moderated = false
invite_only = false
secret = false
protected_topic = false
no_external_messages = false

[[users]]
name = "lucas"
nick = "luckboy"
password = "DGEKj3C60CRBF+eQQF9HCmt26ofniR373G54P9D2FsxzSXzq639lUsgEeQRlMtutYUf/nWnYSOKWIVyeMtK+ug"

[[channels]]
name = "^channel2"
topic = "Some topic 2"
[channels.modes]
key = "hokus pokus"
ban = []
exception = []
invite_exception = [ "nomi@buru.com", "pampam@zerox.net" ]
moderated = true
invite_only = true
client_limit = 200
secret = false
protected_topic = true
no_external_messages = false
"##,
        )
        .unwrap();
        let result = MainConfig::new(cli.clone()).map_err(|e| e.to_string());
        assert_eq!(
            Err(
                "channels[1].name: Validation error: Channel name must have '#' or \
'&' at start and must not contains ',' or ':'. [{\"value\": String(\"^channel2\")}]"
                    .to_string()
            ),
            result
        );

        fs::write(
            file_handle.path.as_str(),
            r##"
name = "irci.localhost"
admin_info = "IRCI is local IRC server"
admin_info2 = "IRCI is good server"
info = "This is IRCI server"
listen = "127.0.0.1"
port = 6667
motd = "Hello, guys!"
network = "IRCInetwork"
max_connections = 4000
max_joins = 10
ping_timeout = 100
pong_timeout = 30
dns_lookup = false
log_level = "INFO"

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
password = "u1hG814j88zYGsEZoKba2op9ems63On/QsqWWTFvEkUWaZFkzcr4Bri/sUIG5+u01qbfQ+GWF+PMXNFIPCJdag"

[[channels]]
name = "#channel1"
topic = "Some topic"
[channels.modes]
ban = [ 'baddi@*', 'baddi2@*' ]
exception = [ 'bobby@*', 'mati@*' ]
moderated = false
invite_only = false
secret = false
protected_topic = false
no_external_messages = false

[[users]]
name = "lucas"
nick = "luckboy"
password = "DGEKj3C60CRBF+eQQF9HCmt26ofniR373G54P9D2FsxzSXzq639lUsgEeQRlMtutYUf/nWnYSOKWIVyeMtK+ug"

[[channels]]
name = "#cha:nnel2"
topic = "Some topic 2"
[channels.modes]
key = "hokus pokus"
ban = []
exception = []
invite_exception = [ "nomi@buru.com", "pampam@zerox.net" ]
moderated = true
invite_only = true
client_limit = 200
secret = false
protected_topic = true
no_external_messages = false
"##,
        )
        .unwrap();
        let result = MainConfig::new(cli.clone()).map_err(|e| e.to_string());
        assert_eq!(
            Err(
                "channels[1].name: Validation error: Channel name must have '#' or \
'&' at start and must not contains ',' or ':'. \
[{\"value\": String(\"#cha:nnel2\")}]"
                    .to_string()
            ),
            result
        );

        fs::write(
            file_handle.path.as_str(),
            r##"
name = "irci.localhost"
admin_info = "IRCI is local IRC server"
admin_info2 = "IRCI is good server"
info = "This is IRCI server"
listen = "127.0.0.1"
port = 6667
password = "814j88zYGsEZoKba2op9ems63On/QsqWWTFvEkUWaZFkzcr4Bri/sUIG5+u01qbfQ+GWF+PMXNFIPCJdag"
motd = "Hello, guys!"
network = "IRCInetwork"
max_connections = 4000
max_joins = 10
ping_timeout = 100
pong_timeout = 30
dns_lookup = false
log_level = "INFO"

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
password = "u1hG814j88zYGsEZoKba2op9ems63On/QsqWWTFvEkUWaZFkzcr4Bri/sUIG5+u01qbfQ+GWF+PMXNFIPCJdag"

[[channels]]
name = "#channel1"
topic = "Some topic"
[channels.modes]
ban = [ 'baddi@*', 'baddi2@*' ]
exception = [ 'bobby@*', 'mati@*' ]
moderated = false
invite_only = false
secret = false
protected_topic = false
no_external_messages = false

[[users]]
name = "lucas"
nick = "luckboy"
password = "DGEKj3C60CRBF+eQQF9HCmt26ofniR373G54P9D2FsxzSXzq639lUsgEeQRlMtutYUf/nWnYSOKWIVyeMtK+ug"

[[channels]]
name = "#channel2"
topic = "Some topic 2"
[channels.modes]
key = "hokus pokus"
ban = []
exception = []
invite_exception = [ "nomi@buru.com", "pampam@zerox.net" ]
moderated = true
invite_only = true
client_limit = 200
secret = false
protected_topic = true
no_external_messages = false
"##,
        )
        .unwrap();
        let result = MainConfig::new(cli.clone()).map_err(|e| e.to_string());
        assert_eq!(
            Err("password: Validation error: Wrong password hash length \
        [{\"value\": String(\"814j88zYGsEZoKba2op9ems63On/QsqWWTFvEkUWaZFkzcr\
        4Bri/sUIG5+u01qbfQ+GWF+PMXNFIPCJdag\")}]"
                .to_string()),
            result
        );

        fs::write(
            file_handle.path.as_str(),
            r##"
name = "irci.localhost"
admin_info = "IRCI is local IRC server"
admin_info2 = "IRCI is good server"
info = "This is IRCI server"
listen = "127.0.0.1"
port = 6667
password = "xxxxxxxxxx"
motd = "Hello, guys!"
network = "IRCInetwork"
max_connections = 4000
max_joins = 10
ping_timeout = 100
pong_timeout = 30
dns_lookup = false
log_level = "INFO"

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
password = "u1hG814j88zYGsEZoKba2op9ems63On/QsqWWTFvEkUWaZFkzcr4Bri/sUIG5+u01qbfQ+GWF+PMXNFIPCJdag"

[[channels]]
name = "#channel1"
topic = "Some topic"
[channels.modes]
ban = [ 'baddi@*', 'baddi2@*' ]
exception = [ 'bobby@*', 'mati@*' ]
moderated = false
invite_only = false
secret = false
protected_topic = false
no_external_messages = false

[[users]]
name = "lucas"
nick = "luckboy"
password = "DGEKj3C60CRBF+eQQF9HCmt26ofniR373G54P9D2FsxzSXzq639lUsgEeQRlMtutYUf/nWnYSOKWIVyeMtK+ug"

[[channels]]
name = "#channel2"
topic = "Some topic 2"
[channels.modes]
key = "hokus pokus"
ban = []
exception = []
invite_exception = [ "nomi@buru.com", "pampam@zerox.net" ]
moderated = true
invite_only = true
client_limit = 200
secret = false
protected_topic = true
no_external_messages = false
"##,
        )
        .unwrap();
        let result = MainConfig::new(cli.clone()).map_err(|e| e.to_string());
        assert_eq!(
            Err("password: Validation error: Wrong base64 password hash \
                [{\"value\": String(\"xxxxxxxxxx\")}]"
                .to_string()),
            result
        );

        fs::write(
            file_handle.path.as_str(),
            r##"
name = "irci.localhost"
admin_info = "IRCI is local IRC server"
admin_info2 = "IRCI is good server"
info = "This is IRCI server"
listen = "127.0.0.1"
port = 6667
password = "VgWezXctjWvsY6V7gzSQPnluUuAwq06m5IxwcIg3OfBIMM+zWCJntk8HEZDgh4ctFei3bqt1r0O1VIyOV7dL+w"
motd = "Hello, guys!"
network = "IRCInetwork"
max_connections = 4000
max_joins = 10
ping_timeout = 100
pong_timeout = 30
dns_lookup = false
log_level = "INFO"

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
password = "xxxxxxx"

[[channels]]
name = "#channel1"
topic = "Some topic"
[channels.modes]
ban = [ 'baddi@*', 'baddi2@*' ]
exception = [ 'bobby@*', 'mati@*' ]
moderated = false
invite_only = false
secret = false
protected_topic = false
no_external_messages = false

[[users]]
name = "lucas"
nick = "luckboy"
password = "DGEKj3C60CRBF+eQQF9HCmt26ofniR373G54P9D2FsxzSXzq639lUsgEeQRlMtutYUf/nWnYSOKWIVyeMtK+ug"

[[channels]]
name = "#channel2"
topic = "Some topic 2"
[channels.modes]
key = "hokus pokus"
ban = []
exception = []
invite_exception = [ "nomi@buru.com", "pampam@zerox.net" ]
moderated = true
invite_only = true
client_limit = 200
secret = false
protected_topic = true
no_external_messages = false
"##,
        )
        .unwrap();
        let result = MainConfig::new(cli.clone()).map_err(|e| e.to_string());
        assert_eq!(
            Err(
                "operators[0].password: Validation error: Wrong base64 password \
                hash [{\"value\": String(\"xxxxxxx\")}]"
                    .to_string()
            ),
            result
        );

        fs::write(
            file_handle.path.as_str(),
            r##"
name = "irci.localhost"
admin_info = "IRCI is local IRC server"
admin_info2 = "IRCI is good server"
info = "This is IRCI server"
listen = "127.0.0.1"
port = 6667
password = "VgWezXctjWvsY6V7gzSQPnluUuAwq06m5IxwcIg3OfBIMM+zWCJntk8HEZDgh4ctFei3bqt1r0O1VIyOV7dL+w"
motd = "Hello, guys!"
network = "IRCInetwork"
max_connections = 4000
max_joins = 10
ping_timeout = 100
pong_timeout = 30
dns_lookup = false
log_level = "INFO"

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
password = "u1hG814j88zYGsEZoKba2op9ems63On/QsqWWTFvEkUWaZFkzcr4Bri/sUIG5+u01qbfQ+GWF+PMXNFIPCJdag"

[[channels]]
name = "#channel1"
topic = "Some topic"
[channels.modes]
ban = [ 'baddi@*', 'baddi2@*' ]
exception = [ 'bobby@*', 'mati@*' ]
moderated = false
invite_only = false
secret = false
protected_topic = false
no_external_messages = false

[[users]]
name = "lucas"
nick = "luckboy"
password = "xxxxxxxx"

[[channels]]
name = "#channel2"
topic = "Some topic 2"
[channels.modes]
key = "hokus pokus"
ban = []
exception = []
invite_exception = [ "nomi@buru.com", "pampam@zerox.net" ]
moderated = true
invite_only = true
client_limit = 200
secret = false
protected_topic = true
no_external_messages = false
"##,
        )
        .unwrap();
        let result = MainConfig::new(cli.clone()).map_err(|e| e.to_string());
        assert_eq!(
            Err(
                "users[0].password: Validation error: Wrong base64 password hash \
                [{\"value\": String(\"xxxxxxxx\")}]"
                    .to_string()
            ),
            result
        );
    }

    #[test]
    fn test_usermodes_to_string() {
        assert_eq!(
            "+oOr".to_string(),
            UserModes {
                invisible: false,
                oper: true,
                local_oper: true,
                registered: true,
                wallops: false
            }
            .to_string()
        );
        assert_eq!(
            "+irw".to_string(),
            UserModes {
                invisible: true,
                oper: false,
                local_oper: false,
                registered: true,
                wallops: true
            }
            .to_string()
        );
    }

    #[test]
    fn test_channelmodes_to_string() {
        assert_eq!(
            "+itnl 10 +I somebody +o expert".to_string(),
            ChannelModes {
                ban: None,
                exception: None,
                invite_exception: Some(["somebody".to_string()].into()),
                client_limit: Some(10),
                key: None,
                operators: Some(["expert".to_string()].into()),
                half_operators: None,
                voices: None,
                founders: None,
                protecteds: None,
                invite_only: true,
                moderated: false,
                secret: false,
                protected_topic: true,
                no_external_messages: true
            }
            .to_string()
        );
        let chm_str = ChannelModes {
            ban: Some(["somebody".to_string(), "somebody2".to_string()].into()),
            exception: None,
            invite_exception: None,
            client_limit: None,
            key: Some("password".to_string()),
            operators: Some(["expert".to_string()].into()),
            half_operators: Some(["spec".to_string()].into()),
            voices: None,
            founders: None,
            protecteds: None,
            invite_only: false,
            moderated: false,
            secret: true,
            protected_topic: true,
            no_external_messages: false,
        }
        .to_string();
        assert!(
            "+stk password +b somebody +b somebody2 +o expert +h spec" == chm_str
                || "+stk password +b somebody2 +b somebody +o expert +h spec" == chm_str
        );
        let chm_str = ChannelModes {
            ban: None,
            exception: None,
            invite_exception: Some(["somebody".to_string()].into()),
            client_limit: None,
            key: None,
            operators: None,
            half_operators: None,
            founders: None,
            protecteds: None,
            voices: Some(["guy1".to_string(), "guy2".to_string()].into()),
            invite_only: true,
            moderated: true,
            secret: false,
            protected_topic: false,
            no_external_messages: true,
        }
        .to_string();
        assert!(
            "+imn +I somebody +v guy1 +v guy2".to_string() == chm_str
                || "+imn +I somebody +v guy2 +v guy1".to_string() == chm_str
        );
        let chm_str = ChannelModes {
            ban: None,
            exception: None,
            invite_exception: Some(["somebody".to_string()].into()),
            client_limit: None,
            key: None,
            operators: None,
            half_operators: None,
            founders: Some(["guy1".to_string(), "guy2".to_string()].into()),
            protecteds: None,
            voices: None,
            invite_only: true,
            moderated: true,
            secret: false,
            protected_topic: false,
            no_external_messages: true,
        }
        .to_string();
        assert!(
            "+imn +I somebody +q guy1 +q guy2".to_string() == chm_str
                || "+imn +I somebody +q guy2 +q guy1".to_string() == chm_str
        );
        let chm_str = ChannelModes {
            ban: None,
            exception: None,
            invite_exception: Some(["somebody".to_string()].into()),
            client_limit: None,
            key: None,
            operators: None,
            half_operators: None,
            founders: None,
            protecteds: Some(["guy1".to_string(), "guy2".to_string()].into()),
            voices: None,
            invite_only: true,
            moderated: true,
            secret: false,
            protected_topic: false,
            no_external_messages: true,
        }
        .to_string();
        assert!(
            "+imn +I somebody +a guy1 +a guy2".to_string() == chm_str
                || "+imn +I somebody +a guy2 +a guy1".to_string() == chm_str
        );
    }

    #[test]
    fn test_channelmodes_new_for_channel() {
        let mut exp_chm = ChannelModes::default();
        exp_chm.founders = Some(["biggy".to_string()].into());
        exp_chm.operators = Some(["biggy".to_string()].into());
        assert_eq!(exp_chm, ChannelModes::new_for_channel("biggy".to_string()));
    }

    #[test]
    fn test_channelmodes_banned() {
        let mut chm = ChannelModes::default();
        chm.ban = Some(["bom!*@*".to_string()].into());
        assert!(chm.banned("bom!bom@gugu.com"));
        assert!(chm.banned("bom!bam@ggregi.com"));
        assert!(!chm.banned("bam!bom@gugu.com"));
        chm.exception = Some(["bom!*@ggregi*".to_string()].into());
        assert!(chm.banned("bom!bom@gugu.com"));
        assert!(!chm.banned("bom!bam@ggregi.com"));
        chm.exception = Some(["*!*@ggregi*".to_string()].into());
        assert!(chm.banned("bom!bom@gugu.com"));
        assert!(!chm.banned("bom!bam@ggregi.com"));
        chm.ban = Some(["bom!*@*".to_string(), "zigi!*@*".to_string()].into());
        assert!(chm.banned("bom!bom@gugu.com"));
        assert!(chm.banned("zigi!zigol@gugu.com"));
        assert!(!chm.banned("bom!bam@ggregi.com"));
        assert!(!chm.banned("zigi!zigol@ggregi.net"));
    }

    #[test]
    fn test_channelmodes_rename_user() {
        let mut chm = ChannelModes::default();
        chm.operators = Some(["bobby".to_string(), "gugu".to_string()].into());
        chm.half_operators = Some(["bobby".to_string(), "alice".to_string()].into());
        chm.voices = Some(["bobby".to_string(), "nolan".to_string()].into());
        chm.founders = Some(["bobby".to_string(), "ben".to_string()].into());
        chm.protecteds = Some(["bobby".to_string(), "irek".to_string()].into());
        chm.rename_user(&"bobby".to_string(), "robert".to_string());
        let mut exp_chm = ChannelModes::default();
        exp_chm.operators = Some(["robert".to_string(), "gugu".to_string()].into());
        exp_chm.half_operators = Some(["robert".to_string(), "alice".to_string()].into());
        exp_chm.voices = Some(["robert".to_string(), "nolan".to_string()].into());
        exp_chm.founders = Some(["robert".to_string(), "ben".to_string()].into());
        exp_chm.protecteds = Some(["robert".to_string(), "irek".to_string()].into());
        assert_eq!(exp_chm, chm);
    }
}
