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

use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use clap;
use clap::Parser;
use toml;
use serde_derive::{Serialize, Deserialize};
use validator::{Validate,ValidationError};

#[derive(clap::Parser, Clone)]
#[clap(author, version, about, long_about = None)]
pub(crate) struct Cli {
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

pub(crate) fn validate_username(username: &str) -> Result<(), ValidationError> {
    if username.len() != 0 && (username.as_bytes()[0] == b'#' ||
            username.as_bytes()[0] == b'&') {
        Err(ValidationError::new("Username must not have channel prefix."))
    } else if !username.contains('.') && !username.contains(':') && !username.contains(',') {
        Ok(())
    } else {
        Err(ValidationError::new("Username must not contains '.', ',' or ':'."))
    }
}

pub(crate) fn validate_channel(channel: &str) -> Result<(), ValidationError> {
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
pub(crate) struct UserModes {
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
pub(crate) struct ChannelModes {
    ban: Option<Vec<String>>,
    exception: Option<Vec<String>>,
    client_limit: Option<usize>,
    invite_exception: Option<Vec<String>>,
    key: Option<String>,
    operators: Option<Vec<String>>,
    half_operators: Option<Vec<String>>,
    voices: Option<Vec<String>>,
    private: bool,
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
pub(crate) struct MainConfig {
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
    pub(crate) fn new(cli: Cli) -> Result<MainConfig, Box<dyn Error>> {
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

#[cfg(test)]
mod test {
    use super::*;
    
    use std::env::temp_dir;
    use std::fs;
    
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
private = false
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
private = false
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
                        operators: None, half_operators: None, voices: None,
                        client_limit: None,
                        moderated: false, secret: false, protected_topic: false,
                        private: false, no_external_messages: false },
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
                        operators: None, half_operators: None, voices: None,
                        client_limit: Some(200),
                        moderated: true, secret: false, protected_topic: true,
                        private: false, no_external_messages: false },
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
                        operators: None, half_operators: None, voices: None,
                        client_limit: None,
                        moderated: false, secret: false, protected_topic: false,
                        private: false, no_external_messages: false },
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
                        operators: None, half_operators: None, voices: None,
                        client_limit: Some(200),
                        moderated: true, secret: false, protected_topic: true,
                        private: false, no_external_messages: false },
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
private = true
protected_topic = false
no_external_messages = false

[[channels]]
name = "#channel2"
topic = "Some topic 2"
[channels.modes]
moderated = true
secret = false
private = false
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
                        operators: None, half_operators: None, voices: None,
                        client_limit: None,
                        moderated: false, secret: false, protected_topic: false,
                        private: true, no_external_messages: false },
                },
                ChannelConfig{
                    name: "#channel2".to_string(),
                    topic: "Some topic 2".to_string(),
                    modes: ChannelModes{ key: None,
                        ban: None,
                        exception: None,
                        invite_exception: None,
                        operators: None, half_operators: None, voices: None,
                        client_limit: None,
                        moderated: true, secret: false, protected_topic: true,
                        private: false, no_external_messages: false },
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
private = false
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
private = false
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
private = false
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
private = false
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
private = false
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
private = false
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
private = false
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
private = false
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
private = false
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
private = false
protected_topic = true
no_external_messages = false
"##).unwrap();
        let result = MainConfig::new(cli.clone()).map_err(|e| e.to_string());
        assert_eq!(Err("channels[1].name: Validation error: Channel name must have '#' or \
'&' at start and must not contains ',' or ':'. \
[{\"value\": String(\"#cha:nnel2\")}]".to_string()), result);
    }
}
