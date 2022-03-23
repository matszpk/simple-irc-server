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

use std::fmt;
use std::rc::Rc;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, TcpStream};
use std::error::Error;
use bytes::{BufMut, BytesMut};
use clap;
use clap::Parser;
use toml;
use tokio;
use tokio_util::codec::{Framed, LinesCodec, Decoder, Encoder};
use dashmap::DashMap;

use config::*;
use reply::*;
use command::*;

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

struct User {
    name: String,
    nick: String,
    modes: UserModes,
    ip_addr: IpAddr,
    hostname: String,
    stream: Framed<TcpStream, IRCLinesCodec>,
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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let config = MainConfig::new(cli)?;
    println!("Hello, world!");
    Ok(())
}
