// utils.rs - commands
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
use bytes::{BufMut, BytesMut};
use tokio_util::codec::{Framed, LinesCodec, Decoder, Encoder};
use validator::ValidationError;

use crate::command::CommandId::*;
use crate::command::CommandError;
use crate::command::CommandError::*;

// special LinesCodec for IRC - encode with "\r\n".
pub(crate) struct IRCLinesCodec(LinesCodec);

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

pub fn validate_username(username: &str) -> Result<(), ValidationError> {
    if username.len() != 0 && (username.as_bytes()[0] == b'#' ||
            username.as_bytes()[0] == b'&') {
        Err(ValidationError::new("Username must not have channel prefix."))
    } else if !username.contains('.') && !username.contains(':') && !username.contains(',') {
        Ok(())
    } else {
        Err(ValidationError::new("Username must not contains '.', ',' or ':'."))
    }
}

pub fn validate_channel(channel: &str) -> Result<(), ValidationError> {
    if channel.len() != 0 && !channel.contains(':') && !channel.contains(',') &&
        (channel.as_bytes()[0] == b'#' || channel.as_bytes()[0] == b'&') {
        Ok(())
    } else {
        Err(ValidationError::new("Channel name must have '#' or '&' at start and \
                must not contains ',' or ':'."))
    }
}

pub(crate) fn validate_server<E: Error>(s: &str, e: E) -> Result<(), E> {
    if s.contains('.') { Ok(()) }
    else { Err(e) }
}

pub(crate) fn validate_server_mask<E: Error>(s: &str, e: E) -> Result<(), E>  {
    if s.contains('.') | s.contains('*') { Ok(()) }
    else { Err(e) }
}

pub(crate) fn validate_prefixed_channel<E: Error>(channel: &str, e: E) -> Result<(), E> {
    if channel.len() != 0 && !channel.contains(':') && !channel.contains(',') {
        let cfirst = channel.as_bytes()[0];
        if channel.len() >= 3 && cfirst==b'&' && (
            channel.as_bytes()[1] == b'&' || channel.as_bytes()[1] == b'#') {
            return Ok(());  // protected prefix
        }
        let channel = if cfirst == b'~' || cfirst == b'@' || cfirst == b'%' ||
                    cfirst == b'+' {
            &channel[1..]
        } else { channel };
        let cfirst = channel.as_bytes()[0];
        if cfirst == b'#' || cfirst == b'&' {
            Ok(())
        } else { Err(e) }
    } else { Err(e) }
}

pub(crate) fn validate_usermodes<'a>(modes: &Vec<(&'a str, Vec<&'a str>)>)
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

pub(crate) fn validate_channelmodes<'a>(modes: &Vec<(&'a str, Vec<&'a str>)>)
                -> Result<(), CommandError> {
    let mut param_idx = 1;
    modes.iter().try_for_each(|(ms, margs)| {
        if ms.len() != 0 {
            let mut args_char = ' ';
            let mut cur_mode_set = false;
            let mut mode_set = false;
            ms.chars().try_for_each(|c| {
                if c!='+' && c!='-' && c!='b' && c!='e' && c!='i' && c!='I' &&
                    c!='l' && c!='k' && c!='m' && c!='t' && c!='n' && c!='s' && c!='p' &&
                    c!='o' && c!='v' && c!='h' {
                    return Err(WrongParameter(MODEId, param_idx));
                }
                if c=='+' { cur_mode_set = true; }
                else if c=='-' { cur_mode_set = false; }
                // if found flag with argument
                if c=='b' || c=='e' || c=='I' || c=='o' || c=='v' || c=='h' ||
                        (cur_mode_set && (c=='l' || c=='k')) {
                    if args_char != ' ' {
                        return Err(WrongParameter(MODEId, param_idx));
                    }
                    args_char = c;
                    mode_set = cur_mode_set;
                }
                Ok(())
            })?;
            param_idx += 1;
            
            if margs.len() != 0 {
                match args_char {
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
                        }
                    }
                    // key
                    'k' => {
                        if mode_set {
                            if margs.len() != 1 {
                                return Err(WrongParameter(MODEId, param_idx));
                            }
                            param_idx += 1;
                        }
                    }
                    // lists
                    'b'|'e'|'I' => { param_idx += margs.len(); }
                    ' ' => { return Err(WrongParameter(MODEId, param_idx)); }
                    _ => { return Err(WrongParameter(MODEId, param_idx)); }
                }
            } else {
                match args_char {
                    'l'|'k' => {
                        if mode_set { return Err(WrongParameter(MODEId, param_idx-1)); }
                    }
                    'b'|'e'|'i'|'I'|'m'|'t'|'n'|'s'|'p' => { }
                    ' ' => {}
                    _ => { return Err(WrongParameter(MODEId, param_idx-1)); }
                }
            }
            
            Ok(())
        } else { // if empty
            Err(WrongParameter(MODEId, param_idx))
        }
    })
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
    
    #[test]
    fn test_validate_username() {
        assert_eq!(true, validate_username("ala").is_ok());
        assert_eq!(false, validate_username("#ala").is_ok());
        assert_eq!(false, validate_username("&ala").is_ok());
        assert_eq!(false, validate_username("a.la").is_ok());
        assert_eq!(false, validate_username("a,la").is_ok());
        assert_eq!(false, validate_username("aL:a").is_ok());
    }
    
    #[test]
    fn test_validate_channel() {
        assert_eq!(true, validate_channel("#ala").is_ok());
        assert_eq!(true, validate_channel("&ala").is_ok());
        assert_eq!(false, validate_channel("&al:a").is_ok());
        assert_eq!(false, validate_channel("&al,a").is_ok());
        assert_eq!(false, validate_channel("#al:a").is_ok());
        assert_eq!(false, validate_channel("#al,a").is_ok());
        assert_eq!(false, validate_channel("ala").is_ok());
    }
    
    #[test]
    fn test_validate_server() {
        assert_eq!(true, validate_server("somebody.org",
                WrongParameter(PINGId, 0)).is_ok());
        assert_eq!(false, validate_server("somebodyorg",
                WrongParameter(PINGId, 0)).is_ok());
    }
    
    #[test]
    fn test_validate_server_mask() {
        assert_eq!(true, validate_server_mask("somebody.org",
                WrongParameter(PINGId, 0)).is_ok());
        assert_eq!(true, validate_server_mask("*org",
                WrongParameter(PINGId, 0)).is_ok());
        assert_eq!(false, validate_server_mask("somebodyorg",
                WrongParameter(PINGId, 0)).is_ok());
    }
    
    #[test]
    fn test_validate_prefixed_channel() {
        assert_eq!(true, validate_prefixed_channel("#ala",
                WrongParameter(PINGId, 0)).is_ok());
        assert_eq!(true, validate_prefixed_channel("&ala",
                WrongParameter(PINGId, 0)).is_ok());
        assert_eq!(false, validate_prefixed_channel("&al:a",
                WrongParameter(PINGId, 0)).is_ok());
        assert_eq!(false, validate_prefixed_channel("&al,a",
                WrongParameter(PINGId, 0)).is_ok());
        assert_eq!(false, validate_prefixed_channel("#al:a",
                WrongParameter(PINGId, 0)).is_ok());
        assert_eq!(false, validate_prefixed_channel("#al,a",
                WrongParameter(PINGId, 0)).is_ok());
        assert_eq!(false, validate_prefixed_channel("ala",
                WrongParameter(PINGId, 0)).is_ok());
        
        assert_eq!(true, validate_prefixed_channel("~#ala",
                WrongParameter(PINGId, 0)).is_ok());
        assert_eq!(true, validate_prefixed_channel("+#ala",
                WrongParameter(PINGId, 0)).is_ok());
        assert_eq!(true, validate_prefixed_channel("%#ala",
                WrongParameter(PINGId, 0)).is_ok());
        assert_eq!(true, validate_prefixed_channel("&#ala",
                WrongParameter(PINGId, 0)).is_ok());
        assert_eq!(true, validate_prefixed_channel("@#ala",
                WrongParameter(PINGId, 0)).is_ok());
        assert_eq!(true, validate_prefixed_channel("~&ala",
                WrongParameter(PINGId, 0)).is_ok());
        assert_eq!(true, validate_prefixed_channel("+&ala",
                WrongParameter(PINGId, 0)).is_ok());
        assert_eq!(true, validate_prefixed_channel("%&ala",
                WrongParameter(PINGId, 0)).is_ok());
        assert_eq!(true, validate_prefixed_channel("&&ala",
                WrongParameter(PINGId, 0)).is_ok());
        assert_eq!(true, validate_prefixed_channel("@&ala",
                WrongParameter(PINGId, 0)).is_ok());
        assert_eq!(false, validate_prefixed_channel("*#ala",
                WrongParameter(PINGId, 0)).is_ok());
        assert_eq!(false, validate_prefixed_channel("*&ala",
                WrongParameter(PINGId, 0)).is_ok());
    }
    
    #[test]
    fn test_validate_usermodes() {
        assert_eq!(Ok(()), validate_usermodes(&vec![
            ("+io-rw", vec![]), ("-O", vec![])]).map_err(|e| e.to_string()));
        assert_eq!(Ok(()), validate_usermodes(&vec![
            ("+io", vec![]), ("-rO", vec![]), ("-w", vec![])])
                .map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 1 in command 'MODE'".to_string()),
            validate_usermodes(&vec![("+io-rw", vec!["xx"]),
                    ("-O", vec![])]).map_err(|e| e.to_string()));
        assert_eq!(Err("Wrong parameter 2 in command 'MODE'".to_string()),
            validate_usermodes(&vec![
                ("+io-rw", vec![]), ("-x", vec![])]).map_err(|e| e.to_string()));
    }
}
