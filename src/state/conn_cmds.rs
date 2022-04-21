// conn_cmds.rs - main state
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
use std::ops::DerefMut;
use std::sync::atomic::Ordering;
use super::ConnState;
use crate::command::*;
use crate::reply::*;
use crate::utils::*;
use Reply::*;
use super::User;

struct SupportTokenIntValue{ name: &'static str, value: usize }

static SUPPORT_TOKEN_INT_VALUE: [SupportTokenIntValue; 13] = [
    SupportTokenIntValue{ name: "AWAYLEN", value: 1000 },
    SupportTokenIntValue{ name: "CHANNELLEN", value: 1000 },
    SupportTokenIntValue{ name: "HOSTLEN", value: 1000 },
    SupportTokenIntValue{ name: "KEYLEN", value: 1000 },
    SupportTokenIntValue{ name: "KICKLEN", value: 1000 },
    SupportTokenIntValue{ name: "LINELEN", value: 2000 },
    SupportTokenIntValue{ name: "MAXNICKLEN", value: 200 },
    SupportTokenIntValue{ name: "MAXPARA", value: 500 },
    SupportTokenIntValue{ name: "MAXTARGETS", value: 500 },
    SupportTokenIntValue{ name: "MODES", value: 500 },
    SupportTokenIntValue{ name: "NICKLEN", value: 200 },
    SupportTokenIntValue{ name: "TOPICLEN", value: 1000 },
    SupportTokenIntValue{ name: "USERLEN", value: 200 },
];

impl ToString for SupportTokenIntValue {
    fn to_string(&self) -> String {
        let mut s = self.name.to_string();
        s.push('=');
        s.push_str(&self.value.to_string());
        s
    }
}

struct SupportTokenStringValue{ name: &'static str, value: &'static str }

static SUPPORT_TOKEN_STRING_VALUE: [SupportTokenStringValue; 9] = [
    SupportTokenStringValue{ name: "CASEMAPPING", value: "ascii" },
    SupportTokenStringValue{ name: "CHANMODES", value: "Iabehiklmnopqstv" },
    SupportTokenStringValue{ name: "CHANTYPES", value: "&#" },
    SupportTokenStringValue{ name: "EXCEPTS", value: "e" },
    SupportTokenStringValue{ name: "INVEX", value: "I" },
    SupportTokenStringValue{ name: "MAXLIST", value: "beI:1000" },
    SupportTokenStringValue{ name: "PREFIX", value: "(qaohv)~&@%+" },
    SupportTokenStringValue{ name: "STATUSMSG", value: "~&@%+" },
    SupportTokenStringValue{ name: "USERMODES", value: "Oiorw" },
];

impl ToString for SupportTokenStringValue {
    fn to_string(&self) -> String {
        let mut s = self.name.to_string();
        s.push('=');
        s.push_str(&self.value);
        s
    }
}

static SUPPORT_TOKEN_BOOL_VALUE: [&'static str; 2] = [
    "FNC",
    "SAFELIST",
];

impl super::MainState {
    pub(super) async fn process_cap<'a>(&self, conn_state: &mut ConnState,
            subcommand: CapCommand, caps: Option<Vec<&'a str>>, _: Option<u32>)
            -> Result<(), Box<dyn Error>> {
        match subcommand {
            CapCommand::LS => {
                conn_state.caps_negotation = true;
                self.feed_msg(&mut conn_state.stream, "CAP * LS :multi-prefix").await
            }
            CapCommand::LIST => {
                self.feed_msg(&mut conn_state.stream,
                        &format!("CAP * LIST :{}", conn_state.caps)).await
                }
            CapCommand::REQ => {
                conn_state.caps_negotation = true;
                if let Some(cs) = caps {
                    let mut new_caps = conn_state.caps;
                    if cs.iter().all(|c| new_caps.apply_cap(c)) {
                        conn_state.caps = new_caps;
                        self.feed_msg(&mut conn_state.stream,
                            format!("CAP * ACK :{}", cs.join(" "))).await
                    } else {    // NAK
                        self.feed_msg(&mut conn_state.stream,
                            format!("CAP * NAK :{}", cs.join(" "))).await
                    }
                } else { Ok(()) }
            }
            CapCommand::END => {
                conn_state.caps_negotation = false;
                if !conn_state.user_state.authenticated {
                    self.authenticate(conn_state).await?;
                }
                Ok(()) }
        }?;
        Ok(())
    }
    
    pub(super) async fn send_isupport(&self, conn_state: &mut ConnState)
        -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        // support tokens
        let mut tokens = vec![ format!("NETWORK={}", self.config.network) ];
        if let Some(max_joins) = self.config.max_joins {
            tokens.push(format!("CHANLIMIT=&#:{}", max_joins));
            tokens.push(format!("MAXCHANNELS={}", max_joins));
        }
        SUPPORT_TOKEN_STRING_VALUE.iter().for_each(|t| { tokens.push(t.to_string()); });
        SUPPORT_TOKEN_INT_VALUE.iter().for_each(|t| { tokens.push(t.to_string()); });
        SUPPORT_TOKEN_BOOL_VALUE.iter().for_each(|t| { tokens.push(t.to_string()); });
        
        tokens.sort();
        
        for toks in tokens.chunks(10) {
            self.feed_msg(&mut conn_state.stream,
                RplISupport005{ client, tokens: &toks.join(" ") }).await?;
        }
        Ok(())
    }
    
    async fn authenticate(&self, conn_state: &mut ConnState)
        -> Result<(), Box<dyn Error>> {
        let (auth_opt, registered) = {
            if !conn_state.caps_negotation {
                let user_state = &mut conn_state.user_state;
                if user_state.nick.is_some() {
                    if let Some(ref name) = user_state.name {
                        let mut registered = false;
                        let password_opt = if let Some(uidx) =
                                    self.user_config_idxs.get(name) {
                            // match user mask
                            if let Some(ref users) = self.config.users {
                                if let Some(ref mask) = users[*uidx].mask {
                                    if match_wildcard(&mask, &user_state.source) {
                                        registered = true;
                                        users[*uidx].password.as_ref()
                                    } else {
                                        self.feed_msg(&mut conn_state.stream,
                                            "ERROR: user mask doesn't match").await?;
                                        return Ok(());
                                    }
                                } else {
                                    registered = true;
                                    users[*uidx].password.as_ref()
                                }
                            } else { None }
                        } else { None }
                            .or(self.config.password.as_ref());
                        
                        if let Some(password) = password_opt {
                            let good = if let Some(ref entered_pwd) = user_state.password {
                                *entered_pwd == *password
                            } else { false };
                            
                            user_state.authenticated = good;
                            (Some(good), registered)
                        } else { (Some(true), registered) }
                    } else { (None, false) }
                } else { (None, false) }
            } else { (None, false) }
        };
        
        if let Some(good) = auth_opt {
            if good {
                let user_modes = {   // add new user to hash map
                    let mut user_state = &mut conn_state.user_state;
                    user_state.registered = registered;
                    let mut state = self.state.write().await;
                    let mut user = User::new(&self.config, &user_state,
                                conn_state.sender.take().unwrap(), 
                                conn_state.quit_sender.take().unwrap());
                    user.modes = self.config.default_user_modes;
                    let umode_str = user.modes.to_string();
                    state.add_user(user);
                    umode_str
                };
                
                {
                    let user_state = &conn_state.user_state;
                    let client = user_state.client_name();
                    // welcome
                    self.feed_msg(&mut conn_state.stream, RplWelcome001{ client,
                        networkname: &self.config.network,
                                nick: user_state.name.as_deref().unwrap_or_default(),
                                user: user_state.name.as_deref().unwrap_or_default(),
                                host: &user_state.hostname }).await?;
                    self.feed_msg(&mut conn_state.stream, RplYourHost002{ client,
                            servername: &self.config.name,
                            version: concat!(env!("CARGO_PKG_NAME"), "-",
                                    env!("CARGO_PKG_VERSION")) }).await?;
                    self.feed_msg(&mut conn_state.stream, RplCreated003{ client,
                            datetime: &self.created }).await?;
                    self.feed_msg(&mut conn_state.stream, RplMyInfo004{ client,
                            servername: &self.config.name,
                            version: concat!(env!("CARGO_PKG_NAME"), "-",
                                    env!("CARGO_PKG_VERSION")),
                            avail_user_modes: "Oiorw",
                            avail_chmodes: "Iabehiklmnopqstv",
                            avail_chmodes_with_params: None }).await?;
                    
                    self.send_isupport(conn_state).await?;
                }
                
                self.process_lusers(conn_state).await?;
                self.process_motd(conn_state, None).await?;
                
                // mode
                let client = conn_state.user_state.client_name();
                self.feed_msg(&mut conn_state.stream,
                        RplUModeIs221{ client, user_modes: &user_modes }).await?;
                
                // run ping waker for this connection
                conn_state.run_ping_waker(&self.config);
            } else {
                let client = conn_state.user_state.client_name();
                conn_state.quit.store(1, Ordering::SeqCst);
                self.feed_msg(&mut conn_state.stream, ErrPasswdMismatch464{ client }).await?;
            }
        }
        Ok(())
    }
    
    pub(super) async fn process_authenticate(&self, conn_state: &mut ConnState)
            -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        
        self.feed_msg(&mut conn_state.stream, ErrUnknownCommand421{ client,
                command: "AUTHENTICATE" }).await?;
        Ok(())
    }
    
    pub(super) async fn process_pass<'a>(&self, conn_state: &mut ConnState, pass: &'a str)
            -> Result<(), Box<dyn Error>> {
        if !conn_state.user_state.authenticated {
            conn_state.user_state.password = Some(pass.to_string());
            self.authenticate(conn_state).await?;
        } else {
            let client = conn_state.user_state.client_name();
            self.feed_msg(&mut conn_state.stream, ErrAlreadyRegistered462{ client }).await?;
        }
        Ok(())
    }
    
    pub(super) async fn process_nick<'a>(&self, conn_state: &mut ConnState, nick: &'a str,
                msg: &'a Message<'a>) -> Result<(), Box<dyn Error>> {
        if !conn_state.user_state.authenticated {
            conn_state.user_state.set_nick(nick.to_string());
            self.authenticate(conn_state).await?;
        } else {
            let mut statem = self.state.write().await;
            let state = statem.deref_mut();
            let old_nick = conn_state.user_state.nick.as_ref().unwrap().to_string();
            if nick != old_nick {
                let nick_str = nick.to_string();
                if !state.users.get(&nick_str).is_some() {
                    let mut user = state.users.remove(&old_nick).unwrap();
                    conn_state.user_state.set_nick(nick_str.clone());
                    user.update_nick(&conn_state.user_state);
                    for ch in &user.channels {
                        state.channels.get_mut(&ch.clone()).unwrap().rename_user(
                                    &old_nick, nick_str.clone());
                    }
                    // add nick history
                    state.insert_to_nick_history(&old_nick, user.history_entry.clone());
                    
                    state.users.insert(nick_str.clone(), user);
                    // wallops users
                    if state.wallops_users.contains(&old_nick) {
                        state.wallops_users.remove(&old_nick);
                        state.wallops_users.insert(nick_str);
                    }
                    
                    for (_,u) in &state.users {
                        if !u.modes.invisible || u.nick == nick {
                            u.send_message(msg, &conn_state.user_state.source)?;
                        }
                    }
                } else {    // if nick in use
                    let client = conn_state.user_state.client_name();
                    self.feed_msg(&mut conn_state.stream,
                            ErrNicknameInUse433{ client, nick }).await?;
                }
            }
        }
        Ok(())
    }
    
    pub(super) async fn process_user<'a>(&self, conn_state: &mut ConnState, username: &'a str,
            _: &'a str, _: &'a str, realname: &'a str)
            -> Result<(), Box<dyn Error>> {
        if !conn_state.user_state.authenticated {
            conn_state.user_state.set_name(username.to_string());
            conn_state.user_state.realname = Some(realname.to_string());
            self.authenticate(conn_state).await?;
        } else {
            let client = conn_state.user_state.client_name();
            self.feed_msg(&mut conn_state.stream, ErrAlreadyRegistered462{ client }).await?;
        }
        Ok(())
    }
    
    pub(super) async fn process_ping<'a>(&self, conn_state: &mut ConnState, token: &'a str)
            -> Result<(), Box<dyn Error>> {
        self.feed_msg(&mut conn_state.stream, format!("PONG {} {} :{}", self.config.name,
                    self.config.name, token)).await?;
        Ok(())
    }
    
    pub(super) async fn process_pong<'a>(&self, conn_state: &mut ConnState, _: &'a str)
            -> Result<(), Box<dyn Error>> {
        if let Some(notifier) = conn_state.pong_notifier.take() {
            notifier.send(()).map_err(|_| "pong notifier error".to_string())?;
        }
        Ok(())
    }
    
    pub(super) async fn process_oper<'a>(&self, conn_state: &mut ConnState, nick: &'a str,
            password: &'a str) -> Result<(), Box<dyn Error>> {
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        let client = conn_state.user_state.client_name();
        
        if let Some(oper_idx) = self.oper_config_idxs.get(nick) {
            let mut state = self.state.write().await;
            let mut user = state.users.get_mut(user_nick).unwrap();
            let op_cfg_opt = self.config.operators.as_ref().unwrap().get(*oper_idx);
            let op_config = op_cfg_opt.as_ref().unwrap();
            
            if op_config.password != password {
                self.feed_msg(&mut conn_state.stream,
                        ErrPasswdMismatch464{ client }).await?;
            }
            if let Some(ref op_mask) = op_config.mask {
                if match_wildcard(&op_mask, &conn_state.user_state.source) {
                    self.feed_msg(&mut conn_state.stream,
                            ErrNoOperHost491{ client }).await?;
                }
            }
            user.modes.oper = true;
            state.operators_count += 1;
            self.feed_msg(&mut conn_state.stream, RplYoureOper381{ client }).await?;
        } else {
            self.feed_msg(&mut conn_state.stream, ErrNoOperHost491{ client }).await?;
        }
        Ok(())
    }
    
    pub(super) async fn process_quit(&self, conn_state: &mut ConnState)
            -> Result<(), Box<dyn Error>> {
        conn_state.quit.store(1, Ordering::SeqCst);
        self.feed_msg(&mut conn_state.stream, "ERROR: Closing connection").await?;
        Ok(())
    }
}
