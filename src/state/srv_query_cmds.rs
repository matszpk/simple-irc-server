// srv_query_cmds.rs - main state
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
use std::time::{SystemTime, UNIX_EPOCH};
use chrono::prelude::*;
use super::*;

static HELP_TOPICS: [(&'static str, &'static str); 1] = [
    ("COMMANDS", "List of commands
    ADMIN - 
    HELP -
    JOIN -")
];

impl super::MainState {
    pub(super) async fn process_motd<'a>(&self, conn_state: &mut ConnState,
            target: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        
        if target.is_some() {
            self.feed_msg(&mut conn_state.stream, ErrUnknownError400{ client,
                    command: "MOTD", subcommand: None, info: "Server unsupported" }).await?;
        } else {
            self.feed_msg(&mut conn_state.stream, RplMotdStart375{ client,
                    server: &self.config.name }).await?;
            self.feed_msg(&mut conn_state.stream, RplMotd372{ client,
                    motd: &self.config.motd }).await?;
            self.feed_msg(&mut conn_state.stream, RplEndOfMotd376{ client }).await?;
        }
        Ok(())
    }
    
    pub(super) async fn process_version<'a>(&self, conn_state: &mut ConnState,
            target: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        if target.is_some() {
            let client = conn_state.user_state.client_name();
            self.feed_msg(&mut conn_state.stream, ErrUnknownError400{ client,
                    command: "VERSION", subcommand: None, info: "Server unsupported" }).await?;
        } else {
            self.send_isupport(conn_state).await?;
            let client = conn_state.user_state.client_name();
            self.feed_msg(&mut conn_state.stream, RplVersion351{ client,
                version: concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION")),
                server: &self.config.name, comments: "simple IRC server" }).await?;
        }
        Ok(())
    }
    
    pub(super) async fn process_admin<'a>(&self, conn_state: &mut ConnState,
            target: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        if target.is_some() {
            self.feed_msg(&mut conn_state.stream, ErrUnknownError400{ client,
                    command: "ADMIN", subcommand: None, info: "Server unsupported" }).await?;
        } else {
            self.feed_msg(&mut conn_state.stream, RplAdminMe256{ client,
                    server: &self.config.name }).await?;
            self.feed_msg(&mut conn_state.stream, RplAdminLoc1257{ client,
                    info: &self.config.admin_info }).await?;
            if let Some(ref info2) = self.config.admin_info2 {
                self.feed_msg(&mut conn_state.stream, RplAdminLoc2258{ client,
                        info: info2 }).await?;
            }
            if let Some(ref email) = self.config.admin_email {
                self.feed_msg(&mut conn_state.stream, RplAdminEmail259{ client,
                        email: email }).await?;
            }
        }
        Ok(())
    }
    
    pub(super) async fn process_connect<'a>(&self, _: &mut ConnState, _: &'a str,
            _: Option<u16>, _: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    pub(super) async fn process_lusers(&self, conn_state: &mut ConnState)
            -> Result<(), Box<dyn Error>> {
        let state = self.state.read().await;
        let client = conn_state.user_state.client_name();
        self.feed_msg(&mut conn_state.stream, RplLUserClient251{ client, 
                users_num: state.users.len() - state.invisible_users_count,
                inv_users_num: state.invisible_users_count, servers_num: 1 }).await?;
        self.feed_msg(&mut conn_state.stream, RplLUserOp252{ client,
                ops_num: state.operators_count }).await?;
        self.feed_msg(&mut conn_state.stream, RplLUserUnknown253{ client,
                conns_num: 0 }).await?;
        self.feed_msg(&mut conn_state.stream, RplLUserChannels254{ client,
                channels_num: state.channels.len() }).await?;
        self.feed_msg(&mut conn_state.stream, RplLUserMe255{ client,
                clients_num: state.users.len(), servers_num: 1 }).await?;
        self.feed_msg(&mut conn_state.stream, RplLocalUsers265{ client,
                clients_num: state.users.len(),
                max_clients_num: state.max_users_count }).await?;
        self.feed_msg(&mut conn_state.stream, RplGlobalUsers266{ client,
                clients_num: state.users.len(),
                max_clients_num: state.max_users_count }).await?;
        Ok(())
    }
    
    pub(super) async fn process_time<'a>(&self, conn_state: &mut ConnState,
            server: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        
        if server.is_some() {
            self.feed_msg(&mut conn_state.stream, ErrUnknownError400{ client,
                    command: "TIME", subcommand: None, info: "Server unsupported" }).await?;
        } else {
            let time = Local::now();
            self.feed_msg(&mut conn_state.stream, RplTime391{ client,
                server: &self.config.name, timestamp: time.timestamp() as u64,
                    ts_offset: "", human_readable: time.to_rfc2822().as_str() }).await?;
        }
        Ok(())
    }
    
    pub(super) async fn process_stats<'a>(&self, _: &mut ConnState, _: char,
            _: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    
    pub(super) async fn process_links<'a>(&self, conn_state: &mut ConnState,
            remote_server: Option<&'a str>, server_mask: Option<&'a str>)
            -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        if remote_server.is_some() || server_mask.is_some() {
            self.feed_msg(&mut conn_state.stream, ErrUnknownError400{ client,
                    command: "TIME", subcommand: None, info: "Server unsupported" }).await?;
        } else {
            self.feed_msg(&mut conn_state.stream, RplLinks364{ client,
                    server: &self.config.name, mask: &self.config.name, 
                    hop_count: 0, server_info: &self.config.info }).await?;
            self.feed_msg(&mut conn_state.stream,
                    RplEndOfLinks365{ client, mask: "*" }).await?;
        }
        Ok(())
    }
    
    pub(super) async fn process_help<'a>(&self, conn_state: &mut ConnState, subject: &'a str)
            -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        if let Some((_, content)) = HELP_TOPICS.iter().find(|(t, _)| *t == subject) {
            let lines = content.split_terminator('\n').collect::<Vec<_>>();
            for (i, line) in lines.iter().enumerate() {
                if i+1 == lines.len() {
                    self.feed_msg(&mut conn_state.stream,
                            RplEndOfHelp706{ client, subject, line }).await?;
                } else if i == 0 {
                    self.feed_msg(&mut conn_state.stream,
                            RplHelpStart704{ client, subject, line }).await?;
                } else {
                    self.feed_msg(&mut conn_state.stream,
                            RplHelpTxt705{ client, subject, line }).await?;
                }
            }
        } else {
            self.feed_msg(&mut conn_state.stream,
                        ErrHelpNotFound524{ client, subject }).await?;
        }
        Ok(())
    }
    
    pub(super) async fn process_info(&self, conn_state: &mut ConnState)
            -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        
        self.feed_msg(&mut conn_state.stream, RplInfo371{ client, info:
            concat!(env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION")) }).await?;
        self.feed_msg(&mut conn_state.stream, RplEndOfInfo374{ client }).await?;
        Ok(())
    }
    
    async fn process_mode_channel<'a>(&self, conn_state: &mut ConnState,
            chanobj: &mut Channel, target: &'a str, modes: Vec<(&'a str, Vec<&'a str>)>,
            chum: &ChannelUserModes) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        let if_op = chum.is_operator();
        let if_half_op = chum.is_operator();
        
        if modes.len() == 0 {
            self.feed_msg(&mut conn_state.stream, RplChannelModeIs324{ client,
                    channel: target, modestring: &chanobj.modes.to_string() }).await?;
            self.feed_msg(&mut conn_state.stream, RplCreationTime329{ client,
                channel: target, creation_time: chanobj.creation_time }).await?;
        } else {
        //
        for (mchars, margs) in modes {
            let mut margs_it = margs.iter();
            let mut mode_set = false;
            for mchar in mchars.chars() {
                match mchar {
                    'i'|'m'|'t'|'n'|'s'|'l'|'k'|'o'|'v'|'h'|'q'|'a' => {
                        if !if_op {
                            self.feed_msg(&mut conn_state.stream,
                                ErrChanOpPrivsNeeded482{ client,
                                        channel: target }).await?;
                        }
                    }
                    _ => (),
                }
            
                match mchar {
                    '+' => mode_set = true,
                    '-' => mode_set = false,
                    'b' => {
                        if let Some(bmask) = margs_it.next() {
                            if if_half_op {
                                let mut ban = chanobj.modes.ban.take()
                                        .unwrap_or_default();
                                let norm_bmask = normalize_sourcemask(bmask);
                                if mode_set {
                                    ban.insert(norm_bmask.clone());
                                    chanobj.ban_info.insert(norm_bmask.clone(), BanInfo{
                                        who: conn_state.user_state.nick
                                                .as_ref().unwrap().to_string(),
                                        set_time: SystemTime::now()
                                            .duration_since(UNIX_EPOCH).unwrap().as_secs() });
                                } else {
                                    ban.remove(&norm_bmask);
                                    chanobj.ban_info.remove(&norm_bmask);
                                }
                                chanobj.modes.ban = Some(ban);
                            } else {
                                self.feed_msg(&mut conn_state.stream, ErrChanOpPrivsNeeded482{
                                        client, channel: target }).await?;
                            }
                        } else { // print
                            if let Some(ban) = &chanobj.modes.ban {
                                for b in ban {
                                    if let Some(ban_info) = chanobj.ban_info
                                            .get(&b.clone()) {
                                        self.feed_msg(&mut conn_state.stream,
                                            RplBanList367{ client, channel: target, mask: &b,
                                                who: &ban_info.who,
                                                set_ts: ban_info.set_time }).await?;
                                    } else {
                                        self.feed_msg(&mut conn_state.stream,
                                            RplBanList367{ client, channel: target,
                                            mask: &b, who: "", set_ts: 0 }).await?;
                                    }
                                }
                            }
                            self.feed_msg(&mut conn_state.stream,  RplEndOfBanList368{
                                    client, channel: target }).await?;
                        }
                    },
                    'e' => {
                        if let Some(emask) = margs_it.next() {
                            if if_op {
                                let mut exp = chanobj.modes.exception.take()
                                        .unwrap_or_default();
                                if mode_set {
                                    exp.insert(normalize_sourcemask(emask));
                                } else {
                                    exp.remove(&normalize_sourcemask(emask));
                                }
                                chanobj.modes.exception = Some(exp);
                            } else {
                                self.feed_msg(&mut conn_state.stream, ErrChanOpPrivsNeeded482{
                                        client, channel: target }).await?;
                            }
                        } else { // print
                            if let Some(exception) = &chanobj.modes.exception {
                                for e in exception {
                                    self.feed_msg(&mut conn_state.stream, RplExceptList348{
                                        client, channel: target, mask: &e }).await?;
                                }
                            }
                            self.feed_msg(&mut conn_state.stream, 
                                RplEndOfExceptList349{ client,
                                        channel: target }).await?;
                        }
                    },
                    'I' => {
                        if let Some(imask) = margs_it.next() {
                            if if_op {
                                let mut exp = chanobj.modes.invite_exception.take()
                                        .unwrap_or_default();
                                if mode_set {
                                    exp.insert(normalize_sourcemask(imask));
                                } else {
                                    exp.remove(&normalize_sourcemask(imask));
                                }
                                chanobj.modes.invite_exception = Some(exp);
                            } else {
                                self.feed_msg(&mut conn_state.stream, ErrChanOpPrivsNeeded482{
                                        client, channel: target }).await?;
                            }
                        } else { // print
                            if let Some(inv_ex) = &chanobj.modes.invite_exception {
                                for e in inv_ex {
                                    self.feed_msg(&mut conn_state.stream, RplInviteList346{
                                        client, channel: target, mask: &e }).await?;
                                }
                            }
                            self.feed_msg(&mut conn_state.stream, 
                                RplEndOfInviteList347{ client,
                                        channel: target }).await?;
                        }
                    },
                    'o'|'v'|'h'|'q'|'a' => {
                        let arg = margs_it.next().unwrap();
                        if chanobj.users.contains_key(&arg.to_string()) {
                            match mchar {
                                'o' => {
                                    if if_op {
                                        if mode_set {
                                            chanobj.add_operator(&arg);
                                        } else {
                                            chanobj.remove_operator(&arg);
                                        }
                                    }
                                },
                                'v' => {
                                    if if_half_op {
                                        if mode_set {
                                            chanobj.add_voice(&arg);
                                        } else {
                                            chanobj.remove_voice(&arg);
                                        }
                                    }
                                },
                                'h' => {
                                    if if_op {
                                        if mode_set {
                                            chanobj.add_half_operator(&arg);
                                        } else {
                                            chanobj.remove_half_operator(&arg);
                                        }
                                    }
                                },
                                'q' => {
                                    if chum.founder {
                                        if mode_set {
                                            chanobj.add_founder(&arg);
                                        } else {
                                            chanobj.remove_founder(&arg);
                                        }
                                    }
                                },
                                'a' => {
                                    if chum.is_protected() {
                                        if mode_set {
                                            chanobj.add_protected(&arg);
                                        } else {
                                            chanobj.remove_protected(&arg);
                                        }
                                    }
                                },
                                _ => {},
                            }
                        } else {
                            self.feed_msg(&mut conn_state.stream, ErrNotOnChannel442{ client,
                                    channel: target }).await?;
                        }
                    },
                    'l' => { 
                        let arg = margs_it.next().unwrap();
                        if if_op {
                            chanobj.modes.client_limit = if mode_set {
                                Some(arg.parse::<usize>().unwrap())
                            } else { None };
                        }
                    },
                    'k' => { 
                        let arg = margs_it.next().unwrap();
                        if if_op { chanobj.modes.key =
                            if mode_set { Some(arg.to_string()) } else { None }; }
                    },
                    'i' => if if_op { chanobj.modes.invite_only = mode_set; },
                    'm' => if if_op { chanobj.modes.moderated = mode_set; },
                    't' => if if_op { chanobj.modes.protected_topic = mode_set; },
                    'n' => if if_op {
                            chanobj.modes.no_external_messages = mode_set; },
                    's' => if if_op { chanobj.modes.secret = mode_set; },
                    _ => (),
                }
            }
        }
        } // if modes.len() == 0
        Ok(())
    }
    
    async fn process_mode_user<'a>(&self, conn_state: &mut ConnState,
            state: &mut VolatileState, target: &'a str,
            modes: Vec<(&'a str, Vec<&'a str>)>) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        let mut user = state.users.get_mut(target).unwrap();
        let user_nick = target;
        if modes.len() == 0 {
            self.feed_msg(&mut conn_state.stream, RplUModeIs221{ client,
                    user_modes: &user.modes.to_string() }).await?;
        } else {
        for (mchars, _) in modes {
            let mut mode_set = false;
            for mchar in mchars.chars() {
                match mchar {
                    '+' => mode_set = true,
                    '-' => mode_set = false,
                    'i' => {
                        if mode_set {
                            if !user.modes.invisible {
                                user.modes.invisible = true;
                                state.invisible_users_count += 1;
                            }
                        } else {
                            if user.modes.invisible {
                                user.modes.invisible = false;
                                state.invisible_users_count -= 1;
                            }
                        }
                    },
                    'r' => {
                        if mode_set {
                            if !user.modes.registered {
                                if conn_state.user_state.registered {
                                    user.modes.registered = true;
                                } else {
                                    self.feed_msg(&mut conn_state.stream,
                                        ErrNoPrivileges481{ client }).await?;
                                }
                            }
                        } else {
                            if user.modes.registered {
                                user.modes.registered = false;
                                self.feed_msg(&mut conn_state.stream,
                                    ErrYourConnRestricted484{ client }).await?;
                            }
                        }
                    },
                    'w' => {
                        if mode_set {
                            if !user.modes.wallops {
                                state.wallops_users.insert(user_nick.to_string());
                                user.modes.wallops = true;
                            }
                        } else {
                            if user.modes.wallops {
                                state.wallops_users.remove(&user_nick.to_string());
                                user.modes.wallops = false;
                            }
                        }
                    },
                    'o' => {
                        if mode_set {
                            if !user.modes.oper {
                                if self.oper_config_idxs.contains_key(user_nick) {
                                    user.modes.oper = true;
                                    if !user.modes.local_oper {
                                        state.operators_count += 1;
                                    }
                                } else {
                                    self.feed_msg(&mut conn_state.stream,
                                        ErrNoPrivileges481{ client }).await?;
                                }
                            }
                        } else {
                            if user.modes.oper {
                                user.modes.oper = false;
                                if !user.modes.local_oper {
                                    state.operators_count -= 1;
                                }
                            }
                        }
                    },
                    'O' => {
                        if mode_set {
                            if !user.modes.local_oper {
                                if self.oper_config_idxs.contains_key(user_nick) {
                                    user.modes.oper = true;
                                    if !user.modes.oper {
                                        state.operators_count += 1;
                                    }
                                } else {
                                    self.feed_msg(&mut conn_state.stream,
                                        ErrNoPrivileges481{ client }).await?;
                                }
                            }
                        } else {
                            if user.modes.oper {
                                user.modes.oper = false;
                                if !user.modes.oper {
                                    state.operators_count -= 1;
                                }
                            }
                        }
                    },
                    _ => (),
                }
            }
        }
        } // if modes.len() != 0
        Ok(())
    }
    
    pub(super) async fn process_mode<'a>(&self, conn_state: &mut ConnState, target: &'a str,
            modes: Vec<(&'a str, Vec<&'a str>)>) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        let mut statem = self.state.write().await;
        let state = statem.deref_mut();
        
        if validate_channel(target).is_ok() {
            // channel
            if let Some(chanobj) = state.channels.get_mut(target) {
                let (chum, error) = if let Some(chum) = chanobj.users.get(user_nick) {
                    (*chum, false)
                } else {
                    self.feed_msg(&mut conn_state.stream, ErrNotOnChannel442{ client,
                            channel: target }).await?;
                    (ChannelUserModes::default(), true)
                };
                if !error {
                    self.process_mode_channel(conn_state, chanobj, target,
                            modes, &chum).await?;
                }
            } else {
                self.feed_msg(&mut conn_state.stream, ErrNoSuchChannel403{ client,
                            channel: target }).await?;
            }
        } else {
            // user
            if user_nick == target {
                self.process_mode_user(conn_state, state, target, modes).await?;
            } else if state.users.contains_key(target) {
                self.feed_msg(&mut conn_state.stream,
                        ErrUsersDontMatch502{ client }).await?;
            } else {
                self.feed_msg(&mut conn_state.stream,
                        ErrNoSuchNick401{ client, nick: target }).await?;
            }
        }
        Ok(())
    }
}
