// rest_cmds.rs - main state
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
use std::collections::HashSet;
use std::iter::FromIterator;
use std::time::{SystemTime, UNIX_EPOCH};
use chrono::prelude::*;
use super::*;

impl super::MainState {
    async fn process_privmsg_notice<'a>(&self, conn_state: &mut ConnState,
            targets: Vec<&'a str>, text: &'a str,
            notice: bool) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        
        let mut something_done = false;
        {
        let state = self.state.read().await;
        
        for target in HashSet::<&&str>::from_iter(targets.iter()) {
            let msg_str = if notice {
                format!("NOTICE {} :{}", target, text)
            } else { format!("PRIVMSG {} :{}", target, text) };
            let (target_type, chan_str) = get_privmsg_target_type(target);
            if target_type.contains(PrivMsgTargetType::Channel) { // to channel
                if let Some(chanobj) = state.channels.get(chan_str) {
                    let chanuser_mode = chanobj.users.get(user_nick);
                    let can_send = {
                        if (!chanobj.modes.no_external_messages &&
                                    !chanobj.modes.secret) ||
                                chanuser_mode.is_some() {
                            true
                        } else {
                            if !notice {
                                self.feed_msg(&mut conn_state.stream, ErrCannotSendToChain404{
                                        client, channel: chan_str }).await?;
                            }
                            false
                        }
                    };
                    let can_send = can_send && {
                        if !chanobj.modes.banned(&conn_state.user_state.source) {
                            true
                        } else {
                            if !notice {
                                self.feed_msg(&mut conn_state.stream, ErrCannotSendToChain404{
                                        client, channel: chan_str }).await?;
                            }
                            false
                        }
                    };
                    let can_send = can_send && {
                        if !chanobj.modes.moderated ||
                            chanuser_mode.map_or(false, |chum| chum.is_voice()) {
                            true
                        } else {
                            if !notice {
                                self.feed_msg(&mut conn_state.stream, ErrCannotSendToChain404{
                                        client, channel: chan_str }).await?;
                            }
                            false
                        }
                    };
                    
                    if can_send {
                        use PrivMsgTargetType::*;
                        if !(target_type & ChannelAllSpecial).is_empty() {
                            // to special
                            if !(target_type & ChannelFounder).is_empty() {
                                if let Some(ref founders) = chanobj.modes.founders {
                                    founders.iter().try_for_each(|u|
                                        state.users.get(u).unwrap().send_msg_display(
                                                &conn_state.user_state.source, &msg_str))?;
                                }
                            }
                            if !(target_type & ChannelProtected).is_empty() {
                                if let Some(ref protecteds) = chanobj.modes.protecteds {
                                    protecteds.iter().try_for_each(|u|
                                        state.users.get(u).unwrap().send_msg_display(
                                                &conn_state.user_state.source, &msg_str))?;
                                }
                            }
                            if !(target_type & ChannelOper).is_empty() {
                                if let Some(ref operators) = chanobj.modes.operators {
                                    operators.iter().try_for_each(|u|
                                        state.users.get(u).unwrap().send_msg_display(
                                                &conn_state.user_state.source, &msg_str))?;
                                }
                            }
                            if !(target_type & ChannelHalfOper).is_empty() {
                                if let Some(ref half_ops) = chanobj.modes.half_operators {
                                    half_ops.iter().try_for_each(|u|
                                        state.users.get(u).unwrap().send_msg_display(
                                                &conn_state.user_state.source, &msg_str))?;
                                }
                            }
                            if !(target_type & ChannelVoice).is_empty() {
                                if let Some(ref voices) = chanobj.modes.voices {
                                    voices.iter().try_for_each(|u|
                                        state.users.get(u).unwrap().send_msg_display(
                                                &conn_state.user_state.source, &msg_str))?;
                                }
                            }
                        } else {
                            chanobj.users.keys().try_for_each(|u|
                                state.users.get(u).unwrap().send_msg_display(
                                        &conn_state.user_state.source, &msg_str))?;
                        }
                        something_done = true;
                    }
                } else {
                    if !notice {
                        self.feed_msg(&mut conn_state.stream,
                                ErrNoSuchChannel403{ client, channel: chan_str }).await?;
                    }
                }
            } else {    // to user
                if let Some(cur_user) = state.users.get(*target) {
                    cur_user.send_msg_display(&conn_state.user_state.source, msg_str)?;
                    if !notice {
                        if let Some(ref away) = cur_user.away {
                            self.feed_msg(&mut conn_state.stream, RplAway301{ client,
                                        nick: target, message: &away }).await?;
                        }
                    }
                    something_done = true;
                } else {
                    if !notice {
                        self.feed_msg(&mut conn_state.stream, ErrNoSuchNick401{ client,
                                        nick: target }).await?;
                    }
                }
            }
        }
        }
        
        {
            if something_done {
                let mut state = self.state.write().await;
                let mut user = state.users.get_mut(user_nick).unwrap();
                user.last_activity = SystemTime::now().duration_since(UNIX_EPOCH)
                        .unwrap().as_secs();
            }
        }
        Ok(())
    }
    
    pub(super) async fn process_privmsg<'a>(&self, conn_state: &mut ConnState,
            targets: Vec<&'a str>, text: &'a str) -> Result<(), Box<dyn Error>> {
        self.process_privmsg_notice(conn_state, targets, text, false).await
    }
    
    pub(super) async fn process_notice<'a>(&self, conn_state: &mut ConnState,
            targets: Vec<&'a str>, text: &'a str) -> Result<(), Box<dyn Error>> {
        self.process_privmsg_notice(conn_state, targets, text, true).await
    }
    
    pub(super) async fn send_who_info<'a>(&self, conn_state: &mut ConnState,
            channel: Option<(&'a str, &ChannelUserModes)>,
            user: &User, cmd_user: &User) -> Result<(), Box<dyn Error>> {
        if !user.modes.invisible || !user.channels.is_disjoint(&cmd_user.channels) {
            let client = conn_state.user_state.client_name();
            let mut flags = String::new();
            if user.away.is_some() { flags.push('G');
            } else { flags.push('H'); }
            if user.modes.is_local_oper() {
                flags.push('*');
            }
            if let Some((_, ref chum)) = channel {
                flags += &chum.to_string(&conn_state.caps);
            }
            self.feed_msg(&mut conn_state.stream, RplWhoReply352{ client,
                channel: channel.map(|(c,_)| c).unwrap_or("*"), username: &user.name,
                host: &user.hostname, server: &self.config.name, nick: &user.nick,
                flags: &flags, hopcount: 0, realname: &user.realname}).await?;
        }
        Ok(())
    }
    
    pub(super) async fn process_who<'a>(&self, conn_state: &mut ConnState, mask: &'a str)
            -> Result<(), Box<dyn Error>> {
        let state = self.state.read().await;
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        let user = state.users.get(user_nick).unwrap();
        
        if mask.contains('*') || mask.contains('?') {
            for (_, u) in &state.users {
                if match_wildcard(mask, &u.nick) || match_wildcard(mask, &u.source) ||
                    match_wildcard(mask, &u.realname) {
                    self.send_who_info(conn_state, None, &u, &user).await?;
                }
            }
        } else if validate_channel(mask).is_ok() {
            if let Some(channel) = state.channels.get(mask) {
                for (u, chum) in &channel.users {
                    self.send_who_info(conn_state, Some((&channel.name, chum)),
                        state.users.get(u).unwrap(), &user).await?;
                }
            }
        } else if validate_username(mask).is_ok() {
            if let Some(ref arg_user) = state.users.get(mask) {
                self.send_who_info(conn_state, None, arg_user, &user).await?;
            }
        }
        let client = conn_state.user_state.client_name();
        self.feed_msg(&mut conn_state.stream, RplEndOfWho315{ client, mask }).await?;
        Ok(())
    }
    
    pub(super) async fn process_whois<'a>(&self, conn_state: &mut ConnState,
            target: Option<&'a str>, nickmasks: Vec<&'a str>) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        
        if target.is_some() {
            self.feed_msg(&mut conn_state.stream, ErrUnknownError400{ client,
                    command: "WHOIS", subcommand: None, info: "Server unsupported" }).await?;
        } else {
            let state = self.state.read().await;
            let user_nick = conn_state.user_state.nick.as_ref().unwrap();
            let user = state.users.get(user_nick).unwrap();
            
            let mut nicks = HashSet::<String>::new();
            let mut real_nickmasks = vec![];
            
            nickmasks.iter().for_each(|nickmask| {
                if nickmask.contains('*') || nickmask.contains('?') {
                    // wildcard
                    real_nickmasks.push(nickmask);
                } else {
                    if state.users.contains_key(&nickmask.to_string()) {
                        nicks.insert(nickmask.to_string());
                    }
                }
            });
            
            state.users.keys().for_each(|nick| {
                if real_nickmasks.iter().any(|mask| match_wildcard(mask, nick)) {
                    nicks.insert(nick.to_string());
                }
            });
            
            for nick in nicks {
                let arg_user = state.users.get(&nick).unwrap();
                if arg_user.modes.invisible &&
                    arg_user.channels.is_disjoint(&user.channels) { continue; }
                
                if arg_user.modes.registered {
                    self.feed_msg(&mut conn_state.stream, RplWhoIsRegNick307{ client,
                            nick: &nick }).await?;
                }
                self.feed_msg(&mut conn_state.stream, RplWhoIsUser311{ client,
                        nick: &nick, username: &user.name, host: &user.hostname,
                        realname: &user.realname }).await?;
                self.feed_msg(&mut conn_state.stream, RplWhoIsServer312{ client,
                        nick: &nick, server: &self.config.name,
                        server_info: &self.config.info }).await?;
                if arg_user.modes.is_local_oper() {
                    self.feed_msg(&mut conn_state.stream, RplWhoIsOperator313{ client,
                            nick: &nick }).await?;
                }
                // channels
                let channel_replies = arg_user.channels.iter()
                    .filter_map(|chname| {
                    let ch = state.channels.get(chname).unwrap();
                    if !ch.modes.secret {
                        Some(WhoIsChannelStruct{ prefix: Some(ch.users.get(&arg_user.nick)
                            .unwrap().to_string(&conn_state.caps)).clone(),
                            channel: &ch.name })
                    } else { None }
                    }).collect::<Vec<_>>();
                
                for chr_chunk in channel_replies.chunks(30) {
                    self.feed_msg(&mut conn_state.stream, RplWhoIsChannels319{ client,
                            nick: &nick, channels: &chr_chunk }).await?;
                }
                
                self.feed_msg(&mut conn_state.stream, RplwhoIsIdle317{ client,
                        nick: &nick, secs: SystemTime::now().duration_since(UNIX_EPOCH)
                            .unwrap().as_secs() - user.last_activity,
                        signon: user.signon }).await?;
                if user.modes.is_local_oper() {
                    self.feed_msg(&mut conn_state.stream, RplWhoIsHost378{ client,
                            nick: &nick, host_info: &user.hostname }).await?;
                    self.feed_msg(&mut conn_state.stream, RplWhoIsModes379{ client,
                            nick: &nick, modes: &user.modes.to_string() }).await?;
                }
            }
            self.feed_msg(&mut conn_state.stream, RplEndOfWhoIs318{ client,
                nick: &nickmasks.join(",") }).await?;
        }
        Ok(())
    }
    
    pub(super) async fn process_whowas<'a>(&self, conn_state: &mut ConnState,
            nickname: &'a str, count: Option<usize>,
            server: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        
        if server.is_some() {
            self.feed_msg(&mut conn_state.stream, ErrUnknownError400{ client,
                    command: "WHOWAS", subcommand: None, info: "Server unsupported" }).await?;
        } else {
            let state = self.state.read().await;
            if let Some(hist) = state.nick_histories.get(&nickname.to_string()) {
                let hist_count = if let Some(c) = count {
                    if c > 0 { c } else { hist.len() }
                } else { hist.len() };
                for entry in hist.iter().rev().take(hist_count) {
                    self.feed_msg(&mut conn_state.stream, RplWhoWasUser314{ client,
                            nick: &nickname, username: &entry.username,
                            host: &entry.hostname, realname: &entry.realname }).await?;
                    self.feed_msg(&mut conn_state.stream, RplWhoIsServer312{ client,
                            nick: &nickname, server: &self.config.name,
                            server_info: &format!("Logged in at {}",
                                DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(
                                        entry.signon as i64, 0), Utc)) }).await?;
                }
            } else {
                self.feed_msg(&mut conn_state.stream, ErrWasNoSuchNick406{ client,
                    nick: nickname }).await?;
            }
            self.feed_msg(&mut conn_state.stream, RplEndOfWhoWas369{ client,
                    nick: nickname }).await?;
        }
        Ok(())
    }
    
    pub(super) async fn process_kill<'a>(&self, conn_state: &mut ConnState, nickname: &'a str,
            comment: &'a str) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        let mut state = self.state.write().await;
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        let user = state.users.get(user_nick).unwrap();
        
        if user.modes.oper {
            if let Some(user_to_kill) = state.users.get_mut(nickname) {
                if let Some(sender) = user_to_kill.quit_sender.take() {
                    sender.send((user_nick.to_string(), comment.to_string()))
                            .map_err(|_| "error".to_string())?;
                }
            } else {
                self.feed_msg(&mut conn_state.stream, ErrNoSuchNick401{ client,
                            nick: nickname }).await?;
            }
        } else {
            self.feed_msg(&mut conn_state.stream, ErrNoPrivileges481{ client }).await?;
        }
        Ok(())
    }
    
    pub(super) async fn process_rehash(&self, conn_state: &mut ConnState)
            -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        self.feed_msg(&mut conn_state.stream, ErrUnknownError400{ client,
                    command: "REHASH", subcommand: None,
                    info: "Server unsupported" }).await?;
        Ok(())
    }
    
    pub(super) async fn process_restart(&self, conn_state: &mut ConnState)
            -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        self.feed_msg(&mut conn_state.stream, ErrUnknownError400{ client,
                    command: "RESTART", subcommand: None,
                    info: "Server unsupported" }).await?;
        Ok(())
    }
    
    pub(super) async fn process_squit<'a>(&self, conn_state: &mut ConnState, server: &'a str,
            comment: &'a str) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        if self.config.name != server {
            self.feed_msg(&mut conn_state.stream, ErrUnknownError400{ client,
                    command: "SQUIT", subcommand: None, info: "Server unsupported" }).await?;
        } else {
            let mut state = self.state.write().await;
            let user_nick = conn_state.user_state.nick.as_ref().unwrap();
            let user = state.users.get(user_nick).unwrap();
            
            if user.modes.oper {
                for u in state.users.values_mut() {
                    if let Some(sender) = u.quit_sender.take() {
                        sender.send((user_nick.to_string(), comment.to_string()))
                                    .map_err(|_| "error".to_string())?;
                    }
                }
                if let Some(sender) = state.quit_sender.take() {
                    sender.send(comment.to_string())?;
                }
            } else {
                self.feed_msg(&mut conn_state.stream, ErrCantKillServer483{ client }).await?;
            }
        }
        Ok(())
    }
    
    pub(super) async fn process_away<'a>(&self, conn_state: &mut ConnState,
            text: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        let mut state = self.state.write().await;
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        let mut user = state.users.get_mut(user_nick).unwrap();
        if let Some(t) = text {
            user.away = Some(t.to_string());
            self.feed_msg(&mut conn_state.stream, RplNowAway306{ client }).await?;
        } else {
            user.away = None;
            self.feed_msg(&mut conn_state.stream, RplUnAway305{ client }).await?;
        }
        Ok(())
    }
    
    pub(super) async fn process_userhost<'a>(&self, conn_state: &mut ConnState,
            nicknames: Vec<&'a str>) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        let state = self.state.read().await;
        
        for nicks in nicknames.chunks(20) {
            let replies = nicks.iter().map(|nick| {
                let user = state.users.get(&nick.to_string()).unwrap();
                format!("{}=+~{}@{}", nick, user.name, user.hostname)
            }).collect::<Vec<_>>();
            self.feed_msg(&mut conn_state.stream, RplUserHost302{ client,
                    replies: &replies }).await?;
        }
        Ok(())
    }
    
    pub(super) async fn process_wallops<'a>(&self, conn_state: &mut ConnState, _: &'a str,
            msg: &'a Message<'a>) -> Result<(), Box<dyn Error>> {
        let state = self.state.read().await;
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        let user = state.users.get(user_nick).unwrap();
        
        if user.modes.is_local_oper() {
            state.wallops_users.iter().try_for_each(|wu| state.users.get(wu).unwrap()
                .send_message(msg, &conn_state.user_state.source))?;
        } else {
            let client = conn_state.user_state.client_name();
            self.feed_msg(&mut conn_state.stream, ErrNoPrivileges481{ client }).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use super::super::test::*;
    
    #[tokio::test]
    async fn test_command_privmsg_user() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;
        
        {
            let mut line_stream = login_to_test_and_skip(port, "alan", "alan",
                    "Alan Bodarski").await;
            let mut line_stream2 = login_to_test_and_skip(port, "bowie", "bowie",
                    "Bowie Catcher").await;
            
            line_stream.send("PRIVMSG bowie :Hello guy!".to_string()).await.unwrap();
            assert_eq!(":alan!~alan@127.0.0.1 PRIVMSG bowie :Hello guy!".to_string(),
                            line_stream2.next().await.unwrap().unwrap());
            line_stream2.send("PRIVMSG alan :Hello too!".to_string()).await.unwrap();
            assert_eq!(":bowie!~bowie@127.0.0.1 PRIVMSG alan :Hello too!".to_string(),
                            line_stream.next().await.unwrap().unwrap());
        }
        
        quit_test_server(main_state, handle).await;
    }
}
