// channel_cmds.rs - main state
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
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use super::*;

impl super::MainState {
    pub(super) async fn process_join<'a>(&self, conn_state: &mut ConnState,
            channels: Vec<&'a str>, keys_opt: Option<Vec<&'a str>>)
            -> Result<(), Box<dyn Error>> {
        let mut statem = self.state.write().await;
        let state = statem.deref_mut();
        let user_nick = conn_state.user_state.nick.as_ref().unwrap().clone();
        let mut join_count = state.users.get(&user_nick).unwrap().channels.len();
        
        let mut joined_created = vec![];
        
        {
        let client = conn_state.user_state.client_name();
        let mut user = state.users.get_mut(user_nick.as_str()).unwrap();
        for (i, chname_str) in channels.iter().enumerate() {
            let (join, create) = if let Some(channel) =
                                state.channels.get(&chname_str.to_string()) {
                // if already created
                let do_join = if let Some(key) = &channel.modes.key {
                    if let Some(ref keys) = keys_opt {
                        key == keys[i]
                    } else {
                        self.feed_msg(&mut conn_state.stream, ErrBadChannelKey475{
                            client, channel: chname_str }).await?;
                        false
                    }
                } else { true };
                
                let do_join = do_join && {
                    if !channel.modes.banned(&conn_state.user_state.source) {
                        true
                    } else {
                        self.feed_msg(&mut conn_state.stream, ErrBannedFromChan474{
                            client, channel: chname_str }).await?;
                        false
                    }
                };
                
                let do_join = do_join && {
                     if !channel.modes.invite_only ||
                        user.invited_to.contains(&channel.name) ||
                        channel.modes.invite_exception.as_ref().map_or(false,
                            |e| e.iter().any(|e|
                                match_wildcard(&e, &conn_state.user_state.source))) {
                        true
                    } else {
                        self.feed_msg(&mut conn_state.stream, ErrInviteOnlyChan473{
                            client, channel: chname_str }).await?;
                        false
                    }
                };
                
                let do_join = do_join && {
                    let not_full = if let Some(client_limit) = channel.modes.client_limit {
                        channel.users.len() < client_limit
                    } else { true };
                    if not_full { true } else {
                        self.feed_msg(&mut conn_state.stream, ErrChannelIsFull471{
                            client, channel: chname_str }).await?;
                        false
                    }
                };
                
                if do_join { (true, false)
                } else { (false, false) }
            } else { // if new channel
                (true, true)
            };
            
            let do_join = if let Some(max_joins) = self.config.max_joins {
                if join_count >= max_joins {
                    self.feed_msg(&mut conn_state.stream, ErrTooManyChannels405{
                            client, channel: chname_str }).await?;
                }
                join_count < max_joins
            } else { true };
            
            if do_join {
                joined_created.push((join, create));
                join_count += 1;
            }
        }
        
        for ((join, create), chname_str) in joined_created.iter().zip(channels.iter()) {
            let chname = chname_str.to_string();
            
            if *join {
                user.channels.insert(chname_str.to_string());
                if *create {
                    state.channels.insert(chname.clone(), Channel::new(
                                chname.clone(), user_nick.clone()));
                } else {
                    state.channels.get_mut(&chname).unwrap().add_user(&user_nick);
                    
                }
            }
        }
        if join_count!=0 {
            user.last_activity = SystemTime::now().duration_since(UNIX_EPOCH)
                        .unwrap().as_secs();
        }
        }
        
        // sending messages
        {
        let user = state.users.get(user_nick.as_str()).unwrap();
        for ((join, _), chname_str) in joined_created.iter().zip(channels.iter()) {
            if *join {
                let chanobj = state.channels.get(&chname_str.to_string()).unwrap();
                let join_msg = "JOIN ".to_string() + chname_str;
                {
                    let client = conn_state.user_state.client_name();
                    self.feed_msg_source(&mut conn_state.stream,
                                &conn_state.user_state.source, join_msg.as_str()).await?;
                    if let Some(ref topic) = chanobj.topic {
                        self.feed_msg(&mut conn_state.stream, RplTopic332{ client,
                                channel: chname_str, topic: &topic.topic }).await?;
                    }
                }
                self.send_names_from_channel(conn_state, chanobj,
                                &state.users, &user).await?;
                
                for (nick, _) in &chanobj.users {
                    if nick != user_nick.as_str() {
                        state.users.get(&nick.clone()).unwrap().send_msg_display(
                            &conn_state.user_state.source, join_msg.as_str())?;
                    }
                }
            }
        }
        }
        
        Ok(())
    }
    
    pub(super) async fn process_part<'a>(&self, conn_state: &mut ConnState,
            channels: Vec<&'a str>, reason: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        let mut statem = self.state.write().await;
        let state = statem.deref_mut();
        let user_nick = conn_state.user_state.nick.as_ref().unwrap().clone();
        
        let mut removed_from = vec![];
        let mut something_done = false;
        
        for channel in &channels {
            if let Some(chanobj) = state.channels.get_mut(channel.clone()) {
                let do_it = if chanobj.users.contains_key(&user_nick) {
                    chanobj.remove_user(&user_nick);
                    removed_from.push(true);
                    something_done = true;
                    true
                } else {
                    self.feed_msg(&mut conn_state.stream,
                                ErrNotOnChannel442{ client, channel }).await?;
                    removed_from.push(false);
                    false
                };
                
                // send message
                if do_it {
                    let part_msg = if let Some(r) = reason {
                        format!("PART {} :{}", channel, r)
                    } else {
                        format!("PART {}", channel)
                    };
                    for (nick, _) in &chanobj.users {
                        state.users.get(&nick.clone()).unwrap().send_msg_display(
                                    &conn_state.user_state.source, part_msg.as_str())?;
                    }
                }
            } else {
                self.feed_msg(&mut conn_state.stream,
                                ErrNoSuchChannel403{ client, channel }).await?;
                removed_from.push(false);
            }
        }
        
        let user_nick = conn_state.user_state.nick.as_ref().unwrap().clone();
        let mut user = state.users.get_mut(user_nick.as_str()).unwrap();
        for channel in &channels {
            user.channels.remove(&channel.to_string());
        }
        if something_done {
            user.last_activity = SystemTime::now().duration_since(UNIX_EPOCH)
                        .unwrap().as_secs();
        }
        Ok(())
    }
    
    pub(super) async fn process_topic<'a>(&self, conn_state: &mut ConnState, channel: &'a str,
            topic_opt: Option<&'a str>, msg: &'a Message<'a>) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        
        if let Some(topic) = topic_opt {
            let mut state = self.state.write().await;
            let user_nick = conn_state.user_state.nick.as_ref().unwrap();
            
            let do_change_topic = if let Some(chanobj) = state.channels.get(channel) {
                if chanobj.users.contains_key(user_nick) {
                    if !chanobj.modes.protected_topic || chanobj.users.get(user_nick)
                                .unwrap().is_half_operator() {
                        true
                    } else {
                        self.feed_msg(&mut conn_state.stream,
                                    ErrChanOpPrivsNeeded482{ client, channel }).await?;
                        false
                    }
                } else {
                    self.feed_msg(&mut conn_state.stream,
                                ErrNotOnChannel442{ client, channel }).await?;
                    false
                }
            } else {
                self.feed_msg(&mut conn_state.stream,
                                ErrNoSuchChannel403{ client, channel }).await?;
                false
            };
            
            if do_change_topic {
                let chanobj = state.channels.get_mut(channel).unwrap();
                if topic.len() != 0 {
                    chanobj.topic = Some(ChannelTopic::new_with_nick(
                        topic.to_string(), user_nick.clone()));
                } else {
                    chanobj.topic = None
                }
            }
            if do_change_topic {
                let chanobj = state.channels.get(channel).unwrap();
                for (cu, _) in &chanobj.users {
                    state.users.get(cu).unwrap().send_message(msg,
                                &conn_state.user_state.source)?;
                }
            }
        } else {
            // read
            let state = self.state.read().await;
            if let Some(chanobj) = state.channels.get(channel) {
                let user_nick = conn_state.user_state.nick.as_ref().unwrap();
                
                if chanobj.users.contains_key(user_nick) {
                    if let Some(ref topic) = chanobj.topic {
                        self.feed_msg(&mut conn_state.stream, RplTopic332{ client,
                            channel, topic: &topic.topic }).await?;
                        self.feed_msg(&mut conn_state.stream, RplTopicWhoTime333{ client,
                            channel, nick: &topic.nick, setat: topic.set_time }).await?;
                    } else {
                        self.feed_msg(&mut conn_state.stream, RplNoTopic331{ client,
                            channel }).await?;
                    }
                } else {
                    self.feed_msg(&mut conn_state.stream,
                                ErrNotOnChannel442{ client, channel }).await?;
                }
            } else {
                self.feed_msg(&mut conn_state.stream,
                                ErrNoSuchChannel403{ client, channel }).await?;
            }
        }
        Ok(())
    }
    
    async fn send_names_from_channel(&self, conn_state: &mut ConnState,
                channel: &Channel, users: &HashMap<String, User>, conn_user: &User)
                -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        
        let in_channel = channel.users.contains_key(&conn_user.nick);
        if !channel.modes.secret || in_channel {
            const NAMES_COUNT: usize = 20;
            let symbol = if channel.modes.secret { "=" } else { "@" };
            
            let mut name_chunk = vec![];
            name_chunk.reserve(NAMES_COUNT);
            
            for n in &channel.users {
                let user = users.get(n.0.as_str()).unwrap();
                if !user.modes.invisible || in_channel {
                    name_chunk.push(NameReplyStruct{
                        prefix: n.1.to_string(&conn_state.caps), nick: &user.nick });
                }
                if name_chunk.len() == NAMES_COUNT {
                    self.feed_msg(&mut conn_state.stream, RplNameReply353{ client, symbol,
                                channel: &channel.name, replies: &name_chunk }).await?;
                    name_chunk.clear();
                }
            }
            if name_chunk.len() != 0 {   // last chunk
                self.feed_msg(&mut conn_state.stream, RplNameReply353{ client, symbol,
                                channel: &channel.name, replies: &name_chunk }).await?;
            }
        }
        self.feed_msg(&mut conn_state.stream, RplEndOfNames366{ client,
                    channel: &channel.name }).await?;
        Ok(())
    }
    
    pub(super) async fn process_names<'a>(&self, conn_state: &mut ConnState,
            channels: Vec<&'a str>) -> Result<(), Box<dyn Error>> {
        let state = self.state.read().await;
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        let user = state.users.get(user_nick).unwrap();
        
        if channels.len() != 0 { 
            for c in channels.iter().filter_map(|c| state.channels.get(c.clone())) {
                self.send_names_from_channel(conn_state, &c, &state.users, &user).await?;
            }
        } else {
            for c in state.channels.values() {
                self.send_names_from_channel(conn_state, &c, &state.users, &user).await?;
            }
        }
        Ok(())
    }
    
    pub(super) async fn process_list<'a>(&self, conn_state: &mut ConnState,
            channels: Vec<&'a str>, server: Option<&'a str>) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        
        if server.is_some() {
            self.feed_msg(&mut conn_state.stream, ErrUnknownError400{ client,
                    command: "LIST", subcommand: None, info: "Server unsupported" }).await?;
        } else {
            let state = self.state.read().await;
            self.feed_msg(&mut conn_state.stream, RplListStart321{ client }).await?;
            let mut count = 0;
            for ch in channels.iter().filter_map(|ch| {
                    state.channels.get(&ch.to_string()).filter(|ch| !ch.modes.secret)
                }) {
                self.feed_msg(&mut conn_state.stream, RplList322{ client,
                        channel: &ch.name, client_count: ch.users.len(),
                        topic: ch.topic.as_ref().map(|x| &x.topic)
                            .unwrap_or(&String::new()) }).await?;
                count += 1;
            }
            if count == 0 {
                for ch in state.channels.values().filter(|ch| !ch.modes.secret) {
                    self.feed_msg(&mut conn_state.stream, RplList322{ client,
                        channel: &ch.name, client_count: ch.users.len(),
                        topic: ch.topic.as_ref().map(|x| &x.topic)
                            .unwrap_or(&String::new()) }).await?;
                }
            }
            self.feed_msg(&mut conn_state.stream, RplListEnd323{ client }).await?;
        }
        Ok(())
    }
    
    pub(super) async fn process_invite<'a>(&self, conn_state: &mut ConnState,
            nickname: &'a str, channel: &'a str, msg: &'a Message<'a>)
            -> Result<(), Box<dyn Error>> {
        let mut state = self.state.write().await;
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        let client = conn_state.user_state.client_name();
        
        let do_invite = if let Some(ref chanobj) = state.channels.get(channel) {
            if chanobj.users.contains_key(user_nick) {
                let do_invite2 = if chanobj.modes.invite_only {
                    if !chanobj.users.get(user_nick).unwrap().operator {
                        self.feed_msg(&mut conn_state.stream,
                                    ErrChanOpPrivsNeeded482{ client, channel }).await?;
                        false
                    } else { true }
                } else { true };
                if do_invite2 {
                    if chanobj.users.contains_key(nickname) {
                        self.feed_msg(&mut conn_state.stream, ErrUserOnChannel443{ client,
                                    nick: nickname, channel }).await?;
                        false
                    } else { true }
                } else { false }
            } else {
                self.feed_msg(&mut conn_state.stream,
                                    ErrNotOnChannel442{ client, channel }).await?;
                false
            }
        } else {
            self.feed_msg(&mut conn_state.stream,
                            ErrNoSuchChannel403{ client, channel }).await?;
            false
        };
        
        if do_invite {
            // check user
            if let Some(invited) = state.users.get_mut(nickname) {
                invited.invited_to.insert(channel.to_string());
                self.feed_msg(&mut conn_state.stream, RplInviting341{ client,
                                nick: nickname, channel }).await?;
                invited.send_message(msg, &conn_state.user_state.source)?;
            } else {
                self.feed_msg(&mut conn_state.stream,
                                ErrNoSuchNick401{ client, nick: nickname }).await?;
            }
        }
        Ok(())
    }
    
    pub(super) async fn process_kick<'a>(&self, conn_state: &mut ConnState, channel: &'a str,
            kick_users: Vec<&'a str>, comment: Option<&'a str>)
            -> Result<(), Box<dyn Error>> {
        let mut statem = self.state.write().await;
        let state = statem.deref_mut();
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        let client = conn_state.user_state.client_name();
        
        let mut kicked = vec![];
        
        if let Some(chanobj) = state.channels.get_mut(channel) {
            if chanobj.users.contains_key(user_nick) {
                let user_chum = chanobj.users.get(user_nick).unwrap();
                if user_chum.is_half_operator() {
                    let is_only_half_oper = user_chum.is_only_half_operator();
                    for kick_user in &kick_users {
                        let ku = kick_user.to_string();
                        if let Some(chum) = chanobj.users.get(&ku) {
                            if !chum.is_protected() && (!chum.is_half_operator() ||
                                !is_only_half_oper) {
                                chanobj.remove_user(&ku);
                                kicked.push(kick_user);
                            } else {
                                self.feed_msg(&mut conn_state.stream, ErrCannotDoCommand972{
                                    client }).await?;
                            }
                        } else {
                            self.feed_msg(&mut conn_state.stream, ErrUserNotInChannel441{
                                    client, nick: kick_user, channel }).await?;
                        }
                    }
                } else {
                    self.feed_msg(&mut conn_state.stream,
                                ErrChanOpPrivsNeeded482{ client, channel }).await?;
                }
            } else {
                self.feed_msg(&mut conn_state.stream,
                                ErrNotOnChannel442{ client, channel }).await?;
            }
        } else {
            self.feed_msg(&mut conn_state.stream,
                        ErrNoSuchChannel403{ client, channel }).await?;
        }
        
        {
            let chanobj = state.channels.get(channel).unwrap();
            for ku in &kicked {
                let kick_msg = format!("KICK {} {} :{}", channel, ku,
                                comment.unwrap_or("Kicked"));
                for (nick, _) in &chanobj.users {
                    state.users.get(&nick.to_string()).unwrap().send_msg_display(
                            &conn_state.user_state.source, kick_msg.clone())?;
                }
                state.users.get_mut(&ku.to_string()).unwrap().channels
                    .remove(&channel.to_string());
            }
        }
        Ok(())
    }
}
