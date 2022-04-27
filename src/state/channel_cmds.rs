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
        let user_joined = state.users.get(&user_nick).unwrap().channels.len();
        let mut join_count = user_joined;
        
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
                        if key != keys[i] {
                            self.feed_msg(&mut conn_state.stream, ErrBadChannelKey475{
                            client, channel: chname_str }).await?;
                            false
                        } else { true }
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
                join && join_count < max_joins
            } else { join };
            
            joined_created.push((do_join, create));
            if do_join { join_count += 1; }
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
        if join_count != user_joined {
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
                
                if do_it {
                    chanobj.remove_user(&user_nick);
                    removed_from.push(true);
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
            let symbol = if channel.modes.secret { "@" } else { "=" };
            
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

#[cfg(test)]
mod test {
    use super::*;
    use super::super::test::*;
    
    fn equal_channel_names<'a>(exp_msg: &'a str, exp_names: &'a[&'a str],
                names_replies: &'a[&'a str]) -> bool {
        let mut match_count = 0;
        let mut exp_names_sorted = Vec::from(exp_names);
        exp_names_sorted.sort();
        names_replies.iter().all(|reply| {
            if reply.starts_with(exp_msg) {
                reply[exp_msg.len()..].split_terminator(" ").all(|c| {
                    if exp_names_sorted.binary_search(&c).is_ok() {
                        match_count += 1;
                        true
                    } else { false }
                })
            } else { false }
        }) && match_count == exp_names.len()
    }
    
    #[tokio::test]
    async fn test_command_join() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;
        
        {
            let mut line_stream = login_to_test_and_skip(port, "charlie", "charlie2",
                    "Charlie Brown").await;
            
            line_stream.send("JOIN #fruits".to_string()).await.unwrap();
            assert_eq!(":charlie!~charlie2@127.0.0.1 JOIN #fruits".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 353 charlie = #fruits :~charlie".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 366 charlie #fruits :End of /NAMES list".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            
            let mut line_stream2 = login_to_test_and_skip(port, "eddix", "eddie",
                    "Eddie Flower").await;
            line_stream2.send("JOIN #fruits".to_string()).await.unwrap();
            assert_eq!(":eddix!~eddie@127.0.0.1 JOIN #fruits".to_string(),
                    line_stream2.next().await.unwrap().unwrap());
            assert!(equal_channel_names(":irc.irc 353 eddix = #fruits :",
                    &["eddix", "~charlie"],
                    &[&line_stream2.next().await.unwrap().unwrap()]));
            assert_eq!(":irc.irc 366 eddix #fruits :End of /NAMES list".to_string(),
                    line_stream2.next().await.unwrap().unwrap());
            
            assert_eq!(":eddix!~eddie@127.0.0.1 JOIN #fruits".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            
            let mut line_stream3 = login_to_test_and_skip(port, "logan", "logan",
                    "Logan Powers").await;
            line_stream3.send("JOIN #fruits".to_string()).await.unwrap();
            assert_eq!(":logan!~logan@127.0.0.1 JOIN #fruits".to_string(),
                    line_stream3.next().await.unwrap().unwrap());
            assert!(equal_channel_names(":irc.irc 353 logan = #fruits :",
                    &["eddix", "~charlie", "logan"],
                    &[&line_stream3.next().await.unwrap().unwrap()]));
            assert_eq!(":irc.irc 366 logan #fruits :End of /NAMES list".to_string(),
                    line_stream3.next().await.unwrap().unwrap());
            
            let mut exp_channel = Channel{ name: "#fruits".to_string(), topic: None,
                        creation_time: 0,
                        modes: ChannelModes::new_for_channel("charlie".to_string()),
                        default_modes: ChannelDefaultModes::default(),
                        ban_info: HashMap::new(),
                        users: [
                        ("charlie".to_string(), ChannelUserModes{ founder: true,
                            protected: false, voice: false, operator: true,
                            half_oper: false }),
                        ("eddix".to_string(), ChannelUserModes{ founder: false,
                            protected: false, voice: false, operator: false,
                            half_oper: false }),
                        ("logan".to_string(), ChannelUserModes{ founder: false,
                            protected: false, voice: false, operator: false,
                            half_oper: false })].into() };
            {
                let state = main_state.state.read().await;
                let channel = state.channels.get("#fruits").unwrap();
                exp_channel.creation_time = channel.creation_time;
                assert_eq!(exp_channel, *channel);
                
                assert_eq!(HashSet::from(["#fruits".to_string()]),
                        state.users.get("charlie").unwrap().channels);
                assert_eq!(HashSet::from(["#fruits".to_string()]),
                        state.users.get("eddix").unwrap().channels);
                assert_eq!(HashSet::from(["#fruits".to_string()]),
                        state.users.get("logan").unwrap().channels);
            }
            line_stream3.send("QUIT :Bye".to_string()).await.unwrap();
            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                exp_channel.remove_user("logan");
                let channel = state.channels.get("#fruits").unwrap();
                assert_eq!(exp_channel, *channel);
            }
            line_stream2.send("QUIT :Bye".to_string()).await.unwrap();
            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                exp_channel.remove_user("eddix");
                let channel = state.channels.get("#fruits").unwrap();
                assert_eq!(exp_channel, *channel);
            }
            line_stream.send("QUIT :Bye".to_string()).await.unwrap();
            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                exp_channel.remove_user("charlie");
                let channel = state.channels.get("#fruits").unwrap();
                assert_eq!(exp_channel, *channel);
            }
        }
        
        quit_test_server(main_state, handle).await;
    }
    
    #[tokio::test]
    async fn test_command_join_with_topic() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;
        
        {
            let mut line_stream = login_to_test_and_skip(port, "charlie", "charlie2",
                    "Charlie Brown").await;
            
            line_stream.send("JOIN #fruits".to_string()).await.unwrap();
            for _ in 0..3 { line_stream.next().await.unwrap().unwrap(); }
            
            time::sleep(Duration::from_millis(50)).await;
            {
                let mut state = main_state.state.write().await;
                state.channels.get_mut("#fruits").unwrap().topic = Some(
                        ChannelTopic::new_with_nick("This topic".to_string(), 
                                    "charlie".to_string()));
            }
            
            let mut line_stream2 = login_to_test_and_skip(port, "eddix", "eddie",
                    "Eddie Flower").await;
            line_stream2.send("JOIN #fruits".to_string()).await.unwrap();
            assert_eq!(":eddix!~eddie@127.0.0.1 JOIN #fruits".to_string(),
                    line_stream2.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 332 eddix #fruits :This topic".to_string(),
                    line_stream2.next().await.unwrap().unwrap());
            assert!(equal_channel_names(":irc.irc 353 eddix = #fruits :",
                    &["eddix", "~charlie"],
                    &[&line_stream2.next().await.unwrap().unwrap()]));
            assert_eq!(":irc.irc 366 eddix #fruits :End of /NAMES list".to_string(),
                    line_stream2.next().await.unwrap().unwrap());
        }
        
        quit_test_server(main_state, handle).await;
    }
    
    #[tokio::test]
    async fn test_command_join_limit_check() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;
        
        const CLIENT_LIMIT: usize = 10;
        // limit check
        {
            let mut line_stream = login_to_test_and_skip(port, "charlie", "charlie2",
                    "Charlie Brown").await;
            
            line_stream.send("JOIN #oranges".to_string()).await.unwrap();
            time::sleep(Duration::from_millis(70)).await;
            {
                let mut state = main_state.state.write().await;
                state.channels.get_mut("#oranges").unwrap().modes.client_limit = 
                            Some(CLIENT_LIMIT);
            }
            
            let mut line_streams = vec![];
            for i in 0..CLIENT_LIMIT {
                line_streams.push(login_to_test_and_skip(port, &format!("FInni{}", i),
                    &format!("FInnix{}", i), &format!("FInni Somewhere {}", i)).await);
                if i == CLIENT_LIMIT-2 {
                    time::sleep(Duration::from_millis(70)).await;
                }
            }
            for (i, line_streamx) in line_streams.iter_mut().enumerate() {
                line_streamx.send("JOIN #oranges".to_string()).await.unwrap();
                if i != CLIENT_LIMIT-1 {
                    assert_eq!(format!(":FInni{}!~FInnix{}@127.0.0.1 JOIN #oranges", i, i),
                            line_streamx.next().await.unwrap().unwrap());
                } else {
                    assert_eq!(":irc.irc 471 FInni9 #oranges :Cannot join channel (+l)"
                        .to_string(), line_streamx.next().await.unwrap().unwrap());
                }
            }
            
            for (_, line_streamx) in line_streams.iter_mut().enumerate() {
                line_streamx.send("QUIT :Bye".to_string()).await.unwrap();
            }
            line_stream.send("QUIT :Bye".to_string()).await.unwrap();
        }
        
        quit_test_server(main_state, handle).await;
    }
    
    #[tokio::test]
    async fn test_command_join_ban() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;
        // ban and ban exception
        {
            let mut line_stream = login_to_test_and_skip(port, "expert", "expertx",
                    "SuperExpert").await;
            line_stream.send("JOIN #secrets".to_string()).await.unwrap();
            
            time::sleep(Duration::from_millis(70)).await;
            {
                let mut state = main_state.state.write().await;
                let mut chmodes = &mut state.channels.get_mut("#secrets").unwrap().modes;
                chmodes.ban = Some(["roland!*@*".to_string(), "gugu!*@*".to_string(),
                        "devil!*@*".to_string()].into());
                chmodes.exception = Some(["devil!*@*".to_string()].into());
            }
            
            let mut roland_stream = login_to_test_and_skip(port, "roland", "Roland",
                    "Roland XX").await;
            let mut gugu_stream = login_to_test_and_skip(port, "gugu", "gugu",
                    "GuuGuu").await;
            let mut devil_stream = login_to_test_and_skip(port, "devil", "scary_devil",
                    "Very Scary Devil").await;
            let mut angel_stream = login_to_test_and_skip(port, "angel", "good_angel",
                    "Very Good Angel").await;
            
            roland_stream.send("JOIN #secrets".to_string()).await.unwrap();
            assert_eq!(":irc.irc 474 roland #secrets :Cannot join channel (+b)".to_string(),
                    roland_stream.next().await.unwrap().unwrap());
            gugu_stream.send("JOIN #secrets".to_string()).await.unwrap();
            assert_eq!(":irc.irc 474 gugu #secrets :Cannot join channel (+b)".to_string(),
                    gugu_stream.next().await.unwrap().unwrap());
            devil_stream.send("JOIN #secrets".to_string()).await.unwrap();
            assert_eq!(":devil!~scary_devil@127.0.0.1 JOIN #secrets".to_string(),
                    devil_stream.next().await.unwrap().unwrap());
            angel_stream.send("JOIN #secrets".to_string()).await.unwrap();
            assert_eq!(":angel!~good_angel@127.0.0.1 JOIN #secrets".to_string(),
                    angel_stream.next().await.unwrap().unwrap());
        }
        
        quit_test_server(main_state, handle).await;
    }
    
    #[tokio::test]
    async fn test_command_join_invite() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;
        // invite
        {
            let mut line_stream = login_to_test_and_skip(port, "damian", "damian",
                    "Damian Kozlowski").await;
            line_stream.send("JOIN #exclusive".to_string()).await.unwrap();
            
            time::sleep(Duration::from_millis(70)).await;
            {
                let mut state = main_state.state.write().await;
                let mut chmodes = &mut state.channels.get_mut("#exclusive").unwrap().modes;
                chmodes.invite_only = true;
                chmodes.invite_exception = Some([ "ex*!*@*".to_string() ].into());
            }
            
            let mut henry_stream = login_to_test_and_skip(port, "henry", "henryk",
                    "Henri Stones").await;
            let mut excel_stream = login_to_test_and_skip(port, "excel", "excel",
                    "Excel Total").await;
            
            henry_stream.send("JOIN #exclusive".to_string()).await.unwrap();
            assert_eq!(":irc.irc 473 henry #exclusive :Cannot join channel (+i)".to_string(),
                    henry_stream.next().await.unwrap().unwrap());
            excel_stream.send("JOIN #exclusive".to_string()).await.unwrap();
            assert_eq!(":excel!~excel@127.0.0.1 JOIN #exclusive".to_string(),
                    excel_stream.next().await.unwrap().unwrap());
            
            {
                let mut state = main_state.state.write().await;
                state.users.get_mut("henry").unwrap().invited_to =
                        ["#exclusive".to_string()].into();
            }
            henry_stream.send("JOIN #exclusive".to_string()).await.unwrap();
            assert_eq!(":henry!~henryk@127.0.0.1 JOIN #exclusive".to_string(),
                    henry_stream.next().await.unwrap().unwrap());
        }
        quit_test_server(main_state, handle).await;
    }
    
    #[tokio::test]
    async fn test_command_join_key_check() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;
        // key check
        {
            let mut line_stream = login_to_test_and_skip(port, "garry", "garry",
                    "Garry NextSomebody").await;
            line_stream.send("JOIN #protected".to_string()).await.unwrap();
            
            time::sleep(Duration::from_millis(70)).await;
            {
                let mut state = main_state.state.write().await;
                state.channels.get_mut("#protected").unwrap().modes.key =
                        Some("longpassword!!".to_string());
            }
            
            let mut jobe_stream = login_to_test_and_skip(port, "jobe", "jobe",
                    "Jobe Smith").await;
            jobe_stream.send("JOIN #protected".to_string()).await.unwrap();
            assert_eq!(":irc.irc 475 jobe #protected :Cannot join channel (+k)".to_string(),
                    jobe_stream.next().await.unwrap().unwrap());
            
            jobe_stream.send("JOIN #protected longpass".to_string()).await.unwrap();
            assert_eq!(":irc.irc 475 jobe #protected :Cannot join channel (+k)".to_string(),
                    jobe_stream.next().await.unwrap().unwrap());
            
            jobe_stream.send("JOIN #protected longpassword!!".to_string()).await.unwrap();
            assert_eq!(":jobe!~jobe@127.0.0.1 JOIN #protected".to_string(),
                    jobe_stream.next().await.unwrap().unwrap());
        }
        
        quit_test_server(main_state, handle).await;
    }
    
    #[tokio::test]
    async fn test_command_join_max_joins() {
        let mut config = MainConfig::default();
        const MAX_JOINS: usize = 10;
        config.max_joins = Some(MAX_JOINS);
        let (main_state, handle, port) = run_test_server(config).await;
        
        {
            let mut line_stream = login_to_test_and_skip(port, "garry", "garry",
                    "Garry NextSomebody").await;
            for i in 0..(MAX_JOINS+1) {
                line_stream.send(format!("JOIN #chan{}", i)).await.unwrap();
            }
            
            time::sleep(Duration::from_millis(50)).await;
            
            let mut jobe_stream = login_to_test_and_skip(port, "jobe", "jobe",
                    "Jobe Smith").await;
            for i in 0..(MAX_JOINS+1) {
                jobe_stream.send(format!("JOIN #chan{}", i)).await.unwrap();
                if i<MAX_JOINS {
                    assert_eq!(format!(":jobe!~jobe@127.0.0.1 JOIN #chan{}", i),
                            jobe_stream.next().await.unwrap().unwrap());
                    jobe_stream.next().await.unwrap().unwrap();
                    jobe_stream.next().await.unwrap().unwrap();
                } else {
                    assert_eq!(":irc.irc 405 jobe #chan10 :You have joined too many channels"
                            .to_string(), jobe_stream.next().await.unwrap().unwrap());
                }
            }
        }
        
        quit_test_server(main_state, handle).await;
    }
    
    #[tokio::test]
    async fn test_command_join_no_max_joins() {
        const MAX_JOINS: usize = 10;
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;
        
        {
            let mut line_stream = login_to_test_and_skip(port, "garry", "garry",
                    "Garry NextSomebody").await;
            for i in 0..(MAX_JOINS+1) {
                line_stream.send(format!("JOIN #chan{}", i)).await.unwrap();
            }
            
            time::sleep(Duration::from_millis(50)).await;
            
            let mut jobe_stream = login_to_test_and_skip(port, "jobe", "jobe",
                    "Jobe Smith").await;
            for i in 0..(MAX_JOINS+1) {
                jobe_stream.send(format!("JOIN #chan{}", i)).await.unwrap();
                assert_eq!(format!(":jobe!~jobe@127.0.0.1 JOIN #chan{}", i),
                        jobe_stream.next().await.unwrap().unwrap());
                jobe_stream.next().await.unwrap().unwrap();
                jobe_stream.next().await.unwrap().unwrap();
            }
        }
        
        quit_test_server(main_state, handle).await;
    }
    
    #[tokio::test]
    async fn test_command_join_multiple() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;
        
        {
            let mut line_stream = login_to_test_and_skip(port, "derek", "derek-z",
                    "Derek Zinni").await;
            
            line_stream.send("JOIN #finances".to_string()).await.unwrap();
            line_stream.send("JOIN #stocks".to_string()).await.unwrap();
            line_stream.send("JOIN #hardware".to_string()).await.unwrap();
            line_stream.send("JOIN #software".to_string()).await.unwrap();
            line_stream.send("JOIN #furnitures".to_string()).await.unwrap();
            line_stream.send("JOIN #tools".to_string()).await.unwrap();
            line_stream.send("JOIN #cloaths".to_string()).await.unwrap();
            
            time::sleep(Duration::from_millis(50)).await;
            {
                let mut state = main_state.state.write().await;
                state.channels.get_mut("#finances").unwrap().modes.client_limit = Some(2);
                state.channels.get_mut("#stocks").unwrap().modes.client_limit = Some(3);
                state.channels.get_mut("#hardware").unwrap().modes.ban =
                            Some(["*g*!*@*".to_string()].into());
                state.channels.get_mut("#software").unwrap().modes.invite_only = true;
                let mut modes = &mut state.channels.get_mut("#furnitures").unwrap().modes;
                modes.invite_only = true;
                modes.invite_exception = Some(["*g*!*@*".to_string()].into());
            }
            
            let mut robby_stream = login_to_test_and_skip(port, "robby", "robbie",
                    "Robbie Runnie").await;
            robby_stream.send("JOIN #finances".to_string()).await.unwrap();
            robby_stream.send("JOIN #stocks".to_string()).await.unwrap();
            
            let mut zephyr_stream = login_to_test_and_skip(port, "zephyr", "zephyr",
                    "Zephyr Somewhere").await;
            zephyr_stream.send("JOIN #stocks".to_string()).await.unwrap();
            
            let mut greg_stream = login_to_test_and_skip(port, "greg", "gregory",
                    "Gregory Powerful").await;
            greg_stream.send(
                "JOIN #finances,#stocks,#hardware,#software,#furnitures,#tools,#cloaths"
                .to_string()).await.unwrap();
            
            assert_eq!(":irc.irc 471 greg #finances :Cannot join channel (+l)".to_string(),
                    greg_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 471 greg #stocks :Cannot join channel (+l)".to_string(),
                    greg_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 474 greg #hardware :Cannot join channel (+b)".to_string(),
                    greg_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 473 greg #software :Cannot join channel (+i)".to_string(),
                    greg_stream.next().await.unwrap().unwrap());
            assert_eq!(":greg!~gregory@127.0.0.1 JOIN #furnitures".to_string(),
                    greg_stream.next().await.unwrap().unwrap());
            assert!(equal_channel_names(":irc.irc 353 greg = #furnitures :",
                    &["~derek", "greg"], &[&greg_stream.next().await.unwrap().unwrap()]));
            assert_eq!(":irc.irc 366 greg #furnitures :End of /NAMES list".to_string(),
                    greg_stream.next().await.unwrap().unwrap());
            assert_eq!(":greg!~gregory@127.0.0.1 JOIN #tools".to_string(),
                    greg_stream.next().await.unwrap().unwrap());
            assert!(equal_channel_names(":irc.irc 353 greg = #tools :",
                    &["~derek", "greg"], &[&greg_stream.next().await.unwrap().unwrap()]));
            assert_eq!(":irc.irc 366 greg #tools :End of /NAMES list".to_string(),
                    greg_stream.next().await.unwrap().unwrap());
            assert_eq!(":greg!~gregory@127.0.0.1 JOIN #cloaths".to_string(),
                    greg_stream.next().await.unwrap().unwrap());
            assert!(equal_channel_names(":irc.irc 353 greg = #cloaths :",
                    &["~derek", "greg"], &[&greg_stream.next().await.unwrap().unwrap()]));
            assert_eq!(":irc.irc 366 greg #cloaths :End of /NAMES list".to_string(),
                    greg_stream.next().await.unwrap().unwrap());
            
            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.write().await;
                assert!(!state.channels.get("#finances").unwrap()
                            .users.contains_key("greg"));
                assert!(!state.channels.get("#stocks").unwrap()
                            .users.contains_key("greg"));
                assert!(!state.channels.get("#hardware").unwrap()
                            .users.contains_key("greg"));
                assert!(!state.channels.get("#software").unwrap()
                            .users.contains_key("greg"));
                assert!(state.channels.get("#furnitures").unwrap()
                            .users.contains_key("greg"));
                assert!(state.channels.get("#tools").unwrap()
                            .users.contains_key("greg"));
                assert!(state.channels.get("#cloaths").unwrap()
                            .users.contains_key("greg"));
                assert_eq!(HashSet::from(["#tools".to_string(), "#furnitures".to_string(),
                        "#cloaths".to_string()]),
                        state.users.get("greg").unwrap().channels);
            }
        }
        
        quit_test_server(main_state, handle).await;
    }
    
    #[tokio::test]
    async fn test_command_join_multiple_with_key() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;
        
        {
            let mut line_stream = login_to_test_and_skip(port, "derek", "derek-z",
                    "Derek Zinni").await;
            
            line_stream.send("JOIN #crypto".to_string()).await.unwrap();
            line_stream.send("JOIN #servers".to_string()).await.unwrap();
            line_stream.send("JOIN #drinks".to_string()).await.unwrap();
            line_stream.send("JOIN #job".to_string()).await.unwrap();
            line_stream.send("JOIN #cars".to_string()).await.unwrap();
            
            time::sleep(Duration::from_millis(50)).await;
            {
                let mut state = main_state.state.write().await;
                state.channels.get_mut("#crypto").unwrap().modes.key =
                        Some("altcoin".to_string());
                state.channels.get_mut("#servers").unwrap().modes.key =
                        Some("amd_epyc".to_string());
                state.channels.get_mut("#cars").unwrap().modes.key =
                        Some("Buggatti".to_string());
            }
            
            let mut greg_stream = login_to_test_and_skip(port, "greg", "gregory",
                    "Gregory Powerful").await;
            greg_stream.send(
                "JOIN #crypto,#servers,#drinks,#job,#cars ZRX,amd_epyc,tequilla,,Lambo"
                .to_string()).await.unwrap();
            
            assert_eq!(":irc.irc 475 greg #crypto :Cannot join channel (+k)".to_string(),
                    greg_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 475 greg #cars :Cannot join channel (+k)".to_string(),
                    greg_stream.next().await.unwrap().unwrap());
            assert_eq!(":greg!~gregory@127.0.0.1 JOIN #servers".to_string(),
                    greg_stream.next().await.unwrap().unwrap());
            assert!(equal_channel_names(":irc.irc 353 greg = #servers :",
                    &["~derek", "greg"], &[&greg_stream.next().await.unwrap().unwrap()]));
            assert_eq!(":irc.irc 366 greg #servers :End of /NAMES list".to_string(),
                    greg_stream.next().await.unwrap().unwrap());
            assert_eq!(":greg!~gregory@127.0.0.1 JOIN #drinks".to_string(),
                    greg_stream.next().await.unwrap().unwrap());
            assert!(equal_channel_names(":irc.irc 353 greg = #drinks :",
                    &["~derek", "greg"], &[&greg_stream.next().await.unwrap().unwrap()]));
            assert_eq!(":irc.irc 366 greg #drinks :End of /NAMES list".to_string(),
                    greg_stream.next().await.unwrap().unwrap());
            assert_eq!(":greg!~gregory@127.0.0.1 JOIN #job".to_string(),
                    greg_stream.next().await.unwrap().unwrap());
            assert!(equal_channel_names(":irc.irc 353 greg = #job :",
                    &["~derek", "greg"], &[&greg_stream.next().await.unwrap().unwrap()]));
            assert_eq!(":irc.irc 366 greg #job :End of /NAMES list".to_string(),
                    greg_stream.next().await.unwrap().unwrap());
        }
        
        time::sleep(Duration::from_millis(50)).await;
        {
            let state = main_state.state.write().await;
            assert!(!state.channels.get("#crypto").unwrap().users.contains_key("greg"));
            assert!(!state.channels.get("#cars").unwrap().users.contains_key("greg"));
            assert!(state.channels.get("#servers").unwrap().users.contains_key("greg"));
            assert!(state.channels.get("#drinks").unwrap().users.contains_key("greg"));
            assert!(state.channels.get("#job").unwrap().users.contains_key("greg"));
            assert_eq!(HashSet::from(["#servers".to_string(), "#drinks".to_string(),
                    "#job".to_string()]), state.users.get("greg").unwrap().channels);
        }
        
        quit_test_server(main_state, handle).await;
    }
    
    #[tokio::test]
    async fn test_command_join_multiple_no_max_joins() {
        const MAX_JOINS: usize = 10;
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;
        
        {
            let mut line_stream = login_to_test_and_skip(port, "garry", "garry",
                    "Garry NextSomebody").await;
            for i in 0..(MAX_JOINS+1) {
                line_stream.send(format!("JOIN #chan{}", i)).await.unwrap();
            }
            
            time::sleep(Duration::from_millis(50)).await;
            
            let mut jobe_stream = login_to_test_and_skip(port, "jobe", "jobe",
                    "Jobe Smith").await;
            jobe_stream.send(format!("JOIN {}", (0..(MAX_JOINS+1))
                    .map(|x| format!("#chan{}", x))
                        .collect::<Vec<_>>().join(","))).await.unwrap();
            
            for i in 0..(MAX_JOINS+1) {
                assert_eq!(format!(":jobe!~jobe@127.0.0.1 JOIN #chan{}", i),
                        jobe_stream.next().await.unwrap().unwrap());
                jobe_stream.next().await.unwrap().unwrap();
                jobe_stream.next().await.unwrap().unwrap();
            }
        }
        
        quit_test_server(main_state, handle).await;
    }
    
    #[tokio::test]
    async fn test_command_join_activity() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;
        
        {
            let mut line_stream = login_to_test_and_skip(port, "florian", "florian-f",
                    "Florian Fabian").await;
            
            line_stream.send("JOIN #roses".to_string()).await.unwrap();
            line_stream.send("JOIN #tulipans".to_string()).await.unwrap();
            line_stream.send("JOIN #fruits".to_string()).await.unwrap();
            line_stream.send("JOIN #flowers".to_string()).await.unwrap();
            
            time::sleep(Duration::from_millis(50)).await;
            {
                let mut state = main_state.state.write().await;
                state.channels.get_mut("#roses").unwrap().modes.key =
                        Some("whiterose".to_string());
                state.channels.get_mut("#fruits").unwrap().modes.key =
                        Some("cocoa".to_string());
            }
            
            let mut line_stream = login_to_test_and_skip(port, "rosy", "rosy-f",
                    "Rosy Red").await;
            
            time::sleep(Duration::from_millis(50)).await;
            let activity = {
                let mut state = main_state.state.write().await;
                state.users.get_mut("rosy").unwrap().last_activity -= 10;
                state.users.get("rosy").unwrap().last_activity
            };
            
            line_stream.send("JOIN #roses".to_string()).await.unwrap();
            time::sleep(Duration::from_millis(50)).await;
            assert_eq!(":irc.irc 475 rosy #roses :Cannot join channel (+k)".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            {
                let state = main_state.state.read().await;
                assert_eq!(activity, state.users.get("rosy").unwrap().last_activity);
            }
            
            line_stream.send("JOIN #tulipans".to_string()).await.unwrap();
            time::sleep(Duration::from_millis(50)).await;
            assert_eq!(":rosy!~rosy-f@127.0.0.1 JOIN #tulipans".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            {
                let state = main_state.state.read().await;
                assert_ne!(activity, state.users.get("rosy").unwrap().last_activity);
                line_stream.next().await.unwrap().unwrap();
                line_stream.next().await.unwrap().unwrap();
            }
            
            let activity = {
                let mut state = main_state.state.write().await;
                state.users.get_mut("rosy").unwrap().last_activity -= 10;
                state.users.get("rosy").unwrap().last_activity
            };
            
            line_stream.send("JOIN #fruits".to_string()).await.unwrap();
            time::sleep(Duration::from_millis(50)).await;
            assert_eq!(":irc.irc 475 rosy #fruits :Cannot join channel (+k)".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            {
                let state = main_state.state.read().await;
                assert_eq!(activity, state.users.get("rosy").unwrap().last_activity);
            }
            
            line_stream.send("JOIN #flowers".to_string()).await.unwrap();
            time::sleep(Duration::from_millis(50)).await;
            assert_eq!(":rosy!~rosy-f@127.0.0.1 JOIN #flowers".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            {
                let state = main_state.state.read().await;
                assert_ne!(activity, state.users.get("rosy").unwrap().last_activity);
            }
        }
        
        quit_test_server(main_state, handle).await;
    }
    
    #[tokio::test]
    async fn test_command_join_multiple_activity() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;
        
        {
            let mut line_stream = login_to_test_and_skip(port, "mobiler", "mobilerx",
                    "Mobiler Smartphone").await;
            
            line_stream.send("JOIN #smartphones".to_string()).await.unwrap();
            line_stream.send("JOIN #smartwatches".to_string()).await.unwrap();
            line_stream.send("JOIN #ebooks".to_string()).await.unwrap();
            line_stream.send("JOIN #smartglasses".to_string()).await.unwrap();
            line_stream.send("JOIN #wearables".to_string()).await.unwrap();
            line_stream.send("JOIN #fitbits".to_string()).await.unwrap();
            line_stream.send("JOIN #huawei".to_string()).await.unwrap();
            
            time::sleep(Duration::from_millis(50)).await;
            {
                let mut state = main_state.state.write().await;
                state.channels.get_mut("#ebooks").unwrap().modes.key =
                        Some("Neuromancer".to_string());
                state.channels.get_mut("#wearables").unwrap().modes.key =
                        Some("Cyberpunk".to_string());
                state.channels.get_mut("#fitbits").unwrap().modes.key =
                        Some("training".to_string());
                state.channels.get_mut("#huawei").unwrap().modes.key =
                        Some("secretpass".to_string());
            }
            
            let mut line_stream = login_to_test_and_skip(port, "geek", "geeker",
                    "Young Geek").await;
            
            let activity = {
                let mut state = main_state.state.write().await;
                state.users.get_mut("geek").unwrap().last_activity -= 10;
                state.users.get("geek").unwrap().last_activity
            };
            
            line_stream.send("JOIN #smartphones".to_string()).await.unwrap();
            assert_eq!(":geek!~geeker@127.0.0.1 JOIN #smartphones".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            line_stream.next().await.unwrap().unwrap();
            line_stream.next().await.unwrap().unwrap();
            
            line_stream.send("JOIN #smartwatches,#ebooks,#smartglasses,#wearables"
                        .to_string()).await.unwrap();
            assert_eq!(":irc.irc 475 geek #ebooks :Cannot join channel (+k)".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 475 geek #wearables :Cannot join channel (+k)".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":geek!~geeker@127.0.0.1 JOIN #smartwatches".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            line_stream.next().await.unwrap().unwrap();
            line_stream.next().await.unwrap().unwrap();
            assert_eq!(":geek!~geeker@127.0.0.1 JOIN #smartglasses".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            line_stream.next().await.unwrap().unwrap();
            line_stream.next().await.unwrap().unwrap();
            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                assert_ne!(activity, state.users.get("geek").unwrap().last_activity);
            }
            
            let activity = {
                let mut state = main_state.state.write().await;
                state.users.get_mut("geek").unwrap().last_activity -= 10;
                state.users.get("geek").unwrap().last_activity
            };
            
            line_stream.send("JOIN #fitbits,#huawei".to_string()).await.unwrap();
            assert_eq!(":irc.irc 475 geek #fitbits :Cannot join channel (+k)".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 475 geek #huawei :Cannot join channel (+k)".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                assert_eq!(activity, state.users.get("geek").unwrap().last_activity);
            }
        }
        
        quit_test_server(main_state, handle).await;
    }
    
    #[tokio::test]
    async fn test_command_join_multi_prefix_names() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;
        
        {
            let mut line_stream = connect_to_test(port).await;
            line_stream.send("CAP LS 302".to_string()).await.unwrap();
            line_stream.send("NICK mati".to_string()).await.unwrap();
            line_stream.send("USER mat 8 * :MatiSzpaki".to_string()).await.unwrap();
            line_stream.send("CAP REQ :multi-prefix".to_string()).await.unwrap();
            line_stream.send("CAP END".to_string()).await.unwrap();
            
            for _ in 0..20 { line_stream.next().await.unwrap().unwrap(); }
            
            line_stream.send("JOIN #oldhardware".to_string()).await.unwrap();
            assert_eq!(":mati!~mat@127.0.0.1 JOIN #oldhardware".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 353 mati = #oldhardware :~@mati".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 366 mati #oldhardware :End of /NAMES list".to_string(),
                    line_stream.next().await.unwrap().unwrap());
        }
        
        quit_test_server(main_state, handle).await;
    }
    
    #[tokio::test]
    async fn test_command_part() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;
        
        {
            let mut line_stream = login_to_test_and_skip(port, "joel", "mrjoel",
                    "Joel Dickson").await;
            line_stream.send("JOIN #math".to_string()).await.unwrap();
            for _ in 0..3 { line_stream.next().await.unwrap().unwrap(); }
            
            let mut line_stream2 = login_to_test_and_skip(port, "noah", "z_noah",
                    "Noah Monus").await;
            line_stream2.send("JOIN #math".to_string()).await.unwrap();
            for _ in 0..3 { line_stream2.next().await.unwrap().unwrap(); }
            line_stream.next().await.unwrap().unwrap();
            
            time::sleep(Duration::from_millis(50)).await;
            let mut exp_channel = {
                let state = main_state.state.read().await;
                state.channels.get("#math").unwrap().clone()
            };
            exp_channel.remove_user("joel");
            
            line_stream.send("PART #math".to_string()).await.unwrap();
            assert_eq!(":joel!~mrjoel@127.0.0.1 PART #math".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":joel!~mrjoel@127.0.0.1 PART #math".to_string(),
                    line_stream2.next().await.unwrap().unwrap());
            
            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                assert_eq!(exp_channel, *state.channels.get("#math").unwrap());
                assert_eq!(HashSet::new(), state.users.get("joel").unwrap().channels);
            }
            
            exp_channel.remove_user("noah");
            
            line_stream2.send("PART #math".to_string()).await.unwrap();
            assert_eq!(":noah!~z_noah@127.0.0.1 PART #math".to_string(),
                    line_stream2.next().await.unwrap().unwrap());
            
            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                assert_eq!(exp_channel, *state.channels.get("#math").unwrap());
                assert_eq!(HashSet::new(), state.users.get("noah").unwrap().channels);
            }
        }
        
        quit_test_server(main_state, handle).await;
    }
    
    #[tokio::test]
    async fn test_command_part_with_reason() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;
        
        {
            let mut line_stream = login_to_test_and_skip(port, "joel", "mrjoel",
                    "Joel Dickson").await;
            line_stream.send("JOIN #math".to_string()).await.unwrap();
            for _ in 0..3 { line_stream.next().await.unwrap().unwrap(); }
            
            let mut line_stream2 = login_to_test_and_skip(port, "noah", "z_noah",
                    "Noah Monus").await;
            line_stream2.send("JOIN #math".to_string()).await.unwrap();
            for _ in 0..3 { line_stream2.next().await.unwrap().unwrap(); }
            line_stream.next().await.unwrap().unwrap();
            
            time::sleep(Duration::from_millis(50)).await;
            let mut exp_channel = {
                let state = main_state.state.read().await;
                state.channels.get("#math").unwrap().clone()
            };
            exp_channel.remove_user("joel");
            
            line_stream.send("PART #math :I don't have".to_string()).await.unwrap();
            assert_eq!(":joel!~mrjoel@127.0.0.1 PART #math :I don't have".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":joel!~mrjoel@127.0.0.1 PART #math :I don't have".to_string(),
                    line_stream2.next().await.unwrap().unwrap());
            
            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                assert_eq!(exp_channel, *state.channels.get("#math").unwrap());
                assert_eq!(HashSet::new(), state.users.get("joel").unwrap().channels);
            }
            
            exp_channel.remove_user("noah");
            
            line_stream2.send("PART #math :I don't have too".to_string()).await.unwrap();
            assert_eq!(":noah!~z_noah@127.0.0.1 PART #math :I don't have too".to_string(),
                    line_stream2.next().await.unwrap().unwrap());
            
            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                assert_eq!(exp_channel, *state.channels.get("#math").unwrap());
                assert_eq!(HashSet::new(), state.users.get("noah").unwrap().channels);
            }
        }
        
        quit_test_server(main_state, handle).await;
    }
    
    #[tokio::test]
    async fn test_command_part_multiple() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;
        
        {
            let mut line_stream = login_to_test_and_skip(port, "joel", "mrjoel",
                    "Joel Dickson").await;
            line_stream.send("JOIN #math,#algebra,#physics".to_string()).await.unwrap();
            for _ in 0..9 { line_stream.next().await.unwrap().unwrap(); }
            
            let mut line_stream2 = login_to_test_and_skip(port, "marty1", "marty1",
                    "Marty XXX 1").await;
            let mut line_stream3 = login_to_test_and_skip(port, "lucky1", "lucky1",
                    "Lucky XXX 1").await;
            
            line_stream2.send("JOIN #math,#algebra".to_string()).await.unwrap();
            line_stream3.send("JOIN #physics,#algebra".to_string()).await.unwrap();
            for _ in 0..7 { line_stream2.next().await.unwrap().unwrap(); }
            for _ in 0..6 { line_stream3.next().await.unwrap().unwrap(); }
            for _ in 0..4 { line_stream.next().await.unwrap().unwrap(); }
            
            time::sleep(Duration::from_millis(50)).await;
            let (mut exp_math, mut exp_algebra, mut exp_physics) = {
                let state = main_state.state.read().await;
                (state.channels.get("#math").unwrap().clone(),
                    state.channels.get("#algebra").unwrap().clone(),
                    state.channels.get("#physics").unwrap().clone())
            };
            
            line_stream2.send("PART #math,#algebra :Return".to_string()).await.unwrap();
            assert_eq!(":marty1!~marty1@127.0.0.1 PART #math :Return".to_string(),
                    line_stream2.next().await.unwrap().unwrap());
            assert_eq!(":marty1!~marty1@127.0.0.1 PART #algebra :Return".to_string(),
                    line_stream2.next().await.unwrap().unwrap());
            assert_eq!(":marty1!~marty1@127.0.0.1 PART #algebra :Return".to_string(),
                    line_stream3.next().await.unwrap().unwrap());
            assert_eq!(":marty1!~marty1@127.0.0.1 PART #math :Return".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":marty1!~marty1@127.0.0.1 PART #algebra :Return".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            
            exp_math.remove_user("marty1");
            exp_algebra.remove_user("marty1");
            
            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                assert_eq!(exp_math, *state.channels.get("#math").unwrap());
                assert_eq!(exp_algebra, *state.channels.get("#algebra").unwrap());
                assert_eq!(HashSet::new(), state.users.get("marty1").unwrap().channels);
            }
            
            line_stream3.send("PART #physics,#algebra :Return".to_string()).await.unwrap();
            assert_eq!(":lucky1!~lucky1@127.0.0.1 PART #physics :Return".to_string(),
                    line_stream3.next().await.unwrap().unwrap());
            assert_eq!(":lucky1!~lucky1@127.0.0.1 PART #algebra :Return".to_string(),
                    line_stream3.next().await.unwrap().unwrap());
            assert_eq!(":lucky1!~lucky1@127.0.0.1 PART #physics :Return".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":lucky1!~lucky1@127.0.0.1 PART #algebra :Return".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            
            exp_physics.remove_user("lucky1");
            exp_algebra.remove_user("lucky1");
            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                assert_eq!(exp_physics, *state.channels.get("#physics").unwrap());
                assert_eq!(exp_algebra, *state.channels.get("#algebra").unwrap());
                assert_eq!(HashSet::new(), state.users.get("lucky1").unwrap().channels);
            }
        }
        
        quit_test_server(main_state, handle).await;
    }
    
    #[tokio::test]
    async fn test_command_part_multiple_activity() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;
        
        {
            let mut line_stream = login_to_test_and_skip(port, "joel", "mrjoel",
                    "Joel Dickson").await;
            line_stream.send("JOIN #biology,#technics".to_string()).await.unwrap();
            for _ in 0..6 { line_stream.next().await.unwrap().unwrap(); }
            
            let mut line_stream2 = login_to_test_and_skip(port, "marty1", "marty1",
                    "Marty XXX 1").await;
            
            line_stream2.send("JOIN #biology".to_string()).await.unwrap();
            for _ in 0..3 { line_stream2.next().await.unwrap().unwrap(); }
            
            let activity = {
                let mut state = main_state.state.write().await;
                state.users.get_mut("marty1").unwrap().last_activity -= 10;
                state.users.get("marty1").unwrap().last_activity
            };
            line_stream2.send("PART #physics,#algebra :Return".to_string()).await.unwrap();
            assert_eq!(":irc.irc 403 marty1 #physics :No such channel".to_string(),
                    line_stream2.next().await.unwrap().unwrap());
            assert_eq!(":irc.irc 403 marty1 #algebra :No such channel".to_string(),
                    line_stream2.next().await.unwrap().unwrap());
            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                assert_eq!(activity, state.users.get("marty1").unwrap().last_activity);
            }
            
            let activity = {
                let mut state = main_state.state.write().await;
                state.users.get_mut("marty1").unwrap().last_activity -= 10;
                state.users.get("marty1").unwrap().last_activity
            };
            
            line_stream2.send("PART #technics,#biology :Return".to_string()).await.unwrap();
            assert_eq!(":irc.irc 442 marty1 #technics :You're not on that channel"
                    .to_string(), line_stream2.next().await.unwrap().unwrap());
            assert_eq!(":marty1!~marty1@127.0.0.1 PART #biology :Return".to_string(),
                    line_stream2.next().await.unwrap().unwrap());
            time::sleep(Duration::from_millis(50)).await;
            {   // has some activity
                let state = main_state.state.read().await;
                assert_ne!(activity, state.users.get("marty1").unwrap().last_activity);
            }
        }
        
        quit_test_server(main_state, handle).await;
    }
    
    #[tokio::test]
    async fn test_command_topic_write() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;
        
        {
            let mut line_stream = login_to_test_and_skip(port, "robbie", "robbie",
                    "Robbie Williams").await;
            line_stream.send("JOIN #hifi,#techno,#trance".to_string()).await.unwrap();
            for _ in 0..9 { line_stream.next().await.unwrap().unwrap(); }
            
            line_stream.send("TOPIC #hifi :About HiFi".to_string()).await.unwrap();
            line_stream.send("TOPIC #techno :About Techno Music".to_string()).await.unwrap();
            line_stream.send("TOPIC #trance :About Trance Music".to_string()).await.unwrap();
            
            assert_eq!(":robbie!~robbie@127.0.0.1 TOPIC #hifi :About HiFi".to_string(),
                    line_stream.next().await.unwrap().unwrap());
            assert_eq!(":robbie!~robbie@127.0.0.1 TOPIC #techno :About Techno Music"
                    .to_string(), line_stream.next().await.unwrap().unwrap());
            assert_eq!(":robbie!~robbie@127.0.0.1 TOPIC #trance :About Trance Music"
                    .to_string(), line_stream.next().await.unwrap().unwrap());
            
            {
                let mut state = main_state.state.write().await;
                state.channels.get_mut("#trance").unwrap().modes.protected_topic = true;
                state.channels.get_mut("#techno").unwrap().modes.protected_topic = true;
            }
            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                let topic = state.channels.get("#hifi").unwrap().topic.clone().unwrap();
                assert_eq!(("About HiFi".to_string(), "robbie".to_string()),
                        (topic.topic, topic.nick));
                let topic = state.channels.get("#techno").unwrap().topic.clone().unwrap();
                assert_eq!(("About Techno Music".to_string(), "robbie".to_string()),
                        (topic.topic, topic.nick));
                let topic = state.channels.get("#trance").unwrap().topic.clone().unwrap();
                assert_eq!(("About Trance Music".to_string(), "robbie".to_string()),
                        (topic.topic, topic.nick));
            }
        }
        
        quit_test_server(main_state, handle).await;
    }
}
