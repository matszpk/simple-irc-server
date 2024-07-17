// channel_cmds.rs - channel commands
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

use super::*;
use std::collections::HashMap;
use std::error::Error;
use std::ops::DerefMut;
use std::time::{SystemTime, UNIX_EPOCH};

impl super::MainState {
    pub(super) async fn process_join<'a>(
        &self,
        conn_state: &mut ConnState,
        channels: Vec<&'a str>,
        keys_opt: Option<Vec<&'a str>>,
    ) -> Result<(), Box<dyn Error>> {
        let mut statem = self.state.write().await;
        let state = statem.deref_mut();
        let user_nick = conn_state.user_state.nick.as_ref().unwrap().clone();
        let user_joined = state.users.get(&user_nick).unwrap().channels.len();
        let mut join_count = user_joined;

        let mut joined_created = vec![];

        {
            let client = conn_state.user_state.client_name();
            let user = state.users.get_mut(user_nick.as_str()).unwrap();
            for (i, chname_str) in channels.iter().enumerate() {
                let chname = chname_str.to_string();
                let (join, create) = if let Some(channel) = state.channels.get(&chname) {
                    // if already created
                    let do_join = if let Some(key) = &channel.modes.key {
                        if let Some(ref keys) = keys_opt {
                            // check key
                            if key != keys[i] {
                                self.feed_msg(
                                    &mut conn_state.stream,
                                    ErrBadChannelKey475 {
                                        client,
                                        channel: chname_str,
                                    },
                                )
                                .await?;
                                false
                            } else {
                                true
                            }
                        } else {
                            // no key then bad key
                            self.feed_msg(
                                &mut conn_state.stream,
                                ErrBadChannelKey475 {
                                    client,
                                    channel: chname_str,
                                },
                            )
                            .await?;
                            false
                        }
                    } else {
                        true
                    };

                    // check whether user is banned
                    let do_join = do_join && {
                        if !channel.modes.banned(&conn_state.user_state.source) {
                            true
                        } else {
                            self.feed_msg(
                                &mut conn_state.stream,
                                ErrBannedFromChan474 {
                                    client,
                                    channel: chname_str,
                                },
                            )
                            .await?;
                            false
                        }
                    };

                    // check whether must have invitation
                    let do_join = do_join && {
                        if !channel.modes.invite_only
                            || user.invited_to.contains(&chname)
                            || channel.modes.invite_exception.as_ref().map_or(false, |e| {
                                e.iter()
                                    .any(|e| match_wildcard(e, &conn_state.user_state.source))
                            })
                        {
                            true
                        } else {
                            self.feed_msg(
                                &mut conn_state.stream,
                                ErrInviteOnlyChan473 {
                                    client,
                                    channel: chname_str,
                                },
                            )
                            .await?;
                            false
                        }
                    };

                    // check whether channel is not full
                    let do_join = do_join && {
                        let not_full = if let Some(client_limit) = channel.modes.client_limit {
                            channel.users.len() < client_limit
                        } else {
                            true
                        };
                        if not_full {
                            true
                        } else {
                            self.feed_msg(
                                &mut conn_state.stream,
                                ErrChannelIsFull471 {
                                    client,
                                    channel: chname_str,
                                },
                            )
                            .await?;
                            false
                        }
                    };
                    // check whether user is not alrady joined
                    let do_join = do_join && !channel.users.contains_key(&user_nick);

                    if do_join {
                        (true, false)
                    } else {
                        (false, false)
                    }
                } else {
                    // if new channel
                    (true, true)
                };

                // check whether user is not in max channels
                let do_join = if let Some(max_joins) = self.config.max_joins {
                    if join_count >= max_joins {
                        self.feed_msg(
                            &mut conn_state.stream,
                            ErrTooManyChannels405 {
                                client,
                                channel: chname_str,
                            },
                        )
                        .await?;
                    }
                    join && join_count < max_joins
                } else {
                    join
                };

                joined_created.push((do_join, create));
                if do_join {
                    join_count += 1;
                }
            }

            // insert create channel or add user to channel
            for ((join, create), chname_str) in joined_created.iter().zip(channels.iter()) {
                let chname = chname_str.to_string();

                if *join {
                    user.channels.insert(chname.clone());
                    user.invited_to.remove(&chname);
                    if *create {
                        info!(
                            "User {} create channel {}",
                            conn_state.user_state.source, chname_str
                        );
                        state
                            .channels
                            .insert(chname, Channel::new_on_user_join(user_nick.clone()));
                    } else {
                        state
                            .channels
                            .get_mut(&chname)
                            .unwrap()
                            .add_user(&user_nick);
                    }
                }
            }
            // if something done - then change last activity
            if join_count != user_joined {
                user.last_activity = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
            }
        }

        // sending messages
        {
            for ((join, _), chname_str) in joined_created.iter().zip(channels.iter()) {
                if *join {
                    let chanobj = state.channels.get(&chname_str.to_string()).unwrap();
                    let join_msg = "JOIN ".to_string() + chname_str;
                    {
                        let client = conn_state.user_state.client_name();
                        self.feed_msg_source(
                            &mut conn_state.stream,
                            &conn_state.user_state.source,
                            join_msg.as_str(),
                        )
                        .await?;
                        if let Some(ref topic) = chanobj.topic {
                            self.feed_msg(
                                &mut conn_state.stream,
                                RplTopic332 {
                                    client,
                                    channel: chname_str,
                                    topic: &topic.topic,
                                },
                            )
                            .await?;
                        }
                    }
                    self.send_names_from_channel(
                        conn_state,
                        chname_str,
                        chanobj,
                        &state.users,
                        true,
                    )
                    .await?;

                    // send message to other users in channel
                    for nick in chanobj.users.keys() {
                        if nick != user_nick.as_str() {
                            state.users.get(&nick.clone()).unwrap().send_msg_display(
                                &conn_state.user_state.source,
                                join_msg.as_str(),
                            )?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub(super) async fn process_part<'a>(
        &self,
        conn_state: &mut ConnState,
        channels: Vec<&'a str>,
        reason: Option<&'a str>,
    ) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        let mut statem = self.state.write().await;
        let state = statem.deref_mut();
        let user_nick = conn_state.user_state.nick.as_ref().unwrap().clone();

        let mut removed_from = vec![];
        let mut something_done = false;

        for channel in &channels {
            if let Some(chanobj) = state.channels.get_mut(channel.to_owned()) {
                // if user in channel
                let do_it = if chanobj.users.contains_key(&user_nick) {
                    something_done = true;
                    true
                } else {
                    self.feed_msg(
                        &mut conn_state.stream,
                        ErrNotOnChannel442 { client, channel },
                    )
                    .await?;
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
                    for nick in chanobj.users.keys() {
                        state
                            .users
                            .get(&nick.clone())
                            .unwrap()
                            .send_msg_display(&conn_state.user_state.source, part_msg.as_str())?;
                    }
                }

                // remove user from channel
                if do_it {
                    state.remove_user_from_channel(channel, &user_nick);
                    removed_from.push(true);
                }
            } else {
                self.feed_msg(
                    &mut conn_state.stream,
                    ErrNoSuchChannel403 { client, channel },
                )
                .await?;
                removed_from.push(false);
            }
        }

        let user_nick = conn_state.user_state.nick.as_ref().unwrap().clone();
        let user = state.users.get_mut(user_nick.as_str()).unwrap();

        // if something done then change last activity time
        if something_done {
            user.last_activity = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
        }
        Ok(())
    }

    pub(super) async fn process_topic<'a>(
        &self,
        conn_state: &mut ConnState,
        channel: &'a str,
        topic_opt: Option<&'a str>,
        msg: &'a Message<'a>,
    ) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();

        if let Some(topic) = topic_opt {
            // if change topic
            let mut state = self.state.write().await;
            let user_nick = conn_state.user_state.nick.as_ref().unwrap();

            // if channel exists
            let do_change_topic = if let Some(chanobj) = state.channels.get(channel) {
                // if user on channel
                if chanobj.users.contains_key(user_nick) {
                    // if channel topic is not protected otherwise use should be at least
                    // a half-operator.
                    if !chanobj.modes.protected_topic
                        || chanobj.users.get(user_nick).unwrap().is_half_operator()
                    {
                        true
                    } else {
                        self.feed_msg(
                            &mut conn_state.stream,
                            ErrChanOpPrivsNeeded482 { client, channel },
                        )
                        .await?;
                        false
                    }
                } else {
                    self.feed_msg(
                        &mut conn_state.stream,
                        ErrNotOnChannel442 { client, channel },
                    )
                    .await?;
                    false
                }
            } else {
                self.feed_msg(
                    &mut conn_state.stream,
                    ErrNoSuchChannel403 { client, channel },
                )
                .await?;
                false
            };

            if do_change_topic {
                // change topic
                let chanobj = state.channels.get_mut(channel).unwrap();
                if !topic.is_empty() {
                    chanobj.topic = Some(ChannelTopic::new_with_nick(
                        topic.to_string(),
                        user_nick.clone(),
                    ));
                } else {
                    chanobj.topic = None
                }
            }
            if do_change_topic {
                // send message about to all users in channel.
                let chanobj = state.channels.get(channel).unwrap();
                for cu in chanobj.users.keys() {
                    state
                        .users
                        .get(cu)
                        .unwrap()
                        .send_message(msg, &conn_state.user_state.source)?;
                }
            }
        } else {
            // read topic
            let state = self.state.read().await;
            if let Some(chanobj) = state.channels.get(channel) {
                let user_nick = conn_state.user_state.nick.as_ref().unwrap();

                if chanobj.users.contains_key(user_nick) {
                    // if user on channel
                    if let Some(ref topic) = chanobj.topic {
                        self.feed_msg(
                            &mut conn_state.stream,
                            RplTopic332 {
                                client,
                                channel,
                                topic: &topic.topic,
                            },
                        )
                        .await?;
                        self.feed_msg(
                            &mut conn_state.stream,
                            RplTopicWhoTime333 {
                                client,
                                channel,
                                nick: &topic.nick,
                                setat: topic.set_time,
                            },
                        )
                        .await?;
                    } else {
                        self.feed_msg(&mut conn_state.stream, RplNoTopic331 { client, channel })
                            .await?;
                    }
                } else {
                    self.feed_msg(
                        &mut conn_state.stream,
                        ErrNotOnChannel442 { client, channel },
                    )
                    .await?;
                }
            } else {
                self.feed_msg(
                    &mut conn_state.stream,
                    ErrNoSuchChannel403 { client, channel },
                )
                .await?;
            }
        }
        Ok(())
    }

    // routine used for sending names of channel. end argument - if true then send EndOfNames.
    async fn send_names_from_channel<'a>(
        &self,
        conn_state: &mut ConnState,
        channel_name: &'a str,
        channel: &'a Channel,
        users: &HashMap<String, User>,
        end: bool,
    ) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        let conn_user_nick = conn_state.user_state.nick.as_ref().unwrap();

        let in_channel = channel.users.contains_key(conn_user_nick);
        // if channel is not secret or user on channel.
        if !channel.modes.secret || in_channel {
            const NAMES_COUNT: usize = 20;
            let symbol = if channel.modes.secret { "@" } else { "=" };

            let mut name_chunk = vec![];
            name_chunk.reserve(NAMES_COUNT);

            for (unick, chum) in &channel.users {
                let user = users.get(unick.as_str()).unwrap();
                // do not send names of invisible users or user on channel
                if !user.modes.invisible || in_channel {
                    name_chunk.push(NameReplyStruct {
                        prefix: chum.to_string(&conn_state.caps),
                        nick: unick,
                    });
                }
                if name_chunk.len() == NAMES_COUNT {
                    self.feed_msg(
                        &mut conn_state.stream,
                        RplNameReply353 {
                            client,
                            symbol,
                            channel: channel_name,
                            replies: &name_chunk,
                        },
                    )
                    .await?;
                    name_chunk.clear();
                }
            }
            if !name_chunk.is_empty() {
                // last chunk
                self.feed_msg(
                    &mut conn_state.stream,
                    RplNameReply353 {
                        client,
                        symbol,
                        channel: channel_name,
                        replies: &name_chunk,
                    },
                )
                .await?;
            }
            if end {
                self.feed_msg(
                    &mut conn_state.stream,
                    RplEndOfNames366 {
                        client,
                        channel: channel_name,
                    },
                )
                .await?;
            }
        }
        Ok(())
    }

    pub(super) async fn process_names<'a>(
        &self,
        conn_state: &mut ConnState,
        channels: Vec<&'a str>,
    ) -> Result<(), Box<dyn Error>> {
        let state = self.state.read().await;

        if !channels.is_empty() {
            // send names with EndOfNames
            for c in channels {
                if let Some(channel) = state.channels.get(c) {
                    self.send_names_from_channel(conn_state, c, channel, &state.users, true)
                        .await?;
                } else {
                    let client = conn_state.user_state.client_name();
                    self.feed_msg(
                        &mut conn_state.stream,
                        RplEndOfNames366 { client, channel: c },
                    )
                    .await?;
                }
            }
        } else {
            // send names.
            for (cn, c) in state.channels.iter() {
                self.send_names_from_channel(conn_state, cn, c, &state.users, false)
                    .await?;
            }
            let client = conn_state.user_state.client_name();
            // send single EndOfNames with wildcard.
            self.feed_msg(
                &mut conn_state.stream,
                RplEndOfNames366 {
                    client,
                    channel: "*",
                },
            )
            .await?;
        }
        Ok(())
    }

    pub(super) async fn process_list<'a>(
        &self,
        conn_state: &mut ConnState,
        channels: Vec<&'a str>,
        server: Option<&'a str>,
    ) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();

        if server.is_some() {
            self.feed_msg(
                &mut conn_state.stream,
                ErrUnknownError400 {
                    client,
                    command: "LIST",
                    subcommand: None,
                    info: "Server unsupported",
                },
            )
            .await?;
        } else {
            let state = self.state.read().await;
            self.feed_msg(&mut conn_state.stream, RplListStart321 { client })
                .await?;
            if !channels.is_empty() {
                // send channels that are public (not secret).
                for (chname, ch) in channels.iter().filter_map(|chname| {
                    state
                        .channels
                        .get(&chname.to_string())
                        .filter(|ch| !ch.modes.secret)
                        .map(|ch| (chname, ch))
                }) {
                    self.feed_msg(
                        &mut conn_state.stream,
                        RplList322 {
                            client,
                            channel: chname,
                            client_count: ch.users.len(),
                            topic: ch
                                .topic
                                .as_ref()
                                .map(|x| &x.topic)
                                .unwrap_or(&String::new()),
                        },
                    )
                    .await?;
                }
            } else {
                // send channels that are public (not secret).
                for (chname, ch) in state.channels.iter().filter(|(_, ch)| !ch.modes.secret) {
                    self.feed_msg(
                        &mut conn_state.stream,
                        RplList322 {
                            client,
                            channel: chname,
                            client_count: ch.users.len(),
                            topic: ch
                                .topic
                                .as_ref()
                                .map(|x| &x.topic)
                                .unwrap_or(&String::new()),
                        },
                    )
                    .await?;
                }
            }
            self.feed_msg(&mut conn_state.stream, RplListEnd323 { client })
                .await?;
        }
        Ok(())
    }

    pub(super) async fn process_invite<'a>(
        &self,
        conn_state: &mut ConnState,
        nickname: &'a str,
        channel: &'a str,
        msg: &'a Message<'a>,
    ) -> Result<(), Box<dyn Error>> {
        let mut state = self.state.write().await;
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        let client = conn_state.user_state.client_name();

        let do_invite = if let Some(chanobj) = state.channels.get(channel) {
            if chanobj.users.contains_key(user_nick) {
                let do_invite2 = if chanobj.modes.invite_only {
                    // only operator can invite into channel if channel is invite_only.
                    if !chanobj.users.get(user_nick).unwrap().operator {
                        self.feed_msg(
                            &mut conn_state.stream,
                            ErrChanOpPrivsNeeded482 { client, channel },
                        )
                        .await?;
                        false
                    } else {
                        true
                    }
                } else {
                    true
                };
                if do_invite2 {
                    if chanobj.users.contains_key(nickname) {
                        self.feed_msg(
                            &mut conn_state.stream,
                            ErrUserOnChannel443 {
                                client,
                                nick: nickname,
                                channel,
                            },
                        )
                        .await?;
                        false
                    } else {
                        true
                    }
                } else {
                    false
                }
            } else {
                self.feed_msg(
                    &mut conn_state.stream,
                    ErrNotOnChannel442 { client, channel },
                )
                .await?;
                false
            }
        } else {
            self.feed_msg(
                &mut conn_state.stream,
                ErrNoSuchChannel403 { client, channel },
            )
            .await?;
            false
        };

        if do_invite {
            // check user
            if let Some(invited) = state.users.get_mut(nickname) {
                invited.invited_to.insert(channel.to_string());
                self.feed_msg(
                    &mut conn_state.stream,
                    RplInviting341 {
                        client,
                        nick: nickname,
                        channel,
                    },
                )
                .await?;
                invited.send_message(msg, &conn_state.user_state.source)?;
            } else {
                self.feed_msg(
                    &mut conn_state.stream,
                    ErrNoSuchNick401 {
                        client,
                        nick: nickname,
                    },
                )
                .await?;
            }
        }
        Ok(())
    }

    pub(super) async fn process_kick<'a>(
        &self,
        conn_state: &mut ConnState,
        channel: &'a str,
        kick_users: Vec<&'a str>,
        comment: Option<&'a str>,
    ) -> Result<(), Box<dyn Error>> {
        let mut statem = self.state.write().await;
        let state = statem.deref_mut();
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        let client = conn_state.user_state.client_name();

        let mut kicked = vec![];

        if let Some(chanobj) = state.channels.get(channel) {
            // if user on channel
            if chanobj.users.contains_key(user_nick) {
                let user_chum = chanobj.users.get(user_nick).unwrap();
                // if user is half operator at least.
                if user_chum.is_half_operator() {
                    let is_only_half_oper = user_chum.is_only_half_operator();
                    for kick_user in &kick_users {
                        let ku = kick_user.to_string();
                        if let Some(chum) = chanobj.users.get(&ku) {
                            if !chum.is_protected()
                                && (!chum.is_half_operator() || !is_only_half_oper)
                            {
                                kicked.push(kick_user);
                            } else {
                                self.feed_msg(
                                    &mut conn_state.stream,
                                    ErrCannotDoCommand972 { client },
                                )
                                .await?;
                            }
                        } else {
                            self.feed_msg(
                                &mut conn_state.stream,
                                ErrUserNotInChannel441 {
                                    client,
                                    nick: kick_user,
                                    channel,
                                },
                            )
                            .await?;
                        }
                    }
                } else {
                    self.feed_msg(
                        &mut conn_state.stream,
                        ErrChanOpPrivsNeeded482 { client, channel },
                    )
                    .await?;
                }
            } else {
                self.feed_msg(
                    &mut conn_state.stream,
                    ErrNotOnChannel442 { client, channel },
                )
                .await?;
            }
        } else {
            self.feed_msg(
                &mut conn_state.stream,
                ErrNoSuchChannel403 { client, channel },
            )
            .await?;
        }

        {
            // kick users
            for ku in &kicked {
                state.remove_user_from_channel(channel, ku);
            }
            let chanobj = state.channels.get(channel).unwrap();
            for ku in &kicked {
                let kick_msg = format!("KICK {} {} :{}", channel, ku, comment.unwrap_or("Kicked"));
                for nick in chanobj.users.keys() {
                    state
                        .users
                        .get(nick)
                        .unwrap()
                        .send_msg_display(&conn_state.user_state.source, kick_msg.clone())?;
                }
                // and send to kicked user
                state
                    .users
                    .get(&ku.to_string())
                    .unwrap()
                    .send_msg_display(&conn_state.user_state.source, kick_msg.clone())?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::super::test::*;
    use super::*;
    use tokio::net::TcpStream;

    fn equal_channel_names<'a>(
        exp_msg: &'a str,
        exp_names: &'a [&'a str],
        names_replies: &'a [&'a str],
    ) -> bool {
        let mut exp_names_sorted = Vec::from(exp_names);
        exp_names_sorted.sort();
        let mut touched = vec![false; exp_names.len()];
        names_replies.iter().all(|reply| {
            if reply.starts_with(exp_msg) {
                reply[exp_msg.len()..].split_terminator(" ").all(|c| {
                    if let Ok(p) = exp_names_sorted.binary_search(&c) {
                        touched[p] = true;
                        true
                    } else {
                        false
                    }
                })
            } else {
                false
            }
        }) && touched.iter().all(|x| *x)
    }

    #[tokio::test]
    async fn test_command_join() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "charlie", "charlie2", "Charlie Brown").await;

            line_stream.send("JOIN #fruits".to_string()).await.unwrap();
            assert_eq!(
                ":charlie!~charlie2@127.0.0.1 JOIN #fruits".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 353 charlie = #fruits :~charlie".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 366 charlie #fruits :End of /NAMES list".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            let mut line_stream2 =
                login_to_test_and_skip(port, "eddix", "eddie", "Eddie Flower").await;
            line_stream2.send("JOIN #fruits".to_string()).await.unwrap();
            assert_eq!(
                ":eddix!~eddie@127.0.0.1 JOIN #fruits".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
            assert!(equal_channel_names(
                ":irc.irc 353 eddix = #fruits :",
                &["eddix", "~charlie"],
                &[&line_stream2.next().await.unwrap().unwrap()]
            ));
            assert_eq!(
                ":irc.irc 366 eddix #fruits :End of /NAMES list".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );

            assert_eq!(
                ":eddix!~eddie@127.0.0.1 JOIN #fruits".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            let mut line_stream3 =
                login_to_test_and_skip(port, "logan", "logan", "Logan Powers").await;
            line_stream3.send("JOIN #fruits".to_string()).await.unwrap();
            assert_eq!(
                ":logan!~logan@127.0.0.1 JOIN #fruits".to_string(),
                line_stream3.next().await.unwrap().unwrap()
            );
            assert!(equal_channel_names(
                ":irc.irc 353 logan = #fruits :",
                &["eddix", "~charlie", "logan"],
                &[&line_stream3.next().await.unwrap().unwrap()]
            ));
            assert_eq!(
                ":irc.irc 366 logan #fruits :End of /NAMES list".to_string(),
                line_stream3.next().await.unwrap().unwrap()
            );

            let mut exp_channel = Channel {
                topic: None,
                creation_time: 0,
                preconfigured: false,
                modes: ChannelModes::new_for_channel("charlie".to_string()),
                default_modes: ChannelDefaultModes::default(),
                ban_info: HashMap::new(),
                users: [
                    (
                        "charlie".to_string(),
                        ChannelUserModes {
                            founder: true,
                            protected: false,
                            voice: false,
                            operator: true,
                            half_oper: false,
                        },
                    ),
                    (
                        "eddix".to_string(),
                        ChannelUserModes {
                            founder: false,
                            protected: false,
                            voice: false,
                            operator: false,
                            half_oper: false,
                        },
                    ),
                    (
                        "logan".to_string(),
                        ChannelUserModes {
                            founder: false,
                            protected: false,
                            voice: false,
                            operator: false,
                            half_oper: false,
                        },
                    ),
                ]
                .into(),
            };
            {
                let state = main_state.state.read().await;
                let channel = state.channels.get("#fruits").unwrap();
                exp_channel.creation_time = channel.creation_time;
                assert_eq!(exp_channel, *channel);

                assert_eq!(
                    HashSet::from(["#fruits".to_string()]),
                    state.users.get("charlie").unwrap().channels
                );
                assert_eq!(
                    HashSet::from(["#fruits".to_string()]),
                    state.users.get("eddix").unwrap().channels
                );
                assert_eq!(
                    HashSet::from(["#fruits".to_string()]),
                    state.users.get("logan").unwrap().channels
                );
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
                assert!(!state.channels.contains_key("#fruits"));
            }
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_join_already_joined() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "charlie", "charlie2", "Charlie Brown").await;

            line_stream.send("JOIN #fruits".to_string()).await.unwrap();
            for _ in 0..3 {
                line_stream.next().await.unwrap().unwrap();
            }

            time::sleep(Duration::from_millis(100)).await;

            {
                // set some channel user mode
                main_state
                    .state
                    .write()
                    .await
                    .channels
                    .get_mut("#fruits")
                    .unwrap()
                    .add_voice("charlie");
            }

            line_stream.send("JOIN #fruits".to_string()).await.unwrap();
            time::sleep(Duration::from_millis(100)).await;
            {
                // check user mode (voice)
                assert!(
                    main_state
                        .state
                        .read()
                        .await
                        .channels
                        .get("#fruits")
                        .unwrap()
                        .users
                        .get("charlie")
                        .unwrap()
                        .voice
                );
            }
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_join_with_topic() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "charlie", "charlie2", "Charlie Brown").await;

            line_stream.send("JOIN #fruits".to_string()).await.unwrap();
            for _ in 0..3 {
                line_stream.next().await.unwrap().unwrap();
            }

            time::sleep(Duration::from_millis(50)).await;
            {
                let mut state = main_state.state.write().await;
                state.channels.get_mut("#fruits").unwrap().topic = Some(
                    ChannelTopic::new_with_nick("This topic".to_string(), "charlie".to_string()),
                );
            }

            let mut line_stream2 =
                login_to_test_and_skip(port, "eddix", "eddie", "Eddie Flower").await;
            line_stream2.send("JOIN #fruits".to_string()).await.unwrap();
            assert_eq!(
                ":eddix!~eddie@127.0.0.1 JOIN #fruits".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 332 eddix #fruits :This topic".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
            assert!(equal_channel_names(
                ":irc.irc 353 eddix = #fruits :",
                &["eddix", "~charlie"],
                &[&line_stream2.next().await.unwrap().unwrap()]
            ));
            assert_eq!(
                ":irc.irc 366 eddix #fruits :End of /NAMES list".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_join_limit_check() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        const CLIENT_LIMIT: usize = 10;
        // limit check
        {
            let mut line_stream =
                login_to_test_and_skip(port, "charlie", "charlie2", "Charlie Brown").await;

            line_stream.send("JOIN #oranges".to_string()).await.unwrap();
            time::sleep(Duration::from_millis(70)).await;
            {
                let mut state = main_state.state.write().await;
                state
                    .channels
                    .get_mut("#oranges")
                    .unwrap()
                    .modes
                    .client_limit = Some(CLIENT_LIMIT);
            }

            let mut line_streams = vec![];
            for i in 0..CLIENT_LIMIT {
                line_streams.push(
                    login_to_test_and_skip(
                        port,
                        &format!("FInni{}", i),
                        &format!("FInnix{}", i),
                        &format!("FInni Somewhere {}", i),
                    )
                    .await,
                );
                if i == CLIENT_LIMIT - 2 {
                    time::sleep(Duration::from_millis(70)).await;
                }
            }
            for (i, line_streamx) in line_streams.iter_mut().enumerate() {
                line_streamx
                    .send("JOIN #oranges".to_string())
                    .await
                    .unwrap();
                if i != CLIENT_LIMIT - 1 {
                    assert_eq!(
                        format!(":FInni{}!~FInnix{}@127.0.0.1 JOIN #oranges", i, i),
                        line_streamx.next().await.unwrap().unwrap()
                    );
                } else {
                    assert_eq!(
                        ":irc.irc 471 FInni9 #oranges :Cannot join channel (+l)".to_string(),
                        line_streamx.next().await.unwrap().unwrap()
                    );
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
            let mut line_stream =
                login_to_test_and_skip(port, "expert", "expertx", "SuperExpert").await;
            line_stream.send("JOIN #secrets".to_string()).await.unwrap();

            time::sleep(Duration::from_millis(70)).await;
            {
                let mut state = main_state.state.write().await;
                let mut chmodes = &mut state.channels.get_mut("#secrets").unwrap().modes;
                chmodes.ban = Some(
                    [
                        "roland!*@*".to_string(),
                        "gugu!*@*".to_string(),
                        "devil!*@*".to_string(),
                    ]
                    .into(),
                );
                chmodes.exception = Some(["devil!*@*".to_string()].into());
            }

            let mut roland_stream =
                login_to_test_and_skip(port, "roland", "Roland", "Roland XX").await;
            let mut gugu_stream = login_to_test_and_skip(port, "gugu", "gugu", "GuuGuu").await;
            let mut devil_stream =
                login_to_test_and_skip(port, "devil", "scary_devil", "Very Scary Devil").await;
            let mut angel_stream =
                login_to_test_and_skip(port, "angel", "good_angel", "Very Good Angel").await;

            roland_stream
                .send("JOIN #secrets".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 474 roland #secrets :Cannot join channel (+b)".to_string(),
                roland_stream.next().await.unwrap().unwrap()
            );
            gugu_stream.send("JOIN #secrets".to_string()).await.unwrap();
            assert_eq!(
                ":irc.irc 474 gugu #secrets :Cannot join channel (+b)".to_string(),
                gugu_stream.next().await.unwrap().unwrap()
            );
            devil_stream
                .send("JOIN #secrets".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":devil!~scary_devil@127.0.0.1 JOIN #secrets".to_string(),
                devil_stream.next().await.unwrap().unwrap()
            );
            angel_stream
                .send("JOIN #secrets".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":angel!~good_angel@127.0.0.1 JOIN #secrets".to_string(),
                angel_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_join_invite() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;
        // invite
        {
            let mut line_stream =
                login_to_test_and_skip(port, "damian", "damian", "Damian Kozlowski").await;
            line_stream
                .send("JOIN #exclusive".to_string())
                .await
                .unwrap();

            time::sleep(Duration::from_millis(70)).await;
            {
                let mut state = main_state.state.write().await;
                let mut chmodes = &mut state.channels.get_mut("#exclusive").unwrap().modes;
                chmodes.invite_only = true;
                chmodes.invite_exception = Some(["ex*!*@*".to_string()].into());
            }

            let mut henry_stream =
                login_to_test_and_skip(port, "henry", "henryk", "Henri Stones").await;
            let mut excel_stream =
                login_to_test_and_skip(port, "excel", "excel", "Excel Total").await;

            henry_stream
                .send("JOIN #exclusive".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 473 henry #exclusive :Cannot join channel (+i)".to_string(),
                henry_stream.next().await.unwrap().unwrap()
            );
            excel_stream
                .send("JOIN #exclusive".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":excel!~excel@127.0.0.1 JOIN #exclusive".to_string(),
                excel_stream.next().await.unwrap().unwrap()
            );

            {
                let mut state = main_state.state.write().await;
                state.users.get_mut("henry").unwrap().invited_to =
                    ["#exclusive".to_string()].into();
            }
            henry_stream
                .send("JOIN #exclusive".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":henry!~henryk@127.0.0.1 JOIN #exclusive".to_string(),
                henry_stream.next().await.unwrap().unwrap()
            );
        }
        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_join_key_check() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;
        // key check
        {
            let mut line_stream =
                login_to_test_and_skip(port, "garry", "garry", "Garry NextSomebody").await;
            line_stream
                .send("JOIN #protected".to_string())
                .await
                .unwrap();

            time::sleep(Duration::from_millis(70)).await;
            {
                let mut state = main_state.state.write().await;
                state.channels.get_mut("#protected").unwrap().modes.key =
                    Some("longpassword!!".to_string());
            }

            let mut jobe_stream = login_to_test_and_skip(port, "jobe", "jobe", "Jobe Smith").await;
            jobe_stream
                .send("JOIN #protected".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 475 jobe #protected :Cannot join channel (+k)".to_string(),
                jobe_stream.next().await.unwrap().unwrap()
            );

            jobe_stream
                .send("JOIN #protected longpass".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 475 jobe #protected :Cannot join channel (+k)".to_string(),
                jobe_stream.next().await.unwrap().unwrap()
            );

            jobe_stream
                .send("JOIN #protected longpassword!!".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":jobe!~jobe@127.0.0.1 JOIN #protected".to_string(),
                jobe_stream.next().await.unwrap().unwrap()
            );
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
            let mut line_stream =
                login_to_test_and_skip(port, "garry", "garry", "Garry NextSomebody").await;
            for i in 0..(MAX_JOINS + 1) {
                line_stream.send(format!("JOIN #chan{}", i)).await.unwrap();
            }

            time::sleep(Duration::from_millis(50)).await;

            let mut jobe_stream = login_to_test_and_skip(port, "jobe", "jobe", "Jobe Smith").await;
            for i in 0..(MAX_JOINS + 1) {
                jobe_stream.send(format!("JOIN #chan{}", i)).await.unwrap();
                if i < MAX_JOINS {
                    assert_eq!(
                        format!(":jobe!~jobe@127.0.0.1 JOIN #chan{}", i),
                        jobe_stream.next().await.unwrap().unwrap()
                    );
                    jobe_stream.next().await.unwrap().unwrap();
                    jobe_stream.next().await.unwrap().unwrap();
                } else {
                    assert_eq!(
                        ":irc.irc 405 jobe #chan10 :You have joined too many channels".to_string(),
                        jobe_stream.next().await.unwrap().unwrap()
                    );
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
            let mut line_stream =
                login_to_test_and_skip(port, "garry", "garry", "Garry NextSomebody").await;
            for i in 0..(MAX_JOINS + 1) {
                line_stream.send(format!("JOIN #chan{}", i)).await.unwrap();
            }

            time::sleep(Duration::from_millis(50)).await;

            let mut jobe_stream = login_to_test_and_skip(port, "jobe", "jobe", "Jobe Smith").await;
            for i in 0..(MAX_JOINS + 1) {
                jobe_stream.send(format!("JOIN #chan{}", i)).await.unwrap();
                assert_eq!(
                    format!(":jobe!~jobe@127.0.0.1 JOIN #chan{}", i),
                    jobe_stream.next().await.unwrap().unwrap()
                );
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
            let mut line_stream =
                login_to_test_and_skip(port, "derek", "derek-z", "Derek Zinni").await;

            line_stream
                .send("JOIN #finances".to_string())
                .await
                .unwrap();
            line_stream.send("JOIN #stocks".to_string()).await.unwrap();
            line_stream
                .send("JOIN #hardware".to_string())
                .await
                .unwrap();
            line_stream
                .send("JOIN #software".to_string())
                .await
                .unwrap();
            line_stream
                .send("JOIN #furnitures".to_string())
                .await
                .unwrap();
            line_stream.send("JOIN #tools".to_string()).await.unwrap();
            line_stream.send("JOIN #cloaths".to_string()).await.unwrap();

            time::sleep(Duration::from_millis(50)).await;
            {
                let mut state = main_state.state.write().await;
                state
                    .channels
                    .get_mut("#finances")
                    .unwrap()
                    .modes
                    .client_limit = Some(2);
                state
                    .channels
                    .get_mut("#stocks")
                    .unwrap()
                    .modes
                    .client_limit = Some(3);
                state.channels.get_mut("#hardware").unwrap().modes.ban =
                    Some(["*g*!*@*".to_string()].into());
                state
                    .channels
                    .get_mut("#software")
                    .unwrap()
                    .modes
                    .invite_only = true;
                let mut modes = &mut state.channels.get_mut("#furnitures").unwrap().modes;
                modes.invite_only = true;
                modes.invite_exception = Some(["*g*!*@*".to_string()].into());
            }

            let mut robby_stream =
                login_to_test_and_skip(port, "robby", "robbie", "Robbie Runnie").await;
            robby_stream
                .send("JOIN #finances".to_string())
                .await
                .unwrap();
            robby_stream.send("JOIN #stocks".to_string()).await.unwrap();

            let mut zephyr_stream =
                login_to_test_and_skip(port, "zephyr", "zephyr", "Zephyr Somewhere").await;
            zephyr_stream
                .send("JOIN #stocks".to_string())
                .await
                .unwrap();

            let mut greg_stream =
                login_to_test_and_skip(port, "greg", "gregory", "Gregory Powerful").await;
            greg_stream
                .send(
                    "JOIN #finances,#stocks,#hardware,#software,#furnitures,#tools,#cloaths"
                        .to_string(),
                )
                .await
                .unwrap();

            assert_eq!(
                ":irc.irc 471 greg #finances :Cannot join channel (+l)".to_string(),
                greg_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 471 greg #stocks :Cannot join channel (+l)".to_string(),
                greg_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 474 greg #hardware :Cannot join channel (+b)".to_string(),
                greg_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 473 greg #software :Cannot join channel (+i)".to_string(),
                greg_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":greg!~gregory@127.0.0.1 JOIN #furnitures".to_string(),
                greg_stream.next().await.unwrap().unwrap()
            );
            assert!(equal_channel_names(
                ":irc.irc 353 greg = #furnitures :",
                &["~derek", "greg"],
                &[&greg_stream.next().await.unwrap().unwrap()]
            ));
            assert_eq!(
                ":irc.irc 366 greg #furnitures :End of /NAMES list".to_string(),
                greg_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":greg!~gregory@127.0.0.1 JOIN #tools".to_string(),
                greg_stream.next().await.unwrap().unwrap()
            );
            assert!(equal_channel_names(
                ":irc.irc 353 greg = #tools :",
                &["~derek", "greg"],
                &[&greg_stream.next().await.unwrap().unwrap()]
            ));
            assert_eq!(
                ":irc.irc 366 greg #tools :End of /NAMES list".to_string(),
                greg_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":greg!~gregory@127.0.0.1 JOIN #cloaths".to_string(),
                greg_stream.next().await.unwrap().unwrap()
            );
            assert!(equal_channel_names(
                ":irc.irc 353 greg = #cloaths :",
                &["~derek", "greg"],
                &[&greg_stream.next().await.unwrap().unwrap()]
            ));
            assert_eq!(
                ":irc.irc 366 greg #cloaths :End of /NAMES list".to_string(),
                greg_stream.next().await.unwrap().unwrap()
            );

            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.write().await;
                assert!(!state
                    .channels
                    .get("#finances")
                    .unwrap()
                    .users
                    .contains_key("greg"));
                assert!(!state
                    .channels
                    .get("#stocks")
                    .unwrap()
                    .users
                    .contains_key("greg"));
                assert!(!state
                    .channels
                    .get("#hardware")
                    .unwrap()
                    .users
                    .contains_key("greg"));
                assert!(!state
                    .channels
                    .get("#software")
                    .unwrap()
                    .users
                    .contains_key("greg"));
                assert!(state
                    .channels
                    .get("#furnitures")
                    .unwrap()
                    .users
                    .contains_key("greg"));
                assert!(state
                    .channels
                    .get("#tools")
                    .unwrap()
                    .users
                    .contains_key("greg"));
                assert!(state
                    .channels
                    .get("#cloaths")
                    .unwrap()
                    .users
                    .contains_key("greg"));
                assert_eq!(
                    HashSet::from([
                        "#tools".to_string(),
                        "#furnitures".to_string(),
                        "#cloaths".to_string()
                    ]),
                    state.users.get("greg").unwrap().channels
                );
            }
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_join_multiple_with_key() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "derek", "derek-z", "Derek Zinni").await;

            line_stream.send("JOIN #crypto".to_string()).await.unwrap();
            line_stream.send("JOIN #servers".to_string()).await.unwrap();
            line_stream.send("JOIN #drinks".to_string()).await.unwrap();
            line_stream.send("JOIN #job".to_string()).await.unwrap();
            line_stream.send("JOIN #cars".to_string()).await.unwrap();

            time::sleep(Duration::from_millis(50)).await;
            {
                let mut state = main_state.state.write().await;
                state.channels.get_mut("#crypto").unwrap().modes.key = Some("altcoin".to_string());
                state.channels.get_mut("#servers").unwrap().modes.key =
                    Some("amd_epyc".to_string());
                state.channels.get_mut("#cars").unwrap().modes.key = Some("Buggatti".to_string());
            }

            let mut greg_stream =
                login_to_test_and_skip(port, "greg", "gregory", "Gregory Powerful").await;
            greg_stream
                .send(
                    "JOIN #crypto,#servers,#drinks,#job,#cars ZRX,amd_epyc,tequilla,,Lambo"
                        .to_string(),
                )
                .await
                .unwrap();

            assert_eq!(
                ":irc.irc 475 greg #crypto :Cannot join channel (+k)".to_string(),
                greg_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 475 greg #cars :Cannot join channel (+k)".to_string(),
                greg_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":greg!~gregory@127.0.0.1 JOIN #servers".to_string(),
                greg_stream.next().await.unwrap().unwrap()
            );
            assert!(equal_channel_names(
                ":irc.irc 353 greg = #servers :",
                &["~derek", "greg"],
                &[&greg_stream.next().await.unwrap().unwrap()]
            ));
            assert_eq!(
                ":irc.irc 366 greg #servers :End of /NAMES list".to_string(),
                greg_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":greg!~gregory@127.0.0.1 JOIN #drinks".to_string(),
                greg_stream.next().await.unwrap().unwrap()
            );
            assert!(equal_channel_names(
                ":irc.irc 353 greg = #drinks :",
                &["~derek", "greg"],
                &[&greg_stream.next().await.unwrap().unwrap()]
            ));
            assert_eq!(
                ":irc.irc 366 greg #drinks :End of /NAMES list".to_string(),
                greg_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":greg!~gregory@127.0.0.1 JOIN #job".to_string(),
                greg_stream.next().await.unwrap().unwrap()
            );
            assert!(equal_channel_names(
                ":irc.irc 353 greg = #job :",
                &["~derek", "greg"],
                &[&greg_stream.next().await.unwrap().unwrap()]
            ));
            assert_eq!(
                ":irc.irc 366 greg #job :End of /NAMES list".to_string(),
                greg_stream.next().await.unwrap().unwrap()
            );

            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.write().await;
                assert!(!state
                    .channels
                    .get("#crypto")
                    .unwrap()
                    .users
                    .contains_key("greg"));
                assert!(!state
                    .channels
                    .get("#cars")
                    .unwrap()
                    .users
                    .contains_key("greg"));
                assert!(state
                    .channels
                    .get("#servers")
                    .unwrap()
                    .users
                    .contains_key("greg"));
                assert!(state
                    .channels
                    .get("#drinks")
                    .unwrap()
                    .users
                    .contains_key("greg"));
                assert!(state
                    .channels
                    .get("#job")
                    .unwrap()
                    .users
                    .contains_key("greg"));
                assert_eq!(
                    HashSet::from([
                        "#servers".to_string(),
                        "#drinks".to_string(),
                        "#job".to_string()
                    ]),
                    state.users.get("greg").unwrap().channels
                );
            }
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_join_multiple_no_max_joins() {
        const MAX_JOINS: usize = 10;
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "garry", "garry", "Garry NextSomebody").await;
            for i in 0..(MAX_JOINS + 1) {
                line_stream.send(format!("JOIN #chan{}", i)).await.unwrap();
            }

            time::sleep(Duration::from_millis(50)).await;

            let mut jobe_stream = login_to_test_and_skip(port, "jobe", "jobe", "Jobe Smith").await;
            jobe_stream
                .send(format!(
                    "JOIN {}",
                    (0..(MAX_JOINS + 1))
                        .map(|x| format!("#chan{}", x))
                        .collect::<Vec<_>>()
                        .join(",")
                ))
                .await
                .unwrap();

            for i in 0..(MAX_JOINS + 1) {
                assert_eq!(
                    format!(":jobe!~jobe@127.0.0.1 JOIN #chan{}", i),
                    jobe_stream.next().await.unwrap().unwrap()
                );
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
            let mut line_stream =
                login_to_test_and_skip(port, "florian", "florian-f", "Florian Fabian").await;

            line_stream.send("JOIN #roses".to_string()).await.unwrap();
            line_stream
                .send("JOIN #tulipans".to_string())
                .await
                .unwrap();
            line_stream.send("JOIN #fruits".to_string()).await.unwrap();
            line_stream.send("JOIN #flowers".to_string()).await.unwrap();

            time::sleep(Duration::from_millis(50)).await;
            {
                let mut state = main_state.state.write().await;
                state.channels.get_mut("#roses").unwrap().modes.key = Some("whiterose".to_string());
                state.channels.get_mut("#fruits").unwrap().modes.key = Some("cocoa".to_string());
            }

            let mut line_stream = login_to_test_and_skip(port, "rosy", "rosy-f", "Rosy Red").await;

            time::sleep(Duration::from_millis(50)).await;
            let activity = {
                let mut state = main_state.state.write().await;
                state.users.get_mut("rosy").unwrap().last_activity -= 10;
                state.users.get("rosy").unwrap().last_activity
            };

            line_stream.send("JOIN #roses".to_string()).await.unwrap();
            time::sleep(Duration::from_millis(50)).await;
            assert_eq!(
                ":irc.irc 475 rosy #roses :Cannot join channel (+k)".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            {
                let state = main_state.state.read().await;
                assert_eq!(activity, state.users.get("rosy").unwrap().last_activity);
            }

            line_stream
                .send("JOIN #tulipans".to_string())
                .await
                .unwrap();
            time::sleep(Duration::from_millis(50)).await;
            assert_eq!(
                ":rosy!~rosy-f@127.0.0.1 JOIN #tulipans".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
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
            assert_eq!(
                ":irc.irc 475 rosy #fruits :Cannot join channel (+k)".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            {
                let state = main_state.state.read().await;
                assert_eq!(activity, state.users.get("rosy").unwrap().last_activity);
            }

            line_stream.send("JOIN #flowers".to_string()).await.unwrap();
            time::sleep(Duration::from_millis(50)).await;
            assert_eq!(
                ":rosy!~rosy-f@127.0.0.1 JOIN #flowers".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
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
            let mut line_stream =
                login_to_test_and_skip(port, "mobiler", "mobilerx", "Mobiler Smartphone").await;

            line_stream
                .send("JOIN #smartphones".to_string())
                .await
                .unwrap();
            line_stream
                .send("JOIN #smartwatches".to_string())
                .await
                .unwrap();
            line_stream.send("JOIN #ebooks".to_string()).await.unwrap();
            line_stream
                .send("JOIN #smartglasses".to_string())
                .await
                .unwrap();
            line_stream
                .send("JOIN #wearables".to_string())
                .await
                .unwrap();
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

            let mut line_stream =
                login_to_test_and_skip(port, "geek", "geeker", "Young Geek").await;

            let activity = {
                let mut state = main_state.state.write().await;
                state.users.get_mut("geek").unwrap().last_activity -= 10;
                state.users.get("geek").unwrap().last_activity
            };

            line_stream
                .send("JOIN #smartphones".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":geek!~geeker@127.0.0.1 JOIN #smartphones".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            line_stream.next().await.unwrap().unwrap();
            line_stream.next().await.unwrap().unwrap();

            time::sleep(Duration::from_millis(50)).await;

            line_stream
                .send("JOIN #smartwatches,#ebooks,#smartglasses,#wearables".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 475 geek #ebooks :Cannot join channel (+k)".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 475 geek #wearables :Cannot join channel (+k)".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":geek!~geeker@127.0.0.1 JOIN #smartwatches".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            line_stream.next().await.unwrap().unwrap();
            line_stream.next().await.unwrap().unwrap();
            assert_eq!(
                ":geek!~geeker@127.0.0.1 JOIN #smartglasses".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
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

            line_stream
                .send("JOIN #fitbits,#huawei".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 475 geek #fitbits :Cannot join channel (+k)".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 475 geek #huawei :Cannot join channel (+k)".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
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
            line_stream
                .send("USER mat 8 * :MatiSzpaki".to_string())
                .await
                .unwrap();
            line_stream
                .send("CAP REQ :multi-prefix".to_string())
                .await
                .unwrap();
            line_stream.send("CAP END".to_string()).await.unwrap();

            for _ in 0..20 {
                line_stream.next().await.unwrap().unwrap();
            }

            line_stream
                .send("JOIN #oldhardware".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":mati!~mat@127.0.0.1 JOIN #oldhardware".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 353 mati = #oldhardware :~@mati".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 366 mati #oldhardware :End of /NAMES list".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_part() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "joel", "mrjoel", "Joel Dickson").await;
            line_stream.send("JOIN #math".to_string()).await.unwrap();
            for _ in 0..3 {
                line_stream.next().await.unwrap().unwrap();
            }

            let mut line_stream2 =
                login_to_test_and_skip(port, "noah", "z_noah", "Noah Monus").await;
            line_stream2.send("JOIN #math".to_string()).await.unwrap();
            for _ in 0..3 {
                line_stream2.next().await.unwrap().unwrap();
            }
            line_stream.next().await.unwrap().unwrap();

            time::sleep(Duration::from_millis(50)).await;
            let mut exp_channel = {
                let state = main_state.state.read().await;
                state.channels.get("#math").unwrap().clone()
            };
            exp_channel.remove_user("joel");

            line_stream.send("PART #math".to_string()).await.unwrap();
            assert_eq!(
                ":joel!~mrjoel@127.0.0.1 PART #math".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":joel!~mrjoel@127.0.0.1 PART #math".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );

            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                assert_eq!(exp_channel, *state.channels.get("#math").unwrap());
                assert_eq!(HashSet::new(), state.users.get("joel").unwrap().channels);
            }

            line_stream2.send("PART #math".to_string()).await.unwrap();
            assert_eq!(
                ":noah!~z_noah@127.0.0.1 PART #math".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );

            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                assert!(!state.channels.contains_key("#math"));
                assert_eq!(HashSet::new(), state.users.get("noah").unwrap().channels);
            }
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_part_with_reason() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "joel", "mrjoel", "Joel Dickson").await;
            line_stream.send("JOIN #math".to_string()).await.unwrap();
            for _ in 0..3 {
                line_stream.next().await.unwrap().unwrap();
            }

            let mut line_stream2 =
                login_to_test_and_skip(port, "noah", "z_noah", "Noah Monus").await;
            line_stream2.send("JOIN #math".to_string()).await.unwrap();
            for _ in 0..3 {
                line_stream2.next().await.unwrap().unwrap();
            }
            line_stream.next().await.unwrap().unwrap();

            time::sleep(Duration::from_millis(50)).await;
            let mut exp_channel = {
                let state = main_state.state.read().await;
                state.channels.get("#math").unwrap().clone()
            };
            exp_channel.remove_user("joel");

            line_stream
                .send("PART #math :I don't have".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":joel!~mrjoel@127.0.0.1 PART #math :I don't have".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":joel!~mrjoel@127.0.0.1 PART #math :I don't have".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );

            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                assert_eq!(exp_channel, *state.channels.get("#math").unwrap());
                assert_eq!(HashSet::new(), state.users.get("joel").unwrap().channels);
            }

            line_stream2
                .send("PART #math :I don't have too".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":noah!~z_noah@127.0.0.1 PART #math :I don't have too".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );

            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                assert!(!state.channels.contains_key("#math"));
                assert_eq!(HashSet::new(), state.users.get("noah").unwrap().channels);
            }
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_part_preconfigured() {
        let mut config = MainConfig::default();
        config.channels = Some(vec![ChannelConfig {
            name: "#carrots".to_string(),
            topic: None,
            modes: ChannelModes::default(),
        }]);
        let (main_state, handle, port) = run_test_server(config).await;

        {
            let mut line_stream = login_to_test_and_skip(port, "brian", "brianx", "BrianX").await;
            line_stream
                .send("JOIN #carrots,#apples".to_string())
                .await
                .unwrap();

            line_stream
                .send("PART #carrots,#apples".to_string())
                .await
                .unwrap();
            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                assert!(state.channels.contains_key("#carrots"));
                assert!(!state.channels.contains_key("#apples"));
            }
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_part_multiple() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "joel", "mrjoel", "Joel Dickson").await;
            line_stream
                .send("JOIN #math,#algebra,#physics".to_string())
                .await
                .unwrap();
            for _ in 0..9 {
                line_stream.next().await.unwrap().unwrap();
            }

            let mut line_stream2 =
                login_to_test_and_skip(port, "marty1", "marty1", "Marty XXX 1").await;
            let mut line_stream3 =
                login_to_test_and_skip(port, "lucky1", "lucky1", "Lucky XXX 1").await;

            line_stream2
                .send("JOIN #math,#algebra".to_string())
                .await
                .unwrap();
            line_stream3
                .send("JOIN #physics,#algebra".to_string())
                .await
                .unwrap();
            for _ in 0..7 {
                line_stream2.next().await.unwrap().unwrap();
            }
            for _ in 0..6 {
                line_stream3.next().await.unwrap().unwrap();
            }
            for _ in 0..4 {
                line_stream.next().await.unwrap().unwrap();
            }

            time::sleep(Duration::from_millis(50)).await;
            let (mut exp_math, mut exp_algebra, mut exp_physics) = {
                let state = main_state.state.read().await;
                (
                    state.channels.get("#math").unwrap().clone(),
                    state.channels.get("#algebra").unwrap().clone(),
                    state.channels.get("#physics").unwrap().clone(),
                )
            };

            line_stream2
                .send("PART #math,#algebra :Return".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":marty1!~marty1@127.0.0.1 PART #math :Return".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":marty1!~marty1@127.0.0.1 PART #algebra :Return".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":marty1!~marty1@127.0.0.1 PART #algebra :Return".to_string(),
                line_stream3.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":marty1!~marty1@127.0.0.1 PART #math :Return".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":marty1!~marty1@127.0.0.1 PART #algebra :Return".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            exp_math.remove_user("marty1");
            exp_algebra.remove_user("marty1");

            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                assert_eq!(exp_math, *state.channels.get("#math").unwrap());
                assert_eq!(exp_algebra, *state.channels.get("#algebra").unwrap());
                assert_eq!(HashSet::new(), state.users.get("marty1").unwrap().channels);
            }

            line_stream3
                .send("PART #physics,#algebra :Return".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":lucky1!~lucky1@127.0.0.1 PART #physics :Return".to_string(),
                line_stream3.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":lucky1!~lucky1@127.0.0.1 PART #algebra :Return".to_string(),
                line_stream3.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":lucky1!~lucky1@127.0.0.1 PART #physics :Return".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":lucky1!~lucky1@127.0.0.1 PART #algebra :Return".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

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
            let mut line_stream =
                login_to_test_and_skip(port, "joel", "mrjoel", "Joel Dickson").await;
            line_stream
                .send("JOIN #biology,#technics".to_string())
                .await
                .unwrap();
            for _ in 0..6 {
                line_stream.next().await.unwrap().unwrap();
            }

            let mut line_stream2 =
                login_to_test_and_skip(port, "marty1", "marty1", "Marty XXX 1").await;

            line_stream2
                .send("JOIN #biology".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                line_stream2.next().await.unwrap().unwrap();
            }

            let activity = {
                let mut state = main_state.state.write().await;
                state.users.get_mut("marty1").unwrap().last_activity -= 10;
                state.users.get("marty1").unwrap().last_activity
            };
            line_stream2
                .send("PART #physics,#algebra :Return".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 403 marty1 #physics :No such channel".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 403 marty1 #algebra :No such channel".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
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

            line_stream2
                .send("PART #technics,#biology :Return".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 442 marty1 #technics :You're not on that channel".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":marty1!~marty1@127.0.0.1 PART #biology :Return".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
            time::sleep(Duration::from_millis(50)).await;
            {
                // has some activity
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
            let mut line_stream =
                login_to_test_and_skip(port, "robbie", "robbie", "Robbie Williams").await;
            line_stream
                .send("JOIN #hifi,#techno,#trance".to_string())
                .await
                .unwrap();
            for _ in 0..9 {
                line_stream.next().await.unwrap().unwrap();
            }

            line_stream
                .send("TOPIC #hifi :About HiFi".to_string())
                .await
                .unwrap();
            line_stream
                .send("TOPIC #techno :About Techno Music".to_string())
                .await
                .unwrap();
            line_stream
                .send("TOPIC #trance :About Trance Music".to_string())
                .await
                .unwrap();

            assert_eq!(
                ":robbie!~robbie@127.0.0.1 TOPIC #hifi :About HiFi".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":robbie!~robbie@127.0.0.1 TOPIC #techno :About Techno Music".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":robbie!~robbie@127.0.0.1 TOPIC #trance :About Trance Music".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            {
                let mut state = main_state.state.write().await;
                state
                    .channels
                    .get_mut("#trance")
                    .unwrap()
                    .modes
                    .protected_topic = true;
                state
                    .channels
                    .get_mut("#techno")
                    .unwrap()
                    .modes
                    .protected_topic = true;
            }
            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                let topic = state.channels.get("#hifi").unwrap().topic.clone().unwrap();
                assert_eq!(
                    ("About HiFi".to_string(), "robbie".to_string()),
                    (topic.topic, topic.nick)
                );
                let topic = state
                    .channels
                    .get("#techno")
                    .unwrap()
                    .topic
                    .clone()
                    .unwrap();
                assert_eq!(
                    ("About Techno Music".to_string(), "robbie".to_string()),
                    (topic.topic, topic.nick)
                );
                let topic = state
                    .channels
                    .get("#trance")
                    .unwrap()
                    .topic
                    .clone()
                    .unwrap();
                assert_eq!(
                    ("About Trance Music".to_string(), "robbie".to_string()),
                    (topic.topic, topic.nick)
                );
            }

            let mut line_stream2 =
                login_to_test_and_skip(port, "djtechno", "djtechno0", "DJ Techno Maniac").await;
            line_stream2
                .send("TOPIC #hifi :About HiFi equipment".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 442 djtechno #hifi :You're not on that channel".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );

            time::sleep(Duration::from_millis(50)).await;
            {
                // old topic
                let state = main_state.state.read().await;
                let topic = state.channels.get("#hifi").unwrap().topic.clone().unwrap();
                assert_eq!(
                    ("About HiFi".to_string(), "robbie".to_string()),
                    (topic.topic, topic.nick)
                );
            }

            line_stream2
                .send("JOIN #hifi,#techno,#trance".to_string())
                .await
                .unwrap();
            for _ in 0..(4 * 3) {
                line_stream2.next().await.unwrap().unwrap();
            }
            // skip JOIN messages for robbie
            for _ in 0..3 {
                line_stream.next().await.unwrap().unwrap();
            }

            line_stream2
                .send("TOPIC #hifi :About HiFi hardware".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":djtechno!~djtechno0@127.0.0.1 TOPIC #hifi :About HiFi hardware".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":djtechno!~djtechno0@127.0.0.1 TOPIC #hifi :About HiFi hardware".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                let topic = state.channels.get("#hifi").unwrap().topic.clone().unwrap();
                assert_eq!(
                    ("About HiFi hardware".to_string(), "djtechno".to_string()),
                    (topic.topic, topic.nick)
                );
            }

            line_stream2
                .send("TOPIC #techno :About Techno genre".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 482 djtechno #techno :You're not channel operator".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
            line_stream2
                .send("TOPIC #trance :About Trance genre".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 482 djtechno #trance :You're not channel operator".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );

            // unset topic
            line_stream2
                .send("TOPIC #hifi :".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":djtechno!~djtechno0@127.0.0.1 TOPIC #hifi :".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":djtechno!~djtechno0@127.0.0.1 TOPIC #hifi :".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                assert_eq!(None, state.channels.get("#hifi").unwrap().topic);
            }

            // no channel
            line_stream2
                .send("TOPIC #hifix :bla bla".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 403 djtechno #hifix :No such channel".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_topic_read() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "maniac", "maniac", "SuperGeek").await;
            line_stream.send("JOIN #cpus".to_string()).await.unwrap();
            for _ in 0..3 {
                line_stream.next().await.unwrap().unwrap();
            }

            line_stream.send("TOPIC #cpus".to_string()).await.unwrap();
            assert_eq!(
                ":irc.irc 331 maniac #cpus :No topic is set".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            line_stream
                .send("TOPIC #cpus :About processors".to_string())
                .await
                .unwrap();
            line_stream.next().await.unwrap().unwrap();

            line_stream.send("TOPIC #cpus".to_string()).await.unwrap();
            assert_eq!(
                ":irc.irc 332 maniac #cpus :About processors".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            let set_time = main_state
                .state
                .read()
                .await
                .channels
                .get("#cpus")
                .unwrap()
                .topic
                .as_ref()
                .unwrap()
                .set_time;
            assert_eq!(
                format!(":irc.irc 333 maniac #cpus maniac {}", set_time),
                line_stream.next().await.unwrap().unwrap()
            );

            let mut newbie_stream =
                login_to_test_and_skip(port, "newbie", "newbie0", "Computer's Newbie").await;
            newbie_stream.send("TOPIC #cpus".to_string()).await.unwrap();
            assert_eq!(
                ":irc.irc 442 newbie #cpus :You're not on that channel".to_string(),
                newbie_stream.next().await.unwrap().unwrap()
            );
            newbie_stream.send("JOIN #cpus".to_string()).await.unwrap();
            for _ in 0..4 {
                newbie_stream.next().await.unwrap().unwrap();
            }
            // after join
            newbie_stream.send("TOPIC #cpus".to_string()).await.unwrap();
            assert_eq!(
                ":irc.irc 332 newbie #cpus :About processors".to_string(),
                newbie_stream.next().await.unwrap().unwrap()
            );

            let set_time = main_state
                .state
                .read()
                .await
                .channels
                .get("#cpus")
                .unwrap()
                .topic
                .as_ref()
                .unwrap()
                .set_time;
            assert_eq!(
                format!(":irc.irc 333 newbie #cpus maniac {}", set_time),
                newbie_stream.next().await.unwrap().unwrap()
            );

            newbie_stream.send("TOPIC #apus".to_string()).await.unwrap();
            assert_eq!(
                ":irc.irc 403 newbie #apus :No such channel".to_string(),
                newbie_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    async fn assert_names_lists_chanlist<'a>(
        exp_names_input: &HashMap<&'a str, (&'a str, &'a str, Vec<String>, bool)>,
        line_stream: &mut Framed<TcpStream, IRCLinesCodec>,
        total_count: usize,
        nick: &'a str,
    ) {
        let mut last_chan = None;
        let mut chan_replies = vec![];
        let mut exp_names = exp_names_input.clone();
        let reply_start = format!(":irc.irc 353 {} ", nick);

        for i in 0..total_count {
            let reply = line_stream.next().await.unwrap().unwrap();
            if reply.starts_with(&reply_start) {
                let chan = reply[reply_start.len() + 2..]
                    .split_ascii_whitespace()
                    .next()
                    .unwrap();
                if let Some(ref prev_chan) = last_chan {
                    assert_eq!(prev_chan, chan, "order chan test {}", i);
                } else {
                    last_chan = Some(chan.to_string());
                }
                chan_replies.push(reply.clone());
            } else {
                if let Some(ref prev_chan) = last_chan {
                    assert_eq!(
                        format!(":irc.irc 366 {} {} :End of /NAMES list", nick, prev_chan),
                        reply
                    );
                    let exp_name_list = exp_names.get(prev_chan.as_str()).unwrap();
                    assert!(equal_channel_names(
                        &format!("{}{}{}", exp_name_list.0, nick, exp_name_list.1),
                        &exp_name_list
                            .2
                            .iter()
                            .map(|x| x.as_str())
                            .collect::<Vec<_>>(),
                        &chan_replies.iter().map(|x| x.as_str()).collect::<Vec<_>>()
                    ));

                    exp_names.get_mut(prev_chan.as_str()).unwrap().3 = true;
                } else {
                    let reply_start_2 = format!(":irc.irc 366 {} ", nick);
                    if reply.starts_with(&reply_start_2) {
                        let chan = reply[reply_start_2.len()..]
                            .split_ascii_whitespace()
                            .next()
                            .unwrap();
                        assert!(
                            (!exp_names.contains_key(chan))
                                || exp_names.get(chan).unwrap().2.is_empty()
                        );
                    }
                }
                last_chan = None;
                chan_replies.clear();
            }
        }
        assert!(exp_names.values().all(|x| x.3)); // if all touched
    }

    async fn assert_names_lists_all<'a>(
        exp_names_input: &HashMap<&'a str, (&'a str, &'a str, Vec<String>, bool)>,
        line_stream: &mut Framed<TcpStream, IRCLinesCodec>,
        total_count: usize,
        nick: &'a str,
    ) {
        let mut last_chan = None;
        let mut chan_replies = vec![];
        let mut exp_names = exp_names_input.clone();
        let reply_start = format!(":irc.irc 353 {} ", nick);

        for _ in 0..total_count {
            let reply = line_stream.next().await.unwrap().unwrap();
            if reply.starts_with(&reply_start) {
                let chan = reply[reply_start.len() + 2..]
                    .split_ascii_whitespace()
                    .next()
                    .unwrap();
                if last_chan == Some(chan.to_string()) {
                    chan_replies.push(reply.clone());
                } else if let Some(ref prev_chan) = last_chan {
                    let exp_name_list = exp_names.get(prev_chan.as_str()).unwrap();
                    assert!(equal_channel_names(
                        &format!("{}{}{}", exp_name_list.0, nick, exp_name_list.1),
                        &exp_name_list
                            .2
                            .iter()
                            .map(|x| x.as_str())
                            .collect::<Vec<_>>(),
                        &chan_replies.iter().map(|x| x.as_str()).collect::<Vec<_>>()
                    ));

                    exp_names.get_mut(prev_chan.as_str()).unwrap().3 = true;
                    last_chan = Some(chan.to_string());
                    chan_replies.clear();
                    chan_replies.push(reply.clone());
                } else {
                    last_chan = Some(chan.to_string());
                    chan_replies.push(reply.clone());
                }
            } else {
                if let Some(prev_chan) = last_chan {
                    assert_eq!(
                        format!(":irc.irc 366 {} * :End of /NAMES list", nick),
                        reply
                    );
                    let exp_name_list = exp_names.get(prev_chan.as_str()).unwrap();
                    assert!(equal_channel_names(
                        &format!("{}{}{}", exp_name_list.0, nick, exp_name_list.1),
                        &exp_name_list
                            .2
                            .iter()
                            .map(|x| x.as_str())
                            .collect::<Vec<_>>(),
                        &chan_replies.iter().map(|x| x.as_str()).collect::<Vec<_>>()
                    ));

                    exp_names.get_mut(prev_chan.as_str()).unwrap().3 = true;
                    last_chan = None;
                    chan_replies.clear();
                } else {
                    panic!("Unexpected none in last_chan");
                }
                assert_eq!(
                    format!(":irc.irc 366 {} * :End of /NAMES list", nick),
                    reply
                );
            }
        }
        assert!(exp_names.values().all(|x| x.3)); // if all touched
    }

    #[tokio::test]
    async fn test_command_names() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "maniac", "maniac", "SuperGeek").await;
            line_stream
                .send("JOIN #cpus,#gpus,#sdds,#psus,#mobos".to_string())
                .await
                .unwrap();
            for _ in 0..3 * 5 {
                line_stream.next().await.unwrap().unwrap();
            }

            let mut line_streams = vec![];
            for i in 0..60 {
                line_streams.push(
                    login_to_test_and_skip(
                        port,
                        &format!("geek{}", i),
                        &format!("geekx{}", i),
                        &format!("MainGeek{}", i),
                    )
                    .await,
                );
            }

            let mut exp_names = HashMap::from([
                (
                    "#cpus",
                    (
                        ":irc.irc 353 ",
                        " = #cpus :",
                        vec!["~maniac".to_string()],
                        false,
                    ),
                ),
                (
                    "#gpus",
                    (
                        ":irc.irc 353 ",
                        " = #gpus :",
                        vec!["~maniac".to_string()],
                        false,
                    ),
                ),
                (
                    "#sdds",
                    (
                        ":irc.irc 353 ",
                        " = #sdds :",
                        vec!["~maniac".to_string()],
                        false,
                    ),
                ),
                (
                    "#psus",
                    (
                        ":irc.irc 353 ",
                        " = #psus :",
                        vec!["~maniac".to_string()],
                        false,
                    ),
                ),
                (
                    "#mobos",
                    (
                        ":irc.irc 353 ",
                        " = #mobos :",
                        vec!["~maniac".to_string()],
                        false,
                    ),
                ),
            ]);

            for (i, line_stream) in line_streams.iter_mut().enumerate() {
                if (i & 1) == 0 {
                    line_stream.send("JOIN #cpus".to_string()).await.unwrap();
                    exp_names
                        .get_mut("#cpus")
                        .unwrap()
                        .2
                        .push(format!("geek{}", i));
                } else {
                    line_stream.send("JOIN #gpus".to_string()).await.unwrap();
                    exp_names
                        .get_mut("#gpus")
                        .unwrap()
                        .2
                        .push(format!("geek{}", i));
                }
                match i % 3 {
                    0 => {
                        line_stream.send("JOIN #sdds".to_string()).await.unwrap();
                        exp_names
                            .get_mut("#sdds")
                            .unwrap()
                            .2
                            .push(format!("geek{}", i));
                    }
                    1 => {
                        line_stream.send("JOIN #psus".to_string()).await.unwrap();
                        exp_names
                            .get_mut("#psus")
                            .unwrap()
                            .2
                            .push(format!("geek{}", i));
                    }
                    2 => {
                        line_stream.send("JOIN #mobos".to_string()).await.unwrap();
                        exp_names
                            .get_mut("#mobos")
                            .unwrap()
                            .2
                            .push(format!("geek{}", i));
                    }
                    _ => {}
                }
                for _ in 0..6 {
                    line_stream.next().await.unwrap().unwrap();
                }
            }

            for _ in 0..60 * 2 {
                line_stream.next().await.unwrap().unwrap();
            }

            time::sleep(Duration::from_millis(100)).await;

            line_stream.send("NAMES".to_string()).await.unwrap();
            assert_names_lists_all(&exp_names, &mut line_stream, 11, "maniac").await;

            let mut exp_names_2 = HashMap::new();
            exp_names_2.insert("#cpus", exp_names.get("#cpus").unwrap().clone());
            exp_names_2.insert("#psus", exp_names.get("#psus").unwrap().clone());

            line_stream
                .send("NAMES #cpus,#psus".to_string())
                .await
                .unwrap();
            assert_names_lists_chanlist(&exp_names_2, &mut line_stream, 6, "maniac").await;

            line_stream
                .send("NAMES #cpus,#xxxx,#psus".to_string())
                .await
                .unwrap();
            assert_names_lists_chanlist(&exp_names_2, &mut line_stream, 7, "maniac").await;

            line_streams[0].send("NAMES".to_string()).await.unwrap();
            for _ in 0..48 {
                line_streams[0].next().await.unwrap().unwrap();
            }
            assert_names_lists_all(&exp_names, &mut line_streams[0], 11, "geek0").await;
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_names_with_multi_prefix() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream = connect_to_test(port).await;
            line_stream.send("CAP LS 302".to_string()).await.unwrap();
            line_stream.send("NICK forexman".to_string()).await.unwrap();
            line_stream
                .send("USER forexman 8 * :Forex Maniac".to_string())
                .await
                .unwrap();
            line_stream
                .send("CAP REQ :multi-prefix".to_string())
                .await
                .unwrap();
            line_stream.send("CAP END".to_string()).await.unwrap();

            for _ in 0..20 {
                line_stream.next().await.unwrap().unwrap();
            }

            line_stream
                .send("JOIN #coins,#forex,#gold".to_string())
                .await
                .unwrap();
            for _ in 0..3 * 3 {
                line_stream.next().await.unwrap().unwrap();
            }

            let mut gold_stream =
                login_to_test_and_skip(port, "goldy", "goldie", "Gold Maniac").await;
            gold_stream.send("JOIN #forex".to_string()).await.unwrap();
            for _ in 0..3 {
                gold_stream.next().await.unwrap().unwrap();
            }

            let exp_names = HashMap::from([
                (
                    "#coins",
                    (
                        ":irc.irc 353 ",
                        " = #coins :",
                        vec!["~@forexman".to_string()],
                        false,
                    ),
                ),
                (
                    "#forex",
                    (
                        ":irc.irc 353 ",
                        " = #forex :",
                        vec!["~@forexman".to_string(), "goldy".to_string()],
                        false,
                    ),
                ),
                (
                    "#gold",
                    (
                        ":irc.irc 353 ",
                        " = #gold :",
                        vec!["~@forexman".to_string()],
                        false,
                    ),
                ),
            ]);

            line_stream.next().await.unwrap().unwrap(); // skip JOIN
            line_stream.send("NAMES".to_string()).await.unwrap();
            assert_names_lists_all(&exp_names, &mut line_stream, 4, "forexman").await;
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_names_secret() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "forexman", "forexman", "Forex Maniac").await;
            line_stream
                .send("JOIN #coins,#forex,#gold".to_string())
                .await
                .unwrap();
            for _ in 0..3 * 3 {
                line_stream.next().await.unwrap().unwrap();
            }

            time::sleep(Duration::from_millis(50)).await;
            {
                let mut state = main_state.state.write().await;
                state.channels.get_mut("#forex").unwrap().modes.secret = true;
                state.channels.get_mut("#gold").unwrap().modes.secret = true;
            }

            let mut gold_stream =
                login_to_test_and_skip(port, "goldy", "goldie", "Gold Maniac").await;
            gold_stream.send("JOIN #forex".to_string()).await.unwrap();
            for _ in 0..3 {
                gold_stream.next().await.unwrap().unwrap();
            }

            let exp_names = HashMap::from([
                (
                    "#coins",
                    (
                        ":irc.irc 353 ",
                        " = #coins :",
                        vec!["~forexman".to_string()],
                        false,
                    ),
                ),
                (
                    "#forex",
                    (
                        ":irc.irc 353 ",
                        " @ #forex :",
                        vec!["~forexman".to_string(), "goldy".to_string()],
                        false,
                    ),
                ),
            ]);

            gold_stream.send("NAMES".to_string()).await.unwrap();
            assert_names_lists_all(&exp_names, &mut gold_stream, 3, "goldy").await;

            gold_stream
                .send("NAMES #forex,#gold,#coins".to_string())
                .await
                .unwrap();
            assert_names_lists_chanlist(&exp_names, &mut gold_stream, 4, "goldy").await;

            let exp_names = HashMap::from([
                (
                    "#coins",
                    (
                        ":irc.irc 353 ",
                        " = #coins :",
                        vec!["~forexman".to_string()],
                        false,
                    ),
                ),
                (
                    "#forex",
                    (
                        ":irc.irc 353 ",
                        " @ #forex :",
                        vec!["~forexman".to_string(), "goldy".to_string()],
                        false,
                    ),
                ),
                (
                    "#gold",
                    (
                        ":irc.irc 353 ",
                        " @ #gold :",
                        vec!["~forexman".to_string()],
                        false,
                    ),
                ),
            ]);

            line_stream.send("NAMES".to_string()).await.unwrap();
            line_stream.next().await.unwrap().unwrap();
            assert_names_lists_all(&exp_names, &mut line_stream, 4, "forexman").await;
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_names_invisible_users() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream = login_to_test_and_skip(port, "zool", "Zool", "Zool Fan").await;
            line_stream
                .send("JOIN #amiga,#arcades,#zool2".to_string())
                .await
                .unwrap();
            for _ in 0..3 * 3 {
                line_stream.next().await.unwrap().unwrap();
            }

            let mut mati_stream = login_to_test_and_skip(port, "mati", "matix", "MatiSzpaki").await;
            mati_stream
                .send("JOIN #amiga,#arcades".to_string())
                .await
                .unwrap();
            for _ in 0..6 {
                mati_stream.next().await.unwrap().unwrap();
            }

            let mut bee_stream = login_to_test_and_skip(port, "bee", "bee", "Beeeeeeee").await;
            let mut lolipop_stream =
                login_to_test_and_skip(port, "lolipop", "ylolipop", "Lolipop Eater").await;
            let mut chupa_stream =
                login_to_test_and_skip(port, "chupa", "chupachoops", "ChupaChoops").await;

            bee_stream.send("JOIN #arcades".to_string()).await.unwrap();
            for _ in 0..3 {
                bee_stream.next().await.unwrap().unwrap();
            }
            lolipop_stream
                .send("JOIN #amiga".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                lolipop_stream.next().await.unwrap().unwrap();
            }
            chupa_stream.send("JOIN #zool2".to_string()).await.unwrap();
            for _ in 0..3 {
                chupa_stream.next().await.unwrap().unwrap();
            }

            time::sleep(Duration::from_millis(50)).await;
            {
                let mut state = main_state.state.write().await;
                state.users.get_mut("lolipop").unwrap().modes.invisible = true;
                state.users.get_mut("chupa").unwrap().modes.invisible = true;
            }

            let exp_names = HashMap::from([
                (
                    "#amiga",
                    (
                        ":irc.irc 353 ",
                        " = #amiga :",
                        vec![
                            "~zool".to_string(),
                            "mati".to_string(),
                            "lolipop".to_string(),
                        ],
                        false,
                    ),
                ),
                (
                    "#arcades",
                    (
                        ":irc.irc 353 ",
                        " = #arcades :",
                        vec!["~zool".to_string(), "mati".to_string(), "bee".to_string()],
                        false,
                    ),
                ),
                (
                    "#zool2",
                    (
                        ":irc.irc 353 ",
                        " = #zool2 :",
                        vec!["~zool".to_string()],
                        false,
                    ),
                ),
            ]);

            mati_stream.send("NAMES".to_string()).await.unwrap();
            mati_stream.next().await.unwrap().unwrap();
            mati_stream.next().await.unwrap().unwrap();
            assert_names_lists_all(&exp_names, &mut mati_stream, 4, "mati").await;
        }

        quit_test_server(main_state, handle).await;
    }

    fn equal_channel_list<'a>(
        msg_start: &'a str,
        expected: &'a [&'a str],
        results: &'a [&'a str],
    ) -> bool {
        let mut expected_sorted = Vec::from(expected);
        expected_sorted.sort();
        let mut touched = vec![false; expected.len()];

        results.iter().all(|res| {
            if res.starts_with(msg_start) {
                let rest = &res[msg_start.len()..];
                if let Ok(p) = expected_sorted.binary_search(&rest) {
                    touched[p] = true;
                    true
                } else {
                    false
                }
            } else {
                false
            }
        }) && touched.iter().all(|x| *x)
    }

    #[tokio::test]
    async fn test_command_list() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "edmund", "edmund", "Edmund Serious").await;
            line_stream
                .send("JOIN #politics,#economics,#management".to_string())
                .await
                .unwrap();
            line_stream
                .send("TOPIC #economics :About economics".to_string())
                .await
                .unwrap();

            let mut line_stream2 =
                login_to_test_and_skip(port, "nick", "nicolas", "Nicolas Serious").await;
            line_stream2
                .send("JOIN #politics,#economics".to_string())
                .await
                .unwrap();
            for _ in 0..3 * 2 + 1 {
                line_stream2.next().await.unwrap().unwrap();
            }

            for _ in 0..3 * 3 + 3 {
                line_stream.next().await.unwrap().unwrap();
            }

            line_stream.send("LIST".to_string()).await.unwrap();
            assert_eq!(
                ":irc.irc 321 edmund Channel :Users  Name".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert!(equal_channel_list(
                ":irc.irc 322 edmund ",
                &[
                    "#politics 2 :",
                    "#economics 2 :About economics",
                    "#management 1 :"
                ],
                &[
                    &line_stream.next().await.unwrap().unwrap(),
                    &line_stream.next().await.unwrap().unwrap(),
                    &line_stream.next().await.unwrap().unwrap()
                ]
            ));
            assert_eq!(
                ":irc.irc 323 edmund :End of /LIST".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            line_stream2.send("LIST".to_string()).await.unwrap();
            assert_eq!(
                ":irc.irc 321 nick Channel :Users  Name".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
            assert!(equal_channel_list(
                ":irc.irc 322 nick ",
                &[
                    "#politics 2 :",
                    "#economics 2 :About economics",
                    "#management 1 :"
                ],
                &[
                    &line_stream2.next().await.unwrap().unwrap(),
                    &line_stream2.next().await.unwrap().unwrap(),
                    &line_stream2.next().await.unwrap().unwrap()
                ]
            ));
            assert_eq!(
                ":irc.irc 323 nick :End of /LIST".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );

            line_stream
                .send("LIST #politics,#management,#decisions".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 321 edmund Channel :Users  Name".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert!(equal_channel_list(
                ":irc.irc 322 edmund ",
                &["#politics 2 :", "#management 1 :"],
                &[
                    &line_stream.next().await.unwrap().unwrap(),
                    &line_stream.next().await.unwrap().unwrap()
                ]
            ));
            assert_eq!(
                ":irc.irc 323 edmund :End of /LIST".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            time::sleep(Duration::from_millis(50)).await;
            // secret channel
            main_state
                .state
                .write()
                .await
                .channels
                .get_mut("#management")
                .unwrap()
                .modes
                .secret = true;

            line_stream.send("LIST".to_string()).await.unwrap();
            assert_eq!(
                ":irc.irc 321 edmund Channel :Users  Name".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert!(equal_channel_list(
                ":irc.irc 322 edmund ",
                &["#politics 2 :", "#economics 2 :About economics"],
                &[
                    &line_stream.next().await.unwrap().unwrap(),
                    &line_stream.next().await.unwrap().unwrap()
                ]
            ));
            assert_eq!(
                ":irc.irc 323 edmund :End of /LIST".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_invite() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "seba", "sebastian", "Sebastian Gross").await;
            line_stream
                .send("JOIN #funky,#punky".to_string())
                .await
                .unwrap();
            for _ in 0..6 {
                line_stream.next().await.unwrap().unwrap();
            }

            let mut line_stream2 =
                login_to_test_and_skip(port, "stan", "stan", "Stan Straightforward").await;
            time::sleep(Duration::from_millis(50)).await;
            {
                // set invite only for punky
                main_state
                    .state
                    .write()
                    .await
                    .channels
                    .get_mut("#punky")
                    .unwrap()
                    .modes
                    .invite_only = true;
            }
            line_stream
                .send("INVITE stan #funky".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 341 seba stan #funky".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            time::sleep(Duration::from_millis(50)).await;
            {
                assert!(main_state
                    .state
                    .read()
                    .await
                    .users
                    .get("stan")
                    .unwrap()
                    .invited_to
                    .contains("#funky"));
            }
            assert_eq!(
                ":seba!~sebastian@127.0.0.1 INVITE stan #funky".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
            line_stream2.send("JOIN #funky".to_string()).await.unwrap();
            for _ in 0..3 {
                line_stream2.next().await.unwrap().unwrap();
            }
            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                assert!(!state
                    .users
                    .get("stan")
                    .unwrap()
                    .invited_to
                    .contains("#funky"));
                assert!(state
                    .channels
                    .get("#funky")
                    .unwrap()
                    .users
                    .contains_key("stan"));
            }
            line_stream.next().await.unwrap().unwrap(); // skip JOIN

            line_stream
                .send("INVITE stan #punky".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 341 seba stan #punky".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            time::sleep(Duration::from_millis(50)).await;
            {
                assert!(main_state
                    .state
                    .read()
                    .await
                    .users
                    .get("stan")
                    .unwrap()
                    .invited_to
                    .contains("#punky"));
            }
            line_stream2.send("JOIN #punky".to_string()).await.unwrap();
            assert_eq!(
                ":seba!~sebastian@127.0.0.1 INVITE stan #punky".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                assert!(!state
                    .users
                    .get("stan")
                    .unwrap()
                    .invited_to
                    .contains("#punky"));
                assert!(state
                    .channels
                    .get("#punky")
                    .unwrap()
                    .users
                    .contains_key("stan"));
            }
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_invite_failures() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "seba", "sebastian", "Sebastian Gross").await;
            line_stream
                .send("JOIN #funky,#punky".to_string())
                .await
                .unwrap();
            for _ in 0..6 {
                line_stream.next().await.unwrap().unwrap();
            }

            let mut line_stream2 =
                login_to_test_and_skip(port, "stan", "stan", "Stan Straightforward").await;
            line_stream2.send("JOIN #punky".to_string()).await.unwrap();
            for _ in 0..3 {
                line_stream2.next().await.unwrap().unwrap();
            }

            line_stream.next().await.unwrap().unwrap(); // skip JOIN stan

            time::sleep(Duration::from_millis(50)).await;
            {
                // set invite only for punky
                main_state
                    .state
                    .write()
                    .await
                    .channels
                    .get_mut("#punky")
                    .unwrap()
                    .modes
                    .invite_only = true;
            }

            login_to_test_and_skip(port, "sonny", "sonny9", "Sonny Sunshine").await;
            time::sleep(Duration::from_millis(50)).await;
            line_stream2
                .send("INVITE sonny #funky".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 442 stan #funky :You're not on that channel".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
            line_stream2
                .send("INVITE sonny #punky".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 482 stan #punky :You're not channel operator".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
            line_stream2
                .send("INVITE sonny #pinky".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 403 stan #pinky :No such channel".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );

            line_stream
                .send("INVITE sunday #punky".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 401 seba sunday :No such nick/channel".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_kick() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "adam", "adam", "Adam Sandwich").await;
            line_stream
                .send("JOIN #impressions".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                line_stream.next().await.unwrap().unwrap();
            }

            let mut ben_stream =
                login_to_test_and_skip(port, "ben", "benedict", "Benedict Tomato").await;
            ben_stream
                .send("JOIN #impressions".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                ben_stream.next().await.unwrap().unwrap();
            }

            let mut chris_stream =
                login_to_test_and_skip(port, "chris", "christopher", "Christopher Lambda").await;
            chris_stream
                .send("JOIN #impressions".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                chris_stream.next().await.unwrap().unwrap();
            }

            let mut charlie_stream =
                login_to_test_and_skip(port, "charlie", "charlie", "Charlie Pingy").await;
            charlie_stream
                .send("JOIN #impressions".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                charlie_stream.next().await.unwrap().unwrap();
            }

            let mut david_stream =
                login_to_test_and_skip(port, "david", "david", "David Storm").await;
            david_stream
                .send("JOIN #impressions".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                david_stream.next().await.unwrap().unwrap();
            }

            login_to_test_and_skip(port, "eliach", "eliach", "Eliach Thunder").await;

            for _ in 0..4 {
                line_stream.next().await.unwrap().unwrap();
            }
            for _ in 0..3 {
                ben_stream.next().await.unwrap().unwrap();
            }
            for _ in 0..2 {
                chris_stream.next().await.unwrap().unwrap();
            }
            charlie_stream.next().await.unwrap().unwrap();

            time::sleep(Duration::from_millis(100)).await;
            {
                let mut state = main_state.state.write().await;
                let channel = state.channels.get_mut("#impressions").unwrap();
                channel.add_voice("david");
                channel.add_half_operator("chris");
                channel.add_half_operator("charlie");
                channel.add_protected("ben");
            }

            chris_stream
                .send("KICK #impressions david".to_string())
                .await
                .unwrap();
            for line_stream in [
                &mut line_stream,
                &mut ben_stream,
                &mut chris_stream,
                &mut charlie_stream,
                &mut david_stream,
            ] {
                assert_eq!(
                    ":chris!~christopher@127.0.0.1 KICK #impressions david :Kicked",
                    line_stream.next().await.unwrap().unwrap()
                );
            }
            time::sleep(Duration::from_millis(50)).await;
            {
                assert!(!main_state
                    .state
                    .read()
                    .await
                    .channels
                    .get("#impressions")
                    .unwrap()
                    .users
                    .contains_key("david"));
            }

            chris_stream
                .send("KICK #impressions charlie".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 972 chris :Can not do command".to_string(),
                chris_stream.next().await.unwrap().unwrap()
            );
            time::sleep(Duration::from_millis(50)).await;
            {
                assert!(main_state
                    .state
                    .read()
                    .await
                    .channels
                    .get("#impressions")
                    .unwrap()
                    .users
                    .contains_key("charlie"));
            }

            chris_stream
                .send("KICK #impressions ben".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 972 chris :Can not do command".to_string(),
                chris_stream.next().await.unwrap().unwrap()
            );
            time::sleep(Duration::from_millis(50)).await;
            {
                assert!(main_state
                    .state
                    .read()
                    .await
                    .channels
                    .get("#impressions")
                    .unwrap()
                    .users
                    .contains_key("ben"));
            }

            chris_stream
                .send("KICK #impressions adam".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 972 chris :Can not do command".to_string(),
                chris_stream.next().await.unwrap().unwrap()
            );
            time::sleep(Duration::from_millis(50)).await;
            {
                assert!(main_state
                    .state
                    .read()
                    .await
                    .channels
                    .get("#impressions")
                    .unwrap()
                    .users
                    .contains_key("adam"));
            }

            ben_stream
                .send("KICK #impressions charlie".to_string())
                .await
                .unwrap();
            for line_stream in [
                &mut line_stream,
                &mut ben_stream,
                &mut chris_stream,
                &mut charlie_stream,
            ] {
                assert_eq!(
                    ":ben!~benedict@127.0.0.1 KICK #impressions charlie :Kicked",
                    line_stream.next().await.unwrap().unwrap()
                );
            }
            time::sleep(Duration::from_millis(50)).await;
            {
                assert!(!main_state
                    .state
                    .read()
                    .await
                    .channels
                    .get("#impressions")
                    .unwrap()
                    .users
                    .contains_key("charlie"));
            }

            chris_stream
                .send("KICK #impressions eliach".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 441 chris eliach #impressions \
                    :They aren't on that channel"
                    .to_string(),
                chris_stream.next().await.unwrap().unwrap()
            );

            david_stream
                .send("JOIN #impressions".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                david_stream.next().await.unwrap().unwrap();
            }

            david_stream
                .send("KICK #impressions chris".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 482 david #impressions :You're not channel operator".to_string(),
                david_stream.next().await.unwrap().unwrap()
            );
            time::sleep(Duration::from_millis(50)).await;
            {
                assert!(main_state
                    .state
                    .read()
                    .await
                    .channels
                    .get("#impressions")
                    .unwrap()
                    .users
                    .contains_key("chris"));
            }
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_kick_self() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "adam", "adam", "Adam Sandwich").await;
            line_stream
                .send("JOIN #impressions".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                line_stream.next().await.unwrap().unwrap();
            }

            let mut ben_stream =
                login_to_test_and_skip(port, "ben", "benedict", "Benedict Tomato").await;
            ben_stream
                .send("JOIN #impressions".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                ben_stream.next().await.unwrap().unwrap();
            }

            let mut chris_stream =
                login_to_test_and_skip(port, "chris", "christopher", "Christopher Lambda").await;
            chris_stream
                .send("JOIN #impressions".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                chris_stream.next().await.unwrap().unwrap();
            }

            let mut charlie_stream =
                login_to_test_and_skip(port, "charlie", "charlie", "Charlie Pingy").await;
            charlie_stream
                .send("JOIN #impressions".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                charlie_stream.next().await.unwrap().unwrap();
            }

            let mut david_stream =
                login_to_test_and_skip(port, "david", "david", "David Storm").await;
            david_stream
                .send("JOIN #impressions".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                david_stream.next().await.unwrap().unwrap();
            }

            for _ in 0..4 {
                line_stream.next().await.unwrap().unwrap();
            }
            for _ in 0..3 {
                ben_stream.next().await.unwrap().unwrap();
            }
            for _ in 0..2 {
                chris_stream.next().await.unwrap().unwrap();
            }
            charlie_stream.next().await.unwrap().unwrap();

            time::sleep(Duration::from_millis(100)).await;
            {
                let mut state = main_state.state.write().await;
                let channel = state.channels.get_mut("#impressions").unwrap();
                channel.add_voice("david");
                channel.add_half_operator("chris");
                channel.add_operator("charlie");
                channel.add_protected("ben");
            }

            david_stream
                .send("KICK #impressions david".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 482 david #impressions :You're not channel operator".to_string(),
                david_stream.next().await.unwrap().unwrap()
            );

            chris_stream
                .send("KICK #impressions chris".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 972 chris :Can not do command".to_string(),
                chris_stream.next().await.unwrap().unwrap()
            );

            charlie_stream
                .send("KICK #impressions charlie".to_string())
                .await
                .unwrap();
            for line_stream in [
                &mut line_stream,
                &mut ben_stream,
                &mut chris_stream,
                &mut charlie_stream,
            ] {
                assert_eq!(
                    ":charlie!~charlie@127.0.0.1 KICK #impressions charlie :Kicked".to_string(),
                    line_stream.next().await.unwrap().unwrap()
                );
            }

            ben_stream
                .send("KICK #impressions ben".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 972 ben :Can not do command".to_string(),
                ben_stream.next().await.unwrap().unwrap()
            );

            line_stream
                .send("KICK #impressions adam".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 972 adam :Can not do command".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_kick_reason() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "adam", "adam", "Adam Sandwich").await;
            line_stream
                .send("JOIN #impressions".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                line_stream.next().await.unwrap().unwrap();
            }

            let mut ben_stream =
                login_to_test_and_skip(port, "ben", "benedict", "Benedict Tomato").await;
            ben_stream
                .send("JOIN #impressions".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                ben_stream.next().await.unwrap().unwrap();
            }

            line_stream.next().await.unwrap().unwrap();

            line_stream
                .send("KICK #impressions ben :Bad Boy".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":adam!~adam@127.0.0.1 KICK #impressions ben :Bad Boy".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":adam!~adam@127.0.0.1 KICK #impressions ben :Bad Boy".to_string(),
                ben_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_kick_multiple_users() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "adam", "adam", "Adam Sandwich").await;
            line_stream
                .send("JOIN #impressions".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                line_stream.next().await.unwrap().unwrap();
            }

            let mut ben_stream =
                login_to_test_and_skip(port, "ben", "benedict", "Benedict Tomato").await;
            ben_stream
                .send("JOIN #impressions".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                ben_stream.next().await.unwrap().unwrap();
            }

            let mut chris_stream =
                login_to_test_and_skip(port, "chris", "christopher", "Christopher Lambda").await;
            chris_stream
                .send("JOIN #impressions".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                chris_stream.next().await.unwrap().unwrap();
            }

            let mut charlie_stream =
                login_to_test_and_skip(port, "charlie", "charlie", "Charlie Pingy").await;
            charlie_stream
                .send("JOIN #impressions".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                charlie_stream.next().await.unwrap().unwrap();
            }

            for _ in 0..3 {
                line_stream.next().await.unwrap().unwrap();
            }
            for _ in 0..2 {
                ben_stream.next().await.unwrap().unwrap();
            }
            chris_stream.next().await.unwrap().unwrap();

            time::sleep(Duration::from_millis(100)).await;
            {
                let mut state = main_state.state.write().await;
                let channel = state.channels.get_mut("#impressions").unwrap();
                channel.add_half_operator("chris");
                channel.add_operator("charlie");
                channel.add_protected("ben");
            }

            line_stream
                .send("KICK #impressions chris,charlie,ben :You are bad".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 972 adam :Can not do command".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":adam!~adam@127.0.0.1 KICK #impressions chris :You are bad".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":adam!~adam@127.0.0.1 KICK #impressions charlie :You are bad".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":adam!~adam@127.0.0.1 KICK #impressions chris :You are bad".to_string(),
                chris_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":adam!~adam@127.0.0.1 KICK #impressions charlie :You are bad".to_string(),
                charlie_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }
}
