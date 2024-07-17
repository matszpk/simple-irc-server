// rest_cmds.rs - rest commands
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
use std::collections::HashSet;
use std::error::Error;
use std::iter::FromIterator;
use std::time::{SystemTime, UNIX_EPOCH};

impl super::MainState {
    async fn process_privmsg_notice<'a>(
        &self,
        conn_state: &mut ConnState,
        targets: Vec<&'a str>,
        text: &'a str,
        notice: bool,
    ) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();

        let mut something_done = false;
        {
            let state = self.state.read().await;

            for target in HashSet::<&&str>::from_iter(targets.iter()) {
                let msg_str = if notice {
                    format!("NOTICE {} :{}", target, text)
                } else {
                    format!("PRIVMSG {} :{}", target, text)
                };
                let (target_type, chan_str) = get_privmsg_target_type(target);
                if target_type.contains(PrivMsgTargetType::Channel) {
                    // to channel
                    if let Some(chanobj) = state.channels.get(chan_str) {
                        let chanuser_mode = chanobj.users.get(user_nick);
                        // check whether can send from outside channel
                        let can_send = {
                            if (!chanobj.modes.no_external_messages && !chanobj.modes.secret)
                                || chanuser_mode.is_some()
                            {
                                true
                            } else {
                                if !notice {
                                    self.feed_msg(
                                        &mut conn_state.stream,
                                        ErrCannotSendToChain404 {
                                            client,
                                            channel: chan_str,
                                        },
                                    )
                                    .await?;
                                }
                                false
                            }
                        };
                        // check whether user in channel is banned
                        let can_send = can_send && {
                            if !chanobj.modes.banned(&conn_state.user_state.source) {
                                true
                            } else {
                                if !notice {
                                    self.feed_msg(
                                        &mut conn_state.stream,
                                        ErrCannotSendToChain404 {
                                            client,
                                            channel: chan_str,
                                        },
                                    )
                                    .await?;
                                }
                                false
                            }
                        };
                        // check whether is channel moderated and user have voice permissions
                        let can_send = can_send && {
                            if !chanobj.modes.moderated
                                || chanuser_mode.map_or(false, |chum| chum.is_voice())
                            {
                                true
                            } else {
                                if !notice {
                                    self.feed_msg(
                                        &mut conn_state.stream,
                                        ErrCannotSendToChain404 {
                                            client,
                                            channel: chan_str,
                                        },
                                    )
                                    .await?;
                                }
                                false
                            }
                        };

                        if can_send {
                            use PrivMsgTargetType::*;
                            if !(target_type & ChannelAllSpecial).is_empty() {
                                // send to special users
                                if !(target_type & ChannelFounder).is_empty() {
                                    if let Some(ref founders) = chanobj.modes.founders {
                                        founders.iter().try_for_each(|u| {
                                            if u != user_nick {
                                                state.users.get(u).unwrap().send_msg_display(
                                                    &conn_state.user_state.source,
                                                    &msg_str,
                                                )
                                            } else {
                                                Ok(())
                                            }
                                        })?;
                                    }
                                }
                                if !(target_type & ChannelProtected).is_empty() {
                                    if let Some(ref protecteds) = chanobj.modes.protecteds {
                                        protecteds.iter().try_for_each(|u| {
                                            if u != user_nick {
                                                state.users.get(u).unwrap().send_msg_display(
                                                    &conn_state.user_state.source,
                                                    &msg_str,
                                                )
                                            } else {
                                                Ok(())
                                            }
                                        })?;
                                    }
                                }
                                if !(target_type & ChannelOper).is_empty() {
                                    if let Some(ref operators) = chanobj.modes.operators {
                                        operators.iter().try_for_each(|u| {
                                            if u != user_nick {
                                                state.users.get(u).unwrap().send_msg_display(
                                                    &conn_state.user_state.source,
                                                    &msg_str,
                                                )
                                            } else {
                                                Ok(())
                                            }
                                        })?;
                                    }
                                }
                                if !(target_type & ChannelHalfOper).is_empty() {
                                    if let Some(ref half_ops) = chanobj.modes.half_operators {
                                        half_ops.iter().try_for_each(|u| {
                                            if u != user_nick {
                                                state.users.get(u).unwrap().send_msg_display(
                                                    &conn_state.user_state.source,
                                                    &msg_str,
                                                )
                                            } else {
                                                Ok(())
                                            }
                                        })?;
                                    }
                                }
                                if !(target_type & ChannelVoice).is_empty() {
                                    if let Some(ref voices) = chanobj.modes.voices {
                                        voices.iter().try_for_each(|u| {
                                            if u != user_nick {
                                                state.users.get(u).unwrap().send_msg_display(
                                                    &conn_state.user_state.source,
                                                    &msg_str,
                                                )
                                            } else {
                                                Ok(())
                                            }
                                        })?;
                                    }
                                }
                            } else {
                                // send to all users
                                chanobj.users.keys().try_for_each(|u| {
                                    if u != user_nick {
                                        state.users.get(u).unwrap().send_msg_display(
                                            &conn_state.user_state.source,
                                            &msg_str,
                                        )
                                    } else {
                                        Ok(())
                                    }
                                })?;
                            }
                            something_done = true;
                        }
                    } else if !notice {
                        self.feed_msg(
                            &mut conn_state.stream,
                            ErrNoSuchChannel403 {
                                client,
                                channel: chan_str,
                            },
                        )
                        .await?;
                    }
                } else {
                    // to user
                    if let Some(cur_user) = state.users.get(*target) {
                        cur_user.send_msg_display(&conn_state.user_state.source, msg_str)?;
                        if !notice {
                            // if user away
                            if let Some(ref away) = cur_user.away {
                                self.feed_msg(
                                    &mut conn_state.stream,
                                    RplAway301 {
                                        client,
                                        nick: target,
                                        message: away,
                                    },
                                )
                                .await?;
                            }
                        }
                        something_done = true;
                    } else if !notice {
                        self.feed_msg(
                            &mut conn_state.stream,
                            ErrNoSuchNick401 {
                                client,
                                nick: target,
                            },
                        )
                        .await?;
                    }
                }
            }
        }

        {
            // update last activity if something sent
            if something_done {
                let mut state = self.state.write().await;
                let user = state.users.get_mut(user_nick).unwrap();
                user.last_activity = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
            }
        }
        Ok(())
    }

    pub(super) async fn process_privmsg<'a>(
        &self,
        conn_state: &mut ConnState,
        targets: Vec<&'a str>,
        text: &'a str,
    ) -> Result<(), Box<dyn Error>> {
        self.process_privmsg_notice(conn_state, targets, text, false)
            .await
    }

    pub(super) async fn process_notice<'a>(
        &self,
        conn_state: &mut ConnState,
        targets: Vec<&'a str>,
        text: &'a str,
    ) -> Result<(), Box<dyn Error>> {
        self.process_privmsg_notice(conn_state, targets, text, true)
            .await
    }

    // routine to send who info about user
    pub(super) async fn send_who_info<'a>(
        &self,
        conn_state: &mut ConnState,
        channel: Option<(&'a str, &ChannelUserModes)>,
        user_nick: &'a str,
        user: &User,
        cmd_user: &User,
    ) -> Result<(), Box<dyn Error>> {
        if !user.modes.invisible || !user.channels.is_disjoint(&cmd_user.channels) {
            let client = conn_state.user_state.client_name();
            let mut flags = String::new();
            // if user away
            if user.away.is_some() {
                flags.push('G');
            } else {
                flags.push('H');
            }
            // if user is operator
            if user.modes.is_local_oper() {
                flags.push('*');
            }
            if let Some((_, chum)) = channel {
                flags += &chum.to_string(&conn_state.caps);
            }
            self.feed_msg(
                &mut conn_state.stream,
                RplWhoReply352 {
                    client,
                    channel: channel.map(|(c, _)| c).unwrap_or("*"),
                    username: &user.name,
                    host: &user.hostname,
                    server: &self.config.name,
                    nick: user_nick,
                    flags: &flags,
                    hopcount: 0,
                    realname: &user.realname,
                },
            )
            .await?;
        }
        Ok(())
    }

    pub(super) async fn process_who<'a>(
        &self,
        conn_state: &mut ConnState,
        mask: &'a str,
    ) -> Result<(), Box<dyn Error>> {
        let state = self.state.read().await;
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        let user = state.users.get(user_nick).unwrap();

        if mask.contains('*') || mask.contains('?') {
            // if wilcards
            for (unick, u) in &state.users {
                if match_wildcard(mask, unick)
                    || match_wildcard(mask, &u.source)
                    || match_wildcard(mask, &u.realname)
                {
                    self.send_who_info(conn_state, None, unick, u, user).await?;
                }
            }
        } else if validate_channel(mask).is_ok() {
            // if channel
            if let Some(channel) = state.channels.get(mask) {
                for (u, chum) in &channel.users {
                    self.send_who_info(
                        conn_state,
                        Some((mask, chum)),
                        u,
                        state.users.get(u).unwrap(),
                        user,
                    )
                    .await?;
                }
            }
        } else if validate_username(mask).is_ok() {
            if let Some(arg_user) = state.users.get(mask) {
                self.send_who_info(conn_state, None, mask, arg_user, user)
                    .await?;
            }
        }
        let client = conn_state.user_state.client_name();
        self.feed_msg(&mut conn_state.stream, RplEndOfWho315 { client, mask })
            .await?;
        Ok(())
    }

    pub(super) async fn process_whois<'a>(
        &self,
        conn_state: &mut ConnState,
        target: Option<&'a str>,
        nickmasks: Vec<&'a str>,
    ) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();

        if target.is_some() {
            self.feed_msg(
                &mut conn_state.stream,
                ErrUnknownError400 {
                    client,
                    command: "WHOIS",
                    subcommand: None,
                    info: "Server unsupported",
                },
            )
            .await?;
        } else {
            let state = self.state.read().await;
            let user_nick = conn_state.user_state.nick.as_ref().unwrap();
            let user = state.users.get(user_nick).unwrap();

            let mut nicks = HashSet::<String>::new();
            let mut real_nickmasks = vec![];

            // collect real nickmasks (wildcards) and nicks
            nickmasks.iter().for_each(|nickmask| {
                if nickmask.contains('*') || nickmask.contains('?') {
                    // wildcard
                    real_nickmasks.push(nickmask);
                } else if state.users.contains_key(&nickmask.to_string()) {
                    nicks.insert(nickmask.to_string());
                }
            });

            if !real_nickmasks.is_empty() {
                // if filter users by using real nickmasks and insert to nicks
                state.users.keys().for_each(|nick| {
                    if real_nickmasks.iter().any(|mask| match_wildcard(mask, nick)) {
                        nicks.insert(nick.to_string());
                    }
                });
            }

            for nick in nicks {
                let arg_user = state.users.get(&nick).unwrap();
                if arg_user.modes.invisible && arg_user.channels.is_disjoint(&user.channels) {
                    continue;
                }

                if arg_user.modes.registered {
                    self.feed_msg(
                        &mut conn_state.stream,
                        RplWhoIsRegNick307 {
                            client,
                            nick: &nick,
                        },
                    )
                    .await?;
                }
                self.feed_msg(
                    &mut conn_state.stream,
                    RplWhoIsUser311 {
                        client,
                        nick: &nick,
                        username: &arg_user.name,
                        host: &arg_user.hostname,
                        realname: &arg_user.realname,
                    },
                )
                .await?;
                self.feed_msg(
                    &mut conn_state.stream,
                    RplWhoIsServer312 {
                        client,
                        nick: &nick,
                        server: &self.config.name,
                        server_info: &self.config.info,
                    },
                )
                .await?;
                if arg_user.modes.is_local_oper() {
                    self.feed_msg(
                        &mut conn_state.stream,
                        RplWhoIsOperator313 {
                            client,
                            nick: &nick,
                        },
                    )
                    .await?;
                }
                // channels
                let channel_replies = arg_user
                    .channels
                    .iter()
                    .filter_map(|chname| {
                        let ch = state.channels.get(chname).unwrap();
                        if !ch.modes.secret {
                            // put channel only if not secret
                            Some(WhoIsChannelStruct {
                                prefix: Some(
                                    ch.users.get(&nick).unwrap().to_string(&conn_state.caps),
                                ),
                                channel: chname,
                            })
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();

                // divide channel replies by chunks
                for chr_chunk in channel_replies.chunks(30) {
                    self.feed_msg(
                        &mut conn_state.stream,
                        RplWhoIsChannels319 {
                            client,
                            nick: &nick,
                            channels: chr_chunk,
                        },
                    )
                    .await?;
                }

                self.feed_msg(
                    &mut conn_state.stream,
                    RplwhoIsIdle317 {
                        client,
                        nick: &nick,
                        secs: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                            - arg_user.last_activity,
                        signon: arg_user.signon,
                    },
                )
                .await?;
                if arg_user.modes.is_local_oper() {
                    self.feed_msg(
                        &mut conn_state.stream,
                        RplWhoIsHost378 {
                            client,
                            nick: &nick,
                            host_info: &arg_user.hostname,
                        },
                    )
                    .await?;
                    self.feed_msg(
                        &mut conn_state.stream,
                        RplWhoIsModes379 {
                            client,
                            nick: &nick,
                            modes: &arg_user.modes.to_string(),
                        },
                    )
                    .await?;
                }
                // if you connected through TLS connection, then server is working with TLS.
                // then all users is using secure connection.
                if conn_state.is_secure() {
                    self.feed_msg(
                        &mut conn_state.stream,
                        RplWhoIsSecure671 {
                            client,
                            nick: &nick,
                        },
                    )
                    .await?;
                }
            }
            self.feed_msg(
                &mut conn_state.stream,
                RplEndOfWhoIs318 {
                    client,
                    nick: &nickmasks.join(","),
                },
            )
            .await?;
        }
        Ok(())
    }

    pub(super) async fn process_whowas<'a>(
        &self,
        conn_state: &mut ConnState,
        nickname: &'a str,
        count: Option<usize>,
        server: Option<&'a str>,
    ) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();

        if server.is_some() {
            self.feed_msg(
                &mut conn_state.stream,
                ErrUnknownError400 {
                    client,
                    command: "WHOWAS",
                    subcommand: None,
                    info: "Server unsupported",
                },
            )
            .await?;
        } else {
            let state = self.state.read().await;
            if let Some(hist) = state.nick_histories.get(&nickname.to_string()) {
                // get hist_count - length if zero or not given
                let hist_count = if let Some(c) = count {
                    if c > 0 {
                        c
                    } else {
                        hist.len()
                    }
                } else {
                    hist.len()
                };

                // loop to send whowas replies
                for entry in hist.iter().rev().take(hist_count) {
                    self.feed_msg(
                        &mut conn_state.stream,
                        RplWhoWasUser314 {
                            client,
                            nick: nickname,
                            username: &entry.username,
                            host: &entry.hostname,
                            realname: &entry.realname,
                        },
                    )
                    .await?;
                    self.feed_msg(
                        &mut conn_state.stream,
                        RplWhoIsServer312 {
                            client,
                            nick: nickname,
                            server: &self.config.name,
                            server_info: &format!(
                                "Logged in at {}",
                                DateTime::<Utc>::from_utc(
                                    NaiveDateTime::from_timestamp(entry.signon as i64, 0),
                                    Utc
                                )
                            ),
                        },
                    )
                    .await?;
                }
            } else {
                self.feed_msg(
                    &mut conn_state.stream,
                    ErrWasNoSuchNick406 {
                        client,
                        nick: nickname,
                    },
                )
                .await?;
            }
            self.feed_msg(
                &mut conn_state.stream,
                RplEndOfWhoWas369 {
                    client,
                    nick: nickname,
                },
            )
            .await?;
        }
        Ok(())
    }

    pub(super) async fn process_kill<'a>(
        &self,
        conn_state: &mut ConnState,
        nickname: &'a str,
        comment: &'a str,
    ) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        let mut state = self.state.write().await;
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        let user = state.users.get(user_nick).unwrap();

        if user.modes.oper {
            // only operator can kill user
            if let Some(user_to_kill) = state.users.get_mut(nickname) {
                if let Some(sender) = user_to_kill.quit_sender.take() {
                    sender
                        .send((user_nick.to_string(), comment.to_string()))
                        .map_err(|_| "error".to_string())?;
                }
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
        } else {
            self.feed_msg(&mut conn_state.stream, ErrNoPrivileges481 { client })
                .await?;
        }
        Ok(())
    }

    pub(super) async fn process_rehash(
        &self,
        conn_state: &mut ConnState,
    ) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        self.feed_msg(
            &mut conn_state.stream,
            ErrUnknownError400 {
                client,
                command: "REHASH",
                subcommand: None,
                info: "Server unsupported",
            },
        )
        .await?;
        Ok(())
    }

    pub(super) async fn process_restart(
        &self,
        conn_state: &mut ConnState,
    ) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        self.feed_msg(
            &mut conn_state.stream,
            ErrUnknownError400 {
                client,
                command: "RESTART",
                subcommand: None,
                info: "Server unsupported",
            },
        )
        .await?;
        Ok(())
    }

    pub(super) async fn process_squit<'a>(
        &self,
        conn_state: &mut ConnState,
        server: &'a str,
        comment: &'a str,
    ) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        if self.config.name != server {
            self.feed_msg(
                &mut conn_state.stream,
                ErrUnknownError400 {
                    client,
                    command: "SQUIT",
                    subcommand: None,
                    info: "Server unsupported",
                },
            )
            .await?;
        } else {
            self.process_die(conn_state, Some(comment)).await?;
        }
        Ok(())
    }

    pub(super) async fn process_die<'a>(
        &self,
        conn_state: &mut ConnState,
        message_opt: Option<&'a str>,
    ) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        let mut state = self.state.write().await;
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        let user = state.users.get(user_nick).unwrap();
        let message = message_opt.unwrap_or("Quitting from DIE");

        // only operator can kill server
        if user.modes.oper {
            for u in state.users.values_mut() {
                if let Some(sender) = u.quit_sender.take() {
                    sender
                        .send((user_nick.to_string(), message.to_string()))
                        .map_err(|_| "error".to_string())?;
                }
            }
            if let Some(sender) = state.quit_sender.take() {
                sender.send(message.to_string())?;
            }
        } else {
            self.feed_msg(&mut conn_state.stream, ErrCantKillServer483 { client })
                .await?;
        }
        Ok(())
    }

    pub(super) async fn process_away<'a>(
        &self,
        conn_state: &mut ConnState,
        text: Option<&'a str>,
    ) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        let mut state = self.state.write().await;
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        let user = state.users.get_mut(user_nick).unwrap();
        if let Some(t) = text {
            // set away
            user.away = Some(t.to_string());
            self.feed_msg(&mut conn_state.stream, RplNowAway306 { client })
                .await?;
        } else {
            // unset away
            user.away = None;
            self.feed_msg(&mut conn_state.stream, RplUnAway305 { client })
                .await?;
        }
        Ok(())
    }

    pub(super) async fn process_userhost<'a>(
        &self,
        conn_state: &mut ConnState,
        nicknames: Vec<&'a str>,
    ) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        let state = self.state.read().await;

        for nicks in nicknames.chunks(20) {
            let replies = nicks
                .iter()
                .filter_map(|nick| state.users.get(&nick.to_string()).map(|user| (nick, user)))
                .map(|(nick, user)| {
                    let asterisk = if user.modes.is_local_oper() { "*" } else { "" };
                    let away = if user.away.is_some() { '-' } else { '+' };
                    format!(
                        "{}{}={}~{}@{}",
                        nick, asterisk, away, user.name, user.hostname
                    )
                })
                .collect::<Vec<_>>();
            self.feed_msg(
                &mut conn_state.stream,
                RplUserHost302 {
                    client,
                    replies: &replies,
                },
            )
            .await?;
        }
        Ok(())
    }

    pub(super) async fn process_wallops<'a>(
        &self,
        conn_state: &mut ConnState,
        msg: &'a Message<'a>,
    ) -> Result<(), Box<dyn Error>> {
        let state = self.state.read().await;
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        let user = state.users.get(user_nick).unwrap();

        // only local operator or higher can send message to wallops
        if user.modes.is_local_oper() {
            state.wallops_users.iter().try_for_each(|wu| {
                state
                    .users
                    .get(wu)
                    .unwrap()
                    .send_message(msg, &conn_state.user_state.source)
            })?;
        } else {
            let client = conn_state.user_state.client_name();
            self.feed_msg(&mut conn_state.stream, ErrNoPrivileges481 { client })
                .await?;
        }
        Ok(())
    }

    pub(super) async fn process_ison<'a>(
        &self,
        conn_state: &mut ConnState,
        nicknames: Vec<&'a str>,
    ) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        let state = self.state.read().await;
        for nicks in nicknames.chunks(20) {
            let outs = nicks
                .iter()
                .filter(|nick| state.users.contains_key(&nick.to_string()))
                .copied()
                .collect::<Vec<_>>();
            self.feed_msg(
                &mut conn_state.stream,
                RplIson303 {
                    client,
                    nicknames: &outs,
                },
            )
            .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::super::test::*;
    use super::*;

    #[tokio::test]
    async fn test_command_privmsg_user() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "alan", "alan", "Alan Bodarski").await;
            let mut line_stream2 =
                login_to_test_and_skip(port, "bowie", "bowie", "Bowie Catcher").await;

            line_stream
                .send("PRIVMSG bowie :Hello guy!".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":alan!~alan@127.0.0.1 PRIVMSG bowie :Hello guy!".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
            line_stream2
                .send("PRIVMSG alan :Hello too!".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":bowie!~bowie@127.0.0.1 PRIVMSG alan :Hello too!".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            line_stream
                .send("PRIVMSG boxie :Hello guy!".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 401 alan boxie :No such nick/channel".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            // away
            time::sleep(Duration::from_millis(50)).await;
            {
                let mut state = main_state.state.write().await;
                state.users.get_mut("bowie").unwrap().away = Some("Bye".to_string());
            }

            line_stream
                .send("PRIVMSG bowie :Hello guy too!".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 301 alan bowie :Bye".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":alan!~alan@127.0.0.1 PRIVMSG bowie :Hello guy too!".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_privmsg_channel() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "alan", "alan", "Alan Bodarski").await;
            let mut line_stream2 =
                login_to_test_and_skip(port, "bowie", "bowie", "Bowie Catcher").await;
            let mut line_stream3 =
                login_to_test_and_skip(port, "cedric", "cedric", "Cedric Maximus").await;

            for line_stream in [&mut line_stream, &mut line_stream2, &mut line_stream3] {
                line_stream
                    .send("JOIN #channelx".to_string())
                    .await
                    .unwrap();
                for _ in 0..3 {
                    line_stream.next().await.unwrap().unwrap();
                }
            }

            for _ in 0..2 {
                line_stream.next().await.unwrap().unwrap();
            }
            line_stream2.next().await.unwrap().unwrap();

            line_stream
                .send("PRIVMSG #channelx :Hello guy!".to_string())
                .await
                .unwrap();
            for line_stream in [&mut line_stream2, &mut line_stream3] {
                assert_eq!(
                    ":alan!~alan@127.0.0.1 PRIVMSG #channelx :Hello guy!".to_string(),
                    line_stream.next().await.unwrap().unwrap()
                );
            }
            line_stream3
                .send("PRIVMSG #channelx :Hi!".to_string())
                .await
                .unwrap();
            for line_stream in [&mut line_stream, &mut line_stream2] {
                assert_eq!(
                    ":cedric!~cedric@127.0.0.1 PRIVMSG #channelx :Hi!".to_string(),
                    line_stream.next().await.unwrap().unwrap()
                );
            }
            line_stream
                .send("PRIVMSG #channely :Hello guy!".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 403 alan #channely :No such channel".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_privmsg_channel_external_messages() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "alan", "alan", "Alan Bodarski").await;
            let mut line_stream2 =
                login_to_test_and_skip(port, "bowie", "bowie", "Bowie Catcher").await;

            line_stream
                .send("JOIN #channelx".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                line_stream.next().await.unwrap().unwrap();
            }

            // send message to channel
            line_stream2
                .send("PRIVMSG #channelx :I want to join!".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":bowie!~bowie@127.0.0.1 PRIVMSG #channelx :I want to join!".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            time::sleep(Duration::from_millis(50)).await;
            {
                main_state
                    .state
                    .write()
                    .await
                    .channels
                    .get_mut("#channelx")
                    .unwrap()
                    .modes
                    .no_external_messages = true;
            }

            line_stream2
                .send("PRIVMSG #channelx :I want to join!".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 404 bowie #channelx :Cannot send to channel".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_privmsg_channel_moderated() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "alan", "alan", "Alan Bodarski").await;
            let mut line_stream2 =
                login_to_test_and_skip(port, "bowie", "bowie", "Bowie Catcher").await;
            let mut line_stream3 =
                login_to_test_and_skip(port, "cedric", "cedric", "Cedric Maximus").await;

            line_stream
                .send("JOIN #channelx".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                line_stream.next().await.unwrap().unwrap();
            }
            line_stream2
                .send("JOIN #channelx".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                line_stream2.next().await.unwrap().unwrap();
            }
            line_stream.next().await.unwrap().unwrap();

            time::sleep(Duration::from_millis(50)).await;
            {
                main_state
                    .state
                    .write()
                    .await
                    .channels
                    .get_mut("#channelx")
                    .unwrap()
                    .modes
                    .moderated = true;
            }

            // send message to channel
            line_stream
                .send("PRIVMSG #channelx :I want you!".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":alan!~alan@127.0.0.1 PRIVMSG #channelx :I want you!".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );

            line_stream2
                .send("PRIVMSG #channelx :I want you!".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 404 bowie #channelx :Cannot send to channel".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );

            line_stream3
                .send("PRIVMSG #channelx :I want you too!".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 404 cedric #channelx :Cannot send to channel".to_string(),
                line_stream3.next().await.unwrap().unwrap()
            );

            time::sleep(Duration::from_millis(50)).await;
            {
                main_state
                    .state
                    .write()
                    .await
                    .channels
                    .get_mut("#channelx")
                    .unwrap()
                    .add_voice("bowie");
            }
            // if have voice
            line_stream2
                .send("PRIVMSG #channelx :I want you too!".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":bowie!~bowie@127.0.0.1 PRIVMSG #channelx :I want you too!".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_privmsg_channel_banned() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "alan", "alan", "Alan Bodarski").await;
            let mut line_stream2 =
                login_to_test_and_skip(port, "bowie", "bowie", "Bowie Catcher").await;

            line_stream
                .send("JOIN #channelx".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                line_stream.next().await.unwrap().unwrap();
            }
            line_stream2
                .send("JOIN #channelx".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                line_stream2.next().await.unwrap().unwrap();
            }

            line_stream
                .send("MODE #channelx +b bowie".to_string())
                .await
                .unwrap();
            time::sleep(Duration::from_millis(50)).await;
            line_stream.next().await.unwrap().unwrap();
            line_stream2.next().await.unwrap().unwrap();

            line_stream2
                .send("PRIVMSG #channelx :I want you!".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 404 bowie #channelx :Cannot send to channel".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );

            line_stream
                .send("MODE #channelx +e bowie".to_string())
                .await
                .unwrap();
            time::sleep(Duration::from_millis(50)).await;
            line_stream.next().await.unwrap().unwrap();
            line_stream.next().await.unwrap().unwrap();
            line_stream2.next().await.unwrap().unwrap();

            line_stream2
                .send("PRIVMSG #channelx :I want you!".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":bowie!~bowie@127.0.0.1 PRIVMSG #channelx :I want you!".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_privmsg_channel_prefixed() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "alan", "alan", "Alan Bodarski").await;

            let mut founder_stream1 =
                login_to_test_and_skip(port, "founder1", "founder1", "Founder1").await;
            let mut founder_stream2 =
                login_to_test_and_skip(port, "founder2", "founder2", "Founder2").await;
            let mut protected_stream1 =
                login_to_test_and_skip(port, "protected1", "protected1", "Protected1").await;
            let mut protected_stream2 =
                login_to_test_and_skip(port, "protected2", "protected2", "Protected2").await;
            let mut operator_stream1 =
                login_to_test_and_skip(port, "operator1", "operator1", "Operator1").await;
            let mut operator_stream2 =
                login_to_test_and_skip(port, "operator2", "operator2", "Operator2").await;
            let mut halfoper_stream1 =
                login_to_test_and_skip(port, "halfoper1", "halfoper1", "HalfOper1").await;
            let mut halfoper_stream2 =
                login_to_test_and_skip(port, "halfoper2", "halfoper2", "HalfOper2").await;
            let mut voice_stream1 =
                login_to_test_and_skip(port, "voice1", "voice1", "Voice1").await;
            let mut voice_stream2 =
                login_to_test_and_skip(port, "voice2", "voice2", "Voice2").await;

            for line_stream in [
                &mut line_stream,
                &mut founder_stream1,
                &mut founder_stream2,
                &mut protected_stream1,
                &mut protected_stream2,
                &mut operator_stream1,
                &mut operator_stream2,
                &mut halfoper_stream1,
                &mut halfoper_stream2,
                &mut voice_stream1,
                &mut voice_stream2,
            ] {
                line_stream
                    .send("JOIN #channely".to_string())
                    .await
                    .unwrap();
                for _ in 0..3 {
                    line_stream.next().await.unwrap().unwrap();
                }
            }
            // skip joins
            for (n, line_stream) in [
                &mut line_stream,
                &mut founder_stream1,
                &mut founder_stream2,
                &mut protected_stream1,
                &mut protected_stream2,
                &mut operator_stream1,
                &mut operator_stream2,
                &mut halfoper_stream1,
                &mut halfoper_stream2,
                &mut voice_stream1,
                &mut voice_stream2,
            ]
            .iter_mut()
            .enumerate()
            {
                for _ in 0..(10 - n) {
                    line_stream.next().await.unwrap().unwrap();
                }
            }

            line_stream
                .send(
                    "MODE #channely +q founder1 +q founder2 \
                        +a protected1 +a protected2 +o operator1 +o operator2 \
                        +h halfoper1 +h halfoper2 +v voice1 +v voice2"
                        .to_string(),
                )
                .await
                .unwrap();

            // skip joins
            for line_stream in [
                &mut line_stream,
                &mut founder_stream1,
                &mut founder_stream2,
                &mut protected_stream1,
                &mut protected_stream2,
                &mut operator_stream1,
                &mut operator_stream2,
                &mut halfoper_stream1,
                &mut halfoper_stream2,
                &mut voice_stream1,
                &mut voice_stream2,
            ] {
                line_stream.next().await.unwrap().unwrap();
            }

            for (ch, send_stream, send_nick, recv_stream, recv_nick) in [
                (
                    '~',
                    &mut founder_stream1,
                    "founder1",
                    &mut founder_stream2,
                    "founder2",
                ),
                (
                    '&',
                    &mut protected_stream1,
                    "protected1",
                    &mut protected_stream2,
                    "protected2",
                ),
                (
                    '@',
                    &mut operator_stream1,
                    "operator1",
                    &mut operator_stream2,
                    "operator2",
                ),
                (
                    '%',
                    &mut halfoper_stream1,
                    "halfoper1",
                    &mut halfoper_stream2,
                    "halfoper2",
                ),
                (
                    '+',
                    &mut voice_stream1,
                    "voice1",
                    &mut voice_stream2,
                    "voice2",
                ),
            ] {
                send_stream
                    .send(format!("PRIVMSG {}#channely :Hello guys", ch))
                    .await
                    .unwrap();
                assert_eq!(
                    format!(
                        ":{0}!~{0}@127.0.0.1 PRIVMSG {1}#channely :Hello guys",
                        send_nick, ch
                    ),
                    recv_stream.next().await.unwrap().unwrap()
                );
                recv_stream
                    .send(format!("PRIVMSG {}#channely :Hello guys", ch))
                    .await
                    .unwrap();
                assert_eq!(
                    format!(
                        ":{0}!~{0}@127.0.0.1 PRIVMSG {1}#channely :Hello guys",
                        recv_nick, ch
                    ),
                    send_stream.next().await.unwrap().unwrap()
                );
            }
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_privmsg_multiple() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "alan", "alan", "Alan Bodarski").await;
            let mut line_stream2 =
                login_to_test_and_skip(port, "bowie", "bowie", "Bowie Catcher").await;
            let mut line_stream3 =
                login_to_test_and_skip(port, "cedric", "cedric", "Cedric Maximus").await;

            line_stream
                .send("JOIN #channelx".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                line_stream.next().await.unwrap().unwrap();
            }
            line_stream2
                .send("JOIN #channelx".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                line_stream2.next().await.unwrap().unwrap();
            }

            line_stream.next().await.unwrap().unwrap();

            line_stream
                .send("PRIVMSG #channelx,cedric :Hello boys".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":alan!~alan@127.0.0.1 PRIVMSG #channelx :Hello boys".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":alan!~alan@127.0.0.1 PRIVMSG cedric :Hello boys".to_string(),
                line_stream3.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_privmsg_activity() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "alan", "alan", "Alan Bodarski").await;
            let mut line_stream2 =
                login_to_test_and_skip(port, "bowie", "bowie", "Bowie Catcher").await;

            time::sleep(Duration::from_millis(50)).await;
            let activity = {
                let mut state = main_state.state.write().await;
                state.users.get_mut("alan").unwrap().last_activity -= 10;
                state.users.get("alan").unwrap().last_activity
            };
            line_stream
                .send("PRIVMSG guru :Hello boys".to_string())
                .await
                .unwrap();
            time::sleep(Duration::from_millis(50)).await;
            assert_eq!(
                ":irc.irc 401 alan guru :No such nick/channel".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            {
                let state = main_state.state.read().await;
                assert_eq!(activity, state.users.get("alan").unwrap().last_activity);
            }

            line_stream
                .send("PRIVMSG bowie :Hello boys".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":alan!~alan@127.0.0.1 PRIVMSG bowie :Hello boys".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                assert_ne!(activity, state.users.get("alan").unwrap().last_activity);
            }
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_notice() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "alan", "alan", "Alan Bodarski").await;
            let mut line_stream2 =
                login_to_test_and_skip(port, "bowie", "bowie", "Bowie Catcher").await;
            let mut cedric_stream =
                login_to_test_and_skip(port, "cedric", "cedric", "Cedric Maximus").await;

            time::sleep(Duration::from_millis(50)).await;
            {
                let mut state = main_state.state.write().await;
                state.users.get_mut("cedric").unwrap().away = Some("Bye".to_string());
            }

            line_stream
                .send("NOTICE #chan1,guru,cedric :Hello boys".to_string())
                .await
                .unwrap();
            line_stream2
                .send("PRIVMSG alan :Hello boys".to_string())
                .await
                .unwrap();
            // no other error replies (NOTICE - doesn't send error messages)
            // directly this message
            assert_eq!(
                ":bowie!~bowie@127.0.0.1 PRIVMSG alan :Hello boys".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            cedric_stream.send("QUIT :Bye".to_string()).await.unwrap();
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_who() {
        let mut config = MainConfig::default();
        config.operators = Some(vec![OperatorConfig {
            name: "fanny".to_string(),
            password: argon2_hash_password("Funny"),
            mask: None,
        }]);
        let (main_state, handle, port) = run_test_server(config).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "fanny", "fanny", "Fanny BumBumBum").await;
            line_stream
                .send("OPER fanny Funny".to_string())
                .await
                .unwrap();
            line_stream.next().await.unwrap().unwrap();

            let mut line_stream2 =
                login_to_test_and_skip(port, "jerry", "jerry", "Jerry Lazy").await;
            line_stream.send("WHO jerry".to_string()).await.unwrap();
            assert_eq!(
                ":irc.irc 352 fanny * ~jerry 127.0.0.1 irc.irc jerry H :0 \
                    Jerry Lazy"
                    .to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 315 fanny jerry :End of WHO list".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            time::sleep(Duration::from_millis(50)).await;
            {
                let mut state = main_state.state.write().await;
                state.users.get_mut("jerry").unwrap().away = Some("Bye".to_string());
            }

            line_stream.send("WHO jerry".to_string()).await.unwrap();
            assert_eq!(
                ":irc.irc 352 fanny * ~jerry 127.0.0.1 irc.irc jerry G :0 \
                    Jerry Lazy"
                    .to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 315 fanny jerry :End of WHO list".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            line_stream2.send("WHO fanny".to_string()).await.unwrap();
            assert_eq!(
                ":irc.irc 352 jerry * ~fanny 127.0.0.1 irc.irc fanny H* :0 \
                    Fanny BumBumBum"
                    .to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 315 jerry fanny :End of WHO list".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    fn equal_list<'a>(msg_start: &'a str, expected: &'a [&'a str], results: &'a [&'a str]) -> bool {
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
    async fn test_command_who_channel() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "fanny", "fanny", "Fanny BumBumBum").await;
            let mut line_stream2 =
                login_to_test_and_skip(port, "jerry", "jerry", "Jerry Lazy").await;

            for line_stream in [&mut line_stream, &mut line_stream2] {
                line_stream
                    .send("JOIN #channelz".to_string())
                    .await
                    .unwrap();
                for _ in 0..3 {
                    line_stream.next().await.unwrap().unwrap();
                }
            }
            line_stream.next().await.unwrap().unwrap();

            line_stream.send("WHO #channelz".to_string()).await.unwrap();
            assert!(equal_list(
                ":irc.irc 352 fanny #channelz ",
                &[
                    "~fanny 127.0.0.1 irc.irc fanny H~ :0 Fanny BumBumBum",
                    "~jerry 127.0.0.1 irc.irc jerry H :0 Jerry Lazy"
                ],
                &[
                    &line_stream.next().await.unwrap().unwrap(),
                    &line_stream.next().await.unwrap().unwrap()
                ]
            ));
            assert_eq!(
                ":irc.irc 315 fanny #channelz :End of WHO list".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_who_channel_multi_prefix() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream = connect_to_test(port).await;
            line_stream.send("CAP LS 302".to_string()).await.unwrap();
            line_stream.send("NICK fanny".to_string()).await.unwrap();
            line_stream
                .send("USER fanny 8 * :Fanny BumBumBum".to_string())
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

            let mut line_stream2 =
                login_to_test_and_skip(port, "jerry", "jerry", "Jerry Lazy").await;

            for line_stream in [&mut line_stream, &mut line_stream2] {
                line_stream
                    .send("JOIN #channelz".to_string())
                    .await
                    .unwrap();
                for _ in 0..3 {
                    line_stream.next().await.unwrap().unwrap();
                }
            }
            line_stream.next().await.unwrap().unwrap();

            line_stream.send("WHO #channelz".to_string()).await.unwrap();
            assert!(equal_list(
                ":irc.irc 352 fanny #channelz ",
                &[
                    "~fanny 127.0.0.1 irc.irc fanny H~@ :0 Fanny BumBumBum",
                    "~jerry 127.0.0.1 irc.irc jerry H :0 Jerry Lazy"
                ],
                &[
                    &line_stream.next().await.unwrap().unwrap(),
                    &line_stream.next().await.unwrap().unwrap()
                ]
            ));
            assert_eq!(
                ":irc.irc 315 fanny #channelz :End of WHO list".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_who_wildcards() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "fanny", "fanny", "Fanny BumBumBum").await;
            let mut stream1 = login_to_test_and_skip(port, "jerry", "jerry", "Jerry Lazy").await;
            let mut stream2 = login_to_test_and_skip(port, "jarry", "jarry", "Jarry Lazy").await;
            let mut stream3 = login_to_test_and_skip(port, "harry", "harry", "Harry Lazy").await;

            line_stream.send("WHO j*rry".to_string()).await.unwrap();
            assert!(equal_list(
                ":irc.irc 352 fanny * ",
                &[
                    "~jerry 127.0.0.1 irc.irc jerry H :0 Jerry Lazy",
                    "~jarry 127.0.0.1 irc.irc jarry H :0 Jarry Lazy"
                ],
                &[
                    &line_stream.next().await.unwrap().unwrap(),
                    &line_stream.next().await.unwrap().unwrap()
                ]
            ));
            assert_eq!(
                ":irc.irc 315 fanny j*rry :End of WHO list".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            line_stream.send("WHO *rry".to_string()).await.unwrap();
            assert!(equal_list(
                ":irc.irc 352 fanny * ",
                &[
                    "~jerry 127.0.0.1 irc.irc jerry H :0 Jerry Lazy",
                    "~jarry 127.0.0.1 irc.irc jarry H :0 Jarry Lazy",
                    "~harry 127.0.0.1 irc.irc harry H :0 Harry Lazy"
                ],
                &[
                    &line_stream.next().await.unwrap().unwrap(),
                    &line_stream.next().await.unwrap().unwrap(),
                    &line_stream.next().await.unwrap().unwrap()
                ]
            ));
            assert_eq!(
                ":irc.irc 315 fanny *rry :End of WHO list".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            for stream in [&mut stream1, &mut stream2, &mut stream3] {
                stream.send("QUIT :Bye".to_string()).await.unwrap();
            }
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_who_invisible() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "fanny", "fanny", "Fanny BumBumBum").await;

            let mut jerry_stream =
                login_to_test_and_skip(port, "jerry", "jerry", "Jerry Lazy").await;
            let mut jarry_stream =
                login_to_test_and_skip(port, "jarry", "jarry", "Jarry Lazy").await;
            let mut harry_stream =
                login_to_test_and_skip(port, "harry", "harry", "Harry Lazy").await;

            time::sleep(Duration::from_millis(50)).await;
            jarry_stream
                .send("MODE jarry +i".to_string())
                .await
                .unwrap();
            time::sleep(Duration::from_millis(50)).await;

            line_stream.send("WHO *rry".to_string()).await.unwrap();
            assert!(equal_list(
                ":irc.irc 352 fanny * ",
                &[
                    "~jerry 127.0.0.1 irc.irc jerry H :0 Jerry Lazy",
                    "~harry 127.0.0.1 irc.irc harry H :0 Harry Lazy"
                ],
                &[
                    &line_stream.next().await.unwrap().unwrap(),
                    &line_stream.next().await.unwrap().unwrap()
                ]
            ));
            assert_eq!(
                ":irc.irc 315 fanny *rry :End of WHO list".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            for stream in [&mut jerry_stream, &mut jarry_stream, &mut harry_stream] {
                stream.send("QUIT :Bye".to_string()).await.unwrap();
            }
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_who_invisible_channel() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "fanny", "fanny", "Fanny BumBumBum").await;

            let mut jerry_stream =
                login_to_test_and_skip(port, "jerry", "jerry", "Jerry Lazy").await;
            let mut jarry_stream =
                login_to_test_and_skip(port, "jarry", "jarry", "Jarry Lazy").await;
            let mut harry_stream =
                login_to_test_and_skip(port, "harry", "harry", "Harry Lazy").await;

            line_stream
                .send("JOIN #mychannel".to_string())
                .await
                .unwrap();

            time::sleep(Duration::from_millis(50)).await;
            jarry_stream
                .send("JOIN #superchannel".to_string())
                .await
                .unwrap();
            jarry_stream
                .send("MODE jarry +i".to_string())
                .await
                .unwrap();
            harry_stream
                .send("JOIN #mychannel".to_string())
                .await
                .unwrap();
            harry_stream
                .send("MODE harry +i".to_string())
                .await
                .unwrap();
            time::sleep(Duration::from_millis(50)).await;

            for _ in 0..(3 + 1) {
                line_stream.next().await.unwrap().unwrap();
            }

            line_stream.send("WHO *rry".to_string()).await.unwrap();
            assert!(equal_list(
                ":irc.irc 352 fanny * ",
                &[
                    "~jerry 127.0.0.1 irc.irc jerry H :0 Jerry Lazy",
                    "~harry 127.0.0.1 irc.irc harry H :0 Harry Lazy"
                ],
                &[
                    &line_stream.next().await.unwrap().unwrap(),
                    &line_stream.next().await.unwrap().unwrap()
                ]
            ));
            assert_eq!(
                ":irc.irc 315 fanny *rry :End of WHO list".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            jerry_stream.send("QUIT :Bye".to_string()).await.unwrap();
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_whois() {
        let mut config = MainConfig::default();
        config.operators = Some(vec![OperatorConfig {
            name: "fanny".to_string(),
            password: argon2_hash_password("Funny"),
            mask: None,
        }]);
        let (main_state, handle, port) = run_test_server(config).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "fanny", "fanny", "Fanny BumBumBum").await;
            line_stream
                .send("OPER fanny Funny".to_string())
                .await
                .unwrap();
            line_stream.next().await.unwrap().unwrap();
            let mut harry_stream =
                login_to_test_and_skip(port, "harry", "harry", "Harry Lazy").await;

            time::sleep(Duration::from_millis(50)).await;
            let signon = {
                main_state
                    .state
                    .read()
                    .await
                    .users
                    .get("harry")
                    .unwrap()
                    .signon
            };

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            line_stream.send("WHOIS harry".to_string()).await.unwrap();
            for expected in [
                ":irc.irc 311 fanny harry ~harry 127.0.0.1 * :Harry Lazy",
                ":irc.irc 312 fanny harry irc.irc :This is IRC server",
                &format!(
                    ":irc.irc 317 fanny harry {} {} :seconds idle, signon time",
                    now - signon,
                    signon
                ),
                ":irc.irc 318 fanny harry :End of /WHOIS list",
            ] {
                assert_eq!(expected, line_stream.next().await.unwrap().unwrap());
            }

            let signon = {
                main_state
                    .state
                    .read()
                    .await
                    .users
                    .get("fanny")
                    .unwrap()
                    .signon
            };
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            harry_stream.send("WHOIS fanny".to_string()).await.unwrap();
            for expected in [
                ":irc.irc 311 harry fanny ~fanny 127.0.0.1 * :Fanny BumBumBum",
                ":irc.irc 312 harry fanny irc.irc :This is IRC server",
                ":irc.irc 313 harry fanny :is an IRC operator",
                &format!(
                    ":irc.irc 317 harry fanny {} {} :seconds idle, signon time",
                    now - signon,
                    signon
                ),
                ":irc.irc 378 harry fanny :is connecting from 127.0.0.1",
                ":irc.irc 379 harry fanny :is using modes +o",
                ":irc.irc 318 harry fanny :End of /WHOIS list",
            ] {
                assert_eq!(expected, harry_stream.next().await.unwrap().unwrap());
            }
        }

        quit_test_server(main_state, handle).await;
    }

    #[cfg(any(feature = "tls_rustls", feature = "tls_openssl"))]
    #[tokio::test]
    async fn test_command_whois_tls() {
        let (main_state, handle, port) = run_test_tls_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_tls_and_skip(port, "fanny", "fanny", "Fanny BumBumBum").await;
            let mut harry_stream =
                login_to_test_tls_and_skip(port, "harry", "harry", "Harry Lazy").await;

            time::sleep(Duration::from_millis(50)).await;
            let signon = {
                main_state
                    .state
                    .read()
                    .await
                    .users
                    .get("harry")
                    .unwrap()
                    .signon
            };

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            line_stream.send("WHOIS harry".to_string()).await.unwrap();
            for expected in [
                ":irc.irc 311 fanny harry ~harry 127.0.0.1 * :Harry Lazy",
                ":irc.irc 312 fanny harry irc.irc :This is IRC server",
                &format!(
                    ":irc.irc 317 fanny harry {} {} :seconds idle, signon time",
                    now - signon,
                    signon
                ),
                ":irc.irc 671 fanny harry :is using a secure connection",
                ":irc.irc 318 fanny harry :End of /WHOIS list",
            ] {
                assert_eq!(expected, line_stream.next().await.unwrap().unwrap());
            }
            harry_stream.send("QUIT :Bye".to_string()).await.unwrap();
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_whois_wilcards() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "fanny", "fanny", "Fanny BumBumBum").await;
            let mut stream1 = login_to_test_and_skip(port, "henry", "henry", "Henry Solo").await;
            let mut stream2 = login_to_test_and_skip(port, "harry", "harry", "Harry Lazy").await;
            let mut stream3 = login_to_test_and_skip(port, "dizzy", "dizzy", "Dizzy Multi").await;

            time::sleep(Duration::from_millis(50)).await;
            let (signon, signon2) = {
                let state = main_state.state.read().await;
                (
                    state.users.get("harry").unwrap().signon,
                    state.users.get("henry").unwrap().signon,
                )
            };

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            line_stream.send("WHOIS *ry".to_string()).await.unwrap();
            let mut expecteds = [
                ":irc.irc 311 fanny harry ~harry 127.0.0.1 * :Harry Lazy",
                ":irc.irc 312 fanny harry irc.irc :This is IRC server",
                &format!(
                    ":irc.irc 317 fanny harry {} {} :seconds idle, signon time",
                    now - signon,
                    signon
                ),
                ":irc.irc 311 fanny henry ~henry 127.0.0.1 * :Henry Solo",
                ":irc.irc 312 fanny henry irc.irc :This is IRC server",
                &format!(
                    ":irc.irc 317 fanny henry {} {} :seconds idle, signon time",
                    now - signon2,
                    signon2
                ),
            ]
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>();
            expecteds.sort();
            let mut results = vec![];
            for _ in 0..6 {
                results.push(line_stream.next().await.unwrap().unwrap());
            }
            results.sort();
            assert_eq!(expecteds, results);
            assert_eq!(
                ":irc.irc 318 fanny *ry :End of /WHOIS list".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            for stream in [&mut stream1, &mut stream2, &mut stream3] {
                stream.send("QUIT :Bye".to_string()).await.unwrap();
            }
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_whois_invisible_channel() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "fanny", "fanny", "Fanny BumBumBum").await;

            let mut jerry_stream =
                login_to_test_and_skip(port, "jerry", "jerry", "Jerry Lazy").await;
            let mut jarry_stream =
                login_to_test_and_skip(port, "jarry", "jarry", "Jarry Lazy").await;
            let mut harry_stream =
                login_to_test_and_skip(port, "harry", "harry", "Harry Lazy").await;

            line_stream
                .send("JOIN #mychannel".to_string())
                .await
                .unwrap();

            time::sleep(Duration::from_millis(50)).await;
            jarry_stream
                .send("JOIN #superchannel".to_string())
                .await
                .unwrap();
            jarry_stream
                .send("MODE jarry +i".to_string())
                .await
                .unwrap();
            harry_stream
                .send("JOIN #mychannel".to_string())
                .await
                .unwrap();
            harry_stream
                .send("MODE harry +i".to_string())
                .await
                .unwrap();
            time::sleep(Duration::from_millis(50)).await;

            for _ in 0..(3 + 1) {
                line_stream.next().await.unwrap().unwrap();
            }

            time::sleep(Duration::from_millis(50)).await;
            let (signon, signon2) = {
                let state = main_state.state.read().await;
                (
                    state.users.get("harry").unwrap().signon,
                    state.users.get("jerry").unwrap().signon,
                )
            };

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            line_stream.send("WHOIS *rry".to_string()).await.unwrap();
            let mut expecteds = [
                ":irc.irc 311 fanny harry ~harry 127.0.0.1 * :Harry Lazy",
                ":irc.irc 312 fanny harry irc.irc :This is IRC server",
                ":irc.irc 319 fanny harry :#mychannel",
                &format!(
                    ":irc.irc 317 fanny harry {} {} :seconds idle, signon time",
                    now - signon,
                    signon
                ),
                ":irc.irc 311 fanny jerry ~jerry 127.0.0.1 * :Jerry Lazy",
                ":irc.irc 312 fanny jerry irc.irc :This is IRC server",
                &format!(
                    ":irc.irc 317 fanny jerry {} {} :seconds idle, signon time",
                    now - signon2,
                    signon2
                ),
            ]
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>();
            expecteds.sort();
            let mut results = vec![];
            for _ in 0..7 {
                results.push(line_stream.next().await.unwrap().unwrap());
            }
            results.sort();
            assert_eq!(expecteds, results);
            assert_eq!(
                ":irc.irc 318 fanny *rry :End of /WHOIS list".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            jerry_stream.send("QUIT :Bye".to_string()).await.unwrap();
        }

        quit_test_server(main_state, handle).await;
    }

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
    async fn test_command_whois_channels() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "fanny", "fanny", "Fanny BumBumBum").await;
            let mut harry_stream =
                login_to_test_and_skip(port, "harry", "harry", "Harry Lazy").await;
            for i in 0..45 {
                harry_stream
                    .send(format!("JOIN #channel{}", i))
                    .await
                    .unwrap();
                for _ in 0..3 {
                    harry_stream.next().await.unwrap().unwrap();
                }
            }

            time::sleep(Duration::from_millis(50)).await;
            let signon = {
                main_state
                    .state
                    .read()
                    .await
                    .users
                    .get("harry")
                    .unwrap()
                    .signon
            };

            line_stream.send("WHOIS harry".to_string()).await.unwrap();
            assert_eq!(
                ":irc.irc 311 fanny harry ~harry 127.0.0.1 * :Harry Lazy".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 312 fanny harry irc.irc :This is IRC server".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            let channel_list = (0..45)
                .map(|x| format!("~#channel{}", x))
                .collect::<Vec<_>>();
            let channel_str_list = channel_list.iter().map(|x| x.as_str()).collect::<Vec<_>>();
            assert!(equal_channel_names(
                ":irc.irc 319 fanny harry :",
                channel_str_list.as_slice(),
                &[
                    &line_stream.next().await.unwrap().unwrap(),
                    &line_stream.next().await.unwrap().unwrap()
                ]
            ));
            assert_eq!(
                format!(
                    ":irc.irc 317 fanny harry {} {} :seconds idle, signon time",
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        - signon,
                    signon
                ),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 318 fanny harry :End of /WHOIS list".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_whois_channel_multi_prefix() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream = connect_to_test(port).await;
            line_stream.send("CAP LS 302".to_string()).await.unwrap();
            line_stream.send("NICK fanny".to_string()).await.unwrap();
            line_stream
                .send("USER fanny 8 * :Fanny BumBumBum".to_string())
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
            let mut harry_stream =
                login_to_test_and_skip(port, "harry", "harry", "Harry Lazy").await;

            harry_stream
                .send("JOIN #channel2".to_string())
                .await
                .unwrap();
            for _ in 0..3 {
                harry_stream.next().await.unwrap().unwrap();
            }

            time::sleep(Duration::from_millis(50)).await;
            let signon = {
                main_state
                    .state
                    .read()
                    .await
                    .users
                    .get("harry")
                    .unwrap()
                    .signon
            };

            line_stream.send("WHOIS harry".to_string()).await.unwrap();
            assert_eq!(
                ":irc.irc 311 fanny harry ~harry 127.0.0.1 * :Harry Lazy".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 312 fanny harry irc.irc :This is IRC server".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 319 fanny harry :~@#channel2".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                format!(
                    ":irc.irc 317 fanny harry {} {} :seconds idle, signon time",
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        - signon,
                    signon
                ),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 318 fanny harry :End of /WHOIS list".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_whois_multiple() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "fanny", "fanny", "Fanny BumBumBum").await;
            let mut henry_stream =
                login_to_test_and_skip(port, "henry", "henry", "Henry Solo").await;
            let mut harry_stream =
                login_to_test_and_skip(port, "harry", "harry", "Harry Lazy").await;
            let mut dizzy_stream =
                login_to_test_and_skip(port, "dizzy", "dizzy", "Dizzy Multi").await;

            time::sleep(Duration::from_millis(50)).await;
            let (signon, signon2, signon3) = {
                let state = main_state.state.read().await;
                (
                    state.users.get("harry").unwrap().signon,
                    state.users.get("henry").unwrap().signon,
                    state.users.get("dizzy").unwrap().signon,
                )
            };

            line_stream
                .send("WHOIS *ry,dizzy".to_string())
                .await
                .unwrap();
            let mut expecteds = [
                ":irc.irc 311 fanny harry ~harry 127.0.0.1 * :Harry Lazy",
                ":irc.irc 312 fanny harry irc.irc :This is IRC server",
                &format!(
                    ":irc.irc 317 fanny harry {} {} :seconds idle, signon time",
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        - signon,
                    signon
                ),
                ":irc.irc 311 fanny henry ~henry 127.0.0.1 * :Henry Solo",
                ":irc.irc 312 fanny henry irc.irc :This is IRC server",
                &format!(
                    ":irc.irc 317 fanny henry {} {} :seconds idle, signon time",
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        - signon2,
                    signon2
                ),
                ":irc.irc 311 fanny dizzy ~dizzy 127.0.0.1 * :Dizzy Multi",
                ":irc.irc 312 fanny dizzy irc.irc :This is IRC server",
                &format!(
                    ":irc.irc 317 fanny dizzy {} {} :seconds idle, signon time",
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        - signon3,
                    signon3
                ),
            ]
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>();
            expecteds.sort();
            let mut results = vec![];
            for _ in 0..9 {
                results.push(line_stream.next().await.unwrap().unwrap());
            }
            results.sort();
            assert_eq!(expecteds, results);
            assert_eq!(
                ":irc.irc 318 fanny *ry,dizzy :End of /WHOIS list".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            for stream in [&mut henry_stream, &mut harry_stream, &mut dizzy_stream] {
                stream.send("QUIT :Bye".to_string()).await.unwrap();
            }
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_whowas() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "fanny", "fanny", "Fanny BumBumBum").await;
            let mut dizzy_stream =
                login_to_test_and_skip(port, "dizzy", "dizzy", "Dizzy Multi").await;
            dizzy_stream.send("QUIT :Bye".to_string()).await.unwrap();
            time::sleep(Duration::from_millis(50)).await;
            let mut dizzy_stream =
                login_to_test_and_skip(port, "dizzy", "dizzy", "Dizzy MultiX").await;
            dizzy_stream.send("QUIT :Bye".to_string()).await.unwrap();
            time::sleep(Duration::from_millis(50)).await;

            let (signon1, signon2) = {
                let state = main_state.state.read().await;
                let history = state.nick_histories.get("dizzy").unwrap();
                (history[1].signon, history[0].signon)
            };

            line_stream.send("WHOWAS dizzy".to_string()).await.unwrap();
            for expected in [
                ":irc.irc 314 fanny dizzy ~dizzy 127.0.0.1 * :Dizzy MultiX",
                &format!(
                    ":irc.irc 312 fanny dizzy irc.irc :Logged in at {}",
                    DateTime::<Utc>::from_utc(
                        NaiveDateTime::from_timestamp(signon1 as i64, 0),
                        Utc
                    )
                ),
                ":irc.irc 314 fanny dizzy ~dizzy 127.0.0.1 * :Dizzy Multi",
                &format!(
                    ":irc.irc 312 fanny dizzy irc.irc :Logged in at {}",
                    DateTime::<Utc>::from_utc(
                        NaiveDateTime::from_timestamp(signon2 as i64, 0),
                        Utc
                    )
                ),
            ] {
                assert_eq!(
                    expected.to_string(),
                    line_stream.next().await.unwrap().unwrap()
                );
            }
            assert_eq!(
                ":irc.irc 369 fanny dizzy :End of WHOWAS".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            line_stream
                .send("WHOWAS dizzy 1".to_string())
                .await
                .unwrap();
            for expected in [
                ":irc.irc 314 fanny dizzy ~dizzy 127.0.0.1 * :Dizzy MultiX",
                &format!(
                    ":irc.irc 312 fanny dizzy irc.irc :Logged in at {}",
                    DateTime::<Utc>::from_utc(
                        NaiveDateTime::from_timestamp(signon1 as i64, 0),
                        Utc
                    )
                ),
            ] {
                assert_eq!(
                    expected.to_string(),
                    line_stream.next().await.unwrap().unwrap()
                );
            }
            assert_eq!(
                ":irc.irc 369 fanny dizzy :End of WHOWAS".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            let mut dizzy_stream =
                login_to_test_and_skip(port, "dizzy", "dizzy", "Dizzy MultiZ").await;
            dizzy_stream.send("NICK gizzy".to_string()).await.unwrap();
            dizzy_stream.next().await.unwrap().unwrap();
            line_stream.next().await.unwrap().unwrap();
            time::sleep(Duration::from_millis(50)).await;
            let signon0 = {
                let state = main_state.state.read().await;
                let history = state.nick_histories.get("dizzy").unwrap();
                history[2].signon
            };

            line_stream.send("WHOWAS dizzy".to_string()).await.unwrap();
            for expected in [
                ":irc.irc 314 fanny dizzy ~dizzy 127.0.0.1 * :Dizzy MultiZ",
                &format!(
                    ":irc.irc 312 fanny dizzy irc.irc :Logged in at {}",
                    DateTime::<Utc>::from_utc(
                        NaiveDateTime::from_timestamp(signon0 as i64, 0),
                        Utc
                    )
                ),
                ":irc.irc 314 fanny dizzy ~dizzy 127.0.0.1 * :Dizzy MultiX",
                &format!(
                    ":irc.irc 312 fanny dizzy irc.irc :Logged in at {}",
                    DateTime::<Utc>::from_utc(
                        NaiveDateTime::from_timestamp(signon1 as i64, 0),
                        Utc
                    )
                ),
                ":irc.irc 314 fanny dizzy ~dizzy 127.0.0.1 * :Dizzy Multi",
                &format!(
                    ":irc.irc 312 fanny dizzy irc.irc :Logged in at {}",
                    DateTime::<Utc>::from_utc(
                        NaiveDateTime::from_timestamp(signon2 as i64, 0),
                        Utc
                    )
                ),
            ] {
                assert_eq!(
                    expected.to_string(),
                    line_stream.next().await.unwrap().unwrap()
                );
            }
            assert_eq!(
                ":irc.irc 369 fanny dizzy :End of WHOWAS".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            line_stream.send("WHOWAS zizzy".to_string()).await.unwrap();
            assert_eq!(
                ":irc.irc 406 fanny zizzy :There was no such nickname".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 369 fanny zizzy :End of WHOWAS".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_kill() {
        let mut config = MainConfig::default();
        config.operators = Some(vec![OperatorConfig {
            name: "fanny".to_string(),
            password: argon2_hash_password("Funny"),
            mask: None,
        }]);
        let (main_state, handle, port) = run_test_server(config).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "fanny", "fanny", "Fanny BumBumBum").await;
            line_stream
                .send("OPER fanny Funny".to_string())
                .await
                .unwrap();
            line_stream.next().await.unwrap().unwrap();
            let mut dizzy_stream =
                login_to_test_and_skip(port, "dizzy", "dizzy", "Dizzy Multi").await;

            line_stream
                .send("KILL dizzy :Not polite".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc ERROR :User killed by fanny: Not polite".to_string(),
                dizzy_stream.next().await.unwrap().unwrap()
            );
            time::sleep(Duration::from_millis(50)).await;
            assert!(!main_state.state.read().await.users.contains_key("dizzy"));
            line_stream
                .send("KILL dizzy :Not polite".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 401 fanny dizzy :No such nick/channel".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_kill_no_privileges() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "fanny", "fanny", "Fanny BumBumBum").await;
            line_stream
                .send("OPER fanny Funny".to_string())
                .await
                .unwrap();
            line_stream.next().await.unwrap().unwrap();
            login_to_test_and_skip(port, "dizzy", "dizzy", "Dizzy Multi").await;

            line_stream
                .send("KILL dizzy :Not polite".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 481 fanny :Permission Denied- You're not an IRC \
                        operator"
                    .to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            time::sleep(Duration::from_millis(50)).await;
            assert!(!main_state.state.read().await.users.contains_key("dizzy"));
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_squit() {
        let mut config = MainConfig::default();
        config.operators = Some(vec![OperatorConfig {
            name: "fanny".to_string(),
            password: argon2_hash_password("Funny"),
            mask: None,
        }]);
        let (_, _, port) = run_test_server(config).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "fanny", "fanny", "Fanny BumBumBum").await;
            line_stream
                .send("OPER fanny Funny".to_string())
                .await
                .unwrap();
            line_stream.next().await.unwrap().unwrap();
            line_stream
                .send("SQUIT irc.irc :Blabla".to_string())
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn test_command_die() {
        let mut config = MainConfig::default();
        config.operators = Some(vec![OperatorConfig {
            name: "fanny".to_string(),
            password: argon2_hash_password("Funny"),
            mask: None,
        }]);
        let (_, _, port) = run_test_server(config).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "fanny", "fanny", "Fanny BumBumBum").await;
            line_stream
                .send("OPER fanny Funny".to_string())
                .await
                .unwrap();
            line_stream.next().await.unwrap().unwrap();
            line_stream.send("DIE :Blabla".to_string()).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_command_die_no_message() {
        let mut config = MainConfig::default();
        config.operators = Some(vec![OperatorConfig {
            name: "fanny".to_string(),
            password: argon2_hash_password("Funny"),
            mask: None,
        }]);
        let (_, _, port) = run_test_server(config).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "fanny", "fanny", "Fanny BumBumBum").await;
            line_stream
                .send("OPER fanny Funny".to_string())
                .await
                .unwrap();
            line_stream.next().await.unwrap().unwrap();
            line_stream.send("DIE".to_string()).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_command_squit_no_privileges() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "fanny", "fanny", "Fanny BumBumBum").await;
            line_stream
                .send("SQUIT irc.irc :Blabla".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 483 fanny :You cant kill a server!".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_away() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "fanny", "fanny", "Fanny BumBumBum").await;
            line_stream
                .send("AWAY :See later".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 306 fanny :You have been marked as being away".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            time::sleep(Duration::from_millis(50)).await;
            assert_eq!(
                Some("See later".to_string()),
                main_state
                    .state
                    .read()
                    .await
                    .users
                    .get("fanny")
                    .unwrap()
                    .away
            );

            line_stream.send("AWAY".to_string()).await.unwrap();
            assert_eq!(
                ":irc.irc 305 fanny :You are no longer marked as being away".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            time::sleep(Duration::from_millis(50)).await;
            assert!(main_state
                .state
                .read()
                .await
                .users
                .get("fanny")
                .unwrap()
                .away
                .is_none());
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_userhost() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "funny", "funny", "Bunny BumBumBum").await;
            let mut xstreams = vec![];
            for i in 0..50 {
                xstreams.push(
                    login_to_test_and_skip(
                        port,
                        &format!("binny{}", i),
                        &format!("binny{}", i),
                        &format!("Binny{} BigBang", i),
                    )
                    .await,
                );
            }

            line_stream
                .send(format!(
                    "USERHOST {}",
                    (0..50)
                        .map(|x| format!("binny{}", x))
                        .collect::<Vec<_>>()
                        .join(" ")
                ))
                .await
                .unwrap();
            for range in [(0..20), (20..40), (40..50)] {
                assert_eq!(
                    ":irc.irc 302 funny :".to_string()
                        + &(range
                            .map(|x| format!("binny{0}=+~binny{0}@127.0.0.1", x))
                            .collect::<Vec<_>>()
                            .join(" ")),
                    line_stream.next().await.unwrap().unwrap()
                );
            }
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_userhost_away() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "funny", "funny", "Bunny BumBumBum").await;

            line_stream.send("AWAY :blablam".to_string()).await.unwrap();
            line_stream.next().await.unwrap().unwrap();

            line_stream
                .send("USERHOST funny".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 302 funny :funny=-~funny@127.0.0.1".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_userhost_oper() {
        let mut config = MainConfig::default();
        config.operators = Some(vec![OperatorConfig {
            name: "fanny".to_string(),
            password: argon2_hash_password("Funny"),
            mask: None,
        }]);
        let (main_state, handle, port) = run_test_server(config).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "funny", "funny", "Funny BumBumBum").await;
            line_stream
                .send("OPER fanny Funny".to_string())
                .await
                .unwrap();
            line_stream.next().await.unwrap().unwrap();

            line_stream
                .send("USERHOST funny".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 302 funny :funny*=+~funny@127.0.0.1".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_userhost_notfound() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "funny", "funny", "Bunny BumBumBum").await;

            line_stream
                .send("USERHOST ziggy".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 302 funny :".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_ison() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "funny", "funny", "Bunny BumBumBum").await;
            let mut xstreams = vec![];
            for i in 0..50 {
                xstreams.push(
                    login_to_test_and_skip(
                        port,
                        &format!("binny{}", i),
                        &format!("binny{}", i),
                        &format!("Binny{} BigBang", i),
                    )
                    .await,
                );
            }

            line_stream
                .send(format!(
                    "ISON {}",
                    (0..50)
                        .map(|x| format!("binny{}", x))
                        .collect::<Vec<_>>()
                        .join(" ")
                ))
                .await
                .unwrap();
            for range in [(0..20), (20..40), (40..50)] {
                assert_eq!(
                    ":irc.irc 303 funny :".to_string()
                        + &(range
                            .map(|x| format!("binny{0}", x))
                            .collect::<Vec<_>>()
                            .join(" ")),
                    line_stream.next().await.unwrap().unwrap()
                );
            }
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_ison_notfound() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "funny", "funny", "Bunny BumBumBum").await;

            line_stream.send("ISON ziggy".to_string()).await.unwrap();
            assert_eq!(
                ":irc.irc 303 funny :".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_wallops() {
        let mut config = MainConfig::default();
        config.operators = Some(vec![OperatorConfig {
            name: "fanny".to_string(),
            password: argon2_hash_password("Funny"),
            mask: None,
        }]);
        let (main_state, handle, port) = run_test_server(config).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "funny", "funny", "Bunny BumBumBum").await;
            line_stream
                .send("OPER fanny Funny".to_string())
                .await
                .unwrap();
            line_stream.next().await.unwrap().unwrap();
            let mut hanna_stream =
                login_to_test_and_skip(port, "hanna", "hanna", "Hanna-Barbera").await;
            let mut gena_stream =
                login_to_test_and_skip(port, "gena", "gena", "Gena Sphinxs").await;
            let mut keith_stream =
                login_to_test_and_skip(port, "keith", "keith", "Keith North").await;

            line_stream.send("MODE funny +w".to_string()).await.unwrap();
            line_stream.next().await.unwrap().unwrap();
            hanna_stream
                .send("MODE hanna +w".to_string())
                .await
                .unwrap();
            hanna_stream.next().await.unwrap().unwrap();
            gena_stream.send("MODE gena +w".to_string()).await.unwrap();
            gena_stream.next().await.unwrap().unwrap();

            line_stream
                .send("WALLOPS :Hello people".to_string())
                .await
                .unwrap();
            for line_stream in [&mut line_stream, &mut hanna_stream, &mut gena_stream] {
                assert_eq!(
                    ":funny!~funny@127.0.0.1 WALLOPS :Hello people".to_string(),
                    line_stream.next().await.unwrap().unwrap()
                );
            }
            hanna_stream
                .send("WALLOPS :Hello people".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 481 hanna :Permission Denied- You're not an IRC \
                    operator"
                    .to_string(),
                hanna_stream.next().await.unwrap().unwrap()
            );
            keith_stream
                .send("WALLOPS :Hello people".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 481 keith :Permission Denied- You're not an IRC \
                    operator"
                    .to_string(),
                keith_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }
}
