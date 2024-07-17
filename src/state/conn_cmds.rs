// conn_cmds.rs - connection commands
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
use std::error::Error;
use std::ops::DerefMut;
use std::sync::atomic::Ordering;

struct SupportTokenIntValue {
    name: &'static str,
    value: usize,
}

static SUPPORT_TOKEN_INT_VALUE: [SupportTokenIntValue; 13] = [
    SupportTokenIntValue {
        name: "AWAYLEN",
        value: 1000,
    },
    SupportTokenIntValue {
        name: "CHANNELLEN",
        value: 1000,
    },
    SupportTokenIntValue {
        name: "HOSTLEN",
        value: 1000,
    },
    SupportTokenIntValue {
        name: "KEYLEN",
        value: 1000,
    },
    SupportTokenIntValue {
        name: "KICKLEN",
        value: 1000,
    },
    SupportTokenIntValue {
        name: "LINELEN",
        value: 2000,
    },
    SupportTokenIntValue {
        name: "MAXNICKLEN",
        value: 200,
    },
    SupportTokenIntValue {
        name: "MAXPARA",
        value: 500,
    },
    SupportTokenIntValue {
        name: "MAXTARGETS",
        value: 500,
    },
    SupportTokenIntValue {
        name: "MODES",
        value: 500,
    },
    SupportTokenIntValue {
        name: "NICKLEN",
        value: 200,
    },
    SupportTokenIntValue {
        name: "TOPICLEN",
        value: 1000,
    },
    SupportTokenIntValue {
        name: "USERLEN",
        value: 200,
    },
];

impl ToString for SupportTokenIntValue {
    fn to_string(&self) -> String {
        let mut s = self.name.to_string();
        s.push('=');
        s.push_str(&self.value.to_string());
        s
    }
}

struct SupportTokenStringValue {
    name: &'static str,
    value: &'static str,
}

static SUPPORT_TOKEN_STRING_VALUE: [SupportTokenStringValue; 9] = [
    SupportTokenStringValue {
        name: "CASEMAPPING",
        value: "ascii",
    },
    SupportTokenStringValue {
        name: "CHANMODES",
        value: "Iabehiklmnopqstv",
    },
    SupportTokenStringValue {
        name: "CHANTYPES",
        value: "&#",
    },
    SupportTokenStringValue {
        name: "EXCEPTS",
        value: "e",
    },
    SupportTokenStringValue {
        name: "INVEX",
        value: "I",
    },
    SupportTokenStringValue {
        name: "MAXLIST",
        value: "beI:1000",
    },
    SupportTokenStringValue {
        name: "PREFIX",
        value: "(qaohv)~&@%+",
    },
    SupportTokenStringValue {
        name: "STATUSMSG",
        value: "~&@%+",
    },
    SupportTokenStringValue {
        name: "USERMODES",
        value: "Oiorw",
    },
];

impl ToString for SupportTokenStringValue {
    fn to_string(&self) -> String {
        let mut s = self.name.to_string();
        s.push('=');
        s.push_str(self.value);
        s
    }
}

static SUPPORT_TOKEN_BOOL_VALUE: [&str; 2] = ["FNC", "SAFELIST"];

impl super::MainState {
    pub(super) async fn process_cap<'a>(
        &self,
        conn_state: &mut ConnState,
        subcommand: CapCommand,
        caps: Option<Vec<&'a str>>,
        _: Option<u32>,
    ) -> Result<(), Box<dyn Error>> {
        match subcommand {
            CapCommand::LS => {
                conn_state.caps_negotation = true;
                self.feed_msg(&mut conn_state.stream, "CAP * LS :multi-prefix")
                    .await
            }
            CapCommand::LIST => {
                self.feed_msg(
                    &mut conn_state.stream,
                    &format!("CAP * LIST :{}", conn_state.caps),
                )
                .await
            }
            CapCommand::REQ => {
                conn_state.caps_negotation = true;
                if let Some(ref cs) = caps {
                    info!("CAPS REQ for {}: {:?}", conn_state.user_state.source, caps);
                    let mut new_caps = conn_state.caps;
                    // accept if all capabilities matches
                    if cs.iter().all(|c| new_caps.apply_cap(c)) {
                        conn_state.caps = new_caps;
                        self.feed_msg(
                            &mut conn_state.stream,
                            format!("CAP * ACK :{}", cs.join(" ")),
                        )
                        .await
                    } else {
                        // NAK
                        self.feed_msg(
                            &mut conn_state.stream,
                            format!("CAP * NAK :{}", cs.join(" ")),
                        )
                        .await
                    }
                } else {
                    Ok(())
                }
            }
            CapCommand::END => {
                conn_state.caps_negotation = false;
                if !conn_state.user_state.authenticated {
                    self.authenticate(conn_state).await?;
                }
                Ok(())
            }
        }?;
        Ok(())
    }

    // send ISupport messages
    pub(super) async fn send_isupport(
        &self,
        conn_state: &mut ConnState,
    ) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();
        // support tokens
        let mut tokens = vec![format!("NETWORK={}", self.config.network)];
        if let Some(max_joins) = self.config.max_joins {
            tokens.push(format!("CHANLIMIT=&#:{}", max_joins));
            tokens.push(format!("MAXCHANNELS={}", max_joins));
        }
        SUPPORT_TOKEN_STRING_VALUE.iter().for_each(|t| {
            tokens.push(t.to_string());
        });
        SUPPORT_TOKEN_INT_VALUE.iter().for_each(|t| {
            tokens.push(t.to_string());
        });
        SUPPORT_TOKEN_BOOL_VALUE.iter().for_each(|t| {
            tokens.push(t.to_string());
        });

        tokens.sort();

        for toks in tokens.chunks(10) {
            self.feed_msg(
                &mut conn_state.stream,
                RplISupport005 {
                    client,
                    tokens: &toks.join(" "),
                },
            )
            .await?;
        }
        Ok(())
    }

    async fn authenticate(&self, conn_state: &mut ConnState) -> Result<(), Box<dyn Error>> {
        // registered - user that defined in configuration
        let (auth_opt, registered) = {
            // finish of authentication requires finish caps negotiation.
            if !conn_state.caps_negotation {
                let user_state = &mut conn_state.user_state;
                // nick must be defined
                if user_state.nick.is_some() {
                    // username must be defined
                    if let Some(ref name) = user_state.name {
                        let mut registered = false;
                        // get password option
                        let password_opt = if let Some(uidx) = self.user_config_idxs.get(name) {
                            // match user mask
                            if let Some(ref users) = self.config.users {
                                if let Some(ref mask) = users[*uidx].mask {
                                    if match_wildcard(mask, &user_state.source) {
                                        registered = true;
                                        users[*uidx].password.as_ref()
                                    } else {
                                        info!(
                                            "Auth failed for {}: user mask doesn't match",
                                            conn_state.user_state.source
                                        );
                                        self.feed_msg(
                                            &mut conn_state.stream,
                                            "ERROR: user mask doesn't match",
                                        )
                                        .await?;
                                        return Ok(());
                                    }
                                } else {
                                    registered = true;
                                    users[*uidx].password.as_ref()
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                        // otherwise get default password from configuration
                        .or(self.config.password.as_ref());

                        if let Some(password) = password_opt {
                            // check password
                            let good = if let Some(ref entered_pwd) = user_state.password {
                                argon2_verify_password_async(entered_pwd.clone(), password.clone())
                                    .await
                                    .is_ok()
                            } else {
                                false
                            };

                            user_state.authenticated = good;
                            (Some(good), registered)
                        } else {
                            user_state.authenticated = true;
                            (Some(true), registered)
                        }
                    } else {
                        (None, false)
                    }
                } else {
                    (None, false)
                }
            } else {
                (None, false)
            }
        };

        if let Some(good) = auth_opt {
            if good {
                let user_nick = conn_state.user_state.nick.clone().unwrap();
                let user_modes = {
                    // add new user to hash map
                    let user_state = &mut conn_state.user_state;
                    user_state.registered = registered;
                    let mut state = self.state.write().await;
                    let user = User::new(
                        &self.config,
                        user_state,
                        conn_state.sender.take().unwrap(),
                        conn_state.quit_sender.take().unwrap(),
                    );
                    let umode_str = user.modes.to_string();
                    if !state.users.contains_key(&user_nick) {
                        state.add_user(&user_nick, user);
                        umode_str
                    } else {
                        // if nick already used
                        let client = conn_state.user_state.client_name();
                        self.feed_msg(
                            &mut conn_state.stream,
                            ErrNicknameInUse433 {
                                client,
                                nick: &user_nick,
                            },
                        )
                        .await?;
                        return Ok(());
                    }
                };

                {
                    // send message to user: welcome,....
                    let user_state = &conn_state.user_state;
                    let client = user_state.client_name();
                    // welcome
                    self.feed_msg(
                        &mut conn_state.stream,
                        RplWelcome001 {
                            client,
                            networkname: &self.config.network,
                            nick: user_state.nick.as_deref().unwrap_or_default(),
                            user: user_state.name.as_deref().unwrap_or_default(),
                            host: &user_state.hostname,
                        },
                    )
                    .await?;
                    self.feed_msg(
                        &mut conn_state.stream,
                        RplYourHost002 {
                            client,
                            servername: &self.config.name,
                            version: concat!(
                                env!("CARGO_PKG_NAME"),
                                "-",
                                env!("CARGO_PKG_VERSION")
                            ),
                        },
                    )
                    .await?;
                    self.feed_msg(
                        &mut conn_state.stream,
                        RplCreated003 {
                            client,
                            datetime: &self.created,
                        },
                    )
                    .await?;
                    self.feed_msg(
                        &mut conn_state.stream,
                        RplMyInfo004 {
                            client,
                            servername: &self.config.name,
                            version: concat!(
                                env!("CARGO_PKG_NAME"),
                                "-",
                                env!("CARGO_PKG_VERSION")
                            ),
                            avail_user_modes: "Oiorw",
                            avail_chmodes: "Iabehiklmnopqstv",
                            avail_chmodes_with_params: None,
                        },
                    )
                    .await?;

                    self.send_isupport(conn_state).await?;
                }

                // send messages from LUSERS and MOTD
                self.process_lusers(conn_state).await?;
                self.process_motd(conn_state, None).await?;

                // send mode reply
                let client = conn_state.user_state.client_name();
                self.feed_msg(
                    &mut conn_state.stream,
                    RplUModeIs221 {
                        client,
                        user_modes: &user_modes,
                    },
                )
                .await?;

                // run ping waker for this connection
                conn_state.run_ping_waker(&self.config);
                info!("Auth succeed for {}", conn_state.user_state.source);
            } else {
                // if authentication failed
                info!("Auth failed for {}", conn_state.user_state.source);
                let client = conn_state.user_state.client_name();
                conn_state.quit.store(1, Ordering::SeqCst);
                self.feed_msg(&mut conn_state.stream, ErrPasswdMismatch464 { client })
                    .await?;
            }
        }
        Ok(())
    }

    pub(super) async fn process_authenticate(
        &self,
        conn_state: &mut ConnState,
    ) -> Result<(), Box<dyn Error>> {
        let client = conn_state.user_state.client_name();

        self.feed_msg(
            &mut conn_state.stream,
            ErrUnknownCommand421 {
                client,
                command: "AUTHENTICATE",
            },
        )
        .await?;
        Ok(())
    }

    pub(super) async fn process_pass<'a>(
        &self,
        conn_state: &mut ConnState,
        pass: &'a str,
    ) -> Result<(), Box<dyn Error>> {
        if !conn_state.user_state.authenticated {
            conn_state.user_state.password = Some(pass.to_string());
            // try authentication
            self.authenticate(conn_state).await?;
        } else {
            let client = conn_state.user_state.client_name();
            self.feed_msg(&mut conn_state.stream, ErrAlreadyRegistered462 { client })
                .await?;
        }
        Ok(())
    }

    pub(super) async fn process_nick<'a>(
        &self,
        conn_state: &mut ConnState,
        nick: &'a str,
        msg: &'a Message<'a>,
    ) -> Result<(), Box<dyn Error>> {
        if !conn_state.user_state.authenticated {
            if !self.state.read().await.users.contains_key(nick) {
                conn_state.user_state.set_nick(nick.to_string());
                // try authentication
                self.authenticate(conn_state).await?;
            } else {
                let client = conn_state.user_state.client_name();
                self.feed_msg(&mut conn_state.stream, ErrNicknameInUse433 { client, nick })
                    .await?;
            }
        } else {
            let mut statem = self.state.write().await;
            let state = statem.deref_mut();
            let old_nick = conn_state.user_state.nick.as_ref().unwrap().to_string();
            if nick != old_nick {
                let nick_str = nick.to_string();
                // if new nick is not used by other
                if !state.users.contains_key(&nick_str) {
                    let old_source = conn_state.user_state.source.clone();
                    let mut user = state.users.remove(&old_nick).unwrap();
                    conn_state.user_state.set_nick(nick_str.clone());
                    user.update_nick(&conn_state.user_state);
                    for ch in &user.channels {
                        state
                            .channels
                            .get_mut(&ch.clone())
                            .unwrap()
                            .rename_user(&old_nick, nick_str.clone());
                    }
                    // add nick history
                    state.insert_to_nick_history(&old_nick, user.history_entry.clone());

                    state.users.insert(nick_str.clone(), user);
                    // wallops users
                    if state.wallops_users.contains(&old_nick) {
                        state.wallops_users.remove(&old_nick);
                        state.wallops_users.insert(nick_str);
                    }

                    for u in state.users.values() {
                        u.send_message(msg, &old_source)?;
                    }
                } else {
                    // if nick in use
                    let client = conn_state.user_state.client_name();
                    self.feed_msg(&mut conn_state.stream, ErrNicknameInUse433 { client, nick })
                        .await?;
                }
            }
        }
        Ok(())
    }

    pub(super) async fn process_user<'a>(
        &self,
        conn_state: &mut ConnState,
        username: &'a str,
        _: &'a str,
        _: &'a str,
        realname: &'a str,
    ) -> Result<(), Box<dyn Error>> {
        if !conn_state.user_state.authenticated {
            conn_state.user_state.set_name(username.to_string());
            conn_state.user_state.realname = Some(realname.to_string());
            // try authentication
            self.authenticate(conn_state).await?;
        } else {
            let client = conn_state.user_state.client_name();
            self.feed_msg(&mut conn_state.stream, ErrAlreadyRegistered462 { client })
                .await?;
        }
        Ok(())
    }

    pub(super) async fn process_ping<'a>(
        &self,
        conn_state: &mut ConnState,
        token: &'a str,
    ) -> Result<(), Box<dyn Error>> {
        self.feed_msg(
            &mut conn_state.stream,
            format!("PONG {} :{}", self.config.name, token),
        )
        .await?;
        Ok(())
    }

    pub(super) async fn process_pong<'a>(
        &self,
        conn_state: &mut ConnState,
        _: &'a str,
    ) -> Result<(), Box<dyn Error>> {
        if let Some(notifier) = conn_state.pong_notifier.take() {
            notifier
                .send(())
                .map_err(|_| "pong notifier error".to_string())?;
        }
        Ok(())
    }

    pub(super) async fn process_oper<'a>(
        &self,
        conn_state: &mut ConnState,
        nick: &'a str,
        password: &'a str,
    ) -> Result<(), Box<dyn Error>> {
        let user_nick = conn_state.user_state.nick.as_ref().unwrap();
        let client = conn_state.user_state.client_name();

        if let Some(oper_idx) = self.oper_config_idxs.get(nick) {
            // if operator defined in configuration
            let mut state = self.state.write().await;
            let user = state.users.get_mut(user_nick).unwrap();
            let op_cfg_opt = self.config.operators.as_ref().unwrap().get(*oper_idx);
            let op_config = op_cfg_opt.as_ref().unwrap();

            // check password
            let do_it =
                if argon2_verify_password_async(password.to_string(), op_config.password.clone())
                    .await
                    .is_err()
                {
                    self.feed_msg(&mut conn_state.stream, ErrPasswdMismatch464 { client })
                        .await?;
                    false
                } else if let Some(ref op_mask) = op_config.mask {
                    if !match_wildcard(op_mask, &conn_state.user_state.source) {
                        self.feed_msg(&mut conn_state.stream, ErrNoOperHost491 { client })
                            .await?;
                        false
                    } else {
                        true
                    }
                } else {
                    true
                };

            if do_it {
                // do it if all is ok.
                user.modes.oper = true;
                state.operators_count += 1;
                info!("New IRC operator {}", conn_state.user_state.source);
                self.feed_msg(&mut conn_state.stream, RplYoureOper381 { client })
                    .await?;
            }
        } else {
            info!(
                "Operator authentication failed for {}",
                conn_state.user_state.source
            );
            self.feed_msg(&mut conn_state.stream, ErrNoOperHost491 { client })
                .await?;
        }
        Ok(())
    }

    pub(super) async fn process_quit(
        &self,
        conn_state: &mut ConnState,
    ) -> Result<(), Box<dyn Error>> {
        conn_state.quit.store(1, Ordering::SeqCst);
        info!("User {} quit", conn_state.user_state.source);
        self.feed_msg(&mut conn_state.stream, "ERROR: Closing connection")
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::super::test::*;
    use super::*;

    use tokio::net::TcpStream;

    #[tokio::test]
    async fn test_auth_with_caps() {
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

            assert_eq!(
                ":irc.irc CAP * LS :multi-prefix".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc CAP * ACK :multi-prefix".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 001 mati :Welcome to the IRCnetwork \
                    Network, mati!~mat@127.0.0.1"
                    .to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                concat!(
                    ":irc.irc 002 mati :Your host is irc.irc, running \
                    version ",
                    env!("CARGO_PKG_NAME"),
                    "-",
                    env!("CARGO_PKG_VERSION")
                )
                .to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                format!(
                    ":irc.irc 003 mati :This server was created {}",
                    main_state.created
                ),
                line_stream.next().await.unwrap().unwrap()
            );

            for _ in 3..18 {
                line_stream.next().await.unwrap().unwrap();
            }

            line_stream.send("CAP LIST".to_string()).await.unwrap();
            assert_eq!(
                ":irc.irc CAP * LIST :multi-prefix".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            line_stream.send("QUIT :Bye".to_string()).await.unwrap();
        }

        {
            let mut line_stream = connect_to_test(port).await;
            line_stream.send("CAP LS 302".to_string()).await.unwrap();
            line_stream
                .send("CAP REQ :multi-prefix".to_string())
                .await
                .unwrap();
            line_stream.send("CAP END".to_string()).await.unwrap();
            line_stream
                .send("USER mat2 8 * :MatiSzpaki2".to_string())
                .await
                .unwrap();
            line_stream.send("NICK mati2".to_string()).await.unwrap();

            assert_eq!(
                ":irc.irc CAP * LS :multi-prefix".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc CAP * ACK :multi-prefix".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 001 mati2 :Welcome to the IRCnetwork \
                    Network, mati2!~mat2@127.0.0.1"
                    .to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            line_stream.send("QUIT :Bye".to_string()).await.unwrap();
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_auth_with_password() {
        let mut config = MainConfig::default();
        config.password = Some(argon2_hash_password("blamblam"));
        let (main_state, handle, port) = run_test_server(config).await;

        for (pass, succeed) in [
            (None, false),
            (Some("blamblam2"), false),
            (Some("blamblam"), true),
        ] {
            let mut line_stream = connect_to_test(port).await;

            if let Some(p) = pass {
                line_stream.send(format!("PASS {}", p)).await.unwrap();
            }
            line_stream.send("NICK mati".to_string()).await.unwrap();
            line_stream
                .send("USER mat 8 * :MatiSzpaki".to_string())
                .await
                .unwrap();

            if succeed {
                assert_eq!(
                    ":irc.irc 001 mati :Welcome to the IRCnetwork \
                        Network, mati!~mat@127.0.0.1"
                        .to_string(),
                    line_stream.next().await.unwrap().unwrap(),
                    "AuthTrial: {:?}",
                    pass
                );
                for _ in 1..17 {
                    line_stream.next().await.unwrap().unwrap();
                }
                assert_eq!(
                    ":irc.irc 221 mati +".to_string(),
                    line_stream.next().await.unwrap().unwrap()
                );
            } else {
                assert_eq!(
                    ":irc.irc 464 mati :Password incorrect".to_string(),
                    line_stream.next().await.unwrap().unwrap(),
                    "AuthTrial: {:?}",
                    pass
                );
            }
            line_stream.send("QUIT :Bye".to_string()).await.unwrap();
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_auth_with_user_configs() {
        let mut config = MainConfig::default();
        config.password = Some(argon2_hash_password("blamblam"));
        config.users = Some(vec![
            UserConfig {
                name: "lucky".to_string(),
                nick: "luckboy".to_string(),
                password: Some(argon2_hash_password("top_secret")),
                mask: None,
            },
            UserConfig {
                name: "mati".to_string(),
                nick: "mat".to_string(),
                password: None,
                mask: None,
            },
            UserConfig {
                name: "mati2".to_string(),
                nick: "mat2".to_string(),
                password: None,
                mask: Some("mat2!~mati2@*".to_string()),
            },
            UserConfig {
                name: "mati3".to_string(),
                nick: "mat3".to_string(),
                password: None,
                mask: Some("mat4!~mati3@*".to_string()),
            }, // fail
        ]);
        let (main_state, handle, port) = run_test_server(config).await;

        for (pass, succeed) in [
            (None, false),
            (Some("blamblam2"), false),
            (Some("blamblam"), false),
            (Some("top_secret"), true),
        ] {
            let mut line_stream = connect_to_test(port).await;

            if let Some(p) = pass {
                line_stream.send(format!("PASS {}", p)).await.unwrap();
            }
            line_stream.send("NICK luckboy".to_string()).await.unwrap();
            line_stream
                .send("USER lucky 8 * :LuckBoy".to_string())
                .await
                .unwrap();

            if succeed {
                assert_eq!(
                    ":irc.irc 001 luckboy :Welcome to the IRCnetwork \
                        Network, luckboy!~lucky@127.0.0.1"
                        .to_string(),
                    line_stream.next().await.unwrap().unwrap(),
                    "AuthTrial: {:?}",
                    pass
                );
                for _ in 1..17 {
                    line_stream.next().await.unwrap().unwrap();
                }
                assert_eq!(
                    ":irc.irc 221 luckboy +r".to_string(),
                    line_stream.next().await.unwrap().unwrap()
                );
            } else {
                assert_eq!(
                    ":irc.irc 464 luckboy :Password incorrect".to_string(),
                    line_stream.next().await.unwrap().unwrap(),
                    "AuthTrial: {:?}",
                    pass
                );
            }
            line_stream.send("QUIT :Bye".to_string()).await.unwrap();
        }

        for (pass, succeed) in [
            (None, false),
            (Some("blamblam2"), false),
            (Some("top_secret"), false),
            (Some("blamblam"), true),
        ] {
            let mut line_stream = connect_to_test(port).await;

            if let Some(p) = pass {
                line_stream.send(format!("PASS {}", p)).await.unwrap();
            }
            line_stream.send("NICK mat".to_string()).await.unwrap();
            line_stream
                .send("USER mati 8 * :MatiX".to_string())
                .await
                .unwrap();

            if succeed {
                assert_eq!(
                    ":irc.irc 001 mat :Welcome to the IRCnetwork \
                        Network, mat!~mati@127.0.0.1"
                        .to_string(),
                    line_stream.next().await.unwrap().unwrap(),
                    "AuthTrial: {:?}",
                    pass
                );
                for _ in 1..17 {
                    line_stream.next().await.unwrap().unwrap();
                }
                assert_eq!(
                    ":irc.irc 221 mat +r".to_string(),
                    line_stream.next().await.unwrap().unwrap()
                );
            } else {
                assert_eq!(
                    ":irc.irc 464 mat :Password incorrect".to_string(),
                    line_stream.next().await.unwrap().unwrap(),
                    "AuthTrial: {:?}",
                    pass
                );
            }
            line_stream.send("QUIT :Bye".to_string()).await.unwrap();
        }

        for (pass, succeed) in [
            (None, false),
            (Some("blamblam2"), false),
            (Some("top_secret"), false),
            (Some("blamblam"), true),
        ] {
            let mut line_stream = connect_to_test(port).await;

            if let Some(p) = pass {
                line_stream.send(format!("PASS {}", p)).await.unwrap();
            }
            line_stream.send("NICK mat2".to_string()).await.unwrap();
            line_stream
                .send("USER mati2 8 * :Mati2".to_string())
                .await
                .unwrap();

            if succeed {
                assert_eq!(
                    ":irc.irc 001 mat2 :Welcome to the IRCnetwork \
                        Network, mat2!~mati2@127.0.0.1"
                        .to_string(),
                    line_stream.next().await.unwrap().unwrap(),
                    "AuthTrial: {:?}",
                    pass
                );
                for _ in 1..17 {
                    line_stream.next().await.unwrap().unwrap();
                }
                assert_eq!(
                    ":irc.irc 221 mat2 +r".to_string(),
                    line_stream.next().await.unwrap().unwrap()
                );
            } else {
                assert_eq!(
                    ":irc.irc 464 mat2 :Password incorrect".to_string(),
                    line_stream.next().await.unwrap().unwrap(),
                    "AuthTrial: {:?}",
                    pass
                );
            }
            line_stream.send("QUIT :Bye".to_string()).await.unwrap();
        }

        for pass in [
            None,
            Some("blamblam2"),
            Some("top_secret"),
            Some("blamblam"),
        ] {
            let mut line_stream = connect_to_test(port).await;

            if let Some(p) = pass {
                line_stream.send(format!("PASS {}", p)).await.unwrap();
            }
            line_stream.send("NICK mat3".to_string()).await.unwrap();
            line_stream
                .send("USER mati3 8 * :Mati3".to_string())
                .await
                .unwrap();

            assert_eq!(
                ":irc.irc ERROR: user mask doesn't match".to_string(),
                line_stream.next().await.unwrap().unwrap(),
                "AuthTrial: {:?}",
                pass
            );
            line_stream.send("QUIT :Bye".to_string()).await.unwrap();
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_auth_with_user_configs_2() {
        let mut config = MainConfig::default();
        config.users = Some(vec![
            UserConfig {
                name: "lucky".to_string(),
                nick: "luckboy".to_string(),
                password: Some(argon2_hash_password("top_secret")),
                mask: None,
            },
            UserConfig {
                name: "mati".to_string(),
                nick: "mat".to_string(),
                password: None,
                mask: None,
            },
            UserConfig {
                name: "mati2".to_string(),
                nick: "mat2".to_string(),
                password: None,
                mask: Some("mat2!~mati2@*".to_string()),
            }, // fail
        ]);
        let (main_state, handle, port) = run_test_server(config).await;

        for (pass, succeed) in [
            (None, false),
            (Some("blamblam2"), false),
            (Some("blamblam"), false),
            (Some("top_secret"), true),
        ] {
            let mut line_stream = connect_to_test(port).await;

            if let Some(p) = pass {
                line_stream.send(format!("PASS {}", p)).await.unwrap();
            }
            line_stream.send("NICK luckboy".to_string()).await.unwrap();
            line_stream
                .send("USER lucky 8 * :LuckBoy".to_string())
                .await
                .unwrap();

            if succeed {
                assert_eq!(
                    ":irc.irc 001 luckboy :Welcome to the IRCnetwork \
                        Network, luckboy!~lucky@127.0.0.1"
                        .to_string(),
                    line_stream.next().await.unwrap().unwrap(),
                    "AuthTrial: {:?}",
                    pass
                );
                for _ in 1..17 {
                    line_stream.next().await.unwrap().unwrap();
                }
                assert_eq!(
                    ":irc.irc 221 luckboy +r".to_string(),
                    line_stream.next().await.unwrap().unwrap()
                );
            } else {
                assert_eq!(
                    ":irc.irc 464 luckboy :Password incorrect".to_string(),
                    line_stream.next().await.unwrap().unwrap(),
                    "AuthTrial: {:?}",
                    pass
                );
            }
            line_stream.send("QUIT :Bye".to_string()).await.unwrap();
        }

        for (pass, succeed) in [
            (None, true),
            (Some("blamblam2"), true),
            (Some("top_secret"), true),
            (Some("blamblam"), true),
        ] {
            let mut line_stream = connect_to_test(port).await;

            if let Some(p) = pass {
                line_stream.send(format!("PASS {}", p)).await.unwrap();
            }
            line_stream.send("NICK mat".to_string()).await.unwrap();
            line_stream
                .send("USER mati 8 * :MatiX".to_string())
                .await
                .unwrap();

            if succeed {
                assert_eq!(
                    ":irc.irc 001 mat :Welcome to the IRCnetwork \
                        Network, mat!~mati@127.0.0.1"
                        .to_string(),
                    line_stream.next().await.unwrap().unwrap(),
                    "AuthTrial: {:?}",
                    pass
                );
                for _ in 1..17 {
                    line_stream.next().await.unwrap().unwrap();
                }
                assert_eq!(
                    ":irc.irc 221 mat +r".to_string(),
                    line_stream.next().await.unwrap().unwrap()
                );
            } else {
                assert_eq!(
                    ":irc.irc 464 mat :Password incorrect".to_string(),
                    line_stream.next().await.unwrap().unwrap(),
                    "AuthTrial: {:?}",
                    pass
                );
            }
            line_stream.send("QUIT :Bye".to_string()).await.unwrap();
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_auth_with_default_user_modes() {
        let mut config = MainConfig::default();
        config.default_user_modes = UserModes {
            registered: true,
            invisible: true,
            local_oper: false,
            oper: false,
            wallops: false,
        };
        let (main_state, handle, port) = run_test_server(config).await;

        {
            let mut line_stream = login_to_test(port, "oliver", "oliverk", "Oliver Kittson").await;

            assert_eq!(
                ":irc.irc 001 oliver :Welcome to the IRCnetwork \
                    Network, oliver!~oliverk@127.0.0.1"
                    .to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            for _ in 1..7 {
                line_stream.next().await.unwrap().unwrap();
            }

            assert_eq!(
                ":irc.irc 251 oliver :There are 0 users and 1 \
                    invisible on 1 servers"
                    .to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 252 oliver 0 :operator(s) online".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 253 oliver 0 :unknown connection(s)".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 254 oliver 0 :channels formed".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 255 oliver :I have 1 clients and 1 servers".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 265 oliver 1 1 :Current local users 1, max 1".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 266 oliver 1 1 :Current global users 1, max 1".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 375 oliver :- irc.irc Message of the day - ".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 372 oliver :Hello, world!".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 376 oliver :End of /MOTD command.".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 221 oliver +ir".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_auth_failed_nick_used() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream = connect_to_test(port).await;
            let mut line_stream2 = connect_to_test(port).await;

            line_stream.send("NICK oliver".to_string()).await.unwrap();
            line_stream
                .send("USER oliverk 8 * :Oliver Kittson".to_string())
                .await
                .unwrap();

            line_stream2.send("NICK oliver".to_string()).await.unwrap();
            line_stream2
                .send("USER oliverk 8 * :Oliver Kittson".to_string())
                .await
                .unwrap();

            assert_eq!(
                ":irc.irc 001 oliver :Welcome to the IRCnetwork \
                    Network, oliver!~oliverk@127.0.0.1"
                    .to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            assert_eq!(
                ":irc.irc 433 127.0.0.1 oliver :Nickname is already in use".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
        }

        {
            let mut line_stream = connect_to_test(port).await;
            let mut line_stream2 = connect_to_test(port).await;

            line_stream.send("NICK aliver".to_string()).await.unwrap();
            line_stream2.send("NICK aliver".to_string()).await.unwrap();
            time::sleep(Duration::from_millis(100)).await;

            line_stream
                .send("USER aliverk 8 * :Oliver Kittson".to_string())
                .await
                .unwrap();
            line_stream2
                .send("USER aliverk 8 * :Oliver Kittson".to_string())
                .await
                .unwrap();

            assert_eq!(
                ":irc.irc 001 aliver :Welcome to the IRCnetwork \
                    Network, aliver!~aliverk@127.0.0.1"
                    .to_string(),
                line_stream.next().await.unwrap().unwrap()
            );

            assert_eq!(
                ":irc.irc 433 aliver aliver :Nickname is already in use".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
        }

        {
            let mut line_stream = connect_to_test(port).await;
            let mut line_stream2 = connect_to_test(port).await;

            line_stream
                .send("USER uliverk 8 * :Oliver Kittson".to_string())
                .await
                .unwrap();
            line_stream2
                .send("USER uliverk 8 * :Oliver Kittson".to_string())
                .await
                .unwrap();

            time::sleep(Duration::from_millis(100)).await;
            line_stream.send("NICK uliver".to_string()).await.unwrap();
            time::sleep(Duration::from_millis(100)).await;
            line_stream2.send("NICK uliver".to_string()).await.unwrap();

            assert_eq!(
                ":irc.irc 001 uliver :Welcome to the IRCnetwork \
                    Network, uliver!~uliverk@127.0.0.1"
                    .to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":irc.irc 433 uliverk uliver :Nickname is already in use".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_auth_after_user_pass_failed() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream =
                login_to_test_and_skip(port, "oliver", "aliverk", "Oliver Kittson").await;

            line_stream
                .send("USER aliverk 8 * :Oliver Kittson".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc 462 oliver :You may not reregister".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
        }

        {
            let mut line_stream =
                login_to_test_and_skip(port, "uliver", "aliverk", "Oliver Kittson").await;

            line_stream.send("PASS xxxx".to_string()).await.unwrap();
            assert_eq!(
                ":irc.irc 462 uliver :You may not reregister".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_nick_rename() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream = login_to_test_and_skip(port, "mati", "mat", "MatSzpak").await;
            let mut line_stream2 = login_to_test_and_skip(port, "lucki", "luck", "LuckBoy").await;
            let mut line_stream3 = login_to_test_and_skip(port, "dam", "dam", "Damon").await;

            line_stream2.send("NICK luke".to_string()).await.unwrap();

            assert_eq!(
                ":lucki!~luck@127.0.0.1 NICK luke".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":lucki!~luck@127.0.0.1 NICK luke".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );
            assert_eq!(
                ":lucki!~luck@127.0.0.1 NICK luke".to_string(),
                line_stream3.next().await.unwrap().unwrap()
            );

            {
                let state = main_state.state.read().await;
                assert!(state.users.contains_key("luke"));
                assert!(!state.users.contains_key("lucki"));
                assert_eq!("luck", state.users.get("luke").unwrap().name);
                assert_eq!("LuckBoy", state.users.get("luke").unwrap().realname);
            }

            // if nothing
            line_stream2.send("NICK luke".to_string()).await.unwrap();
            {
                let state = main_state.state.read().await;
                assert!(state.users.contains_key("luke"));
                assert!(!state.users.contains_key("lucki"));
                assert_eq!("luck", state.users.get("luke").unwrap().name);
                assert_eq!("LuckBoy", state.users.get("luke").unwrap().realname);
            }

            line_stream2.send("NICK dam".to_string()).await.unwrap();
            assert_eq!(
                ":irc.irc 433 luke dam :Nickname is already in use".to_string(),
                line_stream2.next().await.unwrap().unwrap()
            );

            line_stream.send("QUIT :Bye".to_string()).await.unwrap();
            line_stream2.send("QUIT :Bye".to_string()).await.unwrap();
            line_stream3.send("QUIT :Bye".to_string()).await.unwrap();
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_nick_rename_at_channel() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream = login_to_test_and_skip(port, "mati", "mat", "MatSzpak").await;
            line_stream
                .send("JOIN #mychannel".to_string())
                .await
                .unwrap();

            line_stream.send("NICK matszpk".to_string()).await.unwrap();
            time::sleep(Duration::from_millis(50)).await;
            {
                let state = main_state.state.read().await;
                assert_eq!(
                    HashMap::from([(
                        "matszpk".to_string(),
                        ChannelUserModes::new_for_created_channel()
                    )]),
                    state.channels.get("#mychannel").unwrap().users
                );
            }
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_oper() {
        let mut config = MainConfig::default();
        config.operators = Some(vec![
            OperatorConfig {
                name: "guru".to_string(),
                password: argon2_hash_password("NoWay"),
                mask: None,
            },
            OperatorConfig {
                name: "guru2".to_string(),
                password: argon2_hash_password("NoWay2"),
                mask: Some("guruv*@*".to_string()),
            },
            OperatorConfig {
                name: "guru3".to_string(),
                password: argon2_hash_password("NoWay3"),
                mask: Some("guru4*@*".to_string()),
            },
        ]);
        let (main_state, handle, port) = run_test_server(config).await;

        for (opname, pass, res) in [
            ("guru", "NoWay", 2),
            ("guru", "NoWayX", 1),
            ("guru2", "NoWay2", 2),
            ("guru2", "NoWayn", 1),
            ("gurux", "NoWay", 0),
            ("guru3", "NoWay3", 0),
        ] {
            let mut line_stream =
                login_to_test_and_skip(port, "guruv", "guruvx", "SuperGuruV").await;

            line_stream
                .send(format!("OPER {} {}", opname, pass))
                .await
                .unwrap();
            match res {
                2 => {
                    assert_eq!(
                        ":irc.irc 381 guruv :You are now an IRC operator".to_string(),
                        line_stream.next().await.unwrap().unwrap(),
                        "OperTest {} {}",
                        opname,
                        pass
                    );
                    assert!(
                        main_state
                            .state
                            .read()
                            .await
                            .users
                            .get("guruv")
                            .unwrap()
                            .modes
                            .oper,
                        "OperTest {} {}",
                        opname,
                        pass
                    );
                    assert_eq!(1, main_state.state.read().await.operators_count);
                }
                0 => {
                    assert_eq!(
                        ":irc.irc 491 guruv :No O-lines for your host".to_string(),
                        line_stream.next().await.unwrap().unwrap(),
                        "OperTest {} {}",
                        opname,
                        pass
                    );
                    assert!(
                        !main_state
                            .state
                            .read()
                            .await
                            .users
                            .get("guruv")
                            .unwrap()
                            .modes
                            .oper,
                        "OperTest {} {}",
                        opname,
                        pass
                    );
                    assert_eq!(0, main_state.state.read().await.operators_count);
                }
                1 => {
                    assert_eq!(
                        ":irc.irc 464 guruv :Password incorrect".to_string(),
                        line_stream.next().await.unwrap().unwrap(),
                        "OperTest {} {}",
                        opname,
                        pass
                    );
                    assert!(
                        !main_state
                            .state
                            .read()
                            .await
                            .users
                            .get("guruv")
                            .unwrap()
                            .modes
                            .oper,
                        "OperTest {} {}",
                        opname,
                        pass
                    );
                    assert_eq!(0, main_state.state.read().await.operators_count);
                }
                _ => {
                    assert!(false);
                }
            }
            line_stream.send("QUIT :Bye".to_string()).await.unwrap();
            time::sleep(Duration::from_millis(50)).await;
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_quit() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream = login_to_test_and_skip(port, "brian", "brianx", "BrianX").await;

            line_stream.send("QUIT :Bye".to_string()).await.unwrap();
            assert_eq!(
                ":irc.irc ERROR: Closing connection".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
            time::sleep(Duration::from_millis(50)).await;
            assert!(!main_state.state.read().await.users.contains_key("brian"));
        }

        {
            let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let mut line_stream = Framed::new(stream, IRCLinesCodec::new_with_max_length(2000));

            line_stream.send("NICK brian".to_string()).await.unwrap();

            line_stream.send("QUIT :Bye".to_string()).await.unwrap();
            assert_eq!(
                ":irc.irc ERROR: Closing connection".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
        }

        {
            let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let mut line_stream = Framed::new(stream, IRCLinesCodec::new_with_max_length(2000));

            line_stream.send("QUIT :Bye".to_string()).await.unwrap();
            assert_eq!(
                ":irc.irc ERROR: Closing connection".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }

    #[tokio::test]
    async fn test_command_quit_from_channels() {
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

            line_stream.send("QUIT :Bye".to_string()).await.unwrap();
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
    async fn test_command_ping() {
        let (main_state, handle, port) = run_test_server(MainConfig::default()).await;

        {
            let mut line_stream = login_to_test_and_skip(port, "brian", "brianx", "BrianX").await;

            line_stream
                .send("PING aarrgghhh!!!".to_string())
                .await
                .unwrap();
            assert_eq!(
                ":irc.irc PONG irc.irc :aarrgghhh!!!".to_string(),
                line_stream.next().await.unwrap().unwrap()
            );
        }

        quit_test_server(main_state, handle).await;
    }
}
