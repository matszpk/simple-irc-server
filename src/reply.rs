// reply.rs - replies
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

// replies

use std::fmt;

#[derive(Clone)]
pub(crate) struct WhoIsChannelStruct<'a> {
    pub(crate) prefix: Option<String>,
    pub(crate) channel: &'a str,
}

#[derive(Clone)]
pub(crate) struct NameReplyStruct<'a> {
    pub(crate) prefix: String,
    pub(crate) nick: &'a str,
}

// all replies used by this IRC server.
pub(crate) enum Reply<'a> {
    RplWelcome001 {
        client: &'a str,
        networkname: &'a str,
        nick: &'a str,
        user: &'a str,
        host: &'a str,
    },
    RplYourHost002 {
        client: &'a str,
        servername: &'a str,
        version: &'a str,
    },
    RplCreated003 {
        client: &'a str,
        datetime: &'a str,
    },
    RplMyInfo004 {
        client: &'a str,
        servername: &'a str,
        version: &'a str,
        avail_user_modes: &'a str,
        avail_chmodes: &'a str,
        avail_chmodes_with_params: Option<&'a str>,
    },
    RplISupport005 {
        client: &'a str,
        tokens: &'a str,
    },
    RplStatsCommands212 {
        client: &'a str,
        command: &'a str,
        count: u64,
    },
    RplEndOfStats219 {
        client: &'a str,
        stat: char,
    },
    RplUModeIs221 {
        client: &'a str,
        user_modes: &'a str,
    },
    RplStatsUptime242 {
        client: &'a str,
        seconds: u64,
    },
    RplLUserClient251 {
        client: &'a str,
        users_num: usize,
        inv_users_num: usize,
        servers_num: usize,
    },
    RplLUserOp252 {
        client: &'a str,
        ops_num: usize,
    },
    RplLUserUnknown253 {
        client: &'a str,
        conns_num: usize,
    },
    RplLUserChannels254 {
        client: &'a str,
        channels_num: usize,
    },
    RplLUserMe255 {
        client: &'a str,
        clients_num: usize,
        servers_num: usize,
    },
    RplAdminMe256 {
        client: &'a str,
        server: &'a str,
    },
    RplAdminLoc1257 {
        client: &'a str,
        info: &'a str,
    },
    RplAdminLoc2258 {
        client: &'a str,
        info: &'a str,
    },
    RplAdminEmail259 {
        client: &'a str,
        email: &'a str,
    },
    RplLocalUsers265 {
        client: &'a str,
        clients_num: usize,
        max_clients_num: usize,
    },
    RplGlobalUsers266 {
        client: &'a str,
        clients_num: usize,
        max_clients_num: usize,
    },
    //RplWhoIsCertFP276{ client: &'a str, nick: &'a str, fingerprint: &'a str },
    RplAway301 {
        client: &'a str,
        nick: &'a str,
        message: &'a str,
    },
    RplUserHost302 {
        client: &'a str,
        replies: &'a [String],
    },
    RplIson303 {
        client: &'a str,
        nicknames: &'a [&'a str],
    },
    RplUnAway305 {
        client: &'a str,
    },
    RplNowAway306 {
        client: &'a str,
    },
    RplWhoReply352 {
        client: &'a str,
        channel: &'a str,
        username: &'a str,
        host: &'a str,
        server: &'a str,
        nick: &'a str,
        flags: &'a str,
        hopcount: usize,
        realname: &'a str,
    },
    RplEndOfWho315 {
        client: &'a str,
        mask: &'a str,
    },
    RplWhoIsRegNick307 {
        client: &'a str,
        nick: &'a str,
    },
    RplWhoIsUser311 {
        client: &'a str,
        nick: &'a str,
        username: &'a str,
        host: &'a str,
        realname: &'a str,
    },
    RplWhoIsServer312 {
        client: &'a str,
        nick: &'a str,
        server: &'a str,
        server_info: &'a str,
    },
    RplWhoIsOperator313 {
        client: &'a str,
        nick: &'a str,
    },
    RplWhoWasUser314 {
        client: &'a str,
        nick: &'a str,
        username: &'a str,
        host: &'a str,
        realname: &'a str,
    },
    RplwhoIsIdle317 {
        client: &'a str,
        nick: &'a str,
        secs: u64,
        signon: u64,
    },
    RplEndOfWhoIs318 {
        client: &'a str,
        nick: &'a str,
    },
    RplWhoIsChannels319 {
        client: &'a str,
        nick: &'a str,
        channels: &'a [WhoIsChannelStruct<'a>],
    },
    RplListStart321 {
        client: &'a str,
    },
    RplList322 {
        client: &'a str,
        channel: &'a str,
        client_count: usize,
        topic: &'a str,
    },
    RplListEnd323 {
        client: &'a str,
    },
    RplChannelModeIs324 {
        client: &'a str,
        channel: &'a str,
        modestring: &'a str,
    },
    RplCreationTime329 {
        client: &'a str,
        channel: &'a str,
        creation_time: u64,
    },
    RplNoTopic331 {
        client: &'a str,
        channel: &'a str,
    },
    RplTopic332 {
        client: &'a str,
        channel: &'a str,
        topic: &'a str,
    },
    RplTopicWhoTime333 {
        client: &'a str,
        channel: &'a str,
        nick: &'a str,
        setat: u64,
    },
    RplInviting341 {
        client: &'a str,
        nick: &'a str,
        channel: &'a str,
    },
    RplInviteList346 {
        client: &'a str,
        channel: &'a str,
        mask: &'a str,
    },
    RplEndOfInviteList347 {
        client: &'a str,
        channel: &'a str,
    },
    RplExceptList348 {
        client: &'a str,
        channel: &'a str,
        mask: &'a str,
    },
    RplEndOfExceptList349 {
        client: &'a str,
        channel: &'a str,
    },
    RplVersion351 {
        client: &'a str,
        version: &'a str,
        server: &'a str,
        comments: &'a str,
    },
    RplNameReply353 {
        client: &'a str,
        symbol: &'a str,
        channel: &'a str,
        replies: &'a [NameReplyStruct<'a>],
    },
    RplEndOfNames366 {
        client: &'a str,
        channel: &'a str,
    },
    RplLinks364 {
        client: &'a str,
        mask: &'a str,
        server: &'a str,
        hop_count: u64,
        server_info: &'a str,
    },
    RplEndOfLinks365 {
        client: &'a str,
        mask: &'a str,
    },
    RplBanList367 {
        client: &'a str,
        channel: &'a str,
        mask: &'a str,
        who: &'a str,
        set_ts: u64,
    },
    RplEndOfBanList368 {
        client: &'a str,
        channel: &'a str,
    },
    RplEndOfWhoWas369 {
        client: &'a str,
        nick: &'a str,
    },
    RplInfo371 {
        client: &'a str,
        info: &'a str,
    },
    RplEndOfInfo374 {
        client: &'a str,
    },
    RplMotdStart375 {
        client: &'a str,
        server: &'a str,
    },
    RplMotd372 {
        client: &'a str,
        motd: &'a str,
    },
    RplEndOfMotd376 {
        client: &'a str,
    },
    RplWhoIsHost378 {
        client: &'a str,
        nick: &'a str,
        host_info: &'a str,
    },
    RplWhoIsModes379 {
        client: &'a str,
        nick: &'a str,
        modes: &'a str,
    },
    RplYoureOper381 {
        client: &'a str,
    },
    //RplRehashing382{ client: &'a str, config_file: &'a str },
    RplTime391 {
        client: &'a str,
        server: &'a str,
        timestamp: u64,
        ts_offset: &'a str,
        human_readable: &'a str,
    },
    ErrUnknownError400 {
        client: &'a str,
        command: &'a str,
        subcommand: Option<&'a str>,
        info: &'a str,
    },
    ErrNoSuchNick401 {
        client: &'a str,
        nick: &'a str,
    },
    //ErrNoSuchServer402{ client: &'a str, server: &'a str },
    ErrNoSuchChannel403 {
        client: &'a str,
        channel: &'a str,
    },
    ErrCannotSendToChain404 {
        client: &'a str,
        channel: &'a str,
    },
    ErrTooManyChannels405 {
        client: &'a str,
        channel: &'a str,
    },
    ErrWasNoSuchNick406 {
        client: &'a str,
        nick: &'a str,
    },
    ErrInputTooLong417 {
        client: &'a str,
    },
    ErrUnknownCommand421 {
        client: &'a str,
        command: &'a str,
    },
    ErrNicknameInUse433 {
        client: &'a str,
        nick: &'a str,
    },
    ErrUserNotInChannel441 {
        client: &'a str,
        nick: &'a str,
        channel: &'a str,
    },
    ErrNotOnChannel442 {
        client: &'a str,
        channel: &'a str,
    },
    ErrUserOnChannel443 {
        client: &'a str,
        nick: &'a str,
        channel: &'a str,
    },
    ErrNotRegistered451 {
        client: &'a str,
    },
    ErrNeedMoreParams461 {
        client: &'a str,
        command: &'a str,
    },
    ErrAlreadyRegistered462 {
        client: &'a str,
    },
    ErrPasswdMismatch464 {
        client: &'a str,
    },
    //ErrYoureBannedCreep465{ client: &'a str },
    ErrChannelIsFull471 {
        client: &'a str,
        channel: &'a str,
    },
    ErrUnknownMode472 {
        client: &'a str,
        modechar: char,
        channel: &'a str,
    },
    ErrInviteOnlyChan473 {
        client: &'a str,
        channel: &'a str,
    },
    ErrBannedFromChan474 {
        client: &'a str,
        channel: &'a str,
    },
    ErrBadChannelKey475 {
        client: &'a str,
        channel: &'a str,
    },
    ErrNoPrivileges481 {
        client: &'a str,
    },
    ErrChanOpPrivsNeeded482 {
        client: &'a str,
        channel: &'a str,
    },
    ErrCantKillServer483 {
        client: &'a str,
    },
    ErrYourConnRestricted484 {
        client: &'a str,
    },
    ErrNoOperHost491 {
        client: &'a str,
    },
    ErrUmodeUnknownFlag501 {
        client: &'a str,
    },
    ErrUsersDontMatch502 {
        client: &'a str,
    },
    ErrHelpNotFound524 {
        client: &'a str,
        subject: &'a str,
    },
    //RplStartTls670{ client: &'a str },
    RplWhoIsSecure671 {
        client: &'a str,
        nick: &'a str,
    },
    //ErrStartTls691{ client: &'a str },
    ErrInvalidModeParam696 {
        client: &'a str,
        target: &'a str,
        modechar: char,
        param: &'a str,
        description: &'a str,
    },
    RplHelpStart704 {
        client: &'a str,
        subject: &'a str,
        line: &'a str,
    },
    RplHelpTxt705 {
        client: &'a str,
        subject: &'a str,
        line: &'a str,
    },
    RplEndOfHelp706 {
        client: &'a str,
        subject: &'a str,
        line: &'a str,
    },
    //RplLoggedIn900{ client: &'a str, nick: &'a str, user: &'a str, host: &'a str,
    //        account: &'a str, username: &'a str },
    //RplLoggedOut901{ client: &'a str, nick: &'a str, user: &'a str, host: &'a str },
    //ErrNickLocked902{ client: &'a str },
    //RplSaslSuccess903{ client: &'a str },
    //ErrSaslFail904{ client: &'a str },
    //ErrSaslTooLong905{ client: &'a str },
    //ErrSaslAborted906{ client: &'a str },
    //ErrSaslAlready907{ client: &'a str },
    //RplSaslMechs908{ client: &'a str, mechanisms: &'a str },
    ErrCannotDoCommand972 {
        client: &'a str,
    },
}

use Reply::*;

impl<'a> fmt::Display for Reply<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RplWelcome001 {
                client,
                networkname,
                nick,
                user,
                host,
            } => {
                write!(
                    f,
                    "001 {} :Welcome to the {} Network, {}!~{}@{}",
                    client, networkname, nick, user, host
                )
            }
            RplYourHost002 {
                client,
                servername,
                version,
            } => {
                write!(
                    f,
                    "002 {} :Your host is {}, running version {}",
                    client, servername, version
                )
            }
            RplCreated003 { client, datetime } => {
                write!(f, "003 {} :This server was created {}", client, datetime)
            }
            RplMyInfo004 {
                client,
                servername,
                version,
                avail_user_modes,
                avail_chmodes,
                avail_chmodes_with_params,
            } => {
                if let Some(p) = avail_chmodes_with_params {
                    write!(
                        f,
                        "004 {} {} {} {} {} {}",
                        client, servername, version, avail_user_modes, avail_chmodes, p
                    )
                } else {
                    write!(
                        f,
                        "004 {} {} {} {} {}",
                        client, servername, version, avail_user_modes, avail_chmodes
                    )
                }
            }
            RplISupport005 { client, tokens } => {
                write!(f, "005 {} {} :are supported by this server", client, tokens)
            }
            RplStatsCommands212 {
                client,
                command,
                count,
            } => {
                write!(f, "212 {} {} {}", client, command, count)
            }
            RplEndOfStats219 { client, stat } => {
                write!(f, "219 {} {} :End of STATS report", client, stat)
            }
            RplUModeIs221 { client, user_modes } => {
                write!(f, "221 {} {}", client, user_modes)
            }
            RplStatsUptime242 { client, seconds } => {
                let day_time = seconds % (24 * 3600);
                let hour = day_time / 3600;
                let minute = (day_time - hour * 3600) / 60;
                let second = day_time % 60;
                write!(
                    f,
                    "242 {} :Server Up {} days {}:{:02}:{:02}",
                    client,
                    seconds / (24 * 3600),
                    hour,
                    minute,
                    second
                )
            }
            RplLUserClient251 {
                client,
                users_num,
                inv_users_num,
                servers_num,
            } => {
                write!(
                    f,
                    "251 {} :There are {} users and {} invisible on {} servers",
                    client, users_num, inv_users_num, servers_num
                )
            }
            RplLUserOp252 { client, ops_num } => {
                write!(f, "252 {} {} :operator(s) online", client, ops_num)
            }
            RplLUserUnknown253 { client, conns_num } => {
                write!(f, "253 {} {} :unknown connection(s)", client, conns_num)
            }
            RplLUserChannels254 {
                client,
                channels_num,
            } => {
                write!(f, "254 {} {} :channels formed", client, channels_num)
            }
            RplLUserMe255 {
                client,
                clients_num,
                servers_num,
            } => {
                write!(
                    f,
                    "255 {} :I have {} clients and {} servers",
                    client, clients_num, servers_num
                )
            }
            RplAdminMe256 { client, server } => {
                write!(f, "256 {} {} :Administrative info", client, server)
            }
            RplAdminLoc1257 { client, info } => {
                write!(f, "257 {} :{}", client, info)
            }
            RplAdminLoc2258 { client, info } => {
                write!(f, "258 {} :{}", client, info)
            }
            RplAdminEmail259 { client, email } => {
                write!(f, "259 {} :{}", client, email)
            }
            RplLocalUsers265 {
                client,
                clients_num,
                max_clients_num,
            } => {
                write!(
                    f,
                    "265 {} {} {} :Current local users {}, max {}",
                    client, clients_num, max_clients_num, clients_num, max_clients_num
                )
            }
            RplGlobalUsers266 {
                client,
                clients_num,
                max_clients_num,
            } => {
                write!(
                    f,
                    "266 {} {} {} :Current global users {}, max {}",
                    client, clients_num, max_clients_num, clients_num, max_clients_num
                )
            }
            //RplWhoIsCertFP276{ client, nick, fingerprint } => {
            //    write!(f, "276 {} {} :has client certificate fingerprint {}", client, nick,
            //        fingerprint) }
            RplAway301 {
                client,
                nick,
                message,
            } => {
                write!(f, "301 {} {} :{}", client, nick, message)
            }
            RplUserHost302 { client, replies } => {
                write!(
                    f,
                    "302 {} :{}",
                    client,
                    replies
                        .iter()
                        .map(|x| x.to_string())
                        .collect::<Vec::<_>>()
                        .join(" ")
                )
            }
            RplIson303 { client, nicknames } => {
                write!(
                    f,
                    "303 {} :{}",
                    client,
                    nicknames
                        .iter()
                        .map(|x| x.to_string())
                        .collect::<Vec::<_>>()
                        .join(" ")
                )
            }
            RplUnAway305 { client } => {
                write!(f, "305 {} :You are no longer marked as being away", client)
            }
            RplNowAway306 { client } => {
                write!(f, "306 {} :You have been marked as being away", client)
            }
            RplWhoReply352 {
                client,
                channel,
                username,
                host,
                server,
                nick,
                flags,
                hopcount,
                realname,
            } => {
                write!(
                    f,
                    "352 {} {} ~{} {} {} {} {} :{} {}",
                    client, channel, username, host, server, nick, flags, hopcount, realname
                )
            }
            RplEndOfWho315 { client, mask } => {
                write!(f, "315 {} {} :End of WHO list", client, mask)
            }
            RplWhoIsRegNick307 { client, nick } => {
                write!(f, "307 {} {} :has identified for this nick", client, nick)
            }
            RplWhoIsUser311 {
                client,
                nick,
                username,
                host,
                realname,
            } => {
                write!(
                    f,
                    "311 {} {} ~{} {} * :{}",
                    client, nick, username, host, realname
                )
            }
            RplWhoIsServer312 {
                client,
                nick,
                server,
                server_info,
            } => {
                write!(f, "312 {} {} {} :{}", client, nick, server, server_info)
            }
            RplWhoIsOperator313 { client, nick } => {
                write!(f, "313 {} {} :is an IRC operator", client, nick)
            }
            RplWhoWasUser314 {
                client,
                nick,
                username,
                host,
                realname,
            } => {
                write!(
                    f,
                    "314 {} {} ~{} {} * :{}",
                    client, nick, username, host, realname
                )
            }
            RplwhoIsIdle317 {
                client,
                nick,
                secs,
                signon,
            } => {
                write!(
                    f,
                    "317 {} {} {} {} :seconds idle, signon time",
                    client, nick, secs, signon
                )
            }
            RplEndOfWhoIs318 { client, nick } => {
                write!(f, "318 {} {} :End of /WHOIS list", client, nick)
            }
            RplWhoIsChannels319 {
                client,
                nick,
                channels,
            } => {
                write!(
                    f,
                    "319 {} {} :{}",
                    client,
                    nick,
                    channels
                        .iter()
                        .map(|c| {
                            if let Some(ref prefix) = c.prefix {
                                prefix.to_string() + c.channel
                            } else {
                                c.channel.to_string()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            }
            RplListStart321 { client } => {
                write!(f, "321 {} Channel :Users  Name", client)
            }
            RplList322 {
                client,
                channel,
                client_count,
                topic,
            } => {
                write!(f, "322 {} {} {} :{}", client, channel, client_count, topic)
            }
            RplListEnd323 { client } => {
                write!(f, "323 {} :End of /LIST", client)
            }
            RplChannelModeIs324 {
                client,
                channel,
                modestring,
            } => {
                write!(f, "324 {} {} {}", client, channel, modestring)
            }
            RplCreationTime329 {
                client,
                channel,
                creation_time,
            } => {
                write!(f, "329 {} {} {}", client, channel, creation_time)
            }
            RplNoTopic331 { client, channel } => {
                write!(f, "331 {} {} :No topic is set", client, channel)
            }
            RplTopic332 {
                client,
                channel,
                topic,
            } => {
                write!(f, "332 {} {} :{}", client, channel, topic)
            }
            RplTopicWhoTime333 {
                client,
                channel,
                nick,
                setat,
            } => {
                write!(f, "333 {} {} {} {}", client, channel, nick, setat)
            }
            RplInviting341 {
                client,
                nick,
                channel,
            } => {
                write!(f, "341 {} {} {}", client, nick, channel)
            }
            RplInviteList346 {
                client,
                channel,
                mask,
            } => {
                write!(f, "346 {} {} {}", client, channel, mask)
            }
            RplEndOfInviteList347 { client, channel } => {
                write!(f, "347 {} {} :End of channel invite list", client, channel)
            }
            RplExceptList348 {
                client,
                channel,
                mask,
            } => {
                write!(f, "348 {} {} {}", client, channel, mask)
            }
            RplEndOfExceptList349 { client, channel } => {
                write!(
                    f,
                    "349 {} {} :End of channel exception list",
                    client, channel
                )
            }
            RplVersion351 {
                client,
                version,
                server,
                comments,
            } => {
                write!(f, "351 {} {} {} :{}", client, version, server, comments)
            }
            RplNameReply353 {
                client,
                symbol,
                channel,
                replies,
            } => {
                write!(
                    f,
                    "353 {} {} {} :{}",
                    client,
                    symbol,
                    channel,
                    replies
                        .iter()
                        .map(|r| { r.prefix.to_string() + r.nick })
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            }
            RplLinks364 {
                client,
                server,
                mask,
                hop_count,
                server_info,
            } => {
                write!(
                    f,
                    "364 {} {} {} :{} {}",
                    client, server, mask, hop_count, server_info
                )
            }
            RplEndOfLinks365 { client, mask } => {
                write!(f, "365 {} {} :End of LINKS list", client, mask)
            }
            RplEndOfNames366 { client, channel } => {
                write!(f, "366 {} {} :End of /NAMES list", client, channel)
            }
            RplBanList367 {
                client,
                channel,
                mask,
                who,
                set_ts,
            } => {
                write!(f, "367 {} {} {} {} {}", client, channel, mask, who, set_ts)
            }
            RplEndOfBanList368 { client, channel } => {
                write!(f, "368 {} {} :End of channel ban list", client, channel)
            }
            RplEndOfWhoWas369 { client, nick } => {
                write!(f, "369 {} {} :End of WHOWAS", client, nick)
            }
            RplInfo371 { client, info } => {
                write!(f, "371 {} :{}", client, info)
            }
            RplEndOfInfo374 { client } => {
                write!(f, "374 {} :End of INFO list", client)
            }
            RplMotdStart375 { client, server } => {
                write!(f, "375 {} :- {} Message of the day - ", client, server)
            }
            RplMotd372 { client, motd } => {
                write!(f, "372 {} :{}", client, motd)
            }
            RplEndOfMotd376 { client } => {
                write!(f, "376 {} :End of /MOTD command.", client)
            }
            RplWhoIsHost378 {
                client,
                nick,
                host_info,
            } => {
                write!(
                    f,
                    "378 {} {} :is connecting from {}",
                    client, nick, host_info
                )
            }
            RplWhoIsModes379 {
                client,
                nick,
                modes,
            } => {
                write!(f, "379 {} {} :is using modes {}", client, nick, modes)
            }
            RplYoureOper381 { client } => {
                write!(f, "381 {} :You are now an IRC operator", client)
            }
            //RplRehashing382{ client, config_file } => {
            //    write!(f, "382 {} {} :Rehashing", client, config_file) }
            RplTime391 {
                client,
                server,
                timestamp,
                ts_offset,
                human_readable,
            } => {
                write!(
                    f,
                    "391 {} {} {} {} :{}",
                    client, server, timestamp, ts_offset, human_readable
                )
            }
            ErrUnknownError400 {
                client,
                command,
                subcommand,
                info,
            } => {
                if let Some(sc) = subcommand {
                    write!(f, "400 {} {} {} :{}", client, command, sc, info)
                } else {
                    write!(f, "400 {} {} :{}", client, command, info)
                }
            }
            ErrNoSuchNick401 { client, nick } => {
                write!(f, "401 {} {} :No such nick/channel", client, nick)
            }
            //ErrNoSuchServer402{ client, server } => {
            //    write!(f, "402 {} {} :No such server", client, server) }
            ErrNoSuchChannel403 { client, channel } => {
                write!(f, "403 {} {} :No such channel", client, channel)
            }
            ErrCannotSendToChain404 { client, channel } => {
                write!(f, "404 {} {} :Cannot send to channel", client, channel)
            }
            ErrTooManyChannels405 { client, channel } => {
                write!(
                    f,
                    "405 {} {} :You have joined too many channels",
                    client, channel
                )
            }
            ErrWasNoSuchNick406 { client, nick } => {
                write!(f, "406 {} {} :There was no such nickname", client, nick)
            }
            ErrInputTooLong417 { client } => {
                write!(f, "417 {} :Input line was too long", client)
            }
            ErrUnknownCommand421 { client, command } => {
                write!(f, "421 {} {} :Unknown command", client, command)
            }
            ErrNicknameInUse433 { client, nick } => {
                write!(f, "433 {} {} :Nickname is already in use", client, nick)
            }
            ErrUserNotInChannel441 {
                client,
                nick,
                channel,
            } => {
                write!(
                    f,
                    "441 {} {} {} :They aren't on that channel",
                    client, nick, channel
                )
            }
            ErrNotOnChannel442 { client, channel } => {
                write!(f, "442 {} {} :You're not on that channel", client, channel)
            }
            ErrUserOnChannel443 {
                client,
                nick,
                channel,
            } => {
                write!(
                    f,
                    "443 {} {} {} :is already on channel",
                    client, nick, channel
                )
            }
            ErrNotRegistered451 { client } => {
                write!(f, "451 {} :You have not registered", client)
            }
            ErrNeedMoreParams461 { client, command } => {
                write!(f, "461 {} {} :Not enough parameters", client, command)
            }
            ErrAlreadyRegistered462 { client } => {
                write!(f, "462 {} :You may not reregister", client)
            }
            ErrPasswdMismatch464 { client } => {
                write!(f, "464 {} :Password incorrect", client)
            }
            //ErrYoureBannedCreep465{ client } => {
            //    write!(f, "465 {} :You are banned from this server.", client) }
            ErrChannelIsFull471 { client, channel } => {
                write!(f, "471 {} {} :Cannot join channel (+l)", client, channel)
            }
            ErrUnknownMode472 {
                client,
                modechar,
                channel,
            } => {
                write!(
                    f,
                    "472 {} {} :is unknown mode char for {}",
                    client, modechar, channel
                )
            }
            ErrInviteOnlyChan473 { client, channel } => {
                write!(f, "473 {} {} :Cannot join channel (+i)", client, channel)
            }
            ErrBannedFromChan474 { client, channel } => {
                write!(f, "474 {} {} :Cannot join channel (+b)", client, channel)
            }
            ErrBadChannelKey475 { client, channel } => {
                write!(f, "475 {} {} :Cannot join channel (+k)", client, channel)
            }
            ErrNoPrivileges481 { client } => {
                write!(
                    f,
                    "481 {} :Permission Denied- You're not an IRC operator",
                    client
                )
            }
            ErrChanOpPrivsNeeded482 { client, channel } => {
                write!(f, "482 {} {} :You're not channel operator", client, channel)
            }
            ErrCantKillServer483 { client } => {
                write!(f, "483 {} :You cant kill a server!", client)
            }
            ErrYourConnRestricted484 { client } => {
                write!(f, "484 {} :Your connection is restricted!", client)
            }
            ErrNoOperHost491 { client } => {
                write!(f, "491 {} :No O-lines for your host", client)
            }
            ErrUmodeUnknownFlag501 { client } => {
                write!(f, "501 {} :Unknown MODE flag", client)
            }
            ErrUsersDontMatch502 { client } => {
                write!(f, "502 {} :Cant change mode for other users", client)
            }
            ErrHelpNotFound524 { client, subject } => {
                write!(
                    f,
                    "524 {} {} :No help available on this topic",
                    client, subject
                )
            }
            //RplStartTls670{ client } => {
            //    write!(f, "670 {} :STARTTLS successful, proceed with TLS handshake", client) }
            RplWhoIsSecure671 { client, nick } => {
                write!(f, "671 {} {} :is using a secure connection", client, nick)
            }
            //ErrStartTls691{ client } => {
            //    write!(f, "691 {} :STARTTLS failed (Wrong moon phase)", client) }
            ErrInvalidModeParam696 {
                client,
                target,
                modechar,
                param,
                description,
            } => {
                write!(
                    f,
                    "696 {} {} {} {} :{}",
                    client, target, modechar, param, description
                )
            }
            RplHelpStart704 {
                client,
                subject,
                line,
            } => {
                write!(f, "704 {} {} :{}", client, subject, line)
            }
            RplHelpTxt705 {
                client,
                subject,
                line,
            } => {
                write!(f, "705 {} {} :{}", client, subject, line)
            }
            RplEndOfHelp706 {
                client,
                subject,
                line,
            } => {
                write!(f, "706 {} {} :{}", client, subject, line)
            }
            //RplLoggedIn900{ client, nick, user, host, account, username } => {
            //    write!(f, "900 {} {}!~{}@{} {} :You are now logged in as {}", client, nick,
            //        user, host, account, username) }
            //RplLoggedOut901{ client, nick, user, host } => {
            //    write!(f, "901 {} {}!~{}@{} :You are now logged out", client, nick,
            //        user, host) }
            //ErrNickLocked902{ client } => {
            //    write!(f, "902 {} :You must use a nick assigned to you", client) }
            //RplSaslSuccess903{ client } => {
            //    write!(f, "903 {} :SASL authentication successful", client) }
            //ErrSaslFail904{ client } => {
            //    write!(f, "904 {} :SASL authentication failed", client) }
            //ErrSaslTooLong905{ client } => {
            //    write!(f, "905 {} :SASL message too long", client) }
            //ErrSaslAborted906{ client } => {
            //    write!(f, "906 {} :SASL authentication aborted", client) }
            //ErrSaslAlready907{ client } => {
            //    write!(f, "907 {} :You have already authenticated using SASL", client) }
            //RplSaslMechs908{ client, mechanisms } => {
            //    write!(f, "908 {} {} :are available SASL mechanisms", client, mechanisms) }
            ErrCannotDoCommand972 { client } => {
                write!(f, "972 {} :Can not do command", client)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_replies() {
        assert_eq!(
            "001 <client> :Welcome to the <networkname> Network, <nick>!~<user>@<host>",
            format!(
                "{}",
                RplWelcome001 {
                    client: "<client>",
                    networkname: "<networkname>",
                    nick: "<nick>",
                    user: "<user>",
                    host: "<host>"
                }
            )
        );
        assert_eq!(
            "002 <client> :Your host is <servername>, running version <version>",
            format!(
                "{}",
                RplYourHost002 {
                    client: "<client>",
                    servername: "<servername>",
                    version: "<version>"
                }
            )
        );
        assert_eq!(
            "003 <client> :This server was created <datetime>",
            format!(
                "{}",
                RplCreated003 {
                    client: "<client>",
                    datetime: "<datetime>"
                }
            )
        );
        assert_eq!(
            "004 <client> <servername> <version> <available user modes> \
                    <available channel modes> <channel modes with a parameter>",
            format!(
                "{}",
                RplMyInfo004 {
                    client: "<client>",
                    servername: "<servername>",
                    version: "<version>",
                    avail_user_modes: "<available user modes>",
                    avail_chmodes: "<available channel modes>",
                    avail_chmodes_with_params: Some("<channel modes with a parameter>")
                }
            )
        );
        assert_eq!(
            "004 <client> <servername> <version> <available user modes> \
                    <available channel modes>",
            format!(
                "{}",
                RplMyInfo004 {
                    client: "<client>",
                    servername: "<servername>",
                    version: "<version>",
                    avail_user_modes: "<available user modes>",
                    avail_chmodes: "<available channel modes>",
                    avail_chmodes_with_params: None
                }
            )
        );
        assert_eq!(
            "005 <client> <1-13 tokens> :are supported by this server",
            format!(
                "{}",
                RplISupport005 {
                    client: "<client>",
                    tokens: "<1-13 tokens>"
                }
            )
        );
        assert_eq!(
            "212 <client> <command> 67",
            format!(
                "{}",
                RplStatsCommands212 {
                    client: "<client>",
                    command: "<command>",
                    count: 67
                }
            )
        );
        assert_eq!(
            "219 <client> u :End of STATS report",
            format!(
                "{}",
                RplEndOfStats219 {
                    client: "<client>",
                    stat: 'u'
                }
            )
        );
        assert_eq!(
            "221 <client> <user modes>",
            format!(
                "{}",
                RplUModeIs221 {
                    client: "<client>",
                    user_modes: "<user modes>"
                }
            )
        );
        assert_eq!(
            "242 <client> :Server Up 4120 days 21:34:49",
            format!(
                "{}",
                RplStatsUptime242 {
                    client: "<client>",
                    seconds: 356045689
                }
            )
        );
        assert_eq!(
            "251 <client> :There are 3 users and 4 invisible on 5 servers",
            format!(
                "{}",
                RplLUserClient251 {
                    client: "<client>",
                    users_num: 3,
                    inv_users_num: 4,
                    servers_num: 5
                }
            )
        );
        assert_eq!(
            "252 <client> 6 :operator(s) online",
            format!(
                "{}",
                RplLUserOp252 {
                    client: "<client>",
                    ops_num: 6
                }
            )
        );
        assert_eq!(
            "253 <client> 7 :unknown connection(s)",
            format!(
                "{}",
                RplLUserUnknown253 {
                    client: "<client>",
                    conns_num: 7
                }
            )
        );
        assert_eq!(
            "254 <client> 8 :channels formed",
            format!(
                "{}",
                RplLUserChannels254 {
                    client: "<client>",
                    channels_num: 8
                }
            )
        );
        assert_eq!(
            "255 <client> :I have 3 clients and 6 servers",
            format!(
                "{}",
                RplLUserMe255 {
                    client: "<client>",
                    clients_num: 3,
                    servers_num: 6
                }
            )
        );
        assert_eq!(
            "256 <client> <server> :Administrative info",
            format!(
                "{}",
                RplAdminMe256 {
                    client: "<client>",
                    server: "<server>"
                }
            )
        );
        assert_eq!(
            "257 <client> :<info>",
            format!(
                "{}",
                RplAdminLoc1257 {
                    client: "<client>",
                    info: "<info>"
                }
            )
        );
        assert_eq!(
            "258 <client> :<info>",
            format!(
                "{}",
                RplAdminLoc2258 {
                    client: "<client>",
                    info: "<info>"
                }
            )
        );
        assert_eq!(
            "259 <client> :<info>",
            format!(
                "{}",
                RplAdminEmail259 {
                    client: "<client>",
                    email: "<info>"
                }
            )
        );
        assert_eq!(
            "265 <client> 4 7 :Current local users 4, max 7",
            format!(
                "{}",
                RplLocalUsers265 {
                    client: "<client>",
                    clients_num: 4,
                    max_clients_num: 7
                }
            )
        );
        assert_eq!(
            "266 <client> 7 10 :Current global users 7, max 10",
            format!(
                "{}",
                RplGlobalUsers266 {
                    client: "<client>",
                    clients_num: 7,
                    max_clients_num: 10
                }
            )
        );
        //assert_eq!("276 <client> <nick> :has client certificate fingerprint <fingerprint>",
        //    format!("{}", RplWhoIsCertFP276{ client: "<client>", nick: "<nick>",
        //        fingerprint: "<fingerprint>" }));
        assert_eq!(
            "301 <client> <nick> :<message>",
            format!(
                "{}",
                RplAway301 {
                    client: "<client>",
                    nick: "<nick>",
                    message: "<message>"
                }
            )
        );
        assert_eq!(
            "302 <client> :",
            format!(
                "{}",
                RplUserHost302 {
                    client: "<client>",
                    replies: &vec![]
                }
            )
        );
        assert_eq!(
            "302 <client> :<reply1> <reply2> <reply3>",
            format!(
                "{}",
                RplUserHost302 {
                    client: "<client>",
                    replies: &vec![
                        "<reply1>".to_string(),
                        "<reply2>".to_string(),
                        "<reply3>".to_string()
                    ]
                }
            )
        );
        assert_eq!(
            "303 <client> :<nick1> <nick2> <nick3>",
            format!(
                "{}",
                RplIson303 {
                    client: "<client>",
                    nicknames: &vec!["<nick1>", "<nick2>", "<nick3>"]
                }
            )
        );
        assert_eq!(
            "305 <client> :You are no longer marked as being away",
            format!("{}", RplUnAway305 { client: "<client>" })
        );
        assert_eq!(
            "306 <client> :You have been marked as being away",
            format!("{}", RplNowAway306 { client: "<client>" })
        );
        assert_eq!(
            "352 <client> <channel> ~<username> <host> <server> <nick> \
                <flags> :2 <realname>",
            format!(
                "{}",
                RplWhoReply352 {
                    client: "<client>",
                    channel: "<channel>",
                    username: "<username>",
                    host: "<host>",
                    server: "<server>",
                    nick: "<nick>",
                    flags: "<flags>",
                    hopcount: 2,
                    realname: "<realname>"
                }
            )
        );
        assert_eq!(
            "315 <client> <mask> :End of WHO list",
            format!(
                "{}",
                RplEndOfWho315 {
                    client: "<client>",
                    mask: "<mask>"
                }
            )
        );
        assert_eq!(
            "307 <client> <nick> :has identified for this nick",
            format!(
                "{}",
                RplWhoIsRegNick307 {
                    client: "<client>",
                    nick: "<nick>"
                }
            )
        );
        assert_eq!(
            "311 <client> <nick> ~<username> <host> * :<realname>",
            format!(
                "{}",
                RplWhoIsUser311 {
                    client: "<client>",
                    nick: "<nick>",
                    host: "<host>",
                    username: "<username>",
                    realname: "<realname>"
                }
            )
        );
        assert_eq!(
            "312 <client> <nick> <server> :<server info>",
            format!(
                "{}",
                RplWhoIsServer312 {
                    client: "<client>",
                    nick: "<nick>",
                    server: "<server>",
                    server_info: "<server info>"
                }
            )
        );
        assert_eq!(
            "313 <client> <nick> :is an IRC operator",
            format!(
                "{}",
                RplWhoIsOperator313 {
                    client: "<client>",
                    nick: "<nick>"
                }
            )
        );
        assert_eq!(
            "314 <client> <nick> ~<username> <host> * :<realname>",
            format!(
                "{}",
                RplWhoWasUser314 {
                    client: "<client>",
                    nick: "<nick>",
                    username: "<username>",
                    host: "<host>",
                    realname: "<realname>"
                }
            )
        );
        assert_eq!(
            "317 <client> <nick> 134 548989343 :seconds idle, signon time",
            format!(
                "{}",
                RplwhoIsIdle317 {
                    client: "<client>",
                    nick: "<nick>",
                    secs: 134,
                    signon: 548989343
                }
            )
        );
        assert_eq!(
            "318 <client> <nick> :End of /WHOIS list",
            format!(
                "{}",
                RplEndOfWhoIs318 {
                    client: "<client>",
                    nick: "<nick>"
                }
            )
        );
        assert_eq!(
            "319 <client> <nick> :prefix1<channel1> <channel2> prefix3<channel3>",
            format!(
                "{}",
                RplWhoIsChannels319 {
                    client: "<client>",
                    nick: "<nick>",
                    channels: &vec![
                        WhoIsChannelStruct {
                            prefix: Some("prefix1".to_string()),
                            channel: "<channel1>"
                        },
                        WhoIsChannelStruct {
                            prefix: None,
                            channel: "<channel2>"
                        },
                        WhoIsChannelStruct {
                            prefix: Some("prefix3".to_string()),
                            channel: "<channel3>"
                        }
                    ]
                }
            )
        );
        assert_eq!(
            "321 <client> Channel :Users  Name",
            format!("{}", RplListStart321 { client: "<client>" })
        );
        assert_eq!(
            "322 <client> <channel> 47 :<topic>",
            format!(
                "{}",
                RplList322 {
                    client: "<client>",
                    channel: "<channel>",
                    client_count: 47,
                    topic: "<topic>"
                }
            )
        );
        assert_eq!(
            "323 <client> :End of /LIST",
            format!("{}", RplListEnd323 { client: "<client>" })
        );
        assert_eq!(
            "324 <client> <channel> <modestring>",
            format!(
                "{}",
                RplChannelModeIs324 {
                    client: "<client>",
                    channel: "<channel>",
                    modestring: "<modestring>"
                }
            )
        );
        assert_eq!(
            "329 <client> <channel> 334411111",
            format!(
                "{}",
                RplCreationTime329 {
                    client: "<client>",
                    channel: "<channel>",
                    creation_time: 334411111
                }
            )
        );
        assert_eq!(
            "331 <client> <channel> :No topic is set",
            format!(
                "{}",
                RplNoTopic331 {
                    client: "<client>",
                    channel: "<channel>"
                }
            )
        );
        assert_eq!(
            "332 <client> <channel> :<topic>",
            format!(
                "{}",
                RplTopic332 {
                    client: "<client>",
                    channel: "<channel>",
                    topic: "<topic>"
                }
            )
        );
        assert_eq!(
            "333 <client> <channel> <nick> 38329311",
            format!(
                "{}",
                RplTopicWhoTime333 {
                    client: "<client>",
                    channel: "<channel>",
                    nick: "<nick>",
                    setat: 38329311
                }
            )
        );
        assert_eq!(
            "341 <client> <nick> <channel>",
            format!(
                "{}",
                RplInviting341 {
                    client: "<client>",
                    nick: "<nick>",
                    channel: "<channel>"
                }
            )
        );
        assert_eq!(
            "346 <client> <channel> <mask>",
            format!(
                "{}",
                RplInviteList346 {
                    client: "<client>",
                    channel: "<channel>",
                    mask: "<mask>"
                }
            )
        );
        assert_eq!(
            "347 <client> <channel> :End of channel invite list",
            format!(
                "{}",
                RplEndOfInviteList347 {
                    client: "<client>",
                    channel: "<channel>"
                }
            )
        );
        assert_eq!(
            "348 <client> <channel> <mask>",
            format!(
                "{}",
                RplExceptList348 {
                    client: "<client>",
                    channel: "<channel>",
                    mask: "<mask>"
                }
            )
        );
        assert_eq!(
            "349 <client> <channel> :End of channel exception list",
            format!(
                "{}",
                RplEndOfExceptList349 {
                    client: "<client>",
                    channel: "<channel>"
                }
            )
        );
        assert_eq!(
            "351 <client> <version> <server> :<comments>",
            format!(
                "{}",
                RplVersion351 {
                    client: "<client>",
                    version: "<version>",
                    server: "<server>",
                    comments: "<comments>"
                }
            )
        );
        assert_eq!(
            "353 <client> <symbol> <channel> :<prefix1><nick1> <nick2>",
            format!(
                "{}",
                RplNameReply353 {
                    client: "<client>",
                    symbol: "<symbol>",
                    channel: "<channel>",
                    replies: &vec![
                        NameReplyStruct {
                            prefix: "<prefix1>".to_string(),
                            nick: "<nick1>"
                        },
                        NameReplyStruct {
                            prefix: String::new(),
                            nick: "<nick2>"
                        }
                    ]
                }
            )
        );
        assert_eq!(
            "364 <client> <server> <mask> :1 <server_info>",
            format!(
                "{}",
                RplLinks364 {
                    client: "<client>",
                    server: "<server>",
                    mask: "<mask>",
                    hop_count: 1,
                    server_info: "<server_info>"
                }
            )
        );
        assert_eq!(
            "365 <client> <mask> :End of LINKS list",
            format!(
                "{}",
                RplEndOfLinks365 {
                    client: "<client>",
                    mask: "<mask>"
                }
            )
        );
        assert_eq!(
            "366 <client> <channel> :End of /NAMES list",
            format!(
                "{}",
                RplEndOfNames366 {
                    client: "<client>",
                    channel: "<channel>"
                }
            )
        );
        assert_eq!(
            "367 <client> <channel> <mask> <who> 3894211355",
            format!(
                "{}",
                RplBanList367 {
                    client: "<client>",
                    channel: "<channel>",
                    mask: "<mask>",
                    who: "<who>",
                    set_ts: 3894211355
                }
            )
        );
        assert_eq!(
            "368 <client> <channel> :End of channel ban list",
            format!(
                "{}",
                RplEndOfBanList368 {
                    client: "<client>",
                    channel: "<channel>"
                }
            )
        );
        assert_eq!(
            "369 <client> <nick> :End of WHOWAS",
            format!(
                "{}",
                RplEndOfWhoWas369 {
                    client: "<client>",
                    nick: "<nick>"
                }
            )
        );
        assert_eq!(
            "371 <client> :<info>",
            format!(
                "{}",
                RplInfo371 {
                    client: "<client>",
                    info: "<info>"
                }
            )
        );
        assert_eq!(
            "374 <client> :End of INFO list",
            format!("{}", RplEndOfInfo374 { client: "<client>" })
        );
        assert_eq!(
            "375 <client> :- <server> Message of the day - ",
            format!(
                "{}",
                RplMotdStart375 {
                    client: "<client>",
                    server: "<server>"
                }
            )
        );
        assert_eq!(
            "372 <client> :<motd>",
            format!(
                "{}",
                RplMotd372 {
                    client: "<client>",
                    motd: "<motd>"
                }
            )
        );
        assert_eq!(
            "376 <client> :End of /MOTD command.",
            format!("{}", RplEndOfMotd376 { client: "<client>" })
        );
        assert_eq!(
            "378 <client> <nick> :is connecting from *@localhost 127.0.0.1",
            format!(
                "{}",
                RplWhoIsHost378 {
                    client: "<client>",
                    nick: "<nick>",
                    host_info: "*@localhost 127.0.0.1"
                }
            )
        );
        assert_eq!(
            "379 <client> <nick> :is using modes +ailosw",
            format!(
                "{}",
                RplWhoIsModes379 {
                    client: "<client>",
                    nick: "<nick>",
                    modes: "+ailosw"
                }
            )
        );
        assert_eq!(
            "381 <client> :You are now an IRC operator",
            format!("{}", RplYoureOper381 { client: "<client>" })
        );
        //assert_eq!("382 <client> <config file> :Rehashing",
        //    format!("{}", RplRehashing382{ client: "<client>",
        //        config_file: "<config file>" }));
        assert_eq!(
            "391 <client> <server> 485829211 <TS offset> :<human-readable time>",
            format!(
                "{}",
                RplTime391 {
                    client: "<client>",
                    server: "<server>",
                    timestamp: 485829211,
                    ts_offset: "<TS offset>",
                    human_readable: "<human-readable time>"
                }
            )
        );
        assert_eq!(
            "400 <client> <command> :<info>",
            format!(
                "{}",
                ErrUnknownError400 {
                    client: "<client>",
                    command: "<command>",
                    subcommand: None,
                    info: "<info>"
                }
            )
        );
        assert_eq!(
            "400 <client> <command> <subcommand> :<info>",
            format!(
                "{}",
                ErrUnknownError400 {
                    client: "<client>",
                    command: "<command>",
                    subcommand: Some("<subcommand>"),
                    info: "<info>"
                }
            )
        );
        assert_eq!(
            "401 <client> <nickname> :No such nick/channel",
            format!(
                "{}",
                ErrNoSuchNick401 {
                    client: "<client>",
                    nick: "<nickname>"
                }
            )
        );
        //assert_eq!("402 <client> <server name> :No such server",
        //    format!("{}", ErrNoSuchServer402{ client: "<client>",
        //        server: "<server name>" }));
        assert_eq!(
            "403 <client> <channel> :No such channel",
            format!(
                "{}",
                ErrNoSuchChannel403 {
                    client: "<client>",
                    channel: "<channel>"
                }
            )
        );
        assert_eq!(
            "404 <client> <channel> :Cannot send to channel",
            format!(
                "{}",
                ErrCannotSendToChain404 {
                    client: "<client>",
                    channel: "<channel>"
                }
            )
        );
        assert_eq!(
            "405 <client> <channel> :You have joined too many channels",
            format!(
                "{}",
                ErrTooManyChannels405 {
                    client: "<client>",
                    channel: "<channel>"
                }
            )
        );
        assert_eq!(
            "406 <client> <nickname> :There was no such nickname",
            format!(
                "{}",
                ErrWasNoSuchNick406 {
                    client: "<client>",
                    nick: "<nickname>"
                }
            )
        );
        assert_eq!(
            "417 <client> :Input line was too long",
            format!("{}", ErrInputTooLong417 { client: "<client>" })
        );
        assert_eq!(
            "421 <client> <command> :Unknown command",
            format!(
                "{}",
                ErrUnknownCommand421 {
                    client: "<client>",
                    command: "<command>"
                }
            )
        );
        assert_eq!(
            "433 <client> <nick> :Nickname is already in use",
            format!(
                "{}",
                ErrNicknameInUse433 {
                    client: "<client>",
                    nick: "<nick>"
                }
            )
        );
        assert_eq!(
            "441 <client> <nick> <channel> :They aren't on that channel",
            format!(
                "{}",
                ErrUserNotInChannel441 {
                    client: "<client>",
                    nick: "<nick>",
                    channel: "<channel>"
                }
            )
        );
        assert_eq!(
            "442 <client> <channel> :You're not on that channel",
            format!(
                "{}",
                ErrNotOnChannel442 {
                    client: "<client>",
                    channel: "<channel>"
                }
            )
        );
        assert_eq!(
            "443 <client> <nick> <channel> :is already on channel",
            format!(
                "{}",
                ErrUserOnChannel443 {
                    client: "<client>",
                    nick: "<nick>",
                    channel: "<channel>"
                }
            )
        );
        assert_eq!(
            "451 <client> :You have not registered",
            format!("{}", ErrNotRegistered451 { client: "<client>" })
        );
        assert_eq!(
            "461 <client> <command> :Not enough parameters",
            format!(
                "{}",
                ErrNeedMoreParams461 {
                    client: "<client>",
                    command: "<command>"
                }
            )
        );
        assert_eq!(
            "462 <client> :You may not reregister",
            format!("{}", ErrAlreadyRegistered462 { client: "<client>" })
        );
        assert_eq!(
            "464 <client> :Password incorrect",
            format!("{}", ErrPasswdMismatch464 { client: "<client>" })
        );
        //assert_eq!("465 <client> :You are banned from this server.",
        //    format!("{}", ErrYoureBannedCreep465{ client: "<client>" }));
        assert_eq!(
            "471 <client> <channel> :Cannot join channel (+l)",
            format!(
                "{}",
                ErrChannelIsFull471 {
                    client: "<client>",
                    channel: "<channel>"
                }
            )
        );
        assert_eq!(
            "472 <client> x :is unknown mode char for <channel>",
            format!(
                "{}",
                ErrUnknownMode472 {
                    client: "<client>",
                    modechar: 'x',
                    channel: "<channel>"
                }
            )
        );
        assert_eq!(
            "473 <client> <channel> :Cannot join channel (+i)",
            format!(
                "{}",
                ErrInviteOnlyChan473 {
                    client: "<client>",
                    channel: "<channel>"
                }
            )
        );
        assert_eq!(
            "474 <client> <channel> :Cannot join channel (+b)",
            format!(
                "{}",
                ErrBannedFromChan474 {
                    client: "<client>",
                    channel: "<channel>"
                }
            )
        );
        assert_eq!(
            "475 <client> <channel> :Cannot join channel (+k)",
            format!(
                "{}",
                ErrBadChannelKey475 {
                    client: "<client>",
                    channel: "<channel>"
                }
            )
        );
        assert_eq!(
            "481 <client> :Permission Denied- You're not an IRC operator",
            format!("{}", ErrNoPrivileges481 { client: "<client>" })
        );
        assert_eq!(
            "482 <client> <channel> :You're not channel operator",
            format!(
                "{}",
                ErrChanOpPrivsNeeded482 {
                    client: "<client>",
                    channel: "<channel>"
                }
            )
        );
        assert_eq!(
            "483 <client> :You cant kill a server!",
            format!("{}", ErrCantKillServer483 { client: "<client>" })
        );
        assert_eq!(
            "484 <client> :Your connection is restricted!",
            format!("{}", ErrYourConnRestricted484 { client: "<client>" })
        );
        assert_eq!(
            "491 <client> :No O-lines for your host",
            format!("{}", ErrNoOperHost491 { client: "<client>" })
        );
        assert_eq!(
            "501 <client> :Unknown MODE flag",
            format!("{}", ErrUmodeUnknownFlag501 { client: "<client>" })
        );
        assert_eq!(
            "502 <client> :Cant change mode for other users",
            format!("{}", ErrUsersDontMatch502 { client: "<client>" })
        );
        assert_eq!(
            "524 <client> <subject> :No help available on this topic",
            format!(
                "{}",
                ErrHelpNotFound524 {
                    client: "<client>",
                    subject: "<subject>"
                }
            )
        );
        //assert_eq!("670 <client> :STARTTLS successful, proceed with TLS handshake",
        //    format!("{}", RplStartTls670{ client: "<client>" }));
        //assert_eq!("671 <client> <nick> :is using a secure connection",
        //    format!("{}", RplWhoIsSecure671{ client: "<client>", nick: "<nick>" }));
        //assert_eq!("691 <client> :STARTTLS failed (Wrong moon phase)",
        //    format!("{}", ErrStartTls691{ client: "<client>" }));
        assert_eq!(
            "696 <client> <target chan/user> x <parameter> :<description>",
            format!(
                "{}",
                ErrInvalidModeParam696 {
                    client: "<client>",
                    target: "<target chan/user>",
                    modechar: 'x',
                    param: "<parameter>",
                    description: "<description>"
                }
            )
        );
        assert_eq!(
            "704 <client> <subject> :<first line of help section>",
            format!(
                "{}",
                RplHelpStart704 {
                    client: "<client>",
                    subject: "<subject>",
                    line: "<first line of help section>"
                }
            )
        );
        assert_eq!(
            "705 <client> <subject> :<line of help text>",
            format!(
                "{}",
                RplHelpTxt705 {
                    client: "<client>",
                    subject: "<subject>",
                    line: "<line of help text>"
                }
            )
        );
        assert_eq!(
            "706 <client> <subject> :<last line of help text>",
            format!(
                "{}",
                RplEndOfHelp706 {
                    client: "<client>",
                    subject: "<subject>",
                    line: "<last line of help text>"
                }
            )
        );
        //assert_eq!("900 <client> <nick>!~<user>@<host> <account> \
        //    :You are now logged in as <username>",
        //    format!("{}", RplLoggedIn900{ client: "<client>", nick: "<nick>",
        //        user: "<user>", host: "<host>", account: "<account>",
        //        username: "<username>" }));
        //assert_eq!("901 <client> <nick>!~<user>@<host> :You are now logged out",
        //    format!("{}", RplLoggedOut901{ client: "<client>", nick: "<nick>",
        //        user: "<user>", host: "<host>" }));
        //assert_eq!("902 <client> :You must use a nick assigned to you",
        //    format!("{}", ErrNickLocked902{ client: "<client>" }));
        //assert_eq!("903 <client> :SASL authentication successful",
        //    format!("{}", RplSaslSuccess903{ client: "<client>" }));
        //assert_eq!("904 <client> :SASL authentication failed",
        //    format!("{}", ErrSaslFail904{ client: "<client>" }));
        //assert_eq!("905 <client> :SASL message too long",
        //    format!("{}", ErrSaslTooLong905{ client: "<client>" }));
        //assert_eq!("906 <client> :SASL authentication aborted",
        //    format!("{}", ErrSaslAborted906{ client: "<client>" }));
        //assert_eq!("907 <client> :You have already authenticated using SASL",
        //    format!("{}", ErrSaslAlready907{ client: "<client>" }));
        //assert_eq!("908 <client> <mechanisms> :are available SASL mechanisms",
        //    format!("{}", RplSaslMechs908{ client: "<client>",
        //        mechanisms: "<mechanisms>" }));
        assert_eq!(
            "972 <client> :Can not do command",
            format!("{}", ErrCannotDoCommand972 { client: "<client>" })
        );
    }
}
