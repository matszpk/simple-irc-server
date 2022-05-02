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

pub(crate) static HELP_TOPICS: [(&'static str, &'static str); 1] = [
    (r##"COMMANDS", "List of commands
CAPId = CommandName{ name: "CAP" },
AUTHENTICATE - unsupported
PASS
NICK
USER
PING
PONG
OPER
QUIT
JOIN
PART
TOPIC
NAMES
LIST
INVITE
KICK
MOTD
VERSION
ADMIN
CONNECT - unsupported
LUSERS
TIME
STATS - unsupported
LINKS
HELP
INFO
MODE
PRIVMSG
NOTICE
WHO
WHOIS
WHOWAS
KILL
REHASH
RESTART
SQUIT
AWAY
USERHOST
WALLOPS
"##)
];
