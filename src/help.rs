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

// help topics list with its content.
pub(crate) static HELP_TOPICS: [(&str, &str); 2] = [
    (
        "COMMANDS",
        r##"List of commands:
ADMIN
AUTHENTICATE - unsupported
AWAY
CAP
CONNECT - unsupported
DIE
HELP
INFO
INVITE
ISON
JOIN
KICK
KILL
LINKS
LIST
LUSERS
MODE
MOTD
NAMES
NICK
NOTICE
OPER
PART
PASS
PING
PONG
PRIVMSG
QUIT
REHASH
RESTART
SQUIT
STATS
TIME
TOPIC
USER
USERHOST
VERSION
WALLOPS
WHO
WHOIS
WHOWAS"##,
    ),
    (
        "MAIN",
        r##"This is Simple IRC Server.
Use 'HELP COMMANDS' to list of commands.
If you want get HELP about commands please refer to https://modern.ircdocs.horse/
or https://datatracker.ietf.org/doc/html/rfc1459."##,
    ),
];
