// main.rs - main program
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

mod config;
mod reply;
mod command;
mod utils;
mod state;

use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use clap;
use clap::Parser;
use tokio;
use tokio::net::{TcpStream,TcpListener};
use tokio_util::codec::Framed;

use config::*;
use command::*;
use utils::*;
use state::*;

async fn user_state_process(main_state: Arc<MainState>, stream: TcpStream, addr: SocketAddr) {
    let line_stream = Framed::new(stream, IRCLinesCodec::new());
    if let Some(mut conn_state) = main_state.register_conn_state(addr.ip(), line_stream) {
        while !conn_state.is_quit() {
            if let Err(e) = main_state.process(&mut conn_state).await {
                eprintln!("Error: {}" , e);
            }
        }
        main_state.remove_user(&conn_state).await;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let config = MainConfig::new(cli)?;
    let listener = TcpListener::bind((config.listen, config.port)).await?;
    let main_state = Arc::new(MainState::new_from_config(config));
    
    let mut quit_receiver = main_state.get_quit_receiver().await;
    let mut do_quit = false;
    while !do_quit {
        tokio::select! {
            res = listener.accept() => {
                let (stream, addr) = res?;
                tokio::spawn(user_state_process(main_state.clone(), stream, addr));
            }
            Ok(msg) = &mut quit_receiver => {
                println!("Server quit: {}", msg);
                do_quit = true;
            }
        }
    }
    Ok(())
}
