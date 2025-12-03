use clap::Parser;
use log::{error, info};
use tokio::{fs::File, io, spawn};

use crate::network::{client::connect_to_peer, listenter::start_listener};

mod file_transfer;
mod network;
mod protocol;
mod security;
mod tls;

#[derive(Parser)]
#[command(
    version = "0.1.0",
    about = "P2P file transfer application",
    long_about = "A peer-to-peer file transfer tool with TLS and encryption.\n\
                   Usage examples:\n\
                   - Start listener: cargo run -- --port 8081\n\
                   - Send file: cargo run -- --send test.txt --to 127.0.0.1:8081"
)]
struct Args {
    #[arg(short, long, help = "Port to listen on")]
    port: Option<u16>,
    #[arg(short, long, help = "Path to file to send")]
    send: Option<String>,
    #[arg(
        short,
        long,
        help = "Address of peer to send file to (e.g., 127.0.0.1:8081)"
    )]
    to: Option<String>,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    // initilize loggig
    simple_logger::init().unwrap();

    let args = Args::parse();

    // send file
    if let (Some(p), Some(to)) = (args.send, args.to) {
        info!("Sending file: {} to: {}", p, to);
        send_file(p.as_str(), to.as_str()).await?;
    }

    // start listener
    if let Some(port) = args.port {
        let handler = spawn(async move {
            info!("server started lintening on port: {}", port);

            if let Err(e) = start_listener(port).await {
                error!("Listener error: {e}");
            }
        });
        handler.await?;
    }

    Ok(())
}

async fn send_file(path: &str, addr: &str) -> io::Result<()> {
    // check if file is not exist then panic
    let file = File::open(path).await?;
    drop(file);

    connect_to_peer(addr, path).await?;
    Ok(())
}
