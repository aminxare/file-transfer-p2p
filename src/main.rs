use clap::Parser;
use tokio::{fs::File, io, spawn};

use crate::peer::{connect_to_peer, start_listener};

mod file_handler;
mod peer;
mod protocol;
mod security;

#[derive(Parser)]
#[command(
    version = "0.1.0",
    about = "P2P file transfer application",
    long_about = "A peer-to-peer file transfer tool with TLS and encryption.\n\
                   Usage examples:\n\
                   - Start listener: cargo run -- --port 8081\n\
                   - Send file: cargo run -- --port 8082 --send test.txt --to 127.0.0.1:8081"
)]
struct Args {
    #[arg(short, long, help = "Port to listen on")]
    port: u16,
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
    let args = Args::parse();

    // start listener
    let handler = spawn(async move {
        println!("--- start listening on port: {}", args.port);
        start_listener(args.port)
            .await
            .map_err(|e| eprintln!("Fail to start lintening. cause: {e}"))
            .unwrap();
    });

    if let (Some(p), Some(to)) = (args.send, args.to) {
        println!("Sending file: {}", p);
        send_file(p.as_str(), to.as_str()).await?;
    }

    handler.await?;
    Ok(())
}

async fn send_file(path: &str, addr: &str) -> io::Result<()> {
    // check if file is not exist then panic
    let file = File::open(path).await?;
    drop(file);

    connect_to_peer(addr, path).await?;
    Ok(())
}
