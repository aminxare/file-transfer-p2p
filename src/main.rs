use clap::Parser;
use log::{error, info};
use tokio::{fs::File, io, spawn};

use ft::network::{client::connect_to_peer, listener::start_listener};

#[derive(Parser)]
#[command(
    version = "0.1.0",
    about = "P2P file transfer application",
    long_about = "A peer-to-peer file transfer tool with TLS and encryption.\n\
                   Usage examples:\n\
                   - Start listener: cargo run -- --port 8081\n\
                   - Send file: cargo run -- --file test.txt --to 127.0.0.1:8081"
)]
struct Args {
    #[arg(short, long, help = "Port to listen on")]
    port: Option<u16>,
    #[arg(
        short,
        long,
        help = "Address of peer to send file to (e.g., 127.0.0.1:8081)"
    )]
    address: Option<String>,
    #[arg(short, long, help = "Path to file to send")]
    file: Option<String>,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    simple_logger::init().unwrap();
    let args = Args::parse();

    // send file
    if let (Some(file_path), Some(address)) = (args.file, args.address) {
        info!("Sending file: {} to: {}", file_path, address);
        send_file(file_path.as_str(), address.as_str()).await?;
    }

    // start listener
    if let Some(port) = args.port {
        let _handler = spawn(async move {
            info!("server started listening on port: {}", port);

            if let Err(e) = start_listener(port).await {
                error!("Listener error: {e}");
            }
        });
        // We don't necessarily want to wait for the handler if we are also sending a file in the same process,
        // but typically it's one or the other. If it's a listener, it should run forever.
        // For simplicity in CLI, we wait if port is provided.
        tokio::signal::ctrl_c().await?;
        info!("Shutting down...");
    }

    Ok(())
}

async fn send_file(path: &str, addr: &str) -> io::Result<()> {
    // check if file exists
    let _file = File::open(path).await?;
    connect_to_peer(addr, path).await?;
    Ok(())
}
