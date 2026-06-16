//! Listener implementation for receiving connections from peers.

use crate::file_transfer::receive::receive_file;
use crate::network::io::read_message;
use crate::protocol::{Message, MessageType, serialize};
use log::{error, info, warn};
use rand_core::OsRng;
use tokio::{
    io::{self, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Starts a TCP listener on the specified port.
///
/// For each incoming connection, it spawns a new task to handle the file transfer protocol.
pub async fn start_listener(port: u16) -> io::Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    info!("Listening on 0.0.0.0:{}", port);

    loop {
        let (stream, addr) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, addr.to_string()).await {
                error!("Error handling connection from {}: {}", addr, e);
            }
        });
    }
}

/// Handles an incoming peer connection.
///
/// This function performs the handshake and handles protocol messages (KeyExchange, Request, etc.).
async fn handle_connection(
    mut stream: TcpStream,
    addr: String,
) -> io::Result<()> {
    let mut key = [0u8; 32];
    loop {
        let msg = read_message(&mut stream).await?;

        match msg.msg_type {
            MessageType::KeyExchange { public_key } => {
                info!("Server starting handshake with {}...", addr);
                // Clear previous key if any
                key.fill(0);

                // Generate ephemeral keypair
                let receiver_secret = EphemeralSecret::random_from_rng(OsRng);
                let receiver_public = PublicKey::from(&receiver_secret);

                // Send our public key
                let response = Message::new(MessageType::KeyExchange {
                    public_key: receiver_public.to_bytes(),
                });
                stream.write_all(&serialize(&response)).await?;

                // Calculate shared secret
                let sender_public = PublicKey::from(public_key);
                let shared_secret = receiver_secret.diffie_hellman(&sender_public);
                key.copy_from_slice(shared_secret.to_bytes().as_slice());
                info!("Handshake complete with {}.", addr);
            }
            MessageType::Request {
                file_name, size, ..
            } => {
                info!(
                    "Received file request from {}: {} ({} bytes)",
                    addr, file_name, size
                );

                // TODO: Implement user prompt for acceptance
                let response = Message::new(MessageType::Accept);

                stream.write_all(&serialize(&response)).await?;
                return receive_file(&mut stream, &file_name, &key).await;
            }
            MessageType::Cancel => {
                info!("Transfer cancelled by {}", addr);
                break;
            }
            _ => warn!("Unhandled message type from {}: {:?}", addr, msg.msg_type),
        }
    }
    Ok(())
}
