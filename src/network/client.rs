//! Client implementation for connecting to peers and initiating file transfers.

use crate::file_transfer::send::send_file;
use crate::network::io::read_message;
use crate::protocol::{Message, MessageType, serialize};
use crate::security::calculate_file_hash;
use log::{error, info};
use rand_core::OsRng;
use std::io;
use std::path::Path;
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
};
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Connects to a peer at the given address and sends a file.
///
/// This function performs the following steps:
/// 1. Establishes a TCP connection.
/// 2. Performs an ECDH handshake to establish a shared session key.
/// 3. Sends a file transfer request and waits for acceptance.
/// 4. If accepted, sends the file encrypted with the session key.
pub async fn connect_to_peer(addr: &str, file_path: &str) -> io::Result<()> {
    let mut stream = TcpStream::connect(addr).await?;
    info!("Connected to peer at {}", addr);

    let key = perform_handshake(&mut stream).await?;
    info!("Handshake complete, shared key established.");

    let response = send_request(&mut stream, file_path).await?;

    match response.msg_type {
        MessageType::Accept => {
            info!("Peer accepted request, sending file...");
            send_file(&mut stream, file_path, &key).await
        }
        MessageType::Reject => {
            error!("Peer rejected the file transfer.");
            Ok(())
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unexpected response: {:?}", other),
        )),
    }
}

/// Performs an ECDH (X25519) handshake over the stream to establish a shared 32-byte secret.
async fn perform_handshake(stream: &mut TcpStream) -> io::Result<[u8; 32]> {
    info!("Client starting handshake...");

    // Generate ephemeral keypair
    let sender_secret = EphemeralSecret::random_from_rng(OsRng);
    let sender_public = PublicKey::from(&sender_secret);

    // Send our public key
    let msg = Message::new(MessageType::KeyExchange {
        public_key: sender_public.to_bytes(),
    });
    stream.write_all(&serialize(&msg)).await?;

    // Receive peer's public key
    let response = read_message(stream).await?;
    let receiver_public = match response.msg_type {
        MessageType::KeyExchange { public_key } => PublicKey::from(public_key),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Expected KeyExchange response",
            ));
        }
    };

    // Compute shared secret
    let shared_secret = sender_secret.diffie_hellman(&receiver_public);
    info!("Client handshake finished.");

    Ok(shared_secret.to_bytes())
}

/// Sends a file transfer request to the peer.
async fn send_request(stream: &mut TcpStream, file_path: &str) -> io::Result<Message> {
    let path = Path::new(file_path);
    let metadata = std::fs::metadata(path)?;
    let hash = calculate_file_hash(path)?;

    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string());

    info!("Sending file request for '{}'...", file_name);
    let msg = Message::new(MessageType::Request {
        file_name,
        size: metadata.len(),
        hash,
    });
    stream.write_all(&serialize(&msg)).await?;

    // Wait for response (ACCEPT/REJECT)
    read_message(stream).await
}
