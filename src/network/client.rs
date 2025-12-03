use crate::network::io::{read_message, send};
use crate::protocol::{Message, MessageType, serialize};
use log::info;
use rand_core::OsRng;
use tokio::{
    io::{self, AsyncWriteExt},
    net::TcpStream,
};
use x25519_dalek::{EphemeralSecret, PublicKey};

// connect to another peer
pub async fn connect_to_peer(addr: &str, file_path: &str) -> io::Result<()> {
    let mut stream = TcpStream::connect(addr).await?;
    info!("Connected to peer at {}", addr);

    let key = perform_handshake(&mut stream).await?; // AES-256
    info!("Handshake complete, shared key established.");

    send(&mut stream, file_path, &key).await
}

async fn perform_handshake(stream: &mut TcpStream) -> io::Result<[u8; 32]> {
    info!("Client starting handshake...");

    // Generate sender keypair
    let sender_secret = EphemeralSecret::random_from_rng(OsRng);
    let sender_public = PublicKey::from(&sender_secret);

    // Send our public key
    let msg = Message {
        version: 1,
        msg_type: MessageType::KeyExchange {
            public_key: sender_public.to_bytes(),
        },
    };
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
    let key = shared_secret.to_bytes();
    info!("Client handshake finished.");

    Ok(key)
}
