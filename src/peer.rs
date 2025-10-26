use crate::file_transfer::receive::receive_file;
use crate::file_transfer::send::send_file;
use crate::network::io::read_message;
use crate::protocol::{Message, MessageType, serialize};
use log::{error, info, warn};
use rand_core::OsRng;
use std::fs::File;
use tokio::{
    io::{self, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use x25519_dalek::{EphemeralSecret, PublicKey};

// start listening to get data
pub async fn start_listener(port: u16) -> io::Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;

    loop {
        let (stream, addr) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, addr.to_string()).await {
                error!("Error handling connection from {}: {}", addr, e);
            }
        });
    }
}

// connect to another peer
pub async fn connect_to_peer(addr: &str, file_path: &str) -> io::Result<()> {
    let mut stream = TcpStream::connect(addr).await?;
    info!("Connected to peer at {}", addr);

    let key = perform_handshake(&mut stream).await?; // AES-256
    info!("Handshake complete, shared key established.");

    send_file_request_and_transfer(&mut stream, file_path, &key).await
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

async fn send_file_request_and_transfer(
    stream: &mut TcpStream,
    file_path: &str,
    key: &[u8; 32],
) -> io::Result<()> {
    let file = File::open(file_path)?;
    let metadata = file.metadata()?;
    let hash = "dummy_hash".to_string(); // TODO: Replace with SHA-256

    // Send REQUEST
    info!("Sending file request...");
    let msg = Message {
        version: 1,
        msg_type: MessageType::Request {
            file_name: file_path.to_string(),
            size: metadata.len(),
            hash,
        },
    };
    stream.write_all(&serialize(&msg)).await?;

    // Wait for response (ACCEPT/REJECT)
    let response = read_message(stream).await?;
    match response.msg_type {
        MessageType::Accept => {
            info!("Peer accepted request, sending file...");
            send_file(stream, file_path, key).await
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

// handle incoming connections
async fn handle_connection(
    // mut stream: tokio_rustls::server::TlsStream<TcpStream>,
    mut stream: TcpStream,
    addr: String,
) -> io::Result<()> {
    let mut key = [0u8; 32];
    loop {
        let msg = read_message(&mut stream).await?;

        match msg.msg_type {
            MessageType::KeyExchange { public_key } => {
                info!("Server start handshaking...");
                // clear previous key
                key.fill(0);

                // Generate receiver keypair
                let receiver_secret = EphemeralSecret::random_from_rng(OsRng);
                let receiver_public = PublicKey::from(&receiver_secret);

                // Send our public key
                let response = Message {
                    version: 1,
                    msg_type: MessageType::KeyExchange {
                        public_key: receiver_public.to_bytes(),
                    },
                };
                stream.write_all(&serialize(&response)).await?;

                // calculate shared secret
                let sender_public = PublicKey::from(public_key);
                let shared_secret = receiver_secret.diffie_hellman(&sender_public);
                key.copy_from_slice(shared_secret.to_bytes().as_slice());
                info!("Server handshake complete.");
            }
            MessageType::Request {
                file_name, size, ..
            } => {
                info!(
                    "Received file request from {}: {} ({} bytes)",
                    addr, file_name, size
                );

                // TODO: ask user for permission instead of auto-accept
                let response = Message {
                    version: 1,
                    msg_type: MessageType::Accept, // TODO: get from user
                };

                stream.write_all(&serialize(&response)).await?;
                return receive_file(&mut stream, &file_name, &key).await;
            }
            MessageType::Cancel => {
                info!("Transfer cancelled by {}", addr);
                break;
            }
            _ => warn!("Unhandled message type from {}", addr),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn test_key_exchange() {
        let sender_secret = EphemeralSecret::random_from_rng(OsRng);
        let sender_public = PublicKey::from(&sender_secret);
        let receiver_secret = EphemeralSecret::random_from_rng(OsRng);
        let receiver_public = PublicKey::from(&receiver_secret);
        let sender_shared = sender_secret.diffie_hellman(&receiver_public);
        let receiver_shared = receiver_secret.diffie_hellman(&sender_public);
        assert_eq!(sender_shared.to_bytes(), receiver_shared.to_bytes());
    }

    // TODO: use tmp file
    #[tokio::test]
    async fn test_connect_and_send_request() {
        let port = 8081;

        tokio::spawn(async move {
            start_listener(port).await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        fs::write("test.txt", "Hello").unwrap();
        let result = timeout(
            Duration::from_secs(2),
            connect_to_peer("127.0.0.1:8081", "test.txt"),
        )
        .await;
        assert!(result.is_ok(), "Failed to connect and send request");
        fs::remove_file("test.txt").unwrap();
    }

    #[tokio::test]
    async fn test_receive_file() {
        let port = 8083;

        tokio::spawn(async move {
            start_listener(port).await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(100)).await;

        fs::write("send_test.txt", "Hello, world!").unwrap();

        let result = timeout(
            Duration::from_secs(2),
            connect_to_peer("127.0.0.1:8083", "send_test.txt"),
        )
        .await;
        assert!(result.is_ok(), "Failed to send file");

        let received = fs::read_to_string("send_test.txt").unwrap();
        assert_eq!(received, "Hello, world!");

        fs::remove_file("send_test.txt").unwrap();
    }
}
