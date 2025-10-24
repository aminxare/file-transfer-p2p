use crate::protocol::{Message, MessageType, deserialize, serialize};
use crate::security::{decrypt, encrypt};
use log::{debug, error, info, warn};
use rand_core::OsRng;
use rustls::RootCertStore;
use rustls::{
    ClientConfig, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use x25519_dalek::{EphemeralSecret, PublicKey};

// Configure TLS server
fn load_server_config() -> io::Result<Arc<ServerConfig>> {
    let cert_file = &mut BufReader::new(File::open("cert.pem")?);
    let key_file = &mut BufReader::new(File::open("key.pem")?);

    let certs = certs(cert_file)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(CertificateDer::from)
        .collect();

    let mut keys = pkcs8_private_keys(key_file).collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from(
        keys.pop()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "No private key found"))?,
    );

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    Ok(Arc::new(config))
}

fn load_client_config() -> io::Result<Arc<ClientConfig>> {
    let cert_file = &mut BufReader::new(File::open("cert.pem")?);
    let mut root_store = RootCertStore::empty();

    let certs = certs(cert_file)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(CertificateDer::from);

    for cert in certs {
        root_store
            .add(cert)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(Arc::new(config))
}

// start listening to get data
pub async fn start_listener(port: u16) -> io::Result<()> {
    // let config = load_server_config()?;
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    // let acceptor = tokio_rustls::TlsAcceptor::from(config);

    loop {
        let (stream, addr) = listener.accept().await?;
        // let acceptor = acceptor.clone();

        tokio::spawn(async move {
            // let stream = acceptor
            //     .accept(stream)
            //     .await
            //     .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
            //     .into();
            handle_connection(stream, addr.to_string())
                .await
                .unwrap_or_else(|e| {
                    error!("Error handling connection from {}: {}", addr, e);
                });
            Ok::<_, io::Error>(())
        });
    }
}

// connect to another peer
pub async fn connect_to_peer(addr: &str, file_path: &str) -> io::Result<()> {
    // let config = load_client_config()?;
    let mut stream = TcpStream::connect(addr).await?;
    // let server_name = rustls::pki_types::ServerName::try_from("localhost")
    //     .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // let connector = tokio_rustls::TlsConnector::from(config);
    // let mut stream = connector.connect(server_name, stream).await?;

    // produce key pair sender
    info!("client started handshaking...");
    let sender_secret = EphemeralSecret::random_from_rng(OsRng);
    let sender_public = PublicKey::from(&sender_secret);
    let msg = Message {
        version: 1,
        msg_type: MessageType::KeyExchange {
            public_key: sender_public.to_bytes(),
        },
    };
    stream.write_all(&serialize(&msg)).await?;

    // wait for recieve public key reciever
    let response = read_message(&mut stream).await?;
    let receiver_public = if let MessageType::KeyExchange { public_key } = response.msg_type {
        PublicKey::from(public_key)
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Expected KeyExchange",
        ));
    };

    // calculate shared secrect
    let shared_secret = sender_secret.diffie_hellman(&receiver_public);
    let key: [u8; 32] = shared_secret.to_bytes(); // AES-256
    info!("client end handshaking...");

    // send REQUEST message
    let file = File::open(file_path)?;
    let metadata = file.metadata()?;
    let hash = "dummy_hash".to_string(); // TODO: real SHA-256
    let msg = Message {
        version: 1,
        msg_type: MessageType::Request {
            file_name: file_path.to_string(),
            size: metadata.len(),
            hash,
        },
    };
    info!("client started sending REQUEST.");
    let data = serialize(&msg);
    stream.write_all(&data).await?;

    // wait for answer (ACCEPT/REJECT)
    let response = read_message(&mut stream).await?;
    info!("client end sending REQUEST.");
    match response.msg_type {
        MessageType::Accept => send_file(&mut stream, file_path, &key).await,
        MessageType::Reject => Ok(error!("Peer rejected the file transfer")),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unexpected response",
        )),
    }
}

// read message from stream
async fn read_message<S>(stream: &mut S) -> io::Result<Message>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf: Vec<u8> = Vec::new();
    let size = 4096;
    loop {
        let mut buffer = vec![0u8; size];
        let n = stream.read(&mut buffer).await?;
        println!("{n}");
        // EOF
        if n == 0 || n < size {
            buf.append(&mut buffer);
            break;
        }
        buf.append(&mut buffer);
    }
    
    deserialize(&buf)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Failed to deserialize message"))
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
                info!("server start handshaking.");
                // clear previous key
                key.fill(0);
                // produce key pair receiver
                let receiver_secret = EphemeralSecret::random_from_rng(OsRng);
                let receiver_public = PublicKey::from(&receiver_secret);
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
                info!("server end handshaking");

                continue; // wait for next message like REQUEST
            }
            MessageType::Request {
                file_name,
                size,
                hash,
            } => {
                // TODO: ask user for accept from CLI
                info!(
                    "Received file request from {}: {} ({} bytes)",
                    addr, file_name, size
                );
                let response = Message {
                    version: 1,
                    msg_type: MessageType::Accept, // TODO: get from user
                };
                // sending REQUEST result
                stream.write_all(&serialize(&response)).await?;
                // receive file if REQUEST accepted!
                return receive_file(&mut stream, &file_name, &hash, &key).await;
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


// send file
async fn send_file<S>(stream: &mut S, file_path: &str, key: &[u8; 32]) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut file = File::open(file_path)?;
    let mut buffer = vec![0u8; 4096]; // chunk 4kb
    let mut offset = 0;

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            // end of file
            let msg = Message {
                version: 1,
                msg_type: MessageType::Complete,
            };
            stream.write_all(&serialize(&msg)).await?;
            info!("file has been sent!");
            break;
        }
        let chunk = &buffer[..n];
        let encrypted = encrypt(chunk, key).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Failed to encrypt data: {e}"))
        })?;
        info!("chunk len: {}", chunk.len());
        info!("encrypted len: {}", encrypted.len());
        let msg = Message {
            version: 1,
            msg_type: MessageType::Chunk {
                offset,
                data: encrypted,
            },
        };

        stream.write_all(&serialize(&msg)).await?;
        offset += n as u64;

        // waiting for receive ACK message
        let response = read_message(stream).await?;
        if let MessageType::Ack { offset: ack_offset } = response.msg_type {
            if ack_offset != offset {
                info!("Invalid ack");
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid ACK offset",
                ));
            }
        } else if let MessageType::Cancel = response.msg_type {
            info!("Transfer cancelled by peer");
            return Ok(());
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected response",
            ));
        }
    }
    Ok(())
}

// recieve file
async fn receive_file(
    // stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    stream: &mut TcpStream,
    file_name: &str,
    _expected_hash: &str,
    key: &[u8; 32],
) -> io::Result<()> {
    let mut file = File::create(format!("recieve_{}", file_name))?;
    loop {
        let msg = read_message(stream).await?;
        info!("|||||||||||||||||||||||||||||||||||||||||||");
        match msg.msg_type {
            MessageType::Chunk { offset, data } => {
                let decrypted = decrypt(&data, &key).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "Decryption failed")
                })?;
                file.write_all(&decrypted)?;
                let ack = Message {
                    version: 1,
                    msg_type: MessageType::Ack {
                        offset: offset + decrypted.len() as u64,
                    },
                };
                stream.write_all(&serialize(&ack)).await?;
            }
            MessageType::Complete => {
                // TODO: check file hash
                info!("File received: {}", file_name);
                break;
            }
            MessageType::Cancel => {
                info!("Transfer cancelled by sender");
                break;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unexpected message",
                ));
            }
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

        fs::write("test.txt", "Hello").unwrap(); // فایل تست
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
