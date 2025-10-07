use crate::protocol::{Message, MessageType, deserialize, serialize};
use crate::security::{decrypt, encrypt, generate_key};
use rustls::RootCertStore;
use rustls::{
    ClientConfig, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::TlsStream;

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
    let config = load_server_config()?;
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    let acceptor = tokio_rustls::TlsAcceptor::from(config);

    loop {
        let (stream, addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        
        // BUG: 
        // SECURITY FLAW/BUG: The **key must be provided** by the file sender. 
        // Local key generation is a **temporary test measure** and **must not be used** in real scenarios.
        let key = generate_key().expect("fail to generate key");
        
        tokio::spawn(async move {
            let stream: TlsStream<TcpStream> = acceptor
                .accept(stream)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
                .into();
            handle_connection(stream, addr.to_string(), &key)
                .await
                .unwrap_or_else(|e| {
                    eprintln!("Error handling connection from {}: {}", addr, e);
                });
            Ok::<_, io::Error>(())
        });
    }
}

// connect to another peer
pub async fn connect_to_peer(addr: &str, key: &[u8; 32], file_path: &str) -> io::Result<()> {
    let config = load_client_config()?;
    let stream = TcpStream::connect(addr).await?;
    let server_name = rustls::pki_types::ServerName::try_from("localhost")
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let mut stream: TlsStream<TcpStream> = connector.connect(server_name, stream).await?.into();

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
    let data = serialize(&msg);
    stream.write_all(&data).await?;

    // wait for answer (ACCEPT/REJECT)
    let response = read_message(&mut stream).await?;
    match response.msg_type {
        MessageType::Accept => send_file(&mut stream, file_path, key).await,
        MessageType::Reject => Ok(println!("Peer rejected the file transfer")),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unexpected response",
        )),
    }
}

// read message from stream
async fn read_message(stream: &mut TlsStream<TcpStream>) -> io::Result<Message> {
    let mut buffer = vec![0u8; 1024];
    let n = stream.read(&mut buffer).await?;
    deserialize(&buffer[..n])
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Failed to deserialize message"))
}

// handle incoming connections
async fn handle_connection(
    mut stream: TlsStream<TcpStream>,
    addr: String,
    key: &[u8; 32],
) -> io::Result<()> {
    loop {
        let msg = read_message(&mut stream).await?;
        match msg.msg_type {
            MessageType::Request {
                file_name,
                size,
                hash,
            } => {
                // TODO: ask user for accept from CLI
                println!(
                    "Received file request from {}: {} ({} bytes)",
                    addr, file_name, size
                );
                let response = Message {
                    version: 1,
                    msg_type: MessageType::Accept, // TODO: get from user
                };
                stream.write_all(&serialize(&response)).await?;
                receive_file(&mut stream, &file_name, &hash, key).await?;
            }
            MessageType::Cancel => {
                println!("Transfer cancelled by {}", addr);
                break;
            }
            _ => println!("Unhandled message type from {}", addr),
        }
    }
    Ok(())
}

// send file
async fn send_file(
    stream: &mut TlsStream<TcpStream>,
    file_path: &str,
    key: &[u8; 32],
) -> io::Result<()> {
    let mut file = File::open(file_path)?;
    let mut buffer = vec![0u8; 4096]; // chunkهای 4KB
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
            break;
        }
        let chunk = &buffer[..n];
        let encrypted = encrypt(chunk, key).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Failed to encrypt data: {e}"))
        })?;
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
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid ACK offset",
                ));
            }
        } else if let MessageType::Cancel = response.msg_type {
            return Ok(println!("Transfer cancelled by peer"));
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
    stream: &mut TlsStream<TcpStream>,
    file_name: &str,
    _expected_hash: &str,
    key: &[u8; 32],
) -> io::Result<()> {
    let mut file = File::create(file_name)?;
    loop {
        let msg = read_message(stream).await?;
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
                println!("File received: {}", file_name);
                break;
            }
            MessageType::Cancel => {
                println!("Transfer cancelled by sender");
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
    use tokio::time::{timeout, Duration};
    use std::fs;

    #[tokio::test]
    async fn test_connect_and_send_request() {
        let port = 8081;
        let key = generate_key().unwrap();
        
        // شروع listener در پس‌زمینه
        tokio::spawn(async move {
            start_listener(port).await.unwrap();
        });
        
        // صبر برای شروع listener
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // تست اتصال و ارسال REQUEST
        fs::write("test.txt", "Hello").unwrap(); // فایل تست
        let result = timeout(Duration::from_secs(2), connect_to_peer("127.0.0.1:8081", &key, "test.txt")).await;
        assert!(result.is_ok(), "Failed to connect and send request");
        fs::remove_file("test.txt").unwrap();
    }

    #[tokio::test]
    async fn test_handle_invalid_message() {
        let port = 8082;
        tokio::spawn(async move {
            start_listener(port).await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let config = load_client_config().unwrap();
        let stream = TcpStream::connect("127.0.0.1:8082").await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let connector = tokio_rustls::TlsConnector::from(config);
        let mut stream = connector.connect(server_name, stream).await.unwrap();
        
        // ارسال پیام نامعتبر
        stream.write_all(b"INVALID").await.unwrap();
        // صبر برای اطمینان از اینکه اتصال بسته نشده
        tokio::time::sleep(Duration::from_millis(100)).await;
        // تست اینکه stream هنوز قابل نوشتنه
        let result = stream.write_all(b"PING").await;
        assert!(result.is_ok(), "Stream is not writable after invalid message");
    }

    #[tokio::test]
    async fn test_receive_file() {
        let port = 8083;
        let key = generate_key().unwrap();
        
        // شروع listener در پس‌زمینه
        tokio::spawn(async move {
            start_listener(port).await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // ایجاد فایل تست
        fs::write("send_test.txt", "Hello, world!").unwrap();
        
        // اتصال و ارسال فایل
        let result = timeout(Duration::from_secs(2), connect_to_peer("127.0.0.1:8083", &key, "send_test.txt")).await;
        assert!(result.is_ok(), "Failed to send file");
        
        // بررسی فایل دریافت‌شده
        let received = fs::read_to_string("send_test.txt").unwrap();
        assert_eq!(received, "Hello, world!");
        
        // پاک‌سازی
        fs::remove_file("send_test.txt").unwrap();
    }
}