//! Handles serialization and deserialization of protocol messages
//! and provides helper functions for async read/write.

use crate::file_transfer::send::send_file;
use crate::protocol::{Message, MessageType, deserialize, serialize};
use log::{error, info};
use std::fs::File;
use std::io;
use std::path::Path;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::{io::AsyncWriteExt, net::TcpStream};

/// Reads and deserializes a [`Message`] from an async stream.
pub async fn read_message<S>(stream: &mut S) -> io::Result<Message>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Read fixed header: 5 bytes magic + 4 bytes length (big-endian)
    let mut header = [0u8; 9];
    stream.read_exact(&mut header).await?;

    if &header[0..5] != b"MAGIC" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid magic header",
        ));
    }

    let len = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;

    let mut frame = Vec::with_capacity(9 + len);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&payload);

    deserialize(&frame)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Failed to deserialize message"))
}

async fn send_request(stream: &mut TcpStream, file_path: &str) -> io::Result<Message> {
    let path = Path::new(file_path);
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    let hash = "dummy_hash".to_string(); // TODO: Replace with SHA-256

    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string());

    // Send REQUEST
    info!("Sending file request...");
    let msg = Message {
        version: 1,
        msg_type: MessageType::Request {
            file_name,
            size: metadata.len(),
            hash,
        },
    };
    stream.write_all(&serialize(&msg)).await?;

    // Wait for response (ACCEPT/REJECT)
    let response = read_message(stream).await?;
    Ok(response)
}

pub async fn send(stream: &mut TcpStream, file_path: &str, key: &[u8; 32]) -> io::Result<()> {
    let response = send_request(stream, file_path).await?;

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
