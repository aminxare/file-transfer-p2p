//! File sending utilities with encryption and message-based transport.

use crate::network::io::read_message;
use crate::protocol::{Message, MessageType, serialize};
use crate::security::encrypt;
use log::{info, error};
use std::io;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// Sends a file through the given stream, encrypted with the provided key.
///
/// The file is read in chunks, each chunk is encrypted and sent as a [`MessageType::Chunk`].
/// After each chunk, it waits for an [`MessageType::Ack`] from the receiver.
///
/// # Errors
///
/// Returns an [`io::Error`] if file reading, encryption, or network communication fails.
pub async fn send_file<S>(stream: &mut S, file_path: &str, key: &[u8; 32]) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let file = File::open(file_path).await?;
    let mut file = BufReader::new(file);
    let mut buffer = vec![0u8; 262_144]; // 256KB buffer
    let mut offset = 0;

    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            // EOF reached
            let msg = Message::new(MessageType::Complete);
            stream.write_all(&serialize(&msg)).await?;
            info!("File sent successfully!");
            break;
        }

        let chunk = &buffer[..n];
        let encrypted = encrypt(chunk, key)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption failed: {}", e)))?;

        let msg = Message::new(MessageType::Chunk {
            offset,
            data: encrypted,
        });

        stream.write_all(&serialize(&msg)).await?;
        
        // Wait for ACK
        let response = read_message(stream).await?;
        match response.msg_type {
            MessageType::Ack { offset: ack_offset } => {
                let expected_offset = offset + n as u64;
                if ack_offset != expected_offset {
                    error!("Received ACK for wrong offset: expected {}, got {}", expected_offset, ack_offset);
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "ACK offset mismatch"));
                }
                offset = ack_offset;
            }
            MessageType::Cancel => {
                info!("Transfer cancelled by peer");
                return Ok(());
            }
            other => {
                error!("Unexpected response during file transfer: {:?}", other);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unexpected response",
                ));
            }
        }
    }

    Ok(())
}
