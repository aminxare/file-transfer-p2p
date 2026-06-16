//! File receiving utilities with decryption and ACK handling.

use crate::network::io::read_message;
use crate::protocol::{Message, MessageType, serialize};
use crate::security::decrypt;
use log::{info, error};
use tokio::fs::File;
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt, BufWriter};

/// Receives a file and decrypts it using the given key.
///
/// This function listens for [`MessageType::Chunk`] messages, decrypts the data,
/// writes it to a file, and sends back an [`MessageType::Ack`].
///
/// # Errors
///
/// Returns an [`io::Error`] if decryption fails, file writing fails, or network communication fails.
pub async fn receive_file<S>(stream: &mut S, file_name: &str, key: &[u8; 32]) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let out_path = format!("recv_{}", file_name);
    let file = File::create(&out_path).await?;
    let mut file = BufWriter::new(file);

    loop {
        let msg = read_message(stream).await?;
        match msg.msg_type {
            MessageType::Chunk { offset, data } => {
                let decrypted = decrypt(&data, key)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Decryption failed: {}", e)))?;
                
                file.write_all(&decrypted).await?;
                
                let ack = Message::new(MessageType::Ack {
                    offset: offset + decrypted.len() as u64,
                });
                stream.write_all(&serialize(&ack)).await?;
            }
            MessageType::Complete => {
                file.flush().await?;
                info!("File received successfully: {}", out_path);
                break;
            }
            MessageType::Cancel => {
                info!("Transfer cancelled by sender");
                break;
            }
            other => {
                error!("Unexpected message during file receipt: {:?}", other);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unexpected message",
                ));
            }
        }
    }

    Ok(())
}
