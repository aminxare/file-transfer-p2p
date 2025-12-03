//! File receiving utilities with decryption and ACK handling.

use crate::network::io::read_message;
use crate::protocol::{Message, MessageType, serialize};
use crate::security::decrypt;
use log::info;
use tokio::fs::File;
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt, BufWriter};

/// Receives a file and decrypts it using the given key.
pub async fn receive_file<S>(stream: &mut S, file_name: &str, key: &[u8; 32]) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let file = File::create(format!("recv_{file_name}")).await?;
    let mut file = BufWriter::new(file);

    loop {
        let msg = read_message(stream).await?;
        match msg.msg_type {
            MessageType::Chunk { offset, data } => {
                let decrypted = decrypt(&data, key).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "Decryption failed")
                })?;
                file.write_all(&decrypted).await?;
                let ack = Message {
                    version: 1,
                    msg_type: MessageType::Ack {
                        offset: offset + decrypted.len() as u64,
                    },
                };
                stream.write_all(&serialize(&ack)).await?;
            }
            MessageType::Complete => {
                info!("File received successfully: {file_name}");
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
