//! File sending utilities with encryption and message-based transport.

use crate::network::io::read_message;
use crate::protocol::{Message, MessageType, serialize};
use crate::security::encrypt;
use log::info;
use std::io;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::io::{AsyncReadExt, BufReader};

/// Sends a file through the given stream, encrypted with the provided key.
pub async fn send_file<S>(stream: &mut S, file_path: &str, key: &[u8; 32]) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let file = File::open(file_path).await?;
    let mut file = BufReader::new(file);
    let mut buffer = vec![0u8; 262_144];
    let mut offset = 0;

    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            stream
                .write_all(&serialize(&Message {
                    version: 1,
                    msg_type: MessageType::Complete,
                }))
                .await?;
            info!("File sent successfully!");
            break;
        }

        let chunk = &buffer[..n];
        let encrypted =
            encrypt(chunk, key).map_err(|e| io::Error::other(format!("Encryption failed: {e}")))?;

        let msg = Message {
            version: 1,
            msg_type: MessageType::Chunk {
                offset,
                data: encrypted,
            },
        };

        stream.write_all(&serialize(&msg)).await?;
        offset += n as u64;

        let response = read_message(stream).await?;
        match response.msg_type {
            MessageType::Ack { offset: ack_offset } if ack_offset == offset => (),
            MessageType::Cancel => {
                info!("Transfer cancelled by peer");
                return Ok(());
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unexpected response",
                ));
            }
        }
    }

    Ok(())
}
