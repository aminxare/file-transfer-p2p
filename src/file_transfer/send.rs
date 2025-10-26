//! File sending utilities with encryption and message-based transport.

use crate::network::io::read_message;
use crate::protocol::{Message, MessageType, serialize};
use crate::security::encrypt;
use log::info;
use std::fs::File;
use std::io::{self, Read};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// Sends a file through the given stream, encrypted with the provided key.
pub async fn send_file<S>(stream: &mut S, file_path: &str, key: &[u8; 32]) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut file = File::open(file_path)?;
    let mut buffer = vec![0u8; 4096];
    let mut offset = 0;

    loop {
        let n = file.read(&mut buffer)?;
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
