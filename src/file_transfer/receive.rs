//! File receiving utilities with decryption and ACK handling.

use crate::network::io::read_message;
use crate::protocol::{Message, MessageType, serialize};
use crate::security::decrypt;
use indicatif::{ProgressBar, ProgressStyle};
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
pub async fn receive_file<S>(
    stream: &mut S,
    file_name: &str,
    file_size: u64,
    key: &[u8; 32],
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let out_path = format!("recv_{}", file_name);
    let file = File::create(&out_path).await?;
    let mut file = BufWriter::new(file);

    let pb = ProgressBar::new(file_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta}) {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );

    let mut received_bytes = 0u64;

    loop {
        let msg = read_message(stream).await?;
        match msg.msg_type {
            MessageType::Chunk { offset, data } => {
                let decrypted = decrypt(&data, key).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("Decryption failed: {}", e))
                })?;

                file.write_all(&decrypted).await?;
                received_bytes += decrypted.len() as u64;
                pb.set_position(received_bytes);

                let ack = Message::new(MessageType::Ack {
                    offset: offset + decrypted.len() as u64,
                });
                stream.write_all(&serialize(&ack)).await?;
            }
            MessageType::Complete => {
                file.flush().await?;
                pb.finish_with_message("File received successfully!");
                info!("File received successfully: {}", out_path);
                break;
            }
            MessageType::Cancel => {
                pb.abandon_with_message("Transfer cancelled by sender");
                info!("Transfer cancelled by sender");
                break;
            }
            other => {
                error!("Unexpected message during file receipt: {:?}", other);
                pb.abandon();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unexpected message",
                ));
            }
        }
    }

    Ok(())
}
