//! Low-level I/O utilities for the P2P protocol.
//!
//! This module provides functions to read and write framed messages over an async stream.

use crate::protocol::{Message, deserialize, HEADER_SIZE, MAGIC};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

/// Reads and deserializes a [`Message`] from an async stream.
///
/// This function first reads the fixed 9-byte header (Magic + Length),
/// then reads the JSON payload, and finally deserializes it.
///
/// # Errors
///
/// Returns an [`io::Error`] if the read fails, the magic bytes are invalid,
/// or deserialization fails.
pub async fn read_message<S>(stream: &mut S) -> io::Result<Message>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Read fixed header: 5 bytes magic + 4 bytes length (big-endian)
    let mut header = [0u8; HEADER_SIZE];
    if let Err(e) = stream.read_exact(&mut header).await {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Peer closed the connection before sending header",
            ));
        }
        return Err(e);
    }

    if &header[0..5] != MAGIC {
        let actual = String::from_utf8_lossy(&header[0..5]);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid magic header: expected 'MAGIC', got '{}' (bytes: {:?})", actual, &header[0..5]),
        ));
    }

    let len = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;

    // Combine for deserialization (protocol::deserialize expects the full frame)
    let mut frame = Vec::with_capacity(HEADER_SIZE + len);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&payload);

    deserialize(&frame).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}
