//! Handles serialization and deserialization of protocol messages
//! and provides helper functions for async read/write.

use crate::protocol::{Message, deserialize};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

/// Reads and deserializes a [`Message`] from an async stream.
pub async fn read_message<S>(stream: &mut S) -> io::Result<Message>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Read fixed header: 5 bytes magic + 4 bytes length (big-endian)
    let mut header = [0u8; 9];
    stream.read_exact(&mut header).await?;

    if &header[0..5] != b"MAGIC" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid magic header"));
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
