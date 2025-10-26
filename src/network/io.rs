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
    let mut buf: Vec<u8> = Vec::new();
    let size = 4096;
    loop {
        let mut buffer = vec![0u8; size];
        let n = stream.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&buffer[..n]);
        if n < size {
            break;
        }
    }

    deserialize(&buf)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Failed to deserialize message"))
}
