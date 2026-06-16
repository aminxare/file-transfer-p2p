//! Protocol definitions and serialization for the P2P file transfer.
//!
//! This module defines the [`Message`] structure and the various [`MessageType`]s
//! used in the communication between peers.

use serde::{Deserialize, Serialize};
use std::fmt;

/// The Magic bytes used to identify the protocol frames.
pub const MAGIC: &[u8; 5] = b"MAGIC";
/// The length of the frame header (Magic + 4 bytes length).
pub const HEADER_SIZE: usize = 9;

/// Custom error type for protocol operations.
#[derive(Debug)]
pub enum ProtocolError {
    /// The message header is invalid (wrong magic bytes).
    InvalidMagic,
    /// The payload length does not match the header.
    LengthMismatch { expected: usize, actual: usize },
    /// Failed to serialize the message to JSON.
    SerializationError(String),
    /// Failed to deserialize the message from JSON.
    DeserializationError(String),
    /// The payload is not valid UTF-8.
    Utf8Error(std::str::Utf8Error),
}

impl std::error::Error for ProtocolError {}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "Invalid magic header"),
            Self::LengthMismatch { expected, actual } => {
                write!(f, "Length mismatch: expected {}, got {}", expected, actual)
            }
            Self::SerializationError(e) => write!(f, "Serialization error: {}", e),
            Self::DeserializationError(e) => write!(f, "Deserialization error: {}", e),
            Self::Utf8Error(e) => write!(f, "UTF-8 error: {}", e),
        }
    }
}

/// A Result type specialized for protocol operations.
pub type Result<T> = std::result::Result<T, ProtocolError>;

/// Represents the different types of messages in the protocol.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum MessageType {
    /// Request to send a file.
    Request {
        /// The name of the file.
        file_name: String,
        /// Total size of the file in bytes.
        size: u64,
        /// SHA-256 hash of the file (for integrity verification).
        hash: String,
    },
    /// Accept a file transfer request.
    Accept,
    /// Reject a file transfer request.
    Reject,
    /// Cancel an ongoing transfer.
    Cancel,
    /// Exchange public keys for ECDH.
    KeyExchange {
        /// The X25519 public key.
        public_key: [u8; 32],
    },
    /// A chunk of file data.
    Chunk {
        /// The offset in the original file.
        offset: u64,
        /// The encrypted data.
        data: Vec<u8>,
    },
    /// Acknowledgment of a received chunk.
    Ack {
        /// The offset up to which data has been received.
        offset: u64,
    },
    /// Signifies that the file transfer is complete.
    Complete,
    /// An error message.
    Error {
        /// Descriptive error message.
        message: String,
    },
}

/// A protocol message containing a version and a type.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Message {
    /// Protocol version (currently 1).
    pub version: u32,
    /// The specific message payload.
    pub msg_type: MessageType,
}

impl Message {
    /// Creates a new message with version 1.
    pub fn new(msg_type: MessageType) -> Self {
        Self {
            version: 1,
            msg_type,
        }
    }
}

/// Serializes a [`Message`] into a framed byte vector.
///
/// The frame format is: `MAGIC` (5 bytes) + `length` (4 bytes, Big-Endian) + `JSON payload`.
pub fn serialize(msg: &Message) -> Vec<u8> {
    let json = serde_json::to_vec(msg).expect("Failed to serialize message to JSON");
    let len = json.len() as u32;

    let mut frame = Vec::with_capacity(HEADER_SIZE + json.len());
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&json);
    frame
}

/// Deserializes a [`Message`] from a framed byte slice.
///
/// # Errors
///
/// Returns [`ProtocolError`] if the magic bytes are wrong, the length is invalid,
/// or the JSON payload cannot be parsed.
pub fn deserialize(data: &[u8]) -> Result<Message> {
    if data.len() < HEADER_SIZE {
        return Err(ProtocolError::LengthMismatch {
            expected: HEADER_SIZE,
            actual: data.len(),
        });
    }

    if &data[0..5] != MAGIC {
        return Err(ProtocolError::InvalidMagic);
    }

    let payload_len = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;
    let payload = &data[HEADER_SIZE..];

    if payload.len() != payload_len {
        return Err(ProtocolError::LengthMismatch {
            expected: payload_len,
            actual: payload.len(),
        });
    }

    serde_json::from_slice(payload).map_err(|e| ProtocolError::DeserializationError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_deserialize() {
        let msg = Message::new(MessageType::Request {
            file_name: "test.txt".to_string(),
            size: 1024,
            hash: "abc123".to_string(),
        });
        let bytes = serialize(&msg);
        let deserialized = deserialize(&bytes).unwrap();
        assert_eq!(msg, deserialized);
    }

    #[test]
    fn test_invalid_magic() {
        let mut bytes = serialize(&Message::new(MessageType::Accept));
        bytes[0] = b'X';
        assert!(matches!(deserialize(&bytes), Err(ProtocolError::InvalidMagic)));
    }

    #[test]
    fn test_length_mismatch() {
        let mut bytes = serialize(&Message::new(MessageType::Accept));
        bytes.pop(); // Remove one byte from payload
        assert!(matches!(
            deserialize(&bytes),
            Err(ProtocolError::LengthMismatch { .. })
        ));
    }
}
