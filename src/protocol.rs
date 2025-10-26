use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum MessageType {
    Request {
        file_name: String,
        size: u64,
        hash: String,
    },
    Accept,
    Reject,
    Cancel,
    KeyExchange {
        public_key: [u8; 32],
    },
    Chunk {
        offset: u64,
        data: Vec<u8>,
    },
    Ack {
        offset: u64,
    },
    Complete,
    Error {
        message: String,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Message {
    pub version: u32,
    pub msg_type: MessageType,
}

pub fn serialize(msg: &Message) -> Vec<u8> {
    let json = serde_json::to_string(msg).unwrap();
    let mut bytes = json.into_bytes();
    let len = bytes.len() as u32;
    
    let mut header = b"MAGIC".to_vec(); // 5 bytes magic
    header.extend_from_slice(&len.to_be_bytes()); // 4 bytes length
    header.append(&mut bytes);
    header
}

pub fn deserialize(data: &[u8]) -> Option<Message> {
    if data.len() < 9 || &data[0..5] != b"MAGIC" {
        return None;
    }
    let len = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;
    let mut data = data[9..].to_vec();
    data.retain(|&b| b != 0); // remove null characters
    
    // check if some data lost
    if data.len() != len {
        return None;
    }

    let json = std::str::from_utf8(&data).ok()?;
    serde_json::from_str(json).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange_serialize() {
        let msg = Message {
            version: 1,
            msg_type: MessageType::KeyExchange {
                public_key: [0u8; 32],
            },
        };
        let bytes = serialize(&msg);
        let deserialized = deserialize(&bytes).unwrap();
        assert_eq!(msg, deserialized);
    }

    #[test]
    fn test_serialize_deserialize() {
        let msg = Message {
            version: 1,
            msg_type: MessageType::Request {
                file_name: "test.txt".to_string(),
                size: 1024,
                hash: "abc123".to_string(),
            },
        };
        let bytes = serialize(&msg);
        let deserialized = deserialize(&bytes).unwrap();
        assert_eq!(msg, deserialized);
    }

    #[test]
    fn test_invalid_magic() {
        let mut bytes = serialize(&Message {
            version: 1,
            msg_type: MessageType::Accept,
        });
        bytes[0] = b'X'; // corrupt magic
        assert!(deserialize(&bytes).is_none());
    }
}
