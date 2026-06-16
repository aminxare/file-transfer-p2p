//! Security primitives for the P2P file transfer application.
//!
//! This module provides encryption and decryption using AES-256-GCM,
//! as well as SHA-256 hashing for file integrity.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use rand::{TryRngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{self as std_io, Read};

/// Custom error type for security operations.
#[derive(Debug)]
pub enum SecurityError {
    /// Failed to generate random bytes for the nonce.
    RngError(String),
    /// Encryption operation failed.
    EncryptionFailed(String),
    /// Decryption operation failed.
    DecryptionFailed,
    /// Data to decrypt is too short (must include 12-byte nonce).
    InvalidDataLength,
}

impl std::error::Error for SecurityError {}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RngError(e) => write!(f, "RNG error: {}", e),
            Self::EncryptionFailed(e) => write!(f, "Encryption failed: {}", e),
            Self::DecryptionFailed => write!(f, "Decryption failed"),
            Self::InvalidDataLength => write!(f, "Invalid data length for decryption"),
        }
    }
}

/// A Result type specialized for security operations.
pub type Result<T> = std::result::Result<T, SecurityError>;

/// Calculates the SHA-256 hash of a file at the given path.
pub fn calculate_file_hash(path: &std::path::Path) -> std_io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

/// Encrypts data using AES-256-GCM with the provided 32-byte key.
///
/// Returns a `Vec<u8>` containing the 12-byte nonce followed by the ciphertext.
///
/// # Errors
///
/// Returns [`SecurityError::RngError`] if nonce generation fails,
/// or [`SecurityError::EncryptionFailed`] if the encryption itself fails.
pub fn encrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|e| SecurityError::RngError(e.to_string()))?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| SecurityError::EncryptionFailed(e.to_string()))?;

    let mut encrypted = nonce_bytes.to_vec();
    encrypted.extend_from_slice(&ciphertext);
    Ok(encrypted)
}

/// Decrypts data using AES-256-GCM with the provided 32-byte key.
///
/// The input `encrypted` data is expected to start with a 12-byte nonce.
///
/// # Errors
///
/// Returns [`SecurityError::InvalidDataLength`] if the input is too short,
/// or [`SecurityError::DecryptionFailed`] if decryption fails (e.g., wrong key or corrupted data).
pub fn decrypt(encrypted: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    if encrypted.len() < 12 {
        return Err(SecurityError::InvalidDataLength);
    }
    let (nonce_bytes, ciphertext) = encrypted.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new(key.into());

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| SecurityError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_key() -> Result<[u8; 32]> {
        let mut key = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut key)
            .map_err(|e| SecurityError::RngError(e.to_string()))?;
        Ok(key)
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = generate_key().expect("Failed to generate key");
        let data = b"Hello, world!";

        let encrypted = encrypt(data, &key).expect("Encryption failed");
        let decrypted = decrypt(&encrypted, &key).expect("Decryption failed");
        assert_eq!(data, &decrypted[..]);
    }

    #[test]
    fn test_invalid_decrypt() {
        let key = generate_key().expect("Failed to generate key");
        let mut encrypted = encrypt(b"test", &key).expect("Encryption failed");
        encrypted[0] = encrypted[0].wrapping_add(1); // corrupt
        assert!(matches!(decrypt(&encrypted, &key), Err(SecurityError::DecryptionFailed)));
    }

    #[test]
    fn test_too_short_data() {
        let key = [0u8; 32];
        assert!(matches!(decrypt(&[0u8; 11], &key), Err(SecurityError::InvalidDataLength)));
    }
}
