use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use rand::{TryRngCore, rngs::OsRng};

type Error = Box<dyn std::error::Error>;
type Result<T> = core::result::Result<T, Error>;

pub fn generate_key() -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut key)
        .map_err(|e| format!("error while filling bytes: cause -> {e}"))?;
    Ok(key)
}

pub fn encrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|e| format!("error while filling bytes: cause -> {e}"))?;

    let ciphertext = cipher
        .encrypt(&Nonce::from_slice(&nonce), data)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let mut encrypted = nonce.to_vec();
    encrypted.extend_from_slice(&ciphertext);
    Ok(encrypted)
}

pub fn decrypt(encrypted: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    // nonce 12 bits
    if encrypted.len() < 12 {
        return None;
    }
    let nonce = &encrypted[0..12];
    let ciphertext = &encrypted[12..];
    let cipher = Aes256Gcm::new(key.into());
    cipher.decrypt(Nonce::from_slice(nonce), ciphertext).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(decrypt(&encrypted, &key).is_none());
    }
}
