//! # File Transfer P2P (ft)
//!
//! A secure peer-to-peer file transfer library.
//!
//! This library provides the building blocks for creating a P2P file transfer
//! application with end-to-end encryption using AES-256-GCM and session keys
//! derived via ECDH (X25519).
//!
//! ## Modules
//!
//! - [`file_transfer`]: Core logic for sending and receiving files in chunks.
//! - [`network`]: Networking primitives, including client and listener implementations.
//! - [`protocol`]: Message definitions and serialization logic.
//! - [`security`]: Cryptographic primitives for encryption and decryption.
//! - [`tls`]: (Experimental) TLS configuration utilities.

pub mod file_transfer; 
pub mod network; 
pub mod tls;
pub mod protocol; 
pub mod security; 
