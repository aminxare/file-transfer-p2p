//! TLS configuration utilities
//!
//! Provides helper functions to load certificates and private keys
//! for both client and server sides.

use rustls::pki_types::PrivateKeyDer;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::{self, BufReader};
use std::sync::Arc;

/// Loads the TLS server configuration using `cert.pem` and `key.pem`.
pub fn load_server_config() -> io::Result<Arc<ServerConfig>> {
    let cert_file = &mut BufReader::new(File::open("cert.pem")?);
    let key_file = &mut BufReader::new(File::open("key.pem")?);

    let certs = certs(cert_file)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .collect();

    let mut keys = pkcs8_private_keys(key_file).collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from(
        keys.pop()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "No private key found"))?,
    );

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(io::Error::other)?;

    Ok(Arc::new(config))
}

/// Loads the TLS client configuration using `cert.pem`.
pub fn load_client_config() -> io::Result<Arc<ClientConfig>> {
    let cert_file = &mut BufReader::new(File::open("cert.pem")?);
    let mut root_store = RootCertStore::empty();

    let certs = certs(cert_file).collect::<Result<Vec<_>, _>>()?.into_iter();

    for cert in certs {
        root_store
            .add(cert)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(Arc::new(config))
}
