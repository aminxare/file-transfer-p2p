## SecureP2P – Secure Peer-to-P2P File Transfer

**SecureP2P** is a lightweight, secure, and decentralized peer-to-peer file transfer application written in **Rust**. It enables direct file sharing between two peers over the network with **end-to-end encryption**, and **ephemeral key exchange** using **ECDH (X25519)**.

No central server. No data stored. Just secure, fast, and private file transfer.

---

## Features

- **End-to-End Encryption**: Files are encrypted using **AES-256-GCM** with a session key derived via **ECDH (X25519)**.
- **Zero-Knowledge Key Exchange**: No pre-shared keys. Keys are generated and exchanged securely per session.
- **Chunked Transfer with ACKs**: Reliable delivery with 4KB chunks and acknowledgment mechanism.
<!-- - **Cancel Support**: Either peer can cancel the transfer mid-progress. -->
- **CLI-Driven**: Simple command-line interface using `clap`.
- **Test-Driven Development (TDD)**: Full unit and integration test coverage.

---

## Security Model

| Layer | Technology | Purpose |
|------|------------|--------|
| **Key Exchange** | `x25519-dalek` (ECDH) | Securely derives shared secret |
| **File Encryption** | `aes-gcm` | End-to-end encryption of file chunks |
| **Integrity** | GCM authentication tag + SHA-256 (planned) | Detects tampering |

> **No keys are ever sent in plaintext.**  
> **Perfect Forward Secrecy** via ephemeral ECDH keys.

---

## Prerequisites

- **Rust & Cargo**: `1.70+`
<!-- - **OpenSSL** (for certificate generation): `openssl` -->
- **tokio**, `x25519-dalek`, `clap`, `serde`, `aes-gcm`

---

## Setup

### 1. Clone the Repository

```bash
git clone https://github.com/aminxare/file-transfer-p2p.git
cd File-transfer-p2p
```
---

### Usage

```bash
Start a Listener (Receiver)
bashcargo run -- -p 3000
```

> Listens on 0.0.0.0:3000 for incoming file requests

---

### Send a File (Sender)

```bash
cargo run -- -s myfile.txt -t 127.0.0.1:3000
```

> Connects to peer at 127.0.0.1:3000 and sends myfile.txt
---
### Protocol
All messages are JSON-serialized and sent over TLS. Protocol version: **1**.

| Type | Fields | Description |
|------|--------|-------------|
| **KeyExchange** | **public_key: [u8; 32]** | X25519 public key |
| **Request** | **file_name**, **size**, **hash** | File transfer request
| **Accept** | — | Accept transfer |
| **Reject** | — | Reject transfer |
| **Chunk** | **offset: u64**, **data: Vec\<u8\>** | Encrypted file chunk
| **Ack** | **offset: u64** | Acknowledge received chunk |
| **Complete** | — | Transfer finished |
| **Cancel** | — | Cancel transfer |

---

### Development

#### Run tests

```bash
cargo test
```

#### Build Release

```bash
cargo build --release
```

## Roadmap

| Feature | Status |
|-------|--------|
| ECDH Key Exchange | Done |
| TLS 1.3 | In Progress |
| Chunked Transfer + ACK | Done |
| Cancel Transfer | In Progress |
| CLI Accept/Reject Prompt | In Progress |
| SHA-256 File Hashing | Planned |
| Peer Discovery (mDNS) | Planned |
| Cross-Platform GUI | Future |

---

## License

```
MIT License
```

---

## Author

**AminXare** - Developer.
