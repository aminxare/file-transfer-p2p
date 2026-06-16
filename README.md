## SecureP2P – Secure Peer-to-Peer File Transfer

**SecureP2P** is a lightweight, secure, and decentralized peer-to-peer file transfer application written in **Rust**. It enables direct file sharing between two peers over the network with **end-to-end encryption**, and **ephemeral key exchange** using **ECDH (X25519)**.

No central server. No data stored. Just secure, fast, and private file transfer.

---

## Features

- **End-to-End Encryption**: Files are encrypted using **AES-256-GCM** with a session key derived via **ECDH (X25519)**.
- **Zero-Knowledge Key Exchange**: No pre-shared keys. Keys are generated and exchanged securely per session.
- **Chunked Transfer with ACKs**: Reliable delivery with 256KB chunks and acknowledgment mechanism.
- **File Integrity Verification**: SHA-256 hashing to ensure the received file matches the original.
- **CLI-Driven**: Simple command-line interface using `clap`.
- **Clean Architecture**: Refactored into a reusable library (`ft`) and a thin CLI wrapper.

---

## Security Model

| Layer | Technology | Purpose |
|------|------------|--------|
| **Key Exchange** | `x25519-dalek` (ECDH) | Securely derives shared secret |
| **File Encryption** | `aes-gcm` | End-to-end encryption of file chunks |
| **Integrity** | GCM authentication tag + SHA-256 | Detects tampering and ensures file completeness |

> **No keys are ever sent in plaintext.**  
> **Perfect Forward Secrecy** via ephemeral ECDH keys.

---

## Prerequisites

- **Rust & Cargo**: `1.70+`
- **tokio**, `x25519-dalek`, `clap`, `serde`, `aes-gcm`, `sha2`

---

## Setup

### 1. Clone the Repository

```bash
git clone https://github.com/aminxare/file-transfer-p2p.git
cd file-transfer-p2p
```

### 2. Build the Project

```bash
cargo build --release
```

---

## Usage

### Start a Listener (Receiver)

```bash
cargo run -- --port 3000
```

> Listens on `0.0.0.0:3000` for incoming file requests. Files will be saved as `recv_<original_name>`.

### Send a File (Sender)

```bash
cargo run -- --file myfile.txt --address 127.0.0.1:3000
```

> Connects to peer at `127.0.0.1:3000` and sends `myfile.txt`.

---

## Protocol

All messages are JSON-serialized and sent over a framed TCP stream. 

**Frame format:** `MAGIC` (5 bytes) + `Length` (4 bytes, BE) + `JSON payload`.

| Type | Fields | Description |
|------|--------|-------------|
| **KeyExchange** | **public_key: [u8; 32]** | X25519 public key |
| **Request** | **file_name**, **size**, **hash** | File transfer request with SHA-256 hash |
| **Accept** | — | Accept transfer |
| **Reject** | — | Reject transfer |
| **Chunk** | **offset: u64**, **data: Vec\<u8\>** | Encrypted file chunk |
| **Ack** | **offset: u64** | Acknowledge received chunk |
| **Complete** | — | Transfer finished |
| **Cancel** | — | Cancel transfer |

---

## Roadmap

| Feature | Status |
|-------|--------|
| ECDH Key Exchange | Done |
| Chunked Transfer + ACK | Done |
| SHA-256 File Hashing | Done |
| Refactored Library Structure | Done |
| CLI Accept/Reject Prompt | Planned |
| TLS 1.3 | Planned |
| Peer Discovery (mDNS) | Planned |

---

## License

```
MIT License
```

---

## Author

**AminXare** - Developer.
