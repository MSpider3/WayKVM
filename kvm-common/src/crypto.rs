use crate::{deserialize_packet, serialize_packet, KvmPacket, PROTOCOL_VERSION};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::Path;

pub const MAGIC: &[u8; 4] = b"WK01";

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ReplayError {
    TooOld,
    Replayed,
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReplayError::TooOld => write!(f, "Packet sequence number is too old"),
            ReplayError::Replayed => write!(
                f,
                "Packet sequence number already received (replay detected)"
            ),
        }
    }
}

impl std::error::Error for ReplayError {}

#[derive(Debug)]
pub enum CryptoError {
    TooShort(usize),
    InvalidMagic,
    AuthFailed,
    Serialization(bincode::Error),
    Replay(ReplayError),
    InvalidSession,
    HandshakeRequired,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::TooShort(len) => write!(f, "Datagram too short: {} bytes", len),
            CryptoError::InvalidMagic => write!(f, "Invalid magic bytes in datagram header"),
            CryptoError::AuthFailed => write!(
                f,
                "Authentication or decryption failed (invalid key, tag, or corrupted packet)"
            ),
            CryptoError::Serialization(e) => write!(f, "Packet serialization error: {}", e),
            CryptoError::Replay(e) => write!(f, "Replay check failed: {}", e),
            CryptoError::InvalidSession => write!(f, "Invalid or stale session ID"),
            CryptoError::HandshakeRequired => {
                write!(f, "Handshake required before receiving input events")
            }
        }
    }
}

impl std::error::Error for CryptoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CryptoError::Serialization(e) => Some(e),
            CryptoError::Replay(e) => Some(e),
            _ => None,
        }
    }
}

impl From<bincode::Error> for CryptoError {
    fn from(e: bincode::Error) -> Self {
        CryptoError::Serialization(e)
    }
}

impl From<ReplayError> for CryptoError {
    fn from(e: ReplayError) -> Self {
        CryptoError::Replay(e)
    }
}

#[derive(Debug, Clone)]
pub struct ReplayWindow {
    last_seq: u64,
    bitmap: u128,
    initialized: bool,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            last_seq: 0,
            bitmap: 0,
            initialized: false,
        }
    }

    pub fn reset(&mut self) {
        self.last_seq = 0;
        self.bitmap = 0;
        self.initialized = false;
    }

    pub fn check_and_update(&mut self, seq: u64) -> Result<(), ReplayError> {
        if !self.initialized {
            self.initialized = true;
            self.last_seq = seq;
            self.bitmap = 1;
            return Ok(());
        }

        if seq > self.last_seq {
            let diff = seq - self.last_seq;
            if diff < 128 {
                self.bitmap <<= diff;
                self.bitmap |= 1;
            } else {
                self.bitmap = 1;
            }
            self.last_seq = seq;
            Ok(())
        } else {
            let diff = self.last_seq - seq;
            if diff >= 128 {
                return Err(ReplayError::TooOld);
            }
            let mask = 1u128 << diff;
            if (self.bitmap & mask) != 0 {
                return Err(ReplayError::Replayed);
            }
            self.bitmap |= mask;
            Ok(())
        }
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).expect("failed to generate random key");
    key
}

pub fn key_to_hex(key: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in key {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

pub fn parse_key(input: &str) -> [u8; 32] {
    let trimmed = input.trim();
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut key = [0u8; 32];
        let mut valid = true;
        for (i, chunk) in trimmed.as_bytes().chunks(2).enumerate() {
            if let Ok(s) = std::str::from_utf8(chunk) {
                if let Ok(byte) = u8::from_str_radix(s, 16) {
                    key[i] = byte;
                } else {
                    valid = false;
                    break;
                }
            } else {
                valid = false;
                break;
            }
        }
        if valid {
            return key;
        }
    }
    // Derive 32-byte key from passphrase using SHA-256
    let hash = Sha256::digest(trimmed.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

pub fn resolve_key(key_arg: Option<&str>, key_file_arg: Option<&Path>) -> Result<[u8; 32], String> {
    if let Some(k) = key_arg {
        let trimmed = k.trim();
        if trimmed.is_empty() {
            return Err("Provided key is empty".to_string());
        }
        return Ok(parse_key(trimmed));
    }
    if let Ok(env_key) = std::env::var("WAYKVM_KEY") {
        let trimmed = env_key.trim();
        if !trimmed.is_empty() {
            return Ok(parse_key(trimmed));
        }
    }
    if let Some(path) = key_file_arg {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read key file {:?}: {}", path, e))?;
        let trimmed = content.trim();
        if trimmed.is_empty() {
            return Err(format!("Key file {:?} is empty", path));
        }
        return Ok(parse_key(trimmed));
    }
    Err("A pre-shared key is required for authentication and encryption. Provide --key <KEY>, --key-file <PATH>, or set WAYKVM_KEY environment variable. Run with --generate-key to generate a new key.".to_string())
}

pub struct PacketSender {
    cipher: XChaCha20Poly1305,
    session_id: u64,
    next_seq: u64,
}

impl PacketSender {
    pub fn new(key: &[u8; 32], session_id: u64) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new(key.into()),
            session_id,
            next_seq: 0,
        }
    }

    pub fn encrypt_packet(&mut self, packet: &KvmPacket) -> Result<Vec<u8>, CryptoError> {
        let serialized = serialize_packet(packet)?;
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);

        let mut plaintext = Vec::with_capacity(16 + serialized.len());
        plaintext.extend_from_slice(&self.session_id.to_le_bytes());
        plaintext.extend_from_slice(&seq.to_le_bytes());
        plaintext.extend_from_slice(&serialized);

        let mut nonce_bytes = [0u8; 24];
        getrandom::fill(&mut nonce_bytes).expect("failed to generate random nonce");
        let nonce = XNonce::from(nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|_| CryptoError::AuthFailed)?;

        let mut datagram = Vec::with_capacity(4 + 24 + ciphertext.len());
        datagram.extend_from_slice(MAGIC);
        datagram.extend_from_slice(&nonce_bytes);
        datagram.extend_from_slice(&ciphertext);

        Ok(datagram)
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }
}

pub struct PacketReceiver {
    cipher: XChaCha20Poly1305,
    current_session_id: Option<u64>,
    replay_window: ReplayWindow,
}

impl PacketReceiver {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new(key.into()),
            current_session_id: None,
            replay_window: ReplayWindow::new(),
        }
    }

    pub fn current_session_id(&self) -> Option<u64> {
        self.current_session_id
    }

    pub fn decrypt_packet(&mut self, datagram: &[u8]) -> Result<KvmPacket, CryptoError> {
        // MAGIC(4) + NONCE(24) + Poly1305 TAG(16) + session_id(8) + seq(8) = 60
        if datagram.len() < 60 {
            return Err(CryptoError::TooShort(datagram.len()));
        }

        if &datagram[0..4] != MAGIC {
            return Err(CryptoError::InvalidMagic);
        }

        let nonce_bytes: [u8; 24] = datagram[4..28]
            .try_into()
            .map_err(|_| CryptoError::TooShort(datagram.len()))?;
        let nonce = XNonce::from(nonce_bytes);
        let ciphertext = &datagram[28..];

        let plaintext = self
            .cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| CryptoError::AuthFailed)?;

        if plaintext.len() < 16 {
            return Err(CryptoError::TooShort(plaintext.len()));
        }

        let session_id = u64::from_le_bytes(plaintext[0..8].try_into().unwrap());
        let seq = u64::from_le_bytes(plaintext[8..16].try_into().unwrap());
        let packet = deserialize_packet(&plaintext[16..])?;

        match &packet {
            KvmPacket::Handshake { version } => {
                if *version != PROTOCOL_VERSION {
                    return Ok(packet);
                }
                if self.current_session_id != Some(session_id) {
                    if let Some(prev) = self.current_session_id {
                        if session_id <= prev {
                            return Err(CryptoError::InvalidSession);
                        }
                    }
                    self.current_session_id = Some(session_id);
                    self.replay_window.reset();
                }
                self.replay_window.check_and_update(seq)?;
                Ok(packet)
            }
            _ => {
                if self.current_session_id != Some(session_id) {
                    return Err(CryptoError::HandshakeRequired);
                }
                self.replay_window.check_and_update(seq)?;
                Ok(packet)
            }
        }
    }
}
