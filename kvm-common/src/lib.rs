use bincode::Options;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct KvmEvent {
    pub event_type: u16,
    pub code: u16,
    pub value: i32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum KvmPacket {
    Handshake { version: u32 },
    Events(Vec<KvmEvent>),
    ReleaseAll,
}

pub const PROTOCOL_VERSION: u32 = 1;

pub fn serialize_packet(packet: &KvmPacket) -> Result<Vec<u8>, bincode::Error> {
    bincode::options()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .serialize(packet)
}

pub fn deserialize_packet(bytes: &[u8]) -> Result<KvmPacket, bincode::Error> {
    bincode::options()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .deserialize(bytes)
}

pub mod crypto;
pub use crypto::{
    generate_key, key_to_hex, parse_key, resolve_key, CryptoError, PacketReceiver, PacketSender,
    ReplayError, ReplayWindow, MAGIC,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_roundtrip() {
        let packet = KvmPacket::Handshake {
            version: PROTOCOL_VERSION,
        };
        let serialized = serialize_packet(&packet).unwrap();
        let deserialized = deserialize_packet(&serialized).unwrap();
        match deserialized {
            KvmPacket::Handshake { version } => {
                assert_eq!(version, PROTOCOL_VERSION);
            }
            _ => panic!("Expected Handshake packet"),
        }
    }

    #[test]
    fn test_events_roundtrip() {
        let events = vec![
            KvmEvent {
                event_type: 1,
                code: 30,
                value: 1,
            },
            KvmEvent {
                event_type: 2,
                code: 0,
                value: -10,
            },
        ];
        let packet = KvmPacket::Events(events.clone());
        let serialized = serialize_packet(&packet).unwrap();
        let deserialized = deserialize_packet(&serialized).unwrap();
        match deserialized {
            KvmPacket::Events(deserialized_events) => {
                assert_eq!(deserialized_events.len(), 2);
                assert_eq!(deserialized_events[0].event_type, 1);
                assert_eq!(deserialized_events[0].code, 30);
                assert_eq!(deserialized_events[0].value, 1);
                assert_eq!(deserialized_events[1].event_type, 2);
                assert_eq!(deserialized_events[1].code, 0);
                assert_eq!(deserialized_events[1].value, -10);
            }
            _ => panic!("Expected Events packet"),
        }
    }

    #[test]
    fn test_release_all_roundtrip() {
        let packet = KvmPacket::ReleaseAll;
        let serialized = serialize_packet(&packet).unwrap();
        let deserialized = deserialize_packet(&serialized).unwrap();
        match deserialized {
            KvmPacket::ReleaseAll => {}
            _ => panic!("Expected ReleaseAll packet"),
        }
    }

    #[test]
    fn test_crypto_roundtrip() {
        let key = generate_key();
        let session_id = 1000;
        let mut sender = PacketSender::new(&key, session_id);
        let mut receiver = PacketReceiver::new(&key);

        // 1. Handshake
        let hs_packet = KvmPacket::Handshake {
            version: PROTOCOL_VERSION,
        };
        let enc_hs = sender
            .encrypt_packet(&hs_packet)
            .expect("Encryption failed");
        assert_eq!(&enc_hs[0..4], MAGIC);
        let dec_hs = receiver.decrypt_packet(&enc_hs).expect("Decryption failed");
        match dec_hs {
            KvmPacket::Handshake { version } => assert_eq!(version, PROTOCOL_VERSION),
            _ => panic!("Expected Handshake"),
        }
        assert_eq!(receiver.current_session_id(), Some(session_id));

        // 2. Events
        let events = vec![KvmEvent {
            event_type: 1,
            code: 30,
            value: 1,
        }];
        let ev_packet = KvmPacket::Events(events);
        let enc_ev = sender
            .encrypt_packet(&ev_packet)
            .expect("Encryption failed");
        let dec_ev = receiver.decrypt_packet(&enc_ev).expect("Decryption failed");
        match dec_ev {
            KvmPacket::Events(evs) => assert_eq!(evs.len(), 1),
            _ => panic!("Expected Events"),
        }

        // 3. ReleaseAll
        let rel_packet = KvmPacket::ReleaseAll;
        let enc_rel = sender
            .encrypt_packet(&rel_packet)
            .expect("Encryption failed");
        let dec_rel = receiver
            .decrypt_packet(&enc_rel)
            .expect("Decryption failed");
        match dec_rel {
            KvmPacket::ReleaseAll => {}
            _ => panic!("Expected ReleaseAll"),
        }
    }

    #[test]
    fn test_crypto_tamper_rejected() {
        let key = generate_key();
        let mut sender = PacketSender::new(&key, 1000);
        let mut receiver = PacketReceiver::new(&key);

        let packet = KvmPacket::Handshake {
            version: PROTOCOL_VERSION,
        };
        let mut enc = sender.encrypt_packet(&packet).unwrap();

        // Flip a byte in the ciphertext
        let len = enc.len();
        enc[len - 1] ^= 0xFF;

        let res = receiver.decrypt_packet(&enc);
        assert!(matches!(res, Err(CryptoError::AuthFailed)));
    }

    #[test]
    fn test_crypto_wrong_key_rejected() {
        let key1 = generate_key();
        let key2 = generate_key();
        let mut sender = PacketSender::new(&key1, 1000);
        let mut receiver = PacketReceiver::new(&key2);

        let packet = KvmPacket::Handshake {
            version: PROTOCOL_VERSION,
        };
        let enc = sender.encrypt_packet(&packet).unwrap();

        let res = receiver.decrypt_packet(&enc);
        assert!(matches!(res, Err(CryptoError::AuthFailed)));
    }

    #[test]
    fn test_crypto_replay_rejected() {
        let key = generate_key();
        let mut sender = PacketSender::new(&key, 1000);
        let mut receiver = PacketReceiver::new(&key);

        let hs = KvmPacket::Handshake {
            version: PROTOCOL_VERSION,
        };
        let enc_hs = sender.encrypt_packet(&hs).unwrap();
        assert!(receiver.decrypt_packet(&enc_hs).is_ok());

        // Replaying the handshake
        let replay_res = receiver.decrypt_packet(&enc_hs);
        assert!(matches!(
            replay_res,
            Err(CryptoError::Replay(ReplayError::Replayed))
        ));

        // Replaying an events packet
        let ev = KvmPacket::Events(vec![KvmEvent {
            event_type: 1,
            code: 30,
            value: 1,
        }]);
        let enc_ev = sender.encrypt_packet(&ev).unwrap();
        assert!(receiver.decrypt_packet(&enc_ev).is_ok());

        let replay_ev_res = receiver.decrypt_packet(&enc_ev);
        assert!(matches!(
            replay_ev_res,
            Err(CryptoError::Replay(ReplayError::Replayed))
        ));
    }

    #[test]
    fn test_crypto_events_before_handshake_rejected() {
        let key = generate_key();
        let mut sender = PacketSender::new(&key, 1000);
        let mut receiver = PacketReceiver::new(&key);

        // Sending events before any handshake is established
        let ev = KvmPacket::Events(vec![KvmEvent {
            event_type: 1,
            code: 30,
            value: 1,
        }]);
        let enc_ev = sender.encrypt_packet(&ev).unwrap();
        let res = receiver.decrypt_packet(&enc_ev);
        assert!(matches!(res, Err(CryptoError::HandshakeRequired)));
    }

    #[test]
    fn test_crypto_old_session_handshake_rejected() {
        let key = generate_key();
        let mut sender2 = PacketSender::new(&key, 2000);
        let mut sender1 = PacketSender::new(&key, 1000);
        let mut receiver = PacketReceiver::new(&key);

        // Connect session 2000
        let hs2 = KvmPacket::Handshake {
            version: PROTOCOL_VERSION,
        };
        let enc2 = sender2.encrypt_packet(&hs2).unwrap();
        assert!(receiver.decrypt_packet(&enc2).is_ok());

        // Try to connect session 1000 (older timestamp)
        let hs1 = KvmPacket::Handshake {
            version: PROTOCOL_VERSION,
        };
        let enc1 = sender1.encrypt_packet(&hs1).unwrap();
        let res = receiver.decrypt_packet(&enc1);
        assert!(matches!(res, Err(CryptoError::InvalidSession)));
    }

    #[test]
    fn test_key_parsing() {
        let key = generate_key();
        let hex = key_to_hex(&key);
        let parsed = parse_key(&hex);
        assert_eq!(key, parsed);

        let pass_key1 = parse_key("mypassphrase");
        let pass_key2 = parse_key("mypassphrase");
        assert_eq!(pass_key1, pass_key2);
        assert_ne!(pass_key1, [0u8; 32]);
    }

    #[test]
    fn test_replay_window_out_of_order_and_too_old() {
        let mut window = ReplayWindow::new();

        // Initial packet 10
        assert!(window.check_and_update(10).is_ok());

        // Replay of 10
        assert_eq!(window.check_and_update(10), Err(ReplayError::Replayed));

        // Advance to 15
        assert!(window.check_and_update(15).is_ok());

        // Out-of-order arrivals within window: 12, 14, 11
        assert!(window.check_and_update(12).is_ok());
        assert!(window.check_and_update(14).is_ok());
        assert!(window.check_and_update(11).is_ok());

        // Replays of out-of-order packets
        assert_eq!(window.check_and_update(12), Err(ReplayError::Replayed));
        assert_eq!(window.check_and_update(14), Err(ReplayError::Replayed));

        // Jump ahead by 150
        assert!(window.check_and_update(165).is_ok());

        // Packet 13 was never received, but now is too old (> 128 packets behind 165)
        assert_eq!(window.check_and_update(13), Err(ReplayError::TooOld));

        // Packet 164 is within window
        assert!(window.check_and_update(164).is_ok());
        assert_eq!(window.check_and_update(164), Err(ReplayError::Replayed));
    }

    #[test]
    fn test_resolve_key() {
        // Direct key argument
        let key_hex = key_to_hex(&generate_key());
        let res1 = resolve_key(Some(&key_hex), None).unwrap();
        assert_eq!(key_to_hex(&res1), key_hex);

        // From file
        let tmp_dir = std::env::temp_dir();
        let key_file_path = tmp_dir.join("waykvm_test_key.txt");
        std::fs::write(&key_file_path, format!("  {} \n", key_hex)).unwrap();
        let res2 = resolve_key(None, Some(&key_file_path)).unwrap();
        assert_eq!(res1, res2);
        let _ = std::fs::remove_file(key_file_path);

        // Neither provided
        let res_err = resolve_key(None, None);
        assert!(res_err.is_err());
    }

    #[test]
    fn test_invalid_magic_and_truncated() {
        let key = generate_key();
        let mut receiver = PacketReceiver::new(&key);

        // Truncated packet
        assert!(matches!(
            receiver.decrypt_packet(&[0u8; 10]),
            Err(CryptoError::TooShort(_))
        ));

        // Invalid magic
        let mut bogus = vec![0u8; 64];
        bogus[0..4].copy_from_slice(b"BAD0");
        assert!(matches!(
            receiver.decrypt_packet(&bogus),
            Err(CryptoError::InvalidMagic)
        ));
    }
}
