use kvm_common::{
    generate_key, key_to_hex, parse_key, serialize_packet, CryptoError, KvmEvent, KvmPacket,
    PacketReceiver, PacketSender, ReplayError, PROTOCOL_VERSION,
};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

#[test]
fn test_end_to_end_udp_authenticated_kvm_flow() {
    // 1. Set up pre-shared key
    let key = generate_key();
    let host_session_id = 12345678;

    // 2. Set up local UDP sockets
    let client_socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind client socket");
    client_socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let client_addr = client_socket.local_addr().unwrap();

    let host_socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind host socket");
    host_socket
        .connect(client_addr)
        .expect("Failed to connect host socket");
    let host_addr = host_socket.local_addr().unwrap();

    let mut sender = PacketSender::new(&key, host_session_id);
    let mut receiver = PacketReceiver::new(&key);
    let mut session_peer: Option<SocketAddr> = None;

    let mut buf = vec![0u8; 65535];

    // 3. Host sends Handshake
    let hs_packet = KvmPacket::Handshake {
        version: PROTOCOL_VERSION,
    };
    let hs_bytes = sender.encrypt_packet(&hs_packet).unwrap();
    host_socket.send(&hs_bytes).unwrap();

    let (len, src) = client_socket.recv_from(&mut buf).unwrap();
    assert_eq!(src, host_addr);

    let decrypted_hs = receiver.decrypt_packet(&buf[..len]).unwrap();
    match decrypted_hs {
        KvmPacket::Handshake { version } => {
            assert_eq!(version, PROTOCOL_VERSION);
            if session_peer.is_none() {
                session_peer = Some(src);
            }
        }
        _ => panic!("Expected Handshake packet"),
    }
    assert_eq!(session_peer, Some(host_addr));

    // 4. Host sends Events (e.g. typing 'A' and mouse move)
    let events = vec![
        KvmEvent {
            event_type: 1,
            code: 30,
            value: 1,
        }, // 'A' key down
        KvmEvent {
            event_type: 2,
            code: 0,
            value: 5,
        }, // mouse delta X
    ];
    let ev_packet = KvmPacket::Events(events.clone());
    let ev_bytes = sender.encrypt_packet(&ev_packet).unwrap();
    host_socket.send(&ev_bytes).unwrap();

    let (len, src) = client_socket.recv_from(&mut buf).unwrap();
    assert_eq!(src, host_addr);
    assert_eq!(session_peer, Some(src));

    let decrypted_ev = receiver.decrypt_packet(&buf[..len]).unwrap();
    match decrypted_ev {
        KvmPacket::Events(received_events) => {
            assert_eq!(received_events.len(), 2);
            assert_eq!(received_events[0].code, 30);
            assert_eq!(received_events[0].value, 1);
            assert_eq!(received_events[1].code, 0);
            assert_eq!(received_events[1].value, 5);
        }
        _ => panic!("Expected Events packet"),
    }

    // 5. Host sends ReleaseAll
    let rel_packet = KvmPacket::ReleaseAll;
    let rel_bytes = sender.encrypt_packet(&rel_packet).unwrap();
    host_socket.send(&rel_bytes).unwrap();

    let (len, src) = client_socket.recv_from(&mut buf).unwrap();
    assert_eq!(src, host_addr);

    let decrypted_rel = receiver.decrypt_packet(&buf[..len]).unwrap();
    match decrypted_rel {
        KvmPacket::ReleaseAll => {}
        _ => panic!("Expected ReleaseAll packet"),
    }
}

#[test]
fn test_security_cwe_306_unauthenticated_injection_blocked() {
    // Client setup
    let key = generate_key();
    let mut receiver = PacketReceiver::new(&key);

    // Attacker sends plain bincode datagram (as reported in BUG-R2-C1-A1-H1: Win+R command injection)
    let attack_events = vec![
        KvmEvent {
            event_type: 1,
            code: 125,
            value: 1,
        }, // Win down
        KvmEvent {
            event_type: 1,
            code: 19,
            value: 1,
        }, // R down
        KvmEvent {
            event_type: 1,
            code: 19,
            value: 0,
        }, // R up
        KvmEvent {
            event_type: 1,
            code: 125,
            value: 0,
        }, // Win up
    ];
    let attacker_raw_datagram = serialize_packet(&KvmPacket::Events(attack_events)).unwrap();

    // Client receive attempt: MUST fail authentication / header check
    let res = receiver.decrypt_packet(&attacker_raw_datagram);
    assert!(res.is_err(), "Unauthenticated datagram must be rejected");
    match res {
        Err(CryptoError::TooShort(_))
        | Err(CryptoError::InvalidMagic)
        | Err(CryptoError::AuthFailed) => {}
        other => panic!("Unexpected error type: {:?}", other),
    }
}

#[test]
fn test_security_cwe_319_cleartext_disclosure_prevented() {
    let key = generate_key();
    let mut sender = PacketSender::new(&key, 9999);

    // Host sends password / keystrokes: 's', 'e', 'c', 'r', 'e', 't'
    let sensitive_keys = vec![
        KvmEvent {
            event_type: 1,
            code: 31,
            value: 1,
        }, // 's'
        KvmEvent {
            event_type: 1,
            code: 18,
            value: 1,
        }, // 'e'
        KvmEvent {
            event_type: 1,
            code: 46,
            value: 1,
        }, // 'c'
        KvmEvent {
            event_type: 1,
            code: 19,
            value: 1,
        }, // 'r'
        KvmEvent {
            event_type: 1,
            code: 18,
            value: 1,
        }, // 'e'
        KvmEvent {
            event_type: 1,
            code: 20,
            value: 1,
        }, // 't'
    ];
    let packet = KvmPacket::Events(sensitive_keys);
    let wire_bytes = sender.encrypt_packet(&packet).unwrap();

    // Sniffer on the network trying to deserialize cleartext:
    let sniffer_decode_result = kvm_common::deserialize_packet(&wire_bytes);
    assert!(
        sniffer_decode_result.is_err(),
        "Wire bytes must not be decodable as plaintext"
    );

    // Eavesdropper with a wrong key cannot decrypt
    let wrong_key = generate_key();
    let mut sniffer_receiver = PacketReceiver::new(&wrong_key);
    let sniffer_decrypt_result = sniffer_receiver.decrypt_packet(&wire_bytes);
    assert!(
        sniffer_decrypt_result.is_err(),
        "Sniffer without PSK must fail decryption"
    );
}

#[test]
fn test_security_replay_attack_rejected() {
    let key = generate_key();
    let mut sender = PacketSender::new(&key, 1234);
    let mut receiver = PacketReceiver::new(&key);

    // Host connects with Handshake
    let hs = KvmPacket::Handshake {
        version: PROTOCOL_VERSION,
    };
    let enc_hs = sender.encrypt_packet(&hs).unwrap();
    assert!(receiver.decrypt_packet(&enc_hs).is_ok());

    // Host sends typed command
    let cmd = KvmPacket::Events(vec![KvmEvent {
        event_type: 1,
        code: 28,
        value: 1,
    }]); // Enter
    let enc_cmd = sender.encrypt_packet(&cmd).unwrap();

    // Legitimate first receive
    let res1 = receiver.decrypt_packet(&enc_cmd);
    assert!(res1.is_ok());

    // Attacker replaying the exact same packet across the network
    let res_replay = receiver.decrypt_packet(&enc_cmd);
    assert!(res_replay.is_err(), "Replayed packet must be rejected");
    match res_replay {
        Err(CryptoError::Replay(ReplayError::Replayed)) => {}
        other => panic!("Expected Replayed error, got {:?}", other),
    }
}

#[test]
fn test_security_tampered_packet_rejected() {
    let key = generate_key();
    let mut sender = PacketSender::new(&key, 1234);
    let mut receiver = PacketReceiver::new(&key);

    let hs = KvmPacket::Handshake {
        version: PROTOCOL_VERSION,
    };
    let mut enc_hs = sender.encrypt_packet(&hs).unwrap();

    // Attacker alters a byte in transit
    let len = enc_hs.len();
    enc_hs[len - 5] ^= 0x01;

    let res = receiver.decrypt_packet(&enc_hs);
    assert!(
        res.is_err(),
        "Tampered packet must fail Poly1305 MAC tag verification"
    );
    match res {
        Err(CryptoError::AuthFailed) => {}
        other => panic!("Expected AuthFailed error, got {:?}", other),
    }
}

#[test]
fn test_key_derivation_consistency() {
    let pass = "my_secure_kvm_password";
    let key1 = parse_key(pass);
    let key2 = parse_key(pass);
    assert_eq!(key1, key2);

    let hex = key_to_hex(&key1);
    let key3 = parse_key(&hex);
    assert_eq!(key1, key3);
}
