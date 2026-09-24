use clap::Parser;
use kvm_common::{resolve_key, CryptoError, KvmEvent, KvmPacket, PacketReceiver, PROTOCOL_VERSION};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Socket bind address
    #[arg(short, long, default_value = "0.0.0.0:8000")]
    pub bind: String,

    /// Pre-shared key (passphrase or 64-char hex) for encryption & authentication. Can also be set via WAYKVM_KEY env var.
    #[arg(short, long)]
    pub key: Option<String>,

    /// Path to file containing pre-shared key
    #[arg(long)]
    pub key_file: Option<PathBuf>,

    /// Optional allowed host IP address (handshakes from other IPs will be rejected)
    #[arg(long)]
    pub allowed_host: Option<String>,

    /// Generate a secure random 32-byte key (hex) and exit
    #[arg(long)]
    pub generate_key: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PacketAction {
    IgnoredNotAllowedHost,
    IgnoredNotPinnedPeer,
    DroppedAuthError,
    HandshakeAccepted(SocketAddr),
    HandshakeVersionMismatch { version: u32, expected: u32 },
    Events(Vec<KvmEvent>),
    ReleaseAll,
    IgnoredBeforeHandshake,
}

pub fn handle_incoming_datagram(
    receiver: &mut PacketReceiver,
    session_peer: &mut Option<SocketAddr>,
    allowed_ip: Option<IpAddr>,
    src: SocketAddr,
    buf: &[u8],
) -> PacketAction {
    // 1. Check allowed host IP if configured
    if let Some(ref allowed) = allowed_ip {
        if src.ip() != *allowed {
            return PacketAction::IgnoredNotAllowedHost;
        }
    }

    // 2. Check pinned session peer: ignore datagrams from any source other than the pinned host
    if session_peer.is_some_and(|p| p != src) {
        return PacketAction::IgnoredNotPinnedPeer;
    }

    // 3. Decrypt and authenticate packet
    match receiver.decrypt_packet(buf) {
        Ok(KvmPacket::Handshake { version }) => {
            if version == PROTOCOL_VERSION {
                if session_peer.is_none() {
                    *session_peer = Some(src);
                }
                PacketAction::HandshakeAccepted(src)
            } else {
                PacketAction::HandshakeVersionMismatch {
                    version,
                    expected: PROTOCOL_VERSION,
                }
            }
        }
        Ok(KvmPacket::Events(events)) => {
            if session_peer.is_none() {
                return PacketAction::IgnoredBeforeHandshake;
            }
            PacketAction::Events(events)
        }
        Ok(KvmPacket::ReleaseAll) => {
            if session_peer.is_none() {
                return PacketAction::IgnoredBeforeHandshake;
            }
            PacketAction::ReleaseAll
        }
        Err(CryptoError::HandshakeRequired) => PacketAction::IgnoredBeforeHandshake,
        Err(_) => PacketAction::DroppedAuthError,
    }
}

pub fn evdev_to_windows_vk(evdev_code: u16) -> Option<(u16, bool)> {
    // Translation from Linux evdev keycodes to Windows Virtual Key (VK) codes.
    // Returns Option<(vk_code, is_extended)>
    match evdev_code {
        1 => Some((0x1B, false)),   // ESC -> VK_ESCAPE
        2 => Some((0x31, false)),   // 1 -> '1'
        3 => Some((0x32, false)),   // 2 -> '2'
        4 => Some((0x33, false)),   // 3 -> '3'
        5 => Some((0x34, false)),   // 4 -> '4'
        6 => Some((0x35, false)),   // 5 -> '5'
        7 => Some((0x36, false)),   // 6 -> '6'
        8 => Some((0x37, false)),   // 7 -> '7'
        9 => Some((0x38, false)),   // 8 -> '8'
        10 => Some((0x39, false)),  // 9 -> '9'
        11 => Some((0x30, false)),  // 0 -> '0'
        12 => Some((0xBD, false)),  // MINUS -> VK_OEM_MINUS
        13 => Some((0xBB, false)),  // EQUAL -> VK_OEM_PLUS
        14 => Some((0x08, false)),  // BACKSPACE -> VK_BACK
        15 => Some((0x09, false)),  // TAB -> VK_TAB
        16 => Some((0x51, false)),  // Q -> 'Q'
        17 => Some((0x57, false)),  // W -> 'W'
        18 => Some((0x45, false)),  // E -> 'E'
        19 => Some((0x52, false)),  // R -> 'R'
        20 => Some((0x54, false)),  // T -> 'T'
        21 => Some((0x59, false)),  // Y -> 'Y'
        22 => Some((0x55, false)),  // U -> 'U'
        23 => Some((0x49, false)),  // I -> 'I'
        24 => Some((0x4F, false)),  // O -> 'O'
        25 => Some((0x50, false)),  // P -> 'P'
        26 => Some((0xDB, false)),  // LEFTBRACE -> VK_OEM_4
        27 => Some((0xDD, false)),  // RIGHTBRACE -> VK_OEM_6
        28 => Some((0x0D, false)),  // ENTER -> VK_RETURN
        29 => Some((0xA2, false)),  // LEFTCTRL -> VK_LCONTROL
        30 => Some((0x41, false)),  // A -> 'A'
        31 => Some((0x53, false)),  // S -> 'S'
        32 => Some((0x44, false)),  // D -> 'D'
        33 => Some((0x46, false)),  // F -> 'F'
        34 => Some((0x47, false)),  // G -> 'G'
        35 => Some((0x48, false)),  // H -> 'H'
        36 => Some((0x4A, false)),  // J -> 'J'
        37 => Some((0x4B, false)),  // K -> 'K'
        38 => Some((0x4C, false)),  // L -> 'L'
        39 => Some((0xBA, false)),  // SEMICOLON -> VK_OEM_1
        40 => Some((0xDE, false)),  // APOSTROPHE -> VK_OEM_7
        41 => Some((0xC0, false)),  // GRAVE -> VK_OEM_3
        42 => Some((0xA0, false)),  // LEFTSHIFT -> VK_LSHIFT
        43 => Some((0xDC, false)),  // BACKSLASH -> VK_OEM_5
        44 => Some((0x5A, false)),  // Z -> 'Z'
        45 => Some((0x58, false)),  // X -> 'X'
        46 => Some((0x43, false)),  // C -> 'C'
        47 => Some((0x56, false)),  // V -> 'V'
        48 => Some((0x42, false)),  // B -> 'B'
        49 => Some((0x4E, false)),  // N -> 'N'
        50 => Some((0x4D, false)),  // M -> 'M'
        51 => Some((0xBC, false)),  // COMMA -> VK_OEM_COMMA
        52 => Some((0xBE, false)),  // DOT -> VK_OEM_PERIOD
        53 => Some((0xBF, false)),  // SLASH -> VK_OEM_2
        54 => Some((0xA1, false)),  // RIGHTSHIFT -> VK_RSHIFT
        55 => Some((0x6A, false)),  // KPASTERISK -> VK_MULTIPLY
        56 => Some((0xA4, false)),  // LEFTALT -> VK_LMENU
        57 => Some((0x20, false)),  // SPACE -> VK_SPACE
        58 => Some((0x14, false)),  // CAPSLOCK -> VK_CAPITAL
        59 => Some((0x70, false)),  // F1 -> VK_F1
        60 => Some((0x71, false)),  // F2 -> VK_F2
        61 => Some((0x72, false)),  // F3 -> VK_F3
        62 => Some((0x73, false)),  // F4 -> VK_F4
        63 => Some((0x74, false)),  // F5 -> VK_F5
        64 => Some((0x75, false)),  // F6 -> VK_F6
        65 => Some((0x76, false)),  // F7 -> VK_F7
        66 => Some((0x77, false)),  // F8 -> VK_F8
        67 => Some((0x78, false)),  // F9 -> VK_F9
        68 => Some((0x79, false)),  // F10 -> VK_F10
        87 => Some((0x7A, false)),  // F11 -> VK_F11
        88 => Some((0x7B, false)),  // F12 -> VK_F12
        97 => Some((0xA3, true)),   // RIGHTCTRL -> VK_RCONTROL (extended)
        100 => Some((0xA5, true)),  // RIGHTALT -> VK_RMENU (extended)
        102 => Some((0x24, true)),  // HOME -> VK_HOME (extended)
        103 => Some((0x26, true)),  // UP -> VK_UP (extended)
        104 => Some((0x21, true)),  // PAGEUP -> VK_PRIOR (extended)
        105 => Some((0x25, true)),  // LEFT -> VK_LEFT (extended)
        106 => Some((0x27, true)),  // RIGHT -> VK_RIGHT (extended)
        107 => Some((0x23, true)),  // END -> VK_END (extended)
        108 => Some((0x28, true)),  // DOWN -> VK_DOWN (extended)
        109 => Some((0x22, true)),  // PAGEDOWN -> VK_NEXT (extended)
        110 => Some((0x2D, true)),  // INSERT -> VK_INSERT (extended)
        111 => Some((0x2E, true)),  // DELETE -> VK_DELETE (extended)
        113 => Some((0xAD, false)), // MUTE -> VK_VOLUME_MUTE
        114 => Some((0xAE, false)), // VOLUMEDOWN -> VK_VOLUME_DOWN
        115 => Some((0xAF, false)), // VOLUMEUP -> VK_VOLUME_UP
        119 => Some((0x13, false)), // PAUSE -> VK_PAUSE
        125 => Some((0x5B, true)),  // LEFTMETA -> VK_LWIN (extended)
        126 => Some((0x5C, true)),  // RIGHTMETA -> VK_RWIN (extended)
        71 => Some((0x67, false)),  // KP7 -> VK_NUMPAD7
        72 => Some((0x68, false)),  // KP8 -> VK_NUMPAD8
        73 => Some((0x69, false)),  // KP9 -> VK_NUMPAD9
        74 => Some((0x6D, false)),  // KPMINUS -> VK_SUBTRACT
        75 => Some((0x64, false)),  // KP4 -> VK_NUMPAD4
        76 => Some((0x65, false)),  // KP5 -> VK_NUMPAD5
        77 => Some((0x66, false)),  // KP6 -> VK_NUMPAD6
        78 => Some((0x6B, false)),  // KPPLUS -> VK_ADD
        79 => Some((0x61, false)),  // KP1 -> VK_NUMPAD1
        80 => Some((0x62, false)),  // KP2 -> VK_NUMPAD2
        81 => Some((0x63, false)),  // KP3 -> VK_NUMPAD3
        82 => Some((0x60, false)),  // KP0 -> VK_NUMPAD0
        83 => Some((0x6E, false)),  // KPDOT -> VK_DECIMAL
        _ => None,
    }
}

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use std::collections::HashSet;
    use std::net::UdpSocket;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYEVENTF_EXTENDEDKEY,
        KEYEVENTF_KEYUP, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
        MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN,
        MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_WHEEL, MOUSEINPUT,
    };

    pub fn run(args: Args) {
        println!("Starting KVM Client on Windows 11...");

        let key = match resolve_key(args.key.as_deref(), args.key_file.as_deref()) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Authentication error: {}", e);
                std::process::exit(1);
            }
        };

        let allowed_ip: Option<IpAddr> = match args.allowed_host.as_deref() {
            Some(host_str) => match host_str.parse::<IpAddr>() {
                Ok(ip) => {
                    println!("Restricting connections to host IP: {}", ip);
                    Some(ip)
                }
                Err(e) => {
                    eprintln!("Invalid --allowed-host IP address '{}': {}", host_str, e);
                    std::process::exit(1);
                }
            },
            None => None,
        };

        println!("Binding UDP socket to: {}", args.bind);
        let socket = match UdpSocket::bind(&args.bind) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to bind to socket {}: {:?}", args.bind, e);
                return;
            }
        };

        let mut receiver = PacketReceiver::new(&key);
        let mut pressed_keys: HashSet<(u16, bool)> = HashSet::new();
        let mut pressed_mouse_buttons: HashSet<u16> = HashSet::new();
        // Peer pinned by the first valid Handshake; datagrams from any other
        // source, and input packets received before pinning, are ignored.
        let mut session_peer: Option<SocketAddr> = None;
        let mut buf = vec![0u8; 65535];

        println!("Listening for packets from host...");

        loop {
            match socket.recv_from(&mut buf) {
                Ok((size, src)) => {
                    let action = handle_incoming_datagram(
                        &mut receiver,
                        &mut session_peer,
                        allowed_ip,
                        src,
                        &buf[..size],
                    );

                    match action {
                        PacketAction::HandshakeAccepted(host_addr) => {
                            println!("Connected client to host: {}", host_addr);
                        }
                        PacketAction::HandshakeVersionMismatch { version, expected } => {
                            eprintln!(
                                "Protocol version mismatch! Host: {}, Client: {}",
                                version, expected
                            );
                        }
                        PacketAction::Events(events) => {
                            for ev in events {
                                match ev.event_type {
                                    1 => {
                                        // EV_KEY
                                        if ev.code == 272 {
                                            // BTN_LEFT
                                            let is_down = ev.value != 0;
                                            let flag = if is_down {
                                                MOUSEEVENTF_LEFTDOWN
                                            } else {
                                                MOUSEEVENTF_LEFTUP
                                            };
                                            send_mouse_input(flag, 0, 0, 0);
                                            if is_down {
                                                pressed_mouse_buttons.insert(ev.code);
                                            } else {
                                                pressed_mouse_buttons.remove(&ev.code);
                                            }
                                        } else if ev.code == 273 {
                                            // BTN_RIGHT
                                            let is_down = ev.value != 0;
                                            let flag = if is_down {
                                                MOUSEEVENTF_RIGHTDOWN
                                            } else {
                                                MOUSEEVENTF_RIGHTUP
                                            };
                                            send_mouse_input(flag, 0, 0, 0);
                                            if is_down {
                                                pressed_mouse_buttons.insert(ev.code);
                                            } else {
                                                pressed_mouse_buttons.remove(&ev.code);
                                            }
                                        } else if ev.code == 274 {
                                            // BTN_MIDDLE
                                            let is_down = ev.value != 0;
                                            let flag = if is_down {
                                                MOUSEEVENTF_MIDDLEDOWN
                                            } else {
                                                MOUSEEVENTF_MIDDLEUP
                                            };
                                            send_mouse_input(flag, 0, 0, 0);
                                            if is_down {
                                                pressed_mouse_buttons.insert(ev.code);
                                            } else {
                                                pressed_mouse_buttons.remove(&ev.code);
                                            }
                                        } else {
                                            // Keyboard key
                                            if let Some((vk, is_extended)) =
                                                evdev_to_windows_vk(ev.code)
                                            {
                                                let is_up = ev.value == 0;
                                                send_keyboard_input(vk, is_extended, is_up);
                                                if is_up {
                                                    pressed_keys.remove(&(vk, is_extended));
                                                } else {
                                                    pressed_keys.insert((vk, is_extended));
                                                }
                                            }
                                        }
                                    }
                                    2 => {
                                        // EV_REL
                                        if ev.code == 0 {
                                            // REL_X
                                            send_mouse_input(MOUSEEVENTF_MOVE, ev.value, 0, 0);
                                        } else if ev.code == 1 {
                                            // REL_Y
                                            send_mouse_input(MOUSEEVENTF_MOVE, 0, ev.value, 0);
                                        } else if ev.code == 8 {
                                            // REL_WHEEL
                                            // Scale by standard WHEEL_DELTA (120)
                                            send_mouse_input(
                                                MOUSEEVENTF_WHEEL,
                                                0,
                                                0,
                                                ev.value * 120,
                                            );
                                        } else if ev.code == 6 {
                                            // REL_HWHEEL
                                            send_mouse_input(
                                                MOUSEEVENTF_HWHEEL,
                                                0,
                                                0,
                                                ev.value * 120,
                                            );
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        PacketAction::ReleaseAll => {
                            println!("ReleaseAll packet received. Clearing inputs.");
                            // Release all keys
                            for &(vk, is_extended) in &pressed_keys {
                                send_keyboard_input(vk, is_extended, true);
                            }
                            pressed_keys.clear();

                            // Release all mouse buttons
                            if pressed_mouse_buttons.contains(&272) {
                                send_mouse_input(MOUSEEVENTF_LEFTUP, 0, 0, 0);
                            }
                            if pressed_mouse_buttons.contains(&273) {
                                send_mouse_input(MOUSEEVENTF_RIGHTUP, 0, 0, 0);
                            }
                            if pressed_mouse_buttons.contains(&274) {
                                send_mouse_input(MOUSEEVENTF_MIDDLEUP, 0, 0, 0);
                            }
                            pressed_mouse_buttons.clear();
                        }
                        PacketAction::IgnoredBeforeHandshake
                        | PacketAction::IgnoredNotPinnedPeer
                        | PacketAction::IgnoredNotAllowedHost
                        | PacketAction::DroppedAuthError => {
                            // Ignored or dropped invalid packet
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Socket receive error: {:?}", e);
                }
            }
        }
    }

    fn send_mouse_input(dw_flags: u32, dx: i32, dy: i32, mouse_data: i32) {
        let mut input = unsafe { std::mem::zeroed::<INPUT>() };
        input.r#type = INPUT_MOUSE;
        input.Anonymous.mi = MOUSEINPUT {
            dx,
            dy,
            mouseData: mouse_data as u32,
            dwFlags: dw_flags,
            time: 0,
            dwExtraInfo: 0,
        };
        unsafe {
            SendInput(1, &input, std::mem::size_of::<INPUT>() as i32);
        }
    }

    fn send_keyboard_input(vk_code: u16, is_extended: bool, is_up: bool) {
        let mut flags = if is_up { KEYEVENTF_KEYUP } else { 0 };
        if is_extended {
            flags |= KEYEVENTF_EXTENDEDKEY;
        }
        let mut input = unsafe { std::mem::zeroed::<INPUT>() };
        input.r#type = INPUT_KEYBOARD;
        input.Anonymous.ki = KEYBDINPUT {
            wVk: vk_code,
            wScan: 0,
            dwFlags: flags,
            time: 0,
            dwExtraInfo: 0,
        };
        unsafe {
            SendInput(1, &input, std::mem::size_of::<INPUT>() as i32);
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod other_impl {
    use super::{resolve_key, Args};
    pub fn run(args: Args) {
        if let Err(e) = resolve_key(args.key.as_deref(), args.key_file.as_deref()) {
            eprintln!("Authentication error: {}", e);
            std::process::exit(1);
        }
        eprintln!("kvm-client is only supported on Windows. Exiting.");
        std::process::exit(1);
    }
}

fn main() {
    let args = Args::parse();
    if args.generate_key {
        println!("{}", kvm_common::key_to_hex(&kvm_common::generate_key()));
        return;
    }

    #[cfg(target_os = "windows")]
    windows_impl::run(args);

    #[cfg(not(target_os = "windows"))]
    other_impl::run(args);
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_common::{generate_key, KvmEvent, KvmPacket, PacketSender, PROTOCOL_VERSION};
    use std::net::SocketAddr;

    #[test]
    fn test_unauthenticated_packet_dropped() {
        let key = generate_key();
        let mut receiver = PacketReceiver::new(&key);
        let mut session_peer = None;
        let src: SocketAddr = "192.168.1.50:8000".parse().unwrap();

        // Plaintext bincode packet sent by attacker (CWE-306 / BUG-R2-C1-A1-H1 attack)
        let plain_bytes = kvm_common::serialize_packet(&KvmPacket::Events(vec![KvmEvent {
            event_type: 1,
            code: 125, // Win key
            value: 1,
        }]))
        .unwrap();

        let action =
            handle_incoming_datagram(&mut receiver, &mut session_peer, None, src, &plain_bytes);
        assert_eq!(action, PacketAction::DroppedAuthError);
        assert_eq!(session_peer, None);
    }

    #[test]
    fn test_events_before_handshake_ignored() {
        let key = generate_key();
        let mut sender = PacketSender::new(&key, 1000);
        let mut receiver = PacketReceiver::new(&key);
        let mut session_peer = None;
        let src: SocketAddr = "192.168.1.50:8000".parse().unwrap();

        let ev_packet = KvmPacket::Events(vec![KvmEvent {
            event_type: 1,
            code: 30,
            value: 1,
        }]);
        let enc_ev = sender.encrypt_packet(&ev_packet).unwrap();

        let action = handle_incoming_datagram(&mut receiver, &mut session_peer, None, src, &enc_ev);
        assert_eq!(action, PacketAction::IgnoredBeforeHandshake);
        assert_eq!(session_peer, None);
    }

    #[test]
    fn test_session_peer_pinning_and_event_dispatch() {
        let key = generate_key();
        let mut sender = PacketSender::new(&key, 1000);
        let mut receiver = PacketReceiver::new(&key);
        let mut session_peer = None;
        let host_addr: SocketAddr = "192.168.1.10:8000".parse().unwrap();
        let attacker_addr: SocketAddr = "192.168.1.99:8000".parse().unwrap();

        // 1. Host sends Handshake
        let hs_packet = KvmPacket::Handshake {
            version: PROTOCOL_VERSION,
        };
        let enc_hs = sender.encrypt_packet(&hs_packet).unwrap();
        let action =
            handle_incoming_datagram(&mut receiver, &mut session_peer, None, host_addr, &enc_hs);
        assert_eq!(action, PacketAction::HandshakeAccepted(host_addr));
        assert_eq!(session_peer, Some(host_addr));

        // 2. Attacker sends from different address
        let mut attacker_sender = PacketSender::new(&key, 1000);
        let ev_packet = KvmPacket::Events(vec![KvmEvent {
            event_type: 1,
            code: 30,
            value: 1,
        }]);
        let enc_ev = attacker_sender.encrypt_packet(&ev_packet).unwrap();
        let action = handle_incoming_datagram(
            &mut receiver,
            &mut session_peer,
            None,
            attacker_addr,
            &enc_ev,
        );
        assert_eq!(action, PacketAction::IgnoredNotPinnedPeer);

        // 3. Genuine host sends events
        let enc_ev_host = sender.encrypt_packet(&ev_packet).unwrap();
        let action = handle_incoming_datagram(
            &mut receiver,
            &mut session_peer,
            None,
            host_addr,
            &enc_ev_host,
        );
        match action {
            PacketAction::Events(evs) => assert_eq!(evs.len(), 1),
            other => panic!("Expected Events, got {:?}", other),
        }

        // 4. ReleaseAll from genuine host
        let rel_packet = KvmPacket::ReleaseAll;
        let enc_rel = sender.encrypt_packet(&rel_packet).unwrap();
        let action =
            handle_incoming_datagram(&mut receiver, &mut session_peer, None, host_addr, &enc_rel);
        assert_eq!(action, PacketAction::ReleaseAll);
    }

    #[test]
    fn test_allowed_host_filter() {
        let key = generate_key();
        let mut sender = PacketSender::new(&key, 1000);
        let mut receiver = PacketReceiver::new(&key);
        let mut session_peer = None;
        let allowed_ip = "192.168.1.10".parse().unwrap();
        let host_addr: SocketAddr = "192.168.1.10:8000".parse().unwrap();
        let wrong_addr: SocketAddr = "192.168.1.11:8000".parse().unwrap();

        let hs_packet = KvmPacket::Handshake {
            version: PROTOCOL_VERSION,
        };
        let enc_hs = sender.encrypt_packet(&hs_packet).unwrap();

        // Datagram from wrong IP
        let action = handle_incoming_datagram(
            &mut receiver,
            &mut session_peer,
            Some(allowed_ip),
            wrong_addr,
            &enc_hs,
        );
        assert_eq!(action, PacketAction::IgnoredNotAllowedHost);
        assert_eq!(session_peer, None);

        // Datagram from allowed IP
        let action = handle_incoming_datagram(
            &mut receiver,
            &mut session_peer,
            Some(allowed_ip),
            host_addr,
            &enc_hs,
        );
        assert_eq!(action, PacketAction::HandshakeAccepted(host_addr));
        assert_eq!(session_peer, Some(host_addr));
    }

    #[test]
    fn test_evdev_to_windows_vk_mapping() {
        // Esc
        assert_eq!(evdev_to_windows_vk(1), Some((0x1B, false)));
        // Letters: Q, W, E, R
        assert_eq!(evdev_to_windows_vk(16), Some((0x51, false)));
        assert_eq!(evdev_to_windows_vk(19), Some((0x52, false)));
        // Win keys (extended)
        assert_eq!(evdev_to_windows_vk(125), Some((0x5B, true)));
        assert_eq!(evdev_to_windows_vk(126), Some((0x5C, true)));
        // Non-existent key
        assert_eq!(evdev_to_windows_vk(9999), None);
    }
}
