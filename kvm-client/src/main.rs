#[cfg(target_os = "windows")]
mod windows_impl {
    use clap::Parser;
    use kvm_common::{deserialize_packet, KvmPacket, PROTOCOL_VERSION};
    use std::collections::HashSet;
    use std::net::UdpSocket;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, MOUSEINPUT,
        KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN,
        MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE,
        MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_WHEEL,
    };

    #[derive(Parser, Debug)]
    #[command(author, version, about, long_about = None)]
    struct Args {
        /// Socket bind address
        #[arg(short, long, default_value = "0.0.0.0:8000")]
        bind: String,
    }

    pub fn run() {
        let args = Args::parse();
        println!("Starting KVM Client on Windows 11...");
        println!("Binding UDP socket to: {}", args.bind);

        let socket = match UdpSocket::bind(&args.bind) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to bind to socket {}: {:?}", args.bind, e);
                return;
            }
        };

        let mut pressed_keys: HashSet<(u16, bool)> = HashSet::new();
        let mut pressed_mouse_buttons: HashSet<u16> = HashSet::new();
        let mut buf = vec![0u8; 65535];

        println!("Listening for packets from host...");

        loop {
            match socket.recv_from(&mut buf) {
                Ok((size, src)) => {
                    match deserialize_packet(&buf[..size]) {
                        Ok(KvmPacket::Handshake { version }) => {
                            if version == PROTOCOL_VERSION {
                                println!("Connected client to host: {}", src);
                            } else {
                                eprintln!(
                                    "Protocol version mismatch! Host: {}, Client: {}",
                                    version, PROTOCOL_VERSION
                                );
                            }
                        }
                        Ok(KvmPacket::Events(events)) => {
                            for ev in events {
                                match ev.event_type {
                                    1 => { // EV_KEY
                                        if ev.code == 272 { // BTN_LEFT
                                            let is_down = ev.value != 0;
                                            let flag = if is_down { MOUSEEVENTF_LEFTDOWN } else { MOUSEEVENTF_LEFTUP };
                                            send_mouse_input(flag, 0, 0, 0);
                                            if is_down {
                                                pressed_mouse_buttons.insert(ev.code);
                                            } else {
                                                pressed_mouse_buttons.remove(&ev.code);
                                            }
                                        } else if ev.code == 273 { // BTN_RIGHT
                                            let is_down = ev.value != 0;
                                            let flag = if is_down { MOUSEEVENTF_RIGHTDOWN } else { MOUSEEVENTF_RIGHTUP };
                                            send_mouse_input(flag, 0, 0, 0);
                                            if is_down {
                                                pressed_mouse_buttons.insert(ev.code);
                                            } else {
                                                pressed_mouse_buttons.remove(&ev.code);
                                            }
                                        } else if ev.code == 274 { // BTN_MIDDLE
                                            let is_down = ev.value != 0;
                                            let flag = if is_down { MOUSEEVENTF_MIDDLEDOWN } else { MOUSEEVENTF_MIDDLEUP };
                                            send_mouse_input(flag, 0, 0, 0);
                                            if is_down {
                                                pressed_mouse_buttons.insert(ev.code);
                                            } else {
                                                pressed_mouse_buttons.remove(&ev.code);
                                            }
                                        } else {
                                            // Keyboard key
                                            if let Some((vk, is_extended)) = evdev_to_windows_vk(ev.code) {
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
                                    2 => { // EV_REL
                                        if ev.code == 0 { // REL_X
                                            send_mouse_input(MOUSEEVENTF_MOVE, ev.value, 0, 0);
                                        } else if ev.code == 1 { // REL_Y
                                            send_mouse_input(MOUSEEVENTF_MOVE, 0, ev.value, 0);
                                        } else if ev.code == 8 { // REL_WHEEL
                                            // Scale by standard WHEEL_DELTA (120)
                                            send_mouse_input(MOUSEEVENTF_WHEEL, 0, 0, ev.value * 120);
                                        } else if ev.code == 6 { // REL_HWHEEL
                                            send_mouse_input(MOUSEEVENTF_HWHEEL, 0, 0, ev.value * 120);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Ok(KvmPacket::ReleaseAll) => {
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
                        Err(e) => {
                            eprintln!("Failed to deserialize packet: {:?}", e);
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

    fn evdev_to_windows_vk(evdev_code: u16) -> Option<(u16, bool)> {
        // Translation from Linux evdev keycodes to Windows Virtual Key (VK) codes.
        // Returns Option<(vk_code, is_extended)>
        match evdev_code {
            1 => Some((0x1B, false)),  // ESC -> VK_ESCAPE
            2 => Some((0x31, false)),  // 1 -> '1'
            3 => Some((0x32, false)),  // 2 -> '2'
            4 => Some((0x33, false)),  // 3 -> '3'
            5 => Some((0x34, false)),  // 4 -> '4'
            6 => Some((0x35, false)),  // 5 -> '5'
            7 => Some((0x36, false)),  // 6 -> '6'
            8 => Some((0x37, false)),  // 7 -> '7'
            9 => Some((0x38, false)),  // 8 -> '8'
            10 => Some((0x39, false)), // 9 -> '9'
            11 => Some((0x30, false)), // 0 -> '0'
            12 => Some((0xBD, false)), // MINUS -> VK_OEM_MINUS
            13 => Some((0xBB, false)), // EQUAL -> VK_OEM_PLUS
            14 => Some((0x08, false)), // BACKSPACE -> VK_BACK
            15 => Some((0x09, false)), // TAB -> VK_TAB
            16 => Some((0x51, false)), // Q -> 'Q'
            17 => Some((0x57, false)), // W -> 'W'
            18 => Some((0x45, false)), // E -> 'E'
            19 => Some((0x52, false)), // R -> 'R'
            20 => Some((0x54, false)), // T -> 'T'
            21 => Some((0x59, false)), // Y -> 'Y'
            22 => Some((0x55, false)), // U -> 'U'
            23 => Some((0x49, false)), // I -> 'I'
            24 => Some((0x4F, false)), // O -> 'O'
            25 => Some((0x50, false)), // P -> 'P'
            26 => Some((0xDB, false)), // LEFTBRACE -> VK_OEM_4
            27 => Some((0xDD, false)), // RIGHTBRACE -> VK_OEM_6
            28 => Some((0x0D, false)), // ENTER -> VK_RETURN
            29 => Some((0xA2, false)), // LEFTCTRL -> VK_LCONTROL
            30 => Some((0x41, false)), // A -> 'A'
            31 => Some((0x53, false)), // S -> 'S'
            32 => Some((0x44, false)), // D -> 'D'
            33 => Some((0x46, false)), // F -> 'F'
            34 => Some((0x47, false)), // G -> 'G'
            35 => Some((0x48, false)), // H -> 'H'
            36 => Some((0x4A, false)), // J -> 'J'
            37 => Some((0x4B, false)), // K -> 'K'
            38 => Some((0x4C, false)), // L -> 'L'
            39 => Some((0xBA, false)), // SEMICOLON -> VK_OEM_1
            40 => Some((0xDE, false)), // APOSTROPHE -> VK_OEM_7
            41 => Some((0xC0, false)), // GRAVE -> VK_OEM_3
            42 => Some((0xA0, false)), // LEFTSHIFT -> VK_LSHIFT
            43 => Some((0xDC, false)), // BACKSLASH -> VK_OEM_5
            44 => Some((0x5A, false)), // Z -> 'Z'
            45 => Some((0x58, false)), // X -> 'X'
            46 => Some((0x43, false)), // C -> 'C'
            47 => Some((0x56, false)), // V -> 'V'
            48 => Some((0x42, false)), // B -> 'B'
            49 => Some((0x4E, false)), // N -> 'N'
            50 => Some((0x4D, false)), // M -> 'M'
            51 => Some((0xBC, false)), // COMMA -> VK_OEM_COMMA
            52 => Some((0xBE, false)), // DOT -> VK_OEM_PERIOD
            53 => Some((0xBF, false)), // SLASH -> VK_OEM_2
            54 => Some((0xA1, false)), // RIGHTSHIFT -> VK_RSHIFT
            55 => Some((0x6A, false)), // KPASTERISK -> VK_MULTIPLY
            56 => Some((0xA4, false)), // LEFTALT -> VK_LMENU
            57 => Some((0x20, false)), // SPACE -> VK_SPACE
            58 => Some((0x14, false)), // CAPSLOCK -> VK_CAPITAL
            59 => Some((0x70, false)), // F1 -> VK_F1
            60 => Some((0x71, false)), // F2 -> VK_F2
            61 => Some((0x72, false)), // F3 -> VK_F3
            62 => Some((0x73, false)), // F4 -> VK_F4
            63 => Some((0x74, false)), // F5 -> VK_F5
            64 => Some((0x75, false)), // F6 -> VK_F6
            65 => Some((0x76, false)), // F7 -> VK_F7
            66 => Some((0x77, false)), // F8 -> VK_F8
            67 => Some((0x78, false)), // F9 -> VK_F9
            68 => Some((0x79, false)), // F10 -> VK_F10
            87 => Some((0x7A, false)), // F11 -> VK_F11
            88 => Some((0x7B, false)), // F12 -> VK_F12
            97 => Some((0xA3, true)),  // RIGHTCTRL -> VK_RCONTROL (extended)
            100 => Some((0xA5, true)), // RIGHTALT -> VK_RMENU (extended)
            102 => Some((0x24, true)), // HOME -> VK_HOME (extended)
            103 => Some((0x26, true)), // UP -> VK_UP (extended)
            104 => Some((0x21, true)), // PAGEUP -> VK_PRIOR (extended)
            105 => Some((0x25, true)), // LEFT -> VK_LEFT (extended)
            106 => Some((0x27, true)), // RIGHT -> VK_RIGHT (extended)
            107 => Some((0x23, true)), // END -> VK_END (extended)
            108 => Some((0x28, true)), // DOWN -> VK_DOWN (extended)
            109 => Some((0x22, true)), // PAGEDOWN -> VK_NEXT (extended)
            110 => Some((0x2D, true)), // INSERT -> VK_INSERT (extended)
            111 => Some((0x2E, true)), // DELETE -> VK_DELETE (extended)
            113 => Some((0xAD, false)), // MUTE -> VK_VOLUME_MUTE
            114 => Some((0xAE, false)), // VOLUMEDOWN -> VK_VOLUME_DOWN
            115 => Some((0xAF, false)), // VOLUMEUP -> VK_VOLUME_UP
            119 => Some((0x13, false)), // PAUSE -> VK_PAUSE
            125 => Some((0x5B, true)),  // LEFTMETA -> VK_LWIN (extended)
            126 => Some((0x5C, true)),  // RIGHTMETA -> VK_RWIN (extended)
            71 => Some((0x67, false)), // KP7 -> VK_NUMPAD7
            72 => Some((0x68, false)), // KP8 -> VK_NUMPAD8
            73 => Some((0x69, false)), // KP9 -> VK_NUMPAD9
            74 => Some((0x6D, false)), // KPMINUS -> VK_SUBTRACT
            75 => Some((0x64, false)), // KP4 -> VK_NUMPAD4
            76 => Some((0x65, false)), // KP5 -> VK_NUMPAD5
            77 => Some((0x66, false)), // KP6 -> VK_NUMPAD6
            78 => Some((0x6B, false)), // KPPLUS -> VK_ADD
            79 => Some((0x61, false)), // KP1 -> VK_NUMPAD1
            80 => Some((0x62, false)), // KP2 -> VK_NUMPAD2
            81 => Some((0x63, false)), // KP3 -> VK_NUMPAD3
            82 => Some((0x60, false)), // KP0 -> VK_NUMPAD0
            83 => Some((0x6E, false)), // KPDOT -> VK_DECIMAL
            _ => None,
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod other_impl {
    pub fn run() {
        eprintln!("kvm-client is only supported on Windows. Exiting.");
        std::process::exit(1);
    }
}

fn main() {
    #[cfg(target_os = "windows")]
    windows_impl::run();

    #[cfg(not(target_os = "windows"))]
    other_impl::run();
}
