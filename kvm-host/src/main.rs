use clap::Parser;
use evdev::Device;
use kvm_common::{serialize_packet, KvmEvent, KvmPacket, PROTOCOL_VERSION};
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::poll::{poll, PollFd, PollFlags};
use std::collections::HashSet;
use std::net::UdpSocket;
use std::os::fd::BorrowedFd;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Client target address (IP:PORT)
    #[arg(short, long)]
    client: String,

    /// Optional device name filter (default "Logitech")
    #[arg(short, long, default_value = "Logitech")]
    name: String,

    /// Optional specific device path to monitor
    #[arg(short, long)]
    device: Option<String>,

    /// Optional hotkey to toggle grab (e.g. "meta+esc", "ctrl+alt+k", or "125,1")
    #[arg(short, long, default_value = "meta+esc")]
    hotkey: String,
}

struct InputDevice {
    path: PathBuf,
    device: Device,
    is_grabbed: bool,
}

impl Drop for InputDevice {
    fn drop(&mut self) {
        if self.is_grabbed {
            let _ = self.device.ungrab();
            println!("Automatically ungrabbed {:?}", self.path);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    println!("KVM Host Daemon starting...");
    println!("Target client: {}", args.client);

    let hotkey_sets = match parse_hotkey(&args.hotkey) {
        Ok(sets) => sets,
        Err(e) => {
            eprintln!("Invalid hotkey configuration: {}", e);
            std::process::exit(1);
        }
    };
    println!("Hotkey toggle configured: {}", args.hotkey);

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(&args.client)?;
    println!("Socket connected to client {}", args.client);

    // Register signals using signal-hook for clean termination
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&shutdown_flag))?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&shutdown_flag))?;

    let mut devices: Vec<InputDevice> = Vec::new();
    let mut is_grabbed = false;
    let mut active_keys = HashSet::new();
    let mut last_scan = Instant::now() - Duration::from_secs(5); // Force scan on start

    println!("Entering main event loop...");

    while !shutdown_flag.load(Ordering::Relaxed) {
        let now = Instant::now();

        // Scan/rediscover devices matching name filter every 2 seconds
        if args.device.is_none() && now.duration_since(last_scan) >= Duration::from_secs(2) {
            last_scan = now;
            let found_paths = find_matching_devices(&args.name);

            // Remove disconnected devices (which are dropped and thus automatically ungrabbed)
            devices.retain(|d| {
                if !found_paths.contains(&d.path) {
                    println!("Device removed: {:?}", d.path);
                    false
                } else {
                    true
                }
            });

            // Add newly connected devices
            for path in found_paths {
                if !devices.iter().any(|d| d.path == path) {
                    match open_and_prepare_device(&path, is_grabbed) {
                        Ok(input_dev) => {
                            println!("Device added: {:?}", path);
                            devices.push(input_dev);
                        }
                        Err(e) => {
                            eprintln!("Failed to add device {:?}: {:?}", path, e);
                        }
                    }
                }
            }
        } else if args.device.is_some() && devices.is_empty() {
            // Specific device path was specified
            let path = PathBuf::from(args.device.as_ref().unwrap());
            match open_and_prepare_device(&path, is_grabbed) {
                Ok(input_dev) => {
                    println!("Specific device added: {:?}", path);
                    devices.push(input_dev);
                }
                Err(e) => {
                    eprintln!("Failed to open specific device {:?}: {:?}", path, e);
                    std::thread::sleep(Duration::from_secs(2));
                }
            }
        }

        if devices.is_empty() {
            std::thread::sleep(Duration::from_millis(200));
            continue;
        }

        let mut ready_indices = Vec::new();

        // Scope block to confine the immutable borrow of `devices` by the poll fd array
        {
            // Build BorrowedFds first using raw file descriptor borrows
            let borrowed_fds: Vec<BorrowedFd> = devices
                .iter()
                .map(|d| unsafe { BorrowedFd::borrow_raw(d.device.as_raw_fd()) })
                .collect();

            // Build PollFds borrowing from borrowed_fds
            let mut poll_fds: Vec<PollFd> = borrowed_fds
                .iter()
                .map(|fd| PollFd::new(fd, PollFlags::POLLIN))
                .collect();

            // Poll with a 500ms timeout
            let poll_res = poll(&mut poll_fds, 500);

            match poll_res {
                Ok(n) if n > 0 => {
                    for (idx, poll_fd) in poll_fds.iter().enumerate() {
                        if poll_fd.any().unwrap_or_default() {
                            ready_indices.push(idx);
                        }
                    }
                }
                Ok(_) => {
                    // Timeout (no events), check signals and loop
                }
                Err(nix::errno::Errno::EINTR) => {
                    // Interrupted by signal, top of loop checks shutdown flag
                }
                Err(e) => {
                    eprintln!("Poll error: {:?}", e);
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }

        // Now we can safely borrow `devices` mutably since `poll_fds` has been dropped
        let mut devices_to_remove = Vec::new();
        let mut events_to_process = Vec::new();

        for idx in ready_indices {
            let dev_info = &mut devices[idx];
            match dev_info.device.fetch_events() {
                Ok(events) => {
                    for ev in events {
                        events_to_process.push(ev);
                    }
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        eprintln!("Read error on device {:?}: {:?}", dev_info.path, e);
                        devices_to_remove.push(idx);
                    }
                }
            }
        }

        // Remove failed devices in reverse order to preserve indexing
        if !devices_to_remove.is_empty() {
            devices_to_remove.sort_by(|a, b| b.cmp(a));
            for idx in devices_to_remove {
                println!("Removing failed device: {:?}", devices[idx].path);
                devices.remove(idx);
            }
        }

        // Process ready events
        if !events_to_process.is_empty() {
            process_events(
                events_to_process,
                &mut devices,
                &mut is_grabbed,
                &mut active_keys,
                &socket,
                &hotkey_sets,
            )?;
        }
    }

    println!("Shutdown signal received. Ungrabbing all devices and exiting...");
    devices.clear(); // Explicit drop triggers clean ungrab
    Ok(())
}

fn open_and_prepare_device(path: &Path, grab: bool) -> Result<InputDevice, Box<dyn std::error::Error>> {
    let mut device = Device::open(path)?;

    // Set non-blocking using fcntl
    let fd = device.as_raw_fd();
    let flags = fcntl(fd, FcntlArg::F_GETFL)?;
    let mut oflags = OFlag::from_bits_truncate(flags);
    oflags.insert(OFlag::O_NONBLOCK);
    fcntl(fd, FcntlArg::F_SETFL(oflags))?;

    let mut is_grabbed = false;
    if grab {
        if let Err(e) = device.grab() {
            eprintln!("Warning: could not grab device {:?}: {:?}", path, e);
        } else {
            is_grabbed = true;
        }
    }

    Ok(InputDevice {
        path: path.to_path_buf(),
        device,
        is_grabbed,
    })
}

fn find_matching_devices(filter: &str) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let filter_lower = filter.to_lowercase();
    if let Ok(entries) = std::fs::read_dir("/dev/input") {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if let Some(file_name) = path.file_name() {
                    if let Some(name_str) = file_name.to_str() {
                        if name_str.starts_with("event") {
                            if let Ok(device) = Device::open(&path) {
                                if let Some(name) = device.name() {
                                    if name.to_lowercase().contains(&filter_lower) {
                                        found.push(path);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    found
}

fn process_events(
    events: Vec<evdev::InputEvent>,
    devices: &mut [InputDevice],
    is_grabbed: &mut bool,
    active_keys: &mut HashSet<u16>,
    socket: &UdpSocket,
    hotkey_sets: &[HashSet<u16>],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kvm_events = Vec::new();
    let mut toggle_triggered = false;

    for ev in events {
        let event_type = ev.event_type().0;
        let code = ev.code();
        let value = ev.value();

        // Check configured hotkey combination
        if event_type == 1 { // EV_KEY
            if value == 1 { // Press
                active_keys.insert(code);
                
                // Check if the current pressed key is part of the hotkey
                let code_is_part_of_hotkey = hotkey_sets.iter().any(|set| set.contains(&code));
                if code_is_part_of_hotkey {
                    // Check if all sets are satisfied by active_keys
                    let all_satisfied = hotkey_sets.iter().all(|set| {
                        set.iter().any(|k| active_keys.contains(k))
                    });
                    if all_satisfied {
                        toggle_triggered = true;
                    }
                }
            } else if value == 2 { // Repeat
                active_keys.insert(code);
            } else if value == 0 { // Release
                active_keys.remove(&code);
            }
        }

        if toggle_triggered {
            // Consume the trigger key press event so it isn't forwarded
            continue;
        }

        if *is_grabbed {
            kvm_events.push(KvmEvent {
                event_type,
                code,
                value,
            });
        }
    }

    if toggle_triggered {
        let new_state = !*is_grabbed;
        *is_grabbed = new_state;
        println!("Toggle triggered! Grabbed = {}", new_state);

        // Update EVIOCGRAB locks on all devices
        for dev in devices.iter_mut() {
            if dev.is_grabbed != new_state {
                if new_state {
                    match dev.device.grab() {
                        Ok(_) => {
                            dev.is_grabbed = true;
                            println!("Grabbed device: {:?}", dev.path);
                        }
                        Err(e) => {
                            eprintln!("Failed to grab device {:?}: {:?}", dev.path, e);
                        }
                    }
                } else {
                    let _ = dev.device.ungrab();
                    dev.is_grabbed = false;
                    println!("Ungrabbed device: {:?}", dev.path);
                }
            }
        }

        if new_state {
            // Send Handshake
            let packet = KvmPacket::Handshake {
                version: PROTOCOL_VERSION,
            };
            let bytes = serialize_packet(&packet)?;
            let _ = socket.send(&bytes);
        } else {
            // Send ReleaseAll
            let packet = KvmPacket::ReleaseAll;
            let bytes = serialize_packet(&packet)?;
            let _ = socket.send(&bytes);

            // Reset baseline state completely on toggle-off
            active_keys.clear();
        }
    } else if *is_grabbed && !kvm_events.is_empty() {
        // Send events batch
        let packet = KvmPacket::Events(kvm_events);
        let bytes = serialize_packet(&packet)?;
        let _ = socket.send(&bytes);
    }

    Ok(())
}

fn key_name_to_codes(name: &str) -> Result<HashSet<u16>, String> {
    let name_lower = name.trim().to_lowercase();
    
    // Check if it's a numeric keycode first
    if let Ok(code) = name_lower.parse::<u16>() {
        let mut hs = HashSet::new();
        hs.insert(code);
        return Ok(hs);
    }
    
    let codes = match name_lower.as_str() {
        "esc" | "escape" => vec![1],
        "meta" | "super" | "win" | "windows" | "mod" => vec![125, 126],
        "leftmeta" | "lmeta" | "lsuper" | "lwin" => vec![125],
        "rightmeta" | "rmeta" | "rsuper" | "rwin" => vec![126],
        "ctrl" | "control" => vec![29, 97],
        "leftctrl" | "lctrl" => vec![29],
        "rightctrl" | "rctrl" => vec![97],
        "alt" => vec![56, 100],
        "leftalt" | "lalt" => vec![56],
        "rightalt" | "ralt" | "altgr" => vec![100],
        "shift" => vec![42, 54],
        "leftshift" | "lshift" => vec![42],
        "rightshift" | "rshift" => vec![54],
        "space" | "spacebar" => vec![57],
        "enter" | "return" => vec![28],
        "tab" => vec![15],
        "capslock" | "caps" => vec![58],
        "a" => vec![30],
        "b" => vec![48],
        "c" => vec![46],
        "d" => vec![32],
        "e" => vec![18],
        "f" => vec![33],
        "g" => vec![34],
        "h" => vec![35],
        "i" => vec![23],
        "j" => vec![36],
        "k" => vec![37],
        "l" => vec![38],
        "m" => vec![50],
        "n" => vec![49],
        "o" => vec![24],
        "p" => vec![25],
        "q" => vec![16],
        "r" => vec![19],
        "s" => vec![31],
        "t" => vec![20],
        "u" => vec![22],
        "v" => vec![47],
        "w" => vec![17],
        "x" => vec![45],
        "y" => vec![21],
        "z" => vec![44],
        _ => return Err(format!("Unknown key name: '{}'", name)),
    };
    
    Ok(codes.into_iter().collect())
}

fn parse_hotkey(hotkey_str: &str) -> Result<Vec<HashSet<u16>>, String> {
    let parts: Vec<&str> = if hotkey_str.contains('+') {
        hotkey_str.split('+').collect()
    } else if hotkey_str.contains(',') {
        hotkey_str.split(',').collect()
    } else {
        vec![hotkey_str]
    };

    let mut result = Vec::new();
    for part in parts {
        let part = part.trim();
        if !part.is_empty() {
            result.push(key_name_to_codes(part)?);
        }
    }

    if result.is_empty() {
        return Err("Hotkey cannot be empty".to_string());
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hotkey() {
        let hotkey = parse_hotkey("meta+esc").unwrap();
        assert_eq!(hotkey.len(), 2);
        assert!(hotkey[0].contains(&125));
        assert!(hotkey[0].contains(&126));
        assert!(hotkey[1].contains(&1));

        let hotkey2 = parse_hotkey("ctrl,alt,k").unwrap();
        assert_eq!(hotkey2.len(), 3);
        assert!(hotkey2[0].contains(&29));
        assert!(hotkey2[0].contains(&97));
        assert!(hotkey2[1].contains(&56));
        assert!(hotkey2[1].contains(&100));
        assert!(hotkey2[2].contains(&37));

        let hotkey3 = parse_hotkey("125,1").unwrap();
        assert_eq!(hotkey3.len(), 2);
        assert!(hotkey3[0].contains(&125));
        assert!(hotkey3[1].contains(&1));

        assert!(parse_hotkey("unknown+esc").is_err());
    }
}

