# WayKVM — Step-by-Step Installation & Setup Guide

This guide is designed to help you install, compile, and run WayKVM, even if you do not have advanced experience with command-line interfaces or systems programming. 

---

## 📋 Table of Contents
1. [System Architecture Clarification](#-system-architecture-clarification)
2. [Step 1: Install the Rust Toolchain](#step-1-install-the-rust-toolchain)
3. [Step 2: Clone the Project Source Code](#step-2-clone-the-project-source-code)
4. [Step 3: Compile the Binaries](#step-3-compile-the-binaries)
5. [Step 4: Configure the Windows Firewall](#step-4-configure-the-windows-firewall)
6. [Step 5: Identify Host Input Devices (Linux)](#step-5-identify-host-input-devices-linux)
7. [Step 6: Run the Applications](#step-6-run-the-applications)
8. [Step 7: Safety & Emergency Rescue Plan](#step-7-safety--emergency-rescue-plan)

---

## 🔍 System Architecture Clarification

> [!IMPORTANT]
> **Directional Limitation Notice:**
> WayKVM is asymmetric. It is designed **exclusively** to share input devices (keyboard and mouse) connected to your **Linux host** with a **Windows client**.
> *   **Supported:** Linux (Host/Sender) $\rightarrow$ Windows (Client/Receiver)
> *   **NOT Supported:** Windows (Host/Sender) $\rightarrow$ Linux (Client/Receiver)
> Ensure your physical keyboard and mouse are plugged into your Linux computer.

---

## Step 1: Install the Rust Toolchain

To build WayKVM, you need the Rust compiler (`rustc`) and package manager (`cargo`).

### On your Linux Host:
Open a terminal and run the following command to download and install Rust:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
1. When prompted, press `1` and hit `Enter` to proceed with the default installation.
2. Once complete, reload your shell path configurations:
   ```bash
   source "$HOME/.cargo/env"
   ```
3. Verify the installation succeeded:
   ```bash
   rustc --version
   ```

### On your Windows Client:
1. Download the Rust installer from [rustup.rs](https://rustup.rs/).
2. Run `rustup-init.exe`.
3. If prompted to install "Microsoft C++ Build Tools", follow the link, download the installer, select the **Desktop development with C++** workload, and complete the installation.
4. Restart your computer if prompted, then open a Command Prompt or PowerShell and verify:
   ```cmd
   rustc --version
   ```

---

## Step 2: Clone the Project Source Code

You must clone the source code onto **both** machines.

### On Linux:
Run this command to download the code:
```bash
git clone https://github.com/MSpider3/WayKVM.git
cd WayKVM
```

### On Windows:
1. Install Git for Windows if you don't have it (from [git-scm.com](https://git-scm.com/)).
2. Open a Command Prompt, navigate to the folder where you want to download the project, and run:
   ```cmd
   git clone https://github.com/MSpider3/WayKVM.git
   cd WayKVM
   ```

---

## Step 3: Compile the Binaries

### On Linux (Host):
From inside the `WayKVM` directory, run:
```bash
cargo build --release -p kvm-host
```
This builds the release version of the capture daemon. The output binary is created at:
`target/release/kvm-host`

### On Windows (Client):
From inside the `WayKVM` directory, run:
```cmd
cargo build --release -p kvm-client
```
This builds the Windows input injection receiver. The output binary is created at:
`target\release\kvm-client.exe`

---

## Step 4: Configure the Windows Firewall

The Windows client receives inputs over the local network via UDP port `8000`. By default, Windows blocks incoming network packets unless a rule is defined.

1. Right-click the Windows Start menu button and select **Terminal (Admin)** or **PowerShell (Administrator)**.
2. Copy and paste the following command, then press `Enter`:
   ```powershell
   New-NetFirewallRule -DisplayName "WayKVM Client Receiver" -Direction Inbound -Action Allow -Protocol UDP -LocalPort 8000
   ```

---

## Step 5: Identify Host Input Devices (Linux)

WayKVM automatically searches `/dev/input/` for input devices containing a specific string (like `"Logitech"`). If your keyboard/mouse are made by a different manufacturer:

1. List the connected input devices:
   ```bash
   cat /proc/bus/input/devices
   ```
2. Look for the name of your keyboard or mouse receiver (e.g., `Name="Logitech USB Receiver"` or `Name="Razer DeathAdder"`).
3. Note the name. You will pass this name to the host daemon using the `--name` flag (e.g., `--name Razer`).

---

## Step 6: Run the Applications

### 1. Launch the Receiver on Windows First
1. Open a Command Prompt **as Administrator** (search for `cmd` in the Start menu, right-click it, and choose "Run as administrator").
2. Navigate to the built directory:
   ```cmd
   cd target\release
   ```
3. Run the client:
   ```cmd
   kvm-client.exe --bind 0.0.0.0:8000
   ```
   *The client will start listening for network packets.*

### 2. Launch the Host on Linux
1. Find your Windows computer's local IP address (run `ipconfig` in a Windows Command Prompt).
2. Open a terminal on your Linux computer, navigate to the `WayKVM` directory, and run:
   ```bash
   sudo ./target/release/kvm-host --client <WINDOWS_IP>:8000 --name Logitech
   ```
   *(Replace `<WINDOWS_IP>` with your Windows IP, e.g., `192.168.1.15`, and replace `Logitech` with your mouse/keyboard identifier if necessary).*

### 3. Toggle Control
*   Press **`Right Ctrl + K`** on your keyboard.
*   Your mouse and keyboard inputs will be locked on Linux and start moving your cursor and entering characters on Windows.
*   Press **`Right Ctrl + K`** again to return control back to your Linux desktop.

---

## Step 7: Safety & Emergency Rescue Plan

WayKVM locks keyboard and mouse inputs using the kernel's `EVIOCGRAB` feature. In the rare event that the Linux daemon crashes or hangs while inputs are locked, your mouse and keyboard on Linux will freeze.

### Emergency Workarounds:
1.  **Keep a rescue terminal ready:** Keep an SSH client open on your smartphone or a laptop. Connect to your Linux host. If a lockup occurs, type:
    ```bash
    sudo killall kvm-host
    ```
    *WayKVM is programmed to release the locks immediately when it receives a termination signal.*
2.  **Use TTY Switch:** Press `Ctrl + Alt + F3` (or `F4`, `F5`) to drop to a terminal login screen. Log in and kill the process.
3.  **Physical Reset:** Unplug your USB keyboard/mouse dongle from the computer and plug it back in. The Linux kernel will re-initialize the device and clear the lock automatically.
