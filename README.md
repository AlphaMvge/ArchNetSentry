# ArchNetSentry 🌐🔒

> **Arch Linux / Linux Network Security Audit, Encrypted DoH Enforcement & MAC Spoofing Tool**  
> *The Linux equivalent of [WinNetSentry](https://github.com/AlphaMvge/WinNetSentry).*

[![Platform](https://img.shields.io/badge/Platform-Arch%20Linux%20%7C%20Linux-blue?logo=arch-linux)](https://archlinux.org)
[![Shell](https://img.shields.io/badge/Language-Bash-4EAA25?logo=gnu-bash)](https://www.gnu.org/software/bash/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security Hardened](https://img.shields.io/badge/Security-DoT%2FDoH%20Enforced-brightgreen)](#)

---

## 🚀 Overview

**ArchNetSentry** is a lightweight, high-performance security audit and hardening suite engineered specifically for Arch Linux and modern `systemd` / `NetworkManager` Linux systems. 

It provides real-time network listener inspection, process anomaly detection heuristics, encrypted DNS enforcement (DNS-over-TLS / DoH via `systemd-resolved`), dynamic MAC address spoofing, and automated security audit report generation.

---

## ✨ Features

- **🌐 Active Listener & Connection Auditor**: Scans open TCP/UDP ports and active sockets mapped directly to process names and PIDs using `ss`.
- **🕵️ Suspicious Process & Anomaly Detector**: Scans `/proc` for suspicious executables, unlinked binary paths, volatile directory execution (`/tmp`, `/dev/shm`), system binary spoofing, and non-package-owned listening binaries via `pacman -Qo`.
- **🔒 DNS Encryption & Leak Auditor**: Checks `systemd-resolved` and `/etc/resolv.conf` status to ensure DNS queries are encrypted and protected against plaintext ISP leaks.
- **🛡️ Auto-Enforce Encrypted DNS (DoT/DoH)**: One-click setup for Cloudflare, Quad9, AdGuard, or Mullvad DNS-over-TLS via `systemd-resolved` stub configuration.
- **🎭 MAC Address Spoofer & Restorer**: Instantly generates locally administered random MAC addresses for physical network interfaces (`wlan0`, `eth0`), with `ethtool` / `nmcli` hardware restoration fallback.
- **📄 Unified Security Audit Reporting**: Exports structured JSON and Markdown audit reports to `/var/log/archnetsentry/` or `~/.local/share/archnetsentry/reports/`.
- **💻 Full CLI & Interactive UI**: Supports both interactive ANSI color menu and automated command-line flags for scripting / CI integration.

---

## 📥 Installation

```bash
git clone https://github.com/AlphaMvge/ArchNetSentry.git
cd ArchNetSentry
sudo ./install.sh
```

---

## 🎮 Usage

### Interactive Menu Mode
Simply launch `archnetsentry` as root:
```bash
sudo archnetsentry
```

```text
 █████╗ ██████╗  ██████╗██╗  ██╗███╗   ██╗███████╗████████╗███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗
██╔══██╗██╔══██╗██╔════╝██║  ██║████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝
███████║██████╔╝██║     ███████║██╔██╗ ██║█████╗     ██║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ 
██╔══██║██╔══██╗██║     ██╔══██║██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  
██║  ██║██║  ██║╚██████╗██║  ██║██║ ╚████║███████╗   ██║   ███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   
                  -- [ Arch/Linux Network Audit, DoH Securing & MAC Spoofing Tool ] --

  [1] Audit Active Network Listeners & Connections
  [2] Hunt for Irregular / Sketchy Processes
  [3] Audit DNS Leaks & Encryption Status
  [4] Enforce DNS-over-HTTPS / DoT (Cloudflare/Quad9/AdGuard/Mullvad)
  [5] Spoof Network Adapter MAC Address
  [6] Restore Adapter Original MAC Address
  [7] Generate Unified Security Report (Save Logs)
  [8] Exit
```

### Non-Interactive Command-Line Flags
```bash
# Audit active network listeners & connections
sudo archnetsentry --audit

# Run process anomaly scanner
sudo archnetsentry --hunt

# Audit DNS status
sudo archnetsentry --dns

# Enforce Cloudflare DNS-over-TLS
sudo archnetsentry --doh cloudflare

# Enforce Quad9 DNS-over-TLS
sudo archnetsentry --doh quad9

# Randomize MAC address for wlan0
sudo archnetsentry --spoof-mac wlan0

# Restore hardware MAC for wlan0
sudo archnetsentry --restore-mac wlan0

# Generate JSON and Markdown audit reports
sudo archnetsentry --report

# Output raw JSON audit stream to stdout (ideal for pipelines)
sudo archnetsentry --json
```

---

## ⏰ Automated Daily Audit (systemd Timer)

ArchNetSentry includes a systemd timer for automated daily security reporting:

```bash
sudo systemctl enable --now archnetsentry-audit.timer
```

Audit reports will be automatically saved to `/var/log/archnetsentry/`.

---

## 📋 Requirements

- **OS**: Arch Linux or systemd-based Linux distribution
- **Tools**: `bash`, `iproute2` (`ss`, `ip`), `systemd-resolved`, `pacman` (optional, for package heuristics), `ethtool` (optional), `jq` (optional, for formatted JSON output)

---

## 📜 License

Distributed under the [MIT License](LICENSE). Developed for security research, system hardening, and privacy protection.
