#!/usr/bin/env bash
# ArchNetSentry Uninstaller Script
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[-] Please run uninstall.sh with sudo or as root."
    exit 1
fi

echo "[*] Removing ArchNetSentry files..."
rm -f /usr/local/bin/archnetsentry
rm -f /usr/share/bash-completion/completions/archnetsentry
rm -f /usr/lib/systemd/system/archnetsentry-audit.service
rm -f /usr/lib/systemd/system/archnetsentry-audit.timer

echo "[+] ArchNetSentry successfully uninstalled."
