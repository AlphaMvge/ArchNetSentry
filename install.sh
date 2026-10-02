#!/usr/bin/env bash
# ArchNetSentry Installer Script
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[-] Please run install.sh with sudo or as root.${NC}"
    exit 1
fi

echo -e "${CYAN}[*] Installing ArchNetSentry to /usr/local/bin/archnetsentry...${NC}"
install -Dm755 bin/archnetsentry /usr/local/bin/archnetsentry

if [[ -d completions ]]; then
    echo -e "${CYAN}[*] Installing bash completion...${NC}"
    install -Dm644 completions/archnetsentry.bash /usr/share/bash-completion/completions/archnetsentry 2>/dev/null || true
fi

if [[ -d systemd ]]; then
    echo -e "${CYAN}[*] Installing systemd audit service & timer...${NC}"
    install -Dm644 systemd/archnetsentry-audit.service /usr/lib/systemd/system/archnetsentry-audit.service 2>/dev/null || true
    install -Dm644 systemd/archnetsentry-audit.timer /usr/lib/systemd/system/archnetsentry-audit.timer 2>/dev/null || true
fi

echo -e "${GREEN}[+] ArchNetSentry installation complete!${NC}"
echo -e "${CYAN}[*] Run 'sudo archnetsentry' or 'archnetsentry --help' to get started.${NC}"
