#!/usr/bin/env bash
# ArchNetSentry - Arch Linux / Linux Network Audit, DoH Securing & MAC Spoofing Tool
# Equivalent of WinNetSentry.ps1
# Requires root. Designed for Arch Linux (works on most systemd + NetworkManager / systemd-resolved systems).

set -euo pipefail

VERBOSE=${VERBOSE:-0}
SKIP_MENU=${SKIP_MENU:-0}

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
GRAY='\033[0;90m'
NC='\033[0m'

# --- Helpers ---
log() { echo -e "${CYAN}[*]${NC} $*"; }
ok()  { echo -e "${GREEN}[+]${NC} $*"; }
warn(){ echo -e "${YELLOW}[!]${NC} $*"; }
err() { echo -e "${RED}[-]${NC} $*"; }
vlog(){ [[ $VERBOSE -eq 1 ]] && echo -e "${GRAY}[V] $*${NC}"; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        log "ArchNetSentry requires root. Elevating..."
        exec sudo -E bash "$0" "$@"
    fi
}

show_banner() {
    clear
    cat << 'EOF'
 █████╗ ██████╗  ██████╗██╗  ██╗███╗   ██╗███████╗████████╗███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗
██╔══██╗██╔══██╗██╔════╝██║  ██║████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝
███████║██████╔╝██║     ███████║██╔██╗ ██║█████╗     ██║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ 
██╔══██║██╔══██╗██║     ██╔══██║██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  
██║  ██║██║  ██║╚██████╗██║  ██║██║ ╚████║███████╗   ██║   ███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   
EOF
    echo -e "${CYAN}                  -- [ Arch/Linux Network Audit, DoH Securing & MAC Spoofing Tool ] --${NC}"
    echo -e "${CYAN}                  -- [           Developed for Privacy, Security & Hardening        ] --${NC}"
    echo "===================================================================================================="
}

show_header() {
    echo -e "\n${MAGENTA}[>>>] $1${NC}"
    echo "------------------------------------------------------------"
}

pause() {
    echo -e "\n${YELLOW}Press Enter to return to the main menu...${NC}"
    read -r
}

# --- 1. Network Listener & Connection Auditor ---
audit_network_ports() {
    show_header "ACTIVE NETWORK LISTENERS & CONNECTIONS"
    vlog "Enumerating active TCP and UDP sockets..."

    echo -e "\n${CYAN}[!] ACTIVE LISTENERS (PORTS OPEN TO CONNECTION):${NC}"
    # ss -tulnp gives listening sockets with process info
    if command -v ss >/dev/null; then
        ss -tulnp 2>/dev/null | awk '
        BEGIN { printf "%-6s %-22s %-8s %-30s %s\n", "Proto", "Local Address", "Port", "Process", "PID" }
        NR>1 {
            proto=$1; addr=$5; users=$7
            split(addr, a, ":"); port=a[length(a)]
            # portable: extract proc/pid without gawk 3-arg match()
            proc="?"; pid="?"
            if (match(users, /"[^"]+",pid=[0-9]+/)) {
                seg=substr(users, RSTART, RLENGTH)
                sub(/^"/, "", seg)
                sub(/".*/, "", seg); proc=seg
                if (match(users, /pid=[0-9]+/)) {
                    pid=substr(users, RSTART+4, RLENGTH-4)
                }
            }
            printf "%-6s %-22s %-8s %-30s %s\n", proto, addr, port, proc, pid
        }'
    else
        warn "ss not found. Install iproute2."
    fi

    echo -e "\n${CYAN}[!] ESTABLISHED NETWORK CONNECTIONS:${NC}"
    if command -v ss >/dev/null; then
        ss -tunp state established 2>/dev/null | awk '
        BEGIN { printf "%-6s %-25s %-25s %-20s %s\n", "Proto", "Local", "Remote", "Process", "PID" }
        NR>1 {
            proto=$1; local=$4; remote=$5; users=$6
            proc="?"; pid="?"
            if (match(users, /"[^"]+",pid=[0-9]+/)) {
                seg=substr(users, RSTART, RLENGTH)
                sub(/^"/, "", seg)
                sub(/".*/, "", seg); proc=seg
                if (match(users, /pid=[0-9]+/)) {
                    pid=substr(users, RSTART+4, RLENGTH-4)
                }
            }
            printf "%-6s %-25s %-25s %-20s %s\n", proto, local, remote, proc, pid
        }'
    fi
}

# --- 2. Hunt for Irregular / Sketchy Processes ---
hunt_sketchy_processes() {
    show_header "SUSPICIOUS PROCESS & ANOMALY DETECTOR"
    vlog "Running heuristics..."

    local flagged=0
    echo -e "${CYAN}Checking for common anomalies...${NC}\n"

    # Common system binaries that should only live in /usr/bin, /usr/sbin, /bin, /sbin
    local system_bins=(sshd nginx apache2 httpd python python3 node java bash dash sh)
    
    while read -r pid path; do
        local name
        name=$(basename "$path" 2>/dev/null || echo "?")

        [[ -z "$path" || "$path" == "-" ]] && continue

        local reasons=()

        # 1. System-looking binaries from weird locations
        for bin in "${system_bins[@]}"; do
            if [[ "$name" == "$bin" || "$name" == "${bin}."* ]]; then
                if [[ ! "$path" =~ ^/(usr/)?(s)?bin/ && ! "$path" =~ ^/usr/lib ]]; then
                    reasons+=("System-like binary from anomalous path: $path")
                fi
            fi
        done

        # 2. Executing from temp / cache / world-writable locations
        if [[ "$path" =~ /(tmp|Temp|cache|Cache|/dev/shm|/var/tmp)/ ]]; then
            reasons+=("Binary running from volatile/temp path: $path")
        fi

        # 3. No executable bit or weird permissions (basic)
        if [[ -f "$path" && ! -x "$path" ]]; then
            reasons+=("File exists but is not marked executable")
        fi

        # 4. Unsigned-ish: no package ownership (Arch specific)
        if command -v pacman >/dev/null && [[ -f "$path" ]]; then
            if ! pacman -Qo "$path" &>/dev/null; then
                # also check if it has network sockets
                if ss -tulnp 2>/dev/null | grep -q "pid=$pid,"; then
                    reasons+=("Network-listening binary not owned by any package (possible dropped payload)")
                fi
            fi
        fi

        if [[ ${#reasons[@]} -gt 0 ]]; then
            flagged=1
            echo -e "${RED}PID $pid | $name${NC}"
            echo -e "  Path   : $path"
            for r in "${reasons[@]}"; do
                echo -e "  Reason : $r"
            done
            echo
        fi
    done < <(ps -eo pid=,cmd= --no-headers | while read -r pid cmd; do
        # resolve real path of the executable
        # NOTE: 'local' cannot be used in a subshell/pipe; use plain assignment
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)
        echo "$pid $exe"
    done)

    if [[ $flagged -eq 0 ]]; then
        ok "No highly anomalous processes detected."
    else
        warn "Review the findings above carefully."
    fi
}

# --- 3. DNS Leak & Encryption Status ---
get_dns_status() {
    show_header "DNS SECURITY & ENCRYPTION STATUS"
    vlog "Evaluating DNS configuration..."

    local dns_secure=1
    local doh_policy="unknown"

    # systemd-resolved
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        echo -e "${CYAN}systemd-resolved is active${NC}"
        local resolvectl_out
        resolvectl_out=$(resolvectl status 2>/dev/null || true)

        # Check DNSOverTLS / DNSOverHTTPS
        if echo "$resolvectl_out" | grep -qi "DNSOverTLS.*yes\|DNSOverHTTPS.*yes\|DNSOverTLS: yes"; then
            ok "DNS-over-TLS / DoH appears enabled"
            doh_policy="enabled"
        else
            err "DNS-over-TLS / DoH does not appear enforced"
            doh_policy="disabled"
            dns_secure=0
        fi

        echo -e "\n${CYAN}Current DNS servers (per interface):${NC}"
        echo "$resolvectl_out" | grep -E "DNS Servers|Link|DNS Domain" | head -40
    else
        warn "systemd-resolved is not active. Checking /etc/resolv.conf and NetworkManager..."
        doh_policy="not-managed-by-resolved"
        dns_secure=0
    fi

    # Also show classic resolv.conf
    echo -e "\n${CYAN}/etc/resolv.conf:${NC}"
    cat /etc/resolv.conf 2>/dev/null || echo "(not readable)"

    # Heuristic: Cloudflare presence
    local _resolv_cf=0
    grep -qE "1\.1\.1\.1|1\.0\.0\.1|2606:4700:4700::1111" /etc/resolv.conf 2>/dev/null && _resolv_cf=1 || true
    local _resolvectl_cf=0
    resolvectl status 2>/dev/null | grep -qE "1\.1\.1\.1|1\.0\.0\.1" && _resolvectl_cf=1 || true
    if [[ $_resolv_cf -eq 1 || $_resolvectl_cf -eq 1 ]]; then
        ok "Cloudflare DNS addresses detected"
    else
        warn "Cloudflare DNS (1.1.1.1 / 1.0.0.1) not detected → potential plaintext leak risk"
        dns_secure=0
    fi

    if [[ $dns_secure -eq 1 ]]; then
        ok "DNS configuration looks reasonably secure."
    else
        err "DNS configuration is vulnerable or not fully encrypted."
        echo -e "    Select option [4] to enforce Cloudflare DoH via systemd-resolved."
    fi
}

# --- 4. Enforce Cloudflare DNS-over-HTTPS ---
set_secure_dns_cloudflare() {
    show_header "ENFORCING CLOUDFLARE DNS-OVER-HTTPS"

    if ! systemctl is-active --quiet systemd-resolved; then
        warn "systemd-resolved is not running. Attempting to enable it..."
        systemctl enable --now systemd-resolved 2>/dev/null || true
    fi

    # Configure systemd-resolved for Cloudflare + DoT/DoH
    # Modern systemd supports DNSOverTLS=yes and DNS= with DoH templates on newer versions.
    # We use the well-supported DNS-over-TLS approach + Cloudflare IPs (widely available on Arch).

    local conf="/etc/systemd/resolved.conf.d/99-archnetsentry-cloudflare.conf"
    mkdir -p /etc/systemd/resolved.conf.d

    cat > "$conf" << 'EOF'
[Resolve]
DNS=1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com 2606:4700:4700::1111#cloudflare-dns.com 2606:4700:4700::1001#cloudflare-dns.com
FallbackDNS=9.9.9.9#dns.quad9.net
DNSOverTLS=yes
DNSSEC=allow-downgrade
Domains=~.
EOF

    # Make sure resolv.conf points to resolved
    if [[ -f /etc/resolv.conf && ! -L /etc/resolv.conf ]]; then
        log "Backing up /etc/resolv.conf and linking to systemd-resolved..."
        cp /etc/resolv.conf /etc/resolv.conf.bak.archnetsentry 2>/dev/null || true
        ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    fi

    systemctl restart systemd-resolved
    sleep 1

    ok "Cloudflare DNS + DNS-over-TLS applied via systemd-resolved."
    ok "Queries should now be encrypted (DoT). Check with option [3]."
    echo
    resolvectl status | head -30
}

# --- 5 & 6. MAC Address Spoof / Restore ---
generate_random_mac() {
    # Locally administered address: second nibble must be 2,6,A,E
    local second=("2" "6" "A" "E")
    local hex=("0" "1" "2" "3" "4" "5" "6" "7" "8" "9" "A" "B" "C" "D" "E" "F")
    local mac="${hex[$((RANDOM%16))]}${second[$((RANDOM%4))]}"
    for i in {1..5}; do
        mac+=":${hex[$((RANDOM%16))]}${hex[$((RANDOM%16))]}"
    done
    echo "$mac"
}

list_physical_ifaces() {
    # Prefer physical interfaces (exclude lo, docker, veth, bridges, etc.)
    ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -vE '^(lo|docker|veth|br-|virbr|tun|tap|wg)' || true
}

change_mac_address() {
    show_header "SPOOF NETWORK ADAPTER MAC ADDRESS"

    mapfile -t ifaces < <(list_physical_ifaces)
    if [[ ${#ifaces[@]} -eq 0 ]]; then
        err "No suitable physical interfaces found."
        return
    fi

    echo -e "${CYAN}Select an interface to spoof:${NC}"
    for i in "${!ifaces[@]}"; do
        local mac
        mac=$(ip link show "${ifaces[$i]}" | grep -oP 'link/ether \K[0-9a-f:]+' || echo "unknown")
        echo -e "  [${i}] ${ifaces[$i]}  (current MAC: $mac)"
    done

    local choice
    while true; do
        read -rp $'\nEnter selection: ' choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 0 && choice < ${#ifaces[@]} )); then
            break
        fi
        err "Invalid choice."
    done

    local iface="${ifaces[$choice]}"
    local newmac

    echo -e "\n${CYAN}Choose mode:${NC}"
    echo "  [1] Generate random locally-administered MAC (recommended)"
    echo "  [2] Enter custom MAC"
    read -rp "Select mode [1/2]: " mode

    if [[ "$mode" == "2" ]]; then
        while true; do
            read -rp "Enter 12-digit hex MAC (e.g. 02:A1:C3:D4:E5:F6 or 02A1C3D4E5F6): " input
            input=$(echo "$input" | tr -d ':-' | tr 'a-f' 'A-F')
            if [[ "$input" =~ ^[0-9A-F]{12}$ ]]; then
                newmac=$(echo "$input" | sed 's/../&:/g;s/:$//')
                break
            fi
            err "Invalid format."
        done
    else
        newmac=$(generate_random_mac)
        ok "Generated: $newmac"
    fi

    log "Setting MAC of $iface to $newmac ..."
    ip link set dev "$iface" down
    ip link set dev "$iface" address "$newmac"
    ip link set dev "$iface" up

    sleep 1
    local current
    current=$(ip link show "$iface" | grep -oP 'link/ether \K[0-9a-f:]+')
    ok "Adapter cycled."
    echo "  Expected : $newmac"
    echo "  Active   : $current"
    if [[ "${current,,}" == "${newmac,,}" ]]; then
        ok "MAC spoof verified."
    else
        warn "MAC did not stick (driver restriction or interface type)."
    fi
}

restore_mac_address() {
    show_header "RESTORE ORIGINAL ADAPTER MAC ADDRESS"

    mapfile -t ifaces < <(list_physical_ifaces)
    if [[ ${#ifaces[@]} -eq 0 ]]; then
        err "No suitable interfaces found."
        return
    fi

    echo -e "${CYAN}Select interface to restore:${NC}"
    for i in "${!ifaces[@]}"; do
        local mac
        mac=$(ip link show "${ifaces[$i]}" | grep -oP 'link/ether \K[0-9a-f:]+' || echo "unknown")
        echo -e "  [${i}] ${ifaces[$i]}  (current: $mac)"
    done

    local choice
    while true; do
        read -rp $'\nEnter selection: ' choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 0 && choice < ${#ifaces[@]} )); then
            break
        fi
        err "Invalid choice."
    done

    local iface="${ifaces[$choice]}"

    log "Restoring permanent MAC for $iface (via ethtool if available)..."
    if command -v ethtool >/dev/null; then
        # ethtool can sometimes read the permanent address
        local perm
        perm=$(ethtool -P "$iface" 2>/dev/null | awk '{print $3}')
        if [[ -n "$perm" && "$perm" != "00:00:00:00:00:00" ]]; then
            ip link set dev "$iface" down
            ip link set dev "$iface" address "$perm"
            ip link set dev "$iface" up
            ok "Restored to permanent address: $perm"
            return
        fi
    fi

    # Fallback: just bring the interface down/up and hope the driver reloads the factory MAC
    # (many drivers do this when you remove a temporary address)
    warn "Could not determine permanent MAC via ethtool. Performing interface reset."
    ip link set dev "$iface" down
    sleep 1
    ip link set dev "$iface" up
    local current
    current=$(ip link show "$iface" | grep -oP 'link/ether \K[0-9a-f:]+')
    ok "Interface reset. Current MAC: $current"
    echo "  (If it is still the spoofed address, reboot or use the driver's permanent address manually.)"
}

# --- 7. Save Security Report ---
save_security_report() {
    show_header "GENERATING SECURITY AUDIT REPORTS"

    local report_dir="${HOME}/ArchNetSentry/logs"
    mkdir -p "$report_dir"
    local ts
    ts=$(date +%Y%m%d_%H%M%S)
    local json_path="$report_dir/audit_report_${ts}.json"
    local md_path="$report_dir/audit_report_${ts}.md"

    # Collect quick data
    local listeners
    listeners=$(ss -tulnp 2>/dev/null || echo "ss unavailable")
    local established
    established=$(ss -tunp state established 2>/dev/null || echo "")
    local dns_info
    dns_info=$(resolvectl status 2>/dev/null || cat /etc/resolv.conf 2>/dev/null || echo "unavailable")

    # JSON (simple)
    cat > "$json_path" << EOF
{
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "dns_status": $(echo "$dns_info" | head -c 2000 | jq -Rs . 2>/dev/null || echo "\"raw data omitted\""),
  "listeners": $(echo "$listeners" | head -c 5000 | jq -Rs . 2>/dev/null || echo "\"raw data omitted\""),
  "note": "Full details also in the Markdown report"
}
EOF

    # Markdown
    cat > "$md_path" << EOF
# ArchNetSentry Security Audit Report

**Generated on**: $(date)
**System**: $(hostname)
**Kernel**: $(uname -r)

---

## DNS Security Status

\`\`\`
$dns_info
\`\`\`

---

## Active Listeners

\`\`\`
$listeners
\`\`\`

---

## Established Connections

\`\`\`
$established
\`\`\`

---

*ArchNetSentry – for administrative analysis and privacy verification.*
EOF

    ok "JSON report : $json_path"
    ok "Markdown    : $md_path"
}

# --- Main Menu ---
main() {
    require_root "$@"

    if [[ $SKIP_MENU -eq 1 ]]; then
        return
    fi

    while true; do
        show_banner
        echo -e "  ${CYAN}[1]${NC} Audit Active Network Listeners"
        echo -e "  ${CYAN}[2]${NC} Hunt for Irregular / Sketchy Processes"
        echo -e "  ${CYAN}[3]${NC} Audit DNS Leaks & Encryption Status"
        echo -e "  ${GREEN}[4]${NC} Enforce Cloudflare DNS-over-HTTPS / DoT (Auto-Fix)"
        echo -e "  ${YELLOW}[5]${NC} Spoof Network Adapter MAC Address"
        echo -e "  ${YELLOW}[6]${NC} Restore Adapter Original MAC Address"
        echo -e "  ${MAGENTA}[7]${NC} Generate Unified Security Report (Save Logs)"
        echo -e "  ${RED}[8]${NC} Exit"
        echo "===================================================================================================="
        read -rp "Select an option [1-8]: " choice

        case "$choice" in
            1) audit_network_ports; pause ;;
            2) hunt_sketchy_processes; pause ;;
            3) get_dns_status; pause ;;
            4) set_secure_dns_cloudflare; pause ;;
            5) change_mac_address; pause ;;
            6) restore_mac_address; pause ;;
            7) save_security_report; pause ;;
            8) echo -e "\n${GREEN}Thank you for using ArchNetSentry. Stay Secure!${NC}"; exit 0 ;;
            *) err "Invalid option."; sleep 1 ;;
        esac
    done
}

main "$@"
