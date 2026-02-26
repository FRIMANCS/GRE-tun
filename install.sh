#!/bin/sh
set -eu

# =========================
# Defaults (can be changed at runtime)
# =========================
TUN_NAME_DEFAULT="gre1"
MTU_DEFAULT="1360"
TTL_DEFAULT="255"

# These will be asked interactively
IR_PUBLIC=""
FR_PUBLIC=""

IR_TUN_CIDR=""
FR_TUN_CIDR=""
TUN_PEER_IR=""
TUN_PEER_FR=""

TUN_NAME="$TUN_NAME_DEFAULT"
MTU="$MTU_DEFAULT"
TTL="$TTL_DEFAULT"

SERVICE_PATH=""

# =========================
# Helpers
# =========================
log() { printf "%s\n" "$*"; }
warn() { printf "WARN: %s\n" "$*" >&2; }
die() { printf "ERROR: %s\n" "$*" >&2; exit 1; }

need_root() {
  [ "$(id -u)" = "0" ] || die "Run as root (sudo su -)."
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

detect_wan_if() {
  ip route show default 2>/dev/null | awk 'NR==1{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}

enable_module() {
  if have_cmd modprobe; then
    modprobe ip_gre 2>/dev/null || true
  fi
}

ip_forward_on() {
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  if [ -f /etc/sysctl.conf ]; then
    if ! grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null; then
      printf "\nnet.ipv4.ip_forward=1\n" >> /etc/sysctl.conf
    fi
  else
    printf "net.ipv4.ip_forward=1\n" > /etc/sysctl.conf
  fi
  sysctl -p >/dev/null 2>&1 || true
}

allow_gre_firewall() {
  # Allow GRE protocol 47 (best-effort)
  if have_cmd ufw && ufw status >/dev/null 2>&1; then
    ufw allow proto gre >/dev/null 2>&1 || true
    ufw reload >/dev/null 2>&1 || true
    log "Firewall: ufw allow proto gre"
    return 0
  fi

  if have_cmd iptables; then
    iptables -C INPUT  -p gre -j ACCEPT >/dev/null 2>&1 || iptables -I INPUT  -p gre -j ACCEPT >/dev/null 2>&1 || true
    iptables -C OUTPUT -p gre -j ACCEPT >/dev/null 2>&1 || iptables -I OUTPUT -p gre -j ACCEPT >/dev/null 2>&1 || true
    log "Firewall: iptables allow gre (best-effort, not persisted) (NOTE: does NOT open provider firewall)"
    return 0
  fi

  warn "No ufw/iptables found. Ensure GRE (protocol 47) is allowed in your provider firewall too."
}

delete_tunnel_runtime() {
  ip link set "$TUN_NAME" down >/dev/null 2>&1 || true
  ip tunnel del "$TUN_NAME" >/dev/null 2>&1 || true
}

create_tunnel_runtime() {
  local local_ip="$1"
  local remote_ip="$2"
  local tun_cidr="$3"
  local mtu="$4"
  local ttl="$5"

  delete_tunnel_runtime

  ip tunnel add "$TUN_NAME" mode gre local "$local_ip" remote "$remote_ip" ttl "$ttl"
  ip addr add "$tun_cidr" dev "$TUN_NAME"
  ip link set "$TUN_NAME" mtu "$mtu"
  ip link set "$TUN_NAME" up
}

write_systemd_service() {
  local local_ip="$1"
  local remote_ip="$2"
  local tun_cidr="$3"
  local mtu="$4"
  local ttl="$5"

  SERVICE_PATH="/etc/systemd/system/${TUN_NAME}.service"

  cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=GRE Tunnel ${TUN_NAME}
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/modprobe ip_gre
ExecStart=/sbin/ip tunnel add ${TUN_NAME} mode gre local ${local_ip} remote ${remote_ip} ttl ${ttl}
ExecStart=/sbin/ip addr add ${tun_cidr} dev ${TUN_NAME}
ExecStart=/sbin/ip link set ${TUN_NAME} mtu ${mtu}
ExecStart=/sbin/ip link set ${TUN_NAME} up
ExecStop=/sbin/ip link set ${TUN_NAME} down
ExecStop=/sbin/ip tunnel del ${TUN_NAME}

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "${TUN_NAME}.service"
}

status_info() {
  log "=== Tunnel status ==="
  ip -d tunnel show "$TUN_NAME" || true
  ip addr show dev "$TUN_NAME" || true
  ip -s link show "$TUN_NAME" || true
  log "=== Service status ==="
  systemctl status "${TUN_NAME}.service" -l --no-pager || true
}

ping_test() {
  local target="$1"
  log "=== Ping test: $target ==="
  ping -c 4 "$target" || true
}

setup_nat_on_exit() {
  local wan_if
  wan_if="$(detect_wan_if)"
  [ -n "$wan_if" ] || die "Could not detect WAN interface for NAT."

  ip_forward_on

  if have_cmd iptables; then
    iptables -t nat -C POSTROUTING -o "$wan_if" -j MASQUERADE >/dev/null 2>&1 || \
      iptables -t nat -A POSTROUTING -o "$wan_if" -j MASQUERADE

    iptables -C FORWARD -i "$TUN_NAME" -j ACCEPT >/dev/null 2>&1 || iptables -A FORWARD -i "$TUN_NAME" -j ACCEPT
    iptables -C FORWARD -o "$TUN_NAME" -j ACCEPT >/dev/null 2>&1 || iptables -A FORWARD -o "$TUN_NAME" -j ACCEPT

    log "NAT enabled on $wan_if (iptables, not persisted)."
    log "If you want persistence: apt-get install -y iptables-persistent"
  else
    warn "iptables not found; NAT not configured."
  fi
}

setup_policy_routing_on_entry() {
  ip_forward_on

  log "Choose one method:"
  log "  1) Route traffic with fwmark=0x1 via GRE (recommended)"
  log "  2) Route traffic from a specific source IP via GRE"
  printf "Select [1-2] (default 1): "
  read ans || true
  ans="${ans:-1}"

  # Ask peer explicitly (no defaults)
  printf "Enter GRE exit peer tunnel IP (example: 10.10.10.2): "
  read peer || true
  [ -n "${peer:-}" ] || die "No peer tunnel IP provided."

  # Create routing table 100
  if ! grep -qE '^\s*100\s+greout\s*$' /etc/iproute2/rt_tables 2>/dev/null; then
    printf "\n100 greout\n" >> /etc/iproute2/rt_tables 2>/dev/null || true
  fi

  ip route replace default via "$peer" dev "$TUN_NAME" table greout

  if [ "$ans" = "2" ]; then
    printf "Enter source IP to route via GRE (example: your service IP): "
    read srcip || true
    [ -n "${srcip:-}" ] || die "No source IP provided."
    ip rule add from "$srcip" table greout priority 1000 2>/dev/null || true
    log "Policy rule added: from $srcip -> table greout"
  else
    ip rule add fwmark 0x1 table greout priority 1000 2>/dev/null || true
    log "Policy rule added: fwmark 0x1 -> table greout"
    log "Now mark traffic you want to go via GRE, examples:"
    log "  - Mark a destination IP:"
    log "      iptables -t mangle -A OUTPUT -d 8.8.8.8 -j MARK --set-mark 1"
    log "  - Mark a local port (e.g., 443):"
    log "      iptables -t mangle -A OUTPUT -p tcp --dport 443 -j MARK --set-mark 1"
    log "Note: mangle rules are not persisted by default."
  fi
}

uninstall_all() {
  systemctl disable --now "${TUN_NAME}.service" >/dev/null 2>&1 || true
  [ -n "${SERVICE_PATH:-}" ] && rm -f "$SERVICE_PATH" >/dev/null 2>&1 || true
  # If SERVICE_PATH wasn't set yet, try default path
  rm -f "/etc/systemd/system/${TUN_NAME}.service" >/dev/null 2>&1 || true
  systemctl daemon-reload >/dev/null 2>&1 || true
  delete_tunnel_runtime
  log "Uninstalled: ${TUN_NAME} and systemd service."
}

show_logs_hint() {
  log "Logs:"
  log "  journalctl -u ${TUN_NAME}.service -n 100 --no-pager"
  log "  journalctl -u ${TUN_NAME}.service -f"
  log "Network monitors (useful when it 'cuts' under load):"
  log "  ip monitor link"
  log "  ip monitor route"
}

print_menu() {
  log ""
  log "=============================="
  log " GRE Tunnel Installer (sh)"
  log " Tunnel: $TUN_NAME"
  log " IR public: $IR_PUBLIC   FR public: $FR_PUBLIC"
  log " IR tun: $IR_TUN_CIDR   FR tun: $FR_TUN_CIDR"
  log "=============================="
  log "1) Install on IRAN server (client side)  - local=$IR_PUBLIC remote=$FR_PUBLIC tun=$IR_TUN_CIDR"
  log "2) Install on FOREIGN server (exit side) - local=$FR_PUBLIC remote=$IR_PUBLIC tun=$FR_TUN_CIDR"
  log "3) Enable NAT on this server (exit only)"
  log "4) Policy routing on this server (entry only, avoid SSH cut)"
  log "5) Show status + logs hint"
  log "6) Uninstall"
  log "0) Exit"
  log "=============================="
  printf "Select: "
}

ask_config() {
  log "=== Initial config (required) ==="

  printf "Enter IRAN public IP: "
  read IR_PUBLIC || true
  [ -n "${IR_PUBLIC:-}" ] || die "IRAN public IP cannot be empty."

  printf "Enter FOREIGN public IP: "
  read FR_PUBLIC || true
  [ -n "${FR_PUBLIC:-}" ] || die "FOREIGN public IP cannot be empty."

  printf "Enter IRAN tunnel LOCAL CIDR (example: 10.10.10.1/30): "
  read IR_TUN_CIDR || true
  [ -n "${IR_TUN_CIDR:-}" ] || die "IRAN tunnel CIDR cannot be empty."

  printf "Enter FOREIGN tunnel LOCAL CIDR (example: 10.10.10.2/30): "
  read FR_TUN_CIDR || true
  [ -n "${FR_TUN_CIDR:-}" ] || die "FOREIGN tunnel CIDR cannot be empty."

  printf "Enter IRAN tunnel LOCAL IP without mask (peer for FOREIGN ping) (example: 10.10.10.1): "
  read TUN_PEER_IR || true
  [ -n "${TUN_PEER_IR:-}" ] || die "TUN_PEER_IR cannot be empty."

  printf "Enter FOREIGN tunnel LOCAL IP without mask (peer for IRAN ping) (example: 10.10.10.2): "
  read TUN_PEER_FR || true
  [ -n "${TUN_PEER_FR:-}" ] || die "TUN_PEER_FR cannot be empty."

  printf "Tunnel name (default: %s): " "$TUN_NAME_DEFAULT"
  read tn || true
  TUN_NAME="${tn:-$TUN_NAME_DEFAULT}"

  printf "MTU (default: %s): " "$MTU_DEFAULT"
  read mtu || true
  MTU="${mtu:-$MTU_DEFAULT}"

  printf "TTL (default: %s): " "$TTL_DEFAULT"
  read ttl || true
  TTL="${ttl:-$TTL_DEFAULT}"

  SERVICE_PATH="/etc/systemd/system/${TUN_NAME}.service"

  log "=== Config summary ==="
  log "TUN_NAME=$TUN_NAME  MTU=$MTU  TTL=$TTL"
  log "IR_PUBLIC=$IR_PUBLIC"
  log "FR_PUBLIC=$FR_PUBLIC"
  log "IR_TUN_CIDR=$IR_TUN_CIDR (peer IP: $TUN_PEER_IR)"
  log "FR_TUN_CIDR=$FR_TUN_CIDR (peer IP: $TUN_PEER_FR)"
}

main() {
  need_root
  ask_config
  enable_module
  allow_gre_firewall

  while :; do
    print_menu
    read choice || true
    case "${choice:-}" in
      1)
        log "Installing GRE on IRAN server..."
        create_tunnel_runtime "$IR_PUBLIC" "$FR_PUBLIC" "$IR_TUN_CIDR" "$MTU" "$TTL"
        write_systemd_service "$IR_PUBLIC" "$FR_PUBLIC" "$IR_TUN_CIDR" "$MTU" "$TTL"
        status_info
        ping_test "$TUN_PEER_FR"
        ;;
      2)
        log "Installing GRE on FOREIGN server..."
        create_tunnel_runtime "$FR_PUBLIC" "$IR_PUBLIC" "$FR_TUN_CIDR" "$MTU" "$TTL"
        write_systemd_service "$FR_PUBLIC" "$IR_PUBLIC" "$FR_TUN_CIDR" "$MTU" "$TTL"
        status_info
        ping_test "$TUN_PEER_IR"
        ;;
      3)
        log "Enabling NAT (exit server use-case)..."
        setup_nat_on_exit
        ;;
      4)
        log "Setting policy routing (entry server use-case)..."
        setup_policy_routing_on_entry
        ;;
      5)
        status_info
        show_logs_hint
        ;;
      6)
        uninstall_all
        ;;
      0)
        exit 0
        ;;
      *)
        warn "Invalid choice."
        ;;
    esac
  done
}

main "$@"
