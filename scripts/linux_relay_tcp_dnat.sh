#!/usr/bin/env bash
#
# رلهٔ TCP فقط با شبکهٔ بومی لینوکس (nftables + ip_forward).
# کاربرد: ورودی عمومی روی سرور واسط (مثلاً ترکیه) → همان پورت روی سرور پشتیبان (مثلاً آلمان).
# کانال UDP دانلود ultraSpoof از این اسکریپت عبور نمی‌کند؛ فقط کنترل TCP.
#
# پیش‌نیاز: nftables (Debian/Ubuntu: apt install nftables)
#
# مثال:
#   export ULTRASPOOF_BACKEND_IP='203.0.113.50'
#   export ULTRASPOOF_WAN_IF='eth0'
#   export ULTRASPOOF_RELAY_PORT='9443'
#   sudo -E ./scripts/linux_relay_tcp_dnat.sh apply
#
# حذف قوانین اضافه‌شده توسط همین اسکریپت:
#   sudo ./scripts/linux_relay_tcp_dnat.sh remove

set -euo pipefail

usage() {
  sed -n '1,25p' "$0" | tail -n +2
  echo "Usage: $0 apply|remove"
}

require_root() {
  if [[ "${EUID:-}" -ne 0 ]]; then
    echo "Run as root (sudo)." >&2
    exit 1
  fi
}

apply_nft() {
  : "${ULTRASPOOF_BACKEND_IP:?Set ULTRASPOOF_BACKEND_IP (backend host IPv4)}"
  : "${ULTRASPOOF_WAN_IF:?Set ULTRASPOOF_WAN_IF (incoming interface, e.g. eth0)}"
  : "${ULTRASPOOF_RELAY_PORT:=9443}"

  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  nft delete table ip ultraspoof_relay_nat 2>/dev/null || true
  nft delete table inet ultraspoof_relay_filter 2>/dev/null || true

  # NAT: DNAT روی اینترفیس اینترنت، سپس SNAT/MASQUERADE برای بسته‌های به سمت بک‌اند
  nft add table ip ultraspoof_relay_nat
  nft add chain ip ultraspoof_relay_nat prerouting \
    '{ type nat hook prerouting priority dstnat; policy accept; }'
  nft add chain ip ultraspoof_relay_nat postrouting \
    '{ type nat hook postrouting priority srcnat; policy accept; }'

  nft add rule ip ultraspoof_relay_nat prerouting \
    iifname "$ULTRASPOOF_WAN_IF" tcp dport "$ULTRASPOOF_RELAY_PORT" \
    dnat to "${ULTRASPOOF_BACKEND_IP}:${ULTRASPOOF_RELAY_PORT}"

  nft add rule ip ultraspoof_relay_nat postrouting \
    ip daddr "$ULTRASPOOF_BACKEND_IP" tcp dport "$ULTRASPOOF_RELAY_PORT" masquerade

  # فیلتر: اجازهٔ فوروارد فقط برای این جریان (+ پاسخ‌های مرتبط)
  nft add table inet ultraspoof_relay_filter
  nft add chain inet ultraspoof_relay_filter forward \
    '{ type filter hook forward priority filter; policy drop; }'

  nft add rule inet ultraspoof_relay_filter forward \
    ct state established,related accept
  nft add rule inet ultraspoof_relay_filter forward \
    iifname "$ULTRASPOOF_WAN_IF" ip daddr "$ULTRASPOOF_BACKEND_IP" \
    tcp dport "$ULTRASPOOF_RELAY_PORT" accept

  echo "Applied nftables rules: WAN_IF=$ULTRASPOOF_WAN_IF port=$ULTRASPOOF_RELAY_PORT -> $ULTRASPOOF_BACKEND_IP"
  echo "Tip: open TCP $ULTRASPOOF_RELAY_PORT on this host firewall (ufw/firewalld) if used."
}

remove_nft() {
  nft delete table ip ultraspoof_relay_nat 2>/dev/null || true
  nft delete table inet ultraspoof_relay_filter 2>/dev/null || true
  echo "Removed tables ip ultraspoof_relay_nat and inet ultraspoof_relay_filter."
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    apply)
      require_root
      apply_nft
      ;;
    remove)
      require_root
      remove_nft
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
}

main "$@"
