#!/usr/bin/env bash
#
# فقط روی سرور واسط (ترکیه): DNAT + SNAT با nftables — بدون نصب برنامه.
# آلمان UDP عادی به TR_PUBLIC:RELAY_UDP می‌فرستد؛ خروجی به ایران با src=spoof_source_ip.
#
# متغیرها را تنظیم کنید، سپس:
#   sudo -E ./scripts/linux_relay_udp_snat_turkey.sh apply
#   sudo ./scripts/linux_relay_udp_snat_turkey.sh remove
#
# روی آلمان در server.download مقدار udp_relay را بگذارید: "TR_PUBLIC_IP:RELAY_UDP"
# (همان پورت RELAY_UDP). iran_ip و iran_udp_port و spoof_source_ip مثل قبل با کلاینت ایران یکی باشد.

set -euo pipefail

usage() {
  sed -n '1,20p' "$0" | tail -n +2
  echo "Usage: $0 apply|remove"
}

require_root() {
  if [[ "${EUID:-}" -ne 0 ]]; then
    echo "Run as root (sudo)." >&2
    exit 1
  fi
}

apply_rules() {
  : "${ULTRASPOOF_WAN_IF:?Set ULTRASPOOF_WAN_IF (e.g. eth0)}"
  : "${ULTRASPOOF_RELAY_UDP_PORT:?Set ULTRASPOOF_RELAY_UDP_PORT (UDP port on Turkey, e.g. 9450)}"
  : "${ULTRASPOOF_IRAN_IP:?Set ULTRASPOOF_IRAN_IP (client public IPv4)}"
  : "${ULTRASPOOF_IRAN_UDP_PORT:?Set ULTRASPOOF_IRAN_UDP_PORT (e.g. 9444)}"
  : "${ULTRASPOOF_SPOOF_SOURCE_IP:?Set ULTRASPOOF_SPOOF_SOURCE_IP (same as spoof_source_ip in configs)}"

  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  nft delete table ip ultraspoof_udp_gw_nat 2>/dev/null || true
  nft delete table inet ultraspoof_udp_gw_filter 2>/dev/null || true

  nft add table ip ultraspoof_udp_gw_nat
  nft add chain ip ultraspoof_udp_gw_nat prerouting \
    '{ type nat hook prerouting priority dstnat; policy accept; }'
  nft add chain ip ultraspoof_udp_gw_nat postrouting \
    '{ type nat hook postrouting priority srcnat; policy accept; }'

  nft add rule ip ultraspoof_udp_gw_nat prerouting \
    iifname "$ULTRASPOOF_WAN_IF" udp dport "$ULTRASPOOF_RELAY_UDP_PORT" \
    dnat to "${ULTRASPOOF_IRAN_IP}:${ULTRASPOOF_IRAN_UDP_PORT}"

  nft add rule ip ultraspoof_udp_gw_nat postrouting \
    ip daddr "$ULTRASPOOF_IRAN_IP" udp dport "$ULTRASPOOF_IRAN_UDP_PORT" \
    snat to "$ULTRASPOOF_SPOOF_SOURCE_IP"

  nft add table inet ultraspoof_udp_gw_filter
  nft add chain inet ultraspoof_udp_gw_filter forward \
    '{ type filter hook forward priority filter; policy drop; }'

  nft add rule inet ultraspoof_udp_gw_filter forward \
    ct state established,related accept
  nft add rule inet ultraspoof_udp_gw_filter forward \
    iifname "$ULTRASPOOF_WAN_IF" \
    ip daddr "$ULTRASPOOF_IRAN_IP" udp dport "$ULTRASPOOF_IRAN_UDP_PORT" accept

  echo "Applied UDP relay NAT: relay_port=$ULTRASPOOF_RELAY_UDP_PORT -> ${ULTRASPOOF_IRAN_IP}:${ULTRASPOOF_IRAN_UDP_PORT} snat=$ULTRASPOOF_SPOOF_SOURCE_IP"
  echo "Open UDP $ULTRASPOOF_RELAY_UDP_PORT on this host if a host firewall blocks it."
}

remove_rules() {
  nft delete table ip ultraspoof_udp_gw_nat 2>/dev/null || true
  nft delete table inet ultraspoof_udp_gw_filter 2>/dev/null || true
  echo "Removed ultraspoof_udp_gw_* tables."
}

main() {
  case "${1:-}" in
    apply)
      require_root
      apply_rules
      ;;
    remove)
      require_root
      remove_rules
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
