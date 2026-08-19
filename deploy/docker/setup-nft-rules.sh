#!/usr/bin/env bash
# setup-nft-rules.sh
#
# Creates an nftables table with two named counters that rule_checker's
# sibling, leak_checker.py, reads (read-only) via `nft -j list table`.
#
# This is a TEMPLATE. You MUST adjust the interface names / fwmark values
# to match your actual sing-box TUN setup — there is no universal way to
# define "traffic that bypassed sing-box" without knowing your topology.
#
# Assumptions to adjust below:
#   - sing-box TUN interface is named tun0 (check your sing-box config:
#     inbounds[].interface_name)
#   - sing-box marks its own outbound traffic with fwmark 0x1 (set this
#     explicitly in sing-box route.rules / route.default_mark if you
#     rely on this rather than interface-based detection)
#   - DNS should only ever go to sing-box's own resolver, e.g. 127.0.0.1
#     or the TUN-assigned resolver IP — adjust ALLOWED_DNS below.

set -euo pipefail

TABLE_NAME="${NFT_TABLE:-singbox_leak_guard}"
TUN_IFACE="${SINGBOX_TUN_IFACE:-tun0}"
ALLOWED_DNS="${SINGBOX_DNS_IP:-127.0.0.1}"

nft add table inet "$TABLE_NAME" 2>/dev/null || true

# --- traffic leak: packets leaving the box on the non-tun path that are
#     NOT destined for the proxy server itself (i.e. not sing-box's own
#     upstream connection) count as a leak. Adjust the "oifname" exclusion
#     list to include your physical uplink interface(s).
nft -- add chain inet "$TABLE_NAME" leak_guard \
    "{ type filter hook output priority 0 ; policy accept ; }" 2>/dev/null || true

nft add counter inet "$TABLE_NAME" traffic_leak 2>/dev/null || true
nft add counter inet "$TABLE_NAME" dns_leak 2>/dev/null || true

# Traffic that should have gone via tun0 (i.e. everything except sing-box's
# own process, which you'd normally exempt via cgroup/uid match) but is
# instead leaving directly — flag it. This rule is intentionally
# conservative; tighten the match to your actual uplink interface name(s)
# such as eth0/ens3 instead of leaving it broad.
nft add rule inet "$TABLE_NAME" leak_guard \
    oifname != "$TUN_IFACE" meta mark != 0x1 counter name traffic_leak 2>/dev/null || true

# DNS leak: any UDP/53 not going to the allowed resolver.
nft add rule inet "$TABLE_NAME" leak_guard \
    udp dport 53 ip daddr != "$ALLOWED_DNS" counter name dns_leak 2>/dev/null || true

echo "nftables leak-guard table '$TABLE_NAME' ready (tun=$TUN_IFACE, dns=$ALLOWED_DNS)"
echo "NOTE: review the generated ruleset with 'nft list table inet $TABLE_NAME' and adjust to your topology before trusting the counters."
