"""
Prometheus metrics definitions + HTTP server bootstrap.

All metrics are labeled with `node`, so a single Prometheus instance can
scrape the whole fleet and you slice by node in Grafana.
"""

import logging
from prometheus_client import Counter, Gauge, start_http_server

log = logging.getLogger("exporter")

# ---- rule compliance ----
rule_checks_total = Counter(
    "singbox_rule_checks_total", "Total connections evaluated against policy", ["node"]
)
rule_drift_total = Counter(
    "singbox_rule_drift_total",
    "Connections whose actual outbound did not match policy",
    ["node", "rule", "expected_outbound", "actual_outbound"],
)
rule_unverifiable_total = Counter(
    "singbox_rule_unverifiable_total",
    "Connections matched by geosite/geoip rules we can't verify locally",
    ["node", "rule"],
)
rule_compliance_ratio = Gauge(
    "singbox_rule_compliance_ratio", "Rolling compliance ratio (0-1)", ["node"]
)

# ---- leaks ----
dns_leak_packets_total = Counter(
    "singbox_dns_leak_packets_total", "DNS packets seen bypassing configured resolvers", ["node"]
)
traffic_leak_bytes_total = Counter(
    "singbox_traffic_leak_bytes_total",
    "Bytes observed bypassing the sing-box routing path",
    ["node"],
)
canary_exit_match = Gauge(
    "singbox_canary_exit_match",
    "1 if canary probe exited via expected outbound/country, else 0",
    ["node", "target"],
)
canary_probe_errors_total = Counter(
    "singbox_canary_probe_errors_total", "Canary probe failures (network/timeout)", ["node", "target"]
)

# ---- health ----
active_connections = Gauge("singbox_active_connections", "Active connections per Clash API", ["node"])
agent_last_check_timestamp = Gauge(
    "singbox_agent_last_check_timestamp", "Unix ts of last successful check cycle", ["node"]
)
agent_up = Gauge("singbox_agent_up", "1 if agent's last cycle completed without fatal error", ["node"])


def start_metrics_server(port: int) -> None:
    start_http_server(port)
    log.info("metrics server listening on :%d/metrics", port)
