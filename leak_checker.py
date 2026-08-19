"""
Leak detector: two independent signals.

1. Passive — reads byte/packet counters from an nftables table that is
   expected to catch traffic bypassing the sing-box path (see
   deploy/*/setup-nft-rules.sh for how that table is created). We only
   *read* counters here; the agent never touches firewall rules itself,
   so it needs no write privileges on the ruleset — just CAP_NET_ADMIN
   to run `nft list`.

2. Active — periodically fires real requests at canary targets through
   sing-box's own inbound, and checks the exit IP / country against what
   the policy manifest says should happen. This catches leaks the passive
   nftables signal might miss (e.g. misconfigured DNS resolving to an
   unexpected but still nftables-legal path).
"""

import json
import logging
import subprocess
import time
from dataclasses import dataclass

import httpx

import exporter

log = logging.getLogger("leak_checker")


def read_nft_counters(table: str, family: str = "inet") -> dict:
    """
    Reads named counters from an nftables table via `nft -j list table`.
    Expects counter objects named `dns_leak` and `traffic_leak` inside the
    table (see setup-nft-rules.sh). Returns zeroed dict if table/counters
    are absent so the agent degrades gracefully instead of crashing.
    """
    result = {"dns_leak_packets": 0, "traffic_leak_bytes": 0}
    try:
        out = subprocess.run(
            ["nft", "-j", "list", "table", family, table],
            capture_output=True, text=True, timeout=5, check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.warning("could not read nft table %s: %s", table, e)
        return result

    try:
        data = json.loads(out.stdout)
    except json.JSONDecodeError:
        log.warning("could not parse nft json output")
        return result

    for item in data.get("nftables", []):
        counter = item.get("counter")
        if not counter:
            continue
        name = counter.get("name")
        packets = counter.get("packets", 0)
        bytes_ = counter.get("bytes", 0)
        if name == "dns_leak":
            result["dns_leak_packets"] = packets
        elif name == "traffic_leak":
            result["traffic_leak_bytes"] = bytes_
    return result


@dataclass
class Canary:
    target: str
    expected_outbound: str
    expected_country: str | None = None


class LeakChecker:
    def __init__(self, node: str, nft_table: str, canaries: list[Canary],
                 proxy_url: str | None, geo_lookup: bool = True):
        self.node = node
        self.nft_table = nft_table
        self.canaries = canaries
        self.proxy_url = proxy_url  # e.g. http://127.0.0.1:2080 (sing-box mixed inbound)
        self.geo_lookup = geo_lookup
        self._last_counters = {"dns_leak_packets": 0, "traffic_leak_bytes": 0}
        self.client = httpx.Client(timeout=10.0, proxy=proxy_url) if proxy_url else httpx.Client(timeout=10.0)

    def check_nft_counters(self) -> None:
        counters = read_nft_counters(self.nft_table)
        # counters are cumulative in nftables; emit the delta as increments
        for key, metric in (
            ("dns_leak_packets", exporter.dns_leak_packets_total),
            ("traffic_leak_bytes", exporter.traffic_leak_bytes_total),
        ):
            delta = counters[key] - self._last_counters[key]
            if delta > 0:
                metric.labels(node=self.node).inc(delta)
                log.warning("%s increased by %d", key, delta)
        self._last_counters = counters

    def _check_country(self, ip: str) -> str | None:
        try:
            resp = self.client.get(f"https://ip-api.com/json/{ip}?fields=countryCode", timeout=5.0)
            return resp.json().get("countryCode")
        except httpx.HTTPError:
            return None

    def run_canaries_once(self) -> None:
        for c in self.canaries:
            try:
                resp = self.client.get(c.target)
                exit_ip = resp.text.strip() if "ifconfig" in c.target or "ip" in c.target else None

                ok = resp.status_code < 400
                if ok and c.expected_country and exit_ip and self.geo_lookup:
                    country = self._check_country(exit_ip)
                    ok = country == c.expected_country
                    if not ok:
                        log.warning(
                            "canary %s: exit_ip=%s country=%s expected=%s",
                            c.target, exit_ip, country, c.expected_country,
                        )

                exporter.canary_exit_match.labels(node=self.node, target=c.target).set(1 if ok else 0)
            except httpx.HTTPError as e:
                log.error("canary probe failed for %s: %s", c.target, e)
                exporter.canary_probe_errors_total.labels(node=self.node, target=c.target).inc()
                exporter.canary_exit_match.labels(node=self.node, target=c.target).set(0)

    def run_forever(self, nft_interval: float = 10.0, canary_interval: float = 60.0) -> None:
        last_canary = 0.0
        while True:
            self.check_nft_counters()
            now = time.time()
            if now - last_canary >= canary_interval:
                self.run_canaries_once()
                last_canary = now
            time.sleep(nft_interval)
