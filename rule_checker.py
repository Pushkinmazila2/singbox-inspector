"""
Rule-drift detector.

Polls sing-box's Clash API (`experimental.clash_api` must be enabled in the
sing-box config) for the live connection table, then re-evaluates each
connection's destination against our own copy of the routing policy
(policy_manifest.yaml) and compares the *expected* outbound to the
*actual* outbound sing-box used.

This does NOT touch packets. It only reads sing-box's own bookkeeping,
so it works identically whether sing-box is native or containerized, as
long as the agent can reach the Clash API (see README for both cases).
"""

import ipaddress
import logging
import time
from dataclasses import dataclass
from typing import Optional

import httpx

import exporter

log = logging.getLogger("rule_checker")


@dataclass
class Rule:
    match: str
    value: Optional[str]
    expected_outbound: str


def load_policy(manifest: dict) -> list[Rule]:
    rules = []
    for r in manifest.get("rules", []):
        rules.append(Rule(match=r["match"], value=r.get("value"), expected_outbound=r["expected_outbound"]))
    if not rules or rules[-1].match != "default":
        log.warning("policy manifest has no trailing 'default' rule — unmatched traffic will be reported as unverifiable")
    return rules


def _domain_matches(rule: Rule, host: str) -> bool:
    if not host:
        return False
    host = host.rstrip(".").lower()
    if rule.match == "domain":
        return host == rule.value.lower()
    if rule.match == "domain_suffix":
        return host == rule.value.lower() or host.endswith("." + rule.value.lower())
    if rule.match == "domain_keyword":
        return rule.value.lower() in host
    return False


def _ip_matches(rule: Rule, ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(rule.value, strict=False)
    except ValueError:
        return False


def evaluate(rules: list[Rule], host: str, dest_ip: str) -> tuple[str, str, bool]:
    """
    Returns (expected_outbound, matched_rule_repr, unverifiable).

    geosite/geoip rules can't be re-evaluated locally without sing-box's
    own geo databases, so we can't tell whether a given destination falls
    under one. Rather than either (a) assuming it never matches — which
    would wrongly fall through to rules below it — or (b) assuming it
    always matches — which wrongly swallows everything below it, we track
    that an unverifiable rule was *passed over* and only report
    unverifiable if we reach the end of the list without a concrete match,
    since at that point one of the skipped geosite/geoip rules may well
    have been the actual match sing-box used.
    """
    passed_unverifiable: list[str] = []
    for rule in rules:
        if rule.match == "default":
            if passed_unverifiable:
                # a geosite/geoip rule sits above this default and could
                # have preempted it — we can't be sure default is correct.
                return rule.expected_outbound, "default", True
            return rule.expected_outbound, "default", False
        if rule.match in ("geosite", "geoip"):
            passed_unverifiable.append(f"{rule.match}:{rule.value}")
            continue
        if rule.match in ("domain", "domain_suffix", "domain_keyword") and _domain_matches(rule, host):
            return rule.expected_outbound, f"{rule.match}:{rule.value}", False
        if rule.match == "ip_cidr" and dest_ip and _ip_matches(rule, dest_ip):
            return rule.expected_outbound, f"ip_cidr:{rule.value}", False
    if passed_unverifiable:
        return "unknown", "+".join(passed_unverifiable), True
    return "unknown", "no_match", True


class RuleChecker:
    def __init__(self, node: str, api_url: str, api_secret: str, rules: list[Rule], timeout: float = 5.0):
        self.node = node
        self.api_url = api_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {api_secret}"} if api_secret else {}
        self.rules = rules
        self.client = httpx.Client(timeout=timeout)
        self._seen_ids: set[str] = set()  # avoid double-counting the same connection every poll

    def poll_once(self) -> None:
        resp = self.client.get(f"{self.api_url}/connections", headers=self.headers)
        resp.raise_for_status()
        data = resp.json()
        conns = data.get("connections", [])
        exporter.active_connections.labels(node=self.node).set(len(conns))

        fresh_ids = set()
        drift = 0
        checked = 0

        for c in conns:
            cid = c.get("id")
            fresh_ids.add(cid)
            if cid in self._seen_ids:
                continue  # already evaluated this connection in a prior cycle

            metadata = c.get("metadata", {})
            host = metadata.get("host") or metadata.get("sniffHost") or ""
            dest_ip = metadata.get("destinationIP", "")
            chains = c.get("chains", [])
            actual_outbound = chains[0] if chains else "unknown"

            expected_outbound, matched_rule, unverifiable = evaluate(self.rules, host, dest_ip)
            checked += 1
            exporter.rule_checks_total.labels(node=self.node).inc()

            if unverifiable:
                exporter.rule_unverifiable_total.labels(node=self.node, rule=matched_rule).inc()
                continue

            if actual_outbound != expected_outbound:
                drift += 1
                exporter.rule_drift_total.labels(
                    node=self.node,
                    rule=matched_rule,
                    expected_outbound=expected_outbound,
                    actual_outbound=actual_outbound,
                ).inc()
                log.warning(
                    "rule drift: host=%s rule=%s expected=%s actual=%s",
                    host, matched_rule, expected_outbound, actual_outbound,
                )

        # rolling window compliance ratio, cheap version: this cycle only
        if checked:
            exporter.rule_compliance_ratio.labels(node=self.node).set((checked - drift) / checked)

        self._seen_ids = fresh_ids
        exporter.agent_last_check_timestamp.labels(node=self.node).set(time.time())

    def run_forever(self, interval: float = 5.0) -> None:
        while True:
            try:
                self.poll_once()
                exporter.agent_up.labels(node=self.node).set(1)
            except httpx.HTTPError as e:
                log.error("clash api unreachable: %s", e)
                exporter.agent_up.labels(node=self.node).set(0)
            time.sleep(interval)
