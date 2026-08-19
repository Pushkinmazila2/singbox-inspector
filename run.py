"""
Entry point. Same binary/image runs identically whether sing-box is
native or containerized — the only difference is how the deployment
wrapper (systemd unit vs docker-compose sidecar) gets the agent into the
same network namespace as sing-box. See README.md.

Configuration is entirely via environment variables so the same artifact
works in both deploy/native and deploy/docker without edits.
"""

import logging
import os
import threading

import yaml

import exporter
from leak_checker import Canary, LeakChecker
from rule_checker import RuleChecker, load_policy

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("run")


def env(name: str, default=None, required: bool = False):
    val = os.environ.get(name, default)
    if required and val is None:
        raise RuntimeError(f"missing required env var {name}")
    return val


def main() -> None:
    node = env("NODE_NAME", required=True)
    clash_api_url = env("CLASH_API_URL", "http://127.0.0.1:9090")
    clash_api_secret = env("CLASH_API_SECRET", "")
    metrics_port = int(env("METRICS_PORT", "9091"))
    policy_path = env("POLICY_MANIFEST_PATH", "/etc/singbox-agent/policy_manifest.yaml")
    nft_table = env("NFT_TABLE", "singbox_leak_guard")
    proxy_url = env("CANARY_PROXY_URL")  # e.g. http://127.0.0.1:2080, sing-box mixed inbound
    rule_poll_interval = float(env("RULE_POLL_INTERVAL", "5"))
    nft_poll_interval = float(env("NFT_POLL_INTERVAL", "10"))
    canary_interval = float(env("CANARY_INTERVAL", "60"))
    geo_lookup = env("CANARY_GEO_LOOKUP", "true").lower() == "true"

    with open(policy_path) as f:
        manifest = yaml.safe_load(f)

    rules = load_policy(manifest)
    canaries = [
        Canary(
            target=c["target"],
            expected_outbound=c["expected_outbound"],
            expected_country=c.get("expected_country"),
        )
        for c in manifest.get("canaries", [])
    ]

    exporter.start_metrics_server(metrics_port)

    rule_checker = RuleChecker(node, clash_api_url, clash_api_secret, rules)
    leak_checker = LeakChecker(node, nft_table, canaries, proxy_url, geo_lookup)

    t1 = threading.Thread(target=rule_checker.run_forever, args=(rule_poll_interval,), daemon=True)
    t2 = threading.Thread(
        target=leak_checker.run_forever, args=(nft_poll_interval, canary_interval), daemon=True
    )
    t1.start()
    t2.start()

    log.info("singbox-agent started for node=%s, metrics on :%d/metrics", node, metrics_port)
    t1.join()
    t2.join()


if __name__ == "__main__":
    main()
