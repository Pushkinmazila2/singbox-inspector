# singbox-agent

Verifies that traffic actually routed by sing-box matches your intended
routing policy, and flags leaks (traffic/DNS bypassing sing-box entirely).
Ships Prometheus metrics for both.

Same agent code runs unmodified whether sing-box is native or in Docker —
only the deployment wrapper differs (systemd unit vs. sidecar container),
because in both cases the agent ends up sharing sing-box's network
namespace and can talk to `127.0.0.1`.

## How it works

Two independent detectors, one exporter:

1. **rule_checker.py** — polls sing-box's own Clash API (`/connections`)
   for live connection metadata (destination, matched rule, outbound
   used), re-evaluates the destination against `policy_manifest.yaml`,
   and reports mismatches. Pure read of sing-box's own state — no packet
   capture involved.

2. **leak_checker.py** — two signals:
   - passive: reads nftables counters (set up by `setup-nft-rules.sh`)
     that catch traffic/DNS bypassing the sing-box path entirely.
   - active: periodically fires real requests at "canary" targets
     defined in the manifest and checks exit IP / country against
     expectation.

3. **exporter.py** — Prometheus metrics on `:9091/metrics` for both.

## Prerequisites

- sing-box config has `experimental.clash_api` enabled, e.g.:
  ```json
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "secret": "change-me"
    }
  }
  ```
- If using TUN mode, note your TUN interface name and sing-box's DNS
  listen address — needed for `setup-nft-rules.sh`.

## Setup

1. Copy `policy_manifest.example.yaml` → your real policy, keep it in
   sync with `route.rules` in your sing-box config (ideally generate
   both from one source of truth if your rule set is large).
2. Pick a deployment mode below.
3. Point Prometheus at `deploy/prometheus.example.yml`.

### Native (sing-box installed directly on the host)

```bash
sudo mkdir -p /opt/singbox-agent /etc/singbox-agent
sudo cp -r . /opt/singbox-agent
sudo cp policy_manifest.example.yaml /etc/singbox-agent/policy_manifest.yaml
sudo cp deploy/native/env.example /etc/singbox-agent/env   # edit values
pip install -r requirements.txt --break-system-packages
sudo cp deploy/native/singbox-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now singbox-agent
```

### Docker (sing-box running as a container)

```bash
cd deploy/docker
cp ../../policy_manifest.example.yaml policy_manifest.yaml   # edit values
$EDITOR agent.env     # copied from native/env.example, edit values
docker compose -f ../../docker-compose.yml -f docker-compose.override.yml up -d
```

The override attaches the agent with `network_mode: "service:singbox"`,
so it shares sing-box's netns — Clash API stays reachable at
`127.0.0.1:9090` exactly like in the native case, no port juggling
needed on your end.

## Adjusting nftables detection to your topology

`deploy/setup-nft-rules.sh` is a **template**, not a drop-in. Leak
detection fundamentally depends on how your sing-box TUN/routing is set
up (interface names, fwmarks, uplink interfaces). Read the comments in
the script and adjust `SINGBOX_TUN_IFACE` / `SINGBOX_DNS_IP`, and tighten
the `oifname` exclusion to your actual physical uplink before trusting
the counters in production.

## Metrics reference

| Metric | Meaning |
|---|---|
| `singbox_rule_checks_total` | connections evaluated against policy |
| `singbox_rule_drift_total{rule,expected_outbound,actual_outbound}` | mismatches |
| `singbox_rule_unverifiable_total{rule}` | matched by geosite/geoip, not locally re-checkable |
| `singbox_rule_compliance_ratio` | 0–1, this cycle's match rate |
| `singbox_dns_leak_packets_total` | DNS packets bypassing configured resolver |
| `singbox_traffic_leak_bytes_total` | bytes bypassing the sing-box path |
| `singbox_canary_exit_match{target}` | 1 = canary exited as expected |
| `singbox_canary_probe_errors_total{target}` | canary probe failures |
| `singbox_active_connections` | live connection count from Clash API |
| `singbox_agent_up` | 0 if Clash API unreachable last cycle |

## Known limitations

- `geosite`/`geoip` rules can't be re-verified locally without shipping
  sing-box's own geo databases — they're reported as "unverifiable"
  rather than silently assumed correct. If these matter a lot to you,
  the next step would be embedding the same geo DB sing-box uses.
- `rule_checker` currently only inspects the *first* hop in `chains`
  (the outbound sing-box picked directly), not further hops through
  chained proxies — extend `actual_outbound = chains[0]` in
  `rule_checker.py` if you need full-chain verification.
- The nftables leak rule as templated is intentionally broad; false
  positives are likely until you scope `oifname`/`mark` to your setup.
