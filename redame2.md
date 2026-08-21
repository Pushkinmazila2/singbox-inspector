# singbox-ebpf-agent

Verifies that sing-box actually routes traffic the way its own config
says it should — **without trusting sing-box's self-report** to do it.
Clash API is optional and clearly siloed as a diagnostic, never as fact.

## Why this design (recap of the two constraints it satisfies)

1. **Policy comes from the real, running sing-box config** — no hand-
   maintained manifest. `config_loader.py` parses `route.rules` and
   `outbounds` directly, and uses sing-box's own `rule-set decompile`
   command for compiled geosite/geoip sets, so accuracy matches
   production exactly, with nothing to fall out of sync.

2. **"Actual" routing is observed independently of sing-box**, not read
   from its API:
   - `ebpf/sni_probe.c` — tc program on the TUN interface's egress,
     which is the point where local apps' traffic enters sing-box's
     TUN reader. Extracts the real TLS SNI before sing-box makes any
     decision.
   - `ebpf/connect_probe.c` — kprobe on `tcp_v4_connect`, filtered to
     the sing-box process. This is a kernel/syscall fact: "this PID
     opened a socket to this IP:port at this time" — not something
     sing-box can misreport about itself, because it's the kernel
     answering, not the application.
   - `ebpf/egress_probe.c` — tc program on the physical uplink,
     tracking real flow starts leaving the machine. Currently used for
     future byte-level cross-checks; the core verdict logic uses the
     kprobe as primary ground truth for "where did it actually go".
   - `correlator.py` matches SNI events to kprobe connect events by
     time window + expected server address (from config, not runtime),
     and only then emits a verdict.

Clash API (`diagnostics.py`) is opt-in and writes to a **separate**
metric (`singbox_rule_selfreport_mismatch_total`) so a dashboard can
never confuse "sing-box's opinion of itself" with the verified
`singbox_rule_drift_total`. Persistent disagreement between the two is
itself worth escalating.

## Honest limitations — read before you trust this in production

**Client-side (TUN) track:**
- **Single-packet ClientHello only.** If a TLS ClientHello is
  fragmented across TCP segments, `sni_probe.c` misses it. No event
  fires for that flow; the correlator eventually reports it as
  `no_matching_connect_observed` after the correlation window rather
  than silently assuming compliance — but it's a blind spot, not a
  verified pass. (This exact class of bug already bit us once in
  development — see the SNI-probe verifier fix in git history: BCC's
  rewriter can lose range refinement on a packet-derived length passed
  to `bpf_skb_load_bytes`, producing a spurious "invalid zero-sized
  read" even when the value can't actually be zero at runtime. Fix was
  to always pass a compile-time-constant size to the helper and treat
  the packet-derived length as metadata only, not as a `bpf_skb_load_bytes`
  argument — the same pattern is used throughout `mirror_probe.c`.)
- **ECH (Encrypted Client Hello)** hides the SNI entirely — reported as
  unverifiable/timeout, not falsely "compliant."
- **IPv4 path is complete; IPv6 is stubbed** in both `sni_probe.c` and
  `egress_probe.c`.

**Server-side (inbound) track — methods A/D/E implemented, B/C not yet:**
- **Method A (plaintext: SOCKS/HTTP/Mixed/VLESS-plain)** — SOCKS5 needs
  2 client packets (greeting + CONNECT request); `mirror_probe.c`
  captures exactly 2 fixed 128-byte slots per flow for this reason. If
  a client pipelines more than 128 bytes of greeting before the CONNECT
  request (unusual), the request may not fit in slot 1 and decoding
  will fail — reported as `undecoded:<tag>`, not silently skipped.
- **Method D (static-key: Shadowsocks, VMess)** — both decoders are
  round-trip tested (`decode_shadowsocks`/`decode_vmess_legacy`) against
  synthetic traffic encrypted the same way a real client would.
  **VMess: legacy (pre-AEAD) header format only.** If your sing-box
  build defaults to the newer AEAD header encryption, this decoder will
  reliably fail to decrypt (not silently return a wrong address) —
  that's a signal to implement the AEAD variant, not a false negative
  you'd never notice.
  **Shadowsocks: chacha20-ietf-poly1305 is stubbed, not implemented** —
  only aes-128-gcm/aes-256-gcm actually decrypt today.
  Multi-user inbounds (distinct password per user, or distinct UUID per
  user) are handled by trying every configured candidate — see
  `config_loader.build_inbound_map`'s `passwords`/`uuids` lists.
- **Method E (kernel_dst: Redirect/TProxy)** — `decoders/kernel_original_dst.py`
  is implemented and tested against synthetic `conntrack -L` output, but
  `InboundCorrelator.poll_kernel_dst_inbounds()` is a stub — it needs to
  be wired to an actual flow-enumeration source (e.g. periodic
  `/proc/net/tcp` scan on the redirect/tproxy ports) before Redirect/
  TProxy inbounds produce any verdicts. Not yet done.
- **Methods B/C (TLS/QUIC-wrapped: VLESS+TLS/REALITY, Trojan, Naive,
  ShadowTLS, AnyTLS, Hysteria/Hysteria2/TUIC)** — require the
  `KeyLogWriter` patch to sing-box discussed separately; not part of
  this eBPF-only package. `config_loader.build_inbound_map` correctly
  tags these ports as `tls_wrapped`/`quic_wrapped` and the inbound
  correlator skips them rather than attempting (and failing at) plaintext
  decoding on ciphertext.
- **Correlation is a time-window heuristic** (default 2s,
  `CORRELATION_WINDOW_SECONDS`), same caveat as the TUN track — see
  below for the shared connect_probe kprobe.

**Shared (connect_probe kprobe):**
- **`comm == "sing-box"` matching** assumes the binary is literally
  named that. Rename it or run multiple instances → switch to
  cgroup-based filtering (comment in `connect_probe.c` notes where).
- Both correlators consume the SAME kprobe attachment via
  `connect_tracker.ConnectTracker` — do not instantiate `ConnectTracker`
  more than once per node; `run.py` already handles this correctly for
  the TUN+inbound-both-enabled case.
- **Outbound `server` hostnames resolved once at startup** — restart the
  agent after any DNS change to your own outbound proxy servers.


## Prerequisites

- Recent kernel with BPF ring buffer support (5.8+ recommended).
- `bcc` + kernel headers installed on the node (install via your distro
  package, e.g. `apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)`
  on Debian/Ubuntu — pip's bcc package is best avoided, it's frequently
  out of sync with available kernel headers).
- `sing-box` binary reachable on PATH (or set `SINGBOX_BIN`) — used for
  config merging and rule-set decompilation, not just as the thing
  being monitored.
- Root privileges for the agent process (see service file comments for
  why a narrower capability set isn't practical here).

## Setup

```bash
sudo mkdir -p /opt/singbox-ebpf-agent /etc/singbox-ebpf-agent
sudo cp -r . /opt/singbox-ebpf-agent
sudo cp deploy/env.example /etc/singbox-ebpf-agent/env   # edit: ENABLE_*_MODE, UPLINK_IFACE/PUBLIC_IFACE, SINGBOX_CONFIG_PATH
sudo cp deploy/singbox-ebpf-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now singbox-ebpf-agent
```

`setup-tc-hooks.sh` currently sets up `TUN_IFACE`+`UPLINK_IFACE` — if
running inbound mode, also add the clsact qdisc on `PUBLIC_IFACE`
(same `tc qdisc add dev <iface> clsact` command).

Verify the tc hooks landed:
```bash
tc filter show dev tun0 egress        # TUN mode
tc filter show dev eth0 egress        # TUN mode, your uplink
tc filter show dev eth0 ingress       # inbound mode, your public-facing interface
```

## Metrics

| Metric | Meaning |
|---|---|
| `singbox_rule_checks_total` | flows independently verified |
| `singbox_rule_drift_total{rule,expected_outbound,actual_outbound}` | **verified** mismatch (eBPF ground truth) |
| `singbox_rule_unverifiable_total{rule}` | matched a rule-set we couldn't decompile, or SNI unavailable (ECH/fragmented) |
| `singbox_rule_selfreport_mismatch_total` | **diagnostic only** — Clash API disagreed with expected; not proof of anything by itself |
| `singbox_agent_up` | 1 if the correlator's main loop is alive |

## Suggested next steps

- Add IPv6 mirrors of both tc programs if relevant to your traffic.
- Add a distinct "unexpected connection" metric for connect() events
  from sing-box's PID that don't match ANY known outbound server —
  currently discussed in limitations above but not yet implemented.
- If correlation false-positives show up under load, move to 5-tuple
  flow tagging shared between the SNI probe and the kprobe via an eBPF
  hash map, instead of the time-window heuristic.

## Docker deployment

For nodes where sing-box itself runs containerized, `deploy/docker/`
has a sidecar setup. Two things that matter here specifically (see
in-file comments for the reasoning):

- **The agent container shares sing-box's network namespace**
  (`network_mode: "service:singbox"`) -- tc hooks on `tun0`/the public
  interface only see traffic if they're attached inside the same netns
  sing-box's interfaces actually live in.
- **`connect_probe.c`'s kprobe is unaffected by container boundaries at
  all** -- kprobes operate at kernel level, so it identifies the
  sing-box process by `comm` regardless of which container/netns it's
  in. No special wiring needed for that piece.

```bash
cd deploy/docker
$EDITOR agent.env
SINGBOX_CONFIG_PATH=/path/to/real/config.json \
  docker compose -f ../../docker-compose.yml -f docker-compose.override.yml up -d --build
```

**Known dependency, not hidden:** this image uses BCC, which compiles
the eBPF C at container start against kernel headers -- the compose
file mounts `/usr/src` and `/lib/modules` from the **host** for exactly
this reason. The container is therefore not fully self-contained; it
depends on the host's kernel headers matching what's mounted. If the
host kernel is upgraded and headers change, expect the agent to fail to
compile until the mount catches up.

**The properly portable fix** is migrating off BCC's runtime compilation
onto **CO-RE** (Compile Once -- Run Everywhere): build the `.o` files
once via libbpf + BTF relocations (e.g. in CI), ship a static object
with no dependency on the target's kernel headers or a C compiler at
all, and load it with `libbpf-python` or `aya` instead of `bcc.BPF()`.
This is a real (if contained) rewrite of `correlator.py`,
`inbound_correlator.py`, and `connect_tracker.py`'s loading code -- not
done in this package, tracked as the recommended next step before
running this across a fleet with heterogeneous/frequently-updated
kernels.

**Not tested end-to-end:** no Docker daemon was available while building
this (sandboxed environment, network restricted to package registries) --
YAML/Dockerfile syntax checked, but the actual capability set, mount
behavior, and BCC compile-in-container path need real verification on
your infrastructure before relying on it.
