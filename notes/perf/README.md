# `notes/perf/` — persisted bench measurements

Each file in this directory is a snapshot of `proteus-bench`
output captured at a known point in time on a known machine. The
JSON-lines schema is defined in
[`projects/proteus/crates/proteus-bench/src/report.rs`](../../projects/proteus/crates/proteus-bench/src/report.rs)
(`RunReport`) and is append-only — additions never reorder or
rename fields, so old baselines stay parseable indefinitely.

## Why persist these

The bench harness produces reproducible numbers, but
hand-typed README tables drift the moment someone tweaks a knob.
Persisted JSONL gives us:

- **Regression detection** — future iterations can re-run the
  same matrix and `diff` the JSONL against the baseline.
- **Honest provenance** — every number in the README's
  performance section can cite a specific file here, with the
  exact machine + perf-profile + payload that produced it.
- **Comparison harness** — Hy2 / TUIC operators who want to
  compare can run their own bench, format to the same schema,
  and put the JSONL next to ours. We don't bundle competitors
  (see `crates/proteus-bench/src/lib.rs` for the rationale).

## Naming

`YYYY-MM-DD-<scenario>.jsonl`. Common scenarios:

- `loopback-baseline.jsonl` — same-host bench, no netem, single
  payload + perf-profile matrix
- `netem-loss-sweep.jsonl` — OrbStack Linux VM with
  `tc qdisc add netem loss N% delay N ms` applied to lo0
- `cross-host-vps.jsonl` — real two-host run over a public link

## Today's baseline

[`2026-05-19-loopback-baseline.jsonl`](2026-05-19-loopback-baseline.jsonl):
12 runs spanning 5 cells on Apple Silicon M-series, release
profile, macOS loopback (`127.0.0.1`).

Cells captured (median MiB/s, n=runs):

| payload_MiB | pad_quic_to_mtu | stream_window | n | median MiB/s | range |
|---:|:---:|:---:|---:|---:|---|
| 16  | off | default (64M) | 3 |  53.5 |  53.3 – 55.6 |
| 16  | on  | default       | 1 |  76.7 |  (single sample) |
| 64  | off | default       | 3 | 108.3 |  91.3 – 114.3 |
| 64  | on  | default       | 2 |  87.4 |  85.2 – 89.7 |
| 128 | off | 256M override | 3 | 112.7 | 102.5 – 115.0 |

### What these numbers say

- **Steady-state β single-stream tops ~110 MiB/s (~0.92 Gbps)
  on this dev box**, sustained across 64 MiB and 128 MiB
  payloads. 16 MiB runs are too short to amortize the handshake
  + BBR ramp-up.
- **The 128 MiB run REQUIRES `--stream-window-mib 256`** to
  reach steady state — the production 64 MiB default is the
  flow-control wall on a single stream. Production deploys keep
  the 64 MiB default; multi-stream is the path to higher
  aggregate (M3 multipath QUIC work).
- **`pad_quic_datagrams_to_mtu = true` does NOT consistently
  hurt throughput on loopback** (16 MiB padded actually went
  faster in the one run; 64 MiB padded was ~20% slower). The
  cell-count is too small to draw a confident curve — the
  `pad-true` data is here mostly as a sanity guard against
  catastrophic regression.

### What these numbers do NOT say

- Nothing about adversarial network conditions. Loopback ≠ WAN.
- Nothing about side-by-side comparison vs Hy2 / TUIC. We
  deliberately don't bundle competitor binaries; the cross-
  protocol comparison must be made by the operator with their
  own competitors' tools.
- Nothing about throughput under packet loss / RTT — that's
  what `netem-loss-sweep.jsonl` would land. Pending an OrbStack
  Ubuntu VM run; the bench harness already supports the
  workflow (see `bench/netem-sweep.sh`).

### Soak baseline

[`2026-05-19-soak-100c-60s.jsonl`](2026-05-19-soak-100c-60s.jsonl):
**100 concurrent clients × 60 seconds × 16 KiB per-session payload**
on the same Apple Silicon dev box, in-process server.

| Metric | Value |
|---|---|
| Total dials attempted | 113,849 |
| Dials succeeded | **113,849 (100.00%)** |
| Dials failed | 0 |
| Spawn leaks | **0** |
| Peak concurrent sessions | 100 |
| Mean per-session RTT | 52.3 ms |
| Total bytes (each direction) | 1.86 GB |
| Aggregate dial rate | ~1,900 dials/sec |

**Why this matters**: single-stream throughput (the 64 MiB / 128 MiB
runs above) measures the carrier's ceiling but says nothing about
the binary's stability under realistic concurrent load. The soak
specifically targets the failure modes throughput-mode can't catch:
session leaks, FD leaks, quinn endpoint accumulation, race
conditions in the auto-deny / probe-anomaly code paths.

**Pass criteria** (`SoakSummary::passed`):
- `spawn_leak_count == 0` — every spawned client task completed its
  outer Future (Drop ran, all resources released).
- `success_rate >= --min-success-rate` (default 0.99).
- At least one dial succeeded (rules out "the test never ran").

A failed soak exits the bench binary with status 1 — drop-in
suitable for CI gating ("don't merge this PR if the 60-second
soak doesn't hit 100%").

### How to reproduce

```bash
# Build the bench binary.
cargo build --release -p proteus-bench

# 16 MiB / 64 MiB cells (default window, three runs each, both
# pad-mtu values):
for payload in 16 64; do
  for pad in "" "--pad-mtu"; do
    for _ in 1 2 3; do
      ./target/release/proteus-bench beta --payload-mib $payload $pad \
        --connect-timeout-secs 120 --total-timeout-secs 180 \
        2>/dev/null | grep '^{'
    done
  done
done

# 128 MiB cell needs the bigger stream window:
for _ in 1 2 3; do
  ./target/release/proteus-bench beta --payload-mib 128 \
    --stream-window-mib 256 --connection-window-mib 1024 \
    --connect-timeout-secs 120 --total-timeout-secs 180 \
    2>/dev/null | grep '^{'
done
```

The full matrix takes about 30 seconds on this dev box.

```bash
# Soak (100 clients × 60 seconds × 16 KiB):
./target/release/proteus-bench soak \
  --clients 100 --duration-secs 60 --per-session-kib 16 \
  --report-interval-secs 10 \
  2>/dev/null | grep '^{' > soak.jsonl

# Verdict — single jq pull:
jq 'select(.kind=="summary")' soak.jsonl
```
