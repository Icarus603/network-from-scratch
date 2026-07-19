# `notes/perf/` — persisted bench measurements

Each file in this directory is a snapshot of `proteus-bench`
output captured at a known point in time on a known machine. The
JSON-lines schema is defined in
[`projects/proteus/crates/proteus-bench/src/report.rs`](../../projects/proteus/crates/proteus-bench/src/report.rs)
(`RunReport`) and is append-only — additions never reorder or
rename fields, so old baselines stay parseable indefinitely.

## 2026-07-19 — v1.3 fresh/fresh PCS overhead gate

[`2026-07-19-v13-pcs-overhead.jsonl`](./2026-07-19-v13-pcs-overhead.jsonl)
preserves the matched compile-time-control experiment at commit `f05773a`.
Both modes used the production proxy workload, 512 MiB payloads, 100 ms RTT,
zero configured loss, distinct digest-pinned images, and 30 runs. PCS-enabled
throughput was 0.214% higher than control; client CPU increased 0.342%, with
a +0.040% to +0.859% bootstrap interval. This passes the 1% throughput and
3% statistically positive CPU regression vetoes. The production image also
retained a +96.51% median throughput margin over Hy2 in this cell. This is
a single-host overhead gate; it does not replace the required physical
two-host matrix.

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

### Netem loss-sweep baseline

[`2026-05-19-netem-loss-sweep.jsonl`](2026-05-19-netem-loss-sweep.jsonl):
**16 MiB single-stream β throughput vs synthetic packet-loss
percentage**, 3 runs per cell, Apple Silicon dev box. Loss is
applied by `proteus-bench`'s **in-process UDP forwarder** (see
`crates/proteus-bench/src/netem.rs`) — pure Rust, no Linux
netem / OrbStack VM required, portable across macOS / Windows.

| loss % | n | median MiB/s | min | max | observation |
|---:|---:|---:|---:|---:|---|
| 0  | 3 | 45.0 | 44.8 | 117.2 | Baseline; outlier max is the BBR-warmed run |
| 1  | 3 | 36.1 | 23.7 |  37.0 | Mild degradation; BBR absorbs it |
| 5  | 3 | 21.7 | 12.3 |  28.7 | Cellular-grade loss; ~50% of baseline |
| 15 | 3 | 20.9 | 12.0 |  26.9 | Degraded long-haul; comparable to 5% |
| 30 | 2 |  0.4 |  0.1 |   0.7 | Brutal regime; BBR essentially collapses |

**What this says**:

- **Up to 5–15% loss, β maintains useful throughput** (~20 MiB/s
  / ~0.17 Gbps, half the baseline). This is the realistic 2026
  GFW QUIC-throttling regime where Hy2/TUIC stops being a
  reliable carrier without Brutal CC.
- **At 30% loss, BBR collapses to ~0.4 MiB/s.** This is the
  design point Hysteria2's Brutal congestion controller targets;
  this baseline predates Proteus Brutal and remains the control
  curve for deciding whether the new controller actually helps.
- The wide range at low-loss (44–117 MiB/s at 0%) is the
  BBR-warmup effect: first run pays the bandwidth-probing cost,
  later runs in the same process inherit the converged state.
  Multi-run median is the honest summary; the cold/warm split is
  documented at the cell level for transparency.

**What this does NOT say**:

- **This BBR baseline alone is not a head-to-head vs Hy2/TUIC.**
  The later version-pinned Hysteria2 comparison is recorded in
  [`2026-07-17-proteus-vs-hy2-head-to-head.md`](2026-07-17-proteus-vs-hy2-head-to-head.md);
  keep the two experiments separate because they use different
  controllers and answer different questions.
- **Not a substitute for real netem.** The forwarder models
  independent uniform loss; netem additionally supports
  correlated loss (Gilbert-Elliott), reordering, and corruption.
  A 5% number from the forwarder is a *lower bound* on the
  Gilbert-Elliott reality — bursty loss is harder for BBR than
  uniform loss.
- **Not cross-validated against Linux netem yet.** That's the
  next-step honesty check. Until done, treat these as
  "directionally correct, magnitude-approximate".

### Proteus Brutal: first falsification run

[`2026-07-17-brutal-vs-bbr-15pct.jsonl`](2026-07-17-brutal-vs-bbr-15pct.jsonl)
is the first same-harness comparison after adding a custom quinn
congestion controller. Both cells use a 16 MiB payload, 64 KiB
records, three independent runs, and the same in-process Bernoulli
15% loss injector.

| controller | target | n | median MiB/s | min | max |
|---|---:|---:|---:|---:|---:|
| quinn BBR | auto | 3 | 14.3 | 4.6 | 16.3 |
| Proteus Brutal | 1000 Mbit/s | 3 | 53.1 | 51.3 | 56.4 |

The median improvement over BBR is **3.7×**. The JSON rows include
per-direction received/drop counters; every run observed roughly
20k packets and 2.7k–3.2k drops, so the 15% impairment is measured
evidence rather than a command-line label.

The first implementation attempt failed this falsification: at a
100 Mbit/s target it delivered only 0.82 MiB/s, versus BBR's
10.25 MiB/s in the matching short run. Root cause was an incomplete
`rate × RTT` window with neither Hysteria2's 2× BDP headroom nor
bounded delivery-loss compensation. The corrected controller tracks
five one-second delivery buckets, clamps `ack_rate` to at least 0.8,
uses `2 × BDP / ack_rate`, and paces at `target / ack_rate`, following
the current Hysteria2 contract at upstream commit
`f2ad1de5da52a1da9622285a1d61553ddaa41f21`.

This closes the internal “BBR collapses and Proteus has no answer”
gap. The first version-pinned comparison ran official Hysteria2
commit `f2ad1de5` through the same FIFO forwarder. Across six
same-host cells, Proteus led the normalized round-trip calculation by
8–24%; see
[`2026-07-17-proteus-vs-hy2-head-to-head.md`](2026-07-17-proteus-vs-hy2-head-to-head.md).
Because that matrix used different application workloads, it is now
classified as exploratory controller evidence. The corrected
production SOCKS workload reuses daemon carriers. Its promoted
512 MiB / 100 ms RTT / 30-run cells lead Hy2 by 24.45% at 0% loss
and 7.92% at 5% IID loss, both with positive 95% bootstrap intervals.
The promoted 30-run severe Gilbert-Elliott cell also leads by 6.09%
(95% bootstrap interval +3.90% to +8.59%), with 30/30 successes and
no β-to-α fallback.
Against the upstream TUIC v5 1.0.0 reference with matched 64 MiB
flow-control windows, the promoted 30-run 512 MiB / 5% IID cell leads
by 48.86% (95% bootstrap interval +40.82% to +52.85%), with 30/30
success. The 0% TUIC cell leads by 102.92% but remains a seven-run
directional result.
The 64 MiB / 5% cell remains statistically unresolved at −0.64%, so
the supported claim is sustained-bulk superiority in these same-host
cells, not universal performance dominance.

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
# Netem loss sweep (16 MiB payload across 0/1/5/15/30% loss, 3 runs each):
for loss in 0 1 5 15 30; do
  for _ in 1 2 3; do
    ./target/release/proteus-bench beta \
      --payload-mib 16 --loss-pct $loss \
      --connect-timeout-secs 120 --total-timeout-secs 180 \
      2>/dev/null | grep '^{'
  done
done > netem-sweep.jsonl

# Direct BBR vs Brutal falsification at 15% loss:
./target/release/proteus-bench beta --payload-mib 16 --runs 3 \
  --loss-pct 15 --congestion bbr
./target/release/proteus-bench beta --payload-mib 16 --runs 3 \
  --loss-pct 15 --congestion brutal --brutal-target-mbps 1000
```

```bash
# Soak (100 clients × 60 seconds × 16 KiB):
./target/release/proteus-bench soak \
  --clients 100 --duration-secs 60 --per-session-kib 16 \
  --report-interval-secs 10 \
  2>/dev/null | grep '^{' > soak.jsonl

# Verdict — single jq pull:
jq 'select(.kind=="summary")' soak.jsonl
```
