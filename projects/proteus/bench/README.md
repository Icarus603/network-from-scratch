# Linux kernel-netem head-to-head stack

This stack is the executable counterpart of the three-node testbed
specified in lessons 9.10 and 12.11–12.14. It reuses the production
Rust builder in `deploy/Dockerfile`. Hysteria2 is built from pinned
source commit `f2ad1de5da52a1da9622285a1d61553ddaa41f21`.
The inline builder mirrors the official `hyperbole.py build -r`
release flags with an explicit `CGO_ENABLED=0 go build`, while using
the commit timestamp instead of wall-clock build time. This removes
the official Dockerfile's unused C toolchain and removes one source of
wall-clock nondeterminism from repeated builds.

The Hysteria builder and runtime use Alpine's listed Taipei TWDS
mirror for APK packages. `BUILDKIT_CONTEXT_KEEP_GIT_DIR=1` preserves
the pinned checkout metadata inside the build context; the resulting
binary exposes its full source commit and quic-go revision through
`hysteria version`.

Two isolated Docker bridges model the client-side and server-side
networks. The `netem` container is the only node attached to both and
forwards packets at layer 3. Symmetric qdiscs live on its two egress
interfaces, so every Proteus and Hysteria2 packet crosses the same
Linux kernel impairment path.

Every netem qdisc uses a 100,000-packet queue limit. The kernel default
of 1,000 is smaller than the bandwidth-delay product of a 1 Gbit/s,
100 ms path and silently creates queue-overflow loss even in a nominal
0% cell. The validator therefore requires exactly zero qdisc drops in
every 0% IID cell.

Run the small steady-state matrix:

```bash
cd projects/proteus
LOSS_PCT_LIST="0 5 15 30" \
DELAY_MS_LIST="50" \
PAYLOAD_MIB=64 \
RUNS_PER_CELL=7 \
./bench/run-netem-head-to-head.sh
```

The default `WORKLOAD_MODE=proxy` runs the real production-shaped
`proteus-client` SOCKS5 inbound and `proteus-server` CONNECT relay.
Proteus, Hysteria2, and official TUIC v5 therefore receive the same
SOCKS5 CONNECT, stream the same deterministic bytes to the same TCP
echo server, and verify every echoed byte. `WORKLOAD_MODE=legacy`
exists only to reproduce older heterogeneous evidence.

Set `INCLUDE_TUIC=1` to add the upstream TUIC v5 1.0.0 client/server
to this protocol-neutral SOCKS5 workload. The release is checksum
pinned, uses explicit 64 MiB send/receive windows, and remains the
upstream project's latest reference release. The sing-box 1.13.12
TUIC services remain available as a compatibility control, but are
not used by the headline runner because their default QUIC flow-control
windows cap the 100 ms RTT workload far below the upstream reference.
Set `SKIP_BUILD=1` only after the images have been built; the runner
still records every reused image ID in `metadata.jsonl`.

Add Gilbert-Elliott burst-loss cells without changing the topology:

```bash
GEMODEL_CELLS="1%,20%,50%,0%,50;2%,10%,75%,0.1%,50" \
LOSS_PCT_LIST='' \
PAYLOAD_MIB=64 \
RUNS_PER_CELL=7 \
./bench/run-netem-head-to-head.sh
```

Add bidirectional packet-reordering cells with the same router and
workload. Each entry is
`REORDER_PCT,CORRELATION_PCT,ONE_WAY_DELAY_MS`:

```bash
LOSS_PCT_LIST='' \
REORDER_CELLS='5,25,50;25,50,50' \
./bench/run-netem-head-to-head.sh
```

The runner records the requested reorder probability and correlation in
the cell config and summary. The summarizer also validates both egress
objects in `qdisc-applied.json`; a benchmark claim requires the kernel
qdisc to show the intended reorder, correlation, and delay options, not
merely an environment variable. Reordering does not imply packet loss,
so zero qdisc drops remain valid for these cells.

Raw outputs are placed under `bench/results/<UTC timestamp>/`. Every
cell contains the two protocol outputs plus `tc -s -j qdisc` snapshots
before and after the runs. `summarize-netem-results.py` rejects missing
runs, unequal sample counts, traffic that missed either egress qdisc, and
non-zero configured loss that produced no kernel drop. Valid runs also
produce `summary.jsonl`, where both protocols use the same round-trip
equivalent MiB/s definition.
Legacy mode samples client CPU time and peak RSS inside each one-shot
container. Proxy mode records per-request cgroup CPU deltas and
after-run daemon RSS for every long-lived Proteus, Hy2, and TUIC client.
It does not call the latter a peak: Docker Desktop exposes
`memory.peak` read-only, so the runner reports the reproducible
post-observation process RSS instead of inventing resettable peaks.

Legacy one-shot mode uses `STREAM_WINDOW_MIB` and
`CONNECTION_WINDOW_MIB`. Production-shaped proxy mode uses
`PROTEUS_STREAM_RECEIVE_WINDOW_MIB`,
`PROTEUS_CONNECTION_RECEIVE_WINDOW_MIB`, and
`PROTEUS_SEND_WINDOW_MIB` symmetrically on both Proteus peers. Their
defaults remain 64, 256, and 64 MiB; `metadata.jsonl` records every
selected value so a memory/throughput sweep cannot silently drift.
The production binaries use mimalloc, and the container matrix sets
`PROTEUS_MIMALLOC_PURGE_DELAY=0` by default so freed burst pages are
returned to the OS before the post-run RSS snapshot. The selected delay
is recorded in `metadata.jsonl`; set it to `1000` to reproduce mimalloc
v3's upstream asynchronous-purge default.

Each workload driver is fresh, with deterministic AB/BA alternation.
In proxy mode every impairment cell force-recreates all long-lived
client daemons, then runs a recorded warmup through each common
SOCKS workload under that cell's active qdisc. The qdisc-before
snapshot is taken only after warmup, so warmup traffic is excluded
from measured drop deltas. Proteus β, Hy2, and TUIC then all reuse
their warm QUIC carrier across the formal runs in that cell; no
congestion-controller or carrier state crosses cell boundaries.

`PROTEUS_BRUTAL_TARGET_MBPS` overrides both Proteus proxy peers for
controlled Brutal/pacer experiments without editing the checked-in
production-shaped configuration. The runner records the selected value
in `metadata.jsonl`; Hysteria2 stays at its checked-in 1 Gbit/s bandwidth
setting.

`PROTEUS_ACK_ELICITING_THRESHOLD` controls the Proteus RFC 9802 ACK
request for matched recovery experiments. The benchmark default is `1`,
matching the production-safe default. A controlled 5% IID loss / 100 ms
RTT / 256 MiB screening cell measured Proteus medians of 116.4, 111.8,
and 99.0 MiB/s at thresholds `1`, `2`, and `10`, respectively; all three
cells completed 3/3 runs for both implementations. Threshold `10`
therefore remains available only as an explicit experiment, never an
implicit benchmark advantage or production recommendation. The
three-run screen selects a candidate; publication claims still require
the documented 7/30-run gates below.

`PROTEUS_PACKET_THRESHOLD` controls Quinn's packet-number loss-detection
threshold. It defaults to `3`, matching RFC recovery behavior and both
Quinn and Hysteria2's quic-go fork. Raising it is a reordering A/B only:
every promoted value must also rerun real-loss cells because delayed
loss detection can trade away the gains.
The default warmup is `min(PAYLOAD_MIB, 64)` MiB so the congestion
controller reaches a meaningful state rather than merely completing
the handshake. Override it with `WARMUP_MIB`, but do not use zero
because it would fail to exercise the data path. The summary includes a
deterministic 20,000-resample bootstrap interval for median uplift, a
two-sided exact permutation p-value for the mean difference, and the
empirical probability that a Proteus observation exceeds a Hysteria2
observation. Seven runs are the documented minimum; larger publication
runs should use at least 30.

The stack is intentionally isolated (`internal: true` networks).
Only image builds can access the Internet; protocol processes cannot
reach public addresses during a run. The benchmark password and
self-signed certificates are disposable test fixtures, never
production credentials.
