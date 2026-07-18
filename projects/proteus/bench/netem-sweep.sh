#!/usr/bin/env bash
# Proteus β throughput-vs-loss sweep using Linux netem.
#
# Runs `proteus-bench beta` repeatedly under varying netem-imposed
# packet-loss / RTT / bandwidth-cap conditions, emitting one JSON line
# per run to stdout. The JSON schema is defined in
# `crates/proteus-bench/src/report.rs::RunReport` and is append-only.
#
# Usage (inside a Linux VM with CAP_NET_ADMIN — OrbStack works):
#
#   sudo ./bench/netem-sweep.sh > /tmp/proteus-bench.jsonl
#   jq -c '.' /tmp/proteus-bench.jsonl  # pretty-print
#   jq -r '[.mib_per_sec, .netem_loss_pct, .netem_delay_ms] | @csv' \
#        /tmp/proteus-bench.jsonl > /tmp/proteus-bench.csv
#
# Why bash, not a Rust driver: netem requires `tc qdisc` calls with
# root/CAP_NET_ADMIN. Bundling that into the Rust harness would force
# either (a) running `proteus-bench` as root (refuse), or (b) shelling
# out from Rust to `sudo tc ...` (just bash with extra steps). The
# bash script is shorter, more obvious, and the JSON-line output is
# what scripts care about anyway.
#
# Honesty caveat: this is the harness, not a head-to-head against Hy2/
# TUIC. To compare, run Hy2/TUIC's own throughput tools under the same
# netem config and combine the JSON files. The Proteus side is
# reproducible; making the comparison rigorous requires the operator
# to run the competitors with parameters they consider fair (Brutal
# rate setting, etc.) — we deliberately don't ship those configs.
#
# Sweep parameters: tunable via env vars.
#   LOSS_PCT_LIST   - whitespace-separated, default "0 1 5 15 30"
#   DELAY_MS_LIST   - whitespace-separated, default "0 10 50 200"
#   RATE_MBIT_LIST  - "0" = unlimited, default "0 100 1000"
#   PAYLOAD_MIB     - default 64 (large enough to amortize handshake)
#   RUNS_PER_CELL   - repeats per (loss, delay, rate), default 3
#   CONGESTION      - "bbr" or "brutal", default "brutal"
#   BRUTAL_TARGET_MBPS - operator-measured capacity, default 1000

set -euo pipefail

LOSS_PCT_LIST="${LOSS_PCT_LIST:-0 1 5 15 30}"
DELAY_MS_LIST="${DELAY_MS_LIST:-0 10 50 200}"
RATE_MBIT_LIST="${RATE_MBIT_LIST:-0 100 1000}"
PAYLOAD_MIB="${PAYLOAD_MIB:-64}"
RUNS_PER_CELL="${RUNS_PER_CELL:-3}"
CONGESTION="${CONGESTION:-brutal}"
BRUTAL_TARGET_MBPS="${BRUTAL_TARGET_MBPS:-1000}"
IFACE="${IFACE:-lo}"

if [[ "${CONGESTION}" != "bbr" && "${CONGESTION}" != "brutal" ]]; then
  echo "CONGESTION must be bbr or brutal, got ${CONGESTION}" >&2
  exit 1
fi
if [[ ! "${BRUTAL_TARGET_MBPS}" =~ ^[1-9][0-9]*$ ]]; then
  echo "BRUTAL_TARGET_MBPS must be a positive integer" >&2
  exit 1
fi

# proteus-bench should be findable in the cargo build dir or PATH.
BENCH_BIN="${BENCH_BIN:-./target/release/proteus-bench}"
if [[ ! -x "${BENCH_BIN}" ]]; then
  echo "proteus-bench not found at ${BENCH_BIN}" >&2
  echo "Build it first: cargo build --release -p proteus-bench" >&2
  exit 1
fi

# Linux-only sanity check. macOS / BSD don't have netem at all.
if ! command -v tc >/dev/null 2>&1; then
  echo "tc(8) not found — this script requires Linux + iproute2" >&2
  exit 1
fi

# Always clean up the netem qdisc on exit, even on failure / Ctrl-C.
cleanup() {
  sudo tc qdisc del dev "${IFACE}" root 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Helper: set netem to specific (loss, delay, rate). Empty values
# omit the parameter so we can express "loss only" or "rate only".
set_netem() {
  local loss="$1" delay="$2" rate="$3"
  sudo tc qdisc del dev "${IFACE}" root 2>/dev/null || true
  local parts=()
  [[ "${loss}" != "0" ]] && parts+=("loss" "${loss}%")
  [[ "${delay}" != "0" ]] && parts+=("delay" "${delay}ms")
  if [[ "${rate}" != "0" ]]; then
    # rate needs `tbf` not `netem`; chain them.
    sudo tc qdisc add dev "${IFACE}" root handle 1: netem "${parts[@]}"
    sudo tc qdisc add dev "${IFACE}" parent 1: handle 10: tbf \
      rate "${rate}mbit" burst 32kbit latency 400ms
  elif [[ "${#parts[@]}" -gt 0 ]]; then
    sudo tc qdisc add dev "${IFACE}" root netem "${parts[@]}"
  fi
}

for loss in ${LOSS_PCT_LIST}; do
  for delay in ${DELAY_MS_LIST}; do
    for rate in ${RATE_MBIT_LIST}; do
      set_netem "${loss}" "${delay}" "${rate}"
      # Give the kernel a moment to settle the qdisc.
      sleep 0.2
      for ((run=0; run<RUNS_PER_CELL; run++)); do
        # Run the bench and annotate each output line with the
        # netem config that produced it. We use `jq` if available;
        # otherwise fall back to a sed-based field injection.
        line=$("${BENCH_BIN}" beta \
          --payload-mib "${PAYLOAD_MIB}" \
          --congestion "${CONGESTION}" \
          --brutal-target-mbps "${BRUTAL_TARGET_MBPS}" \
          --connect-timeout-secs 180 \
          --total-timeout-secs 300 \
          2>/dev/null | tail -n 1)
        if command -v jq >/dev/null 2>&1; then
          echo "${line}" | jq -c \
            --argjson loss "${loss}" \
            --argjson delay "${delay}" \
            --argjson rate "${rate}" \
            --argjson run "${run}" \
            --arg congestion "${CONGESTION}" \
            --argjson brutal_target_mbps "${BRUTAL_TARGET_MBPS}" \
            '. + {netem_loss_pct: $loss, netem_delay_ms: $delay, netem_rate_mbit: $rate, run_ix: $run, congestion: $congestion, brutal_target_mbps: $brutal_target_mbps}'
        else
          # Strip the trailing `}` and append the netem fields.
          echo "${line%\}},\"netem_loss_pct\":${loss},\"netem_delay_ms\":${delay},\"netem_rate_mbit\":${rate},\"run_ix\":${run},\"congestion\":\"${CONGESTION}\",\"brutal_target_mbps\":${BRUTAL_TARGET_MBPS}}"
        fi
      done
    done
  done
done
