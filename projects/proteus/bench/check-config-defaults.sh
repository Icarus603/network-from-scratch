#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

assert_contains() {
    file=$1
    expected=$2
    if ! grep -F "$expected" "$file" >/dev/null; then
        echo "benchmark default drift: $file lacks: $expected" >&2
        exit 1
    fi
}

assert_contains "$root/bench/run-netem-head-to-head.sh" \
    'PROTEUS_ACK_ELICITING_THRESHOLD="${PROTEUS_ACK_ELICITING_THRESHOLD:-1}"'
assert_contains "$root/bench/docker-compose.netem.yml" \
    'ACK_ELICITING_THRESHOLD: "${PROTEUS_ACK_ELICITING_THRESHOLD:-1}"'
assert_contains "$root/bench/container/proteus-proxy-client-entrypoint.sh" \
    'case "${ACK_ELICITING_THRESHOLD:-1}" in'
assert_contains "$root/bench/container/proteus-proxy-server-entrypoint.sh" \
    'case "${ACK_ELICITING_THRESHOLD:-1}" in'
assert_contains "$root/bench/container/proteus-proxy-client.yaml" \
    'beta_ack_eliciting_threshold: 1'
assert_contains "$root/bench/container/proteus-proxy-server.yaml" \
    'beta_ack_eliciting_threshold: 1'
assert_contains "$root/bench/run-netem-head-to-head.sh" \
    'PROTEUS_PACKET_THRESHOLD="${PROTEUS_PACKET_THRESHOLD:-3}"'
assert_contains "$root/bench/run-netem-head-to-head.sh" \
    'PROTEUS_TIME_THRESHOLD="${PROTEUS_TIME_THRESHOLD:-1.125}"'
assert_contains "$root/bench/container/proteus-proxy-client.yaml" \
    'beta_packet_threshold: 3'
assert_contains "$root/bench/container/proteus-proxy-client.yaml" \
    'beta_time_threshold: 1.125'
assert_contains "$root/bench/container/proteus-proxy-server.yaml" \
    'beta_packet_threshold: 3'
assert_contains "$root/bench/container/proteus-proxy-server.yaml" \
    'beta_time_threshold: 1.125'

if grep -R -E \
    'ACK_ELICITING_THRESHOLD:-10|beta_ack_eliciting_threshold: 10' \
    "$root/bench/run-netem-head-to-head.sh" \
    "$root/bench/docker-compose.netem.yml" \
    "$root/bench/container" >/dev/null; then
    echo "benchmark default drift: stale ACK threshold 10 remains" >&2
    exit 1
fi

echo "benchmark defaults match production ACK threshold 1"
