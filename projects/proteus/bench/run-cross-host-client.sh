#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${CROSS_HOST_PREFIX:-proteus-cross-host}"
NETWORK="${PREFIX}-client-net"
STATE_DIR="${STATE_DIR:-${ROOT}/bench/cross-host-state/client}"
CLIENT_BUNDLE_DIR="${CLIENT_BUNDLE_DIR:-}"
SERVER_HOST="${SERVER_HOST:-}"
PROTEUS_SERVER_HOST="${PROTEUS_SERVER_HOST:-$SERVER_HOST}"
HY2_SERVER_HOST="${HY2_SERVER_HOST:-$SERVER_HOST}"
ECHO_HOST="${ECHO_HOST:-$SERVER_HOST}"
ECHO_TARGET_IP="${ECHO_TARGET_IP:-}"
PAYLOAD_MIB="${PAYLOAD_MIB:-64}"
WARMUP_MIB="${WARMUP_MIB:-64}"
RUNS="${RUNS:-30}"
PROTEUS_IMAGE="${PROTEUS_IMAGE:-proteus/proxy-bench:local}"
BENCH_IMAGE="${BENCH_IMAGE:-proteus/bench:local}"
HY2_IMAGE="${HY2_IMAGE:-proteus/hysteria-bench:f2ad1de}"
PROTEUS_BETA_PORT="${PROTEUS_BETA_PORT:-39444}"
PROTEUS_ALPHA_PORT="${PROTEUS_ALPHA_PORT:-39444}"
HY2_PORT="${HY2_PORT:-38443}"
ECHO_PORT="${ECHO_PORT:-38080}"
RESULTS_DIR="${RESULTS_DIR:-${ROOT}/bench/results/cross-host-$(date -u +%Y%m%dT%H%M%SZ)}"
PROTEUS_NAME="${PREFIX}-proteus-client"
HY2_NAME="${PREFIX}-hy2-client"
CLIENT_SUBNET="${CLIENT_SUBNET:-172.31.240.0/24}"
PROTEUS_CLIENT_IP="${PROTEUS_CLIENT_IP:-172.31.240.10}"
HY2_CLIENT_IP="${HY2_CLIENT_IP:-172.31.240.11}"
if [ "${LOCAL_SERVER_CONTAINERS:-0}" = "1" ]; then
    PROTEUS_SERVER_HOST="${PREFIX}-proteus-server"
    HY2_SERVER_HOST="${PREFIX}-hy2-server"
    ECHO_HOST="${PREFIX}-echo"
    PROTEUS_BETA_PORT=9444
    PROTEUS_ALPHA_PORT=8444
    HY2_PORT=8443
    ECHO_PORT=18080
fi
CLIENT_WORKTREE_DIRTY=false
if [ -n "$(git -C "$ROOT" status --short)" ]; then
    CLIENT_WORKTREE_DIRTY=true
    if [ "${ALLOW_DIRTY:-0}" != "1" ]; then
        echo "cross-host formal runs require a clean client worktree" >&2
        exit 2
    fi
fi

if [ -z "$SERVER_HOST" ] || [ "$SERVER_HOST" = "SET_ME_ON_CLIENT" ]; then
    echo "SERVER_HOST must name the physical server host or IP" >&2
    exit 2
fi
if [ -z "$CLIENT_BUNDLE_DIR" ] || [ ! -d "$CLIENT_BUNDLE_DIR" ]; then
    echo "CLIENT_BUNDLE_DIR must point to the sanitized server export" >&2
    exit 2
fi

for value in "$PAYLOAD_MIB" "$WARMUP_MIB" "$RUNS"; do
    case "$value" in
        *[!0-9]*|"")
            echo "PAYLOAD_MIB, WARMUP_MIB and RUNS must be positive integers" >&2
            exit 2
            ;;
        0)
            echo "PAYLOAD_MIB, WARMUP_MIB and RUNS must be greater than zero" >&2
            exit 2
            ;;
    esac
done

required_bundle_files=(
    keys/server_lt.mlkem768.pk
    keys/server_lt.x25519.pk
    keys/server_lt.pq.fingerprint
    keys/client/client.ed25519.sk
    keys/tls/fullchain.pem
    ready
    server-metadata.json
)
for relative in "${required_bundle_files[@]}"; do
    if [ ! -f "${CLIENT_BUNDLE_DIR}/${relative}" ]; then
        echo "client bundle missing ${relative}" >&2
        exit 2
    fi
done
for forbidden in \
    keys/server_lt.mlkem768.sk \
    keys/server_lt.x25519.sk \
    keys/tls/privkey.pem; do
    if [ -e "${CLIENT_BUNDLE_DIR}/${forbidden}" ]; then
        echo "client bundle contains forbidden server secret: ${forbidden}" >&2
        exit 2
    fi
done

mkdir -p "$STATE_DIR" "$RESULTS_DIR"
PROTEUS_CONFIG="${STATE_DIR}/proteus-client.yaml"
HY2_CONFIG="${STATE_DIR}/hy2-client.yaml"

sed \
    -e "s|^server_endpoint:.*|server_endpoint: \"${PROTEUS_SERVER_HOST}:${PROTEUS_ALPHA_PORT}\"|" \
    -e "s|^server_endpoint_beta:.*|server_endpoint_beta: \"${PROTEUS_SERVER_HOST}:${PROTEUS_BETA_PORT}\"|" \
    "${ROOT}/bench/container/proteus-proxy-client.yaml" \
    > "$PROTEUS_CONFIG"
sed \
    -e "s|^server:.*|server: ${HY2_SERVER_HOST}:${HY2_PORT}|" \
    -e "s|^  sni:.*|  sni: proteus.example.com|" \
    -e "s|^  maxIdleTimeout:.*|  maxIdleTimeout: 120s|" \
    "${ROOT}/bench/container/hy2-proxy-client.yaml" \
    > "$HY2_CONFIG"

capture_logs() {
    docker logs "$PROTEUS_NAME" > "${RESULTS_DIR}/proteus-client-daemon.log" 2>&1 || true
    docker logs "$HY2_NAME" > "${RESULTS_DIR}/hy2-client-daemon.log" 2>&1 || true
}

cleanup() {
    capture_logs
    docker rm -f "$PROTEUS_NAME" "$HY2_NAME" >/dev/null 2>&1 || true
    if [ "${LOCAL_SERVER_CONTAINERS:-0}" = "1" ]; then
        docker network disconnect -f "$NETWORK" "${PREFIX}-proteus-server" \
            >/dev/null 2>&1 || true
        docker network disconnect -f "$NETWORK" "${PREFIX}-hy2-server" \
            >/dev/null 2>&1 || true
        docker network disconnect -f "$NETWORK" "${PREFIX}-echo" \
            >/dev/null 2>&1 || true
    fi
    docker network rm "$NETWORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker rm -f "$PROTEUS_NAME" "$HY2_NAME" >/dev/null 2>&1 || true
docker network rm "$NETWORK" >/dev/null 2>&1 || true
docker network create --subnet "$CLIENT_SUBNET" "$NETWORK" >/dev/null
if [ "${LOCAL_SERVER_CONTAINERS:-0}" = "1" ]; then
    docker network connect "$NETWORK" "${PREFIX}-proteus-server"
    docker network connect "$NETWORK" "${PREFIX}-hy2-server"
    docker network connect "$NETWORK" "${PREFIX}-echo"
fi
if [ -z "$ECHO_TARGET_IP" ]; then
    ECHO_TARGET_IP="$(
        docker run --rm \
            --network "$NETWORK" \
            --entrypoint getent \
            "$BENCH_IMAGE" ahostsv4 "$ECHO_HOST" \
            | awk 'NR == 1 { print $1 }'
    )"
fi
if [ -z "$ECHO_TARGET_IP" ]; then
    echo "could not resolve ECHO_HOST to an IPv4 address from the client network" >&2
    exit 1
fi

docker run -d \
    --name "$PROTEUS_NAME" \
    --network "$NETWORK" \
    --ip "$PROTEUS_CLIENT_IP" \
    -e SKIP_STATIC_ROUTE=1 \
    -e CARRIER_IDLE_TIMEOUT_SECS=120 \
    -e BETA_FIRST_TIMEOUT_SECS=60 \
    -e PROTEUS_BETA_SESSION_STATS=1 \
    -v "${CLIENT_BUNDLE_DIR}:/run/proteus-proxy:ro" \
    -v "${ROOT}/bench/container:/bench:ro" \
    -v "${PROTEUS_CONFIG}:/bench/proteus-proxy-client.yaml:ro" \
    --entrypoint /usr/bin/dumb-init \
    "$PROTEUS_IMAGE" -- /bench/proteus-proxy-client-entrypoint.sh \
    >/dev/null

docker run -d \
    --name "$HY2_NAME" \
    --network "$NETWORK" \
    --ip "$HY2_CLIENT_IP" \
    -e SKIP_STATIC_ROUTE=1 \
    -v "${ROOT}/bench/container:/bench:ro" \
    -v "${HY2_CONFIG}:/bench/hy2-proxy-client.yaml:ro" \
    --entrypoint /bin/sh \
    "$HY2_IMAGE" /bench/hy2-client-entrypoint.sh \
        client --disable-update-check -f json \
        -c /bench/hy2-proxy-client.yaml \
    >/dev/null

wait_for_log_marker() {
    name="$1"
    marker="$2"
    deadline=$(( $(date +%s) + 60 ))
    until docker logs "$name" 2>&1 | grep "$marker" >/dev/null; do
        if (( $(date +%s) >= deadline )); then
            docker logs "$name" >&2 || true
            echo "${name} did not publish readiness marker" >&2
            exit 1
        fi
        sleep 1
    done
}
wait_for_log_marker "$PROTEUS_NAME" 'SOCKS5 inbound bound'
wait_for_log_marker "$HY2_NAME" 'SOCKS5 server listening'

run_driver() {
    socks_addr="$1"
    payload_mib="$2"
    output="$3"
    docker run --rm \
        --network "$NETWORK" \
        --entrypoint /usr/local/bin/proteus-bench \
        "$BENCH_IMAGE" \
        socks5-roundtrip \
        --socks-addr "$socks_addr" \
        --target-addr "${ECHO_TARGET_IP}:${ECHO_PORT}" \
        --payload-mib "$payload_mib" \
        --runs 1 \
        --timeout-secs 600 \
        >> "$output" 2>&1
}

: > "${RESULTS_DIR}/warmup.jsonl"
run_driver "${PROTEUS_CLIENT_IP}:1080" "$WARMUP_MIB" "${RESULTS_DIR}/warmup.jsonl"
run_driver "${HY2_CLIENT_IP}:1080" "$WARMUP_MIB" "${RESULTS_DIR}/warmup.jsonl"

: > "${RESULTS_DIR}/proteus.jsonl"
: > "${RESULTS_DIR}/hy2.jsonl"
: > "${RESULTS_DIR}/proteus-resources.jsonl"
: > "${RESULTS_DIR}/hy2-resources.jsonl"

resource_snapshot() {
    docker exec "$1" /bench/cgroup-snapshot.sh
}

append_resource() {
    implementation="$1"
    run="$2"
    before="$3"
    after="$4"
    output="$5"
    jq -cn \
        --arg implementation "$implementation" \
        --argjson run "$run" \
        --argjson before "$before" \
        --argjson after "$after" \
        '{
            kind:"resource",
            implementation:$implementation,
            run:$run,
            cpu_usage_usec:($after.cpu_usage_usec - $before.cpu_usage_usec),
            rss_after_kib:$after.process_rss_kib,
            cgroup_memory_after_bytes:$after.memory_current_bytes,
            process_count_after:$after.process_count,
            exit_status:0
        }' >> "$output"
}

run_one() {
    implementation="$1"
    name="$2"
    client_ip="$3"
    output="$4"
    resources="$5"
    printf '{"kind":"run_start","run":%d}\n' "$run" >> "$output"
    before="$(resource_snapshot "$name")"
    if ! run_driver "${client_ip}:1080" "$PAYLOAD_MIB" "$output"; then
        printf '{"kind":"run_failure","run":%d,"exit_status":1}\n' "$run" >> "$output"
        return 1
    fi
    after="$(resource_snapshot "$name")"
    append_resource "$implementation" "$run" "$before" "$after" "$resources"
}

for ((run = 1; run <= RUNS; run++)); do
    if (( run % 2 == 1 )); then
        run_one proteus-beta-brutal "$PROTEUS_NAME" "$PROTEUS_CLIENT_IP" \
            "${RESULTS_DIR}/proteus.jsonl" "${RESULTS_DIR}/proteus-resources.jsonl"
        run_one hysteria2 "$HY2_NAME" "$HY2_CLIENT_IP" \
            "${RESULTS_DIR}/hy2.jsonl" "${RESULTS_DIR}/hy2-resources.jsonl"
    else
        run_one hysteria2 "$HY2_NAME" "$HY2_CLIENT_IP" \
            "${RESULTS_DIR}/hy2.jsonl" "${RESULTS_DIR}/hy2-resources.jsonl"
        run_one proteus-beta-brutal "$PROTEUS_NAME" "$PROTEUS_CLIENT_IP" \
            "${RESULTS_DIR}/proteus.jsonl" "${RESULTS_DIR}/proteus-resources.jsonl"
    fi
done

capture_logs
if grep -q 'falling back to α' "${RESULTS_DIR}/proteus-client-daemon.log"; then
    echo "cross-host benchmark invalid: Proteus β fell back to α" >&2
    exit 1
fi
if grep -Eq 'β (QUIC )?carrier closed|too many gaps in stream buffer' \
    "${RESULTS_DIR}/proteus-client-daemon.log"; then
    echo "cross-host benchmark invalid: warmed Proteus carrier did not survive" >&2
    exit 1
fi

jq -cn \
    --slurpfile server "${CLIENT_BUNDLE_DIR}/server-metadata.json" \
    --arg timestamp_utc "$(date -u +%Y%m%dT%H%M%SZ)" \
    --arg client_git_commit "$(git -C "$ROOT" rev-parse HEAD)" \
    --arg client_kernel "$(uname -srvmo)" \
    --arg server_host "$SERVER_HOST" \
    --arg proteus_server_host "$PROTEUS_SERVER_HOST" \
    --arg hy2_server_host "$HY2_SERVER_HOST" \
    --arg echo_target_ip "$ECHO_TARGET_IP" \
    --arg proteus_image_id "$(docker image inspect "$PROTEUS_IMAGE" --format '{{.Id}}')" \
    --arg hy2_image_id "$(docker image inspect "$HY2_IMAGE" --format '{{.Id}}')" \
    --argjson client_worktree_dirty "$CLIENT_WORKTREE_DIRTY" \
    --argjson payload_mib "$PAYLOAD_MIB" \
    --argjson runs "$RUNS" \
    --argjson warmup_mib "$WARMUP_MIB" \
    '{
        kind:"environment",
        timestamp_utc:$timestamp_utc,
        server:$server[0],
        client_git_commit:$client_git_commit,
        client_kernel:$client_kernel,
        client_worktree_dirty:$client_worktree_dirty,
        server_host:$server_host,
        proteus_server_host:$proteus_server_host,
        hy2_server_host:$hy2_server_host,
        echo_target_ip:$echo_target_ip,
        client_proteus_image_id:$proteus_image_id,
        client_hy2_image_id:$hy2_image_id,
        payload_mib:$payload_mib,
        runs_per_implementation:$runs,
        warmup_mib:$warmup_mib,
        workload_mode:"production-socks5-cross-host",
        connection_lifecycle:"one-reset-then-warm-ab-ba",
        formal_eligible:(($server[0].worktree_dirty | not) and ($client_worktree_dirty | not))
    }' > "${RESULTS_DIR}/metadata.jsonl"

python3 "${ROOT}/bench/summarize-cross-host-results.py" "$RESULTS_DIR"
echo "$RESULTS_DIR"
