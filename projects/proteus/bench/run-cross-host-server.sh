#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ACTION="${1:-start}"
PREFIX="${CROSS_HOST_PREFIX:-proteus-cross-host}"
STATE_DIR="${STATE_DIR:-${ROOT}/bench/cross-host-state/server}"
SERVER_STATE="${STATE_DIR}/server"
CLIENT_BUNDLE="${STATE_DIR}/client-bundle"
PROTEUS_IMAGE="${PROTEUS_IMAGE:-proteus/proxy-bench:local}"
BENCH_IMAGE="${BENCH_IMAGE:-proteus/bench:local}"
HY2_IMAGE="${HY2_IMAGE:-proteus/hysteria-bench:f2ad1de}"
PROTEUS_BETA_PORT="${PROTEUS_BETA_PORT:-39444}"
PROTEUS_ALPHA_PORT="${PROTEUS_ALPHA_PORT:-39444}"
HY2_PORT="${HY2_PORT:-38443}"
ECHO_PORT="${ECHO_PORT:-38080}"
SERVER_ADVERTISE_HOST="${SERVER_ADVERTISE_HOST:-SET_ME_ON_CLIENT}"

container_names=(
    "${PREFIX}-proteus-server"
    "${PREFIX}-hy2-server"
    "${PREFIX}-echo"
)

remove_containers() {
    for name in "${container_names[@]}"; do
        docker rm -f "$name" >/dev/null 2>&1 || true
    done
}

case "$ACTION" in
    stop)
        remove_containers
        exit 0
        ;;
    snapshot)
        mkdir -p "$CLIENT_BUNDLE"
        docker logs "${PREFIX}-proteus-server" \
            > "${CLIENT_BUNDLE}/proteus-server-daemon.log" 2>&1
        docker logs "${PREFIX}-hy2-server" \
            > "${CLIENT_BUNDLE}/hy2-server-daemon.log" 2>&1
        echo "${CLIENT_BUNDLE}/proteus-server-daemon.log"
        echo "${CLIENT_BUNDLE}/hy2-server-daemon.log"
        exit 0
        ;;
    status)
        docker ps -a \
            --filter "name=^/${PREFIX}-" \
            --format '{{.Names}}\t{{.Status}}\t{{.Image}}'
        exit 0
        ;;
    start) ;;
    *)
        echo "usage: $0 [start|snapshot|stop|status]" >&2
        exit 2
        ;;
esac

SERVER_WORKTREE_DIRTY=false
if [ -n "$(git -C "$ROOT" status --short)" ]; then
    SERVER_WORKTREE_DIRTY=true
    if [ "${ALLOW_DIRTY:-0}" != "1" ]; then
        echo "cross-host formal runs require a clean server worktree" >&2
        exit 2
    fi
fi

for port in "$PROTEUS_BETA_PORT" "$PROTEUS_ALPHA_PORT" "$HY2_PORT" "$ECHO_PORT"; do
    case "$port" in
        *[!0-9]*|"")
            echo "cross-host ports must be positive integers" >&2
            exit 2
            ;;
        0)
            echo "cross-host ports must be greater than zero" >&2
            exit 2
            ;;
    esac
done

for image in "$PROTEUS_IMAGE" "$BENCH_IMAGE" "$HY2_IMAGE"; do
    docker image inspect "$image" >/dev/null
done

mkdir -p "$SERVER_STATE" "$CLIENT_BUNDLE"
find "$SERVER_STATE" -mindepth 1 -delete
find "$CLIENT_BUNDLE" -mindepth 1 -delete
mkdir -p "$CLIENT_BUNDLE/keys/client" "$CLIENT_BUNDLE/keys/tls"
chmod 0700 "$SERVER_STATE" "$CLIENT_BUNDLE"
remove_containers

# Generate a fresh benchmark-only identity on the server host. The complete
# bundle stays server-side; only the minimum client material is exported.
docker run --rm \
    -e PROTEUS_PROXY_STATE=/state \
    -v "${SERVER_STATE}:/state" \
    --entrypoint /usr/local/bin/proteus-proxy-setup.sh \
    "$PROTEUS_IMAGE"

install -m 0644 \
    "${SERVER_STATE}/keys/server_lt.mlkem768.pk" \
    "${CLIENT_BUNDLE}/keys/server_lt.mlkem768.pk"
install -m 0644 \
    "${SERVER_STATE}/keys/server_lt.x25519.pk" \
    "${CLIENT_BUNDLE}/keys/server_lt.x25519.pk"
install -m 0644 \
    "${SERVER_STATE}/keys/server_lt.pq.fingerprint" \
    "${CLIENT_BUNDLE}/keys/server_lt.pq.fingerprint"
install -m 0600 \
    "${SERVER_STATE}/keys/client/client.ed25519.sk" \
    "${CLIENT_BUNDLE}/keys/client/client.ed25519.sk"
install -m 0644 \
    "${SERVER_STATE}/keys/tls/fullchain.pem" \
    "${CLIENT_BUNDLE}/keys/tls/fullchain.pem"
: > "${CLIENT_BUNDLE}/ready"

docker run -d \
    --name "${PREFIX}-proteus-server" \
    --restart no \
    -p "${PROTEUS_ALPHA_PORT}:8444/tcp" \
    -p "${PROTEUS_BETA_PORT}:9444/udp" \
    -e SKIP_STATIC_ROUTE=1 \
    -e CARRIER_IDLE_TIMEOUT_SECS="${PROTEUS_CARRIER_IDLE_TIMEOUT_SECS:-120}" \
    -e BRUTAL_TARGET_MBPS="${PROTEUS_BRUTAL_TARGET_MBPS:-1000}" \
    -e PROTEUS_BETA_SESSION_STATS=1 \
    -v "${SERVER_STATE}:/run/proteus-proxy:ro" \
    -v "${ROOT}/bench/container:/bench:ro" \
    --entrypoint /usr/bin/dumb-init \
    "$PROTEUS_IMAGE" -- /bench/proteus-proxy-server-entrypoint.sh \
    >/dev/null

docker run -d \
    --name "${PREFIX}-hy2-server" \
    --restart no \
    -p "${HY2_PORT}:8443/udp" \
    -e SKIP_STATIC_ROUTE=1 \
    -e HY2_CERT_HOST=proteus.example.com \
    -e HY2_IDLE_TIMEOUT="${HY2_IDLE_TIMEOUT:-120s}" \
    -v "${ROOT}/bench/container:/bench:ro" \
    --entrypoint /bin/sh \
    "$HY2_IMAGE" /bench/hy2-server-entrypoint.sh \
    >/dev/null

docker run -d \
    --name "${PREFIX}-echo" \
    --restart no \
    -p "${ECHO_PORT}:18080/tcp" \
    --entrypoint /usr/bin/dumb-init \
    "$BENCH_IMAGE" -- /usr/local/bin/proteus-bench tcp-echo-server \
        --bind 0.0.0.0:18080 \
    >/dev/null

deadline=$(( $(date +%s) + 30 ))
until docker logs "${PREFIX}-proteus-server" 2>&1 \
    | grep 'β-profile (QUIC) listener bound' >/dev/null \
    && docker logs "${PREFIX}-hy2-server" 2>&1 \
    | grep 'server up and running' >/dev/null; do
    if (( $(date +%s) >= deadline )); then
        docker logs "${PREFIX}-proteus-server" >&2 || true
        docker logs "${PREFIX}-hy2-server" >&2 || true
        echo "cross-host server role failed readiness" >&2
        exit 1
    fi
    sleep 1
done

jq -cn \
    --arg git_commit "$(git -C "$ROOT" rev-parse HEAD)" \
    --arg proteus_image "$PROTEUS_IMAGE" \
    --arg proteus_image_id "$(docker image inspect "$PROTEUS_IMAGE" --format '{{.Id}}')" \
    --arg hy2_image "$HY2_IMAGE" \
    --arg hy2_image_id "$(docker image inspect "$HY2_IMAGE" --format '{{.Id}}')" \
    --arg kernel "$(uname -srvmo)" \
    --arg advertise_host "$SERVER_ADVERTISE_HOST" \
    --argjson worktree_dirty "$SERVER_WORKTREE_DIRTY" \
    --argjson proteus_beta_port "$PROTEUS_BETA_PORT" \
    --argjson proteus_alpha_port "$PROTEUS_ALPHA_PORT" \
    --argjson hy2_port "$HY2_PORT" \
    --argjson echo_port "$ECHO_PORT" \
    '{
        git_commit:$git_commit,
        proteus_image:$proteus_image,
        proteus_image_id:$proteus_image_id,
        hy2_image:$hy2_image,
        hy2_image_id:$hy2_image_id,
        kernel:$kernel,
        worktree_dirty:$worktree_dirty,
        advertise_host:$advertise_host,
        proteus_beta_port:$proteus_beta_port,
        proteus_alpha_port:$proteus_alpha_port,
        hy2_port:$hy2_port,
        echo_port:$echo_port
    }' > "${CLIENT_BUNDLE}/server-metadata.json"

echo "server role ready"
echo "copy this sanitized directory to the client host:"
echo "${CLIENT_BUNDLE}"
echo "then run with SERVER_HOST=${SERVER_ADVERTISE_HOST}"
