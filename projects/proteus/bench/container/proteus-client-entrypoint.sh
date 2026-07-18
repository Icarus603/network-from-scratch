#!/bin/sh
set -eu

ip route replace 10.77.2.0/24 via 10.77.1.2
state=/run/proteus-bench/server.env
deadline=$(( $(date +%s) + 30 ))
while ! grep -q '^BENCH_SERVER_PQ_FINGERPRINT_HEX=' "$state" 2>/dev/null; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
        echo "timed out waiting for Proteus benchmark server identity" >&2
        exit 1
    fi
    sleep 0.1
done

server_leaf_cert_hex="$(sed -n 's/^BENCH_SERVER_LEAF_CERT_HEX=//p' "$state" | tail -n 1)"
server_mlkem_pk_hex="$(sed -n 's/^BENCH_SERVER_MLKEM_PK_HEX=//p' "$state" | tail -n 1)"
server_x25519_pub_hex="$(sed -n 's/^BENCH_SERVER_X25519_PUB_HEX=//p' "$state" | tail -n 1)"
server_pq_fingerprint_hex="$(sed -n 's/^BENCH_SERVER_PQ_FINGERPRINT_HEX=//p' "$state" | tail -n 1)"

set -- proteus-bench beta-client \
    --server-addr 10.77.2.11:9443 \
    --server-name 10.77.2.11 \
    --server-leaf-cert-hex "$server_leaf_cert_hex" \
    --server-mlkem-pk-hex "$server_mlkem_pk_hex" \
    --server-x25519-pub-hex "$server_x25519_pub_hex" \
    --server-pq-fingerprint-hex "$server_pq_fingerprint_hex" \
    --payload-mib "${PAYLOAD_MIB:-64}" \
    --stream-window-mib "${STREAM_WINDOW_MIB:-64}" \
    --connection-window-mib "${CONNECTION_WINDOW_MIB:-256}" \
    --runs "${RUNS_PER_CELL:-3}" \
    --congestion "${CONGESTION:-brutal}" \
    --brutal-target-mbps "${BRUTAL_TARGET_MBPS:-1000}" \
    --connect-timeout-secs 180 \
    --total-timeout-secs 300

if [ "${RESOURCE_MONITOR:-1}" = "1" ]; then
    exec /usr/local/bin/resource-monitor.sh proteus-beta-brutal -- "$@"
fi
exec "$@"
