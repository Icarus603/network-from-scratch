#!/bin/sh
set -eu

if [ "${SKIP_STATIC_ROUTE:-0}" != "1" ]; then
    ip route replace 10.77.1.0/24 via 10.77.2.2
fi
mkdir -p /run/hysteria
hysteria cert \
    --host "${HY2_CERT_HOST:-10.77.2.10}" \
    --cert /run/hysteria/server.crt \
    --key /run/hysteria/server.key \
    --overwrite >/run/hysteria/cert.log
config=/bench/hy2-server.yaml
if [ -n "${HY2_IDLE_TIMEOUT:-}" ]; then
    config=/tmp/hy2-server.yaml
    cp /bench/hy2-server.yaml "$config"
    sed -i \
        "s/^  maxIdleTimeout:.*/  maxIdleTimeout: ${HY2_IDLE_TIMEOUT}/" \
        "$config"
fi
exec hysteria server \
    --disable-update-check \
    -c "$config"
