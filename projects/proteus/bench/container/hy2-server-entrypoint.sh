#!/bin/sh
set -eu

ip route replace 10.77.1.0/24 via 10.77.2.2
mkdir -p /run/hysteria
hysteria cert \
    --host 10.77.2.10 \
    --cert /run/hysteria/server.crt \
    --key /run/hysteria/server.key \
    --overwrite >/run/hysteria/cert.log
exec hysteria server \
    --disable-update-check \
    -c /bench/hy2-server.yaml
