#!/bin/sh
set -eu

ip route replace 10.77.2.0/24 via 10.77.1.2
deadline=$(( $(date +%s) + 30 ))
while [ ! -s /run/tuic/server.crt ] || [ ! -e /run/tuic/server-ready ]; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
        echo "timed out waiting for TUIC benchmark certificate" >&2
        exit 1
    fi
    sleep 0.1
done
exec tuic-client -c /bench/tuic-client.json
