#!/bin/sh
set -eu

ip route replace 10.77.1.0/24 via 10.77.2.2
state=/run/proteus-bench/server.env
rm -f "$state"

# stdbuf keeps the five-line identity banner visible to the client
# immediately instead of waiting for a pipe buffer to fill.
exec stdbuf -oL -eL proteus-bench beta-server \
    --bind 0.0.0.0:9443 \
    --extra-san 10.77.2.11 \
    --congestion "${CONGESTION:-brutal}" \
    --brutal-target-mbps "${BRUTAL_TARGET_MBPS:-1000}" \
    2>&1 | tee "$state"
