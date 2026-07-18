#!/bin/sh
set -eu

state="${PROTEUS_PROXY_STATE:-/run/proteus-proxy}"
mkdir -p "$state/keys/client" "$state/keys/tls"

proteus-server keygen --out "$state/keys" --force
proteus-server gencert \
    --dns-name proteus.example.com \
    --out "$state/keys/tls" \
    --force
proteus-client keygen --out "$state/keys/client" --force
touch "$state/ready"
