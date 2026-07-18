#!/bin/sh
set -eu

ip route replace 10.77.1.0/24 via 10.77.2.2
mkdir -p /run/singbox-tuic
rm -f /run/singbox-tuic/server-ready
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /run/singbox-tuic/server.key \
    -out /run/singbox-tuic/server.crt \
    -days 1 \
    -subj /CN=tuic.example.com \
    -addext subjectAltName=DNS:tuic.example.com \
    -addext basicConstraints=critical,CA:FALSE \
    -addext keyUsage=critical,digitalSignature,keyEncipherment \
    -addext extendedKeyUsage=serverAuth
touch /run/singbox-tuic/server-ready
exec sing-box run -c /bench/singbox-tuic-server.json
