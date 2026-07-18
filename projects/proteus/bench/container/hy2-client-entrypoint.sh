#!/bin/sh
set -eu

ip route replace 10.77.2.0/24 via 10.77.1.2
if [ "${RESOURCE_MONITOR:-1}" = "1" ]; then
    exec /bench/resource-monitor.sh hysteria2 -- hysteria "$@"
fi
exec hysteria "$@"
