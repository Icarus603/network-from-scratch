#!/bin/sh
set -eu

if [ "${SKIP_STATIC_ROUTE:-0}" != "1" ]; then
    ip route replace 10.77.2.0/24 via 10.77.1.2
fi
if [ "${RESOURCE_MONITOR:-1}" = "1" ]; then
    exec /bench/resource-monitor.sh hysteria2 -- hysteria "$@"
fi
exec hysteria "$@"
