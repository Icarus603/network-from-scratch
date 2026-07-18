#!/bin/sh
set -u

label="${1:?usage: resource-monitor.sh LABEL COMMAND [ARG ...]}"
shift
if [ "${1:-}" = "--" ]; then
    shift
fi
if [ "$#" -eq 0 ]; then
    echo "resource-monitor.sh: command is required" >&2
    exit 2
fi

cpu_usage_usec() {
    awk '$1 == "usage_usec" { print $2; found = 1 } END { if (!found) print 0 }' \
        /sys/fs/cgroup/cpu.stat 2>/dev/null
}

uptime_seconds() {
    awk '{ print $1 }' /proc/uptime
}

cpu_before="$(cpu_usage_usec)"
started_at="$(uptime_seconds)"
peak_file="$(mktemp)"
printf '0\n' > "$peak_file"

"$@" &
child_pid=$!

(
    peak_rss_kib=0
    while kill -0 "$child_pid" 2>/dev/null; do
        rss_kib="$(
            awk '$1 == "VmRSS:" { print $2; found = 1 } END { if (!found) print 0 }' \
                "/proc/${child_pid}/status" 2>/dev/null
        )"
        if [ "$rss_kib" -gt "$peak_rss_kib" ]; then
            peak_rss_kib="$rss_kib"
            printf '%s\n' "$peak_rss_kib" > "$peak_file"
        fi
        sleep 0.01
    done
) &
sampler_pid=$!

trap 'kill -TERM "$child_pid" "$sampler_pid" 2>/dev/null || true' INT TERM HUP
wait "$child_pid"
status=$?
wait "$sampler_pid" 2>/dev/null || true

finished_at="$(uptime_seconds)"
cpu_after="$(cpu_usage_usec)"
peak_rss_kib="$(cat "$peak_file")"
rm -f "$peak_file"

awk \
    -v label="$label" \
    -v cpu_before="$cpu_before" \
    -v cpu_after="$cpu_after" \
    -v started_at="$started_at" \
    -v finished_at="$finished_at" \
    -v peak_rss_kib="$peak_rss_kib" \
    -v run="${RESOURCE_RUN:-0}" \
    -v status="$status" \
    'BEGIN {
        printf "{\"kind\":\"resource\",\"implementation\":\"%s\",\"run\":%.0f,\"cpu_usage_usec\":%.0f,\"elapsed_sec\":%.6f,\"peak_rss_kib\":%.0f,\"exit_status\":%.0f}\n",
            label,
            run,
            cpu_after - cpu_before,
            finished_at - started_at,
            peak_rss_kib,
            status
    }' >&2

exit "$status"
