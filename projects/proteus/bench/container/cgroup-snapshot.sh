#!/bin/sh
set -eu

cpu_usage_usec="$(
    awk '$1 == "usage_usec" { print $2 }' /sys/fs/cgroup/cpu.stat
)"
memory_current_bytes="$(cat /sys/fs/cgroup/memory.current)"
self_pid="$$"
process_rss_kib=0
process_count=0

for status_file in /proc/[0-9]*/status; do
    pid="${status_file#/proc/}"
    pid="${pid%/status}"
    [ "$pid" = "$self_pid" ] && continue
    rss_kib="$(
        awk '$1 == "VmRSS:" { print $2; found = 1 }
             END { if (!found) print 0 }' "$status_file" 2>/dev/null || true
    )"
    case "$rss_kib" in
        *[!0-9]*|"") rss_kib=0 ;;
    esac
    process_rss_kib=$((process_rss_kib + rss_kib))
    process_count=$((process_count + 1))
done

printf '{"cpu_usage_usec":%s,"memory_current_bytes":%s,' \
    "$cpu_usage_usec" "$memory_current_bytes"
printf '"process_rss_kib":%s,"process_count":%s}\n' \
    "$process_rss_kib" "$process_count"
