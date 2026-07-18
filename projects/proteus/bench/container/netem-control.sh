#!/bin/sh
set -eu

STATE_FILE=/run/proteus-netem/interfaces.env
if [ ! -r "$STATE_FILE" ]; then
    echo "netem router state is unavailable; is netem-router.sh running?" >&2
    exit 1
fi
. "$STATE_FILE"

clear_qdiscs() {
    tc qdisc del dev "$CLIENT_IFACE" root 2>/dev/null || true
    tc qdisc del dev "$SERVER_IFACE" root 2>/dev/null || true
}

show_stats() {
    jq -cn \
        --arg client_iface "$CLIENT_IFACE" \
        --arg server_iface "$SERVER_IFACE" \
        --argjson client "$(tc -s -j qdisc show dev "$CLIENT_IFACE")" \
        --argjson server "$(tc -s -j qdisc show dev "$SERVER_IFACE")" \
        '{client_iface:$client_iface,server_iface:$server_iface,client_qdisc:$client,server_qdisc:$server}'
}

command="${1:-}"
case "$command" in
    clear)
        clear_qdiscs
        show_stats
        ;;
    stats)
        show_stats
        ;;
    iid)
        loss_pct="${2:?usage: netem-control.sh iid LOSS_PCT ONE_WAY_DELAY_MS}"
        delay_ms="${3:?usage: netem-control.sh iid LOSS_PCT ONE_WAY_DELAY_MS}"
        clear_qdiscs
        for iface in "$CLIENT_IFACE" "$SERVER_IFACE"; do
            tc qdisc add dev "$iface" root netem \
                limit 100000 \
                delay "${delay_ms}ms" \
                loss "${loss_pct}%"
        done
        show_stats
        ;;
    gemodel)
        p="${2:?usage: netem-control.sh gemodel P R 1-H 1-K ONE_WAY_DELAY_MS}"
        r="${3:?usage: netem-control.sh gemodel P R 1-H 1-K ONE_WAY_DELAY_MS}"
        one_minus_h="${4:?usage: netem-control.sh gemodel P R 1-H 1-K ONE_WAY_DELAY_MS}"
        one_minus_k="${5:?usage: netem-control.sh gemodel P R 1-H 1-K ONE_WAY_DELAY_MS}"
        delay_ms="${6:?usage: netem-control.sh gemodel P R 1-H 1-K ONE_WAY_DELAY_MS}"
        clear_qdiscs
        for iface in "$CLIENT_IFACE" "$SERVER_IFACE"; do
            tc qdisc add dev "$iface" root netem \
                limit 100000 \
                delay "${delay_ms}ms" \
                loss gemodel "$p" "$r" "$one_minus_h" "$one_minus_k"
        done
        show_stats
        ;;
    reorder)
        reorder_pct="${2:?usage: netem-control.sh reorder REORDER_PCT CORRELATION_PCT ONE_WAY_DELAY_MS}"
        correlation_pct="${3:?usage: netem-control.sh reorder REORDER_PCT CORRELATION_PCT ONE_WAY_DELAY_MS}"
        delay_ms="${4:?usage: netem-control.sh reorder REORDER_PCT CORRELATION_PCT ONE_WAY_DELAY_MS}"
        clear_qdiscs
        for iface in "$CLIENT_IFACE" "$SERVER_IFACE"; do
            tc qdisc add dev "$iface" root netem \
                limit 100000 \
                delay "${delay_ms}ms" \
                reorder "${reorder_pct}%" "${correlation_pct}%"
        done
        show_stats
        ;;
    *)
        echo "usage: netem-control.sh {clear|stats|iid|gemodel|reorder} ..." >&2
        exit 2
        ;;
esac
