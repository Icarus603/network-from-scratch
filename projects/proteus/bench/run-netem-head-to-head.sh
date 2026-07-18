#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(docker compose -f "${ROOT}/bench/docker-compose.netem.yml")
LOSS_PCT_LIST="${LOSS_PCT_LIST-0 5 15 30}"
DELAY_MS_LIST="${DELAY_MS_LIST-50}"
# Semicolon-separated cells: P,R,1-H,1-K,ONE_WAY_DELAY_MS.
# Percentages follow tc-netem's Gilbert-Elliott model syntax.
GEMODEL_CELLS="${GEMODEL_CELLS:-}"
PAYLOAD_MIB="${PAYLOAD_MIB:-64}"
RUNS_PER_CELL="${RUNS_PER_CELL:-3}"
INCLUDE_TUIC="${INCLUDE_TUIC:-0}"
SKIP_BUILD="${SKIP_BUILD:-0}"
WORKLOAD_MODE="${WORKLOAD_MODE:-proxy}"
PROTEUS_BRUTAL_TARGET_MBPS="${PROTEUS_BRUTAL_TARGET_MBPS:-1000}"
PROTEUS_ACK_ELICITING_THRESHOLD="${PROTEUS_ACK_ELICITING_THRESHOLD:-10}"
PROTEUS_INITIAL_MTU="${PROTEUS_INITIAL_MTU:-1350}"
PROTEUS_MINIMUM_MTU="${PROTEUS_MINIMUM_MTU:-1350}"
PROTEUS_MTU_UPPER_BOUND="${PROTEUS_MTU_UPPER_BOUND:-1452}"
PROTEUS_BETA_FIRST_TIMEOUT_SECS="${PROTEUS_BETA_FIRST_TIMEOUT_SECS:-60}"
if [ -z "${WARMUP_MIB+x}" ]; then
    if (( PAYLOAD_MIB > 64 )); then
        WARMUP_MIB=64
    else
        WARMUP_MIB="$PAYLOAD_MIB"
    fi
fi
HY2_DATA_SIZE="$((PAYLOAD_MIB * 1024 * 1024))"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RESULTS_DIR="${RESULTS_DIR:-${ROOT}/bench/results/${STAMP}}"

mkdir -p "${RESULTS_DIR}"

cleanup() {
    "${COMPOSE[@]}" exec -T netem /usr/local/bin/netem-control.sh clear \
        >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

export PAYLOAD_MIB RUNS_PER_CELL HY2_DATA_SIZE PROTEUS_BRUTAL_TARGET_MBPS
export PROTEUS_ACK_ELICITING_THRESHOLD
export PROTEUS_INITIAL_MTU
export PROTEUS_MINIMUM_MTU
export PROTEUS_MTU_UPPER_BOUND
export PROTEUS_BETA_FIRST_TIMEOUT_SECS

wait_for_log_marker() {
    service="$1"
    marker="$2"
    deadline=$(( $(date +%s) + 60 ))
    until "${COMPOSE[@]}" logs --no-color "$service" 2>&1 \
        | grep "$marker" >/dev/null; do
        if (( $(date +%s) >= deadline )); then
            "${COMPOSE[@]}" logs --no-color "$service" >&2
            echo "service did not publish readiness marker: ${service}" >&2
            exit 1
        fi
        sleep 1
    done
}

warm_proxy_driver() {
    service="$1"
    socks_addr="$2"
    output="$3"
    "${COMPOSE[@]}" run --rm -T \
        --entrypoint /usr/local/bin/proteus-bench \
        "$service" \
        socks5-roundtrip \
        --socks-addr "$socks_addr" \
        --target-addr 10.77.2.20:18080 \
        --payload-mib "$WARMUP_MIB" \
        --runs 1 \
        --timeout-secs 60 \
        > "$output" 2>&1
}

proxy_resource_snapshot() {
    "${COMPOSE[@]}" exec -T "$1" /bench/cgroup-snapshot.sh
}

append_proxy_resource() {
    implementation="$1"
    run_number="$2"
    before="$3"
    after="$4"
    exit_status="$5"
    output="$6"
    jq -cn \
        --arg implementation "$implementation" \
        --argjson run "$run_number" \
        --argjson before "$before" \
        --argjson after "$after" \
        --argjson exit_status "$exit_status" \
        '{
            kind:"resource",
            implementation:$implementation,
            run:$run,
            cpu_usage_usec:($after.cpu_usage_usec - $before.cpu_usage_usec),
            rss_before_kib:$before.process_rss_kib,
            rss_after_kib:$after.process_rss_kib,
            rss_delta_kib:($after.process_rss_kib - $before.process_rss_kib),
            cgroup_memory_before_bytes:$before.memory_current_bytes,
            cgroup_memory_after_bytes:$after.memory_current_bytes,
            process_count_after:$after.process_count,
            exit_status:$exit_status
        }' >> "$output"
}

reset_and_warm_proxy_clients() {
    cell_dir="$1"
    clients=(proteus-proxy-client hy2-proxy-client)
    if [ "$INCLUDE_TUIC" = "1" ]; then
        clients+=(tuic-client)
    fi

    # No carrier or congestion-controller state may leak from the
    # previous impairment cell. Recreate only the long-lived client
    # daemons; servers and the common echo target remain fixed.
    "${COMPOSE[@]}" up -d --force-recreate --no-deps "${clients[@]}"
    wait_for_log_marker proteus-proxy-client 'SOCKS5 inbound bound'
    wait_for_log_marker hy2-proxy-client 'SOCKS5 server listening'
    if [ "$INCLUDE_TUIC" = "1" ]; then
        wait_for_log_marker tuic-client 'server started, listening'
    fi

    mkdir -p "${cell_dir}/warmup"
    warm_proxy_driver \
        proteus-proxy-bench-driver 10.77.1.14:1080 \
        "${cell_dir}/warmup/proteus.jsonl"
    warm_proxy_driver \
        hy2-proxy-bench-driver 10.77.1.10:1080 \
        "${cell_dir}/warmup/hy2.jsonl"
    if [ "$INCLUDE_TUIC" = "1" ]; then
        warm_proxy_driver \
            tuic-bench-driver 10.77.1.12:1080 \
            "${cell_dir}/warmup/tuic.jsonl"
    fi
}

if [ "$WORKLOAD_MODE" = "proxy" ]; then
    build_services=(netem proteus-proxy-setup hy2-server)
    server_services=(
        netem
        proteus-proxy-server
        proteus-proxy-client
        hy2-server
        hy2-proxy-client
        tcp-echo-server
    )
else
    build_services=(netem proteus-server hy2-server)
    server_services=(netem proteus-server hy2-server)
fi
if [ "$INCLUDE_TUIC" = "1" ]; then
    build_services+=(tuic-server)
    server_services+=(tuic-server tuic-client tcp-echo-server)
fi
if [ "$SKIP_BUILD" != "1" ]; then
    "${COMPOSE[@]}" build "${build_services[@]}"
fi
if [ "$WORKLOAD_MODE" = "proxy" ]; then
    # Key generation deliberately rotates the ephemeral benchmark
    # identity. Recreate both long-lived peers so neither keeps the
    # previous key bundle in memory.
    "${COMPOSE[@]}" rm -sf proteus-proxy-client proteus-proxy-server \
        >/dev/null 2>&1 || true
    "${COMPOSE[@]}" run --rm proteus-proxy-setup
fi
"${COMPOSE[@]}" up -d "${server_services[@]}"

for service in "${server_services[@]}"; do
    deadline=$(( $(date +%s) + 60 ))
    until "${COMPOSE[@]}" ps --status running --services \
        | grep -x "$service" >/dev/null; do
        if (( $(date +%s) >= deadline )); then
            "${COMPOSE[@]}" logs "$service" >&2
            echo "service did not become ready: ${service}" >&2
            exit 1
        fi
        sleep 1
    done
done

if [ "$INCLUDE_TUIC" = "1" ]; then
    wait_for_log_marker tuic-client 'server started, listening'
fi

if [ "$WORKLOAD_MODE" = "proxy" ]; then
    deadline=$(( $(date +%s) + 60 ))
    until "${COMPOSE[@]}" logs --no-color proteus-proxy-server 2>&1 \
        | grep 'β-profile (QUIC) listener bound' >/dev/null; do
        if (( $(date +%s) >= deadline )); then
            "${COMPOSE[@]}" logs --no-color proteus-proxy-server >&2
            echo "Proteus proxy server did not become ready" >&2
            exit 1
        fi
        sleep 1
    done

    wait_for_log_marker proteus-proxy-client 'SOCKS5 inbound bound'
    wait_for_log_marker hy2-proxy-client 'SOCKS5 server listening'
fi

deadline=$(( $(date +%s) + 60 ))
until "${COMPOSE[@]}" logs --no-color netem 2>&1 \
    | grep 'NETEM_ROUTER_READY' >/dev/null; do
    if (( $(date +%s) >= deadline )); then
        "${COMPOSE[@]}" logs --no-color netem >&2
        echo "netem router did not publish its ready marker" >&2
        exit 1
    fi
    sleep 1
done

deadline=$(( $(date +%s) + 60 ))
until "${COMPOSE[@]}" logs --no-color hy2-server 2>&1 \
    | grep 'server up and running' >/dev/null; do
    if (( $(date +%s) >= deadline )); then
        "${COMPOSE[@]}" logs --no-color hy2-server >&2
        echo "Hysteria2 server did not become ready" >&2
        exit 1
    fi
    sleep 1
done

{
    printf '{"kind":"environment","timestamp_utc":"%s",' "$STAMP"
    printf '"proteus_git_commit":"%s",' "$(git -C "$ROOT" rev-parse HEAD)"
    printf '"proteus_worktree_dirty":%s,' \
        "$([[ -n "$(git -C "$ROOT" status --short)" ]] && echo true || echo false)"
    printf '"hy2_git_commit":"%s",' "f2ad1de5da52a1da9622285a1d61553ddaa41f21"
    printf '"tuic_version":"%s",' \
        "$([[ "$INCLUDE_TUIC" = "1" ]] && echo "official-tuic-v5-1.0.0" || echo "not-run")"
    if [ "$WORKLOAD_MODE" = "proxy" ]; then
        proteus_image_ref=proteus/proxy-bench:local
    else
        proteus_image_ref=proteus/bench:local
    fi
    printf '"proteus_image_ref":"%s","proteus_image_id":"%s",' \
        "$proteus_image_ref" \
        "$(docker image inspect "$proteus_image_ref" --format '{{.Id}}')"
    printf '"hy2_image_id":"%s",' \
        "$(docker image inspect proteus/hysteria-bench:f2ad1de --format '{{.Id}}')"
    if [ "$INCLUDE_TUIC" = "1" ]; then
        printf '"tuic_image_id":"%s",' \
            "$(docker image inspect proteus/tuic-bench:1.0.0 --format '{{.Id}}')"
    fi
    printf '"payload_mib":%s,"runs_per_cell":%s,' "$PAYLOAD_MIB" "$RUNS_PER_CELL"
    printf '"workload_mode":"%s",' "$WORKLOAD_MODE"
    printf '"proteus_brutal_target_mbps":%s,' "$PROTEUS_BRUTAL_TARGET_MBPS"
    printf '"proteus_ack_eliciting_threshold":%s,' "$PROTEUS_ACK_ELICITING_THRESHOLD"
    printf '"proteus_initial_mtu":%s,' "$PROTEUS_INITIAL_MTU"
    printf '"proteus_minimum_mtu":%s,' "$PROTEUS_MINIMUM_MTU"
    printf '"proteus_mtu_upper_bound":%s,' "$PROTEUS_MTU_UPPER_BOUND"
    printf '"proteus_beta_first_timeout_secs":%s,' "$PROTEUS_BETA_FIRST_TIMEOUT_SECS"
    printf '"connection_lifecycle":"%s","warmup_mib":%s,' \
        "$([[ "$WORKLOAD_MODE" = "proxy" ]] && echo "per-cell-reset-then-warm" || echo "one-shot")" \
        "$WARMUP_MIB"
    printf '"kernel":"%s"}\n' \
        "$("${COMPOSE[@]}" exec -T netem uname -srvmo | sed 's/"/\\"/g')"
} > "${RESULTS_DIR}/metadata.jsonl"

"${COMPOSE[@]}" exec -T netem /usr/local/bin/netem-control.sh clear \
    > "${RESULTS_DIR}/qdisc-baseline.json"

run_cell() {
        cell="$1"
        shift
        cell_dir="${RESULTS_DIR}/${cell}"
        mkdir -p "$cell_dir"

        "${COMPOSE[@]}" exec -T netem \
            /usr/local/bin/netem-control.sh "$@" \
            > "${cell_dir}/qdisc-applied.json"
        jq -cn \
            --arg cell "$cell" \
            --arg model "$1" \
            --argjson arguments "$(printf '%s\n' "$@" | jq -R . | jq -s .)" \
            '{cell:$cell,model:$model,arguments:$arguments}' \
            > "${cell_dir}/cell-config.json"

        if [ "$WORKLOAD_MODE" = "proxy" ]; then
            reset_and_warm_proxy_clients "$cell_dir"
        fi
        "${COMPOSE[@]}" exec -T netem \
            /usr/local/bin/netem-control.sh stats \
            > "${cell_dir}/qdisc-before.json"

        : > "${cell_dir}/proteus.jsonl"
        : > "${cell_dir}/proteus.stderr"
        : > "${cell_dir}/hy2.jsonl"
        if [ "$WORKLOAD_MODE" = "proxy" ]; then
            : > "${cell_dir}/proteus-resources.jsonl"
            : > "${cell_dir}/hy2-resources.jsonl"
        fi
        if [ "$INCLUDE_TUIC" = "1" ]; then
            : > "${cell_dir}/tuic.jsonl"
            if [ "$WORKLOAD_MODE" = "proxy" ]; then
                : > "${cell_dir}/tuic-resources.jsonl"
            fi
        fi

        run_proteus() {
            status=0
            printf '{"kind":"run_start","run":%d}\n' "$run" \
                >> "${cell_dir}/proteus.jsonl"
            if [ "$WORKLOAD_MODE" = "proxy" ]; then
                service=proteus-proxy-bench-driver
                resource_before="$(proxy_resource_snapshot proteus-proxy-client)"
            else
                service=proteus-client
            fi
            "${COMPOSE[@]}" run --rm -T \
                -e RUNS_PER_CELL=1 \
                -e RESOURCE_RUN="$run" \
                "$service" \
                >> "${cell_dir}/proteus.jsonl" \
                2>> "${cell_dir}/proteus.stderr" || status=$?
            if [ "$WORKLOAD_MODE" = "proxy" ]; then
                resource_after="$(proxy_resource_snapshot proteus-proxy-client)"
                append_proxy_resource "proteus-beta-brutal" "$run" \
                    "$resource_before" "$resource_after" "$status" \
                    "${cell_dir}/proteus-resources.jsonl"
            fi
            [ "$status" -eq 0 ] && return 0
            printf '{"kind":"run_failure","run":%d,"exit_status":%d}\n' \
                "$run" "$status" >> "${cell_dir}/proteus.jsonl"
            return 0
        }

        run_hy2() {
            status=0
            printf '{"kind":"run_start","run":%d}\n' "$run" \
                >> "${cell_dir}/hy2.jsonl"
            if [ "$WORKLOAD_MODE" = "proxy" ]; then
                service=hy2-proxy-bench-driver
                resource_before="$(proxy_resource_snapshot hy2-proxy-client)"
            else
                service=hy2-client
            fi
            "${COMPOSE[@]}" run --rm -T \
                -e RESOURCE_RUN="$run" \
                "$service" \
                >> "${cell_dir}/hy2.jsonl" \
                2>&1 || status=$?
            if [ "$WORKLOAD_MODE" = "proxy" ]; then
                resource_after="$(proxy_resource_snapshot hy2-proxy-client)"
                append_proxy_resource "hysteria2" "$run" \
                    "$resource_before" "$resource_after" "$status" \
                    "${cell_dir}/hy2-resources.jsonl"
            fi
            [ "$status" -eq 0 ] && return 0
            printf '{"kind":"run_failure","run":%d,"exit_status":%d}\n' \
                "$run" "$status" >> "${cell_dir}/hy2.jsonl"
            return 0
        }

        run_tuic() {
            status=0
            printf '{"kind":"run_start","run":%d}\n' "$run" \
                >> "${cell_dir}/tuic.jsonl"
            resource_before="$(proxy_resource_snapshot tuic-client)"
            "${COMPOSE[@]}" run --rm -T \
                -e PAYLOAD_MIB="$PAYLOAD_MIB" \
                tuic-bench-driver \
                >> "${cell_dir}/tuic.jsonl" \
                2>&1 || status=$?
            resource_after="$(proxy_resource_snapshot tuic-client)"
            append_proxy_resource "official-tuic-v5-1.0.0" "$run" \
                "$resource_before" "$resource_after" "$status" \
                "${cell_dir}/tuic-resources.jsonl"
            [ "$status" -eq 0 ] && return 0
            printf '{"kind":"run_failure","run":%d,"exit_status":%d}\n' \
                "$run" "$status" >> "${cell_dir}/tuic.jsonl"
            return 0
        }

        for ((run = 1; run <= RUNS_PER_CELL; run++)); do
            if [ "$INCLUDE_TUIC" = "1" ]; then
                # Rotate first/middle/last position across all three
                # implementations without a hidden random seed.
                case $((run % 3)) in
                    1) run_proteus; run_hy2; run_tuic ;;
                    2) run_hy2; run_tuic; run_proteus ;;
                    0) run_tuic; run_proteus; run_hy2 ;;
                esac
            else
                # Alternate AB/BA ordering for the two-way matrix.
                if ((run % 2 == 1)); then
                    run_proteus
                    run_hy2
                else
                    run_hy2
                    run_proteus
                fi
            fi
        done

        "${COMPOSE[@]}" exec -T netem \
            /usr/local/bin/netem-control.sh stats \
            > "${cell_dir}/qdisc-after.json"
        if [ "$WORKLOAD_MODE" = "proxy" ]; then
            "${COMPOSE[@]}" logs --no-color proteus-proxy-client \
                > "${cell_dir}/proteus-client-daemon.log" 2>&1
            "${COMPOSE[@]}" logs --no-color proteus-proxy-server \
                > "${cell_dir}/proteus-server-daemon.log" 2>&1
            "${COMPOSE[@]}" logs --no-color hy2-proxy-client \
                > "${cell_dir}/hy2-client-daemon.log" 2>&1
            "${COMPOSE[@]}" logs --no-color hy2-server \
                > "${cell_dir}/hy2-server-daemon.log" 2>&1
            if [ "$INCLUDE_TUIC" = "1" ]; then
                "${COMPOSE[@]}" logs --no-color tuic-client \
                    > "${cell_dir}/tuic-client-daemon.log" 2>&1
                "${COMPOSE[@]}" logs --no-color tuic-server \
                    > "${cell_dir}/tuic-server-daemon.log" 2>&1
            fi
            if grep -q 'falling back to α' \
                "${cell_dir}/proteus-client-daemon.log"; then
                echo "benchmark invalid: Proteus β fell back to α in ${cell}" >&2
                return 1
            fi
        fi
}

for loss in ${LOSS_PCT_LIST}; do
    for delay in ${DELAY_MS_LIST}; do
        run_cell "iid-loss${loss}-delay${delay}" iid "$loss" "$delay"
    done
done

if [ -n "$GEMODEL_CELLS" ]; then
    old_ifs="$IFS"
    IFS=';'
    for specification in $GEMODEL_CELLS; do
        IFS=','
        set -- $specification
        IFS="$old_ifs"
        if [ "$#" -ne 5 ]; then
            echo "invalid GEMODEL_CELLS entry: ${specification}" >&2
            exit 2
        fi
        cell="$(
            printf 'gemodel-p%s-r%s-h%s-k%s-delay%s' "$1" "$2" "$3" "$4" "$5" \
                | tr '.%' '__'
        )"
        run_cell "$cell" gemodel "$1" "$2" "$3" "$4" "$5"
    done
    IFS="$old_ifs"
fi

python3 "${ROOT}/bench/summarize-netem-results.py" "${RESULTS_DIR}"
echo "${RESULTS_DIR}"
