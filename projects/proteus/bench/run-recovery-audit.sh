#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(docker compose -f "${ROOT}/bench/docker-compose.netem.yml")
AUDIT_CELLS="${AUDIT_CELLS:-reorder,20,25,50;iid,5,50}"
PAYLOAD_MIB="${PAYLOAD_MIB:-64}"
RECOVERY_PROBE_ROUNDS="${RECOVERY_PROBE_ROUNDS:-7}"
RECOVERY_TOLERANT_PACKET_THRESHOLD="${RECOVERY_TOLERANT_PACKET_THRESHOLD:-64}"
RECOVERY_TOLERANT_TIME_THRESHOLD="${RECOVERY_TOLERANT_TIME_THRESHOLD:-1.125}"
SKIP_BUILD="${SKIP_BUILD:-0}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RESULTS_DIR="${RESULTS_DIR:-${ROOT}/bench/results/recovery-audit-${STAMP}}"

mkdir -p "$RESULTS_DIR"

cleanup() {
    "${COMPOSE[@]}" exec -T netem /usr/local/bin/netem-control.sh clear \
        >"${RESULTS_DIR}/qdisc-cleared.json" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

if [ "$SKIP_BUILD" != "1" ]; then
    BUILDKIT_CONTEXT_KEEP_GIT_DIR=1 "${COMPOSE[@]}" build netem proteus-server
fi

"${COMPOSE[@]}" up -d --force-recreate netem proteus-server

deadline=$(( $(date +%s) + 60 ))
until "${COMPOSE[@]}" logs --no-color proteus-server 2>&1 \
    | grep 'BENCH_SERVER_PQ_FINGERPRINT_HEX=' >/dev/null; do
    if (( $(date +%s) >= deadline )); then
        "${COMPOSE[@]}" logs --no-color proteus-server \
            >"${RESULTS_DIR}/server-startup.log" 2>&1
        echo "Proteus benchmark server did not publish its identity" >&2
        exit 1
    fi
    sleep 1
done

"${COMPOSE[@]}" logs --no-color proteus-server \
    >"${RESULTS_DIR}/server-startup.log" 2>&1
"${COMPOSE[@]}" exec -T netem /usr/local/bin/netem-control.sh clear \
    >"${RESULTS_DIR}/qdisc-baseline.json"

jq -cn \
    --arg created_at_utc "$STAMP" \
    --arg git_commit "$(git -C "$ROOT" rev-parse HEAD)" \
    --arg git_status "$(git -C "$ROOT" status --short)" \
    --arg audit_cells "$AUDIT_CELLS" \
    --arg image_id "$(docker image inspect proteus/bench:local --format '{{.Id}}')" \
    --arg kernel "$("${COMPOSE[@]}" exec -T netem uname -srvmo)" \
    --argjson payload_mib "$PAYLOAD_MIB" \
    --argjson recovery_probe_rounds "$RECOVERY_PROBE_ROUNDS" \
    --argjson tolerant_packet_threshold "$RECOVERY_TOLERANT_PACKET_THRESHOLD" \
    --argjson tolerant_time_threshold "$RECOVERY_TOLERANT_TIME_THRESHOLD" \
    '{
        created_at_utc:$created_at_utc,
        git_commit:$git_commit,
        git_status:$git_status,
        audit_cells:$audit_cells,
        image_id:$image_id,
        kernel:$kernel,
        payload_mib:$payload_mib,
        recovery_probe_rounds:$recovery_probe_rounds,
        tolerant_packet_threshold:$tolerant_packet_threshold,
        tolerant_time_threshold:$tolerant_time_threshold
    }' >"${RESULTS_DIR}/metadata.json"

overall_status=0
IFS=';' read -r -a cells <<<"$AUDIT_CELLS"
for cell_spec in "${cells[@]}"; do
    IFS=',' read -r -a arguments <<<"$cell_spec"
    model="${arguments[0]:-}"
    case "$model" in
        iid)
            if [ "${#arguments[@]}" -ne 3 ]; then
                echo "invalid IID audit cell: $cell_spec" >&2
                exit 2
            fi
            cell="iid-loss${arguments[1]}-delay${arguments[2]}"
            ;;
        reorder)
            if [ "${#arguments[@]}" -ne 4 ]; then
                echo "invalid reorder audit cell: $cell_spec" >&2
                exit 2
            fi
            cell="reorder${arguments[1]}-corr${arguments[2]}-delay${arguments[3]}"
            ;;
        *)
            echo "unsupported recovery audit model: $model" >&2
            exit 2
            ;;
    esac

    cell_dir="${RESULTS_DIR}/${cell}"
    mkdir -p "$cell_dir"
    printf '%s\n' "$cell_spec" >"${cell_dir}/cell-spec.txt"
    "${COMPOSE[@]}" exec -T netem \
        /usr/local/bin/netem-control.sh "${arguments[@]}" \
        >"${cell_dir}/qdisc-applied.json"
    "${COMPOSE[@]}" exec -T netem /usr/local/bin/netem-control.sh stats \
        >"${cell_dir}/qdisc-before.json"

    status=0
    "${COMPOSE[@]}" run --rm -T \
        -e PAYLOAD_MIB="$PAYLOAD_MIB" \
        -e RUNS_PER_CELL=1 \
        -e RECOVERY_PROBE_ROUNDS="$RECOVERY_PROBE_ROUNDS" \
        -e RECOVERY_TOLERANT_PACKET_THRESHOLD="$RECOVERY_TOLERANT_PACKET_THRESHOLD" \
        -e RECOVERY_TOLERANT_TIME_THRESHOLD="$RECOVERY_TOLERANT_TIME_THRESHOLD" \
        -e NO_COLOR=1 \
        proteus-client \
        >"${cell_dir}/client.stdout" \
        2>"${cell_dir}/client.stderr" || status=$?

    printf '%s\n' "$status" >"${cell_dir}/exit-status.txt"
    "${COMPOSE[@]}" exec -T netem /usr/local/bin/netem-control.sh stats \
        >"${cell_dir}/qdisc-after.json"
    "${COMPOSE[@]}" logs --no-color proteus-server \
        >"${cell_dir}/server.log" 2>&1

    if [ "$status" -ne 0 ]; then
        echo "recovery audit cell failed: ${cell}; raw evidence retained" >&2
        overall_status=1
    fi
done

printf 'Recovery audit raw evidence: %s\n' "$RESULTS_DIR"
exit "$overall_status"
