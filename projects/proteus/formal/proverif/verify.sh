#!/bin/sh
set -eu

root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
image="${PROVERIF_IMAGE:-proteus/proverif:2.05}"
model="${root}/formal/proverif/proteus-v12-handshake.pv"
ratchet_model="${root}/formal/proverif/proteus-one-shot-ratchet.pv"
results_dir="${PROVERIF_RESULTS_DIR:-${root}/formal/proverif/results}"
output="${results_dir}/proteus-v12-handshake.txt"
ratchet_output="${results_dir}/proteus-one-shot-ratchet.txt"

mkdir -p "$results_dir"

docker build \
    --file "${root}/formal/proverif/Dockerfile" \
    --tag "$image" \
    "${root}/formal/proverif"

docker run --rm \
    --volume "${model}:/model.pv:ro" \
    "$image" \
    /model.pv >"$output" 2>&1

if grep -Eq 'RESULT .* is false|RESULT .* cannot be proved' "$output"; then
    cat "$output" >&2
    exit 1
fi

proved="$(grep -Ec '^RESULT .* is true\.$' "$output" || true)"
if [ "$proved" -ne 4 ]; then
    cat "$output" >&2
    echo "expected exactly 4 proved Proteus v1.2 properties, got ${proved}" >&2
    exit 1
fi

cat "$output"

docker run --rm \
    --volume "${ratchet_model}:/model.pv:ro" \
    "$image" \
    /model.pv >"$ratchet_output" 2>&1

traffic_secret_only="$(
    grep -Ec '^RESULT not attacker(_bitstring)?\(traffic_secret_only_payload\[\]\) is true\.$' \
        "$ratchet_output" || true
)"
full_receiver_state="$(
    grep -Ec '^RESULT not attacker(_bitstring)?\(full_receiver_state_payload\[\]\) is false\.$' \
        "$ratchet_output" || true
)"
forward_secret="$(
    grep -Ec '^RESULT not attacker(_bitstring)?\(forward_secret_payload\[\]\) is true\.$' \
        "$ratchet_output" || true
)"

if [ "$traffic_secret_only" -ne 1 ] \
    || [ "$full_receiver_state" -ne 1 ] \
    || [ "$forward_secret" -ne 1 ]; then
    cat "$ratchet_output" >&2
    echo "unexpected one-shot ratchet proof boundary" >&2
    echo "expected: traffic-secret-only=true, full-receiver-state=false, forward-secret=true" >&2
    exit 1
fi

cat "$ratchet_output"
