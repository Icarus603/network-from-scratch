#!/bin/sh
set -eu

root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
image="${PROVERIF_IMAGE:-proteus/proverif:2.05}"
model="${root}/formal/proverif/proteus-v12-handshake.pv"
results_dir="${PROVERIF_RESULTS_DIR:-${root}/formal/proverif/results}"
output="${results_dir}/proteus-v12-handshake.txt"

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
