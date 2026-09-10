#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 6 ]]; then
    printf 'Usage: %s SCENARIO DEPLOYMENT INPUT_ROOT PROOF_ROOT SCRIPT_ROOT NEW_FIXTURE_ROOT\n' "$0" >&2
    exit 1
fi

scenario="$1"
deployment="$2"
inputs="$3"
proofs="$4"
scripts="$5"
output="$6"
test ! -e "$output" || { printf 'Refusing to overwrite: %s\n' "$output" >&2; exit 1; }

for file in "$scenario" "$deployment"; do
    test -f "$file" || { printf 'Missing artifact: %s\n' "$file" >&2; exit 1; }
done
for name in collection-1 settlement collection-2; do
    for file in "$inputs/$name/input.json" "$proofs/$name/proof.bin" \
        "$proofs/$name/verified.json" "$scripts/$name.json"; do
        test -f "$file" || { printf 'Missing artifact: %s\n' "$file" >&2; exit 1; }
    done
done

mkdir -p "$output"
cp "$scenario" "$output/scenario.json"
cp "$deployment" "$output/deployment.json"
for name in collection-1 settlement collection-2; do
    mkdir "$output/$name"
    cp "$inputs/$name/input.json" "$output/$name/input.json"
    cp "$proofs/$name/proof.bin" "$output/$name/proof.bin"
    cp "$proofs/$name/verified.json" "$output/$name/verified.json"
    cp "$scripts/$name.json" "$output/$name/script.json"
done

(
    cd "$output"
    shasum -a 256 deployment.json scenario.json */input.json */proof.bin \
        */verified.json */script.json > SHA256SUMS
)
printf 'Packaged immutable bounded fixtures: %s\n' "$output"
