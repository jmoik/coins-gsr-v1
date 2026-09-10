#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 3 ]]; then
    printf 'Usage: %s VERIFIED_PROOF_JSON DEPLOYMENT_JSON OUTPUT_JSON\n' "$0" >&2
    exit 1
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
source_repo="${COINS_GSR_GROTH16_REPO:-/Users/julian/Code/bitcoin/zk/groth16}"
revision=343dfd85160e560cb38e721b9bc7af27b897a529
work="$(mktemp -d "${TMPDIR:-/tmp}/coins-gsr-verifier.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir "$work/repo"
git -C "$source_repo" archive "$revision" | tar -x -C "$work/repo"
ln -s "${COINS_GSR_STARK_REPO:-/Users/julian/Code/bitcoin/zk/stark}" "$work/stark"
git -C "$work/repo" apply "$root/patches/gsr-verifier.patch"
cp "$root/script/coins_gsr_adapter.rs" "$work/repo/src/dsl/bn254/coins_gsr_adapter.rs"

export GROTH16_BITCOIN_UTIL="${GROTH16_BITCOIN_UTIL:-/Users/julian/Code/bitcoin/core/gsr/gsr-full/build/bin/bitcoin-util}"
export COINS_GSR_PROOF="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
export COINS_GSR_DEPLOYMENT="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
export COINS_GSR_SCRIPT_OUTPUT="$(cd "$(dirname "$3")" && pwd)/$(basename "$3")"
test -x "$GROTH16_BITCOIN_UTIL"
test ! -e "$COINS_GSR_SCRIPT_OUTPUT"

cd "$work/repo"
cargo +stable test --offline --locked coins_gsr_proof_accepts_gsr_script -- --ignored --nocapture
shasum -a 256 "$GROTH16_BITCOIN_UTIL" "$root/patches/gsr-verifier.patch" \
    "$COINS_GSR_SCRIPT_OUTPUT" > "$COINS_GSR_SCRIPT_OUTPUT.sha256"
printf 'Built and replayed verifier artifact: %s\n' "$COINS_GSR_SCRIPT_OUTPUT"
