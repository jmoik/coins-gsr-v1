#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 1 ]]; then
    printf 'Usage: %s NEW_DIRECTORY\n' "$0" >&2
    exit 1
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
mkdir "$1"
output="$(cd "$1" && pwd)"
archives=("${CARGO_HOME:-$HOME/.cargo}"/registry/cache/*/sp1-prover-6.0.1.crate)
if [[ ${#archives[@]} != 1 || ! -f "${archives[0]}" ]]; then
    printf 'Expected exactly one cached sp1-prover 6.0.1 crate\n' >&2
    exit 1
fi

expected=a47f86dbe432038fed00fd869b0937d11b87abdb0e34a676aaeb5a723f1e31e3
actual="$(shasum -a 256 "${archives[0]}")"
if [[ "${actual%% *}" != "$expected" ]]; then
    printf 'sp1-prover archive checksum mismatch\n' >&2
    exit 1
fi

tar -xzf "${archives[0]}" -C "$output"
sdk="$output/sp1-prover-6.0.1"
git -C "$sdk" apply --check "$root/patches/sp1-deferred-memory.patch"
git -C "$sdk" apply "$root/patches/sp1-deferred-memory.patch"

CARGO_TARGET_DIR="$output/target" cargo build --offline --release \
    --manifest-path "$root/crates/prover-host/Cargo.toml" \
    --config "patch.crates-io.sp1-prover.path='$sdk'"
mkdir "$output/bin"
cp "$output/target/release/coins-gsr-prover-host" "$output/bin/"
shasum -a 256 "${archives[0]}" "$root/patches/sp1-deferred-memory.patch" \
    "$output/bin/coins-gsr-prover-host" > "$output/sha256.txt"
printf 'Built isolated patched prover: %s/bin/coins-gsr-prover-host\n' "$output"
