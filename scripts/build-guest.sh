#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cargo_prove="${COINS_GSR_CARGO_PROVE:-$HOME/.sp1/bin/cargo-prove}"
test -x "$cargo_prove" || {
    printf 'Set COINS_GSR_CARGO_PROVE to the pinned SP1 6.0.1 cargo-prove\n' >&2
    exit 1
}

(cd "$root/guest" && "$cargo_prove" prove build)
elf="$root/guest/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/coins-gsr-guest"
expected=3b0a8aba36a0ced4b6a3ef658d45e61ae4bcfbcc283276d0814e70302cc84473
actual="$(shasum -a 256 "$elf")"
if [[ "${actual%% *}" != "$expected" ]]; then
    printf 'Guest ELF differs from the frozen v1 deployment\n' >&2
    exit 1
fi
printf 'Reproduced guest ELF: %s\n' "$expected"
