#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 3 ]]; then
    printf 'Usage: %s PATCHED_HOST INPUT_JSON NEW_ARTIFACT_DIRECTORY\n' "$0" >&2
    exit 1
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
host="$1"
input="$2"
output="$3"
elf="$root/guest/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/coins-gsr-guest"

test -x "$host" || { printf 'Patched prover host is not executable: %s\n' "$host" >&2; exit 1; }
test -f "$input" || { printf 'Proof input is missing: %s\n' "$input" >&2; exit 1; }
test -f "$elf" || { printf 'Build the pinned guest before proving\n' >&2; exit 1; }
test ! -e "$output" || { printf 'Refusing to overwrite: %s\n' "$output" >&2; exit 1; }

# This bounded profile traded throughput for predictable local memory use on
# the 41.9-million-instruction settlement relation.
export SHARD_SIZE=262144
export MINIMAL_TRACE_CHUNK_THRESHOLD=262144
export ELEMENT_THRESHOLD=16777216
export HEIGHT_THRESHOLD=262144
export SP1_WORKER_NUM_CORE_WORKERS=1
export SP1_WORKER_CORE_BUFFER_SIZE=1
export SP1_WORKER_NUM_SETUP_WORKERS=1
export SP1_WORKER_SETUP_BUFFER_SIZE=1
export SP1_WORKER_NUM_SPLICING_WORKERS=1
export SP1_WORKER_SPLICING_BUFFER_SIZE=1
export SP1_WORKER_NUM_PREPARE_REDUCE_WORKERS=1
export SP1_WORKER_PREPARE_REDUCE_BUFFER_SIZE=1
export SP1_WORKER_NUM_RECURSION_EXECUTOR_WORKERS=1
export SP1_WORKER_RECURSION_EXECUTOR_BUFFER_SIZE=1
export SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=1
export SP1_WORKER_RECURSION_PROVER_BUFFER_SIZE=1
export RAYON_NUM_THREADS="${COINS_GSR_PROVER_THREADS:-4}"

exec "$host" prove "$input" "$elf" "$output"
