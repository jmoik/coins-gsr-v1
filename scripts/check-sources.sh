#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

jq -e '.schema == 1 and (.sources | length > 0)' \
  "$repo_root/sources.lock.json" >/dev/null

while IFS=$'\t' read -r path expected; do
  source_path="$repo_root/$path"
  test -e "$source_path" || {
    echo "missing source: $path" >&2
    exit 1
  }
  if [[ -n "$expected" && -d "$source_path/.git" || -n "$expected" && -f "$source_path/.git" ]]; then
    actual=$(git -C "$source_path" rev-parse HEAD)
    [[ "$actual" == "$expected" ]] || {
      echo "revision mismatch for $path: expected $expected, got $actual" >&2
      exit 1
    }
  fi
done < <(jq -r '.sources[] | select(.path) | [.path, (.repository_revision // "")] | @tsv' \
  "$repo_root/sources.lock.json")

while IFS=$'\t' read -r path expected; do
  actual=$(shasum -a 256 "$repo_root/$path")
  [[ "${actual%% *}" == "$expected" ]] || {
    echo "patch checksum mismatch: $path" >&2
    exit 1
  }
done < <(jq -r '.sources[] | [(.local_patch // .runtime_patch), (.local_patch_sha256 // .runtime_patch_sha256)] | select(.[0] != null and .[0] != "") | @tsv' \
  "$repo_root/sources.lock.json")

gsr_path=$(jq -r '.sources[] | select(.name == "gsr-core") | .path' "$repo_root/sources.lock.json")
for binary in bitcoind bitcoin-util; do
  field=$(printf '%s_sha256' "$binary" | tr - _)
  expected=$(jq -r --arg field "$field" '.sources[] | select(.name == "gsr-core") | .[$field]' \
    "$repo_root/sources.lock.json")
  actual=$(shasum -a 256 "$repo_root/$gsr_path/build/bin/$binary")
  [[ "${actual%% *}" == "$expected" ]] || {
    echo "binary checksum mismatch: $binary" >&2
    exit 1
  }
done

echo "source references are present and pinned revisions match"
