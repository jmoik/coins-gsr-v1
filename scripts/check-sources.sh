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

echo "source references are present and pinned revisions match"
