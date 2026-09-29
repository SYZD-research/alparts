#!/usr/bin/env bash
# Text secret scanners skip binary blobs, and removing a file from HEAD does
# not remove it from history. Fail when any commit reachable from any ref adds
# agent/tool state, local databases, key material or environment files.
set -Eeuo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd -- "$repository_root"

forbidden='(^|/)\.(aurea|commandcode|codex|claude)/|(^|/)audit-alparts/var/|\.(db|sqlite|sqlite3|sqlite3-wal|sqlite3-shm|sqlite-wal|sqlite-shm|pem|key|p12|pfx|keystore|jks|age|dump)$|(^|/)(key\.properties|\.npmrc|id_rsa|id_ed25519)$|(^|/)([^/]*\.)?env$|(^|/)\.env\.[^/]+$'
allowed='(^|/)\.env\.example$|^packages/desktop/src/fixtures/[^/]+\.pem$'

# Historical additions reviewed and accepted by the owner: they hold only
# throwaway development values and are intentionally left in history.
# Entries are exact "commit path" pairs; a new commit adding the same path
# still fails.
accepted=(
  "156ca10b3c06d6f9b05aeffb74f43c9d669b6c18 .aurea/aurea.db"
  "156ca10b3c06d6f9b05aeffb74f43c9d669b6c18 audit-alparts/var/ledger.sqlite3"
  "156ca10b3c06d6f9b05aeffb74f43c9d669b6c18 audit-alparts/var/ledger.sqlite3-shm"
  "156ca10b3c06d6f9b05aeffb74f43c9d669b6c18 audit-alparts/var/ledger.sqlite3-wal"
  "f1a726b0133b8de75bb2326c16e7bf89944d0579 .commandcode/settings.json"
  "f1a726b0133b8de75bb2326c16e7bf89944d0579 .commandcode/taste/taste.md"
  "f1a726b0133b8de75bb2326c16e7bf89944d0579 .commandcode/taste/user-preferences/taste.md"
  "f1a726b0133b8de75bb2326c16e7bf89944d0579 .commandcode/taste/workflow/taste.md"
  "310f1419783ed63bdfe6105bbe32e43d82b741c1 .commandcode/taste/user-preferences/taste.md"
  "310f1419783ed63bdfe6105bbe32e43d82b741c1 .commandcode/taste/workflow/taste.md"
)

is_accepted() {
  local entry
  for entry in "${accepted[@]}"; do
    [[ "$entry" == "$1" ]] && return 0
  done
  return 1
}

found=()
commit=''
while IFS= read -r line; do
  if [[ "$line" == commit\ * ]]; then
    commit="${line#commit }"
    continue
  fi
  [[ -n "$line" ]] || continue
  [[ "$line" =~ $forbidden ]] || continue
  [[ "$line" =~ $allowed ]] && continue
  is_accepted "$commit $line" && continue
  found+=("${commit:0:12} $line")
done < <(git log --all --diff-filter=AMR --name-only --format='commit %H')

if (( ${#found[@]} > 0 )); then
  printf 'Forbidden files are present in git history:\n' >&2
  printf '  %s\n' "${found[@]}" >&2
  printf 'Rotate any secrets they held, then remove them from history (git filter-repo).\n' >&2
  exit 1
fi
