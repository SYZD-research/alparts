#!/usr/bin/env bash
set -Eeuo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd -- "$repository_root"

files=()
while IFS= read -r -d '' file; do
  case "$file" in
    .env.example|pnpm-lock.yaml)
      continue
      ;;
  esac
  files+=("$file")
done < <(git ls-files -z)

(( ${#files[@]} > 0 )) || exit 0
pnpm exec secretlint --no-glob "${files[@]}"
