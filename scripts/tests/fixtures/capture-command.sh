#!/usr/bin/env bash
set -Eeuo pipefail

command_name="${0##*/}"
capture_dir="${BACKUP_TEST_CAPTURE_DIR:?BACKUP_TEST_CAPTURE_DIR is required}"

printf '%s\n' "$@" > "$capture_dir/${command_name}.argv"
env | LC_ALL=C sort > "$capture_dir/${command_name}.env"

case "$command_name" in
  jq)
    exec "${BACKUP_TEST_REAL_JQ:?BACKUP_TEST_REAL_JQ is required}" "$@"
    ;;
  mc)
    import_payload="$(</dev/stdin)"
    printf '%s' "$import_payload" > "$capture_dir/mc.stdin"
    ;;
esac
