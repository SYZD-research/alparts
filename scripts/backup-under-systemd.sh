#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SERVICE_NAME="${ALPARTS_SERVICE_NAME:-alparts.service}"
[[ "$SERVICE_NAME" =~ ^[A-Za-z0-9_.@-]{1,128}$ ]] || {
  printf 'Invalid ALPARTS_SERVICE_NAME\n' >&2
  exit 2
}

# This script runs as root: only accept a plain lock file name under
# /run/lock, and open it without truncation before taking the lock.
LOCK_FILE="${ALPARTS_BACKUP_LOCK_FILE:-/run/lock/alparts-backup.lock}"
[[ "$LOCK_FILE" =~ ^/run/lock/[A-Za-z0-9_.-]{1,64}\.lock$ ]] || {
  printf 'ALPARTS_BACKUP_LOCK_FILE must be a .lock file directly under /run/lock\n' >&2
  exit 2
}
[[ ! -L "$LOCK_FILE" ]] || {
  printf 'Refusing a symbolic-link lock file\n' >&2
  exit 2
}
exec 9>>"$LOCK_FILE"
flock -n 9 || {
  printf 'Another alparts backup is already running\n' >&2
  exit 1
}

systemctl is-active --quiet "$SERVICE_NAME" || {
  printf '%s is not active; refusing to change its state\n' "$SERVICE_NAME" >&2
  exit 1
}

restart_required=false
restart_application() {
  local status=$?
  trap - EXIT HUP INT TERM
  if [[ "$restart_required" == true ]]; then
    if ! systemctl start "$SERVICE_NAME"; then
      printf 'CRITICAL: backup ended and %s could not be restarted\n' "$SERVICE_NAME" >&2
      exit 1
    fi
  fi
  exit "$status"
}
trap restart_application EXIT HUP INT TERM

restart_required=true
systemctl stop "$SERVICE_NAME"
systemctl is-active --quiet "$SERVICE_NAME" && {
  printf '%s remained active after stop\n' "$SERVICE_NAME" >&2
  exit 1
}

export ALPARTS_BACKUP_QUIESCED=YES_WRITES_ARE_STOPPED
"$SCRIPT_DIR/backup.sh"

systemctl start "$SERVICE_NAME"
restart_required=false
systemctl is-active --quiet "$SERVICE_NAME" || {
  printf 'CRITICAL: %s did not return to active state after backup\n' "$SERVICE_NAME" >&2
  exit 1
}

if [[ "${BACKUP_RETENTION_ENABLED:-false}" == true ]]; then
  "$SCRIPT_DIR/prune-backups.sh" --apply
fi
