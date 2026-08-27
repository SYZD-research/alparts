#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

show_help() {
  cat <<'HELP'
Create the mandatory encrypted backup gate before a database migration.

Usage:
  scripts/pre-migration-backup.sh <migration-label>

This wrapper records pre-migration:<label> in the encrypted manifest and invokes
scripts/backup.sh. It does not run a migration, stop/start services, delete data,
or restore anything. All backup.sh settings and its explicit quiescence assertion
are required. Verify the produced artifact with restore-verify.sh before applying
the migration under a separate deployment identity.
HELP
}

if [[ "${1-}" == '--help' || "${1-}" == '-h' ]]; then
  show_help
  exit 0
fi
if [[ $# -ne 1 || ! "$1" =~ ^[A-Za-z0-9._-]{1,60}$ ]]; then
  printf 'Usage: pre-migration-backup.sh <safe-migration-label>\n' >&2
  exit 2
fi

export BACKUP_REASON="pre-migration:$1"
exec "$SCRIPT_DIR/backup.sh"
