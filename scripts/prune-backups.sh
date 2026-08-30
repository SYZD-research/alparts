#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

mode="${1:---dry-run}"
[[ "$mode" == '--dry-run' || "$mode" == '--apply' ]] || {
  printf 'Usage: prune-backups.sh [--dry-run|--apply]\n' >&2
  exit 2
}

output_dir="${BACKUP_OUTPUT_DIR:?BACKUP_OUTPUT_DIR is required}"
retention_days="${BACKUP_RETENTION_DAYS:-30}"
minimum_copies="${BACKUP_MINIMUM_COPIES:-7}"
[[ "$retention_days" =~ ^[1-9][0-9]{0,3}$ ]] || { printf 'Invalid BACKUP_RETENTION_DAYS\n' >&2; exit 2; }
[[ "$minimum_copies" =~ ^[1-9][0-9]{0,3}$ ]] || { printf 'Invalid BACKUP_MINIMUM_COPIES\n' >&2; exit 2; }
(( retention_days <= 3650 && minimum_copies <= 1000 )) || {
  printf 'Backup retention bounds are excessive\n' >&2
  exit 2
}

canonical_dir="$(realpath -e -- "$output_dir")"
case "$canonical_dir" in
  /|/root|/home|/usr|/var|/var/lib|/opt)
    printf 'Refusing broad backup retention target: %s\n' "$canonical_dir" >&2
    exit 2
    ;;
esac
[[ -d "$canonical_dir" && -w "$canonical_dir" ]] || { printf 'Backup directory is not writable\n' >&2; exit 2; }

mapfile -d '' backups < <(find "$canonical_dir" -maxdepth 1 -type f \
  -name 'alparts-backup-????????T??????Z-????????????.tar.age' -print0 | sort -z)
(( ${#backups[@]} > minimum_copies )) || exit 0

delete_count=$(( ${#backups[@]} - minimum_copies ))
now="$(date +%s)"
for (( index=0; index<delete_count; index+=1 )); do
  candidate="${backups[$index]}"
  age_days=$(( (now - $(stat -c '%Y' -- "$candidate")) / 86400 ))
  (( age_days >= retention_days )) || continue
  if [[ "$mode" == '--dry-run' ]]; then
    printf 'would-delete %s\n' "$candidate"
    continue
  fi
  [[ "${BACKUP_PRUNE_ACK:-}" == 'DELETE_EXPIRED_ENCRYPTED_BACKUPS' ]] || {
    printf 'BACKUP_PRUNE_ACK is required for --apply\n' >&2
    exit 2
  }
  rm -- "$candidate"
  printf 'deleted %s\n' "$candidate"
done
