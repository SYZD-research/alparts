#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/backup-common.sh
source "$SCRIPT_DIR/lib/backup-common.sh"

show_help() {
  cat <<'HELP'
Create one recipient-encrypted Phase 1 backup containing a consistent PostgreSQL
custom-format dump and the current encrypted objects from one MinIO bucket.

Required settings (a *_FILE alternative is accepted for values marked secret):
  DATABASE_SERVICE_FILE        Private libpq service file for the source
  DATABASE_SERVICE             Service section name in that file
  MINIO_URL                    Source URL (HTTPS, or HTTP on loopback only)
  MINIO_ACCESS_KEY             Source access key (secret)
  MINIO_SECRET_KEY             Source secret key (secret)
  MINIO_BUCKET                 Source bucket name
  BACKUP_AGE_RECIPIENT         age recipient public key
  BACKUP_OUTPUT_DIR            Existing directory for the encrypted artifact
  ALPARTS_BACKUP_QUIESCED      Must be exactly YES_WRITES_ARE_STOPPED

Optional:
  BACKUP_REASON                Safe label recorded inside the encrypted manifest

The script never stops the application. ALPARTS_BACKUP_QUIESCED is an operator
assertion that all application writes are already stopped for the complete run.
The installed pg_dump major must match the source PostgreSQL server major.
The output is alparts-backup-<run-id>.tar.age and is never silently overwritten.

This is not PITR, WORM retention, off-site replication, or automated disaster
recovery. Browser-held device private keys are not part of a server backup.
HELP
}

if [[ "${1-}" == '--help' || "${1-}" == '-h' ]]; then
  show_help
  exit 0
fi
[[ $# -eq 0 ]] || backup_die 'This script accepts no positional arguments; use --help'

for dependency in age awk chmod cmp cut date find grep jq ln mc mkdir mktemp od pg_dump psql rm sed sha256sum sort stat sync tar tr uniq wc; do
  require_command "$dependency"
done

[[ "${ALPARTS_BACKUP_QUIESCED-}" == 'YES_WRITES_ARE_STOPPED' ]] \
  || backup_die 'Stop application writes, then set ALPARTS_BACKUP_QUIESCED=YES_WRITES_ARE_STOPPED'

[[ -n "${DATABASE_SERVICE_FILE-}" ]] \
  || backup_die 'Missing required setting: DATABASE_SERVICE_FILE'
[[ -n "${DATABASE_SERVICE-}" ]] \
  || backup_die 'Missing required setting: DATABASE_SERVICE'
export -n DATABASE_SERVICE 2>/dev/null || true
load_required_value MINIO_URL
load_required_value MINIO_ACCESS_KEY
load_required_value MINIO_SECRET_KEY
load_required_value MINIO_BUCKET
load_required_value BACKUP_AGE_RECIPIENT
load_required_value BACKUP_OUTPUT_DIR

validate_minio_url "$MINIO_URL"
validate_postgres_service "$DATABASE_SERVICE_FILE" "$DATABASE_SERVICE"
export -n DATABASE_SERVICE_FILE 2>/dev/null || true
validate_bucket_name "$MINIO_BUCKET"
[[ "$BACKUP_AGE_RECIPIENT" != AGE-SECRET-KEY-* && "$BACKUP_AGE_RECIPIENT" != *[$'\t\r\n ']* ]] \
  || backup_die 'BACKUP_AGE_RECIPIENT must be a public recipient, not an age identity'
[[ -d "$BACKUP_OUTPUT_DIR" && -w "$BACKUP_OUTPUT_DIR" ]] \
  || backup_die 'BACKUP_OUTPUT_DIR must be an existing writable directory'

BACKUP_REASON="${BACKUP_REASON-manual}"
[[ "$BACKUP_REASON" =~ ^[A-Za-z0-9._:-]{1,80}$ ]] \
  || backup_die 'BACKUP_REASON must be 1-80 safe label characters'

STAGING_DIR=''
CIPHER_TEMP=''
cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  if [[ -n "$CIPHER_TEMP" && -f "$CIPHER_TEMP" ]]; then
    rm -f -- "$CIPHER_TEMP"
  fi
  if [[ -n "$STAGING_DIR" && -d "$STAGING_DIR" ]]; then
    rm -rf -- "$STAGING_DIR"
  fi
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

STAGING_DIR="$(mktemp -d "${TMPDIR:-/tmp}/alparts-backup.XXXXXXXX")"
chmod 700 -- "$STAGING_DIR"
PAYLOAD_DIR="$STAGING_DIR/payload"
OBJECT_DIR="$PAYLOAD_DIR/objects"
MC_CONFIG_DIR="$STAGING_DIR/mc"
mkdir -p -- "$OBJECT_DIR"

RUN_ID="$(date -u +'%Y%m%dT%H%M%SZ')-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
FINAL_OUTPUT="$BACKUP_OUTPUT_DIR/alparts-backup-${RUN_ID}.tar.age"
[[ ! -e "$FINAL_OUTPUT" ]] || backup_die "Backup output already exists: ${FINAL_OUTPUT}"

backup_log "Starting quiesced backup run ${RUN_ID}"
postgres_with_service "$DATABASE_SERVICE_FILE" "$DATABASE_SERVICE" \
  psql -X --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
  --command 'SELECT 1;' >/dev/null
require_matching_postgres_major pg_dump "$DATABASE_SERVICE_FILE" "$DATABASE_SERVICE"
configure_mc_alias "$MC_CONFIG_DIR" source "$MINIO_URL" "$MINIO_ACCESS_KEY" "$MINIO_SECRET_KEY"
mc_with_config "$MC_CONFIG_DIR" stat "source/$MINIO_BUCKET" >/dev/null
write_table_counts "$DATABASE_SERVICE_FILE" "$DATABASE_SERVICE" "$STAGING_DIR/source-table-counts-before.tsv"
write_object_references "$DATABASE_SERVICE_FILE" "$DATABASE_SERVICE" "$STAGING_DIR/source-object-references-before.tsv"

backup_log 'Creating consistent PostgreSQL custom-format dump'
postgres_with_service "$DATABASE_SERVICE_FILE" "$DATABASE_SERVICE" \
  pg_dump --format=custom --compress=6 --no-owner --no-privileges \
  --serializable-deferrable --file="$PAYLOAD_DIR/database.dump"
pg_dump_version="$(pg_dump --version)"
pg_dump_version="${pg_dump_version%%$'\n'*}"

backup_log 'Copying encrypted MinIO object bytes'
write_mc_object_listing "$MC_CONFIG_DIR" "source/$MINIO_BUCKET" "$STAGING_DIR/source-object-listing.tsv"
mc_with_config "$MC_CONFIG_DIR" mirror "source/$MINIO_BUCKET" "$OBJECT_DIR" >/dev/null
write_mc_object_listing "$MC_CONFIG_DIR" "source/$MINIO_BUCKET" "$STAGING_DIR/source-object-listing-after.tsv"
cmp --silent "$STAGING_DIR/source-object-listing.tsv" "$STAGING_DIR/source-object-listing-after.tsv" \
  || backup_die 'Source bucket changed during the quiesced backup window'
validate_object_tree "$OBJECT_DIR"
write_object_inventory "$OBJECT_DIR" "$PAYLOAD_DIR/object-inventory.tsv"
cut -f 1,2 "$PAYLOAD_DIR/object-inventory.tsv" > "$STAGING_DIR/local-object-listing.tsv"
cmp --silent "$STAGING_DIR/source-object-listing.tsv" "$STAGING_DIR/local-object-listing.tsv" \
  || backup_die 'Mirrored object keys or sizes differ from the source bucket listing'

backup_log 'Capturing database counts and object references'
write_table_counts "$DATABASE_SERVICE_FILE" "$DATABASE_SERVICE" "$PAYLOAD_DIR/table-counts.tsv"
write_object_references "$DATABASE_SERVICE_FILE" "$DATABASE_SERVICE" "$PAYLOAD_DIR/object-references.tsv"
cmp --silent "$STAGING_DIR/source-table-counts-before.tsv" "$PAYLOAD_DIR/table-counts.tsv" \
  || backup_die 'Database row counts changed during the quiesced backup window'
cmp --silent "$STAGING_DIR/source-object-references-before.tsv" "$PAYLOAD_DIR/object-references.tsv" \
  || backup_die 'Database object references changed during the quiesced backup window'
verify_object_references "$PAYLOAD_DIR/object-references.tsv" "$OBJECT_DIR"
write_payload_checksums "$PAYLOAD_DIR"

object_count="$(wc -l < "$PAYLOAD_DIR/object-inventory.tsv")"
object_bytes="$(awk -F '\t' '{ total += $2 } END { print total + 0 }' "$PAYLOAD_DIR/object-inventory.tsv")"
table_count="$(wc -l < "$PAYLOAD_DIR/table-counts.tsv")"
database_sha256="$(sha256sum -- "$PAYLOAD_DIR/database.dump")"
database_sha256="${database_sha256%% *}"
inventory_sha256="$(sha256sum -- "$PAYLOAD_DIR/object-inventory.tsv")"
inventory_sha256="${inventory_sha256%% *}"
created_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
mc_version="$(mc --version 2>&1)"
mc_version="${mc_version%%$'\n'*}"

jq -n \
  --argjson formatVersion 1 \
  --arg runId "$RUN_ID" \
  --arg createdAt "$created_at" \
  --arg reason "$BACKUP_REASON" \
  --arg sourceBucket "$MINIO_BUCKET" \
  --arg databaseSha256 "$database_sha256" \
  --arg inventorySha256 "$inventory_sha256" \
  --arg pgDumpVersion "$pg_dump_version" \
  --arg mcVersion "$mc_version" \
  --argjson tableCount "$table_count" \
  --argjson objectCount "$object_count" \
  --argjson objectBytes "$object_bytes" \
  '{
    formatVersion: $formatVersion,
    runId: $runId,
    createdAt: $createdAt,
    reason: $reason,
    source: { minioBucket: $sourceBucket },
    database: {
      format: "postgresql-custom",
      sha256: $databaseSha256,
      tableCount: $tableCount,
      pgDumpVersion: $pgDumpVersion
    },
    objects: {
      representation: "latest-object-bytes",
      count: $objectCount,
      bytes: $objectBytes,
      inventorySha256: $inventorySha256,
      mcVersion: $mcVersion
    }
  }' > "$PAYLOAD_DIR/manifest.json"

ARCHIVE_FILE="$STAGING_DIR/alparts-backup-${RUN_ID}.tar"
tar --create --format=pax --numeric-owner --owner=0 --group=0 \
  --file="$ARCHIVE_FILE" --directory="$PAYLOAD_DIR" \
  manifest.json checksums.sha256 table-counts.tsv object-references.tsv \
  object-inventory.tsv database.dump objects

backup_log 'Encrypting the complete backup payload for the configured age recipient'
CIPHER_TEMP="$(mktemp "$BACKUP_OUTPUT_DIR/.alparts-backup-${RUN_ID}.XXXXXXXX")"
chmod 600 -- "$CIPHER_TEMP"
age --encrypt --recipient "$BACKUP_AGE_RECIPIENT" < "$ARCHIVE_FILE" > "$CIPHER_TEMP"
sync -- "$CIPHER_TEMP"

# A hard link is an atomic no-clobber publication on the same filesystem.
ln -- "$CIPHER_TEMP" "$FINAL_OUTPUT" \
  || backup_die "Could not publish backup without overwriting an existing file: ${FINAL_OUTPUT}"
rm -f -- "$CIPHER_TEMP"
CIPHER_TEMP=''
chmod 600 -- "$FINAL_OUTPUT"
sync -- "$FINAL_OUTPUT"

backup_log "Backup completed: ${object_count} object(s), ${object_bytes} byte(s), ${table_count} table(s)"
printf '%s\n' "$FINAL_OUTPUT"
