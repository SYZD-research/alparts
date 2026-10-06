#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/backup-common.sh
source "$SCRIPT_DIR/lib/backup-common.sh"

show_help() {
  cat <<'HELP'
Decrypt and restore an Alparts Phase 1 backup into an empty, disposable
verification database and an empty, disposable verification bucket on an
S3-compatible object store (for example SeaweedFS).
The restored row counts, database/object references, object count, and every
object checksum are then compared with the encrypted backup manifest.

Usage:
  scripts/restore-verify.sh /path/to/alparts-backup-<run-id>.tar.age

Required settings (a *_FILE alternative is accepted for values marked secret):
  VERIFY_DATABASE_SERVICE_FILE Private libpq service file for the empty target
  VERIFY_DATABASE_SERVICE      Service section name in that file
  VERIFY_S3_URL                Verification URL (HTTPS, or HTTP on loopback only)
  VERIFY_S3_ACCESS_KEY         Verification access key (secret)
  VERIFY_S3_SECRET_KEY         Verification secret key (secret)
  VERIFY_S3_BUCKET             Existing, empty verification bucket
  RESTORE_AGE_IDENTITY_FILE    Readable age identity file
  ALPARTS_RESTORE_ACK          Must be exactly RESTORE_TO_EMPTY_DISPOSABLE_TARGETS

Optional:
  VERIFY_S3_REGION             Signing region (default us-east-1)

Optional resource limits (positive integers):
  RESTORE_MAX_BYTES            Encrypted and decrypted archive bytes (default 1 TiB)
  RESTORE_MAX_ARCHIVE_ENTRIES  Logical archive entries (default 1000000)
  RESTORE_MAX_FILE_BYTES       Bytes in one expanded regular file (default 1 TiB)
  RESTORE_MAX_EXPANDED_BYTES   Aggregate expanded regular-file bytes (default 1 TiB)

The database name must match alparts_restore_<suffix> or alparts_verify_<suffix>.
The bucket must match alparts-restore-<suffix> or alparts-verify-<suffix>.
The installed pg_restore major must match the verification PostgreSQL server.
Names containing prod, production, live, or primary are refused. The source and
target bucket names must differ. No --clean, DROP, delete, or migration is run.
Partial failed restores are left in place for inspection.
The target database role must be unprivileged (not superuser, role/database
creator, replication, BYPASSRLS, or a server-file/program role).

This verifies one backup; it is not PITR, WORM retention, off-site replication,
or automated disaster recovery. Run it with exclusive access to both disposable
targets so another writer cannot invalidate the empty-target guarantee.
HELP
}

if [[ "${1-}" == '--help' || "${1-}" == '-h' ]]; then
  show_help
  exit 0
fi
[[ $# -eq 1 ]] || backup_die 'Usage: restore-verify.sh <encrypted-backup.tar.age>'
BACKUP_FILE="$1"
[[ -f "$BACKUP_FILE" && -r "$BACKUP_FILE" ]] || backup_die 'Backup file must be a readable regular file'

for dependency in age awk chmod cmp cut find grep jq mkdir mktemp pg_restore psql rclone rm sed sha256sum sort stat tar uniq wc; do
  require_command "$dependency"
done
require_storage_tool

reject_legacy_storage_settings
[[ "${ALPARTS_RESTORE_ACK-}" == 'RESTORE_TO_EMPTY_DISPOSABLE_TARGETS' ]] \
  || backup_die 'Set ALPARTS_RESTORE_ACK=RESTORE_TO_EMPTY_DISPOSABLE_TARGETS after reviewing the targets'

[[ -n "${VERIFY_DATABASE_SERVICE_FILE-}" ]] \
  || backup_die 'Missing required setting: VERIFY_DATABASE_SERVICE_FILE'
[[ -n "${VERIFY_DATABASE_SERVICE-}" ]] \
  || backup_die 'Missing required setting: VERIFY_DATABASE_SERVICE'
export -n VERIFY_DATABASE_SERVICE 2>/dev/null || true
load_required_value VERIFY_S3_URL
load_required_value VERIFY_S3_ACCESS_KEY
load_required_value VERIFY_S3_SECRET_KEY
load_required_value VERIFY_S3_BUCKET
VERIFY_S3_REGION="${VERIFY_S3_REGION:-us-east-1}"
export -n VERIFY_S3_REGION 2>/dev/null || true
[[ -n "${RESTORE_AGE_IDENTITY_FILE-}" ]] \
  || backup_die 'Missing required setting: RESTORE_AGE_IDENTITY_FILE'

validate_s3_url "$VERIFY_S3_URL"
validate_postgres_service "$VERIFY_DATABASE_SERVICE_FILE" "$VERIFY_DATABASE_SERVICE"
export -n VERIFY_DATABASE_SERVICE_FILE 2>/dev/null || true
validate_restore_bucket_name "$VERIFY_S3_BUCKET"
[[ -f "$RESTORE_AGE_IDENTITY_FILE" && -r "$RESTORE_AGE_IDENTITY_FILE" ]] \
  || backup_die 'RESTORE_AGE_IDENTITY_FILE must be a readable regular file'
validate_private_file "$RESTORE_AGE_IDENTITY_FILE" RESTORE_AGE_IDENTITY_FILE

RESTORE_MAX_BYTES="${RESTORE_MAX_BYTES:-1099511627776}"
[[ "$RESTORE_MAX_BYTES" =~ ^[1-9][0-9]{0,17}$ ]] \
  || backup_die 'RESTORE_MAX_BYTES must be a positive integer of at most 18 digits'
RESTORE_MAX_ARCHIVE_ENTRIES="${RESTORE_MAX_ARCHIVE_ENTRIES:-1000000}"
RESTORE_MAX_FILE_BYTES="${RESTORE_MAX_FILE_BYTES:-1099511627776}"
RESTORE_MAX_EXPANDED_BYTES="${RESTORE_MAX_EXPANDED_BYTES:-1099511627776}"
[[ "$RESTORE_MAX_ARCHIVE_ENTRIES" =~ ^[1-9][0-9]{0,17}$ ]] \
  || backup_die 'RESTORE_MAX_ARCHIVE_ENTRIES must be a positive integer of at most 18 digits'
[[ "$RESTORE_MAX_FILE_BYTES" =~ ^[1-9][0-9]{0,17}$ ]] \
  || backup_die 'RESTORE_MAX_FILE_BYTES must be a positive integer of at most 18 digits'
[[ "$RESTORE_MAX_EXPANDED_BYTES" =~ ^[1-9][0-9]{0,17}$ ]] \
  || backup_die 'RESTORE_MAX_EXPANDED_BYTES must be a positive integer of at most 18 digits'
(( RESTORE_MAX_FILE_BYTES <= RESTORE_MAX_EXPANDED_BYTES )) \
  || backup_die 'RESTORE_MAX_FILE_BYTES must not exceed RESTORE_MAX_EXPANDED_BYTES'

(( $(stat -c '%s' -- "$BACKUP_FILE") <= RESTORE_MAX_BYTES )) \
  || backup_die 'Encrypted backup exceeds RESTORE_MAX_BYTES'

STAGING_DIR=''
cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  if [[ -n "$STAGING_DIR" && -d "$STAGING_DIR" ]]; then
    rm -rf -- "$STAGING_DIR"
  fi
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

STAGING_DIR="$(mktemp -d "${TMPDIR:-/tmp}/alparts-restore-verify.XXXXXXXX")"
chmod 700 -- "$STAGING_DIR"
ARCHIVE_FILE="$STAGING_DIR/backup.tar"
PAYLOAD_DIR="$STAGING_DIR/payload"
STORAGE_CONFIG="$STAGING_DIR/rclone.conf"
mkdir -p -- "$PAYLOAD_DIR"

backup_log 'Decrypting backup into protected temporary storage'
# Stop writing one byte past the limit instead of materializing an unbounded
# plaintext first; the size check below then distinguishes the two failures.
decrypt_status=0
age --decrypt --identity "$RESTORE_AGE_IDENTITY_FILE" < "$BACKUP_FILE" \
  | head -c "$((RESTORE_MAX_BYTES + 1))" > "$ARCHIVE_FILE" || decrypt_status=$?
(( $(stat -c '%s' -- "$ARCHIVE_FILE") <= RESTORE_MAX_BYTES )) \
  || backup_die 'Decrypted backup exceeds RESTORE_MAX_BYTES'
(( decrypt_status == 0 )) || backup_die 'Backup decryption failed'

ARCHIVE_LIST="$STAGING_DIR/archive-list.txt"
ARCHIVE_VERBOSE="$STAGING_DIR/archive-list-verbose.txt"
validate_restore_archive "$ARCHIVE_FILE" "$ARCHIVE_LIST" "$ARCHIVE_VERBOSE" \
  "$RESTORE_MAX_ARCHIVE_ENTRIES" "$RESTORE_MAX_FILE_BYTES" "$RESTORE_MAX_EXPANDED_BYTES"
[[ "$(LC_ALL=C sort "$ARCHIVE_LIST" | uniq -d | wc -l)" -eq 0 ]] \
  || backup_die 'Backup archive contains duplicate paths'
while IFS= read -r archive_path; do
  case "$archive_path" in
    manifest.json|checksums.sha256|table-counts.tsv|object-references.tsv|object-inventory.tsv|database.dump|objects|objects/)
      ;;
    objects/*)
      [[ "$archive_path" =~ ^objects/[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] \
        || backup_die 'Backup archive contains an unsafe object path'
      [[ "/$archive_path/" != */../* && "/$archive_path/" != */./* && "$archive_path" != *//* ]] \
        || backup_die 'Backup archive contains an unsafe path component'
      ;;
    *)
      backup_die 'Backup archive contains an unexpected path'
      ;;
  esac
done < "$ARCHIVE_LIST"

tar --extract --file="$ARCHIVE_FILE" --directory="$PAYLOAD_DIR" \
  --no-same-owner --no-same-permissions
for required_file in manifest.json checksums.sha256 table-counts.tsv object-references.tsv object-inventory.tsv database.dump; do
  [[ -f "$PAYLOAD_DIR/$required_file" ]] || backup_die "Backup is missing ${required_file}"
done
[[ -d "$PAYLOAD_DIR/objects" ]] || backup_die 'Backup is missing the objects directory'
validate_object_tree "$PAYLOAD_DIR/objects"
validate_table_counts_file "$PAYLOAD_DIR/table-counts.tsv"
validate_object_references_file "$PAYLOAD_DIR/object-references.tsv"

jq -e '
  .formatVersion == 1 and
  (.runId | type == "string" and test("^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$")) and
  ((.source.bucket // .source.minioBucket) | type == "string") and
  (.database.format == "postgresql-custom") and
  (.database.sha256 | test("^[a-f0-9]{64}$")) and
  (.database.tableCount | type == "number" and . >= 0 and floor == .) and
  (.objects.representation == "latest-object-bytes") and
  (.objects.count | type == "number" and . >= 0 and floor == .) and
  (.objects.bytes | type == "number" and . >= 0 and floor == .) and
  (.objects.inventorySha256 | test("^[a-f0-9]{64}$"))
' "$PAYLOAD_DIR/manifest.json" >/dev/null || backup_die 'Backup manifest is malformed or unsupported'

# Backups made before the move to S3_* names record the bucket as minioBucket.
source_bucket="$(jq -r '.source.bucket // .source.minioBucket' "$PAYLOAD_DIR/manifest.json")"
validate_bucket_name "$source_bucket"
[[ "$VERIFY_S3_BUCKET" != "$source_bucket" ]] \
  || backup_die 'Verification bucket must not have the source bucket name'

checksum_entries="$(validate_checksum_file "$PAYLOAD_DIR")"
write_object_inventory "$PAYLOAD_DIR/objects" "$STAGING_DIR/rebuilt-object-inventory.tsv"
cmp --silent "$PAYLOAD_DIR/object-inventory.tsv" "$STAGING_DIR/rebuilt-object-inventory.tsv" \
  || backup_die 'Object inventory does not match the decrypted object bytes'
expected_object_count="$(jq -r '.objects.count' "$PAYLOAD_DIR/manifest.json")"
expected_object_bytes="$(jq -r '.objects.bytes' "$PAYLOAD_DIR/manifest.json")"
actual_object_count="$(wc -l < "$PAYLOAD_DIR/object-inventory.tsv")"
actual_object_bytes="$(awk -F '\t' '{ total += $2 } END { print total + 0 }' "$PAYLOAD_DIR/object-inventory.tsv")"
expected_table_count="$(jq -r '.database.tableCount' "$PAYLOAD_DIR/manifest.json")"
actual_table_count="$(wc -l < "$PAYLOAD_DIR/table-counts.tsv")"
[[ "$actual_object_count" == "$expected_object_count" && "$actual_object_bytes" == "$expected_object_bytes" ]] \
  || backup_die 'Object inventory totals do not match the manifest'
[[ "$actual_table_count" == "$expected_table_count" ]] \
  || backup_die 'Database table count does not match the manifest'
[[ "$checksum_entries" -eq $((actual_object_count + 1)) ]] \
  || backup_die 'Checksum entry count does not match the database dump plus object inventory'
[[ "$(sha256sum -- "$PAYLOAD_DIR/database.dump" | cut -d ' ' -f 1)" == "$(jq -r '.database.sha256' "$PAYLOAD_DIR/manifest.json")" ]] \
  || backup_die 'Database dump checksum does not match the manifest'
[[ "$(sha256sum -- "$PAYLOAD_DIR/object-inventory.tsv" | cut -d ' ' -f 1)" == "$(jq -r '.objects.inventorySha256' "$PAYLOAD_DIR/manifest.json")" ]] \
  || backup_die 'Object inventory checksum does not match the manifest'
verify_object_references "$PAYLOAD_DIR/object-references.tsv" "$PAYLOAD_DIR/objects"
pg_restore --list "$PAYLOAD_DIR/database.dump" >/dev/null

backup_log 'Validating empty, disposable restore targets'
postgres_with_service "$VERIFY_DATABASE_SERVICE_FILE" "$VERIFY_DATABASE_SERVICE" \
  psql -X --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
  --command 'SELECT 1;' >/dev/null
database_name="$(psql_scalar "$VERIFY_DATABASE_SERVICE_FILE" "$VERIFY_DATABASE_SERVICE" 'SELECT current_database();')"
validate_restore_database_name "$database_name"
require_matching_postgres_major pg_restore "$VERIFY_DATABASE_SERVICE_FILE" "$VERIFY_DATABASE_SERVICE"
[[ "$(psql_scalar "$VERIFY_DATABASE_SERVICE_FILE" "$VERIFY_DATABASE_SERVICE" "SELECT current_setting('transaction_read_only');")" == 'off' ]] \
  || backup_die 'Verification database is read-only'
privileged_restore_role="$(psql_scalar "$VERIFY_DATABASE_SERVICE_FILE" "$VERIFY_DATABASE_SERVICE" "
SELECT EXISTS (
  SELECT 1
  FROM pg_catalog.pg_roles AS role
  WHERE (
    role.rolsuper OR role.rolcreaterole OR role.rolcreatedb OR
    role.rolreplication OR role.rolbypassrls OR
    role.rolname IN ('pg_read_server_files', 'pg_write_server_files', 'pg_execute_server_program')
  )
  AND pg_catalog.pg_has_role(current_user, role.oid, 'MEMBER')
);")"
[[ "$privileged_restore_role" == 'f' ]] \
  || backup_die 'Verification database role has dangerous server-wide privileges'
existing_user_objects="$(psql_scalar "$VERIFY_DATABASE_SERVICE_FILE" "$VERIFY_DATABASE_SERVICE" "
WITH user_namespaces AS (
  SELECT oid
  FROM pg_catalog.pg_namespace
  WHERE nspname = 'public'
     OR (nspname NOT IN ('pg_catalog', 'information_schema') AND nspname !~ '^pg_')
)
SELECT
  (SELECT count(*) FROM pg_catalog.pg_namespace WHERE nspname <> 'public' AND nspname NOT IN ('pg_catalog', 'information_schema') AND nspname !~ '^pg_') +
  (SELECT count(*) FROM pg_catalog.pg_class WHERE relnamespace IN (SELECT oid FROM user_namespaces)) +
  (SELECT count(*) FROM pg_catalog.pg_proc WHERE pronamespace IN (SELECT oid FROM user_namespaces)) +
  (SELECT count(*) FROM pg_catalog.pg_type WHERE typnamespace IN (SELECT oid FROM user_namespaces) AND typisdefined) +
  (SELECT count(*) FROM pg_catalog.pg_operator WHERE oprnamespace IN (SELECT oid FROM user_namespaces)) +
  (SELECT count(*) FROM pg_catalog.pg_collation WHERE collnamespace IN (SELECT oid FROM user_namespaces)) +
  (SELECT count(*) FROM pg_catalog.pg_conversion WHERE connamespace IN (SELECT oid FROM user_namespaces)) +
  (SELECT count(*) FROM pg_catalog.pg_extension WHERE extname <> 'plpgsql') +
  (SELECT count(*) FROM pg_catalog.pg_foreign_data_wrapper) +
  (SELECT count(*) FROM pg_catalog.pg_foreign_server);")"
[[ "$existing_user_objects" == '0' ]] \
  || backup_die 'Verification database contains user schemas or objects; no restore was attempted'

configure_s3_remote "$STORAGE_CONFIG" verify "$VERIFY_S3_URL" "$VERIFY_S3_ACCESS_KEY" "$VERIFY_S3_SECRET_KEY" "$VERIFY_S3_REGION"
rclone_with_config "$STORAGE_CONFIG" lsjson --stat "verify:$VERIFY_S3_BUCKET" >/dev/null \
  || backup_die 'Verification bucket is not reachable; verify the URL, credentials and bucket'
TARGET_LISTING="$STAGING_DIR/target-before.tsv"
write_object_listing "$STORAGE_CONFIG" "verify:$VERIFY_S3_BUCKET" "$TARGET_LISTING"
[[ ! -s "$TARGET_LISTING" ]] \
  || backup_die 'Verification bucket is not empty; no restore was attempted'

backup_log "Restoring database into disposable target ${database_name}"
postgres_with_service "$VERIFY_DATABASE_SERVICE_FILE" "$VERIFY_DATABASE_SERVICE" \
  pg_restore --exit-on-error --single-transaction \
  --no-owner --no-privileges --dbname='' "$PAYLOAD_DIR/database.dump"

RESTORED_COUNTS="$STAGING_DIR/restored-table-counts.tsv"
write_table_counts "$VERIFY_DATABASE_SERVICE_FILE" "$VERIFY_DATABASE_SERVICE" "$RESTORED_COUNTS"
cmp --silent "$PAYLOAD_DIR/table-counts.tsv" "$RESTORED_COUNTS" \
  || backup_die 'Restored database table counts differ from the source snapshot'
RESTORED_REFERENCES="$STAGING_DIR/restored-object-references.tsv"
write_object_references "$VERIFY_DATABASE_SERVICE_FILE" "$VERIFY_DATABASE_SERVICE" "$RESTORED_REFERENCES"
cmp --silent "$PAYLOAD_DIR/object-references.tsv" "$RESTORED_REFERENCES" \
  || backup_die 'Restored database object references differ from the source snapshot'

# Recheck immediately before upload. Exclusive access to this validation-only
# bucket is an explicit operator precondition; the script never deletes objects.
write_object_listing "$STORAGE_CONFIG" "verify:$VERIFY_S3_BUCKET" "$TARGET_LISTING"
[[ ! -s "$TARGET_LISTING" ]] \
  || backup_die 'Verification bucket changed during restore; object restore was refused'

backup_log "Restoring ${actual_object_count} encrypted object(s) into the disposable bucket"
if (( actual_object_count > 0 )); then
  rclone_with_config "$STORAGE_CONFIG" copy "$PAYLOAD_DIR/objects" "verify:$VERIFY_S3_BUCKET" >/dev/null
fi
write_object_listing "$STORAGE_CONFIG" "verify:$VERIFY_S3_BUCKET" "$STAGING_DIR/target-after.tsv"
cut -f 1,2 "$PAYLOAD_DIR/object-inventory.tsv" > "$STAGING_DIR/expected-target-listing.tsv"
cmp --silent "$STAGING_DIR/expected-target-listing.tsv" "$STAGING_DIR/target-after.tsv" \
  || backup_die 'Restored object keys or sizes differ from the backup inventory'

VERIFICATION_OBJECTS="$STAGING_DIR/downloaded-objects"
mkdir -p -- "$VERIFICATION_OBJECTS"
if (( actual_object_count > 0 )); then
  rclone_with_config "$STORAGE_CONFIG" copy "verify:$VERIFY_S3_BUCKET" "$VERIFICATION_OBJECTS" >/dev/null
fi
validate_object_tree "$VERIFICATION_OBJECTS"
write_object_inventory "$VERIFICATION_OBJECTS" "$STAGING_DIR/restored-object-inventory.tsv"
cmp --silent "$PAYLOAD_DIR/object-inventory.tsv" "$STAGING_DIR/restored-object-inventory.tsv" \
  || backup_die 'Restored object keys, sizes, or checksums differ from the backup'
verify_object_references "$RESTORED_REFERENCES" "$VERIFICATION_OBJECTS"

run_id="$(jq -r '.runId' "$PAYLOAD_DIR/manifest.json")"
table_count="$(wc -l < "$RESTORED_COUNTS")"
backup_log "Restore verification succeeded for run ${run_id}: ${table_count} table(s), ${actual_object_count} object(s), ${actual_object_bytes} byte(s)"
printf 'VERIFIED %s\n' "$run_id"
