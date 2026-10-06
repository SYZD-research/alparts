#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)"
# shellcheck source=../lib/backup-common.sh
source "$REPOSITORY_ROOT/scripts/lib/backup-common.sh"

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

assert_file_excludes() {
  local file_path="$1"
  local sentinel="$2"
  if grep -F -- "$sentinel" "$file_path" >/dev/null; then
    fail "$(basename -- "$file_path") contains a credential sentinel"
  fi
}

expect_failure() {
  local expected_message="$1"
  local error_file="$2"
  shift 2
  if ( "$@" ) 2> "$error_file"; then
    fail "expected failure containing: ${expected_message}"
  fi
  grep -F -- "$expected_message" "$error_file" >/dev/null \
    || fail "failure did not contain: ${expected_message}"
}

TEST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/alparts-backup-security-test.XXXXXXXX")"
cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  if [[ -n "${TEST_TMP-}" && -d "$TEST_TMP" ]]; then
    rm -rf -- "$TEST_TMP"
  fi
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

validate_backup_recipient age1pq1qqqqqqqq
expect_failure 'Backups require a hybrid' "$TEST_TMP/classical-recipient.err" validate_backup_recipient age1qqqqqqqq
expect_failure 'Backups require a hybrid' "$TEST_TMP/mixed-recipient.err" validate_backup_recipient $'age1pq1qqqq\nage1qqqq'

REAL_JQ="$(command -v jq)"
[[ -n "$REAL_JQ" ]] || fail 'jq is required'
FAKE_BIN="$TEST_TMP/fake-bin"
CAPTURE_DIR="$TEST_TMP/capture"
mkdir -p -- "$FAKE_BIN" "$CAPTURE_DIR"
for command_name in jq rclone psql pg_dump pg_restore; do
  ln -s -- "$SCRIPT_DIR/fixtures/capture-command.sh" "$FAKE_BIN/$command_name"
done
export BACKUP_TEST_CAPTURE_DIR="$CAPTURE_DIR"
export BACKUP_TEST_REAL_JQ="$REAL_JQ"
PATH="$FAKE_BIN:$PATH"
export PATH

# Only rclone versions with bounded listings are used.
RCLONE_VERSION_OUTPUT="$TEST_TMP/rclone-version.txt"
export BACKUP_TEST_RCLONE_STDOUT="$RCLONE_VERSION_OUTPUT"
for accepted in 'rclone v1.75.1' 'rclone v1.76.0-beta.9001.abc' 'rclone v2.0.0'; do
  printf '%s\n- os/version: test\n' "$accepted" > "$RCLONE_VERSION_OUTPUT"
  ( require_storage_tool ) || fail "rclone version was refused: ${accepted}"
done
printf 'rclone v1.75.0\n' > "$RCLONE_VERSION_OUTPUT"
expect_failure 'rclone 1.75.1 or newer is required' "$TEST_TMP/old-rclone.err" require_storage_tool
printf 'not rclone\n' > "$RCLONE_VERSION_OUTPUT"
expect_failure 'Unrecognized rclone version' "$TEST_TMP/odd-rclone.err" require_storage_tool
unset BACKUP_TEST_RCLONE_STDOUT

PG_SENTINEL='PG_SERVICE_SENTINEL_7f91'
PG_SERVICE_FILE="$TEST_TMP/pg_service.conf"
printf '[backup-test]\nhost=db.invalid\ndbname=alparts\nuser=backup-user\npassword=%s\n' \
  "$PG_SENTINEL" > "$PG_SERVICE_FILE"
chmod 600 -- "$PG_SERVICE_FILE"
validate_postgres_service "$PG_SERVICE_FILE" backup-test
export DATABASE_URL="postgresql://ambient:${PG_SENTINEL}@db.invalid/alparts"
export PGPASSWORD="$PG_SENTINEL"
postgres_with_service "$PG_SERVICE_FILE" backup-test psql --command 'SELECT 1;'
postgres_with_service "$PG_SERVICE_FILE" backup-test pg_dump --format=custom --file=database.dump
postgres_with_service "$PG_SERVICE_FILE" backup-test pg_restore --dbname='' database.dump
for command_name in psql pg_dump pg_restore; do
  assert_file_excludes "$CAPTURE_DIR/${command_name}.argv" "$PG_SENTINEL"
  assert_file_excludes "$CAPTURE_DIR/${command_name}.env" "$PG_SENTINEL"
  grep -Fx -- "PGSERVICEFILE=$PG_SERVICE_FILE" "$CAPTURE_DIR/${command_name}.env" >/dev/null \
    || fail "${command_name} did not inherit PGSERVICEFILE"
  grep -Fx -- 'PGSERVICE=backup-test' "$CAPTURE_DIR/${command_name}.env" >/dev/null \
    || fail "${command_name} did not inherit PGSERVICE"
done
unset DATABASE_URL PGPASSWORD

S3_ACCESS_SENTINEL='S3_ACCESS_ARG_SENTINEL_31c2'
S3_SECRET_SENTINEL='S3_SECRET_ARG_SENTINEL_a804'
export S3_ACCESS_KEY="$S3_ACCESS_SENTINEL"
export S3_SECRET_KEY="$S3_SECRET_SENTINEL"
# Ambient storage-client settings must not redirect or authenticate the copy.
export RCLONE_CONFIG_SOURCE_ENDPOINT='https://redirect.invalid'
export AWS_ACCESS_KEY_ID='AMBIENT_AWS_SENTINEL'
STORAGE_CONFIG="$TEST_TMP/staging/rclone.conf"
mkdir -p -- "$TEST_TMP/staging"
configure_s3_remote "$STORAGE_CONFIG" source 'https://objects.invalid' \
  "$S3_ACCESS_SENTINEL" "$S3_SECRET_SENTINEL" us-east-1
rclone_with_config "$STORAGE_CONFIG" lsjson --stat source:alparts
assert_file_excludes "$CAPTURE_DIR/rclone.argv" "$S3_ACCESS_SENTINEL"
assert_file_excludes "$CAPTURE_DIR/rclone.argv" "$S3_SECRET_SENTINEL"
assert_file_excludes "$CAPTURE_DIR/rclone.env" "$S3_ACCESS_SENTINEL"
assert_file_excludes "$CAPTURE_DIR/rclone.env" "$S3_SECRET_SENTINEL"
assert_file_excludes "$CAPTURE_DIR/rclone.env" 'redirect.invalid'
assert_file_excludes "$CAPTURE_DIR/rclone.env" 'AMBIENT_AWS_SENTINEL'
unset S3_ACCESS_KEY S3_SECRET_KEY RCLONE_CONFIG_SOURCE_ENDPOINT AWS_ACCESS_KEY_ID
[[ "$(stat -c '%a' -- "$STORAGE_CONFIG")" == '600' ]] \
  || fail 'object storage configuration is not mode 0600'
grep -Fx -- "access_key_id = ${S3_ACCESS_SENTINEL}" "$STORAGE_CONFIG" >/dev/null \
  && grep -Fx -- "secret_access_key = ${S3_SECRET_SENTINEL}" "$STORAGE_CONFIG" >/dev/null \
  && grep -Fx -- 'endpoint = https://objects.invalid' "$STORAGE_CONFIG" >/dev/null \
  && grep -Fx -- 'env_auth = false' "$STORAGE_CONFIG" >/dev/null \
  || fail 'object storage configuration is malformed'
expect_failure 'single-line values' "$TEST_TMP/credential-newline.err" \
  configure_s3_remote "$TEST_TMP/staging/injected.conf" source 'https://objects.invalid' \
  $'key\n[other]' secret us-east-1
[[ ! -e "$TEST_TMP/staging/injected.conf" ]] \
  || fail 'a credential containing a line break reached the configuration file'
expect_failure 'now named S3_' "$TEST_TMP/legacy-settings.err" \
  bash -c 'export MINIO_URL=https://objects.invalid; source "$1"; reject_legacy_storage_settings' _ \
  "$REPOSITORY_ROOT/scripts/lib/backup-common.sh"

# Listings: prefixes implied by objects are fine; a folder entry with nothing
# beneath it (a folder-marker object) is refused, including in an otherwise
# empty restore target.
LISTING_FIXTURE="$TEST_TMP/listing.json"
export BACKUP_TEST_RCLONE_STDOUT="$LISTING_FIXTURE"
printf '%s' '[{"Path":"attachments","IsDir":true,"Size":-1},{"Path":"attachments/v1","IsDir":true,"Size":-1},{"Path":"attachments/v1/a/000000","IsDir":false,"Size":7}]' > "$LISTING_FIXTURE"
write_object_listing "$STORAGE_CONFIG" source:alparts "$TEST_TMP/listing.tsv"
[[ "$(cat -- "$TEST_TMP/listing.tsv")" == $'attachments/v1/a/000000\t7' ]] \
  || fail 'object listing did not keep exactly the stored object'
printf '%s' '[]' > "$LISTING_FIXTURE"
write_object_listing "$STORAGE_CONFIG" verify:alparts-verify-x "$TEST_TMP/empty.tsv"
[[ ! -s "$TEST_TMP/empty.tsv" ]] || fail 'an empty bucket was listed as non-empty'
printf '%s' '[{"Path":"marker","IsDir":true,"Size":-1}]' > "$LISTING_FIXTURE"
expect_failure 'folder entry' "$TEST_TMP/marker-only.err" \
  write_object_listing "$STORAGE_CONFIG" verify:alparts-verify-x "$TEST_TMP/marker-only.tsv"
printf '%s' '[{"Path":"attachments","IsDir":true,"Size":-1},{"Path":"attachments/empty","IsDir":true,"Size":-1},{"Path":"attachments/v1/a/000000","IsDir":false,"Size":7}]' > "$LISTING_FIXTURE"
expect_failure 'folder entry' "$TEST_TMP/marker-beside.err" \
  write_object_listing "$STORAGE_CONFIG" source:alparts "$TEST_TMP/marker-beside.tsv"
printf '%s' '[{"Path":"attachments/v1/a//000000","IsDir":false,"Size":7}]' > "$LISTING_FIXTURE"
expect_failure 'unsafe object key' "$TEST_TMP/double-slash.err" \
  write_object_listing "$STORAGE_CONFIG" source:alparts "$TEST_TMP/double-slash.tsv"
unset BACKUP_TEST_RCLONE_STDOUT

ORDINARY_SOURCE="$TEST_TMP/ordinary-source"
ORDINARY_EXTRACT="$TEST_TMP/ordinary-extract"
mkdir -p -- "$ORDINARY_SOURCE/objects" "$ORDINARY_EXTRACT"
printf '{"formatVersion":1}\n' > "$ORDINARY_SOURCE/manifest.json"
printf 'ciphertext-control\n' > "$ORDINARY_SOURCE/objects/control.bin"
ORDINARY_ARCHIVE="$TEST_TMP/ordinary.tar"
tar --create --format=pax --file="$ORDINARY_ARCHIVE" --directory="$ORDINARY_SOURCE" \
  manifest.json objects
validate_restore_archive "$ORDINARY_ARCHIVE" "$TEST_TMP/ordinary.list" \
  "$TEST_TMP/ordinary.verbose" 10 1024 4096
tar --extract --file="$ORDINARY_ARCHIVE" --directory="$ORDINARY_EXTRACT"
cmp --silent "$ORDINARY_SOURCE/manifest.json" "$ORDINARY_EXTRACT/manifest.json" \
  || fail 'ordinary archive control did not round-trip'
cmp --silent "$ORDINARY_SOURCE/objects/control.bin" "$ORDINARY_EXTRACT/objects/control.bin" \
  || fail 'ordinary object control did not round-trip'

expect_failure 'RESTORE_MAX_ARCHIVE_ENTRIES' "$TEST_TMP/entries.err" \
  validate_restore_archive "$ORDINARY_ARCHIVE" "$TEST_TMP/entries.list" \
  "$TEST_TMP/entries.verbose" 1 1024 4096
expect_failure 'RESTORE_MAX_FILE_BYTES' "$TEST_TMP/file-size.err" \
  validate_restore_archive "$ORDINARY_ARCHIVE" "$TEST_TMP/file-size.list" \
  "$TEST_TMP/file-size.verbose" 10 4 4096
expect_failure 'RESTORE_MAX_EXPANDED_BYTES' "$TEST_TMP/aggregate.err" \
  validate_restore_archive "$ORDINARY_ARCHIVE" "$TEST_TMP/aggregate.list" \
  "$TEST_TMP/aggregate.verbose" 10 1024 20

SPARSE_SOURCE="$TEST_TMP/sparse-source"
mkdir -p -- "$SPARSE_SOURCE/objects"
truncate -s 2097152 "$SPARSE_SOURCE/objects/sparse-a.bin"
truncate -s 2097152 "$SPARSE_SOURCE/objects/sparse-b.bin"
printf A | dd of="$SPARSE_SOURCE/objects/sparse-a.bin" bs=1 seek=2097151 conv=notrunc status=none
printf B | dd of="$SPARSE_SOURCE/objects/sparse-b.bin" bs=1 seek=2097151 conv=notrunc status=none
SPARSE_ARCHIVE="$TEST_TMP/sparse.tar"
tar --create --format=pax --sparse --file="$SPARSE_ARCHIVE" --directory="$SPARSE_SOURCE" objects
EXTRACTION_MARKER="$TEST_TMP/sparse-extraction-started"
if (
  validate_restore_archive "$SPARSE_ARCHIVE" "$TEST_TMP/sparse-limit.list" \
    "$TEST_TMP/sparse-limit.verbose" 10 3145728 3145728
  : > "$EXTRACTION_MARKER"
  tar --extract --file="$SPARSE_ARCHIVE" --directory="$TEST_TMP"
) 2> "$TEST_TMP/sparse-limit.err"; then
  fail 'oversized sparse archive unexpectedly passed validation'
fi
[[ ! -e "$EXTRACTION_MARKER" ]] \
  || fail 'sparse archive extraction began before limit rejection'
grep -F -- 'RESTORE_MAX_EXPANDED_BYTES' "$TEST_TMP/sparse-limit.err" >/dev/null \
  || fail 'sparse expansion was not rejected by the aggregate logical-byte limit'
expect_failure 'sparse or unsupported compact file metadata' "$TEST_TMP/sparse-metadata.err" \
  validate_restore_archive "$SPARSE_ARCHIVE" "$TEST_TMP/sparse-metadata.list" \
  "$TEST_TMP/sparse-metadata.verbose" 10 8388608 8388608

RETENTION_DIR="$TEST_TMP/retention"
mkdir -p -- "$RETENTION_DIR"
for run in 20250101T000000Z-000000000001 20250102T000000Z-000000000002 20250103T000000Z-000000000003; do
  : > "$RETENTION_DIR/alparts-backup-${run}.tar.age"
done
touch -d '90 days ago' -- "$RETENTION_DIR"/*.tar.age
retention_output="$(
  BACKUP_OUTPUT_DIR="$RETENTION_DIR" \
  BACKUP_RETENTION_DAYS=30 \
  BACKUP_MINIMUM_COPIES=2 \
    "$REPOSITORY_ROOT/scripts/prune-backups.sh" --dry-run
)"
[[ "$(printf '%s\n' "$retention_output" | wc -l)" -eq 1 ]] \
  || fail 'retention dry-run did not preserve the configured minimum copies'
[[ "$(find "$RETENTION_DIR" -maxdepth 1 -type f | wc -l)" -eq 3 ]] \
  || fail 'retention dry-run removed a backup'
expect_failure 'BACKUP_PRUNE_ACK' "$TEST_TMP/prune-ack.err" \
  env BACKUP_OUTPUT_DIR="$RETENTION_DIR" BACKUP_RETENTION_DAYS=30 BACKUP_MINIMUM_COPIES=2 \
    "$REPOSITORY_ROOT/scripts/prune-backups.sh" --apply
[[ "$(find "$RETENTION_DIR" -maxdepth 1 -type f | wc -l)" -eq 3 ]] \
  || fail 'retention changed files without an explicit acknowledgement'
expect_failure 'Refusing broad backup retention target' "$TEST_TMP/prune-root.err" \
  env BACKUP_OUTPUT_DIR=/ BACKUP_RETENTION_DAYS=30 BACKUP_MINIMUM_COPIES=2 \
    "$REPOSITORY_ROOT/scripts/prune-backups.sh" --dry-run

# The systemd wrapper checks tools and settings before it stops the service.
PREFLIGHT_BIN="$TEST_TMP/preflight-bin"
PREFLIGHT_CAPTURE="$TEST_TMP/preflight-capture"
mkdir -p -- "$PREFLIGHT_BIN" "$PREFLIGHT_CAPTURE" "$TEST_TMP/preflight-output"
for command_name in age jq rclone psql pg_dump; do
  ln -s -- "$SCRIPT_DIR/fixtures/capture-command.sh" "$PREFLIGHT_BIN/$command_name"
done
run_preflight() {
  env PATH="$PREFLIGHT_BIN:$PATH" BACKUP_TEST_CAPTURE_DIR="$PREFLIGHT_CAPTURE" \
    BACKUP_TEST_RCLONE_STDOUT="$RCLONE_VERSION_OUTPUT" \
    DATABASE_SERVICE_FILE="$PG_SERVICE_FILE" DATABASE_SERVICE=backup-test \
    S3_URL=https://storage.invalid S3_ACCESS_KEY=preflight-access S3_SECRET_KEY=preflight-secret \
    S3_BUCKET=alparts BACKUP_AGE_RECIPIENT=age1pq1qqqqqqqq BACKUP_OUTPUT_DIR="$TEST_TMP/preflight-output" \
    "$REPOSITORY_ROOT/scripts/backup.sh" --preflight
}
printf 'rclone v1.75.1\n' > "$RCLONE_VERSION_OUTPUT"
run_preflight 2> "$TEST_TMP/preflight.err" || fail 'backup preflight failed with valid tools and settings'
grep -F 'Preflight passed' "$TEST_TMP/preflight.err" >/dev/null || fail 'backup preflight did not report success'
for command_name in age psql pg_dump; do
  [[ ! -e "$PREFLIGHT_CAPTURE/${command_name}.argv" ]] || fail "backup preflight ran ${command_name}"
done
[[ "$(cat -- "$PREFLIGHT_CAPTURE/rclone.argv")" == version ]] || fail 'backup preflight used the store'
[[ -z "$(find "$TEST_TMP/preflight-output" -mindepth 1)" ]] || fail 'backup preflight wrote output'
printf 'rclone v1.74.3\n' > "$RCLONE_VERSION_OUTPUT"
expect_failure 'rclone 1.75.1 or newer is required' "$TEST_TMP/preflight-old-rclone.err" run_preflight

printf 'backup security tests passed\n'
