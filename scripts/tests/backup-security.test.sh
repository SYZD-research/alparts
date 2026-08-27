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

REAL_JQ="$(command -v jq)"
[[ -n "$REAL_JQ" ]] || fail 'jq is required'
FAKE_BIN="$TEST_TMP/fake-bin"
CAPTURE_DIR="$TEST_TMP/capture"
mkdir -p -- "$FAKE_BIN" "$CAPTURE_DIR"
for command_name in jq mc psql pg_dump pg_restore; do
  ln -s -- "$SCRIPT_DIR/fixtures/capture-command.sh" "$FAKE_BIN/$command_name"
done
export BACKUP_TEST_CAPTURE_DIR="$CAPTURE_DIR"
export BACKUP_TEST_REAL_JQ="$REAL_JQ"
PATH="$FAKE_BIN:$PATH"
export PATH

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

MC_ACCESS_SENTINEL='MC_ACCESS_ARG_SENTINEL_31c2'
MC_SECRET_SENTINEL='MC_SECRET_ARG_SENTINEL_a804'
export MINIO_ACCESS_KEY="$MC_ACCESS_SENTINEL"
export MINIO_SECRET_KEY="$MC_SECRET_SENTINEL"
MC_CONFIG_DIR="$TEST_TMP/mc-config"
configure_mc_alias "$MC_CONFIG_DIR" source 'https://minio.invalid' \
  "$MC_ACCESS_SENTINEL" "$MC_SECRET_SENTINEL"
assert_file_excludes "$CAPTURE_DIR/jq.argv" "$MC_ACCESS_SENTINEL"
assert_file_excludes "$CAPTURE_DIR/jq.argv" "$MC_SECRET_SENTINEL"
assert_file_excludes "$CAPTURE_DIR/mc.argv" "$MC_ACCESS_SENTINEL"
assert_file_excludes "$CAPTURE_DIR/mc.argv" "$MC_SECRET_SENTINEL"
assert_file_excludes "$CAPTURE_DIR/jq.env" "$MC_ACCESS_SENTINEL"
assert_file_excludes "$CAPTURE_DIR/jq.env" "$MC_SECRET_SENTINEL"
assert_file_excludes "$CAPTURE_DIR/mc.env" "$MC_ACCESS_SENTINEL"
assert_file_excludes "$CAPTURE_DIR/mc.env" "$MC_SECRET_SENTINEL"
unset MINIO_ACCESS_KEY MINIO_SECRET_KEY
[[ "$(stat -c '%a' -- "$MC_CONFIG_DIR")" == '700' ]] \
  || fail 'MinIO config directory is not mode 0700'
BACKUP_TEST_EXPECT_ACCESS="$MC_ACCESS_SENTINEL" \
BACKUP_TEST_EXPECT_SECRET="$MC_SECRET_SENTINEL" \
  "$REAL_JQ" -e '
    .url == "https://minio.invalid" and
    .accessKey == env.BACKUP_TEST_EXPECT_ACCESS and
    .secretKey == env.BACKUP_TEST_EXPECT_SECRET and
    .api == "s3v4" and .path == "auto"
  ' "$CAPTURE_DIR/mc.stdin" >/dev/null \
  || fail 'MinIO stdin import payload is malformed'

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

printf 'backup security tests passed\n'
