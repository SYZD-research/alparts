#!/usr/bin/env bash

# Shared primitives for the Phase 1 backup and restore verification scripts.
# This file is meant to be sourced, not executed.

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  printf 'This file is a library and must be sourced.\n' >&2
  exit 2
fi

backup_log() {
  printf '[alparts-backup] %s\n' "$*" >&2
}

backup_die() {
  printf '[alparts-backup] ERROR: %s\n' "$*" >&2
  exit 1
}

# Only hybrid recipients are permitted for new archives. age performs full
# bech32/key validation; this admission check forbids classical/plugin fallback.
validate_backup_recipient() {
  [[ "$1" =~ ^age1pq1[023456789acdefghjklmnpqrstuvwxyz]+$ && ${#1} -le 4096 ]] \
    || backup_die 'Backups require a hybrid age1pq1 recipient generated offline with age-keygen -pq'
}

require_command() {
  local command_name="$1"
  command -v "$command_name" >/dev/null 2>&1 \
    || backup_die "Required command is not installed: ${command_name}"
}

load_required_value() {
  local variable_name="$1"
  local file_variable_name="${variable_name}_FILE"
  local direct_value="${!variable_name-}"
  local value_file="${!file_variable_name-}"
  local loaded_value

  if [[ -n "$direct_value" && -n "$value_file" ]]; then
    backup_die "Set only one of ${variable_name} or ${file_variable_name}"
  fi
  if [[ -z "$direct_value" && -z "$value_file" ]]; then
    backup_die "Missing required setting: ${variable_name} or ${file_variable_name}"
  fi

  if [[ -n "$value_file" ]]; then
    [[ -f "$value_file" && -r "$value_file" ]] \
      || backup_die "${file_variable_name} must name a readable regular file"
    validate_private_file "$value_file" "$file_variable_name"
    if (( $(wc -c < "$value_file") > 65536 )); then
      backup_die "${file_variable_name} is larger than 64 KiB"
    fi
    loaded_value="$(<"$value_file")"
  else
    loaded_value="$direct_value"
  fi

  [[ -n "$loaded_value" ]] || backup_die "${variable_name} must not be empty"
  printf -v "$variable_name" '%s' "$loaded_value"
  # Values supplied through the environment may otherwise be inherited by
  # every utility launched by this process. Retain them as shell variables for
  # the script only; children receive secrets solely through their dedicated
  # private file or stdin channel.
  export -n "$variable_name" 2>/dev/null || true
  unset "$file_variable_name"
}

validate_private_file() {
  local file_path="$1"
  local setting_name="$2"
  local mode
  local mode_value

  mode="$(stat -c '%a' -- "$file_path")"
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || backup_die "Could not validate permissions for ${setting_name}"
  mode_value=$((8#$mode))
  (( (mode_value & 077) == 0 )) \
    || backup_die "${setting_name} must not be readable or writable by group/other"
}

validate_minio_url() {
  local url="$1"
  local authority

  [[ "$url" == http://* || "$url" == https://* ]] \
    || backup_die 'MinIO URL must begin with http:// or https://'
  [[ "$url" != *[$'\t\r\n ']* && "$url" != *@* && "$url" != *\?* && "$url" != *\#* ]] \
    || backup_die 'MinIO URL must not contain credentials, whitespace, a query, or a fragment'
  authority="${url#*://}"
  [[ -n "$authority" && "$authority" != */* ]] \
    || backup_die 'MinIO URL must contain only a scheme and authority (no path)'
  if [[ "$url" == http://* ]]; then
    [[ "$authority" =~ ^(localhost|127\.0\.0\.1)(:[0-9]+)?$ || "$authority" =~ ^\[::1\](:[0-9]+)?$ ]] \
      || backup_die 'Plain HTTP MinIO URLs are permitted only for a loopback endpoint'
  fi
}

validate_postgres_service() {
  local service_file="$1"
  local service_name="$2"

  [[ -f "$service_file" && -r "$service_file" ]] \
    || backup_die 'PostgreSQL service file must be a readable regular file'
  validate_private_file "$service_file" 'PostgreSQL service file'
  (( $(wc -c < "$service_file") <= 65536 )) \
    || backup_die 'PostgreSQL service file is larger than 64 KiB'
  [[ "$service_name" =~ ^[A-Za-z0-9._-]{1,64}$ ]] \
    || backup_die 'PostgreSQL service name must contain 1-64 safe characters'
}

validate_bucket_name() {
  local bucket="$1"
  [[ ${#bucket} -ge 3 && ${#bucket} -le 63 ]] \
    || backup_die 'MinIO bucket name must contain 3 to 63 characters'
  [[ "$bucket" =~ ^[a-z0-9][a-z0-9.-]*[a-z0-9]$ ]] \
    || backup_die 'MinIO bucket name must use lower-case DNS-safe characters'
  [[ "$bucket" != *..* && "$bucket" != *.-* && "$bucket" != *-.* ]] \
    || backup_die 'MinIO bucket name contains an unsafe dot sequence'
}

validate_restore_database_name() {
  local database_name="$1"
  [[ "$database_name" =~ ^alparts_(restore|verify)_[a-z0-9][a-z0-9_]{0,39}$ ]] \
    || backup_die 'Verification database name must match alparts_restore_<suffix> or alparts_verify_<suffix>'
  [[ "$database_name" != *prod* && "$database_name" != *production* && "$database_name" != *live* && "$database_name" != *primary* ]] \
    || backup_die 'Verification database name looks production-like and was refused'
}

validate_restore_bucket_name() {
  local bucket="$1"
  validate_bucket_name "$bucket"
  [[ "$bucket" =~ ^alparts-(restore|verify)-[a-z0-9][a-z0-9-]{0,39}$ ]] \
    || backup_die 'Verification bucket must match alparts-restore-<suffix> or alparts-verify-<suffix>'
  [[ "$bucket" != *prod* && "$bucket" != *production* && "$bucket" != *live* && "$bucket" != *primary* ]] \
    || backup_die 'Verification bucket name looks production-like and was refused'
  [[ "$bucket" != 'alparts' ]] || backup_die 'The default alparts bucket is never a restore target'
}

configure_mc_alias() {
  local config_dir="$1"
  local alias_name="$2"
  local endpoint="$3"
  local access_key="$4"
  local secret_key="$5"

  [[ "$alias_name" =~ ^[A-Za-z][A-Za-z0-9_-]*$ ]] \
    || backup_die 'MinIO alias name is malformed'
  mkdir -p -- "$config_dir"
  chmod 700 -- "$config_dir"
  # Keep credentials out of both argv and the child environment. NUL-delimited
  # stdin preserves punctuation and newlines without shell interpolation; jq
  # converts that one private stream into mc's import format.
  if ! printf '%s\0%s\0%s' "$endpoint" "$access_key" "$secret_key" \
    | run_without_operator_secrets jq -Rsc '
      split("\u0000")
      | if length == 3 then {
          url: .[0],
          accessKey: .[1],
          secretKey: .[2],
          api: "s3v4",
          path: "auto"
        } else error("invalid MinIO credential stream") end
    ' \
    | run_without_operator_secrets mc --config-dir "$config_dir" alias import "$alias_name" >/dev/null 2>&1; then
    backup_die 'MinIO alias setup failed; verify the endpoint and credentials'
  fi
}

mc_with_config() {
  local config_dir="$1"
  shift
  run_without_operator_secrets mc --config-dir "$config_dir" "$@"
}

run_without_operator_secrets() {
  (
    unset DATABASE_URL DATABASE_URL_FILE VERIFY_DATABASE_URL VERIFY_DATABASE_URL_FILE
    unset MINIO_ACCESS_KEY MINIO_ACCESS_KEY_FILE MINIO_SECRET_KEY MINIO_SECRET_KEY_FILE
    unset VERIFY_MINIO_ACCESS_KEY VERIFY_MINIO_ACCESS_KEY_FILE
    unset VERIFY_MINIO_SECRET_KEY VERIFY_MINIO_SECRET_KEY_FILE
    unset PGDATABASE PGHOST PGHOSTADDR PGPORT PGUSER PGPASSWORD PGPASSFILE PGSERVICE PGSERVICEFILE
    # Application secrets may share the operator environment; children never need them.
    unset JWT_SECRET JWT_SECRET_FILE PASSWORD_PEPPER PASSWORD_PEPPER_FILE
    unset PASSWORD_PEPPER_PREVIOUS PASSWORD_PEPPER_PREVIOUS_FILE
    unset AUDIT_INTEGRITY_KEY AUDIT_INTEGRITY_KEY_FILE
    unset REGISTRATION_INVITE_SECRET REGISTRATION_INVITE_SECRET_FILE
    unset METRICS_TOKEN METRICS_TOKEN_FILE MINIO_ROOT_USER MINIO_ROOT_PASSWORD
    unset RESTORE_AGE_IDENTITY_FILE DATABASE_SERVICE_FILE
    exec "$@"
  )
}

postgres_with_service() {
  local service_file="$1"
  local service_name="$2"
  shift 2
  [[ $# -gt 0 ]] || backup_die 'Missing PostgreSQL command'
  # A private libpq service file keeps passwords out of both argv and the child
  # environment. Passing a complete URI through PGDATABASE does not expand it
  # as conninfo in PostgreSQL command-line tools, so require the native service
  # mechanism instead of attempting to parse libpq URIs in shell.
  (
    unset DATABASE_URL DATABASE_URL_FILE VERIFY_DATABASE_URL VERIFY_DATABASE_URL_FILE
    unset MINIO_ACCESS_KEY MINIO_ACCESS_KEY_FILE MINIO_SECRET_KEY MINIO_SECRET_KEY_FILE
    unset VERIFY_MINIO_ACCESS_KEY VERIFY_MINIO_ACCESS_KEY_FILE
    unset VERIFY_MINIO_SECRET_KEY VERIFY_MINIO_SECRET_KEY_FILE
    unset PGDATABASE PGHOST PGHOSTADDR PGPORT PGUSER PGPASSWORD PGPASSFILE PGSERVICE PGSERVICEFILE
    export PGSERVICEFILE="$service_file" PGSERVICE="$service_name"
    exec "$@"
  )
}

validate_restore_archive() {
  local archive_file="$1"
  local archive_list="$2"
  local archive_verbose="$3"
  local max_entries="$4"
  local max_file_bytes="$5"
  local max_expanded_bytes="$6"
  local archive_bytes
  local archive_path
  local verbose_line
  local block_label
  local block_token
  local current_block
  local mode
  local owner
  local logical_size
  local entry_date
  local entry_time
  local verbose_path
  local extra
  local entry_count=0
  local expanded_bytes=0
  local previous_block=''
  local previous_mode=''
  local previous_size=0
  local required_blocks
  local available_blocks
  local compact_sparse_detected=0
  local saw_end_block=0

  if ! LC_ALL=C tar --list --quoting-style=escape --file="$archive_file" \
    | awk -v maximum="$max_entries" '
        NR > maximum { exit 42 }
        { print }
      ' > "$archive_list"; then
    backup_die 'Backup archive is unreadable or exceeds RESTORE_MAX_ARCHIVE_ENTRIES'
  fi
  LC_ALL=C tar --list --verbose --block-number --numeric-owner --full-time \
    --quoting-style=escape --file="$archive_file" > "$archive_verbose"
  archive_bytes="$(stat -c '%s' -- "$archive_file")"
  [[ "$archive_bytes" =~ ^(0|[1-9][0-9]{0,17})$ ]] \
    || backup_die 'Could not validate decrypted archive size'

  exec 3< "$archive_list"
  while IFS= read -r verbose_line; do
    IFS=' ' read -r block_label block_token mode owner logical_size entry_date entry_time verbose_path extra <<< "$verbose_line"
    [[ "$block_label" == 'block' && "$block_token" =~ ^[0-9]+:$ ]] || {
      exec 3<&-
      backup_die 'Backup archive block metadata is malformed'
    }
    current_block="${block_token%:}"
    if [[ -n "$previous_block" ]]; then
      (( current_block > previous_block )) || {
        exec 3<&-
        backup_die 'Backup archive block metadata is inconsistent'
      }
      if [[ "$previous_mode" == '-' ]]; then
        required_blocks=$(((previous_size + 511) / 512))
        available_blocks=$((current_block - previous_block - 1))
        if (( required_blocks > available_blocks )); then
          compact_sparse_detected=1
        fi
      fi
    fi
    if [[ "$mode" == '**' && "$owner" == 'Block' && "$logical_size" == 'of' \
      && "$entry_date" == 'NULs' && "$entry_time" == '**' && -z "${verbose_path-}" ]]; then
      saw_end_block=1
      previous_block=''
      continue
    fi
    (( saw_end_block == 0 )) || {
      exec 3<&-
      backup_die 'Backup archive contains data after its end marker'
    }
    if ! IFS= read -r archive_path <&3; then
      exec 3<&-
      backup_die 'Backup archive listings disagree'
    fi
    [[ -n "$mode" && -n "$owner" && -n "$logical_size" && -n "$entry_date" && -n "$entry_time" \
      && -n "$verbose_path" && -z "${extra-}" && "$verbose_path" == "$archive_path" ]] || {
      exec 3<&-
      backup_die 'Backup archive metadata is malformed or ambiguous'
    }

    entry_count=$((entry_count + 1))
    (( entry_count <= max_entries )) || {
      exec 3<&-
      backup_die 'Backup archive exceeds RESTORE_MAX_ARCHIVE_ENTRIES'
    }

    case "${mode:0:1}" in
      -)
        [[ "$logical_size" =~ ^(0|[1-9][0-9]{0,17})$ ]] || {
          exec 3<&-
          backup_die 'Backup archive contains an invalid logical file size'
        }
        (( logical_size <= max_file_bytes )) || {
          exec 3<&-
          backup_die 'Backup archive file exceeds RESTORE_MAX_FILE_BYTES'
        }
        (( logical_size <= max_expanded_bytes - expanded_bytes )) || {
          exec 3<&-
          backup_die 'Backup archive exceeds RESTORE_MAX_EXPANDED_BYTES'
        }
        expanded_bytes=$((expanded_bytes + logical_size))
        ;;
      d)
        [[ "$logical_size" == '0' ]] || {
          exec 3<&-
          backup_die 'Backup archive directory has unsupported size metadata'
        }
        ;;
      *)
        exec 3<&-
        backup_die 'Backup archive contains links or unsupported entry types'
        ;;
    esac
    previous_block="$current_block"
    previous_mode="${mode:0:1}"
    previous_size="$logical_size"
  done < "$archive_verbose"
  if IFS= read -r archive_path <&3; then
    exec 3<&-
    backup_die 'Backup archive listings disagree'
  fi
  exec 3<&-

  (( entry_count > 0 )) || backup_die 'Backup archive is empty'
  if [[ -n "$previous_block" ]]; then
    current_block=$(((archive_bytes + 511) / 512))
    (( current_block > previous_block )) \
      || backup_die 'Backup archive block metadata is inconsistent'
    if [[ "$previous_mode" == '-' ]]; then
      required_blocks=$(((previous_size + 511) / 512))
      available_blocks=$((current_block - previous_block - 1))
      if (( required_blocks > available_blocks )); then
        compact_sparse_detected=1
      fi
    fi
  fi
  # An uncompressed, non-sparse tar must contain at least the logical bytes of
  # its regular files. GNU tar reports sparse files at their expanded logical
  # size, so this rejects compact sparse/unsupported encodings even when their
  # logical total is below the configured expansion limit.
  (( compact_sparse_detected == 0 && expanded_bytes <= archive_bytes )) \
    || backup_die 'Backup archive uses sparse or unsupported compact file metadata'
}

write_mc_object_listing() {
  local config_dir="$1"
  local target="$2"
  local output_file="$3"
  local raw_file="${output_file}.jsonl"

  mc_with_config "$config_dir" ls --recursive --json "$target" > "$raw_file"
  jq -r '
    if .status != "success" then error("MinIO listing reported an error")
    elif .type == "file" then [.key, (.size | tostring)] | @tsv
    elif .type == "folder" then error("MinIO listing contains a folder marker")
    else error("MinIO listing returned an unsupported entry type")
    end
  ' "$raw_file" | LC_ALL=C sort > "$output_file"

  if [[ -s "$output_file" ]] && ! awk -F '\t' '
    NF != 2 || $1 !~ /^[A-Za-z0-9][A-Za-z0-9._\/-]*$/ ||
      $1 ~ /(^|\/)\.\.?($|\/)/ || $2 !~ /^[0-9]+$/ { exit 1 }
  ' "$output_file"; then
    backup_die 'MinIO returned an unsafe object key or malformed size'
  fi
  [[ "$(cut -f 1 "$output_file" | LC_ALL=C sort | uniq -d | wc -l)" -eq 0 ]] \
    || backup_die 'MinIO listing contains duplicate object keys'
}

psql_scalar() {
  local service_file="$1"
  local service_name="$2"
  local sql="$3"
  postgres_with_service "$service_file" "$service_name" \
    psql -X --no-psqlrc --quiet --tuples-only --no-align \
    --set=ON_ERROR_STOP=1 --command "$sql"
}

postgres_tool_major() {
  local tool_name="$1"
  local version_output

  version_output="$("$tool_name" --version 2>&1)" \
    || backup_die "Could not determine ${tool_name} version"
  if [[ "$version_output" =~ \(PostgreSQL\)[[:space:]]+([0-9]+) ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return
  fi
  backup_die "Could not parse ${tool_name} major version"
}

postgres_server_major() {
  local service_file="$1"
  local service_name="$2"
  local version_number

  version_number="$(psql_scalar "$service_file" "$service_name" "SELECT current_setting('server_version_num');")"
  [[ "$version_number" =~ ^[0-9]{6}$ ]] \
    || backup_die 'Could not determine PostgreSQL server major version'
  printf '%s' "$((version_number / 10000))"
}

require_matching_postgres_major() {
  local tool_name="$1"
  local service_file="$2"
  local service_name="$3"
  local tool_major
  local server_major

  tool_major="$(postgres_tool_major "$tool_name")"
  server_major="$(postgres_server_major "$service_file" "$service_name")"
  [[ "$tool_major" == "$server_major" ]] \
    || backup_die "${tool_name} major ${tool_major} must match PostgreSQL server major ${server_major}"
}

write_table_counts() {
  local service_file="$1"
  local service_name="$2"
  local output_file="$3"

  postgres_with_service "$service_file" "$service_name" \
    psql -X --no-psqlrc --quiet --tuples-only --no-align \
    --field-separator=$'\t' --set=ON_ERROR_STOP=1 > "$output_file" <<'SQL'
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SELECT format(
  'SELECT %L, count(*)::bigint FROM %I.%I;',
  n.nspname || '.' || c.relname,
  n.nspname,
  c.relname
)
FROM pg_catalog.pg_class AS c
JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND n.nspname !~ '^pg_toast'
ORDER BY n.nspname, c.relname
\gexec
COMMIT;
SQL

  LC_ALL=C sort -o "$output_file" "$output_file"
  validate_table_counts_file "$output_file"
}

validate_table_counts_file() {
  local counts_file="$1"
  if [[ -s "$counts_file" ]] && ! awk -F '\t' '
    NF != 2 || $1 !~ /^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*$/ || $2 !~ /^[0-9]+$/ { exit 1 }
  ' "$counts_file"; then
    backup_die 'Database table count file contains an unexpected identifier or value'
  fi
  [[ "$(cut -f 1 "$counts_file" | LC_ALL=C sort | uniq -d | wc -l)" -eq 0 ]] \
    || backup_die 'Database table count file contains duplicate table names'
}

relation_exists() {
  local service_file="$1"
  local service_name="$2"
  local relation_name="$3"
  [[ "$(psql_scalar "$service_file" "$service_name" "SELECT to_regclass('${relation_name}') IS NOT NULL;")" == 't' ]]
}

column_exists() {
  local service_file="$1"
  local service_name="$2"
  local table_name="$3"
  local column_name="$4"
  [[ "$(psql_scalar "$service_file" "$service_name" "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = '${table_name}' AND column_name = '${column_name}');")" == 't' ]]
}

write_object_references() {
  local service_file="$1"
  local service_name="$2"
  local output_file="$3"
  local has_chunk_count='false'

  : > "$output_file"
  if relation_exists "$service_file" "$service_name" 'public.attachments'; then
    if column_exists "$service_file" "$service_name" 'attachments' 'chunk_count'; then
      has_chunk_count='true'
    fi

    if [[ "$has_chunk_count" == 'true' ]]; then
      postgres_with_service "$service_file" "$service_name" \
        psql -X --no-psqlrc --quiet --tuples-only --no-align \
        --field-separator=$'\t' --set=ON_ERROR_STOP=1 \
        --command "SELECT 'attachment', id::text, storage_key, chunk_count::text FROM public.attachments ORDER BY id;" \
        >> "$output_file"
    else
      postgres_with_service "$service_file" "$service_name" \
        psql -X --no-psqlrc --quiet --tuples-only --no-align \
        --field-separator=$'\t' --set=ON_ERROR_STOP=1 \
        --command "SELECT 'attachment', id::text, storage_key, '1' FROM public.attachments ORDER BY id;" \
        >> "$output_file"
    fi

    postgres_with_service "$service_file" "$service_name" \
      psql -X --no-psqlrc --quiet --tuples-only --no-align \
      --field-separator=$'\t' --set=ON_ERROR_STOP=1 \
      --command "SELECT 'thumbnail', id::text, thumbnail_key, '1' FROM public.attachments WHERE thumbnail_key IS NOT NULL ORDER BY id;" \
      >> "$output_file"
  fi

  if relation_exists "$service_file" "$service_name" 'public.attachment_upload_chunks'; then
    postgres_with_service "$service_file" "$service_name" \
      psql -X --no-psqlrc --quiet --tuples-only --no-align \
      --field-separator=$'\t' --set=ON_ERROR_STOP=1 \
      --command "SELECT 'upload_chunk', upload_id::text || ':' || chunk_index::text, storage_key, '1' FROM public.attachment_upload_chunks ORDER BY upload_id, chunk_index;" \
      >> "$output_file"
  fi

  LC_ALL=C sort -o "$output_file" "$output_file"
  validate_object_references_file "$output_file"
}

validate_object_references_file() {
  local references_file="$1"
  if [[ -s "$references_file" ]] && ! awk -F '\t' '
    NF != 4 || $1 !~ /^(attachment|thumbnail|upload_chunk)$/ ||
      $2 !~ /^[a-f0-9-]+(:[0-9]+)?$/ ||
      $3 !~ /^[A-Za-z0-9][A-Za-z0-9._\/-]*$/ ||
      $3 ~ /(^|\/)\.\.?($|\/)/ || $4 !~ /^[1-9][0-9]*$/ { exit 1 }
  ' "$references_file"; then
    backup_die 'Object reference file contains an unsafe or malformed value'
  fi
}

validate_object_tree() {
  local object_root="$1"
  local path
  local relative_path

  if find "$object_root" -mindepth 1 \! -type f \! -type d -print -quit | grep -q .; then
    backup_die 'Object staging contains a symlink or unsupported filesystem entry'
  fi

  while IFS= read -r -d '' path; do
    relative_path="${path#"$object_root"/}"
    [[ "$relative_path" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] \
      || backup_die 'An object key contains unsupported characters'
    [[ "/$relative_path/" != */../* && "/$relative_path/" != */./* && "$relative_path" != *//* ]] \
      || backup_die 'An object key contains an unsafe path component'
  done < <(find "$object_root" -type f -print0)
}

write_object_inventory() {
  local object_root="$1"
  local output_file="$2"
  local relative_path
  local byte_count
  local digest

  : > "$output_file"
  while IFS= read -r relative_path; do
    [[ -n "$relative_path" ]] || continue
    byte_count="$(stat -c '%s' -- "$object_root/$relative_path")"
    digest="$(sha256sum -- "$object_root/$relative_path")"
    digest="${digest%% *}"
    printf '%s\t%s\t%s\n' "$relative_path" "$byte_count" "$digest" >> "$output_file"
  done < <(find "$object_root" -type f -printf '%P\n' | LC_ALL=C sort)
}

verify_object_references() {
  local references_file="$1"
  local object_root="$2"
  local kind
  local reference_id
  local object_key
  local expected_count
  local extra
  local actual_count

  while IFS=$'\t' read -r kind reference_id object_key expected_count extra \
    || [[ -n "${kind}${reference_id}${object_key}${expected_count}${extra-}" ]]; do
    [[ -n "$kind" ]] || continue
    [[ -z "${extra-}" ]] || backup_die 'Object reference file contains extra fields'
    case "$kind" in
      attachment)
        if [[ -f "$object_root/$object_key" ]]; then
          actual_count=1
        elif [[ -d "$object_root/$object_key" ]]; then
          actual_count="$(find "$object_root/$object_key" -type f | wc -l)"
        else
          backup_die "Attachment ${reference_id} has no corresponding object data"
        fi
        [[ "$actual_count" == "$expected_count" ]] \
          || backup_die "Attachment ${reference_id} expected ${expected_count} object chunk(s), found ${actual_count}"
        ;;
      thumbnail|upload_chunk)
        [[ -f "$object_root/$object_key" ]] \
          || backup_die "${kind} ${reference_id} has no corresponding object"
        ;;
      *)
        backup_die 'Object reference file contains an unsupported reference type'
        ;;
    esac
  done < "$references_file"
}

write_payload_checksums() {
  local payload_dir="$1"
  local output_file="$payload_dir/checksums.sha256"
  local relative_path

  : > "$output_file"
  (
    cd "$payload_dir"
    sha256sum -- database.dump
    while IFS= read -r relative_path; do
      sha256sum -- "$relative_path"
    done < <(find objects -type f -printf '%P\n' | LC_ALL=C sort | sed 's#^#objects/#')
  ) >> "$output_file"
}

validate_checksum_file() {
  local payload_dir="$1"
  local checksum_file="$payload_dir/checksums.sha256"
  local line
  local checksum
  local relative_path
  local database_entries=0
  local entry_count=0

  [[ -f "$checksum_file" ]] || backup_die 'Backup is missing checksums.sha256'
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^([a-f0-9]{64})\ \ (database\.dump|objects/[A-Za-z0-9][A-Za-z0-9._/-]*)$ ]] \
      || backup_die 'Backup checksum file contains an unsafe or malformed entry'
    checksum="${BASH_REMATCH[1]}"
    relative_path="${BASH_REMATCH[2]}"
    [[ "/$relative_path/" != */../* && "/$relative_path/" != */./* && "$relative_path" != *//* ]] \
      || backup_die 'Backup checksum file contains an unsafe path'
    [[ "$checksum" =~ ^[a-f0-9]{64}$ ]] || backup_die 'Backup checksum is malformed'
    if [[ "$relative_path" == 'database.dump' ]]; then
      database_entries=$((database_entries + 1))
    fi
    entry_count=$((entry_count + 1))
  done < "$checksum_file"

  [[ "$database_entries" -eq 1 ]] || backup_die 'Backup must contain exactly one database dump checksum'
  [[ "$(awk '{ print $2 }' "$checksum_file" | LC_ALL=C sort | uniq -d | wc -l)" -eq 0 ]] \
    || backup_die 'Backup checksum file contains duplicate paths'
  (
    cd "$payload_dir"
    sha256sum --check --strict --quiet checksums.sha256
  ) || backup_die 'Backup payload checksum validation failed'

  printf '%s' "$entry_count"
}

directory_is_empty() {
  local directory="$1"
  [[ -z "$(find "$directory" -mindepth 1 -print -quit)" ]]
}
