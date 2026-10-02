#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

info() { printf '\033[1;34m[dev]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[dev]\033[0m %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker が見つかりません"
docker compose version >/dev/null 2>&1 || die "docker compose プラグインが見つかりません"

compose() {
  sudo docker compose \
    --project-directory "$PWD" \
    --env-file "$PWD/.env" \
    -f "$PWD/docker-compose.yml" \
    -p alparts \
    "$@"
}

if [ "${1:-}" = "down" ]; then
  [ -f .env ] || die ".env がないため、停止対象を安全に特定できません"
  compose down
  exit 0
fi

command -v pnpm >/dev/null 2>&1 || die "pnpm が見つかりません"
command -v openssl >/dev/null 2>&1 || die "openssl が見つかりません"

rand_hex() { openssl rand -hex "$1"; }

created_env=0
if [ ! -f .env ]; then
  info ".env が存在しないため、ランダムなシークレット付きで生成します"
  umask 077
  db_pass="$(rand_hex 24)"
  cat > .env <<EOF
POSTGRES_USER=alparts
POSTGRES_PASSWORD=${db_pass}
POSTGRES_DB=alparts
DATABASE_URL=postgresql://alparts:${db_pass}@localhost:5433/alparts
BIND_HOST=127.0.0.1
DB_SSL=false

S3_ADMIN_ACCESS_KEY=$(rand_hex 12)
S3_ADMIN_SECRET_KEY=$(rand_hex 32)
S3_ACCESS_KEY=$(rand_hex 8)
S3_SECRET_KEY=$(rand_hex 24)
S3_ENDPOINT=localhost
S3_PORT=9000
S3_USE_SSL=false
S3_BUCKET=alparts
S3_REQUEST_TIMEOUT_MS=10000

PASSWORD_PEPPER=$(rand_hex 48)
JWT_SECRET=$(rand_hex 48)
AUDIT_INTEGRITY_KEY=$(rand_hex 48)
AUDIT_CHECKPOINT_PATH=$PWD/.local/audit-checkpoint.json
AUDIT_CHECKPOINT_REQUIRED=true
AUDIT_HEAD_BUCKET=alparts-audit
AUDIT_HEAD_OBJECT_KEY=$(rand_hex 16)
REGISTRATION_INVITE_SECRET=$(rand_hex 48)
CORS_ORIGINS=http://localhost:5173,http://localhost:3000,http://127.0.0.1:3000
VOICE_ICE_SERVERS_JSON=[]
EOF
  chmod 600 .env
  created_env=1
fi

# .env holds secrets; an existing file may predate the umask above.
env_mode="$(stat -c '%a' .env 2>/dev/null || stat -f '%Lp' .env)"
if [ "$((8#$env_mode & 8#077))" -ne 0 ]; then
  info ".env が他のユーザーから読める設定だったため、所有者のみに制限します"
  chmod 600 .env
fi

is_supported_env_key() {
  case "$1" in
    POSTGRES_USER|POSTGRES_PASSWORD|POSTGRES_DB|POSTGRES_PORT|DATABASE_URL|DB_SSL|DB_POOL_MAX|DB_CONNECT_TIMEOUT_MS|DB_STATEMENT_TIMEOUT_MS|\
    S3_ADMIN_ACCESS_KEY|S3_ADMIN_SECRET_KEY|S3_ACCESS_KEY|S3_SECRET_KEY|S3_ENDPOINT|S3_PORT|S3_USE_SSL|S3_REGION|S3_BUCKET|S3_REQUEST_TIMEOUT_MS|\
    STORAGE_QUOTA_BYTES_PER_USER|STORAGE_QUOTA_BYTES_PER_WORKSPACE|STORAGE_QUOTA_BYTES_PER_CHANNEL|\
    JWT_SECRET|JWT_ISSUER|JWT_AUDIENCE|JWT_EXPIRES_IN_SECONDS|COOKIE_SECURE|\
    PASSWORD_PEPPER|PASSWORD_PEPPER_PREVIOUS|WEBAUTHN_RP_ID|WEBAUTHN_ORIGINS|AUDIT_INTEGRITY_KEY|AUDIT_CHECKPOINT_PATH|AUDIT_CHECKPOINT_REQUIRED|\
    AUDIT_HEAD_BUCKET|AUDIT_HEAD_OBJECT_KEY|AUDIT_WITNESS_REQUIRED|AUDIT_WITNESS_PUBLIC_KEY_FILE|AUDIT_WITNESS_PATH|AUDIT_WITNESS_DEPLOYMENT_ID|\
    METRICS_ENABLED|METRICS_TOKEN|ALLOW_INSECURE_LOOPBACK_DEPENDENCIES|VITE_ALLOWED_HOSTS|\
    REGISTRATION_INVITE_SECRET|CORS_ORIGIN|CORS_ORIGINS|TRUSTED_PROXIES|VOICE_ICE_SERVERS_JSON|BIND_HOST|PORT)
      return 0 ;;
  esac
  # Every documented value may instead be read from a file: NAME_FILE.
  case "$1" in
    *_FILE) is_supported_env_key "${1%_FILE}" ;;
    *) return 1 ;;
  esac
}

# Object storage settings were renamed from MINIO_* to S3_*, and the server
# no longer reads the old names. Rename them in this local .env once.
if grep -q '^MINIO_' .env; then
  info ".env のストレージ設定の名前を新しい名前 (S3_*) に変更します"
  renamed_env="$(mktemp .env.XXXXXX)"
  sed -e 's/^MINIO_ROOT_USER=/S3_ADMIN_ACCESS_KEY=/' \
    -e 's/^MINIO_ROOT_PASSWORD=/S3_ADMIN_SECRET_KEY=/' \
    -e '/^MINIO_CONSOLE_PORT=/d' \
    -e 's/^MINIO_/S3_/' .env > "$renamed_env"
  chmod 600 "$renamed_env"
  mv "$renamed_env" .env
fi

# Treat .env as data, not shell source. This intentionally supports the simple
# KEY=value form generated above and rejects syntax that could execute code.
while IFS= read -r line || [ -n "$line" ]; do
  line="${line%$'\r'}"
  case "$line" in
    ''|'#'*) continue ;;
  esac
  if [[ "$line" != *=* ]]; then
    die ".env に KEY=value ではない行があります"
  fi
  env_key="${line%%=*}"
  env_value="${line#*=}"
  if [[ ! "$env_key" =~ ^[A-Z][A-Z0-9_]*$ ]]; then
    die ".env に不正な変数名があります: ${env_key}"
  fi
  is_supported_env_key "$env_key" || die ".env に未対応の変数があります: ${env_key}"
  export "$env_key=$env_value"
done < .env

# 以前の .env には、後から必須になった設定が欠けている場合がある。
# 実行時エラーになる前に、この場で補う。
append_env() {
  if [ -n "$(tail -c 1 .env)" ]; then
    printf '\n' >> .env
  fi
  printf '%s=%s\n' "$1" "$2" >> .env
}

checkpoint_added=0
head_added=0
if [ -z "${PASSWORD_PEPPER:-}" ] && [ -z "${PASSWORD_PEPPER_FILE:-}" ]; then
  info ".env に PASSWORD_PEPPER がないため、新しい値を追加します"
  PASSWORD_PEPPER="$(rand_hex 48)"
  append_env PASSWORD_PEPPER "$PASSWORD_PEPPER"
  export PASSWORD_PEPPER
fi
if [ -z "${AUDIT_CHECKPOINT_PATH:-}" ]; then
  info ".env に監査チェックポイントの設定がないため、ローカルの検証ファイルを追加します"
  AUDIT_CHECKPOINT_PATH="$PWD/.local/audit-checkpoint.json"
  AUDIT_CHECKPOINT_REQUIRED=true
  append_env AUDIT_CHECKPOINT_PATH "$AUDIT_CHECKPOINT_PATH"
  append_env AUDIT_CHECKPOINT_REQUIRED "$AUDIT_CHECKPOINT_REQUIRED"
  export AUDIT_CHECKPOINT_PATH AUDIT_CHECKPOINT_REQUIRED
  checkpoint_added=1
fi

: "${AUDIT_HEAD_BUCKET:=${S3_BUCKET:-alparts}-audit}"
export AUDIT_HEAD_BUCKET
if [ -z "${AUDIT_HEAD_OBJECT_KEY:-}" ]; then
  AUDIT_HEAD_OBJECT_KEY="$(rand_hex 16)"
  append_env AUDIT_HEAD_OBJECT_KEY "$AUDIT_HEAD_OBJECT_KEY"
  export AUDIT_HEAD_OBJECT_KEY
  head_added=1
fi

: "${POSTGRES_USER:?POSTGRES_USER が .env にありません}"
: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD が .env にありません}"
: "${POSTGRES_DB:?POSTGRES_DB が .env にありません}"
: "${DATABASE_URL:?DATABASE_URL が .env にありません}"

wait_for_postgres() {
  for i in $(seq 1 60); do
    if compose exec -T postgres pg_isready -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" >/dev/null 2>&1; then
      return 0
    fi
    if [ "$i" -eq 60 ]; then
      die "Postgres が時間内に起動しませんでした (docker compose logs postgres で確認してください)"
    fi
    sleep 1
  done
}

postgres_password_ok() {
  compose exec -T -e PGPASSWORD="${POSTGRES_PASSWORD}" postgres \
    psql -h 127.0.0.1 -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -c 'SELECT 1' >/dev/null 2>&1
}

start_deps() {
  info "Postgres / オブジェクトストレージを起動します"
  compose up -d --remove-orphans postgres object-storage
  info "Postgres の起動を待機中"
  wait_for_postgres
  info "オブジェクトストレージの起動を待機中"
  if ! compose up -d --wait object-storage >/dev/null; then
    die "オブジェクトストレージが起動しませんでした (docker compose logs object-storage で確認してください)"
  fi
}

if [ "${created_env}" = 1 ]; then
  info "新しい .env を生成しました。既存volumeがある場合も自動削除しません"
fi

start_deps

if ! postgres_password_ok; then
  die "Postgres に .env の認証情報で接続できません。既存データが不要な場合に限り、内容を確認してから 'docker compose down -v' を手動実行してください"
fi

info "依存パッケージをインストールします"
pnpm install

info "データベースマイグレーションを実行します"
pnpm --filter @alparts/server exec tsx src/scripts/migrate-runtime.ts

if [ "${created_env}" = 1 ] || [ "${checkpoint_added}" = 1 ]; then
  pnpm --filter @alparts/server audit:checkpoint:init
else
  # 保存先を追記した回だけでなく、移行が済むまで毎回止める。
  # 起動時に head を自動作成しないのは意図した動作 (docs/OPERATIONS.md)。
  head_status="$(pnpm --filter @alparts/server --silent exec tsx src/scripts/audit-head-status.ts)" \
    || die "監査記録の状態を確認できませんでした (オブジェクトストレージの起動状態を確認してください)"
  if [ "${head_status}" = "pending" ]; then
    [ "${head_added}" = 1 ] && info "監査記録の保存先を .env に追加しました"
    if [ "${1:-}" != "audit-head-init" ]; then
      die "監査記録の移行が済んでいません。docs/OPERATIONS.md の監査 head 移行手順で確認してから './dev.sh audit-head-init' を一度実行してください"
    fi
    info "監査記録の移行を実行します"
    pnpm --filter @alparts/server audit:head:init
  fi
fi

info "開発サーバーを起動します (client: http://localhost:5173 / 停止: Ctrl+C, 全停止: ./dev.sh down)"
exec pnpm dev
