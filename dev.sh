#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

info() { printf '\033[1;34m[dev]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[dev]\033[0m %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker が見つかりません"
docker compose version >/dev/null 2>&1 || die "docker compose プラグインが見つかりません"

compose() {
  docker compose \
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
  db_pass="$(rand_hex 24)"
  cat > .env <<EOF
POSTGRES_USER=alparts
POSTGRES_PASSWORD=${db_pass}
POSTGRES_DB=alparts
DATABASE_URL=postgresql://alparts:${db_pass}@localhost:5433/alparts
BIND_HOST=127.0.0.1
DB_SSL=false

MINIO_ROOT_USER=$(rand_hex 12)
MINIO_ROOT_PASSWORD=$(rand_hex 32)
MINIO_ACCESS_KEY=$(rand_hex 8)
MINIO_SECRET_KEY=$(rand_hex 24)
MINIO_ENDPOINT=localhost
MINIO_PORT=9000
MINIO_USE_SSL=false
MINIO_BUCKET=alparts
MINIO_REQUEST_TIMEOUT_MS=10000

JWT_SECRET=$(rand_hex 48)
AUDIT_INTEGRITY_KEY=$(rand_hex 48)
REGISTRATION_INVITE_SECRET=$(rand_hex 48)
CORS_ORIGINS=http://localhost:5173
VOICE_ICE_SERVERS_JSON=[]
EOF
  chmod 600 .env
  created_env=1
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
  case "$env_key" in
    POSTGRES_USER|POSTGRES_PASSWORD|POSTGRES_DB|POSTGRES_PORT|DATABASE_URL|DB_SSL|DB_POOL_MAX|DB_CONNECT_TIMEOUT_MS|DB_STATEMENT_TIMEOUT_MS|\
    MINIO_ROOT_USER|MINIO_ROOT_PASSWORD|MINIO_ACCESS_KEY|MINIO_SECRET_KEY|MINIO_ENDPOINT|MINIO_PORT|MINIO_CONSOLE_PORT|MINIO_USE_SSL|MINIO_BUCKET|MINIO_REQUEST_TIMEOUT_MS|\
    STORAGE_QUOTA_BYTES_PER_USER|STORAGE_QUOTA_BYTES_PER_WORKSPACE|STORAGE_QUOTA_BYTES_PER_CHANNEL|\
    JWT_SECRET|JWT_ISSUER|JWT_AUDIENCE|JWT_EXPIRES_IN_SECONDS|COOKIE_SECURE|\
    AUDIT_INTEGRITY_KEY|AUDIT_CHECKPOINT_PATH|AUDIT_CHECKPOINT_REQUIRED|\
    REGISTRATION_INVITE_SECRET|CORS_ORIGIN|CORS_ORIGINS|TRUSTED_PROXIES|VOICE_ICE_SERVERS_JSON|VOICE_ICE_SERVERS_JSON_FILE|BIND_HOST|PORT)
      ;;
    *) die ".env に未対応の変数があります: ${env_key}" ;;
  esac
  export "$env_key=$env_value"
done < .env

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
  info "Postgres / MinIO を起動します"
  compose up -d --remove-orphans postgres minio
  info "Postgres の起動を待機中"
  wait_for_postgres
  info "MinIO の最小権限アプリユーザーを準備します"
  if ! compose run --rm minio-init >/dev/null; then
    die "MinIO の認証情報を確認できませんでした。既存データを保持したまま停止します"
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
pnpm --filter @alparts/server db:migrate

info "開発サーバーを起動します (client: http://localhost:5173 / 停止: Ctrl+C, 全停止: ./dev.sh down)"
exec pnpm dev
