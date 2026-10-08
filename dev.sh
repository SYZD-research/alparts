#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

info() { printf '\033[1;34m[dev]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[dev]\033[0m %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker が見つかりません"
docker compose version >/dev/null 2>&1 || die "docker compose プラグインが見つかりません"

# The object store's administrator credentials reach only its container:
# docker compose reads them from this file. They are kept out of .env, which
# pnpm loads into every script, including the application.
STORAGE_ADMIN_ENV="$PWD/.local/storage-admin.env"

# --tailscale also serves the development client to this tailnet over HTTPS,
# so an Android device on the same tailnet can use it as its server.
use_tailscale=0
if [ "${1:-}" = "--tailscale" ]; then
  use_tailscale=1
  shift
fi

# Prints this machine's tailnet name, e.g. host.tailnet.ts.net, once Tailscale
# is running and HTTPS certificates are enabled for the tailnet.
tailscale_host() {
  tailscale status --json | node -e '
    let input = "";
    process.stdin.on("data", (chunk) => { input += chunk; });
    process.stdin.on("end", () => {
      const status = JSON.parse(input);
      if (status.BackendState !== "Running") process.exit(2);
      const host = String(status.Self?.DNSName ?? "").replace(/\.$/, "");
      if (!host || !(status.CertDomains ?? []).includes(host)) process.exit(3);
      process.stdout.write(host);
    });
  '
}

# The serve rule this script adds; ./dev.sh down removes only this one.
tailscale_serves_dev_client() {
  command -v tailscale >/dev/null 2>&1 && tailscale serve status --json 2>/dev/null | grep -q '"http://localhost:5173"'
}

compose() {
  local env_files=(--env-file "$PWD/.env")
  [ -f "$STORAGE_ADMIN_ENV" ] && env_files+=(--env-file "$STORAGE_ADMIN_ENV")
  sudo docker compose \
    --project-directory "$PWD" \
    "${env_files[@]}" \
    -f "$PWD/docker-compose.yml" \
    -p alparts \
    "$@"
}

if [ "${1:-}" = "down" ]; then
  [ -f .env ] || die ".env がないため、停止対象を安全に特定できません"
  compose down
  if tailscale_serves_dev_client; then
    info "Tailscale での公開を停止します"
    sudo tailscale serve --https=443 off
  fi
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
VOICE_SFU_ENABLED=true
VOICE_SFU_BIND_ADDRESS=0.0.0.0
VOICE_SFU_ANNOUNCED_ADDRESS=127.0.0.1
VOICE_SFU_BASE_PORT=40000
VOICE_SFU_WORKERS=1
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
    	S3_ACCESS_KEY|S3_SECRET_KEY|S3_ENDPOINT|S3_PORT|S3_USE_SSL|S3_REGION|S3_BUCKET|S3_REQUEST_TIMEOUT_MS|\
    	STORAGE_QUOTA_BYTES_PER_USER|STORAGE_QUOTA_BYTES_PER_WORKSPACE|STORAGE_QUOTA_BYTES_PER_CHANNEL|\
    	JWT_SECRET|JWT_ISSUER|JWT_AUDIENCE|JWT_EXPIRES_IN_SECONDS|COOKIE_SECURE|\
    	PASSWORD_PEPPER|PASSWORD_PEPPER_PREVIOUS|WEBAUTHN_RP_ID|WEBAUTHN_ORIGINS|AUDIT_INTEGRITY_KEY|AUDIT_CHECKPOINT_PATH|AUDIT_CHECKPOINT_REQUIRED|\
    	AUDIT_HEAD_BUCKET|AUDIT_HEAD_OBJECT_KEY|AUDIT_WITNESS_REQUIRED|AUDIT_WITNESS_PUBLIC_KEY_FILE|AUDIT_WITNESS_PATH|AUDIT_WITNESS_DEPLOYMENT_ID|\
    	METRICS_ENABLED|METRICS_TOKEN|ALLOW_INSECURE_LOOPBACK_DEPENDENCIES|VITE_ALLOWED_HOSTS|\
    	EMAIL_VERIFICATION|SMTP_HOST|SMTP_PORT|SMTP_SECURE|SMTP_FROM|SMTP_USER|SMTP_PASSWORD|SMTP_TIMEOUT_MS|\
    	REGISTRATION_INVITE_SECRET|CORS_ORIGIN|CORS_ORIGINS|TRUSTED_PROXIES|VOICE_ICE_SERVERS_JSON|\
    	VOICE_SFU_ENABLED|VOICE_SFU_BIND_ADDRESS|VOICE_SFU_ANNOUNCED_ADDRESS|VOICE_SFU_BASE_PORT|VOICE_SFU_WORKERS|BIND_HOST|PORT)
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
legacy_storage_name() {
  case "$1" in
    MINIO_ROOT_USER) printf 'S3_ADMIN_ACCESS_KEY' ;;
    MINIO_ROOT_PASSWORD) printf 'S3_ADMIN_SECRET_KEY' ;;
    MINIO_CONSOLE_PORT) ;;
    MINIO_*) printf 'S3_%s' "${1#MINIO_}" ;;
  esac
}
if grep -q '^MINIO_' .env; then
  # Rewrite the file .env resolves to, in place: a linked .env stays linked and
  # keeps its owner, ACLs and labels.
  env_target="$(readlink -f .env)"
  while IFS='=' read -r legacy_key _; do
    new_key="$(legacy_storage_name "$legacy_key")"
    if [ -n "$new_key" ] && grep -q "^${new_key}=" "$env_target"; then
      die ".env に ${legacy_key} と ${new_key} の両方があります。どちらを使うか決めて、古い方の行を削除してください"
    fi
  done < <(grep '^MINIO_' "$env_target")
  info ".env のストレージ設定の名前を新しい名前 (S3_*) に変更します"
  renamed_env="$(mktemp "${env_target}.XXXXXX")"
  trap 'rm -f -- "$renamed_env"' EXIT
  sed -e 's/^MINIO_ROOT_USER=/S3_ADMIN_ACCESS_KEY=/' \
    -e 's/^MINIO_ROOT_PASSWORD=/S3_ADMIN_SECRET_KEY=/' \
    -e '/^MINIO_CONSOLE_PORT=/d' \
    -e 's/^MINIO_/S3_/' "$env_target" > "$renamed_env"
  cat -- "$renamed_env" > "$env_target"
  rm -f -- "$renamed_env"
  trap - EXIT
fi

# Older .env files held the storage administrator's credentials. Move them to
# their own file, rewriting .env in place as above.
admin_key_pattern='^S3_ADMIN_(ACCESS|SECRET)_KEY='
if grep -qE "$admin_key_pattern" .env; then
  [ -e "$STORAGE_ADMIN_ENV" ] \
    && die ".env と ${STORAGE_ADMIN_ENV} の両方にストレージ管理者の設定があります。.env の S3_ADMIN_* の行を削除してください"
  info "ストレージ管理者の認証情報を、アプリに渡らない .local/storage-admin.env へ移します"
  env_target="$(readlink -f .env)"
  mkdir -p .local
  (umask 077 && grep -E "$admin_key_pattern" "$env_target" > "$STORAGE_ADMIN_ENV")
  remaining_env="$(mktemp "${env_target}.XXXXXX")"
  trap 'rm -f -- "$remaining_env"' EXIT
  grep -vE "$admin_key_pattern" "$env_target" > "$remaining_env" || true
  cat -- "$remaining_env" > "$env_target"
  rm -f -- "$remaining_env"
  trap - EXIT
fi
if [ ! -f "$STORAGE_ADMIN_ENV" ]; then
  # The container rebuilds its identities from these at every start, so new
  # values are safe for existing data too.
  mkdir -p .local
  (umask 077 && printf 'S3_ADMIN_ACCESS_KEY=%s\nS3_ADMIN_SECRET_KEY=%s\n' "$(rand_hex 12)" "$(rand_hex 32)" > "$STORAGE_ADMIN_ENV")
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

# Connect over the container network address: the image trusts loopback
# connections without a password, so 127.0.0.1 would not check the password
# the app uses.
postgres_password_ok() {
  compose exec -T -e PGPASSWORD="${POSTGRES_PASSWORD}" postgres sh -c \
    'psql -h "$(hostname -i | cut -d " " -f 1)" -U "$1" -d "$2" -c "SELECT 1"' sh "${POSTGRES_USER}" "${POSTGRES_DB}" \
    >/dev/null 2>&1
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

ts_host=""
if [ "${use_tailscale}" = 1 ]; then
  command -v tailscale >/dev/null 2>&1 || die "tailscale が見つかりません。Tailscale をインストールしてログインしてください"
  ts_status=0
  ts_host="$(tailscale_host)" || ts_status=$?
  case "${ts_status}" in
    0) ;;
    2) die "Tailscale に接続していません。'tailscale up' でログインしてから再実行してください" ;;
    3) die "この tailnet で HTTPS 証明書が有効になっていません。Tailscale の管理画面の DNS 設定で MagicDNS と HTTPS Certificates を有効にしてください" ;;
    *) die "Tailscale の状態を確認できませんでした" ;;
  esac
  # Only for this run: .env stays as it is. The first origin stays first, since
  # it also decides where web passkeys are registered.
  CORS_ORIGINS="${CORS_ORIGINS:-http://localhost:5173},https://${ts_host}"
  VITE_ALLOWED_HOSTS="${VITE_ALLOWED_HOSTS:+${VITE_ALLOWED_HOSTS},}${ts_host}"
  export CORS_ORIGINS VITE_ALLOWED_HOSTS
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
  # 起動時に head を自動作成しないのは意図した動作 (docs/OPERATIONS.ja.md)。
  head_status="$(pnpm --filter @alparts/server --silent exec tsx src/scripts/audit-head-status.ts)" \
    || die "監査記録の状態を確認できませんでした (オブジェクトストレージの起動状態を確認してください)"
  if [ "${head_status}" = "pending" ]; then
    [ "${head_added}" = 1 ] && info "監査記録の保存先を .env に追加しました"
    if [ "${1:-}" != "audit-head-init" ]; then
      die "監査記録の移行が済んでいません。docs/OPERATIONS.ja.md の監査 head 移行手順で確認してから './dev.sh audit-head-init' を一度実行してください"
    fi
    info "監査記録の移行を実行します"
    pnpm --filter @alparts/server audit:head:init
  fi
fi

if [ -n "${ts_host}" ]; then
  info "Tailscale の tailnet 内に https://${ts_host} で公開します"
  sudo tailscale serve --bg --https=443 http://localhost:5173 >/dev/null
  info "Android アプリの接続先には https://${ts_host} を入力してください"
fi

info "開発サーバーを起動します (client: http://localhost:5173 / 停止: Ctrl+C, 全停止: ./dev.sh down)"
exec pnpm dev
