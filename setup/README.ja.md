# 本番用セットアップ

[English](README.md) | 日本語

1台のサーバーに Alparts を本番用にインストールし、運用するためのプログラムです。いくつかの質問に答えると、次の準備をすべて自動で行います。

- リポジトリの [Dockerfile](../Dockerfile) からアプリのイメージを作成
- PostgreSQL 16 と SeaweedFS（S3互換のオブジェクトストレージ）を起動し、用途ごとに分けた認証情報と最小権限のロールを用意
- アプリとデータベース・ストレージの間の通信を、セットアップが作る内部の認証局による TLS で保護
- Caddy による HTTPS での公開と、Let's Encrypt の証明書の自動取得・更新
- データベースの移行と、操作履歴の記録（監査チェックポイント）の初期化
- 音声通話をサーバー経由でつなぐ中継（SFU）
- 登録メールを送るメール送信サーバー（SMTP）への接続確認
- 暗号化したバックアップの毎日の実行（systemd のタイマー）
- デスクトップ・Android アプリの配布用ビルドに必要な、証明書の鍵の pin ファイルの作成
- 最初のアカウントを作るための招待コードの表示

TypeScript で書かれ、Node.js の標準機能だけで動きます。アプリ本体（`packages/`）とは別に、このディレクトリにまとまっています。

## 必要なもの

- Linux（x86_64 または ARM64）のサーバー。メモリー 2 GB 以上、ディスクの空き 10 GB 以上を推奨
- [Docker Engine](https://docs.docker.com/engine/install/) と Docker Compose プラグイン 2.20 以上。ルートレスモードとユーザー名前空間の割り当て（userns-remap）には対応していません
- Node.js 22.18 以上（推奨は 24）。例えば Ubuntu では `sudo snap install node --classic --channel=24`
- git
- ドメイン名と、それをこのサーバーの IPv4 アドレスに向けた DNS の A レコード
- インターネットからこのサーバーへの次の受信の許可（クラウドのセキュリティグループやファイアウォール）
  - 80/tcp、443/tcp、443/udp（Web と証明書の取得）
  - 40000/udp、40000/tcp（音声通話をサーバー経由でつなぐ場合）
- 推奨: メール送信サーバー（SMTP）のホスト名、ポート、送信元アドレス、ログイン情報
- 推奨: バックアップ用の age の公開鍵。このサーバーとは別の安全な端末で、age 1.3 以降の `age-keygen -pq -o backup-key.txt` で作成し、表示される `age1pq1…` の公開鍵を使います。秘密鍵のファイルはサーバーに置きません

## インストール

```bash
sudo git clone https://github.com/SYZD-research/alparts.git /opt/alparts
cd /opt/alparts
sudo ./setup/alparts-setup
```

`sudo` を付けずに実行すると、自分の Node.js を使い、必要なときに管理者のパスワードを求めます（nvm などで入れた Node.js を使う場合はこちら）。

質問は次の4つです。答えたあとで内容を確認してからインストールします。

1. **公開するアドレス** — 利用者が接続するドメイン名。DNS がこのサーバーを指しているか、ポート 80 で接続できるかを確認します
2. **登録メール** — SMTP の設定。入力した情報で実際に接続とログインを試します。メールを使わない場合は確認なしで登録できるようにできますが、招待コードを持つ人が、登録を試すことで、あるメールアドレスのアカウントがすでにあるかどうかを知ることができるようになります
3. **音声通話** — 通話をこのサーバー経由でつなぐか（推奨）。つなぐ場合は、利用者が接続するこのサーバーの公開 IPv4 アドレス（既定は DNS の A レコード）
4. **バックアップ** — 毎日のバックアップの公開鍵と時刻

初回はアプリのイメージの作成に 10〜20 分ほどかかります。途中で止まっても、もう一度実行すると続きから再開します。完了すると、公開したアドレスと、最初のアカウントを作るための招待コードを表示します。

1. 表示されたアドレスを開き、「アカウント作成」を選びます
2. 「招待コード」に表示されたコードを入力します。このコードで作れるのは、このサーバーの最初のアカウントだけです（`sudo ./setup/alparts-setup invite-code` でもう一度表示できます）
3. ログイン後、左側の「＋」からワークスペースを作り、ワークスペースの管理画面の「招待を管理」からメンバーを招待します

### 回答ファイルによるインストール

質問の回答を JSON ファイルで渡すと、端末での入力なしでインストールできます。

```json
{
  "domain": "chat.example.com",
  "email": {
    "mode": "smtp",
    "host": "smtp.example.com",
    "port": 587,
    "security": "starttls",
    "from": "no-reply@example.com",
    "user": "no-reply@example.com",
    "passwordFile": "/root/smtp-password"
  },
  "voice": { "relay": true, "publicAddress": "203.0.113.10" },
  "backup": { "recipient": "age1pq1…", "time": "04:00" }
}
```

```bash
sudo ./setup/alparts-setup install --answers answers.json
```

| 項目 | 内容 |
| --- | --- |
| `domain` | 必須。公開するドメイン名 |
| `email.mode` | 必須。`smtp` か、メールでの確認をしない `disabled` |
| `email.security` | `starttls`（既定、ポート 587）か `tls`（ポート 465） |
| `email.user` | ログインしない場合は省略。ログインする場合は `password` か、パスワードだけを書いたファイルの `passwordFile` が必要 |
| `voice.relay` | 通話をサーバー経由でつなぐか（既定は `true`） |
| `voice.publicAddress` | 省略すると、ドメイン名の A レコードを使います |
| `backup` | 省略するとバックアップを設定しません |
| `acmeEmail` | 省略可。証明書の発行元に登録する連絡先 |
| `certificates` | `public`（既定、Let's Encrypt）。`local` は公開の DNS がない試験用で、ブラウザーは警告を出します |

SMTP に接続できない場合は止まります。`--yes` を付けると、警告を出して続けます。

## コマンド

| コマンド | 内容 |
| --- | --- |
| `sudo ./setup/alparts-setup` | インストール（`install` と同じ） |
| `… configure` | インストール時の回答（アドレス、メール、通話、バックアップ）を変更して反映 |
| `… status` | 各サービス、証明書の期限、通話、メール、バックアップの状態 |
| `… start` / `stop` / `restart` | 起動・停止・再起動。停止してもデータは残ります |
| `… update` | `git pull` などで取得した、リポジトリの今の内容に更新 |
| `… backup` | 今すぐバックアップを作成 |
| `… backup-setup` | 毎日のバックアップを設定（`--disable` で停止） |
| `… pins` | デスクトップ・Android アプリ用の pin ファイルを書き出す（`--rotate` で鍵を切り替える） |
| `… invite-code` | 最初のアカウントの招待コードを表示 |
| `… logs [app\|proxy\|postgres\|object-storage]` | 動作の記録を表示 |

すべてのコマンドに `--lang ja|en`（表示する言語。既定は OS の言語設定）と `--help` を使えます。

## 構成

```text
              インターネット
     80/443（HTTPS）│                 │ 40000 UDP/TCP（通話の中継）
             ┌──────▼──────┐          │
             │ proxy        │ Caddy    │
             └──────┬──────┘          │
        edge ネットワーク（固定のアドレス範囲）
             ┌──────▼─────────────────▼─────┐
             │ app（Alparts のサーバーと中継）│
             └──────┬───────────────┬───────┘
        backend ネットワーク（外部への経路なし、TLS で接続）
             ┌──────▼──────┐ ┌──────▼─────────┐
             │ postgres     │ │ object-storage  │
             └─────────────┘ └────────────────┘
```

アプリと移行処理の定義はリポジトリの [compose.production.yml](../compose.production.yml) をそのまま使い、セットアップが生成する `compose.json` を重ねて、データベース・ストレージ・HTTPS の公開・通話の中継・バックアップの道具を加えます。Compose のプロジェクト名は `alparts-production` です。

| パス | 内容 |
| --- | --- |
| `/etc/alparts-production/setup.json` | 回答とインストールの状態 |
| `/etc/alparts-production/secrets/` | 認証情報（ディレクトリは root だけが開けます。各ファイルはモード 0400 で、アプリが読むものはアプリのユーザーの所有） |
| `/etc/alparts-production/compose.env`、`compose.json` | Compose 用の生成ファイル |
| `/etc/alparts-production/proxy/Caddyfile` | HTTPS の公開の設定 |
| `/etc/alparts-production/postgres/pg_hba.conf` | PostgreSQL の接続規則 |
| `/etc/alparts-production/transport-pins.json` | デスクトップ・Android アプリ用の pin ファイル |
| `/var/lib/alparts-production/backups/` | 暗号化したバックアップ |
| `/var/log/alparts-production/` | 実行ごとの詳しい記録（最新の 60 件） |
| Docker のボリューム `alparts-production_*` | データベース、ファイル、証明書、操作履歴の基点 |

生成ファイルはセットアップを実行するたびに書き直されます。手で変更せず、`configure` を使ってください。Compose を直接使う場合は次のようにします。

```bash
sudo docker compose --project-name alparts-production --project-directory /opt/alparts \
  --env-file /etc/alparts-production/compose.env \
  -f /opt/alparts/compose.production.yml -f /etc/alparts-production/compose.json ps
```

## セキュリティの設計

- **認証情報** — 初回に乱数から生成し、その後は上書きしません。パスワードのペッパーと監査の鍵は、失うと既存のデータを使えなくなります。`/etc/alparts-production` の写しを暗号化して、サーバーとは別の場所に保管してください
- **PostgreSQL** — 移行を行いスキーマを所有する `alparts_owner`、行の読み書きだけができる `alparts_app`（アプリ）、読み取りだけの `alparts_backup` に分けています。スーパーユーザーはコンテナー内のローカルソケットからだけ使え、パスワードでは接続できません。ロールのパスワードは SCRAM の検証子として設定し、平文をサーバーに送りません
- **TLS** — セットアップが作る内部の認証局で PostgreSQL と SeaweedFS の証明書を発行し、アプリは証明書を検証して接続します。TLS でない接続は PostgreSQL が拒否します
- **ネットワーク** — データベースとストレージは、外部への経路がない内部ネットワークにだけつながり、ホストのポートにも公開しません
- **ストレージの権限** — バケットを作る管理者（アプリには渡しません）、2つのバケットだけを扱うアプリ、アプリのバケットを読むだけのバックアップ用に分けています
- **HTTPS の公開** — ヘルスチェックとメトリクスは外部に公開しません。リクエストの本文は受け取り終えてからアプリへ送ります。アプリが信頼するクライアントのアドレスの転送元は、固定のアドレスを持つ proxy だけです
- **操作履歴** — 監査チェックポイントは初回のインストールで一度だけ作ります。失われた場合は改ざんの可能性があるため自動では作り直さず、[運用ガイド](../docs/OPERATIONS.ja.md)の手順での確認を求めます
- **アプリのコンテナー** — compose.production.yml のとおり、読み取り専用のルート、capability なし、`no-new-privileges`、root 以外のユーザー、メモリーと CPU の上限で動かします。Node.js のパーミッションモデル（`--permission`）は外して起動します。現在の Node.js（22.22 と 24.22 で確認）は、パーミッションモデルを有効にすると `fsync` を使えなくなり、監査チェックポイントを書き込めずに、最初の書き込みのあとアプリが書き込みを受け付けなくなるためです。`--disallow-code-generation-from-strings` などほかの指定はそのまま使います
- **バックアップ** — age の公開鍵に対して暗号化します。復元に必要な秘密鍵はサーバーに置きません

## 更新

```bash
cd /opt/alparts
sudo git pull
sudo ./setup/alparts-setup update
```

新しいバージョンのイメージを作成し、アプリを止めて、バックアップを作り（設定している場合）、データベースを移行してから起動します。新しいバージョンが起動しなかった場合、データベースの移行が行われていなければ、前のバージョンに自動で戻します。移行が行われたあとは前のバージョンに戻せないため、更新前のバックアップと[運用ガイド](../docs/OPERATIONS.ja.md)の手順で対応します。イメージは今のものと1つ前のものを残します。

## バックアップと復元

毎日、設定した時刻（既定は 04:00、10 分以内のずれあり）にアプリを数分止め、[scripts/backup.sh](../scripts/backup.sh) で PostgreSQL のダンプとファイルを1つの暗号化したファイルにまとめます。30 日より古いものを、少なくとも 7 件を残して削除します。`systemctl list-timers alparts-production-backup.timer` で次の実行時刻を、`journalctl -u alparts-production-backup` で結果を確認できます。

サーバーごと失った場合に備えて、`/var/lib/alparts-production/backups/` を別の場所へ定期的にコピーしてください。バックアップから実際に復元できるかは、隔離した環境で [scripts/restore-verify.sh](../scripts/restore-verify.sh) を使って確認します（[バックアップと復元](../docs/BACKUP.ja.md)を参照）。監査の外部の基点（`alparts-audit` バケット）は、通常のバックアップと復元の対象外です。

## デスクトップ・Android アプリ

配布用のデスクトップ・Android アプリは、接続先の証明書の鍵を pin として組み込み、それ以外の鍵の証明書では接続しません。セットアップは証明書の鍵を自分で作って Caddy に渡し、更新のたびに同じ鍵を使わせます。

```bash
sudo ./setup/alparts-setup pins
ALPARTS_TRANSPORT_PINS_FILE=/etc/alparts-production/transport-pins.json pnpm desktop:dist
cd packages/android && ./gradlew -PalpartsTransportPinsFile=/etc/alparts-production/transport-pins.json assembleRelease
```

pin ファイルには、今の鍵と予備の鍵の2つが入っています。`pins --rotate` で予備の鍵に切り替え、新しい予備の鍵を作ります。切り替える前のファイルで作ったアプリは、予備の鍵を知っているためそのまま接続できます。切り替えたあとは、新しいファイルでアプリを作り直してください。サーバーが不正に操作された場合は、予備の鍵も漏れたものとして扱います。

## 対応していないこと

- 1台のサーバーでの構成だけを扱います。複数台での冗長化やフェイルオーバーは Alparts 自体が対応していません
- 監査の独立した外部証跡（witness）とメトリクスは設定しません。必要な場合は[デプロイガイド](../docs/policies/DEPLOYMENT.ja.md)と[運用ガイド](../docs/OPERATIONS.ja.md)を参照してください
- メール送信サーバーの確認は接続とログインまでで、実際のメールは送りません
- 通話の中継が利用者に知らせるのは IPv4 のアドレスだけです
- バックアップの別の場所へのコピーと、復元の確認は自動では行いません

## 困ったとき

- `sudo ./setup/alparts-setup status` で各サービスの状態を、`logs app` などで動作の記録を確認します
- 失敗したときに表示される「詳しい記録」のファイルに、実行したコマンドと出力が残っています（認証情報は書き込みません）
- 証明書を取得できない場合は、DNS の A レコードと、ポート 80・443 への受信の許可を確認してください。準備が整うと自動で取得します
- ポートがほかのプログラムで使われている場合は、そのプログラム（別の Web サーバーなど）を止めてから実行してください

## アンインストール

停止してコンテナーを削除します。データ（ボリューム）は残ります。

```bash
sudo docker compose --project-name alparts-production --project-directory /opt/alparts \
  --env-file /etc/alparts-production/compose.env \
  -f /opt/alparts/compose.production.yml -f /etc/alparts-production/compose.json down
sudo systemctl disable --now alparts-production-backup.timer
sudo rm /etc/systemd/system/alparts-production-backup.service /etc/systemd/system/alparts-production-backup.timer
```

データも完全に消す場合だけ、上の `down` に `--volumes` を付け、`/etc/alparts-production` と `/var/lib/alparts-production` を削除します。元に戻せないため、必要なバックアップと認証情報の写しがあることを確かめてから行ってください。

## 開発

```bash
pnpm --filter @alparts/setup typecheck
pnpm --filter @alparts/setup test
```

テストは Node.js の標準のテストランナーで動き、Docker を使いません。
