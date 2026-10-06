# Phase 1のバックアップと復元の検証

[English](BACKUP.md) | 日本語

`scripts/` のスクリプトは、PostgreSQLとS3互換のオブジェクトバケット（推奨構成ではSeaweedFS）を、受信者の鍵で暗号化した1つのバックアップにまとめます。復元と検証は、使い捨てであることを明示した復元先でだけ行います。これらはPhase 1の単一ノード構成向けのもので、本番の災害復旧の仕組みではありません。

## 安全のための前提

- バックアップの間は、アプリケーションによる書き込みをすべて止めてください。データベースのダンプはPostgreSQLのカスタム形式の一貫したスナップショットですが、PostgreSQLとオブジェクトストアは同じトランザクションを共有しません。`ALPARTS_BACKUP_QUIESCED=YES_WRITES_ARE_STOPPED` は運用者による明示的な宣言で、スクリプト自身はサービスを停止しません。
- できるだけ、短期間だけ有効な読み取り専用のバックアップ用IDを使ってください。オブジェクトストアのIDに必要なのは、元のバケットの一覧と読み取りだけです（SeaweedFSでは `Read:<bucket>` と `List:<bucket>`）。PostgreSQLには、完全な `pg_dump` を取れるだけの読み取り権限が必要です。
- 平文のダンプ、オブジェクトのデータ、一覧、チェックサム、マニフェストは、モード `0700` の `mktemp` ディレクトリの下にだけ置き、trapで削除します。公開する成果物はモード `0600` で、`age` の受信者の公開鍵に対して暗号化します。
- `TMPDIR` には、十分な容量のある暗号化されたローカルのファイルシステム（または適切な容量の保護されたtmpfs）を指定してください。trapは、正常終了、エラー、HUP、INT、TERMに対応します。`SIGKILL`、電源断、ストレージ装置の故障の後は、どのプロセスも後片付けできません。また、通常の削除は、SSDやスナップショット上での安全な消去を保証するものではありません。
- 成果物には、暗号化された添付ファイルのオブジェクトと、平文の256×256 PNGのプロフィール画像（製品内ではワークスペースのメンバーに見えるもの）が含まれます。オブジェクト名、サイズ、データベースのメタデータは機密情報のため、外側の `age` 暗号化で保護します。
- サーバーの `AUDIT_INTEGRITY_KEY`、外部の監査チェックポイントのファイル、デプロイの認証情報、リバースプロキシの設定、ブラウザーの端末の秘密鍵は含まれません。監査の鍵、チェックポイントの証跡、デプロイの設定は、別に暗号化し、独立したアクセス制御のもとでバックアップしてください。ブラウザーの端末の秘密鍵は、意図的にクライアント側だけで保持します。
- `age` の受信者への暗号化は、機密性とペイロードの完全性を提供しますが、誰がバックアップを作成したかは証明しません。公開されている受信者の鍵を持つ人なら、別の有効な成果物を作成できます。作成元が重要な場合は、受け渡しの経路を保護し、暗号化された成果物のダイジェストを、独立して認証されたシステムに記録してください。

バックアップを行うホストには、元のPostgreSQLサーバーと同じメジャーバージョンの `pg_dump`、検証用サーバーと同じメジャーバージョンの `pg_restore`、`psql`、[`rclone`](https://rclone.org/) 1.75.1以降（それより前のバージョンは拒否します。1.75.1で一覧取得の上限の扱いが修正されました）、`age`、`jq`、GNU `tar`、通常のGNU coreutilsをインストールしてください。スクリプトは、ダンプや復元の前に、PostgreSQLのツールとサーバーのメジャーバージョンを確認します。これにより、新しいクライアントが古い復元先の理解できないセッション設定を出力することを防ぎます。どちらのスクリプトも、依存するツールや必須の設定が欠けている場合は、処理を始める前に失敗します。秘密情報と記載した設定は `*_FILE` で渡せます。そのファイルには、グループやその他のユーザーの権限ビットを付けないでください。

PostgreSQLへの接続には、モード `0600` の[libpqのサービスファイル](https://www.postgresql.org/docs/current/libpq-pgservice.html)を使います。PostgreSQLの子プロセスに渡すのは、そのパスと選んだセクション名だけです。スクリプトは接続URIを解析せず、パスワードをコマンドライン引数や子プロセスの環境変数に置きません。オブジェクトストアの認証情報は、シェルの組み込みコマンドで、trapで後片付けするモード `0700` の作業ディレクトリ内のモード `0600` の `rclone` 設定ファイルに書き込みます。コマンドライン引数には現れません。読み込んだ秘密情報の設定と、環境にある `RCLONE_*` や `AWS_*` の変数は、子プロセスに引き継ぐ環境から取り除くため、ストレージのクライアントを設定するのはそのファイルだけです。どちらのスクリプトも、シェルのトレースを有効にしたり、設定した認証情報を表示したりしません。リモートのPostgreSQLとオブジェクトストアには、認証付きのTLSを使ってください。暗号化されないHTTPのオブジェクトストアのURLは、ループバックアドレスでだけ受け付けます。以前の `MINIO_*` の設定は拒否します。下記の `S3_*` の名前を使ってください。

## バックアップを作成する

オフラインで `age-keygen -pq -o identity.txt` によりハイブリッドのIDを作成し、`age-keygen -y identity.txt > recipient.txt` で受信者の公開鍵を書き出します。IDはアプリケーションのノードの外に保管してください。新しいバックアップには `age1pq1...` の受信者とage 1.3.0以降が必要で、従来方式の受信者は拒否します。以前のバックアップは引き続き復元できます。再暗号化しても、第三者がすでに入手したコピーは保護できません。[ageの公式ドキュメント](https://github.com/FiloSottile/age#post-quantum-keys)を参照してください。

アプリケーションの書き込みを止めた状態で、次を実行します。

```bash
# /run/credentials/alparts-backup-pg-service.conf (mode 0600):
# [alparts_backup]
# host=db.internal.example
# port=5432
# dbname=alparts
# user=alparts_backup
# password=replace-with-the-backup-role-password
# sslmode=verify-full
# sslrootcert=/run/credentials/postgresql-ca.pem
export DATABASE_SERVICE_FILE=/run/credentials/alparts-backup-pg-service.conf
export DATABASE_SERVICE=alparts_backup
export S3_URL=https://objects.internal.example
export S3_ACCESS_KEY_FILE=/run/credentials/alparts-backup-s3-access-key
export S3_SECRET_KEY_FILE=/run/credentials/alparts-backup-s3-secret-key
export S3_BUCKET=alparts
# Optional: export S3_REGION=us-east-1
export BACKUP_AGE_RECIPIENT_FILE=/run/credentials/alparts-backup-recipient.txt
export BACKUP_OUTPUT_DIR=/mnt/encrypted-backups
export ALPARTS_BACKUP_QUIESCED=YES_WRITES_ARE_STOPPED

scripts/backup.sh
```

標準出力に出るのは、最後の成果物のパスの1行だけです。暗号化されたペイロードには次が含まれます。

- `--serializable-deferrable` で作成した、PostgreSQLのカスタム形式のダンプ1つ
- 設定したバケットから複製した、すべてのオブジェクトの最新のデータ
- テーブルごとの行数、添付ファイルとプロフィール画像のオブジェクトの参照、オブジェクトの一覧、SHA-256チェックサム、ツールのバージョン、1つの実行ID、1つのUTCの作成時刻

スクリプトは、既存の出力を置き換えません。公開は出力先のファイルシステム内でのアトミックなハードリンクで行うため、同じ名前で競合しても上書きは起きません。

## 復元して検証する

隔離された検証用のPostgreSQL・オブジェクトストアに、新しい空のデータベースと新しい空のバケットを用意してください。本番の接続先は絶対に使わないでください。安全確認のため、受け付ける名前を意図的に次に限っています。

- データベース: `alparts_restore_<suffix>` または `alparts_verify_<suffix>`
- バケット: `alparts-restore-<suffix>` または `alparts-verify-<suffix>`

復元先のデータベースには、スーパーユーザー、`CREATEROLE`、`CREATEDB`、レプリケーション、`BYPASSRLS`、サーバーのファイルやプログラムの権限を持たない専用の所有者を使ってください。スクリプトは、これらの権限を持つ、または取得できるロールを拒否します。検証用のオブジェクトストアのIDには、指定した使い捨てのバケットへのアクセスだけを与えてください。

`prod`、`production`、`live`、`primary` を含む名前は拒否します。既定の `alparts` バケットと、元のバケットと同じ名前の復元先のバケットも拒否します。名前が条件に合うだけでは十分ではありません。スクリプトは、PostgreSQLにシステム以外のスキーマとオブジェクトを問い合わせ、バケットを再帰的に一覧し、どちらも空でなければ拒否します。フォルダーの目印のオブジェクト（`/` で終わるキー）は、アプリケーションのキーの文法に含まれません。元または復元先にそれが含まれている場合は拒否するため、目印だけを含むバケットを空と取り違えることはありません。

以前のMinIOを使ったスクリプトで作成したバックアップも、引き続き復元できます。そのマニフェストには、以前のフィールド名で元のバケットが記録されています。

2つの使い捨ての復元先を占有した状態で、検証を実行します。

```bash
# Use a separate mode-0600 service file containing an alparts_verify section
# for the unprivileged owner of the disposable database.
export VERIFY_DATABASE_SERVICE_FILE=/run/credentials/alparts-verify-pg-service.conf
export VERIFY_DATABASE_SERVICE=alparts_verify
export VERIFY_S3_URL=https://objects-verify.internal.example
export VERIFY_S3_ACCESS_KEY_FILE=/run/credentials/alparts-verify-s3-access-key
export VERIFY_S3_SECRET_KEY_FILE=/run/credentials/alparts-verify-s3-secret-key
export VERIFY_S3_BUCKET=alparts-verify-20260826
export RESTORE_AGE_IDENTITY_FILE=/run/credentials/alparts-backup-age-identity
export ALPARTS_RESTORE_ACK=RESTORE_TO_EMPTY_DISPOSABLE_TARGETS

# Optional policy limits; defaults shown.
export RESTORE_MAX_BYTES=1099511627776
export RESTORE_MAX_ARCHIVE_ENTRIES=1000000
export RESTORE_MAX_FILE_BYTES=1099511627776
export RESTORE_MAX_EXPANDED_BYTES=1099511627776

scripts/restore-verify.sh /mnt/encrypted-backups/alparts-backup-<run-id>.tar.age
```

ファイルシステムへ展開する前に、スクリプトはageの外装を検証し、復号したアーカイブの論理的なエントリー数、展開後の各通常ファイルのサイズ、展開後の合計バイト数を制限します。保存時の圧縮されたサイズではなく、GNU tarの論理サイズを使い、圧縮されたスパースや未対応の形式を検出した場合は拒否します。4つのリソース上限の設定は、いずれも18桁以下の正の整数でなければならず、ファイルごとの上限は合計の上限を超えられません。バイト数の上限は、保護された作業用ボリュームのファイルシステムのクォータと、安全に使える空き容量の両方より小さく設定してください。1 TiBの既定値はプロトコル上の上限で、推奨する容量ではありません。続いてスクリプトは、アーカイブのパスとエントリーの種類、ペイロードのチェックサム、オブジェクトの一覧、添付ファイルの参照、カスタム形式のダンプの読み取り、復元先の名前、復元先が空であることを検証します。`pg_restore` は、`--clean`、所有者の復元、権限の復元を使わずに、1つのトランザクションで実行します。その後、まだ空の検証用バケットにオブジェクトをコピーし、改めてダウンロードして、すべてのキー、バイト数、SHA-256チェックサムを比較します。データベースのすべてのテーブルの行数と添付ファイルの参照も、元のスナップショットと比較します。

スクリプトは、スキーマの削除、バケットの消去、移行の実行、途中で失敗した復元先の後片付けを一切行いません。検証用のバケットに別の誰かが同時に書き込める場合、復元先が空であるという前提を保証できません。この実行のために、認証情報とバケットを隔離してください。

## 移行前の確認

書き込みを止めた後、移行を適用する前に、次のラッパーを使います。

```bash
scripts/pre-migration-backup.sh 0006_example_change
```

これは、理由として `pre-migration:<label>` を記録し、暗号化された成果物を作成するだけで、移行は実行しません。その成果物を `restore-verify.sh` で復元・検証し、`VERIFIED <run-id>` の結果を得てから、別のデプロイ手順で移行を適用してください。

## 監視付きの定期実行と保持

systemdでの構成では、`deploy/alparts-backup.service` と `deploy/alparts-backup.timer` をインストールします。毎日実行される永続タイマーは `scripts/backup-under-systemd.sh` を呼び出し、次の処理を行います。

1. ブロックしないホストのロックを取り、バックアップが重ならないようにします。
2. 設定したアプリケーションのサービスが稼働中でない場合、状態を変更しません。
3. `backup.sh --preflight` を実行し、データベースやストアに触れずにツール（rcloneのバージョンを含む）と設定を確認します。依存するツールが欠けていても、アプリケーションが止まることはありません。
4. アプリケーションを停止し、停止したことを確認します。
5. 書き込み停止の確認の宣言を、正確な値で `backup.sh` に渡します。
6. 正常終了、エラー、HUP、INT、TERMのいずれでも、必ずアプリケーションの再起動を試みます。
7. アプリケーションが再び稼働してから、保持期間の処理を行います。

タイマーが作成するのはローカルの成果物です。それを、独立して管理された別ホスト・別リージョンのストレージにコピーする処理は、監視付きの別のプロセスで行ってください。バックアップのユニットには `Requires=alparts.service` を付けないでください。バックアップは自身の処理の間、意図的にそのサービスを停止するためです。

`scripts/prune-backups.sh` は、`--apply` を明示しない限り試行（ドライラン）だけを行います。範囲の広いディレクトリを拒否し、暗号化されたバックアップの正確な名前だけを対象にし、少なくとも `BACKUP_MINIMUM_COPIES`（既定は7）を残し、`BACKUP_RETENTION_DAYS`（既定は30）を必須とし、`BACKUP_PRUNE_ACK=DELETE_EXPIRED_ENCRYPTED_BACKUPS` を指定した場合にだけ削除します。ドライランの出力を確認し、可能であれば、保存先をストレージ側のバージョン管理やオブジェクトロックで保護してください。

## 制限

この手順でバックアップするのは、書き込みを止めた時点の論理的なデータベースのスナップショット1つと、オブジェクトの最新のデータです。次のものは**提供しません**。

- 任意の時点への復旧（PITR）や、WALの継続的なアーカイブ
- WORMやオブジェクトロックによる保持、侵害されたバックアップ用IDからの保護
- 別拠点への自動複製や、ストレージ側の変更できない媒体のライフサイクル管理（提供するのは安全なローカルでの保持だけです）
- 自動復旧、フェイルオーバー、RTO/RPOの保証、アプリケーション全体の災害復旧の実施テスト
- オブジェクトのバージョン履歴、バケットのポリシー、ライフサイクルのルール、タグ、すべてのオブジェクトのメタデータ
- ブラウザーの端末の秘密鍵のサーバー側での復旧

暗号化された成果物を、独立して管理された別拠点のストレージにコピーし、保持期間を設定・監視し、復元の訓練を定期的に計画してください。スクリプトが成功したことは、この成果物から、テストした復元先にデータベースの行と最新の暗号化されたオブジェクトのデータを再作成できることを示します。サービス全体の復旧や、クライアント側で復号できることを示すものではありません。

## 現在のツリーでの検証の記録

2026-08-30の実行 `20260830T094605Z-3e2bb09737cb` で、移行済みの現在の29テーブルのスキーマと、内容を参照できない128バイトのオブジェクト1つを、112,856バイトのageの成果物にバックアップしました。権限を持たないロールが所有する空のデータベースと、別の名前の空のバケットへの復元で `VERIFIED` が返り、テーブルの行数、マニフェストとチェックサム、オブジェクトの一覧、再ダウンロード、オブジェクトのSHA-256がすべて一致しました。参照されているオブジェクトが欠けている場合と、復元先の名前が無効な場合に、公開や復元の前に失敗することも別途確認しました。[検証の記録全体](./VERIFICATION.md)（英語）を参照してください。
