# Phase 1 Prototype operations

最終更新: 2026-09-04

この文書はWindows・macOS・Linux desktop / Web / single-node / basic per-channel key / text中心＋最大8人P2P音声のprototypeだけを対象とする。Embargoed vulnerability、credential、その他のhigh-impact secretを扱うproduction approvalではない。

## Startup contract

1. PostgreSQLとオブジェクトストレージ（推奨はSeaweedFS）へ独立したleast-privilege credentialを用意し、remote接続ではauthenticated TLSを使う。
2. Secretは`*_FILE`、systemd credential、またはdeployment secret managerから渡す。値をrepository、image、command line、logへ入れない。
3. Migrationはapplication runtimeとは別のdeployment identityで、application writeを停止した状態で実行する。不可逆変更の前は後述のbackup gateを通す。
4. Processをnon-root userで起動し、public TLSは信頼するreverse proxyで終端する。PostgreSQL、オブジェクトストレージ、probe、management endpointをpublic networkへ出さない。
5. Probeを別々にrouteする。

   - `/health/startup`: startupが完了したか。
   - `/health/live`: process event loopがHTTPを処理できるか。
   - `/health/ready`: drain中ではなく、PostgreSQL、設定したオブジェクトストレージのbucket（起動後に消えていないことを毎回確認する）、audit checkpointが利用可能か。

Processはlisten前にaudit HMAC chainを全件検証する。失敗はsecurity incidentである。起動させる目的でaudit rowやcheckpointを書き換えたり削除したりしない。

Serverのlisten addressはIP literalだけを受理し、`BIND_HOST` 未設定時は `127.0.0.1` に限定する。Example systemd unitもloopbackへ固定する。Container imageの既定もloopbackであり、production Composeだけがcontainer network内で `BIND_HOST=0.0.0.0` を明示し、host側は`127.0.0.1`へpublishする。TLS reverse proxyとnetwork policyを必ず前段に置く。オブジェクトストレージへのrequestは `S3_REQUEST_TIMEOUT_MS`（既定10秒）の絶対期限を持ち、object listingは件数・key byte・prefix grammar・absolute deadlineも制限する。添付のdownloadは、GET応答の長さを保存時のサイズと照合し、そのサイズを超えるbyteはclientへ送らない。

新規登録では、入力されたメールアドレスへ6桁の確認コード（15分有効、誤入力5回で無効）を送り、そのアドレスの持ち主であることを確かめる。送信には `SMTP_HOST`・`SMTP_FROM`（必要なら `SMTP_USER`・`SMTP_PASSWORD_FILE`）を設定する。Productionでは `SMTP_SECURE=true`（最初からTLS）またはSTARTTLSを必須とし、証明書を検証する。Productionで`SMTP_HOST`が未設定の場合、既存accountのloginはそのまま使えるが、新規登録は`EMAIL_VERIFICATION=disabled`で明示的に確認を無効にしない限り拒否され、起動時に`registration.unavailable`の警告を出す。開発環境ではSMTPがなければメールをmemoryに保持してlogへ出す。既に登録済みのアドレスにはコードではなく案内メールを送るため、応答からaccountの有無は分からない。この変更より前に作成されたaccountのメールアドレスは確認されていない。

音声通話は `VOICE_ICE_SERVERS_JSON` に最大4件のoperator-controlled STUN/TURNをJSONで設定できる。既定の空配列は第三者serviceへ接続しない代わりに、direct candidateで到達できないNAT間の通話を保証しない。TURN credentialは通話参加clientへ渡るため、service管理者credentialを流用せず、短命・最小権限のcredentialを発行する。TURNはauthenticated TLS（`turns:`）を優先し、public Internetへ無制限relayとして開放しない。P2P meshは最大8人であり、media serverとして水平scaleする構成ではない。

AttachmentのDB rowとオブジェクトストレージ上のobjectは分散transactionではない。Upload statusはDB内で認可とchunk metadataをsnapshotした後、DB connection/lockを解放してからobjectを照合する。その後のchunk PUT/finalizeは改めてlockと認可を取得する。DB失敗後に残るobjectは期限切れcleanupで回収し、download開始後に失権しても送信開始済みciphertext streamは途中回収できない。これらをatomic cross-store commitまたはremote erasureと説明しない。

## Audit checkpoint

2026-09-30以降はローカル checkpoint に加え、別のオブジェクトストレージ bucket に最新の署名済み head を保持する。`AUDIT_HEAD_BUCKET`（既定は `${S3_BUCKET}-audit`）と `AUDIT_HEAD_OBJECT_KEY`（配備ごとに固定した識別子）を設定する。通常の起動では欠落した head を作らない。DB・checkpoint file の両方を過去へ戻しても、この head が保持されていれば再起動後に拒否する。

監査 head 移行手順（既存配備）:

1. アプリを停止し、独立保管した記録と現在の監査チェーンが一致することを確認する。初期化コマンドの HMAC 検査だけでは、移行前に起きた正しい署名付きの末尾切断を判別できない。
2. 通常の画像・添付ファイルとは別の `AUDIT_HEAD_BUCKET` を作成する。アプリにはこの bucket の `s3:GetBucketLocation` / `s3:ListBucket` と対象 head の `s3:GetObject` / `s3:PutObject` を許可する。削除権限は不要。DB・checkpoint file を修復する担当者とバックアップ復元用の identity には head の書換・削除権限を与えない。
3. 固定した `AUDIT_HEAD_OBJECT_KEY` と bucket を環境設定に保存し、通常と同じ DB・監査鍵・checkpoint path で `pnpm --filter @alparts/server audit:head:init` を一度実行する。配布イメージでは `node packages/server/dist/scripts/initialize-audit-head.js`。既存 head は上書きしない。新規配備は `audit:checkpoint:init` が両方を作成する。
4. 再起動して readiness を確認する。以降、識別子・bucket を起動ごとに変更せず、head を通常のデータバックアップと一緒に過去へ復元しない。欠落時に初期化を自動再実行しない。

DB commit → ローカル checkpoint の fsync/rename → head の保存、の順に更新する。途中障害は次の書込みを停止する。ローカル checkpoint が head より進んだ状態は、再起動時にチェーン全体と両方の anchor を検証してから前進させる。checkpoint と head の読取りも監査書込みと直列化し、正常な同時更新を巻き戻しと誤判定しない。

この追加 bucket は WORM ではない。DB・ローカルファイル・head のすべてを書き戻せる管理者やサーバー全体の侵害は別の能力であり、局所的な検証だけでは同時巻き戻しを判別できない。独立 witness は引き続き利用できる。head 保存前に停止した commit、witness 後の記録については既存の限界を保つ。通常の backup/restore は `S3_BUCKET` だけを扱うため、head は含めず独立して保全する。

Newest database audit rowの削除を検出するには、`AUDIT_CHECKPOINT_PATH` をPostgreSQL operatorとはwrite/delete authorityを分離したmountまたはstorageへ置く。FileはHMAC認証され、audit commit後にatomic updateされる。初回deploymentではserverを停止したまま、productionと同じdatabase、`AUDIT_INTEGRITY_KEY`、checkpoint pathを設定して `pnpm --filter @alparts/server audit:checkpoint:init` を一度だけ実行する。その後 `AUDIT_CHECKPOINT_REQUIRED=true` でserverを起動する。既存checkpointがある場合、このcommandは上書きしない。

Required modeでは空chainを含むcheckpoint欠落、参照row/hashの不一致、rollback、tail切断、checkpoint read/write失敗をstartup/readiness/権威的writeでfail closedにする。Message create/edit/delete/replay、reaction/pin、preference/bookmarkとsecurity/administration mutationはstateとaudit rowを同一transactionへ入れる。Read positionとprovisional upload chunk metadata/cleanupは専用audit eventを増やさないが、同じprocess-local admissionを通る。通常appendとcheckpoint更新は同じPostgreSQL advisory lock内で現在anchorのHMACとDB tailへのdescendant関係を検証し、外部fileは比較対象が変わっていない場合だけatomicに置換する。Integrity failureはprocess内でstickyになり、通常のserver起動やaudit appendは欠落checkpointまたは切断されたsuffixを再作成・再署名しない。欠落時に再provisionすると切断後のchainを新しい正史として承認してしまうため、incident responseで独立保管したcheckpoint/backupと照合するまで実行しない。

State mutationとaudit rowは同じDB transactionでcommitするため、その直後のcheckpoint I/Oだけが失敗した場合、既にcommitしたmutationは成功として一度だけ返す。以後のaudited/guarded authoritative mutationとreadinessはfail closedとなる。Storageの一時的な障害など、integrity failureでないcheckpoint I/O失敗は、次のmutationまたはreadiness確認の時点で（最短2秒間隔で）同じchain検証付きで書き直し、成功すれば自動的に受付を再開する。Integrity failureは引き続きstickyで、operatorの復旧が必要である。Audit headの読み書きは、利用者のdownloadと共有しない専用のobject storage接続と同時実行枠を使う。Operatorは「500だったからDBもrollbackした」と推測してretryしてはならない。Presenceとdevice activity timestampは認可等に使わないadvisory telemetryとしてgate外であり、欠落を許容する。Readiness失敗後はingressをdrainし、このtelemetry更新をservice write成功と解釈しない。この仕組みはprocess内admissionを使うため、複数application processには対応しない。

Local systemd `StateDirectory` は事故によるDB row削除の検出を改善するが、同一host/operatorがdatabaseとfileを削除できるならoperator separationではない。独立mountを使わない配置で「operator-independent audit」を主張しない。

`AUDIT_INTEGRITY_KEY` はaudit chainとcheckpointの検証に必要である。Database dumpと同じcredentialまたは同じ暗号化containerへだけ保存せず、別のencrypted assetとして復旧可能にする。

## systemd

Built repositoryを `/opt/alparts` に配置し、`deploy/alparts.service` を `/etc/systemd/system` へinstallする。Example unitはNode.js 24以降を `/usr/bin/node` に要求する。別の場所へinstallした場合は、起動前に`ExecStart`をその検証済みabsolute pathへ変更し、`systemd-analyze verify /etc/systemd/system/alparts.service`を実行する。Root-ownedのcredential fileを `/etc/alparts/credentials` に1 secretずつ置き、non-secret endpoint/policyだけを `/etc/alparts/alparts.env` に置く。Example unitが作る `/var/lib/alparts-audit` は、database operatorから分離するclaimを行う前に独立保護先へbind mountする。

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now alparts.service
systemctl status alparts.service
curl --fail http://127.0.0.1:3000/health/ready
```

## Migration safety sequence

Migration scriptとbackup scriptは互いを自動実行しない。Operatorが次の順序を明示的に管理する。

1. Deploy対象revisionのtypecheck/test/buildと、fresh disposable databaseへのmigrationを先に検証する。
2. Applicationをdrain/stopし、DB/オブジェクトストレージへのwriteを停止する。Backup中にwriteがないことをoperatorが保証する。
3. Age recipient、backup DB read identity、オブジェクトストレージのread identity、output destinationを設定し、migration label付きgateを実行する。

   ```bash
   export ALPARTS_BACKUP_QUIESCED=YES_WRITES_ARE_STOPPED
   scripts/pre-migration-backup.sh 0006_example_change
   ```

4. 出力されたartifactを、productionとは別の空DB/空bucketへ `scripts/restore-verify.sh` で復元検証する。`VERIFIED <run-id>` が得られない場合はmigrationへ進まない。
5. Backup artifactのdigestとverification resultを独立した変更記録へ残す。
6. Application runtimeとは別のdeployment identityでmigrationを実行する。

   ```bash
   pnpm --filter @alparts/server db:migrate:runtime
   ```

7. Applicationを起動し、startup/live/ready、audit integrity、migration journalとPostgreSQL 16 `public` catalog fingerprintを確認する。Fingerprint mismatchを期待値の書換えで回避せず、schema driftを調査してforward repairまたは検証済みrestoreを行う。Rollback/restoreが必要なら新しい隔離環境で原因を確認してから、承認済みrunbookを使う。

`pre-migration-backup.sh` はmigration、service停止、restore、cleanupを実行しない。`restore-verify.sh` は既存schemaをdropせず、既存bucketをclearせず、productionらしいtarget名を拒否する。Environmentと全手順は [BACKUP.md](./BACKUP.md) を参照する。

## Graceful shutdown

`SIGTERM` と `SIGINT` はreadinessを直ちに失敗させ、新規API workを拒否し、realtime clientをdisconnectし、background cleanupを停止し、HTTP connectionを最大25秒drainしてdatabase poolを閉じる。Systemd unitは強制終了まで30秒を許容する。

Shutdownをbackupのquiesce mechanismとして暗黙に扱わない。Database、オブジェクトストレージ、管理toolを含めてwrite sourceが停止したことを別途確認する。

## Metrics and alerting

`METRICS_ENABLED=true` の場合だけ `/metrics` を登録する。`METRICS_TOKEN` またはmodeを保護した `METRICS_TOKEN_FILE` に32 byte以上の値が必須で、Bearer tokenをconstant-time比較する。Endpointはtokenがあってもpublic routeへ公開しない。

収集対象はHTTP rate/status/latency、DB pool total/idle/waiting/max、password/object-storage gate active/pending/cap、event-loop p50/p99/max、process memory/uptimeである。External監視でdisk/inode、PostgreSQL、object容量、TLS期限、backup/off-host copy/restore、systemd restart、synthetic encrypted read/writeを追加する。LogはUTCのstructured JSONでrequest/trace/actor/tenant contextを持つが、body、token、password、key、plaintextは出力しない。

## Automated single-host backup

`deploy/alparts-backup.timer` はdaily + random delay + persistentでoneshot serviceを起動する。`scripts/backup-under-systemd.sh` はflockで重複を拒否し、対象serviceがactiveでなければ状態を変更せず失敗し、appを止める前に`backup.sh --preflight`で必要なcommand（rclone 1.75.1以上を含む）と設定を確認し、stop後だけquiesce assertionを設定する。成功/失敗/signalのtrapはservice再起動を試みる。Backup unitはappを自らstopするため、appへの`Requires=`関係を持たせない。

Retentionはbackup成功とapp再起動の後にだけ実行する。`scripts/prune-backups.sh` はdefault dry-run、狭い既存directory、exact filename、日数/最低copy数、`BACKUP_PRUNE_ACK=DELETE_EXPIRED_ENCRYPTED_BACKUPS`を要求する。Timer成功だけではDRにならないため、artifactのoff-host/off-region copyとrestore testを別に監視する。

## Backup / restore boundary

Backup toolingは次を一つのrun IDへ収集する。

- `--format=custom --serializable-deferrable` のPostgreSQL logical dump。
- 設定したbucket内の最新object byte。
- Table count、attachment/object reference、object inventory、SHA-256 checksum、manifest、tool version。

Plaintext stagingはmode `0700`の`mktemp`配下だけに作りtrapで削除し、published artifactはage recipient public keyへ暗号化する。Output既存fileを置換しない。PostgreSQLとオブジェクトストレージの間に共通transactionはないため、quiesceしないbackupは整合snapshotではない。

Restore verifierは次を強制する。

- `alparts_restore_*` / `alparts_verify_*` databaseと `alparts-restore-*` / `alparts-verify-*` bucketだけを許可し、production-like名とsource/default bucketを拒否する。
- Non-system schema/objectがないDB、objectがないbucketだけを許可する。
- Restore ownerが `NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS` で、危険なbuilt-in roleを継承できないことを確認する。
- Filesystem extraction前にarchive entry数、regular fileごとのlogical byte、aggregate expanded byteを設定上限と照合する。GNU tarが示すexpanded sizeを使い、compact sparse/unsupported metadataを検出できる場合は拒否する。
- Decrypt→archive/path/type validation→checksum→single-transaction `pg_restore`→object copy→全table count・attachment reference・object key/size/SHAの再download比較を行う。

PostgreSQL接続はmode `0600`のlibpq service fileとsection名で渡し、オブジェクトストレージのcredentialはshell builtinでmode `0600`の一時`rclone` configへ書き込む（mode `0700`のstaging配下）。Password、access key、secret keyをchild process argvまたはenvironmentへ渡さず、`RCLONE_*`・`AWS_*`の環境変数もchildから除く。Restoreのexpanded-byte上限は、保護されたstaging filesystemのquotaと安全な空き容量以下へ設定する。

### 確認済みroundtrip

2026-08-26に既存DB/bucket/volumeを使わない一意なPostgreSQL 16/MinIO環境で、`backup.sh` から非特権の空verify DB/空bucketへの `restore-verify.sh` を完走した。

2026-10-02に、オブジェクトストレージを SeaweedFS 4.47、転送ツールを rclone へ置き換えた後、一意な PostgreSQL 16/SeaweedFS 環境で同じ `backup.sh` → `restore-verify.sh` を完走した（43 table、avatar 参照を含む 2 object、74,096 bytes）。

- Run ID: `20260826T144441Z-c50148de2d3e`
- Database: 4 tableのsource/restore count一致
- Object: 2 object、合計144 bytes
- Verification: manifest、payload checksum、attachment reference、object inventory、再download SHAが一致

この結果は、そのartifactのDB rowと最新encrypted object byteを検証targetへ再現できたことだけを示す。Application startup、original audit keyでのchain verification、browser device keyによるfixture decrypt、client attachment full flow、RTO/RPOは検証していない。

### Backupに含まれない資産

- `AUDIT_INTEGRITY_KEY`、age identity、deployment/オブジェクトストレージ/PostgreSQL credential。
- Reverse proxy、systemd、environment/policy configuration。
- External audit checkpoint fileと、その独立保管先の記録。
- Browser device private key、channel keyのclient-side recovery material。
- Object version history、bucket policy、lifecycle、tag、すべてのobject metadata。

これらは必要性とauthorityを分離して別々に暗号化・保管する。Browser device private keyをserver backupへ追加してE2EE recoveryを装わない。

## 未提供の運用保証

このrepositoryは、PITR/continuous WAL archive、WORM/object lock、automatic off-site replication、scheduled automatic restore、full application automatic recovery、failover、HA、実施済みquarterly DR、実測RTO/RPO、72-hour soakを提供しない。安全側のlocal retentionとdaily systemd scheduleは実装したが、同一host内だけではDRではない。Auditのexternal SIEM/WORM転送、data retention/export、signed update/release provenanceも未実装である。

これらは [LIMITATIONS.md](./policies/LIMITATIONS.md) のformal release blockerであり、manual backup roundtrip成功で解除されない。
