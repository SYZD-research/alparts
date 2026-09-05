# alparts

alpartsは、serverへ平文messageを渡さないchannel型communication基盤の **Phase 1 Web / desktop prototype** です。React/TypeScript SPA、Electron、Node.js/TypeScript API、PostgreSQL、MinIOで構成され、少人数向けP2P音声通話も提供します。

このrepositoryは `SPECIFICATION.md` の正式運用版ではありません。現在の到達点はWindows・macOS・Linux desktop / Web / single-process / basic per-channel key / text中心＋最大8人P2P音声のprototypeです。2026-08-30に公式npx CLIのDeep Security Scanを実施し、pre-change treeへ13 canonical finding / 15 report instanceを報告しました。検出根本原因を現treeで修正し、fresh PostgreSQL/MinIOを含む回帰検証を行っていますが、scan coverageはtime ceiling等により`partial`で、独立外部reviewでもありません。ゼロデイ、認証情報、Embargo情報には使用しないでください。正確な境界は [docs/INDEX.md](./docs/INDEX.md)、[LIMITATIONS.md](./docs/policies/LIMITATIONS.md)、[risk register](./docs/RISK_REGISTER.md) を参照してください。

## 現在の到達点

Android 開発クライアントと移行・配布・復元演習の検証ツールを追加しました。
[Android のビルド手順](docs/ANDROID.md) と [Phase 2 の実装状況・残作業](docs/PHASE2.md) を参照してください。
Phase 2 全体の完了や正式運用への適合を示すものではありません。

- workspace/category/public・private channelと、基本的なE2EE text投稿、返信、編集、削除、reaction、pin、bookmark
- 読み込み済み履歴を対象にするthread panel、最大20 pageを遡るUUID message link、大量貼り付け確認preview
- 1対1 DM/group DMのAPI・member model・一覧/作成UI
- 耐久化eventからの決定的client projector、REST/WebSocket同期、idempotent send
- 招待の作成/一覧/失効/受諾UI、role CRUD/割当/preview/有効権限理由、session/device失効UI
- read position/unread、favorite/mute/hide/notification、保存済みmessage
- same-origin IndexedDBへ暗号化するchannel draft/outboxと、online復帰時の再送
- すでに読み込み・復号済みのmessageだけを対象にするlocal search
- preview/revision/effective reasonを備えたcategory/channel role permission overrideと、失権時のroom退出・rekey・client局所消去
- file別key、暗号化filename、5 MiB chunk AEAD、中断再開、opaque download復号、危険形式警告を備えた添付flow
- 同梱UIだけを読み込むWindows・macOS・Linux向けElectron client、OS保護領域を使う鍵保存、OS/idle連動app lock、隔離属性付きnative添付保存
- 最大8人のP2P WebRTC音声通話、署名付きSDP/ICE、参加・退出、ミュート、音声検出／プッシュトゥトーク、入出力device切替、発言者・接続品質表示
- HMAC chained audit、起動時検証、監査閲覧の自己監査、設定可能なHMAC checkpoint
- startup/liveness/readiness、fatal pathを含むgraceful shutdown、structured correlation log、private bearer-protected metrics
- non-root/read-only OCI/systemd例、安全側configuration/TLS、`*_FILE` secret、tracked-file secret/dependency/CI scan
- image内のdatabase-only migrator、migration journal＋PostgreSQL 16 catalog fingerprintによるstartup/readinessのschema/image coupling
- age recipientで暗号化するbackup gate、systemd daily schedule、安全なlocal retention、空の隔離DB/bucketだけを対象にするrestore verification
- tenant/resource/database/object listing/password/audit/upload work、およびbrowser outbox/realtime/voice/attachment workのtransactional・bounded admissionとbulk authorization snapshot

Category/channel permission override、client attachment flow、音声signalingは、fresh PostgreSQL/MinIOを使う認可matrix・複数chunk再開/download SHA・2端末の通話参加/relay/失権退出まで確認しています。MLS、device approval/key transparency、WebAuthn/OIDC、mobile、Restricted profile、HA、PITR/WORM/off-site/automatic DR、retention/export、signed updates、映像・画面共有・SFU/SFrame、Bot/Webhook、独立外部reviewは正式版blockerとして未実装です。

## ローカル起動

必要なもの:

- Linux/macOSまたは互換shell
- Node.js 24以降
- pnpm 11.21.0（Corepackを利用可能）
- DockerとDocker Compose plugin
- OpenSSL

初回起動:

```bash
./dev.sh
```

`.env` がなければ、scriptはmode `0600`のfileへrandomな開発用secretを生成します。その後、loopback限定のPostgreSQL/MinIOを起動し、MinIO専用app userを作成し、依存関係とmigrationを準備してclient/serverを起動します。既存volumeと新しいcredentialが一致しない場合もvolumeを自動削除しません。

- Web: `http://localhost:5173`
- API: `http://localhost:3000`
- Desktop（別terminal）: `pnpm dev:desktop` を実行し、初回画面へ `http://localhost:5173` を入力
- Process停止: 実行中terminalで `Ctrl+C`
- 依存serviceも停止: `./dev.sh down`

Public self-registrationは既定で無効です。`.env` の `REGISTRATION_INVITE_SECRET` はdeployment最初のaccountだけを作るbootstrap secretです。通常の追加userは、workspace管理者がUIで発行する一回限り・期限付きtokenを安全なout-of-band経路で受け取ります。Email配送機能はありません。

音声通話は第三者ICE serviceを既定で利用しません。同一LAN外やNAT越しで確実に接続するには、operatorが管理するSTUN/TURNを `.env` の `VOICE_ICE_SERVERS_JSON` に設定してください。例えば `[{"urls":["turns:turn.example.test:5349?transport=tcp"],"username":"短命user","credential":"短命secret"}]` です。TURN credentialは参加clientへ渡るため、固定の管理credentialではなく短命credentialを使用してください。

## 検証

```bash
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm --filter @alparts/server test:integration
pnpm build
pnpm test:backup-security
pnpm security:secrets
pnpm audit --prod --audit-level high
git diff --check
```

DB integrationは、既存dataを含まない一意な使い捨てPostgreSQL/MinIOで実行してください。通常の `pnpm test` でintegration suiteがskipされた場合、それだけでfinal gateを通過したとは扱いません。

## Cryptoとlocal stateの境界

Message本文はbrowserでAES-256-GCM暗号化し、device P-256 keyでcontext付きprotocol-v3 envelopeへ署名します。Channel-key epochは共通SHA-256 commitmentとfrozen recipient snapshotを持つ`pending`として提案され、全required端末が復号・commitment・server発行のexact deliveryを検証して署名ackした場合だけ`active`になります。Pending epochはmessage/attachment writeに使えず、abort後もversionを再利用しません。全accepted holderを失った場合は旧ciphertextを復旧できたと装わず、`historyRecoveryRequired`を示して新端末から将来用epochだけを確立します。履歴を待たず明示的に再開する場合はpasswordと端末署名を確認し、全eligible端末へ新keyをwrapしたうえで開始端末のack後に将来用epochを有効化します。Serverはciphertext、signature、配送に必要なmetadataを保持します。現在のgroup keyはbasic per-channel epoch方式で、MLS相当のforward secrecy/post-compromise securityを提供しません。

Web版では、device private keyとdraft/outbox用AES-GCM keyをnon-extractable WebCrypto `CryptoKey`としてsame-origin IndexedDBへ保存します。Desktop版ではprivate materialをOS保護領域でwrapし、IndexedDBには参照情報だけを置きます。どちらも実行中の正規clientは鍵を利用できるため、client code侵害への完全な防御ではありません。Searchはmemory上の読み込み済み復号messageだけを対象とし、永続暗号化indexや端末間同期はありません。

## 運用

- [Documentation index](./docs/INDEX.md): inventory、architecture、security、reliability、deployment、runbookへの入口
- [Desktop client](./docs/DESKTOP.md): 開発起動、3 OS向けpackage、trust boundary、検証
- [運用手順](./docs/policies/OPERATIONS.md): monitoring、migration、probe、audit checkpoint、shutdownの境界
- [Backup / restore verification](./docs/BACKUP.md): migration前gate、age暗号化artifact、隔離restore
- [Deployment](./docs/policies/DEPLOYMENT.md): development、single-host、air-gapped、cluster/multi-region非保証
- [Disaster recovery](./docs/policies/DISASTER_RECOVERY.md): RPO/RTO objective、資産、復旧順序、演習
- `Dockerfile`: non-root runtime、readiness healthcheck、production dependencyのみ
- `compose.production.yml`: loopback publish、secret mount、read-only/cap-drop/resource limitのsingle-host profile
- `deploy/alparts.service`: systemd credentials、read-only filesystem hardening、restart/backoff

External公開時はTLS 1.3を優先するreverse proxyを使用し、PostgreSQL、MinIO、管理・監視endpointをpublic networkへ出さないでください。`AUDIT_CHECKPOINT_PATH` がPostgreSQL operatorとはwrite/delete権限を分離したmountにある場合だけ、checkpointをoperator-independentと呼べます。

## Repository policy

脆弱性の報告方法は [SECURITY.md](./docs/policies/SECURITY.md) を参照してください。過去の監査、完了済みstandard scan、2026-08-27に停止したDeep Scan、および2026-08-30にartifact packagingまで完了したcoverage-partial Deep Scanのfindingと修正結果は [SECURITY_AUDIT.md](./docs/policies/SECURITY_AUDIT.md) で分離しています。

このrepositoryは現在 `UNLICENSED` であり、公開閲覧できること自体は利用・改変・再配布の許諾を意味しません。Project licenseの選定は権利者判断が必要な正式版TODOです。Production依存の機械的inventoryでは MIT / ISC / BSD-3-Clause / Apache-2.0 / BlueOak-1.0.0 を確認していますが、これはproject licenseの付与または法的助言ではありません。
