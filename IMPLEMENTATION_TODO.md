# 実装 TODO / 要件ステータス

最終更新: 2026-08-27

この表が完成対象として扱うのは、`LIMITATIONS.md` で定義した **Web / single-node / basic per-channel key / text中心＋最大8人P2P音声のPhase 1 prototype** だけである。`SPECIFICATION.md` の初期正式版全体を実装した、または正式運用へ承認されたという意味ではない。

## ステータス規約

| 状態 | 判定基準 |
| --- | --- |
| 完了 | 実装が存在し、該当するunit/integration試験または隔離実動試験が成功している |
| 進行中 | コードの一部または全部は存在するが、依存実装・統合・受入試験のいずれかが残る |
| 延期 | Prototype境界では実装せず、正式仕様を満たす将来工程へ送る |
| N/A | 現在の単一process構成には対象となる境界自体がない |

`pnpm test` で環境依存integration suiteがskipされた場合、そのsuiteは成功扱いにしない。個別項目の完了と、リポジトリ全体の最終release gateは別に管理する。

## 依存順 TODO

| ID | 依存 | 状態 | 実装内容 / 残作業 | 受入条件 |
| --- | --- | --- | --- | --- |
| DOC-01 | なし | 完了 | Prototype境界、正式版blocker、安全上の制限を本表、`README.md`、`LIMITATIONS.md`、`THREAT_MODEL.md`へ反映 | 文書間で「正式仕様全体が完成」と読める矛盾がなく、相対linkが解決する |
| LIC-01 | DOC-01 | 延期 | Repository/package metadataは誤配布を避けるため `UNLICENSED` とする。production依存のlicense inventoryは取得済みだが、project自体へのlicense grantは権利者判断待ち | 権利者がOSI承認または同等のlicenseを選定し、著作権表示・third-party notice・配布条件を法務確認してrepositoryへ追加する |
| RUN-01 | DOC-01 | 完了 | shared build、本番server起動、non-root OCI image、systemd hardening、`*_FILE` secret、startup/liveness/readiness、graceful drain | typecheck/buildとserver試験に加え、設定不足時のfail-fastおよび各probeを確認 |
| SEC-01 | RUN-01 | 完了 | DB-backed session、HttpOnly cookie、REST/WebSocketのworkspace/channel/private-channel認可、入力制限、rate limit、外部画像の自動取得防止 | server security/unit/integration試験でBOLA、room join、logout/失効、cross-channel参照を拒否 |
| KEY-01 | SEC-01 | 完了 | non-extractable device key、session-bound enrollment proof/current-password step-up、frozen recipient snapshotを持つ二段階`pending→active` channel epoch、全required exact-delivery ack、immutable per-distributor candidate、署名abort、単調version、失効・離脱時のrekey待ち、鍵不在時の平文fallback禁止 | 自己ack、DM proposer、divergent/overwrite candidate、ack前write、abort/retry、device/session競合と正規全員ack activationを自動試験で確認。MLS/既存端末approvalは対象外 |
| EVT-01 | KEY-01 | 完了 | REST/Socketの耐久化後配信、protocol-v3 signed broadcast intent、認証済み`message/edit/delete/reaction` とpin snapshotの決定的projector、REST responseとlocal signed envelopeの完全一致検証、`(createdAt, id)`順序、重複排除 | server WebSocket試験と `message-projector.test.ts` の正常・改ざんresponse controlが成功 |
| CHAT-01 | EVT-01 | 完了 | 基本投稿、返信、編集、削除、reaction、pin、bookmark、typing/presence、既読位置と未読数に加え、loaded-history thread panel、UUID message link、大量貼付previewをserver/clientへ接続 | server integrationとclient model試験が成功。完全なthread取得、20 pageを超えるlink遡及、全履歴mentionは別項目 |
| MGT-01 | SEC-01, KEY-01 | 完了 | workspace/category/channel管理、position変更、private member管理、一回限り・期限付き・email binding可能な招待の作成/一覧/失効/受諾UI、role CRUD/割当/preview/有効権限理由、session/device失効UI | management/server試験、client model試験、typecheck/buildが成功。招待email配送は提供しない |
| DM-01 | KEY-01, EVT-01 | 完了 | 1対1 DM/group DMのAPI、member model、一覧・作成UI、realtime通知 | server management/integration試験と `dm-model.test.ts` が成功 |
| STATE-01 | CHAT-01 | 完了 | favorite/mute/hide/notification level、read position/unread、bookmark/保存済みUIを認可と分離して同期 | server integrationと `user-state-model.test.ts` が成功。mention集計はロード済み復号範囲を明示 |
| LOCAL-01 | KEY-01, EVT-01 | 完了 | channel draftとoutboxをsame-origin IndexedDBのnon-extractable AES-GCM `CryptoKey`で暗号化し、固定idempotency key、`queued/sending/failed`、online復帰時再送を実装 | outbox model試験とclient typecheck/buildが成功。複数端末draft同期とfull offline cacheは延期 |
| SEARCH-LITE-01 | EVT-01 | 完了 | メモリ上ですでに復号済みの履歴だけを本文・投稿者・channel名で検索。検索語をHTTP/WebSocketへ送らない | `search-loaded-messages.test.ts` が成功し、UIが検索範囲を「読み込み済み」と表示 |
| FILE-SRV-01 | SEC-01, EVT-01 | 完了 | 短命upload予約、5 MiB plaintext chunk contract、resume status、quota、idempotent chunk、finalize、認可付きopaque download、期限切れcleanup | `file.test.ts` とserver integration試験が成功 |
| FILE-CLI-01 | FILE-SRV-01, KEY-01 | 完了 | fileごとの鍵、暗号化filename、5 MiB chunk AEAD、明示的な画像・file送信button、resume/retry、download復号、危険拡張子警告、progress UI | pointer/touchでも選択後にsubmitできるUI回帰試験と、fresh PostgreSQL/MinIOで複数chunkの中断再開→finalize→再取得→SHA一致を確認し、失敗/取消/期限切れ/quota/危険形式をserver・client試験で固定 |
| VOICE-LITE-01 | SEC-01, KEY-01 | 完了 | channel連動の最大8人P2P WebRTC音声、参加・退出、mute、音声検出／push-to-talk、入出力device切替、発言者・品質表示。Fresh participant IDと単調sequenceを含むSDP/ICEを端末署名し、serverは認可済みparticipant間だけ中継 | client exact-shape/replay model、server registry/admission unit、fresh DB/MinIOの2端末join・署名signal relay・spoof拒否・失権退出integration、typecheck/buildが成功。映像/SFU/SFrameと実network/browser matrixは対象外 |
| AUTHZ-OVR-01 | SEC-01, MGT-01, KEY-01 | 完了 | category/channel role override、deny/allow、両revision、preview、effective reason、room membership/rekey連動、client管理UI | fresh migrationで継承・allow/deny優先順位・private member・owner保護・stale revision 409・閲覧喪失時room退出/rekeyを認可matrixで検証 |
| AUD-01 | SEC-01 | 完了 | canonical HMAC chainをPostgreSQL advisory lock下で直列化し、state変更とaudit appendを同一transaction化。起動時検証、POST監査閲覧の自己監査、cached coarse integrity、明示provisionするHMAC付き外部checkpoint、anchor-to-tail descendant proof、CAS相当更新、sticky integrity latchを実装 | audit並行試験、空chainを含むrequired checkpoint欠落、runtime rollback、anchor row削除・改変・末尾不整合時のmutation rollback/readiness/write拒否を確認。operator独立性は別権限mountの場合だけ成立 |
| BKP-01 | RUN-01, AUD-01 | 完了 | quiesceを明示要求するmigration前gate、libpq service file、PostgreSQL custom dumpとMinIO objectの単一manifest/checksum、age recipient暗号化、空の隔離先だけへrestore/verify | 2026-08-27の隔離roundtrip `20260827T051348Z-e8e85d921692` で25 table・2 object・134 bytesのcount/reference/SHA一致を確認 |
| FINAL-01 | 上記Prototype項目 | 完了 | 現working tree全体の最終受入、通常のrepository-wide単一pass scan、全findingの修正・再検証 | fresh PostgreSQL/MinIO migration、非skip integration、`pnpm typecheck/test/build/audit`、backup security/roundtrip、OCI runtime probe、`git diff --check`が成功。scan `1e2517d2-1dad-4360-9e0d-855dfd224047` のMedium 4 / Low 3を修正し、独立patch review後の迂回経路も閉鎖 |
| SEC-DEEP-REC-01 | FINAL-01 | 完了 | 完了前に停止したDeep Security Scan child `c677fed2-242f-40e5-92c9-26e44f2de49d` の保存済み34 findingを23根本原因へdedupeし、共有認証・認可・crypto・resource-admission境界で修正 | Fresh migration、悪性/alternate/正規control、skipなしintegration 2/2、server 49/49、client 77/77、全typecheck/build/audit、独立read-only bypass review（具体的残存bypass 0）、artifact `fix_report.md`を完了。Deep Scan自体の完了とは扱わない |
| NET-03 | RUN-01 | N/A | Prototypeは単一application processでservice間通信境界がない | 複数serviceへ分割した時点でmTLS/SPIFFE設計を再開する |

## Prototype内でも残る機能差

次はコードが一部存在しても、対応する正式要件全体を「完了」とは扱わない。

- `SCP-07`: 基本的な返信・編集・削除・reaction・pinに加え、読み込み済み履歴だけのthread panel、UUID message link（最大20 page遡及）、大量貼付previewは利用できる。Server-backedな完全thread取得・履歴完全性とrole/channel mentionは延期。
- `SCP-08` / `FILE-01..13`: Prototypeの暗号化upload/resume/download経路は完了。隔離viewer、OS quarantine相当、archive/image parser防御、malware分析は延期。
- `SCP-09` / `SEARCH-01..12`: `SEARCH-LITE-01` はロード済み復号履歴だけ。暗号化永続index、端末間同期、全履歴・複数workspace検索は延期。
- `AUTHZ-01..10`: workspace/category/channel RBAC、preview、実効理由はPrototype境界で完了。二者承認は延期。
- `BKP-01..12`: 手動で実行する暗号化snapshot/隔離restore検証だけが完了。PITR、WORM、off-site、自動週次restore、完全DRは延期。
- `MEDIA-01..13`: `VOICE-LITE-01` は既存channel上の最大8人P2P音声だけ。専用voice channel、映像、画面共有、SFU/SFrame、録音表示、正式なgroup rekey、全network/browserの性能保証は延期。

## 最終受け入れコマンド

```bash
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm --filter @alparts/server test:integration
pnpm build
pnpm audit --audit-level low
pnpm licenses list --prod --json
bash scripts/tests/backup-security.test.sh
bash -n scripts/*.sh scripts/lib/*.sh
git diff --check
```

DB/MinIOを使う試験は、既存データを含まない一意な使い捨て環境で実行する。backup/restoreの手順は `docs/BACKUP.md` を参照する。backup scriptはmigrationを自動実行せず、restore scriptは既存DB/bucketを消去しない。

## 正式版まで延期するblocker

| 領域 | 状態 | 正式版に必要なもの |
| --- | --- | --- |
| MLS / 鍵透明性 / 端末承認 | 延期 | RFC 9420相当のforward secrecy/post-compromise security、append-only directory、consistency proof、independent witness、既存端末承認 |
| 強固な認証と承認 | 延期 | WebAuthn/Passkey、OIDC、step-up、破壊的操作・export・recoveryの二者承認 |
| Client platform | 延期 | Windows/Linux/macOS desktop、iOS/Android、OS secure storage、signed distribution |
| Restricted profile | 延期 | Web無効化、参加後履歴、通知制限、external user approval、閾値recoveryなどのpolicy enforcement |
| Data lifecycle | 延期 | retention、client cache削除、user/org export、export approval/監査 |
| Availability / recovery | 延期 | HA、broker、DB failover、cluster移行、PITR、WORM、off-site、retention rotation、自動restore、四半期DR |
| Supply chain / update | 延期 | SBOM、SLSA provenance、artifact署名、downgrade防止、desktop/mobile updater |
| License / redistribution | 延期 | 権利者によるproject license選定、copyright/notice、production依存licenseの法務確認 |
| Media / integration | 一部延期 | P2P音声以外の専用voice channel、video/screen share、SFrame、self-hosted SFU、recording表示、Bot/Webhook identityと最小権限API |
| Assurance | 延期 | accessibility/i18n full audit、soak/performance、独立外部security review、運用SLAと組織統制 |

これらが完了するまで、`SPECIFICATION.md` が想定するゼロデイ、認証情報、Embargo情報の正式運用可とは表示しない。
