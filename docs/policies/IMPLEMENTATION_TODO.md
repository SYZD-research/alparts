# 実装 TODO / 要件ステータス

最終更新: 2026-10-07

この表が完成対象として扱うのは、`LIMITATIONS.md` で定義した **Windows・Linux・macOS desktop / Web / single-node / channelごとに継続するMLS group / text中心＋最大8人P2P音声のPhase 1 prototype** だけである。`SPECIFICATION.md` の初期正式版全体を実装した、または正式運用へ承認されたという意味ではない。

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
| LIC-01 | DOC-01 | 一部完了 | 権利者がAGPL-3.0-onlyを選定し、`LICENSE`（FSF公式本文）とpackage metadataへ反映した。配布される依存がすべてAGPL-3.0と両立することを確認済み | 配布物（desktop・Android・OCI image）へのthird-party noticeと対応するソースの提供方法の整備 |
| RUN-01 | DOC-01 | 完了 | shared build、本番server起動、non-root OCI image、systemd hardening、`*_FILE` secret、startup/liveness/readiness、graceful drain | typecheck/buildとserver試験に加え、設定不足時のfail-fastおよび各probeを確認 |
| SEC-01 | RUN-01 | 完了 | DB-backed session、HttpOnly cookie、REST/WebSocketのworkspace/channel/private-channel認可、入力制限、rate limit、外部画像の自動取得防止 | server security/unit/integration試験でBOLA、room join、logout/失効、cross-channel参照を拒否 |
| KEY-01 | SEC-01 | 完了 | non-extractable device key、session-bound enrollment proof/current-password step-up、channelごとに継続するMLS group（group protocol 4、ADR 0012）。Serverがcommitを1 versionずつcompare-and-swapで順序付け、受理したcommitを即時有効化する（二段階`pending→active`、全員ack、署名abortは廃止）。資格を失った端末がgroupに残る間と24時間group更新がない間のwrite停止、offline端末はwriteを止めない、単調version、commit logからの追いつき、rejoin、条件付きfresh start、downgrade拒否、鍵不在時の平文fallback禁止 | 受理規則のserver unit試験（実commit使用）、commitの順序付けと再送、current versionだけのwriteと古いversionの`KEY_VERSION_STALE`、package規則、資格を失った端末のRemoveまでのwrite停止、fresh-start条件を統合試験で、複数端末のcreate/add/remove/更新、offline追いつき、応答喪失後の自commit採用、rejoin、改ざん・rollbackの停止をclient試験で確認。旧二段階方式の記録はADR 0011と`SECURITY_AUDIT.md`を参照 |
| EVT-01 | KEY-01 | 完了 | REST/Socketの耐久化後配信、protocol-v3 signed broadcast intent、認証済み`message/edit/delete/reaction` とpin snapshotの決定的projector、REST responseとlocal signed envelopeの完全一致検証、`(createdAt, id)`順序、重複排除 | server WebSocket試験と `message-projector.test.ts` の正常・改ざんresponse controlが成功 |
| CHAT-01 | EVT-01 | 完了 | 基本投稿、返信、編集、削除、reaction、pin、bookmark、typing/presence、既読位置と未読数に加え、loaded-history thread panel、UUID message link、大量貼付previewをserver/clientへ接続 | server integrationとclient model試験が成功。完全なthread取得、20 pageを超えるlink遡及、全履歴mentionは別項目 |
| MGT-01 | SEC-01, KEY-01 | 完了 | workspace/category/channel管理、position変更、private member管理、一回限り・期限付き・email binding可能な招待、role CRUD/割当/preview/有効権限理由、session/device失効UI。Workspace/user/role/assignment/invitation/bookmarkのtransactional quotaとbounded listを含む | management/server試験、fresh migration、client model、typecheck/buildが成功。招待email配送は提供しない |
| DM-01 | KEY-01, EVT-01 | 完了 | 1対1 DM/group DMのAPI、member model、一覧・作成UI、realtime通知、normal channelとは分離したworkspace/per-creator quotaとcreator provenance | server management/integration試験と `dm-model.test.ts` が成功。Archive/reclaim lifecycleは延期 |
| STATE-01 | CHAT-01 | 完了 | favorite/mute/hide/notification level、read position/unread、bookmark/保存済みUIを認可と分離して同期 | server integrationと `user-state-model.test.ts` が成功。mention集計はロード済み復号範囲を明示 |
| LOCAL-01 | KEY-01, EVT-01 | 完了 | channel draftとoutboxをsame-origin IndexedDBのnon-extractable AES-GCM `CryptoKey`で暗号化し、固定idempotency key、`queued/sending/failed`、上限100/device、bounded backoffでのonline復帰時再送を実装。Draft writeは実行中1+最新待機1へcoalesce | outbox capacity/lifecycle model試験とclient typecheck/buildが成功。複数端末draft同期とfull offline cacheは延期 |
| SEARCH-LITE-01 | EVT-01 | 完了 | メモリ上ですでに復号済みの履歴だけを本文・投稿者・channel名で検索。検索語をHTTP/WebSocketへ送らない | `search-loaded-messages.test.ts` が成功し、UIが検索範囲を「読み込み済み」と表示 |
| FILE-SRV-01 | SEC-01, EVT-01 | 完了 | 短命upload予約、5 MiB plaintext chunk contract、resume status、quota、idempotent chunk、finalize、認可付きopaque download、期限切れcleanup | `file.test.ts` とserver integration試験が成功 |
| FILE-CLI-01 | FILE-SRV-01, KEY-01 | 完了 | fileごとの鍵、暗号化filename、5 MiB chunk AEAD、明示的な画像・file送信button、resume/retry、download復号、危険拡張子警告、progress UI | pointer/touchでも選択後にsubmitできるUI回帰試験と、fresh PostgreSQL/MinIOで複数chunkの中断再開→finalize→再取得→SHA一致を確認し、失敗/取消/期限切れ/quota/危険形式をserver・client試験で固定 |
| VOICE-LITE-01 | SEC-01, KEY-01 | 完了 | channel連動の最大8人P2P WebRTC音声、参加・退出、mute、音声検出／push-to-talk、入出力device切替、発言者・品質表示。Fresh participant IDと単調sequenceを含むSDP/ICEを端末署名し、serverは認可済みparticipant間だけ中継 | client exact-shape/replay model、server registry/admission unit、fresh DB/MinIOの2端末join・署名signal relay・spoof拒否・失権退出integration、typecheck/buildが成功。映像/SFU/SFrameと実network/browser matrixは対象外 |
| AUTHZ-OVR-01 | SEC-01, MGT-01, KEY-01 | 完了 | category/channel role override、deny/allow、両revision、preview、effective reason、room membership/rekey連動、client管理UI | fresh migrationで継承・allow/deny優先順位・private member・owner保護・stale revision 409・閲覧喪失時room退出/rekeyを認可matrixで検証 |
| AUD-01 | SEC-01 | 完了 | canonical HMAC chainをPostgreSQL advisory lock下で直列化し、message/reaction/pin/preference/bookmarkを含む重要state変更とaudit appendを同一transaction化。Read cursor/provisional upload metadataも共通admissionへ入れ、外部checkpoint、descendant proof、atomic CAS相当更新、active 1+pending 64+30秒deadlineのprocess-local sticky fail-closedを実装 | required checkpoint欠落、runtime rollback、checkpoint write failure、guarded operation非実行、anchor削除/改変/末尾不整合、integration chain、auditへのciphertext/signature/idempotency/emoji非混入を確認。失敗後は次のauthoritative write/readinessを拒否。Advisory presence/activity、operator独立性、multi-process witnessは別境界 |
| BKP-01 | RUN-01, AUD-01 | 完了 | quiesced migration gate、private credential delivery、DB+object manifest/checksum、age暗号化、空隔離restore/verify、systemd daily schedule、non-overlap/restart trap、安全なlocal retention | 隔離roundtripとbackup security/retention testsが成功。Off-host copy、PITR/WORM、scheduled restore/full DRは延期 |
| DESKTOP-01 | FILE-CLI-01, LOCAL-01 | 完了 | Windows・Linux・macOS向けElectron shell、同梱UI、sandbox/context isolation、top-frame限定IPC、OS保護領域、OS/idle lock、HTTPS接続先固定、external browser、bounded native添付保存、3 OS package設定 | desktop policy/vault/settings/file unit、client typecheck/test、Linux unpacked package、Electron fuseを確認。各OSの署名済みrelease受入はPhase 2 gate |
| FINAL-01 | 上記Prototype項目 | 完了 | 現working tree全体の最終受入、通常のrepository-wide単一pass scan、全findingの修正・再検証 | fresh PostgreSQL/MinIO migration、非skip integration、`pnpm typecheck/test/build/audit`、backup security/roundtrip、OCI runtime probe、`git diff --check`が成功。scan `1e2517d2-1dad-4360-9e0d-855dfd224047` のMedium 4 / Low 3を修正し、独立patch review後の迂回経路も閉鎖 |
| SEC-DEEP-REC-01 | FINAL-01 | 完了 | 完了前に停止したDeep Security Scan child `c677fed2-242f-40e5-92c9-26e44f2de49d` の保存済み34 findingを23根本原因へdedupeし、共有認証・認可・crypto・resource-admission境界で修正 | Fresh migration、悪性/alternate/正規control、skipなしintegration 2/2、server 49/49、client 77/77、全typecheck/build/audit、独立read-only bypass review（具体的残存bypass 0）、artifact `fix_report.md`を完了。Deep Scan自体の完了とは扱わない |
| HARDEN-20260830 | FINAL-01 | 完了 | 公式npx Deep Security Scan `160868a8-5398-4707-ac05-e4c99c18fdd8` の13 canonical / 15 instanceを根本原因へ統合して修正し、bounded tenant/auth/storage/audit/client、observability、deployment/CI/backup/DR/docsを強化 | Scan coverageはpartialのまま明示。Fresh migration/replay、integration 4/4、server 73/73、client 98/98、lint/type/build、secret/dependency/backup/OCI/Compose/Trivy/SBOM/smokeを通過し、独立read-only reviewで新規P0/P1なし、承認済みsecurity policyと検証記録を反映 |
| NET-03 | RUN-01 | N/A | Prototypeは単一application processでservice間通信境界がない | 複数serviceへ分割した時点でmTLS/SPIFFE設計を再開する |

## Prototype内でも残る機能差

次はコードが一部存在しても、対応する正式要件全体を「完了」とは扱わない。

- `SCP-07`: 基本的な返信・編集・削除・reaction・pinに加え、読み込み済み履歴だけのthread panel、UUID message link（最大20 page遡及）、大量貼付previewは利用できる。Server-backedな完全thread取得・履歴完全性とrole/channel mentionは延期。
- `SCP-08` / `FILE-01..13`: Prototypeの暗号化upload/resume/download経路とdesktopの隔離属性相当保存は完了。隔離viewer、archive/image parser防御、malware分析は延期。
- `SCP-09` / `SEARCH-01..12`: `SEARCH-LITE-01` はロード済み復号履歴だけ。暗号化永続index、端末間同期、全履歴・複数workspace検索は延期。
- `AUTHZ-01..10`: workspace/category/channel RBAC、preview、実効理由はPrototype境界で完了。二者承認は延期。
- `BKP-01..12`: 暗号化snapshot/隔離restore検証、single-host daily schedule、安全なlocal retentionが完了。PITR、WORM、automatic off-site、自動restore、完全DRは延期。
- `MEDIA-01..13`: `VOICE-LITE-01` は既存channel上の最大8人P2P音声だけ。専用voice channel、映像、画面共有、SFU/SFrame、録音表示、正式なgroup rekey、全network/browserの性能保証は延期。

## 最終受け入れコマンド

```bash
pnpm install --frozen-lockfile
pnpm lint
pnpm typecheck
pnpm test
pnpm --filter @alparts/server test:integration
pnpm build
pnpm test:backup-security
pnpm security:secrets
pnpm audit --prod --audit-level high
bash -n scripts/*.sh scripts/lib/*.sh scripts/tests/*.sh
git diff --check
```

DB/MinIOを使う試験は、既存データを含まない一意な使い捨て環境で実行する。backup/restoreの手順は `docs/BACKUP.md` を参照する。backup scriptはmigrationを自動実行せず、restore scriptは既存DB/bucketを消去しない。

## 正式版まで延期するblocker

| 領域 | 状態 | 正式版に必要なもの |
| --- | --- | --- |
| MLS / 鍵透明性 / 端末承認 | 一部完了 | Channelごとに継続するRFC 9420 group、append-only directory、client checkpoint照合、既存端末承認は実装済み。Message単位のforward secrecy、UpdatePath付きcommitをしないmemberへのpost-compromise security、independent witness、独立暗号reviewは延期 |
| 強固な認証と承認 | 延期 | WebAuthn/Passkey、OIDC、step-up、破壊的操作・export・recoveryの二者承認 |
| Client platform | 一部完了 | Windows/Linux/macOS desktopとOS保護領域は完了。iOS/Android、signed/notarized distribution、署名検証updateは延期 |
| Restricted profile | 延期 | Web無効化、参加後履歴、通知制限、external user approval、閾値recoveryなどのpolicy enforcement |
| Data lifecycle | 延期 | retention、client cache削除、user/org export、export approval/監査 |
| Availability / recovery | 一部完了 | single-host supervisor/daily backup/local retentionは完了。HA、broker、DB failover、cluster移行、PITR、WORM、off-site、自動restore、四半期DRは延期 |
| Supply chain / update | 一部完了 | pinned CI、dependency/secret/CodeQL/Trivy scan、SBOMは完了。SLSA provenance、artifact署名、downgrade防止、desktop/mobile updaterは延期 |
| License / redistribution | 延期 | 権利者によるproject license選定、copyright/notice、production依存licenseの法務確認 |
| Media / integration | 一部延期 | P2P音声以外の専用voice channel、video/screen share、SFrame、self-hosted SFU、recording表示、Bot/Webhook identityと最小権限API |
| Assurance | 延期 | accessibility/i18n full audit、soak/performance、独立外部security review、運用SLAと組織統制 |

これらが完了するまで、`SPECIFICATION.md` が想定するゼロデイ、認証情報、Embargo情報の正式運用可とは表示しない。

## Account/group security update (2026-09-16)

| ID | 状態 | 実装と受入範囲 |
| --- | --- | --- |
| SEC-ACCOUNT-01 | 実装済み・独立受入待ち | 既存端末承認、directory chainとcheckpoint照合、固定suite MLS groupをchannelごとに継続するgroup protocol 4（2026-10-07、[ADR 0012](../adr/0012-continuous-mls-groups.md)）、Web Passkey、重要操作step-up、ユーザー管理の暗号化履歴復旧。通常suiteに加えて専用HTTP統合試験と実際のMLS/復号試験を追加。 |

[仕様への対応・限界・移行](../security/ACCOUNT_AND_GROUP_SECURITY.md)を参照。Native WebAuthn、OIDC、独立witness、組織閾値復旧、Restricted policy、独立暗号reviewはこの項目の完了に含めない。
