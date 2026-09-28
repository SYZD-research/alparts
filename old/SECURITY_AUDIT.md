# Security audit — 2026-09-16

最終文書更新: 2026-09-16

この文書は、2026-09-16に現行作業ツリー（未コミットのアカウント/グループセキュリティ実装を含む）へ行った防御的なソース監査の記録である。実運用環境への侵入試験、攻撃手順の再現、PoCの配布は行っていない。独立外部レビュー、暗号ライブラリの形式検証、または本番利用の承認ではない。

過去の Deep Scan / standard scan の finding と修正履歴は [docs/policies/SECURITY_AUDIT.md](./docs/policies/SECURITY_AUDIT.md) に分離する。残課題の運用上の扱いは [docs/RISK_REGISTER.md](./docs/RISK_REGISTER.md)、信頼境界は [docs/security/THREAT_MODEL.md](./docs/security/THREAT_MODEL.md)、アカウント/グループ実装の意図は [docs/security/ACCOUNT_AND_GROUP_SECURITY.md](./docs/security/ACCOUNT_AND_GROUP_SECURITY.md) を正とする。

## 修正後の状態（2026-09-16）

7件を再確認し、6件を修正した。A-20260916-6 は呼び出し先に既存の承認・失効フィルターがあることを確認し、実データベースの回帰テストで否定例を追加した。以下の初回監査記録は検出時点の履歴として保持する。

| ID | 対応 | 検証 |
| --- | --- | --- |
| A-20260916-1 | 修正。Express の実際の pathname で分類し、敏感操作の absolute-form は許可しない | デバイス承認・パスキー登録 options・セッション削除の origin/absolute-form が428。有効な許可も absolute-form では使えず、対応する origin-form だけで一度使える |
| A-20260916-2 | 修正。DB単位の排他起動、所有権喪失時の受付停止、監査checkpoint完了までの引継ぎ待機 | 2プロセス相当の独立DB接続で競合拒否。所有接続を切断し、既存処理の完了まで代替起動が待機することを確認 |
| A-20260916-3 | 修正。暗号化シークレット/履歴取得は承認済み端末を要求。新端末は復旧コードから導いた取得許可を提示してからシークレットを取得 | 未紐付け/未承認セッション、誤った許可・世代を拒否。正しいコードによる端末承認後は履歴取得可能。旧設定の更新も本人確認が必要 |
| A-20260916-4 | 修正。本人確認時の認証情報を許可に保存し、MLS fresh-start の鍵トランザクション内で再検証 | 偽造・再使用・別用途の内部許可、変更されたパスワード、削除されたパスキーを拒否。正しいパスワード/パスキーの確認を受理 |
| A-20260916-5 | 修正。移行時の確認済み prefix head をクライアントbuildに固定し、完全一致まで legacy を未承認扱い | アンカー欠落/差し替え/別アカウント/偽bootstrap/追加legacyを拒否。64件を超える分割取得でも照合完了前に承認しない |
| A-20260916-6 | 初回指摘を訂正。`getEligibleDevicesFromStore` が `approved_at IS NOT NULL AND revoked_at IS NULL` を再要求していた | 活性化と同じ `isEpochRosterCurrent`/`isRecipientSnapshotStillAuthorized` をDBロック下で実行し、承認取消・失効の両方で不一致になることを確認 |
| A-20260916-7 | 修正。Markdown の protocol-relative URL と backslash variant を拒否 | `//`、空白付き参照、backslash混在を拒否し、明示URL/メール/相対パスを保持 |

導入時は migration `0015_audit_hardening.sql`、確認済み移行アンカーのクライアント組込み、既存復旧コードの承認済み端末での更新が必要。[移行手順](./docs/security/ACCOUNT_AND_GROUP_SECURITY.md#migration-and-rollout) を参照。これらの変更を本番へ適用したことや、独立レビューが完了したことを示す記録ではない。

## 初回監査の結論（修正前）

Critical 1、High（条件付き）1、Medium 4、Low 1を記録した。本人確認の分類とExpressルーティングが絶対形式request-targetに対して食い違う問題を隔離環境で確認した。初回監査の A-20260916-6 は上記の再検証により訂正した。

## 範囲と方法

対象:

- サーバ認可・セッション・ステップアップ・パスキー・復旧・ディレクトリ・MLS
- クライアントのディレクトリ検証、復旧暗号、メッセージ/添付の署名検証
- CSRF/Origin、Cookie、WebSocket 入場、添付、Electron/Android の IPC/ブリッジ
- 設定、CORS/WebAuthn 由来、Compose の bind

方法:

- ルート、ミドルウェア、サービス、共有プロトコルのソース追跡
- 敏感操作分類と Express 5 ルーティングの突き合わせ（隔離アプリ。本番アカウントや実データを使わない）
- 既存のアカウントセキュリティ統合試験が想定する fail-closed 条件との照合

行っていないこと: 稼働中デプロイへの試験、テナント横断データの取得、可用性を落とす負荷、攻撃用クライアントの配布。

## Finding（以下は初回監査時点の記録）

### A-20260916-1 — Critical — ステップアップ分類が `req.originalUrl` に依存する

| 項目 | 内容 |
| --- | --- |
| 重大度 | Critical |
| 箇所 | `packages/server/src/middleware/step-up.ts`（`sensitiveActionBoundary`）、`packages/shared/src/security/account.ts`（`isSensitiveAction`） |
| 前提 | 有効なアカウントセッション（Cookie または Bearer）。未認証の公開経路だけでは足りない |
| 影響する性質 | 敏感操作の本人確認（ADR 0011 / アカウントセキュリティ文書が要求する exact-action step-up） |
| 状態 | 未修正 |

`sensitiveActionBoundary` は敏感かどうかの判定に `req.originalUrl` の `?` より前を使う。`isSensitiveAction` は `/api/devices/` で始まる、`/api/auth/passkeys/register/options` と一致する、といった **パス名専用** の条件である。

HTTP/1.1 の request-target はパス（origin-form）だけでなく、スキームとホストを含む絶対 URL（absolute-form）でもよい。後者では:

- Express のルーティングはパス名だけを見て、本来のハンドラへ届ける
- `req.originalUrl` はスキーム付きのままなので、`isSensitiveAction` はすべて不一致になる
- ステップアップ（428）は走らず、ハンドラ本体は実行される

ブラウザの `fetch` は通常 origin-form を送るため、同じオリジンの画面操作では 428 のままである。セッションを持った非ブラウザクライアント、およびクライアントの request-target をそのまま upstream へ渡すリバースプロキシでは、絶対形式が通り得る。

隔離アプリ（本番と同じ分類関数・`/api` マウント）での確認:

| request-target の形 | デバイス承認 / パスキー登録 options / 全セッション削除 |
| --- | --- |
| origin-form（`/api/...`） | 428 `STEP_UP_REQUIRED` |
| absolute-form（スキーム+ホスト付き） | 分類が false のまま正規ルートへ到達 |

ステップアップ対象として文書化されている操作のうち、この分類を唯一の追加ゲートとしているもの（端末のディレクトリ署名を別途要求しないもの）が直接影響する。例:

- パスキー登録オプションの発行。続けて `POST /api/auth/passkeys/register/verify` は origin-form でも分類対象外
- セッションの個別/一括無効化
- パスキー削除（最後の1本はサービス側で拒否）
- メンバー削除、ロール、招待、権限オーバーライド、チャンネル/カテゴリ削除（RBAC は残る）

端末の承認/失効と復旧の設定変更は、分類を過ぎたあとも承認済み端末の署名を要求する。メッセージ/添付の作成もデバイス署名と承認済み端末を要求する。したがって **チャネル鍵の復号や送信署名の偽造はこの欠陥だけでは成立しない。** 破れるのは「盗まれたログインセッションでは敏感なアカウント/テナント操作にパスキーまたはパスワード再確認が要る」という境界である。管理者セッションでは、本人確認なしでメンバーシップや招待を変えられる。パスキーを追加できると、以降のステップアップでパスワードが拒否される。

修正方針（未実装）:

- 判定に使う文字列は `req.originalUrl` ではなく、スキーム/ホストを除いたパス名にする（`URL` で pathname を取る、またはマウントと `req.path` を結合する）
- 既存の大文字・末尾スラッシュ対策は残す
- origin-form と absolute-form の両方で 428 になる回帰をアカウントセキュリティ試験へ追加する
- `POST /api/auth/passkeys/register/verify` を敏感操作に含めるかは別判断（チャレンジが能力になっている現状の防御層）

### A-20260916-2 — High（条件付き） — 複数アプリレプリカはサポート外のセキュリティ前提を壊す

| 項目 | 内容 |
| --- | --- |
| 重大度 | High（単一プロセス配備では緩和済み。複数レプリカでは未サポート） |
| 箇所 | プロセス内レート制限、Socket.IO ルーム、アップロード直列化、監査 checkpoint 入場 |
| 状態 | 文書化済み（R-005）。誤配備でのみ顕在化 |

サポート対象はアプリケーション1プロセスである。レート制限・ソケット上限・監査入場はプロセス内状態である。レプリカを足すと予算が乗算され、ルーム認可と監査順序がノード間で一致しなくなる。これは単一リクエストの認証回避ではなく、トポロジ違反である。

### A-20260916-3 — Medium — 復旧アーカイブの取得が承認済み端末を要求しない

| 項目 | 内容 |
| --- | --- |
| 重大度 | Medium |
| 箇所 | `packages/server/src/routes/recovery.ts` の `GET /api/recovery/keys`、`GET /api/recovery/` |
| 状態 | 未修正 |

履歴鍵バックアップの **書き込み** と候補一覧は `requireApprovedDevice` を通る。暗号化済みバックアップの **読み取り** と復旧設定（公開署名鍵および暗号化シークレット）はセッション認証だけである。パスワードのみのセッション、または未承認端末に紐づくセッションでも、そのアカウントの暗号化ブロブを取得できる。

平文履歴にはユーザ保管の復旧コードが必要である。256 bit のコードに対するオンライン総当たりは現実的でない。パスワード盗難時の防御層としては、承認済み端末と同じゲートにしていない。

### A-20260916-4 — Medium — MLS fresh-start がトランザクション内パスワード再確認を持たない

| 項目 | 内容 |
| --- | --- |
| 重大度 | Medium（ステップアップが有効なら）。A-20260916-1 と重なると高い |
| 箇所 | `packages/server/src/services/key.service.ts` の MLS fresh-start 経路。レガシー `/keys/start-fresh` はパスワードハッシュをトランザクション内で再確認する |
| 状態 | 未修正 |

MLS の明示的な履歴なし開始は HTTP ステップアップとデバイス署名に依存し、レガシー経路のような `expectedPasswordHash` 再確認がない。ステップアップが効いている間は追加のパスワード証明がないだけである。A-20260916-1 でステップアップが外れると、承認済み端末の署名だけで fresh-start できる。

### A-20260916-5 — Medium — 移行用 `legacy` ディレクトリ項目は署名なしで承認扱い

| 項目 | 内容 |
| --- | --- |
| 重大度 | Medium（現行の新規登録パスでは bootstrap が legacy を閉じる） |
| 箇所 | `packages/client/src/services/directory-verifier.ts` |
| 状態 | 移行アンカーとして文書化済み |

`kind: 'legacy'` は署名空欄を要求し、対象を承認済みにする。新規アカウントは sequence 1 の `bootstrap` で `legacyClosed` になる。悪意あるサーバによる初回接触のディレクトリ差し替え（TOFU）は、独立証人がない限り残る。脅威モデルの KEY 残差と一致する。

### A-20260916-6 — Medium — 活性化時の受信者スナップショットが現行の承認/失効を再要求しない

| 項目 | 内容 |
| --- | --- |
| 重大度 | Medium |
| 箇所 | `packages/server/src/services/key.service.ts` の `isRecipientSnapshotStillAuthorized` |
| 状態 | 他層で緩和 |

pending epoch の活性化は、凍結受信者の `deviceId` が同じ `userId` に対応することだけを見る。ack 自体は承認済み・未失効端末を要求する。DB 上の承認状態とスナップショットがずれた場合の最終再確認としては弱い。

### A-20260916-7 — Low — Markdown がプロトコル相対リンクを許可する

| 項目 | 内容 |
| --- | --- |
| 重大度 | Low |
| 箇所 | `packages/client/src/services/url-policy.ts` の `safeMarkdownHref` |
| 状態 | 未修正 |

`javascript:` / `data:` は拒否する。`//example` は https として分類したうえで元文字列を `href` に返すため、クリックで外部サイトへ誘導できる。格納 XSS ではない。React Markdown は生 HTML を通さない。

## 見た範囲で欠陥としなかったもの

次はソース上 fail-closed、または意図した製品境界として扱った。

- テナント横断の workspace/channel/message/file IDOR。欠落したテナント文脈はグローバル許可にならない
- 未承認端末へのチャネル鍵配布、メッセージ/添付の署名付き書き込み、WebSocket 入場、MLS パッケージ公開
- 復旧署名鍵なしの `restore-device`。誤った署名者は統合試験で拒否
- ステップアップ許可のセッション/メソッド/パス/本文ハッシュへの束縛と、origin-form での大文字・末尾スラッシュ分類（絶対形式は A-20260916-1）
- メッセージ AEAD/署名の channel/author/device/version/idempotency への束縛
- MLS 名簿と公開済みパッケージのサーバ側一致、クライアントのディレクトリ承認と KeyPackage の deviceId 束縛
- Cookie セッションの `SameSite=Strict` / HttpOnly、Cookie 付きブラウザ変更の Origin 必須、`Sec-Fetch-Site: cross-site` 拒否
- Drizzle 経由のパラメータ化アクセス、Markdown 生 HTML なし、オブジェクトキーのサーバ生成
- Electron の sandbox / contextIsolation / パッケージ UI 差し替え、Android のアセット UI と main-frame ブリッジ

## 文書化済み残差（本監査の新規欠陥ではない）

脅威モデルとリスク登録に既にあるもの。本監査で再確認したが新規 ID は付けない。

- 同一オリジンの Web 侵害、改変デスクトップ、OS アカウント侵害は、その端末の平文と鍵を破る（R-002）
- 独立したディレクトリ証人（KEY-05）は未実装。初回接触は TOFU
- 保持アーカイブはメッセージ単位の forward secrecy を主張しない
- 単一プロセス/リージョン、外部 WORM 証人なし、署名付きリリースなし
- パスキー登録後もアカウントのパスワードログインは残る。拒否されるのはステップアップのパスワード代替だけである
- 移行 `0014` は既存端末を承認済みの legacy アンカーにする。ロールアウト前の端末棚卸しが必要

## 初回監査時点の検証について

本監査で実行した確認:

- 敏感操作分類と Express 5 ルーティングの隔離突き合わせ（絶対形式 request-target を含む）
- 承認・ステップアップ・MLS・復旧・ディレクトリ経路のソースレビュー
- 既存試験がカバーする fail-closed 条件との照合

本監査の時点で、修正後のアカウントセキュリティ統合試験やフル CI は **再実行していない。** 実装ドキュメント上の 2026-09-16 開発証拠（型検査、lint、build、secret scan、クライアント/サーバ/デスクトップ試験、アカウントセキュリティ統合）は、A-20260916-1 の絶対形式ケースを含まない。

推奨する修正後の確認:

- origin-form と absolute-form の両方で、デバイス承認・パスキー options・セッション削除が 428 になること
- 有効なステップアップ許可では、パス名が一致する origin-form だけが通過すること
- 既存の `pnpm --filter @alparts/server test:account-security` が落ちないこと

## 過去の監査との関係

| 記録 | 関係 |
| --- | --- |
| [docs/policies/SECURITY_AUDIT.md](./docs/policies/SECURITY_AUDIT.md) | 2026-08 の scan と修正。本ファイルの代替ではない |
| 2026-08-27 standard scan Critical/High 0 | 当時のツリー。ステップアップ/MLS/パスキー実装前 |
| 2026-08-30 Deep Scan（coverage partial） | 同上。本 Critical を検出していない |
| 本記録 | 2026-09-16 のアカウント/グループセキュリティ面を含む現行作業ツリー |

過去 scan の「Critical/High 0」を現ツリーへ継承しない。

## 修正後の検証

- PostgreSQL 16 の隔離DBを使用し、既存データの移行、実HTTP/WebAuthn/MLS/復旧、絶対形式request-target、二重起動と所有権喪失を検証。
- クライアントの移行アンカー、復旧取得許可の分離、Markdown URL の回帰テストを追加。
- 最終結果: クライアント149件、サーバー75件、デスクトップ19件、アカウントセキュリティ統合9件、PostgreSQL/MinIO統合4件が通過（計256件）。
- shared/client/server/desktopの型検査、client/server build、lint、差分の空白検査が通過。機密情報スキャンは追加ファイルを含む416ファイルで通過。
- Node 24.21.0 / PostgreSQL 16、使い捨てDB・MinIOで検証。本番データ・本番環境は変更していない。ブラウザ実機操作や外部ペネトレーションテストは今回再実行していない。
