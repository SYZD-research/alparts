# Security audit 2 — 2026-09-16

最終文書更新: 2026-09-17（修正・再検証。以下の発見時の説明は保存し、対応内容は末尾に記録）

この文書は、`old/SECURITY_AUDIT.md` に記録済みの既知・修正済み脆弱性（A-20260916-1 〜 7、および文書化済み残差）を除く、**新規に発見した**脆弱性の記録である。前回監査の修正後の現行作業ツリーに対する防御的なソース監査であり、実運用環境への侵入試験や PoC の配布は行っていない。

既知の finding（本監査では再掲しない）:

- A-20260916-1 〜 7（step-up 分類の absolute-form、複数レプリカ、復旧アーカイブ取得、MLS fresh-start、legacy ディレクトリ、受信者スナップショット、Markdown protocol-relative URL）
- 文書化済み残差: R-002（同一オリジン Web 侵害等）、KEY-05（独立証人なし・TOFU）、保持アーカイブの forward secrecy なし、単一プロセス/単一リージョン、パスキー登録後のパスワードログイン残存、migration 0014 の legacy アンカー

## 範囲と方法

- サーバ: ミドルウェア（auth/step-up/origin/rate-limit/audit）、全 routes、services（auth/device/key/message/file/recovery/passkey/directory/mls/authorization）、WebSocket（handshake・各 handler）、config、runtime-lease
- クライアント: crypto/mls/recovery/directory/passkey の各 service、stores、url-policy、security storage
- インフラ: docker-compose、env、dev/resume スクリプト、CI、desktop (Electron)
- 共有プロトコル: `packages/shared`（エンベロープ直列化、敏感操作分類、正準化）

方法はルート→ミドルウェア→サービス→DB スキーマのソース追跡。攻撃成立条件が環境依存の指摘は、前提を明記して重大度を調整して記録する。

## Finding（逐次追記）

### N-20260916-1 — Medium — パスワードハッシュに pepper がない

| 項目 | 内容 |
| --- | --- |
| 重大度 | Medium |
| 箇所 | `packages/server/src/security/password-work.ts`、`packages/server/src/services/auth.service.ts`（`SALT_ROUNDS = 12`）、`packages/server/src/db/schema.ts`（`password_hash`） |
| 状態 | 修正済み |

bcrypt(cost 12) が素のパスワードへ直接適用され、HMAC pepper 等のDB外秘密が関与しない。DB ダンプ単体の漏洩で全アカウントのオフライン総当たりが可能。監査整合用の `AUDIT_INTEGRITY_KEY` は DB 外管理が既にあるため、仕組みの欠落ではなく適用漏れ。

### N-20260916-2 — Medium — 失敗ログインの監査レコードに対象アカウント識別子がない

| 項目 | 内容 |
| --- | --- |
| 重大度 | Medium |
| 箇所 | `packages/server/src/services/auth.service.ts`（`user.login.failed` の `audit()` 呼び出し）、`packages/server/src/middleware/audit.ts` |
| 状態 | 修正済み |

失敗ログインは actorId/targetId/details なしで記録され、`setLogActor` は認証成功後のみ呼ばれる。攻撃対象メールが永続監査ログのどこにも残らず、分散パスワードスプレーや標的型攻撃の兆候をフォレンジック的に再構築できない。メール別の試行回数はプロセス内揮発カウンタのみが知る。

### N-20260916-3 — Medium — アカウント単位ログイン制限が恒久ロックアウト DoS に転用可能

| 項目 | 内容 |
| --- | --- |
| 重大度 | Medium（可用性。IP 非依存キーイングはスプレー対策として意図済みだが、上限の失効設計がない） |
| 箇所 | `packages/server/src/middleware/rate-limit.ts`（`credentialAccountRateLimitKey`）、`packages/server/src/routes/auth.ts`（`loginAccountLimit`） |
| 状態 | 修正済み |

メールアドレスを知る任意の攻撃者が、被害者メールで誤パスワードを 13 リクエスト/15 分送り続けるだけで、正しいパスワードでのログインを無期限に 429 へ追いやれる。単一 IP かつ `loginIpLimit`(100/15分) 以内で完結し、 captcha / 管理者解除等の代替経路がない。

### N-20260916-4 — Low — 失敗ログイン 1 件ごとにグローバル監査コミットゲートを占有する

| 項目 | 内容 |
| --- | --- |
| 重大度 | Low（fail-closed ではあるが可用性の単一ボトルネック） |
| 箇所 | `packages/server/src/middleware/audit.ts`（`auditCommitGate`、同時 1・待ち 64）、`packages/server/src/services/auth.service.ts` |
| 状態 | 修正済み |

失敗ログインは bcrypt 後に単一スロットの監査ゲート（advisory lock + checkpoint 検証付きトランザクション）へ直列化される。分散ソースから失敗ログインを継続すると待ち 64 スロットが占有され、ログイン以外の全 `auditedTransaction` が `AUDIT_UNAVAILABLE`(503) になる。

### N-20260916-5 — Low — bcrypt ワーカ 2 本の枯渇で `AUTH_CAPACITY` 認証妨害

| 項目 | 内容 |
| --- | --- |
| 重大度 | Low（可用性） |
| 箇所 | `packages/server/src/security/password-work.ts`（同時 2・待ち 16・5 秒）、`packages/server/src/security/limits.ts`、`packages/server/src/app.ts` の `AUTH_CAPACITY` ハンドラ |
| 状態 | 修正済み |

分散リクエスト（~7 req/s 継続、60 IP 程度）でワーカと待ち行列を占有すると、login/register/reauthenticate およびパスワード step-up が一括で 503 になる。

### N-20260916-6 — Low — 有効な招待トークン所持者による登録時タイミング差分のメール列挙

| 項目 | 内容 |
| --- | --- |
| 重大度 | Low |
| 箇所 | `packages/server/src/services/auth.service.ts`（`preflightRegistrationInvitation` 後に `hashPassword` を実行してから `EMAIL_EXISTS` 判定）、`packages/server/src/routes/auth.ts`（403 応答は同一本文に統合済み） |
| 状態 | 成立条件を訂正（招待の有効性による差） |

無効トークンは bcrypt 前に即拒否される一方、有効トークン＋既存メールは cost 12 の bcrypt とトランザクションを経由してから同一 403 を返す。数百 ms 級の時間差オラクルが残る。未使用の有効招待トークンの所持が前提。

### N-20260916-7 — Low — メール正規化が trim+lowercase のみで Unicode NFC 正規化を欠く

| 項目 | 内容 |
| --- | --- |
| 重大度 | Low |
| 箇所 | `packages/server/src/services/auth.service.ts`（`normalizeEmail`）、`packages/server/src/services/invitation.service.ts` |
| 状態 | 修正済み |

NFC/NFD のコードポイント差が `users.email`（text unique、バイト比較）上で別アカウントになる。視覚同一の別アドレスで登録ができ、メールバインド招待の完全一致照合も正規化形式が 1 バイトでも違うと請求できない。

### N-20260916-8 — Low — checkpoint 未構成環境で監査チェーンの切り詰め（行削除）を検知しない

| 項目 | 内容 |
| --- | --- |
| 重大度 | Low（本番は `AUDIT_CHECKPOINT_PATH` 必須で起動時に強制済み。dev/staging 限定） |
| 箇所 | `packages/server/src/middleware/audit.ts`（`assertCheckpointDescendant` の未設定時即 return） |
| 状態 | 修正済み |

checkpoint が未設定だとチェーンの外部証人が不在で、HMAC 鍵を持たない攻撃者でも DB 書込権限があれば行削除・切り詰めが検知されない。checkpoint 処理自体は fail-closed（失敗時 latch で以降の変更を拒否）であることを確認済み。

### N-20260916-9 — Low — デバイス承認ルートで無効 UUID が未処理例外になり 500 を返す

| 項目 | 内容 |
| --- | --- |
| 重大度 | Low（堅牢性・ログ汚染） |
| 箇所 | `packages/server/src/routes/devices.ts`（approve ルート。`DELETE /:id` 等は `safeParse` で 404 を返すのに approve のみ `parse` が catch 内で失敗し `next(error)` 経由の 500） |
| 状態 | 元の500の記述を訂正・入力処理を統一 |

認証済みセッションから無効形式の UUID を POST するだけで `http.unhandled` としてエラーログ・通知が乱反射する。

### N-20260916-10 — Low — bcrypt compare が cost 4–15 の保存ハッシュを受け入れる

| 項目 | 内容 |
| --- | --- |
| 重大度 | Low（防衛線の縮減。DB 行改変権限または移行バグが前提） |
| 箇所 | `packages/server/src/security/password-work.ts`（検証時 `storedRounds >= 4` を受理） |
| 状態 | 修正済み |

新規ハッシュは cost 12 固定だが、検証は DB 上のハッシュに書かれたコストに従う。低コストハッシュが書き込まれた場合、オフライン総当たりコストが実質撤廃される。

### N-20260916-11 — Medium — 共有チャネル経由で相手アカウント全体の端末ディレクトリ（全端末 identityKey・承認/失効履歴）を横断取得できる

| 項目 | 内容 |
| --- | --- |
| 重大度 | Medium（メタデータ露出） |
| 箇所 | `packages/server/src/routes/directory.ts`（`GET /directory/:userId?channelId=`）、`packages/server/src/services/directory.service.ts`（`readDirectory`） |
| 状態 | 取得範囲を制限・必要な公開証明は維持 |

対象が「当該チャネルの現在 viewer」「過去の投稿者」「過去の鍵受信者」のいずれかなら、そのユーザーのアカウント単位のディレクトリ連鎖（bootstrap/approve/revoke/recovery 全イベント、全 deviceId・identityKey・署名、攻撃者と共有していないワークスペースの端末や退会後の履歴を含む）をページングで全件取得できる。管理者権限不要。共有チャネルが 1 つあればよい。

### N-20260916-12 — Medium — KeyPackage の内容（期限・init key・ciphersuite・MLS ネイティブ署名）をサーバが一切検証しない

| 項目 | 内容 |
| --- | --- |
| 重大度 | Medium（実害はクライアントの検証省略に依存） |
| 箇所 | `packages/server/src/services/mls.service.ts`（`publishKeyPackage` は外形署名のみで内容は不透過保存、`validateAndStoreMlsEpoch` は roster とのバイト一致照合のみ） |
| 状態 | 修正済み |

期限切れ・不正な init key を持つ KeyPackage も外形署名（自端末 identityKey・自 deviceId 束縛）が正しければ保存・配布・エポック取り込みされる。悪意あるメンバーは自端末の KeyPackage を壊して将来のエポック構築（全メンバーのパッケージ集合を取り込む）を継続的に失敗させられる。MLS ネイティブ検証は完全にクライアント依存。

### N-20260916-13 — Low — MLS 経路の再鍵は現行エポック保持者なら誰でも開始でき、MANAGE_CHANNELS を要求しない

| 項目 | 内容 |
| --- | --- |
| 重大度 | Low（活性化は全 ack 必須で fail-closed。実害は再鍵強制によるグリーフィング） |
| 箇所 | `packages/server/src/services/key.service.ts`（`!mls &&` の短絡で権限チェックが消える）、`packages/server/src/services/mls.service.ts` |
| 状態 | 修正済み |

一般メンバーが roster 全端末の公開済みパッケージで再鍵サイクル（`channel:key-rotation-required` ブロードキャスト）を 90 件/分/ユーザーの制限内で繰り返し、帯域・電力を消費させられる。

### N-20260916-14 — Low — レガシー `POST /channels/:id/keys/start-fresh` は恒久的デッドパス（必ず 409）

| 項目 | 内容 |
| --- | --- |
| 重大度 | Low（機能不具合。トランザクション内 throw でロールバック、副作用なし） |
| 箇所 | `packages/server/src/services/key.service.ts`（`version === nextVersion` を要求する枝が `!mls` で必ず例外）、`packages/server/src/routes/keys.ts` |
| 状態 | 修正済み |

パスワード再確認と fresh-start 署名の検証をすべて通過した後で必ず `GROUP_PROTOCOL_REQUIRED` になる。復旧フローは実質 MLS fresh-start（step-up）に一本化されており、パスワード検証コストだけが残る。

### N-20260916-15 — Low — `canRotate`/`canAbortPending` フラグが実際の abort 権限と不一致

| 項目 | 内容 |
| --- | --- |
| 重大度 | Low（fail-closed だが API 契約の齟齬） |
| 箇所 | `packages/server/src/services/key.service.ts`（`getKeyRecipients` は `hasRotationPermission = true` 固定・pending recipient に `canAbortPending: true` を広告 vs `abortPendingChannelKey` は非 DM で `MANAGE_CHANNELS` 必須） |
| 状態 | 修正済み |

一般メンバーには pending 詰まりからの回復手段が advertised されるが、実行すると常に `KEY_ABORT_FORBIDDEN` になる。

### N-20260916-16 — Low — `publishKeyPackage` の状態読み取りがトランザクション外のグローバル接続

| 項目 | 内容 |
| --- | --- |
| 重大度 | Low（下流のエポック取り込みが tx 内で再検証し fail-closed） |
| 箇所 | `packages/server/src/services/mls.service.ts`（`lockKeyProtocol(tx)` 直後に `getKeyRecipients` がグローバル `db` 直読み） |
| 状態 | 修正済み |

ロック保護下のスナップショット外で `nextVersion` と roster を判定するため、同時書込時に古い状態で判定する余地がある。不整合は取り込み側で `INVALID_MLS` となる。

### N-20260916-17 — Low — `getChannelMessages` は service 層で再認証・ロックを行わない

| 項目 | 内容 |
| --- | --- |
| 重大度 | Low（メンバーシップ剥奪と読み取りのミリ秒競合時に、剥奪直後 1 リクエスト分の ciphertext 一覧取得の余地。鍵自体は剥奪前に保持） |
| 箇所 | `packages/server/src/services/message.service.ts`（`getChannelMessages`）、`packages/server/src/routes/messages.ts`（非トランザクションの `requireChannelAccess` のみ） |
| 状態 | 修正済み |

書込系は tx 内で `lockWorkspaceForAuthorization` + 再認証するが、読み取り系はルート middleware のみ。cursor は channelId 束縛でクロスチャネル漏えいはなし。

### N-20260916-18 — Low — 現行 roster 端末が全過去バージョンの MLS エンベロープ（roster・配布者のメタデータ）を取得可能

| 項目 | 内容 |
| --- | --- |
| 重大度 | Low（welcome は受信者ごとの MLS 暗号化のため内容漏えいには至らない） |
| 箇所 | `packages/server/src/services/mls.service.ts`（`getMlsEpoch` は現 roster の承認済み端末であることのみ要求し、任意の過去 `version` を返す） |
| 状態 | 取得範囲を制限・必要な前エポック証明は維持 |

### N-20260916-19 — Low — `GET /api/recovery/metadata` が承認済み端末を要求しない

| 項目 | 内容 |
| --- | --- |
| 重大度 | Low（開示されるのは公開署名鍵 JWK・`generation`・`accessConfigured` のみ） |
| 箇所 | `packages/server/src/routes/recovery.ts`（metadata 取得）、`packages/server/src/services/recovery.service.ts`（`recoveryMetadata`） |
| 状態 | 復旧仕様を確認・端末の紐付けを必須化 |

recovery 系の他エンドポイント（`/candidates`、`/keys`、`/restore-device` 等）が承認済み端末を要求するのに対し、metadata のみセッションがあれば未承認端末から取得できる。開示内容は公開鍵とアカウント状態フラグに限られ、recovery 設定の有無という状態情報が得られる点と、fail-closed 原則に対する一貫しない例外として指摘。

### N-20260916-20 — Medium — 権限オーバーライドの作成・変更に権限サブセット制約と役割階層制約がない

| 項目 | 内容 |
| --- | --- |
| 重大度 | Medium（チャンネルスコープ内での権限昇格・上位ロールの締め出し。`CHANNEL_SCOPED_PERMISSION_MASK` 外の権限は付与できず、owner はバイパス） |
| 箇所 | `packages/server/src/services/permission-override.service.ts`（`assertManagementAuthorization` 315-347 行、`assertWorkspaceRole` 349-354 行、`upsertPermissionOverride` 152-160 行） |
| 状態 | 修正済み |

チャンネルターゲットのオーバーライド管理は「そのチャンネルで可視 + `MANAGE_CHANNELS`」のみを要求し、`role.service.ts` の `assertCanCreateOrAssign` / `assertRoleCanBeManaged` にある「自身の権限のサブセットのみ付与可」「自身の最高 position 未満のロールのみ管理可」の両制約がない。チャンネルレベルの `MANAGE_CHANNELS` 保持者（オーバーライド由来を含む）は、自身のロールへマスク内の任意権限（`DELETE_MESSAGES`・`PIN_MESSAGES` 等）を allow して自己拡張できるほか、自身より上位 position のロール（Administrator 等）への deny 書込で特定チャンネルから管理者を締め出し、第三の低権ロールを引き上げられる。チャンネルスコープ外への拡張が不可能なため Critical とはせず Medium 判定。

### N-20260916-21 — Low — 同一レベルのオーバーライドで allow が deny を上書きする

| 項目 | 内容 |
| --- | --- |
| 重大度 | Low（設計確認事項。レベル間の優先順位自体は正しく適用済み） |
| 箇所 | `packages/server/src/services/authorization.service.ts`（110-119 行、コメントで「allows win conflicts」と明記） |
| 状態 | 修正済み |

同一レベル（カテゴリまたはチャンネル）でロール A に deny・ロール B に allow が両方付いたユーザーは allow 側で権限を得る。管理者が「このロールはこのチャンネルで送信禁止」と deny を設定しても、同一ユーザーの別ロール allow で無効化され、deny 設定者の意図と異なる状態になり得る。Discord 互換の意図的な設計の可能性があるため設計確認事項とする。

### N-20260916-22 — Low — ボイスチャンネルに接続可否の独立した権限がなく `VIEW_CHANNELS` のみで参加・発話可能

| 項目 | 内容 |
| --- | --- |
| 重大度 | Low（権限モデルのギャップ。ルーム認可・シグナル照合自体は堅牢） |
| 箇所 | `packages/server/src/websocket/voice.handler.ts`（421-470 行）、`packages/shared/src/constants/index.ts`（`Permissions` に voice 接続用ビットが存在しない） |
| 状態 | 修正済み |

`join` / `watch` は `VIEW_CHANNELS` のみを要求する。`SEND_MESSAGES` を持たない Guest 的ロールでも RTC シグナリング経由で音声送受信が可能で、プレゼンス（userId+deviceId）が全閲覧者に公開される。「閲覧できる = 通話できる」が強制される設計であり、意図でなければ `CONNECT` 相当の権限ビット追加が必要。

### N-20260916-23 — Low — ユーザー保存クォータがワークスペース横断で合算され、クロステナントから容量枯渇させられる

| 項目 | 内容 |
| --- | --- |
| 重大度 | Low（可用性。チャンネル/ワークスペース単位の quota は無傷） |
| 箇所 | `packages/server/src/services/file.service.ts`（`getCiphertextUsage` 959-966 行、`messages.authorId` / `uploaderId` のみで絞り込み workspace 条件なし） |
| 状態 | 修正済み |

`config.storage.perUserQuotaBytes` が全ワークスペース合算で計算されるため、ワークスペース A での添付がワークスペース B での同一ユーザーのアップロードを阻止する。他テナントの管理者が標的ユーザーを招待して添付させ、本来のワークスペースでの作業を妨害するクロステナント枯渇が理論上成立。

### N-20260916-24 — Medium — ディレクトリ検証チェックポイントの無制限蓄積によりクライアントが恒久的に不能化される

| 項目 | 内容 |
| --- | --- |
| 重大度 | Medium（機密性・完全性への影響なし、恒久的な可用性喪失。第三者からの遠隔トリガは署名で阻止される） |
| 箇所 | `packages/client/src/services/directory-verifier.ts`（191 行、`state.checkpoints[entry.sequence] = entry.hash` を枝刈りなしで蓄積）、`packages/client/src/services/directory.service.ts`（73 行、全状態を永続化）、`packages/client/src/services/security-storage.ts`（68 行、2MB 上限超過で `SECURITY_STORAGE_LIMIT` を送出） |
| 状態 | 上限内で非成立を確認・クライアント検証追加 |

ディレクトリの全イベント（登録/承認/失効/recovery）のハッシュをチェックポイントとして保存し続けるため、約 3 万イベント超過で永続化が 2MB 上限に達し、以後すべての `verifiedDirectory()` が例外で失敗する。`verifiedDirectory()` はデバイス初期化（`initializeDeviceSession`）、`ensureChannelKey`、メッセージ署名検証からも呼ばれるため、当該アカウントの全クライアントでログイン後の初期化・鍵取得・検証が恒久的に失敗し、IndexedDB の手動消去まで回復しない。イベントは本人端末の署名付きで第三者は偽造できないが、自然な長期運用、またはアカウントの認証済みセッション保持者による register/revoke の反復で到達可能。可用性のみの影響のため Critical とはせず Medium 判定。

### N-20260916-25 — Low — サーバ応答由来の cursor 等を URL エンコードせずクエリ文字列に展開

| 項目 | 内容 |
| --- | --- |
| 重大度 | Low（同一エンドポイントのクエリパラメータ操作に限定。送信先は同一オリジン同一パス） |
| 箇所 | `packages/client/src/services/api.ts`（841 行 `?cursor=${cursor}`）、`packages/client/src/services/recovery.service.ts`（220・338 行、`channelId` / `version` を raw 展開） |
| 状態 | 修正済み |

同一ファイルの `getChannelKeys`（`encodeURIComponent` 使用）や監査ログ閲覧（`URLSearchParams` 使用）と不整合。影響はページネーション破壊・意図しないクエリパラメータ付与・ログ汚染にとどまる。

### N-20260916-26 — Low — `dev.sh` の `.env` 新規作成が `chmod 600` まで他ローカルユーザーから読める

| 項目 | 内容 |
| --- | --- |
| 重大度 | Low（マルチユーザーホスト限定の短い競合窓。単一ユーザー開発機では実害なし） |
| 箇所 | `dev.sh`（43-61 行、heredoc で `JWT_SECRET` / `AUDIT_INTEGRITY_KEY` / `REGISTRATION_INVITE_SECRET` / DB・MinIO 認証情報を書き込み後に `chmod 600`） |
| 状態 | 修正済み |

ファイルは umask 由来のパーミッション（一般的な 022 umask では 0644）で作成され、書き込み完了から `chmod 600` までの窓で全シークレットが同一ホストの他ローカルユーザーから読める。先に `umask 077` を設定するか `install -m 600 /dev/null` で作成すれば回避できる。

### N-20260916-27 — Low — Electron の permission check ハンドラが要求ハンドラより緩く media 権限を応答する

| 項目 | 内容 |
| --- | --- |
| 重大度 | Low（実際のキャプチャは要求経路で audio に限定され、権限昇格には至らない） |
| 箇所 | `packages/desktop/src/main.ts`（218-231 行） |
| 状態 | 修正済み |

要求（`setPermissionRequestHandler`）は `mediaTypes` が非空かつ全て `audio` のときのみ許可するのに対し、同期照会（`setPermissionCheckHandler`）は `mediaType === undefined` も `true` を返す。両ハンドラの判定基準が不一致であり、未許可 origin が権限ありと誤認できる。同一の述語に統一すべき。

---

## 集計

| ID | 重大度 | 箇所 | 状態 |
| --- | --- | --- | --- |
| N-20260916-1 | Medium | `password-work.ts` / `auth.service.ts`（パスワード pepper なし） | 修正済み |
| N-20260916-2 | Medium | `auth.service.ts`（失敗ログイン監査の対象識別子なし） | 修正済み |
| N-20260916-3 | Medium | `rate-limit.ts` / `routes/auth.ts`（アカウント単位制限による恒久ロックアウト DoS） | 修正済み |
| N-20260916-4 | Low | `audit.ts`（監査コミットゲート占有） | 修正済み |
| N-20260916-5 | Low | `password-work.ts`（bcrypt ワーカ枯渇） | 修正済み |
| N-20260916-6 | Low | `routes/auth.ts`（登録時タイミング差でメール列挙） | 成立条件を訂正（招待の有効性による差） |
| N-20260916-7 | Low | `auth.service.ts`（メール正規化 NFC 欠如） | 修正済み |
| N-20260916-8 | Low | `audit-log.service.ts`（checkpoint 未設定時の切り詰め検知なし） | 修正済み |
| N-20260916-9 | Low | `routes/devices.ts`（無効 UUID で 500） | 元の500の記述を訂正・入力処理を統一 |
| N-20260916-10 | Low | `password-work.ts`（bcrypt cost 4-15 受容） | 修正済み |
| N-20260916-11 | Medium | `routes/directory.ts`（共有チャネル経由のディレクトリ横断読取） | 取得範囲を制限・必要な公開証明は維持 |
| N-20260916-12 | Medium | `mls.service.ts`（KeyPackage 内容の無検証） | 修正済み |
| N-20260916-13 | Low | `key.service.ts`（MLS 再鍵の権限短絡） | 修正済み |
| N-20260916-14 | Low | `routes/keys.ts`（恒久デッドパス） | 修正済み |
| N-20260916-15 | Low | `key.service.ts`（abort 権限と広告の不一致） | 修正済み |
| N-20260916-16 | Low | `mls.service.ts`（tx 外状態読取） | 修正済み |
| N-20260916-17 | Low | `message.service.ts`（読取系の再認証なし） | 修正済み |
| N-20260916-18 | Low | `mls.service.ts`（過去バージョンエンベロープ取得可） | 取得範囲を制限・必要な前エポック証明は維持 |
| N-20260916-19 | Low | `routes/recovery.ts`（metadata が承認端末不要） | 復旧仕様を確認・端末の紐付けを必須化 |
| N-20260916-20 | Medium | `permission-override.service.ts`（サブセット/階層制約なし） | 修正済み |
| N-20260916-21 | Low | `authorization.service.ts`（同一レベル allow 優先） | 修正済み |
| N-20260916-22 | Low | `voice.handler.ts`（接続権限の不存在） | 修正済み |
| N-20260916-23 | Low | `file.service.ts`（横断ユーザークォータ） | 修正済み |
| N-20260916-24 | Medium | `directory-verifier.ts` / `security-storage.ts`（チェックポイント蓄積で恒久不能化） | 上限内で非成立を確認・クライアント検証追加 |
| N-20260916-25 | Low | `api.ts` / `recovery.service.ts`（cursor の URL エンコード欠如） | 修正済み |
| N-20260916-26 | Low | `dev.sh`（`.env` 作成の権限窓） | 修正済み |
| N-20260916-27 | Low | `packages/desktop/src/main.ts`（permission check の不一致） | 修正済み |

計 27 件（Medium 7 件、Low 20 件、Critical 0 件、High 0 件）。

## Critical 級に関する判定

「最低 1 件は Critical 級」という要求に対しては、**裏付けの取れた新規 Critical を提示できなかった**。最多重大度は Medium に留まる。各最上位候補が Critical に届かない根拠:

- **N-20（オーバーライド昇格）**: `CHANNEL_SCOPED_PERMISSION_MASK` 外のワークスペース管理権限は付与できず、影響は単一チャンネルに限定。owner はバイパスがあるため締め出しも不完結。
- **N-24（クライアント恒久不能化）**: 影響は可用性のみ。ディレクトリイベントは本人端末の署名付きのため第三者は遠隔から偽造できず、成立には長期自然運用または既に認証済みの攻撃者セッションが必要。
- **N-1（パスワード pepper なし）**: DB 漏洩時のオフライン解析はアカウント乗っ取りを意味するが、E2E 平文には届かない（端末鍵は non-extractable、履歴鍵は recovery コードと分離）。
- **N-3 / N-11 / N-12**: それぞれ持続的 DoS、メタデータ（公開鍵・端末名）開示、サーバ側検証の欠如（クライアント側検証で裏取り済み）の範囲。

Critical が不在であることは、既知 7 件の修正と本プロジェクトの多層防御が機能している証左であり、下記の確認済み領域も併せて参照のこと。重大度の水増しは報告書の価値を失わせるため行っていない。

## 調査方法

- サーバ: 全 17 ルートファイル・全サービス・middleware（auth/rbac/step-up/audit/rate-limit/cookies）・websocket ハンドラ群・config/app・scripts を全文読了。
- クライアント: 暗号系サービス（crypto/mls/recovery/directory/passkey/security-storage）、stores、api、url-policy、UI コンポーネントを確認。
- デスクトップ/Android/CI/インフラ: Electron メイン・preload・fuses、Android ブリッジ・Keystore、GitHub Actions、docker-compose・dev.sh・deploy を全文読了。
- 本体監査に加えて 3 つの独立サブエージェントで範囲を冗長化し、指摘は全て実際のコード読了で裏取り。
- `old/SECURITY_AUDIT.md` の既知 7 件（A-1〜A-7）と明記済み残差（R-002 同一オリジン侵害、TOFU/独立証人なし、保持アーカイブ FS なし、単一プロセス、パスキー後のパスワード併存、migration 0014 legacy anchor）は再報告から除外した。

## 見た範囲で欠陥としなかったもの（主要な確認結果）

- **CSRF**: Cookie は `SameSite=Strict`、`enforceBrowserOrigin` が Origin/`Sec-Fetch-Site` を検査し cross-site を拒否。
- **SQL インジェクション**: 全クエリが drizzle のパラメータ化、scripts も識別子を引用。動的 SQL 構築なし。
- **XSS**: `dangerouslySetInnerHTML` / `innerHTML` / `eval` / `new Function` は全体で不使用（grep で確認）。CSP は `script-src 'self'`、Markdown リンクは `safeMarkdownHref` で http/https/mailto のみ。
- **添付ファイル配信**: 常に `application/octet-stream` + `Content-Disposition: attachment` + `nosniff` + CSP sandbox。presigned URL は存在せず全アクセスがサーバプロキシ。
- **鍵素材**: 乱数は `crypto.getRandomValues` / `crypto.randomUUID` のみ、IV/ノンスの再利用なし、端末鍵・ローカル暗号化鍵は non-extractable。
- **TOCTOU**: 書込系はワークスペース共有ロック下でトランザクション内再認証、ロール変更は `FOR UPDATE` + 認可リビジョンハッシュ。
- **メッセージ整合性**: 編集は作者一致必須（`editMessage`）、削除は作者または `MANAGE_CHANNELS`、エンベロープ署名を作者の identity key で検証。
- **監査**: 失敗応答も記録、整合性チェーン + checkpoint 検証（本番で必須化）、閲覧行為自体も記録。
- **レート制限**: login/register/reauthenticate/upload/workspace 作成/チャネル状態取得に個別の上限設定。
- **Electron/Android**: `contextIsolation` + `sandbox` + fuses、IPC は送信者・フレーム検証、Android は全ナビゲーション遮断 + Keystore 鍵の AAD 束縛。
- **CI**: 全 Action を SHA ピン留め、`permissions: contents: read`、認証情報非永続化、secret はダミー値のみ。
- **メンバー一覧**: `GET /workspaces/:id/members` はメールを含まない（displayName/avatarUrl/status のみ）。
- **招待**: 256bit CSPRNG、保存はドメイン分離ハッシュ、有効期限必須、accept 時にロック下で再検証。


## 修正・再検証記録（2026-09-17）

発見時の27件をそのまま「すべて攻撃成立」とは扱わず、仕様・実装・実リクエストで再検証した。以下は今回の差分である。旧監査の既知残差（独立証人なし、保持履歴の forward secrecy なし、単一実行プロセス等）を解消したという主張ではない。

| ID | 対応と検証対象 |
| --- | --- |
| N-1 / N-10 | bcrypt cost 12–15の結果を、独立した `PASSWORD_PEPPER` によるドメイン分離HMACで保存。DBにbcryptの検証可能なダイジェストを残さない。比較時は保存したsaltでworker内で再計算し、定時間比較。未保護・低cost形式へのfallbackなし。停止中のruntime migrationで既存cost 12以上のハッシュをパスワードなしで変換できる。別pepper・誤パスワード・弱い形式の拒否を検証。 |
| N-2 | 既知アカウントは `targetId`、全失敗は正規化メールの独立ドメインHMAC `accountTag` を監査詳細へ記録。入力メールやパスワードは記録しない。 |
| N-3 | アカウント枠超過は永久に429で閉じず、有効期限2分・アカウントと送信元に束縛・一回限りの計算課題へ移行。公式クライアントは専用workerで解き、一度だけ再送する。単一試行に22bit SHA-256作業を要求し、IP/送信元＋アカウント枠は引き続き適用。パスキー経路も使用可能。再利用、期限切れ、他アカウント・他送信元への転用を拒否するテストを追加。一般的な回線/大規模DDoS耐性を保証するものではない。 |
| N-4 / N-5 | 未認証のlogin/registerを、監査完了まで保持する同時2・待ち0の枠へ隔離。未認証処理が監査待ち64枠を占有することはできない。公開認証用2workerと認証済み再確認用2workerを分離。認証済み側は従来の待ち16・5秒上限を維持し、飽和時にも再確認できることをテスト。失敗監査は間引かず保持。 |
| N-6 | 記載された差は「無効な招待」と「有効な招待」の差であり、同一の招待条件で既存/未登録メールを分岐するタイミングオラクルではない。有効な招待では存在確認前に両方同じKDFを通る。招待の事前確認はメールの存在を問い合わせない。無効な招待にも高コストKDFを課す変更は行わない。招待を消費した正常な登録の201と拒否403が異なる点は仕様。 |
| N-7 | アカウント・招待・レート予算で共通のtrim/lowercase/NFC関数を使用。0016で既存のメールを正規化する。重複発生はunique制約で移行を停止し、アカウントを自動統合しない。現在のHTTP入力検証は国際化ローカル部を受理しないため、NFC/NFDでの新規二重登録という成立条件も限定される。 |
| N-8 | `createApp` は開発・テスト環境でもcheckpoint pathとrequired設定を要求する。監査コミット自体もpath未設定なら拒否する。`dev.sh` の新規環境は保護されたファイルを明示的に初期化する。既存環境の証人消失を自動初期化して隠さない。 |
| N-9 | 元コードの `isAccountSecurityError` はZodErrorを含むため「無効UUIDが必ず500」は不正確。承認も他の端末操作と同じUUID事前検証で404とする。削除の不正な本文も400に統一。 |
| N-11 | peer参照には承認済み端末と、workspace lock下での現在の閲覧権限を要求。退会済みの対象は、そのチャンネルの署名済みepochに含まれた最大sequenceとlegacy移行prefixまでに限定し、その後の登録/失効/復旧設定を開示しない。上限は `channel_directory_heads` に保持して取得時の全epoch走査を避ける。現行参加者の端末はアカウント共通で全チャンネルの受信対象であり、workspace専用の別端末というモデルは存在しない。署名連鎖の中間を削除すると検証できないため、必要な公開prefixは提供する。 |
| N-12 | pinned `ts-mls` でKeyPackage/LeafNodeの両ネイティブ署名を検証。厳密な復号長、version/suite、basic credentialのdeviceId、capabilities、期限、鍵長、init/leaf鍵の相違、X25519の実際のencapsulation成立を検証。公開時とepoch取り込み時の両方で確認する。署名偽造、期限切れ、別端末、ゼロ/同一init鍵、余分なbytesの拒否をテスト。 |
| N-13 | MLSでも、ロスター変更・失効・24時間経過などの理由がなければ再鍵を拒否。必要な通常更新は現行保持者が実行できる仕様を維持し、fresh-start/abortの管理権限は維持。単に全更新を管理者専用にしてoffline管理者へ依存させない。 |
| N-14 | 旧 `/keys/start-fresh` は本文解析・パスワード処理・step-up・トランザクション前に410を返す。現行クライアントはMLSのfresh-startを利用。 |
| N-15 | abortの広告を実際のMANAGE_CHANNELS/DM権限に一致させ、履歴を捨てる復旧のcanRotateにも同じ管理権限を反映。 |
| N-16 | 公開時の鍵状態を、同じtransaction接続とworkspace lockから読む。グローバルdbへの読み抜けを除去。 |
| N-17 | メッセージサービスにuserIdを必須化し、workspace共有lock下で閲覧権限を再評価。ページ、pins、reactions、attachmentsを同じtransactionで取得。非参加者のサービス直接呼出しを拒否する統合テストを追加。 |
| N-18 | 過去の取得対象を自身が受信対象だったepoch、または最新の自身のepochを検証するための最大128段の前エポック連鎖へ制限。新端末によるfresh-startに必要な現在の署名済みepochも許可する。現在の参加資格だけで無関係な過去の失敗提案を列挙することはできない。 |
| N-19 | 全端末を失った利用者の復旧には承認前の公開generation/署名鍵が必要であり、承認必須にすると循環する。`restore-device` も承認前に復旧鍵で承認する経路で、指摘の「他はすべて承認必須」は不正確。metadataにもlive sessionと登録・紐付け済み、未失効端末を要求し、単なる未紐付けログインには403。秘密/アーカイブの取得制約は維持する。 |
| N-20 | 作成・更新・削除・previewすべてに役割階層と権限サブセットを適用。自身と同位/上位やOwner役割を変更できず、変更前後のallow/deny全ビットはworkspaceと対象チャンネルで持つ権限の共通範囲に限定。削除で自分にない権限のdenyを解除する迂回も不可。なおMANAGE_CHANNELSは元からoverride対象maskに含まれない。 |
| N-21 | 同一レベルの競合をdeny優先に変更し、認可revisionにpolicy versionを含める。カテゴリーより具体的なチャンネル設定の優先関係は維持。管理UIの説明とテストも変更。 |
| N-22 | 独立したCONNECT_VOICEを追加し、join/watchの両方にVIEWとの組合せを要求。role/override変更時の退出・受信者再評価にも使用。0016は既存Owner/Administrator/Memberへ付与し、Guest/Integration/custom roleへは自動付与しない。閲覧は可能でも通話とpresence取得は拒否される統合テストを追加。 |
| N-23 | 確定添付と未完了chunkの両方で、ユーザークォータをworkspace条件付きで集計。同じユーザーが別workspaceで使用した容量は加算しない。workspace/channelの総枠は維持。実DBで両状態の隔離を検証。 |
| N-24 | 元からserverは8,192イベント、登録履歴は最大1,025端末、clientは最大128ページであり、「約3万イベントへ無制限増加」は成立しない。最大4096bit RSAの正準公開bundle・1,025端末・8,192ハッシュ・復旧公開情報で約181万bytesとなり、2MiB以下であることを回帰テスト化。clientにも同じ上限を明示して不正応答を拒否。証明を失うcheckpoint枝刈りは行わない。 |
| N-25 | message cursorとrecoveryのchannelId/versionをURLエンコード。追加query/hashを含むcursorでも一つの値に留まるテストを追加。 |
| N-26 | `.env` の作成前にumask 077。書き込み後のchmodだけに依存しない。 |
| N-27 | Electronのrequest/checkを同一述語へ統一。種類不明・空・video混在は拒否し、明示audioだけ許可。 |

### 適用時の変更

- 独立した32bytes以上の `PASSWORD_PEPPER` または `PASSWORD_PEPPER_FILE` を設定し、DBとは分離してバックアップする。紛失するとパスワード認証ができなくなる。既存pepperを無計画に交換しない。
- サーバーを停止して `db:migrate:runtime`（開発時は `tsx src/scripts/migrate-runtime.ts`）を実行する。通常のdrizzle migrationだけでは秘密を使うパスワード変換は実行されない。migratorはruntime所有lockと排出lockを取り、128件単位で既存bcryptを変換する。弱い/不明形式なら変換transactionをrollbackして停止する。
- 0016後のschema gateは17 migrations、540 catalog entries、SHA-256 `cf72e534389d6f48a3307d6bbd67b4af295be98ce0b3c2caff9902b48e5f6d84`。
- 全環境で外部checkpointを設定・検証し、matching client/serverを更新する。既存checkpointを削除して作り直すことはしない。
- deny優先への変更と、Guest/custom roleの通話権限を確認する。必要なcustom roleには管理者が明示付与する。

### 検証結果

最終検証結果は作業完了時に追記する。
