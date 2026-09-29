# audit-alparts 対応記録

更新日: 2026-09-29。対象は `audit-alparts/findings/` と Phase 2 追跡監査（`c1702f0`、F-P2F-001…052）。監査原本・証拠ファイルは変更しない。
監査対象のコミットと作業ツリーは異なる。着手時点の端末承認、ディレクトリ署名検証、MLS、復旧コード、単一ランタイム制御の実装を維持した上で修正した。

## オーナーが決定した事項

- 鍵の保護は **パスキー＋復旧コード**。PRF に対応しない認証器では新しい設定を拒否する。
- 本番ホストは未定。ネイティブ版の接続先・証明書の固定値は **ビルド時に変更可能** とする。
- この記録の「実装済み」は実稼働への配備を意味しない。実アカウントの停止、公開、リポジトリの公開範囲変更は実施していない。

## 不具合と運用上の修正

| 指摘 | 対応 |
| --- | --- |
| F-KEY-001 | 過去の版を指定した取得で、宛先に含まれていた端末へ retired の未受領配送も返す。受領確認で retired を再活性化しない。結合テスト追加。 |
| F-KEY-002 | 閲覧者の増減で更新を要求。従来方式の追加配送を元のアカウント集合内に限定し、権限変更・失効後の追加配送を拒否。新しい MLS 参加者には次の版を使用。 |
| F-KEY-003 | 健全な現行鍵がある状態で不要な fresh-start を拒否。 |
| F-KEY-004 | 受領確認・中止もワークスペースの更新ロックを取得し、送信や認可変更と直列化。 |
| F-KEY-005 | 正規クライアントは署名、復号、鍵コミットメントの確認後に正確な配送へ署名して受領確認する。サーバーは平文鍵を持たず、この確認を代行できない。確認後の配送選択は変更不可という契約を維持。改造クライアントが虚偽確認するケースをサーバーが修復できるとは扱わない。 |
| F-KEY-006 | 過去メッセージの署名検証に必要な公開端末情報の保持は仕様として維持。現在の閲覧権限と対象 ID 数の上限を要求する。 |
| F-KEY-007 | 15 分以上進まない提案は管理権限を持つ承認済み端末から中止可能。全員の確認を省略して活性化することはしない。参加端末を見直してから再提案する。 |
| F-KEY-008 | 失効先の配送を削除。更新要否の判定に必要な宛先記録は残し、受領記録を消す。 |
| F-STORE-001 | 認証の世代検証と API 呼び出しの直列化。遅延したログイン応答・Cookie がログアウト後に残らない。端末初期化にも世代検証を追加。 |
| F-STORE-002 | チャンネル一覧の取得失敗・古い応答は `null`。正常に検証した一覧にない場合だけ権限消失として処理し、通信失敗で下書きや送信待ちを消さない。 |
| F-STORE-003 | 追加送信も既存の送信キューを使用。同一チャンネルでは失敗した先頭を追い越さず、他チャンネルの送信は続ける。 |
| F-STORE-004 | 下書き削除で以後の書き込みを無効化。保存中の処理が終わってから削除し、再認可時の復帰も順序付ける。 |
| F-STORE-005 | 過去ページの結果・エラーを初期読み込みの世代に束縛し、古いカーソルによる上書きを防止。 |
| F-STORE-006 | ワークスペースの一覧と選択の読み込みを個別に管理し、権限消失で古い読み込み表示が残らない。 |
| F-STORE-007 | DM 一覧の取得失敗・取り消された取得を新規作成の根拠にしない。 |
| F-STORE-008 | 通話の offer 作成と受信処理を直列化。衝突時は参加 ID による対称な規則で片側だけ rollback する。 |
| F-STORE-009 | サーバーは参加ごとに新しいランダム参加 ID を発行済み。署名には送受信の参加 ID が入り、旧参加の信号を新しい参加へ転用できない。連番のリセットだけで再送が通るという候補指摘は現行コードには当てはまらない。 |
| F-STORE-010 | 古い端末一覧に新参加者が含まれない場合に一度再取得。検証後も通話世代と現在の参加者を再確認。 |
| F-STORE-011/012 | 再参加を上限付きの待ち時間で継続。参加確認に期限を設け、履歴取得は確認待ちに依存させない。 |
| F-STORE-013 | 入力中表示を 8 秒で失効し、再通知で延長。チャンネル削除・リセット時にタイマーも削除。 |
| F-STORE-014 | 自分が送ったイベントを未読加算から除外。 |
| F-STORE-015 | 他チャンネルの読み込みが残る間は全体の読み込み表示を維持。 |
| F-STORE-016 | 中止したアップロードの実行枠と File 参照を解放。 |
| F-STORE-017 | 表示中チャンネルを履歴キャッシュの退避対象から除外。 |
| F-STORE-018 | ブックマーク操作の保存中フラグと要求識別子を終了時に削除。古い応答は新しい操作を消さない。 |
| F-STORE-019 | 復号済みの結果を 64 件ごとに反映し、途中キャンセルでも進捗を保持。 |
| F-PERF-001 | 正規化済みの配列を再利用し、投影の再ソートを削除。受信イベントをまとめて反映。上限 1000 件の既存テストも通過。 |
| F-COORD-001 / F-DEP-* | query parser を simple に固定。qs 6.16.0、stream-json 3.5.0、decode-uri-component 0.5.0 に更新。MinIO/query-string の互換パッチと実際の通知ストリームのテストを追加。監査にあった未公開の修正版番号は使用していない。 |
| F-COORD-002 | `disabled_at` と運用者用 CLI を追加。全セッション削除、接続切断、パスワード・パスキーの新規認証拒否。再開しても古いセッションは復活しない。 |
| F-COORD-003 | readiness の同時検査を共有し、成功・失敗とも 2 秒キャッシュ。draining はキャッシュを使用せず拒否。 |
| F-COORD-004 | PostgreSQL のランタイム占有・処理完了待ちのロックが実装済み。複数プロセスを許す変更はしていない。CLI の監査書き込みも処理完了待ちのロックで保護。 |
| F-INPUT-001 | 各名称の入力で制御文字・双方向表示制御・不可視文字を拒否し、NFC に正規化。日本語等の通常の名称は許可。 |
| F-SUPPLY-001 | 依存更新に 7 日の minimumReleaseAge。CI は moderate 以上の脆弱性も失敗条件にする。 |
| F-MOBILE-001 | Android の被覆タッチ拒否、対応 OS の他アプリ重ね合わせ防止を追加。警告ダイアログにも適用。 |
| resolved Promise の保持 | coalesced-value-loader は完了した要求を Map から削除。 |

## Phase 2 追跡監査（F-P2F）への対応

| 指摘 | 対応 |
| --- | --- |
| F-P2F-001 / 049 | **リスク受容**（2026-09-29、オーナー判断）。履歴に残る `.aurea/aurea.db` と `.commandcode/` の値は使い捨ての開発用であり、実環境では使っていないため、履歴からは削除しない。これらの値を実環境で使ってはならない。コード側は pepper の切り替えに対応：保存形式 `p2:`（pepper 識別子付き）、`PASSWORD_PEPPER_PREVIOUS` による旧 pepper の受け入れ、ログイン成功時の自動再保護と監査記録。 |
| F-P2F-002 | パスワード処理をファイルから読み込む worker（`password-worker.ts`）に変更し、文字列からのコード生成を使わない。本番イメージを `--permission` と `--disallow-code-generation-from-strings` 付きで起動し、登録・ログイン・誤パスワード拒否を確認。 |
| F-P2F-003 / 032 / 033 / 048 | `audit-alparts/`・`old/`・`bun.lock`・`SECURITY_AUDIT_2.md`・生成物 `tsconfig.tsbuildinfo` を追跡対象から外す（手元のファイルは残す）。`.gitignore` にエージェント状態、DB、鍵・証明書、ドット無しの `*.env` などを追加。`.gitattributes` を追加。 |
| F-P2F-004 | 履歴鍵の書き出しでも、配布者の公開鍵を検証済みディレクトリと照合してから開封する。 |
| F-P2F-005 | 履歴の復元で、使えなくなったチャンネルの鍵は飛ばして残りを復元する。 |
| F-P2F-006 | 失敗した履歴バックアップの印を読み、ログイン後に自動で再送する。 |
| F-P2F-007 | 使われない MLS パッケージを削除（確定済みの参加者一覧に含まれない版、および古い版を 8 件超えた分）。 |
| F-P2F-008 | 署名済み履歴の食い違い（`INVALID_MLS_TRANSCRIPT` など）を「自分宛てでない配送」として握りつぶさず、エラーとして返す。 |
| F-P2F-009 | 保存済み鍵の再利用は、検証時の鍵コミットメントと配送のコミットメントが一致する場合に限る。 |
| F-P2F-010 | 鍵の宛先一覧を上限（50 人・400 端末）と重複で検証。 |
| F-P2F-011 | API パスの各要素を送信前に検証し、区切り文字や `..` を含む値を拒否。 |
| F-P2F-012 | パスキーでのログインは 10 分以内に限り、端末追加の本人確認として扱う。 |
| F-P2F-013 | 承認済み端末への復旧リプレイではディレクトリにイベントを追加しない。 |
| F-P2F-014 / 041 | 共通のエラー処理で、端末・鍵・送信の既知のエラーを 403/404/409/428/503 に対応付け。 |
| F-P2F-015 | ランタイムの占有を失った場合も 30 秒の強制終了期限を設ける。 |
| F-P2F-017 | CI の配布物ビルドに証明書固定値を渡す手順を追加（リポジトリ変数、PR では到達不能な名前のテスト値、手動実行では未設定を拒否）。 |
| F-P2F-018 / 027 | `dev.sh` が `.env.example` の全設定と `*_FILE` を受け付ける。既存 `.env` の権限を所有者のみに修正。 |
| F-P2F-019 | 本番 compose で metrics token・旧 pepper を任意化、監査 witness の設定とディレクトリを配線、`ALLOW_INSECURE_LOOPBACK_DEPENDENCIES` を app にも渡す。 |
| F-P2F-020 | `meta/0018_snapshot.json` を現在の `schema.ts` から生成（`drizzle-kit generate` が変更なしを返すことを確認）。移行フォルダーに README を追加。 |
| F-P2F-021 / 028 | 移行 `0018_append_only_guards.sql`：ディレクトリの TRUNCATE 拒否、`audit_logs` の更新・削除・TRUNCATE 拒否、`authentication_challenges.session_id` の索引。 |
| F-P2F-022 / 023 / 024 / 025 | バックアップのロックを `/run/lock/*.lock` に限定し切り詰めずに開く。子プロセスからアプリのシークレットも除去。オブジェクトは検証済み一覧のキーだけを複製。復号結果は上限を超えた時点で書き込みを止める。 |
| F-P2F-026 | `secretlint` にファイル名を渡す前に `--` を付与。 |
| F-P2F-030 | macOS の `disable-library-validation` を削除（ネイティブアドオンは同梱していない）。 |
| F-P2F-031 | Android の保存名をデスクトップと同じ規則（NFKC、区切り・制御・書式/双方向文字の置換）に統一。 |
| F-P2F-034 | `.dockerignore` に監査資料・エージェント状態・文書・スクリプト・ネイティブ版を追加。 |
| F-P2F-035 | 開発用 postgres に `no-new-privileges`。 |
| F-P2F-036 | Android CI で Gradle wrapper を公式チェックサムと照合。dependabot に gradle を追加。 |
| F-P2F-037 | CodeQL の SARIF を成果物として保存し、検出があればジョブを失敗させる。 |
| F-P2F-038 | バックアップ unit に `ProtectClock`・`ProtectHostname`・`ProtectKernelLogs`・`ProtectProc`・`ProcSubset`・`RestrictNamespaces`・`RestrictRealtime`・`SystemCallArchitectures` を追加。 |
| F-P2F-039 | デスクトップ/Android の CSP で同梱 worker を許可（`worker-src 'self'` / アセットのみ）。 |
| F-P2F-040 | ロールの解除は、対象メンバーの順位が操作者より低い場合に限る（オーナーは不可、自分自身は可）。プレビューも同じ。 |
| F-P2F-042 | 変更なし。デスクトップは失敗時に一時ファイルを削除済み。ブラウザーは中断時に書き込みを破棄し、元のファイルは閉じるまで置き換わらない。 |
| F-P2F-043 | サーバーのエラー文言を画面に出さず、状態とコードから固定の文言を表示。 |
| F-P2F-044 | ログイン終了時の文言で、別の端末からのログアウトの可能性と確認方法を示す。 |
| F-P2F-045 | 権限変更イベントの待ち行列が上限に達したら、個別イベントを捨てずに 1 回の全体再読み込みにまとめる。 |
| F-P2F-046 | 開発者用語の権限名、未知の権限名・ID の生表示、`Invalid Date`、`Loading...` を修正。 |
| F-P2F-047 | Vite の許可ホストを `VITE_ALLOWED_HOSTS` へ移動。 |
| F-P2F-050 | 表示名で点字空白・ハングルの埋め字を拒否し、表示できる文字を 1 文字以上要求。 |
| F-P2F-051 | `TRUSTED_PROXIES` は IP・CIDR・`loopback` のみ。本番では /8（IPv6 は /32）より広い範囲を拒否。起動ログに有効な値を出力。 |
| F-P2F-052 | CI に履歴全体の検査を追加（禁止ファイルの検出と gitleaks）。上記のリスク受容分だけを、コミットとパスの組（`scripts/check-history-files.sh`）と finding 単位（`.gitleaksignore`）で除外。同じパスでも新しいコミットで追加されれば失敗する。 |
| F-P2F-029 | JWT のアルゴリズム混同・発行者/対象/期限、`javascript:` などのリンク、期限切れ招待、招待の同時使用、非メンバーの送信、ロール解除の階層、古いパスキーセッションでの端末追加、TRUNCATE 拒否のテストを追加。 |
| 観測事項 | 未使用コード（`getReactions`・`getReadPositions`・`startFreshChannelKey`）を削除。デスクトップのログアウトで HTTP キャッシュを消去。ADR 一覧・検証日・移行数・`audit:witness` スクリプトを更新。 |

## 暗号・配布・運用の状態

| 指摘 | 現在の状態と残る範囲 |
| --- | --- |
| マスター鍵の保護 | パスキーの PRF でランダムな 256 bit 復旧用秘密を包む。アカウント、設定世代、認証器、RP を束縛。復旧コードは同じ秘密への代替経路。保存用の鍵は別途導出し、保存用の鍵だけでは復旧署名鍵を開けない。PRF 応答はサーバーへ送らない。現在の復旧署名鍵は既存の P-256 であり、草案の SLH-DSA マスター認証局全体を実装したものではない。 |
| F-E2E-001 | 既存の署名付き端末承認、ディレクトリの履歴検証、利用者同士のチェックポイント照合を維持。初回接触時の信頼と、独立した鍵透明性ログは未解決。 |
| F-E2E-002 | 既存の MLS による版ごとの新しい鍵と 24 時間の更新期限を維持。履歴用の鍵を保持するため、メッセージごとの前方秘匿性や侵害後の自動回復を保証しない。DM のラチェットは未実装。 |
| F-E2E-003 | 新しい本文を暗号化前に 1–16 KiB の 2 の累乗単位へパディング。空の添付メッセージも含む。旧本文は読める。添付最終チャンクの長さ、通信時刻・量・相手・通話参加情報は残る。旧クライアントは新しい本文形式を読めないため、配布時はクライアントとサーバーを一緒に更新する。 |
| F-PQC-001/002 | **未実装**。現行の MLS/RSA/ECDSA は量子計算機に対する保護を保証しない。草案の HQC/Frodo/Falcon/QR-UOV を組み合わせる新方式、配布分割、三重 AEAD は採用実装・試験ベクトル・相互運用・外部レビューが未確定。代替アルゴリズムを勝手に採用したり、未監査の自作方式で完了扱いにしたりしない。 |
| F-PQC-003 | 新しいサーバーバックアップは age の native hybrid recipient のみ許可。実ツールで往復検証済み。旧バックアップの過去の漏えいは後からの暗号化では取り消せない。 |
| F-NET-001 | ネイティブ版の証明書固定をビルド時設定化。現在・予備の 2 本以上を要求し、通常の CA/ホスト/有効期限検証も維持。本番ホスト未定のため CAA/CT の実運用設定は未実施。 |
| F-TRUST-001 | オフライン SLH-DSA-SHA2-256s の鍵生成・署名 CLI、署名・期限・配備先・監査チェーンとの照合を実装。稼働サーバーは公開鍵のみ必要。実運用の独立署名者・公開鍵・署名済みファイルは未発行。保管先の独立性と更新作業は別途必要。 |
| F-TRUST-002 | 実在する管理者を CODEOWNERS に設定。GitHub の rulesets API は契約条件によって 403。承認必須・署名必須の強制設定は未適用。公開範囲や契約を変更していない。 |
| F-CONTAIN-001 | Docker/systemd の Node を権限制限と文字列からのコード生成禁止で起動。systemd 例は外向き通信を localhost に限定。Node の worker 許可はサンドボックスを保証しないため OS の制限を併用。外部依存先を使うコンテナの通信許可リストは配備先で設定する。 |
| ブラウザーの配信元が悪意を持つ場合 | パスキー保護だけでは、秘密を利用者が解除した後の悪意ある同一オリジン JS を排除できない。独立した配信検証器・透明性基盤は未実装。 |

## 導入手順

### パスキーと復旧コード

対応するパスキーを登録後、「履歴の復元」で新規設定する。コードは端末外に保管する。
同期型のパスキーもあり得るため、すべてのパスキーを物理機器に固定された鍵と説明しない。
旧設定は読み取り互換を維持するが、自動的に新しい保護方式へ変換しない。
設定は対応する認証器を使い、サーバーの HTTPS オリジンで Web 版を開いて行う。
ネイティブ版のパスキー連携は未実装であり、復元には保管済みの復旧コードを使う。
実認証器を用いた PRF 対応確認は配布前に必要。

### 接続先のビルド設定

`packages/desktop/transport-pins.json` は空の開発用既定値。配布用には次の形式のファイルを別途用意する。
`hosts` のキーは正確なホスト名。値は leaf 証明書の現在用と更新予備用の SPKI SHA-256 を通常の Base64 で表したもの。ワイルドカードは使わない。

```json
{"version":1,"hosts":{"chat.example.test":["現在の公開鍵の SHA-256 Base64","予備の公開鍵の SHA-256 Base64"]}}
```

上記は形式の説明であり、そのままビルドに使える値ではない。証明書管理者から独立して確認した値を使う。
受信した証明書を無確認で信頼する仕組みは設けていない。

```bash
ALPARTS_TRANSPORT_PINS_FILE=/secure/release/transport-pins.json pnpm desktop:dist
cd packages/android
./gradlew -PalpartsTransportPinsFile=/secure/release/transport-pins.json assembleRelease
```

Android も `ALPARTS_TRANSPORT_PINS_FILE` を利用できる。ファイルは絶対パスで指定する。
値はアプリへ組み込まれ、起動後の環境変数では変更できない。未設定の開発ビルドは通常の証明書検証を行い、配布用ビルドは未設定を拒否する。
更新予備の鍵を配布してからサーバーの鍵を切り替える。pin に失効期限を付けて自動的に検証を無効化することはしない。

### アカウント停止

移行 `0017_audit_remediation.sql` を適用後、運用者がサーバーと同じ DB・監査設定で実行する。
ワークスペース管理者用の HTTP API は作らない。

```bash
node packages/server/dist/scripts/set-account-state.js disable USER_UUID
node packages/server/dist/scripts/set-account-state.js enable USER_UUID
```

### 独立した監査署名

Node 24.8.0 以上が必要。サーバー外のオフライン端末で鍵を作り、独立して確認したチェックポイントのみ署名する。
署名ツールはチェックポイントの元になる DB の真実性を代行して保証しない。過去の署名と継続性を確認し、別管理の保管先にも残す。

```bash
node packages/server/dist/scripts/audit-witness.js keygen offline-private.pem witness-public.pem
node packages/server/dist/scripts/audit-witness.js sign offline-private.pem checkpoint.json DEPLOYMENT_UUID witness.json
node packages/server/dist/scripts/audit-witness.js verify witness-public.pem witness.json DEPLOYMENT_UUID
```

秘密鍵は稼働サーバーへ持ち込まない。公開鍵と署名済みファイルはアプリから書き換えられない場所へ置く。
署名は 24 時間有効。失効前に新しいファイルを原子的に配布する。次を設定すると、欠落・不正・期限切れの場合、起動・readiness・監査対象の書き込みが失敗する。

```dotenv
AUDIT_WITNESS_REQUIRED=true
AUDIT_WITNESS_PUBLIC_KEY_FILE=/run/secrets/audit_witness_public_key
AUDIT_WITNESS_PATH=/run/secrets/audit_witness
AUDIT_WITNESS_DEPLOYMENT_ID=配備ごとに固定したUUID
```

署名されるまでの末尾には未証言の期間が残る。サーバーが完全に乗っ取られた際の外部検出には、独立した署名者・ファイル管理・保管を実際に維持する必要がある。

## 検証

- Node 24.21.0 で型検査・Lint・ビルド・各パッケージのテストを実行。
- クライアント 168 件、サーバー 87 件（結合実行用の 1 件は通常実行時にスキップ）、デスクトップ 22 件が成功。認証競合、下書き削除、送信順序、履歴ページ競合、通話の offer 衝突、読み込み状態、本文パディング、PRF に回帰テストを追加。
- 独立した PostgreSQL 16 / MinIO で認可・暗号化メッセージ・WebSocket・鍵・パスキー・復旧・停止 CLI の結合テスト。一般 4 件、アカウント関連 15 件が成功。
- 移行 0018 適用後のカタログは 546 エントリー、SHA-256 `234ac4b731dfa3bf96c3c9c68f1d12ba4623d562741264e5d1c7ac1c1b233eef`。
- Android: assembleDebug、testDebugUnitTest、lintDebug、runtimeInventory。
- 両ネイティブ版でビルド時の別設定ファイルの組み込みと、空の配布用設定の拒否を確認。仮のテスト用ホストは配布設定に残していない。
- オフライン署名 CLI の往復、権限制限付きの本番モード起動、クライアント配信、監査署名の改ざんによる readiness の拒否と正常署名の復元後の回復を確認。
- バックアップの安全性・リリース検証。age 1.3.2 による hybrid recipient の実暗号化・復号。
- 依存監査は検出 0 件。秘密情報スキャンも実行。

## 参照

- [WebAuthn PRF](https://www.w3.org/TR/webauthn-3/#prf-extension)
- [age の PQ 対応](https://github.com/FiloSottile/age/releases/tag/v1.3.0)
- [stream-json の修正版](https://github.com/advisories/GHSA-528h-pc64-c93x)
- [Electron の証明書検証](https://github.com/electron/electron/blob/main/docs/api/session.md#sessetcertificateverifyprocproc)
- [Android の証明書固定](https://developer.android.com/privacy-and-security/security-config#CertificatePinning)
- [Android の被覆タッチ対策](https://developer.android.com/privacy-and-security/risks/tapjacking)
- [Node 24 の暗号 API](https://nodejs.org/download/release/v24.21.0/docs/api/crypto.html)
