# 現行作業ツリーのセキュリティ監査

## 結論・範囲

基準コミット: `e4766f2`。監査対象は **既存の未コミット変更・未追跡ソースを含む現行作業ツリー** であり、HEAD 単体の評価ではない。

今回の確認事項は、配備時の可用性問題1件、ネイティブクライアントのログイン可用性問題1件、既知依存関係アドバイザリ4件（まとめて1項目）である。新規の Critical / High を裏付ける証拠は得ていない。これは安全性の保証でも、網羅的な脆弱性不在の証明でもない。

重点的に確認したもの:

- Android の WebView、ネイティブブリッジ、Keystore、接続・権限処理
- Electron の UI 配信、通信転送、ナビゲーション、IPC、CSP
- サーバの HTTP 構成、認証・Origin・step-up 境界、ログインチャレンジ、起動設定
- 本番 Compose、Dockerfile、CI、依存関係と既存テスト

既存監査 `SECURITY_AUDIT_2.md` / `old/SECURITY_AUDIT.md` と `docs/RISK_REGISTER.md` は背景情報として参照したが、過去の成功記録を今回の検証結果には算入していない。全サービス・暗号プロトコルの網羅的レビュー、第三者へのアクセス、攻撃再現、負荷試験、本番データの操作は行っていない。

## 1. Medium / P1 — 本番 Compose が必須の password pepper を渡さない

**状態: 設定読み込みをローカルで検証済み。未修正。認証回避ではなく配備時の可用性問題。**

根拠:

- `packages/server/src/config/index.ts:42-47,84-86` は `PASSWORD_PEPPER` を必須とし、未設定時には例外を送出する。
- `packages/server/src/config/source.ts:9-14` は直接値または `_FILE` 指定から値を取得する。
- `compose.production.yml:17-47,92-106` の環境変数・サービスへの secrets 割当・secrets 定義には `PASSWORD_PEPPER` / `PASSWORD_PEPPER_FILE` がない。
- `Dockerfile:18-19,44` にも代替設定はない。

影響: この Compose を追加の override なしで使用すると、他の秘密値が正しく設定されていてもサーバが起動できない。ホストの `.env` に値を追加するだけでは、Compose が列挙していないコンテナ環境変数は渡らない。フェイルクローズ自体は正しい挙動であり、pepper 要求を削除して解決すべきではない。

検証: `pnpm build` 後に `node --input-type=module` のインライン検査を実行。合成環境だけで `packages/server/dist/config/index.js` を別プロセスに import し、pepper なしでは終了1かつ `Missing required configuration: PASSWORD_PEPPER`、合成 pepper 追加後は終了0を assertion で確認した。ネットワーク接続やDB操作は行っていない。Compose コンテナ自体の起動は未検証。

推奨対応:

1. 他の秘密値と同様に `PASSWORD_PEPPER_FILE` と対応する Compose secret を追加する。
2. 独立した秘密を永続管理し、既存アカウントがある環境では不用意な生成し直しを避ける。
3. 本番 Compose そのものを使う起動 smoke test を追加する。現在の CI は `.github/workflows/ci.yml:209-228` の別建て `docker run` 環境に pepper を渡すので、この設定漏れを検出できない。

## 2. Medium / P1 — ネイティブ版の CSP がログイン回復用 Worker を禁止する

**状態: ソースと生成アセットの不整合を確認。実機での挙動は未検証。未修正。**

根拠:

- `packages/server/src/routes/auth.ts:40-47` はアカウント側の制限に達したログインにチャレンジを返す。
- `packages/client/src/services/api.ts:508-510` はチャレンジ応答に対し `solveLoginChallenge()` を呼ぶ。
- `packages/client/src/services/login-challenge.ts:5-8` は専用 Worker を生成する。Worker を使わない代替経路はこの関数にはない。
- 一方、Electron の `packages/desktop/src/main.ts:294-309` と Android の `packages/android/app/src/main/java/app/alparts/android/MainActivity.java:291-295` は、ともに `worker-src 'none'` を配信する。
- `pnpm build` は `dist/assets/login-challenge.worker-*.js` を生成した。

影響: チャレンジが必要になった場合、同梱クライアントは CSP によって計算用 Worker の生成を拒否され、パスワードログインの継続ができないと考えられる。通常のログインすべてが失敗するという指摘ではない。既存セッションや他の認証経路まで不能になることも主張しない。アカウント制限から正規ユーザーを回復させる仕組みが、ネイティブ版のポリシーと整合していない点が問題である。

推奨対応:

- 同梱された専用 Worker のみを許可する CSP と通信ポリシーへ整合させる。広いリモート Worker 許可や CSP 全体の解除は避ける。
- Electron/WebView の実ランタイムで、チャレンジ計算が成功し、API由来・外部由来の実行リソースは引き続き拒否される受け入れ試験を追加する。

## 3. Moderate（レジストリ評価）/ P2 — 本番依存関係に4件の既知アドバイザリ

**状態: `pnpm audit --prod --json` で確認。アプリケーションからの到達可能性・悪用可能性は未検証。未修正。**

| 依存関係・解決版 | 経路 | アドバイザリ | 公開されている修正版範囲 |
| --- | --- | --- | --- |
| `decode-uri-component` 0.2.2 | server → minio → query-string | [GHSA-vcc3-ghjq-m6fr](https://github.com/advisories/GHSA-vcc3-ghjq-m6fr) | >=0.4.3 |
| `qs` 6.15.3 | server → express（body-parser 経由も含む） | [GHSA-x5fp-wj9c-mxmx](https://github.com/advisories/GHSA-x5fp-wj9c-mxmx) | >=6.15.4 |
| `qs` 6.15.3 | 同上 | [GHSA-4mjr-xmp4-gh2g](https://github.com/advisories/GHSA-4mjr-xmp4-gh2g) | >=6.16.0 |
| `stream-json` 1.9.1 | server → minio | [GHSA-528h-pc64-c93x](https://github.com/advisories/GHSA-528h-pc64-c93x) | >=3.4.1 |

ロックファイルの根拠: `pnpm-lock.yaml:1393,2732,3052`。上記はリソース消費・サービス拒否関連の依存関係警告であり、存在だけで公開APIからの攻撃成立を意味しない。

`pnpm audit --prod --audit-level high` は終了0だったが、出力には **moderate 4件** が含まれていた。CI の `.github/workflows/ci.yml:39` は high をしきい値とするため、これらを失敗扱いにしない。成功を「既知脆弱性ゼロ」と解釈しないこと。

推奨対応: 上位ライブラリの対応版を優先して更新し、ロックファイルを更新する。特にメジャー版をまたぐ `stream-json` の強制 override は互換性検証なしに行わない。更新後は MinIO 統合試験と HTTP 試験を実施する。更新できない場合は到達可能性評価と期限付きのリスク判断を残す。`--prod` は Electron の開発依存としてのランタイムや Android 依存関係全体の評価にはならない。

## 今回の検証結果

実行環境は Node **v22.23.1** / pnpm **11.21.0**。プロジェクト要求は Node **>=24** であり、非対応ランタイムでの結果として扱う。

| コマンド | 結果 |
| --- | --- |
| `pnpm build` | 終了0。shared/server/client/desktop のビルド成功。ブラウザ互換性・dynamic import の警告あり |
| `pnpm typecheck` | 終了0 |
| `pnpm lint` | 終了0、0 warnings / 0 errors |
| `pnpm test` | 終了1。デスクトップ20件は成功。サーバーの非同期テスト中断を含むため全体成功ではない |
| `pnpm --filter @alparts/client test` | 終了0、38ファイル・151件成功 |
| `pnpm --filter @alparts/server test` | 終了1、83 tests中65 pass / 17 cancelled / 1 skipped。統合試験のスイートにもskipあり |
| `pnpm audit --prod --audit-level high` | 終了0、moderate 4件を報告 |
| `pnpm audit --prod --json` | 終了1、moderate 4 / high 0 / critical 0 |
| `bash scripts/check-secrets.sh`（出力を捕捉するPythonラッパー経由） | 終了0。追跡ファイルのみ対象。秘密値はレポートに含めていない |
| `node --input-type=module` の合成起動設定チェック | 終了0。項目1の欠落時拒否・追加時成功を確認 |
| `git diff --check` | 終了0 |

サーバーテストでは `Promise resolution is still pending but the event loop has already resolved` が発生した。`password-work.ts:142,181-183` にある watchdog/worker の `unref()` とテストライフサイクルを調査対象にすべきだが、今回原因を確定していない。Node 24 での再実行が必要であり、これを直ちに認証突破や本番障害の証拠とはしない。

検証コマンドは実装を修正するためではなく、監査時点の証拠を得るために実行した。ビルドに伴う生成物は作成・更新され得る。既存ソースの修正、依存関係更新、コミット、履歴改変は実施していない。

## 秘密情報・残存リスク・制約

- `.env` は `git ls-files --error-unmatch .env` で未追跡、`git check-ignore -v .env` で ignore 対象と確認した。ローカルファイルには秘密設定が存在するため内容はここに再掲しない。現在未追跡であることは過去流出や別環境での再利用がない証拠ではない。
- secret scan は `scripts/check-secrets.sh:15` の `git ls-files` に基づく。既存の未追跡ソース、ignore ファイル、Git履歴はカバーしていない。過去秘密の失効・ローテーションは `R-001` の外部対応事項として引き続き確認が必要。
- `R-002`（エンドポイント/配信元侵害）、`R-003`（独立バックアップ）、`R-009`（暗号・ディレクトリ保証）、`R-015`（署名付き配布/来歴）、`R-016`（独立レビュー）等の既知リスクを今回閉じる証拠はない。
- DB/MinIO統合、Android/Electron実機、OCIイメージスキャン、本番設定・バックアップ・外部証人、全Git履歴の秘密検査は実施していない。

優先順は **本番Composeの秘密供給修正 → ネイティブログインのCSP整合と実機試験 → 対応Node版でテスト中断の解消 → 依存関係更新と到達可能性評価** とする。
