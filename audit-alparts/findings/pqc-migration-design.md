# Alparts PQC ハイブリッド暗号設計書（草案）

内部チーム選定アルゴリズムに基づく統合設計。実装はまだ行わない。

## 選定プリミティブ

| 用途 | 現行 | 新規 |
|------|------|------|
| 鍵カプセル化 | RSA-OAEP-256 | ML-KEM-1024, HQC-256, FrodoKEM-1344-SHAKE |
| 署名 | ECDSA P-256 | Falcon-1024, SLH-DSA-256, QR-UOV(Cat5) |
| 対称AEAD | AES-256-GCM(128bit tag) | XChaCha20-Poly1305, AEGIS-256(256bit tag) |

## 設計原則

1. **組合せ安全性**: 全レイヤーで「攻撃者は全構成要素を破る必要がある」を統一方針とする。KEMは全共有秘密の連結KDF（**全因子——4 KEM + RSA + ws_psk——のdecap/unwrap成功を必須とし**、SSを得るには全因子の突破が必要＝どれか1つが安全なら機密性保持）、署名はAND結合（必須署名の全てが検証必須＝ダウングレード不可）、AEADは入れ子（全層を破らなければ機密性も完全性も破れない）。
2. **トランスクリプト束縛**: 全ての組合せで、アルゴリズムID・公開鍵・暗号文・コンテキストを単一のKDF入力に連結。クロスプロトコル移植を排除。
3. **fail-closed**: 1つでも復号・検証が失敗すれば全体を拒否。段階的フォールバックなし。
4. **crypto-agility**: 既存の `keyVersion`/`envelope.version` 機構を拡張し `cryptoSuite` フィールドを追加。スイートID自体を署名/AADに束縛し、ダウングレードを構造的に防止。

## 1. 複合KEM（チャンネル鍵配送）

### 組合せ式

```
SS = KDF-SHAKE256(
  "alparts-ckwrap-v2" ||
  len(ss_mlkem)||ss_mlkem || len(ss_hqc)||ss_hqc ||
  len(ss_frodo)||ss_frodo || len(ss_x25519)||ss_x25519 ||
  len(ss_rsa)||ss_rsa || len(ws_psk)||ws_psk ||
  pk_transcript_hash || ct_transcript_hash ||
  channelId || epochVersion || senderDeviceId || recipientDeviceId
)
```

**6因子構成**:

- `ss_x25519`: 受信デバイス長期DH鍵への新規X25519 ECDH。
- `ss_rsa`: **既存RSA-OAEP-3072鍵を追加因子として維持**。送信者はランダム256bit値 `ss_rsa` を生成しRSA-OAEPで暗号化（実質RSA-KEM）。受信者はdecryptして入力に連結。既存インフラを廃棄せず防御層として再利用 — RSA-OAEP単体では量子脆弱でも、結合の1因子としては「攻撃者は追加でRSA-3072も破る必要」を維持。
- `ws_psk`: **ワークスペースPSK**（32B、オプション・paranoidワークスペースのみ）。オフラインセレモニーで生成・QR/安全経路で新メンバーへ手渡し。サーバーには一切置かない。**全KEM+全実装が破られても、サーバーに存在しないこの値が内容を守る**最終防壁。既定は無効（運用負荷とのトレードオフ）。**注意**: ws_pskを「既メンバーが承認経路で新デバイスへ転送」する運用を許可すると、その転送経路は複合KEMでしか保護されないため、全KEM突破の攻撃者は転送時にws_pskも奪取でき「最終防壁」性が失われる。paranoidモードでは**QR/オフライン手渡しのみを許可**し、アプリ内転送は標準ティアでのみ許容する。

各成分は全て必須（1つでもdecap/unwrap失敗 → 全体拒否）。`ss_rsa`/`ws_psk` が空の場合は長さ0として連結し、スイートIDでその構成を固定（後述のポリシーで「空許容」を制御）。

- `pk_transcript_hash`/`ct_transcript_hash` は全公開鍵・全暗号文の連結SHA-512。recipientが検証してからdecapに進む（改竄された束の部分復号を防ぐ）。
- 実装は**全因子を必ず実行してからAND結合**する。部分失敗の観測（どの成分が壊れたかのオラクル）を防ぐため、**早期returnは禁止** — 失敗しても残り成分のdecapを最後まで実行し、最後にまとめて拒否する。実行順序に意味は持たせない。
- 出力SSは256bit。HKDFで `key_aes`, `key_xchacha`, `key_aegis`, `key_commit`, `key_kc`(鍵確認用) に分離。

### 鍵確認ラウンド

束を受け取ったデバイスは `KC = HMAC-SHA-512(key_kc, transcript_hash || "key-confirm")` をサーバーへ返送し、サーバーは送信者へ転送。送信者は全受信者のKCが揃うまでepochを pending とする。効果:

- 注入/stripping攻撃の即時検出（攻撃者は正しいSSを持たないため正当なKCを生成不可）
- 「送ったが届いていない」デバイスの可視化（既存のpendingKeySync機構と統合）
- オフライン受信者は次回同期時にKCを返送 — 既存の再試行経路を流用

### メッセージ鎖（オプション強化）

チャンネル内で各メッセージのAADに `prevEventHash`（直前の確定済みイベントのSHA-512）を含める。効果:

- サーバーによる**メッセージの順序入替・削除・挿入が鎖の破断として検知可能**（現行は署名のみで、鎖は追加の改竄検知層）
- 実装注意: 並行送信で分岐するため、「鎖は検証ではなく監査指標」として扱い、分岐は許容しつつ記録する設計が現実的（厳密鎖は会話の直列化コストが高い）

### 帯域問題（最重要の実務課題）

デバイス毎の暗号文サイズ（概算）:

| KEM | ct |
|-----|-----|
| ML-KEM-1024 | ~1.6 KB |
| HQC-256 | ~14.4 KB |
| FrodoKEM-1344 | ~21.6 KB |
| X25519 | 32 B |
| 合計/デバイス | **~38 KB** |

現行RSA-OAEP（~512B/デバイス）の約75倍。400デバイスfanoutで ~15MB — 現行512KBボディ制限を超えるため、**push型fanoutは破綻する**。

**対策: staged distribution（Signalのlast-resort prekey方式に準拠）**
1. 送信者は受信者デバイス毎の複合KEM暗号文を生成し、サーバーの `key-bundle staging` エンドポイントへチャンクアップロード（1デバイス毎 or N件束）。
2. サーバーは暗号化された束のみ保持（E2EE維持）。
3. 各デバイスは次回同期時に自分宛の束をpull・decap。`useSocketEvents` の既存 `pendingKeySyncIds`/`retryChannelPreparation` 経路をそのまま使える。
4. これにより送信者の一回のリクエストが巨大化せず、オフライン受信者への再試行も既存機構で処理できる。

公開鍵側（受信者が事前公開する複合KEM ek束）も ~30KB/デバイスになるため、`GET /api/devices` のディレクトリ応答が肥大化する。対策: ek束はデバイス登録時に別エンドポイントへPUT、GETは「ek束のハッシュのみ返し、実体はキャッシュ可能な `/api/devices/:id/pq-bundle` から個別取得」（CDN的にimmutableキャッシュ可）。

## 2. 複合署名（メッセージ/エンベロープ）

### 方針: 用途別ティア

| ティア | 対象 | 構成 | 理由 |
|--------|------|------|------|
| **T1: 高頻度** | メッセージ・編集・削除・voice signal | ECDSA-P256 + Falcon-1024 + QR-UOV-5 | 格(lattice/multivariate/NIST-lattice)の3系統を全メッセージに要求。**サイズ注意**: QR-UOVの署名は~数KB〜10KB級、pkはCat5で~40KB級と大きい（正式値は提出パッケージで要検証）。T1採用の場合、メッセージ1件あたり署名合計~10KB超・デバイス束に+~40KBの帯域コストがかかる |
| **T2: 中頻度・高価値** | チャンネル鍵epoch確定・デバイス登録・権限変更署名 | ECDSA-P256 + Falcon-1024 + QR-UOV-5 | 同上。さらに鍵epoch確定にはKCラウンド完了も要求 |
| **T3: 低頻度・根幹** | 監査チェックポイント・リリースマニフェスト・デバイスルート証明 | ECDSA-P256 + Falcon-1024 + QR-UOV-5 + SLH-DSA-256 | SLH-DSA署名~30-50KB・署名生成~秒級だが年/月単位操作なので許容。全4系統を突破しないと偽造不可 |

### マスターアイデンティティ鍵（F-E2E-001の部分解決）

ユーザー毎に**オフライン・マスター署名鍵**（SLH-DSA-256、デバイス外・セキュアエレメント/紙バックアップ保管）を新設し、各デバイス鍵束をマスター鍵で証明するミニPKI:

- サーバーが rogue device を注入しても、マスター鍵の証明がないデバイス束は他ユーザーが警告表示（既定: 未証明デバイスは「新しい端末」として明示表示）
- 現行F-E2E-001「サーバー仲介のデバイスディレクトリを全信頼」のギャップを、**ユーザーのオフライン鍵で閉じる**
- 運用負荷: デバイス追加時にマスター鍵の署名が必要（QRコード経由など）。paranoidワークスペースでは必須化、一般では警告のみ
- 代替: 全デバイス束のハッシュを透明性ログ/アンカーチェーン（監査チェックポイントに含める）に登録し、事後検知のみでもF-E2E-001を大幅に緩和

### マスター鍵の導出・保護方式（選択は開発チームに委任）

マスター鍵を「ユーザーが持つ秘密」からどう導出・復元するかは、以下のいずれかとし、**採否は開発チームの判断に委任する**。

| 方式 | 内容 | 強み | 正直な限界 |
|------|------|------|-----------|
| **パスワード+ユーザー名導出** | Argon2id等の強化KDFで `username || password` からマスター鍵（またはそのwrap鍵）を導出 | 追加デバイス/UXゼロ・既存パスワード基盤を流用 | パスワード強度に依存。オフライン総当たりに弱いためサーバー側ペッパー/レート制限との併用が前提。既存ログイン/ vault とのドメイン分離必須 |
| **パスキー（WebAuthn `prf`）** | 認証器から秘密を導出しマスター鍵（またはKEK）とする | **ハードウェア束縛で最強** — フィッシング耐性・生バイト非露出 | `prf` 対応はプラットフォーム依存。紛失時の代替経路（回復コード等）が別途必要 |
| **TOTP** | 時間同期OTPを導出入力に使う | 実装が最も簡単 | **単独ではエントロピー不足（~30bit）** — 必ずサーバー側秘密やrate-limitedリリース機構と組合せること。単体採用は不可 |
| **Signal型PIN + セキュアリカバリ** | PIN + サーバー側のSGV/SVR的な rate-limited エスクローで鍵を保護 | PIN UXで実質的な強度（ブルートフォースはエンクレーブ側で制限） | エスクロー基盤の構築コストが最大。サーバー側コンポーネントの信頼前提が増える |

**複合も可**: 「パスワード導出 + TOTP」や「パスキー + PINフォールバック」等の組合せは有効（片方が弱くてももう片方で補強）。

> **実装担当がAIエージェントの場合**: この選択肢はユーザー体験とセキュリティ運用に直結するため、**自律的に選ばず、必ずユーザー（人間のオーナー）に確認してから実装すること**。上記のトレードオフ表を提示した上で選択肢を尋ね、承認された方式のみを実装する。

### ek束の自己署名（必須要件）

公開側の複合KEM ek束は、**そのデバイスのT1/T2構成署名鍵での自己署名を必須**とする（マスター鍵証明とは別層）。さもなければサーバーは新規登録デバイスのekを差替えて、そのデバイス宛の鍵配送を恒常MITMできる。自己署名検証は束の取得者全員が必須実施し、検証失敗束は取得時点で破棄・記録する。マスター鍵証明（paranoid）はこの上に乗る追加層。

### AND検証ルール

```
verify(payload, [sig_ecdsa, sig_falcon, sig_qruov]):
  suite = envelope.cryptoSuite      # 署名対象に含まれる
  required = POLICY[suite]          # 例: T2なら3つ全て
  for each required alg: verify必須（1つでもfail → 全体拒否）
  extra sigs present → 全て検証（未知algがあっても検証成功したら受理）
```

- **部分受理なし**: 提示された署名のうち必須セットが全てvalidでなければreject。
- ダウングレード防止: `cryptoSuite`は `serializeMessageEnvelope`/`serializeMessageAad` に組み込み、署名自体がスイートを固定。
- 移行期間: レガシー（ECDSAのみ）は epoch<=N で受理、`epoch>N` は hybrid必須をサーバー側で強制。UIは旧メッセージに「旧形式」表示（文言ポリシー準拠で技術詳細は出さない）。
- **epoch pinning 対策**: epochはサーバー協調のカウンタであり、悪意あるサーバーは意図的にepochを進めず全員をレガシー期間に留められる。**クライアント側でも期限強制が必須**: 固定日付以後・またはワークスペースポリシーで「hybrid必須」をローカルに強制し、epoch<=Nであっても期限後のレガシー署名は拒否する。サーバー強制は防御深度として残す。

### 各署名の実装リスク

- **Falcon-1024**: 浮動小数点依存・実装複雑。PQClean/liboqsの検証済み実装をWASM化。署名は deterministic（nonce失敗リスクなし）。検証は軽い。FN-DSA(FIPS 206) 最終規格との差分は要追跡。
- **SLH-DSA-256**: FIPS 205確定。署名生成が遅い（秒級）ためT3限定。検証も遅いが頻度が低い。pk小さい(64-80B)。
- **QR-UOV Cat5**: NIST追加署名ラウンド2候補で未標準化・参考実装のみ。**最も成熟度が低い**。T1に採用すると**ホットパスに乗る** — AND結合で「破られても安全性維持」だが、実装バグは可用性リスクになる。対策: (a) vendor固定+KAT全通過必須、(b) WASM isolate、(c) 独立実装との差分ファジング。**フォールバック条件**: 監査で十分な信頼が得られない場合のみ T1 を ECDSA+Falcon に戻し QR-UOV は T2+ に留める（これはセキュリティ上のダウングレードではなく可用性判断）。

## 3. 対称AEADカスケード

### 構成: 入れ子三重AEAD

```
inner  = AES-256-GCM(K0, N0(12B random), plaintext, AAD)      # 現行層を維持（FIPS互換・実績）
mid    = XChaCha20-Poly1305(K1, N1(24B random), inner, AAD || "mid")
outer  = AEGIS-256-256tag(K2, N2(32B random), mid, AAD || "outer")
stored = N0 || N1 || N2 || outer
```

- K0,K1,K2 は `key_aes`/`key_xchacha`/`key_aegis`（KDF分離済み、独立）。
- **3つ全てを破らなければ破れない**。3系統（SPN/ARX/AES-NIベース、ストリーム+Poly1305、AES-roundベース）の設計多様性で、単一の暗号解析的ブレイクスルーでは全層が同時に崩れない。
- 各層のタグ: GCM=128bit, Poly1305=128bit, AEGIS=256bit（最外層が最大の余裕）。
- nonceは全てランダム（96/192/256bit）。AADには既存 `serializeMessageAad` + cryptoSuite + `prevEventHash`(鎖を使う場合)。

### メッセージ単位の鍵確定（invisible-salamanders系対策）

各メッセージに `kc = HMAC-SHA-512(key_commit, N0||N1||N2)` をAAD内フィールドとして追加。多受信者AEADで「同じ暗号文が異なる鍵で別々に正当化される」invisible-salamanders型攻撃を構造的に排除。チャンネル鍵コミットメントとは別物（こちらはメッセージ毎）。

### パディング（F-E2E-003の部分緩和）

平文を **2の累乗バケット**（…/1KB/2KB/4KB/8KB/16KB/32KB）にPKCS#7的パディングしてからinnerに投入。添付チャンクは既に固定境界なので、最終チャンクのみパディング。効果:

- サーバー/ネットワーク観察者への**メッセージ長による内容推定の粒度を粗くする**
- 完全なトラフィック解析対策ではない（タイミング・量・相手は残る）が、低コストで有意な緩和

### keyCommitment

- **SHA-256 → SHA-512 へ更新**（量子衝突余裕: SHA-256はGroverで~85bit、SHA-512で~170bit）。既存 commitment フィールドはbase64固定長ではないため拡張可能。

### 実装上の注意

- **GCMランダムnonceの限界**: 96bitランダムnonceは同一鍵で ~2^32 メッセージが安全限界（誕生日境界）。最内層のため破れても外層が守るが、epochローテーションで実用上問題にならない閾値に留める。
- **AEGIS-256の実装成熟度**: AES-GCMと比較して監査済み実装が少ない（RFC 9458系・libsodium系の実装をvendor）。KAT+差分ファジング対象に含める。
- **三重AEADのコスト**: 暗号化3重実行でメッセージ処理 ~3倍 — 実測ベンチ必須（Phase D）。特に添付チャンクの連続処理で顕在化。

### 適用面

| 面 | 変更 |
|----|------|
| メッセージ本文 | 三重AEAD（上記構成） |
| 添付チャンク | 同上。chunk境界/AAD構造は既存のまま、AEAD層のみ差替 |
| local-state暗号化 | AES-GCM → 三重AEAD。AADの owner/device/purpose束縛は維持 |
| outbox永続化 | 同上 |
| voice signal | 署名のみ（転送は既にTLS+SRTP想定）。SRTP層のPQ化は別フェーズ |

## 4. 既存 finding との関係（この設計が閉じるもの）

| finding | この設計での扱い |
|---------|-----------------|
| **F-PQC-001 (HNDL)** | 複合KEM+三重AEADで内容のHNDL耐性を獲得（**ただしメタデータは残る** — F-E2E-003は別途） |
| **F-TRUST-001 (監査署名鍵常駐)** | SLH-DSA-256を**オフライン・コサイナー**に採用すれば構造的に解決可能：サーバーは行HMACのみ、チェックポイント署名は外部SLH-DSA署名者が行う。サーバー侵害では署名偽造不可 |
| **F-E2E-001 (鍵透過性)** | **大幅緩和**: オフライン・マスター署名鍵（SLH-DSA）によるデバイス束証明 + 鍵透明性アンカーで、サーバー注入は「警告表示」または「事後検知」に格下げ。完全解決にはユーザー検証セレモニー（安全性番号等）が必要 |
| **F-E2E-002 (前方秘匿なし)** | **緩和**: epoch自動ローテーション+旧鍵破棄で侵害時の被害窓を縮小。完全なPCSにはPhase Cのラチェット層が必要 |
| **F-E2E-003 (メタデータ)** | **部分緩和**: 2の累乗パディングで長さ推定を粗化。タイミング/相手/量は別途トラフィック解析対策が必要 |
| **バックアップのHNDL** | **現行age(X25519)はHNDL脆弱**。対策: `age` に `mlkem` plugin経由の受信者を追加、またはバックアップ全体を対称パスフレーズ(オフライン保管)で暗号化。**これは本設計で必須項目** |

## 5. アーキテクチャ統合ポイント（監査済みコードとの対応）

| 既存コード | 変更点 |
|-----------|--------|
| `crypto.service.ts` | デバイス束を拡張: `{ecdsa_sign, rsa_wrap}` → `{ecdsa_sign, rsa_wrap(追加因子), x25519_dh, falcon_sign, qruov_sign, mlkem_ek, hqc_ek, frodo_ek}` + オフラインマスター鍵(SLH-DSA, T3)によるデバイス束証明 + ws_psk(オプション)。JWK以外の鍵はWASM境界で生バイト管理 |
| `serializeMessageAad/Envelope` | `cryptoSuite`フィールド追加。エンベロープ形式 version=4（現行はversion<=3想定） |
| `key.service.ts` (server) | staged distributionエンドポイント追加。epoch状態機械・署名検証は既存のまま流用 |
| `websocket` | `channel:key-rotation-required` 等のイベントは流用。`pq-bundle` ready通知を追加 |
| `attachment-crypto` | AEAD層を差替。manifest構造に `cryptoSuite` |
| `desktop vault`/`android SecretVault` | デバイス秘密鍵束が大きくなる（Falcon sk~1.3KB, QR-UOV sk, 各KEM dk）。AES-GCM→三重AEADで暗号化。`assertSecretName`の namespace 形状は維持 |
| `update-manifest.mjs` (release) | 署名を Falcon+SLH-DSA hybridに更新。検証側も複合化 |

## 6. WASM 実装戦略（最大の技術的課題）

ブラウザWebCryptoにPQCはない（ML-KEMのみ一部実装が進行中）。**WASM境界が必須**:

- **推奨ソース**: PQClean（監査済みクリーン実装群）または liboqs。QR-UOVは提出者実装をvendor固定。AEGIS-256はRFC参照実装。XChaCha20は libsodium系の定数時間実装を移植。
- **供給網**: ソースをrepoにvendorし、コミットハッシュピン。ビルドは reproducible build（Emscripten固定バージョン）。SBOMにWASM成分を追加。
- **メモリ衛生（重要な限界）**: WASM線形メモリは秘密の完全な消去を保証できない（GC/コピー/線形メモリ拡張で残存）。対策: (a) 専用Web Workerで隔離、(b) 秘密バッファの overwrite+即時破棄、(c) ページ離脱時 Worker terminate、(d) 「残存リスク」を脅威モデル文書に明記。
- **KAT必須**: 全プリミティブに公式Known Answer TestをCIで実行（`crypto-conformance` テストパッケージ）。特にQR-UOV/HQC/Frodoは実装差異リスクが高い。
- **定数時間性**: PQCleanの "clean"/"avx2" 実装はSCA対策済み。Falconのfp実装はプラットフォーム間でIEEE754 doubleが決定的であることを確認（WASMでは保証される）。

## 7. 構造強化層

| 強化 | 内容 | 閉じるリスク |
|------|------|-------------|
| **epoch 自動ローテーション** | メンバー変更・一定期間・メッセージ数閾値で `keyVersion` を自動繰上げ。旧epoch鍵は遷移ウィンドウ後に `deletePersistedChannelKeys` で確実に破棄 | デバイス侵害時の前方秘匿（F-E2E-002の緩和） |
| **Tamarin/ProVerif 形式モデル** | KEM結合器・署名AND検証・鍵配送プロトコルを機械検証 | プロトコル論理の微妙な欠陥 |
| **差分ファジング** | 同一プリミティブの2実装（PQClean版とvendor版）で全入力を比較 | QR-UOV/HQC等の実装差異・非決定的バグ |
| **鍵透明性アンカー** | デバイス束ハッシュを監査チェックポイントに含め外部アーカイブ | F-E2E-001（サーバー鍵ディレクトリ改竄の事後検知） |
| **セキュアエレメント委譲** | デバイス秘密鍵束の使用をハードウェア隔離（Android Keystore済み・desktop safeStorage済み・ブラウザは不可=構造限界） | メモリ/プロセス侵害での鍵窃取 |

## 8. ブラウザE2EE信頼層

ブラウザクライアントの本質的弱点「暗号化コード自体がサーバーから毎回配信される」への多層対策。単独では解決不能だが、組合せで「改竄が検知可能」に格上げする。

### 採用する機能（テーマ別）

**コード完全性・配信**

| 技術 | 判定 | 理由 |
|------|------|------|
| **SRI + `require-sri-for 'script'`** | **採用**（外部アンカーと組合せ時） | 単体では悪意あるオリジンに無効（hashも配信できる）。ただし vite のハッシュ付きファイル名と組合せ、(a) dist部分侵害、(b) CDN汚染、(c) index.html固定後の全アセット連鎖固定 に有効 |
| **`Integrity-Policy: blocked-destinations=(script)`** | **採用** | Chrome 139+。全スクリプトにintegrity必須を宣言レベルで強制 — `require-sri-for` の正統後継で属性漏れを構造排除。Report-Only版で段階導入可 |
| **署名ベースSRI（`integrity="ed25519-..."`）** | **採用・最有力** | Chrome 139+。リソースに同梱のEd25519署名を検証し、**公開鍵をindex.htmlに固定するだけで全将来リリースを検証**。ハッシュがリリース毎に変わる問題を解消 — ブートストラップへの最も強い公式解（index.html自体は外部アンカー前提） |
| **ピン留めService Worker** | **採用（外部アンカー前提）** | 永続SWが署名マニフェスト適合アセットのみ配信を強制。SW自体は小さく監査可能に。ただしサーバーはSW更新も可能 → 拡張機能/透明性アンカーと必須組合せ |
| **Isolated Web Apps / Signed Web Bundles** | **長期検討** | Web Bundle署名によるアプリ全体の署名配信。エコシステム未成熟だがこの問題の正攻法将来解 |
| **SXG（Signed HTTP Exchanges）** | **非採用** | Chromeで非推奨化 — IWA/Web Bundleが正統後継 |

**DOM/XSS封殺**

| 技術 | 判定 | 理由 |
|------|------|------|
| **Trusted Types** (`require-trusted-types-for 'script'`) | **採用・効果大** | react-markdownはReactノード生成でraw HTML不使用 → 最小ポリシーでDOM XSSシンクを構造封殺。注入された文字列がinnerHTML/evalに届かない |
| **Sanitizer API (`setHTML`)** | **規約採用** | 現行raw-HTML経路なし。将来HTML挿入が必要になった時の唯一許可経路として規約化 |
| **添付プレビューの `sandbox=""` iframe 隔離** | **採用** | ダウンロード応答のCSP sandboxに加え、ブラウザ内表示もiframeで親コンテキストから分離 |

**プロセス分離**

| 技術 | 判定 | 理由 |
|------|------|------|
| **COOP/COEP/CORP** | **採用** | cross-origin分離でSpectre系から鍵メモリを保護+XS-leak緩和。ヘッダ3個の低コスト |
| `Origin-Agent-Cluster: ?1` | **採用** | 専用プロセス分離。COOP/COEPと重畳 |
| `Document-Policy: js-profiling=()` | **採用** | JS self-profiler 無効化（高精度タイミングSCA対策） |

**セッション・鍵のハードウェア束縛**

| 技術 | 判定 | 理由 |
|------|------|------|
| **WebAuthn パスキー + `prf`拡張** | **採用** | (a) フィッシング耐性ログイン、(b) `prf` で認証器から秘密を導出し vault KEK とする → **物理キーなしに vault を開けない**。webで唯一のハードウェア鍵保管経路 |
| **DBSC（Device Bound Session Credentials）** | **採用** | Chrome 145+（Windows/TPM、macOS今後）。`Secure-Session-Registration` でセッションをTPM/Secure Enclaveの非エクスポート鍵に束縛し、短命cookieを秘密鍵保持証明で更新。**窃取したcookieはデバイス外で無価値**。実装は登録+更新の2エンドポイント追加のみで既存認証フローは不変。非対応ブラウザはgraceful fallback |
| **非抽出CryptoKey + wrapKey/unwrapKey** | **採用** | webクライアントのデバイス秘密鍵は `extractable:false` の CryptoKey をIndexedDBに保持し、wrapKey/unwrapKey経由で扱う — 生の鍵バイトがJSメモリに一度も出ない構造（現行vaultはJWKエクスポート前提のためweb向けに別モード）。改竄JSは「使えても持ち出せない」 |
| **WebAuthn式セレモニー for 危険操作** | **採用** | デバイス登録・epoch変更・ws_psk発行などの高価値操作にパスキー署名を要求 — 「物理プレゼンス」確認層 |

**監視・報告**

| 技術 | 判定 | 理由 |
|------|------|------|
| `Reporting-Endpoints` + **NEL** | **採用** | CSP違反・TLS証明書失敗を same-origin 報告 → MITM/注入試行の検知 |
| **Fetch Metadata検証** | **採用** | `Sec-Fetch-*` でcross-site拒否を多層化（既存origin強制と重複しない） |
| **`Clear-Site-Data` on logout** | **採用** | セッション終了時ストレージ確実消去 |
| **`Cache-Control: no-store`** | **採用** | 機密API応答（暗号文・鍵束・認証応答）のプロキシ/ディスク残留防止 |
| **speculation rules の無効化** | **採用** | `prefetch`/`prerender` による事前fetch漏洩を遮断 |

**制限系（CSP/Permissions-Policy完全化）**

- CSP: `worker-src 'self'`・`script-src-attr 'none'`・`frame-src 'none'`・`child-src 'none'`・`font-src 'self'`・`manifest-src 'self'`・`media-src 'self' blob:`・`form-action 'none'`・`img-src 'self' data: blob:`・`prefetch-src 'self'`・`style-src 'self'`。**openなfetch directiveが1つでも残れば注入JSの持ち出し路になる**（img-src等はconnect-src非適用のため個別に塞ぐ）。
- Permissions-Policy: `browsing-topics/attribution-reporting/shared-storage/join-ad-interest-group/run-ad-auction/usb/bluetooth/serial/hid/midi/idle-detection/window-management/xr-spatial-tracking/payment/clipboard-read/display-capture/local-fonts/file-system-access/speaker-selection/nfc/gamepad/accelerometer/gyroscope/magnetometer/ambient-light-sensor/storage-access/identity-credentials-get/encrypted-media=()` 全て封じる。**注意**: `publickey-credentials-create/get` は WebAuthn のため許可を維持、`microphone` は音声機能のため自己のみ。

### WebRTC抜け道の対策層

**既知の抜け道: CSP `connect-src` は RTCPeerConnection/STUN/TURN を規制しない** — 注入JSはデータチャネルで外部へ持ち出し可能。対策は「閉じる」ではなく「**絞る・無力化・監視化・層ごと削除**」の4段構成。

**L1: チャンネルを絞る（常時適用・XSS注入JSに有効）**
- `iceTransportPolicy:'relay'` で経路を自TURNに限定（ピアIP隠蔽＝F-E2E-003緩和も兼ねる）
- app-loader（他のスクリプトより先に実行）で `RTCPeerConnection` を capability seal: コンストラクタをwrapして `iceServers` を自TURNのみに強制、`iceTransportPolicy` を上書き。**逃げ道の封じ**: `frame-src 'none'`/`child-src 'none'` で iframe の fresh realm 取得を阻止（`iframe.contentWindow.RTCPeerConnection` によるunwrapを遮断）。Worker には RTC API が存在しないため worker-src 側は安全
- 効果の範囲: **XSS/依存混入型の注入には有効**（loader先行実行）。ただし**悪意あるオリジン自身には無効**（サーバーがloader自体を書き換えられる）— Trusted Typesと同じ限界

**L2: 持ち出せる内容を減らす（チャンネルがあっても被害を限定）**
- 非抽出CryptoKey + wrapKey/unwrapKey（生鍵バイトがJSに出ない）＋ PQC鍵の専用Worker隔離（ページJSからはメッセージAPI経由の操作のみ、鍵エクスポート関数を公開しない）→ **注入JSは鍵本体を持ち出せない**。残るのは表示済み平文と「復号オラクル」呼出しのみ
- Worker内の復号呼出しを監査・レート制限（異常な大量decap要求を拒否+記録）→ 「全履歴の一括持ち出し」を困難化
- ws_psk の同様扱い: 結合に必要なためWorker内メモリに存在するが、エクスポートAPIは設けない

**L3: 外部強制（悪意あるオリジンにも有効 — 管理デプロイ向け）**
- **エンタープライズポリシー/拡張**: Chrome管理下では `webRTCNonProxiedUdpEnabled=false`（拡張 `chrome.privacy.network` API）でRTCをプロキシ経由に強制 + 管理拡張が `document_start` で `RTCPeerConnection` の `iceServers` を全呼出しに一律強制（呼出し元を区別しない均一クランプ — 攻撃者自身の `new RTCPeerConnection` も自TURNに縛る）
- **egressファイアウォール（管理ネットワーク）**: 自TURN以外へのUDP/STUNを境界で遮断 — **コードの完全性に依存しない最も確実な閉塞**。注入JSの外部宛RTCはネットワーク層で死ぬ
- 効果: RTC持ち出しが「任意の攻撃者インフラ」から「**自TURN経由のみ**」に縮退 → 以後は監視可能な chokepoint に変わる

**L4: 表面を消す（paranoidティア）**
- 高脅威ワークスペースでは **webクライアントの音声機能を無効化**（音声はバンドルクライアントのみ）→ L1/L3のクランプで `RTCPeerConnection` を完全禁止化でき、RTC抜け道クラスを丸ごと除去

**検知層**: NEL/CSP-reportはRTCを見られないが、L1/L3で全RTCを自TURNに通した後は、**TURNのトラフィックログ（データチャネル量・宛先・頻度）が監視ポイント**になる — 死角を監視済み chokepoint に転換するのがこの設計の実質。

### ブートストラップ設計

```
信頼の起点（外部アンカー、いずれか）
  ├─ ブラウザ拡張機能（Code Verify型: bundle hash を署名マニフェストと照合）
  ├─ ピン留めService Worker（署名マニフェスト適合のみ配信）
  └─ 透明性エンドポイント（別ドメイン/監査チェックポイントのSLH-DSA署名者が bundle hash も署名）
        ↓
index.html（最小限・厳密監査対象 ~数KB）
  └─ app-loader.js (~2KB): 署名マニフェスト検証 → 全アセット（JS/WASM/worker）hash照合 → import
        ↓
アプリケーション本体（全アセットがハッシュ連鎖で固定）
```

### Tinfoil.sh の先行事例（ブラウザ検証の実証済みパターン）

Tinfoil（機密コンピューティングAIチャット）は同一問題を解決済み。2つの問題を分離している点が参考になる:

| Tinfoilの手法 | 詳細 | Alpartsへの適用 |
|--------------|------|----------------|
| サーバーアテステーション | AMD SEV-SNP/TDX エンクレーブ、測定値署名、TLS鍵をアテステーションに束縛、EHBP(HPKE)でエンクレーブ鍵へ直接暗号化 | **不要** — AlpartsはE2EEでサーバーが平文を持たない構造。TEEは「サーバーが平文を処理する」モデル用 |
| **Sigstore透明性ログでweb bundleをピン** | リリースをGitHub Actions→Sigstore append-onlyログへ。ブラウザ内検証器が配信コードとログ上の監査済みリリースを照合 | **採用・自前マニフェストより強い** — 第三者公開監査可能。`sigstore-browser`/`tuf-browser`（合計~50KB・OSS）を再利用可能 |
| untrustedキャッシュプロキシ | 検証データを別経路で配信、全てクライアントが独立検証 | 同パターン適用可 |
| 検証器のWASM→ネイティブ移植 | Go検証器80MB WASM→ブラウザネイティブ50KBに移植 | 同教訓: PQC WASMのサイズも要注意（HQC/Frodoはpk大） |

**結論**: Tinfoilも「web配信コードの完全防止は不可能、Sigstoreによる**公開検知可能化**」に収束 — 本設計の外部アンカー案と同型だが、Sigstore採用で「検知」を公開監査可能に昇格できる。

**残る循環（正直な限界）**: ブラウザ内検証器のJS自体もサーバー配信であるため、「配信コードを検証するコード」にも同じブートストラップ問題が残る。Tinfoilもこの限界は残しており、緩和は (a) 検証器をピン留めSW/ブラウザ拡張/ネイティブクライアント側に置く、(b) 検証器を極小化して外部監査を容易にする、(c) 第三者が任意に検証ツールを実行できる公開性、の3点で「検知の信頼性」を上げる方針のみ。Alpartsも同じ限界を明示する。

### 脅威モデル（信頼層が防ぐ/防げない攻撃者）

**守る対象**: デバイス秘密鍵束（PQC+従来）・vault KEK・ws_psk・平文メッセージ（表示済み+復号オラクル経由の履歴）・セッションcookie・メタデータ（ピアIP・タイミング）

**想定攻撃者の能力**: 対象オリジンで任意JSを実行できる（XSS/依存混入、またはサーバー侵害・強制による悪意あるオリジン）。暗号プリミティブは破れない。**ブラウザ/OS/ハードウェアの侵害は範囲外**（OSマルウェア・スクリーンキャプチャ・ブラウザプロセスのメモリ読取りは別ドメイン — DBSCはこの一部であるcookie窃取のみに効く）。

| 攻撃者クラス | 能力 | 防げる層 | 残存露出 |
|------------|------|---------|---------|
| **A1: XSS注入JS**（依存混入・レンダリング欠陥。オリジン自体は正直） | loaderより後に実行されるJS | **L1有効**（loader先行でRTCを自TURNにクランプ・iframe逃げ道はframe-srcで封鎖）。L2で鍵持ち出し不可・TT/DOMシンク封殺で注入自体を縮小 | 表示済み平文の持ち出しは残る（自TURN経由のみ→ログ可視） |
| **A2: 悪意あるオリジン**（サーバー侵害/強制・標的型に改竄JSを配信） | loader自体を改竄可能 | **L1無効**（loaderが改竄される）。**L2は部分的に有効**（非抽出鍵は改竄JSでもraw bytesを持ち出せないが、sign/decryptオラクル呼出しは可能）。**L3が実質的な唯一の防止**（拡張/egress FWはコード完全性に非依存）。L4は表面削除 | 平文の持ち出し・署名偽造（オラクル経由）は防げない — 検知（Sigstore透明性・TURNログ）と被害限定に依存 |
| **A3: ネットワーク傍受/観察者**（ISP・CA強制MITM） | トラフィック観察・TLS終端試行 | TLS+ピンニング・PNA・CT監視（別層）。RTCはTURN-onlyで経路限定 | メタデータ（通信相手・量・タイミング）は残る — F-E2E-003 |
| **A4: 悪意あるワークスペースメンバー** | 正当な復号権限を持つ内部者 | 範囲外 — 権限モデルの問題。監査ログ・署名で事後追跡 | 正当な閲覧内容の持ち出しは技術的に防げない |
| **A5: エンドポイントマルウェア**（OS級・cookie窃取・メモリ読取り） | ブラウザと同権限 | **DBSCのみ有効**（cookie窃取を無価値化）。E2EE鍵はWASMメモリに残るため限定的 | 鍵・平文の直接窃取は endpoint security の領域 |

**モデルの核心**: A1（注入）はL1+L2で実効的に閉じられる。A2（悪意あるオリジン）は**ブラウザ内では原理的に防止不能**で、唯一の防止はL3（外部強制）またはL4（機能削除）——それがない限り「検知可能化+被害限定（L2）+非抽出鍵で長期鍵は守る」が上限。この構造は「悪意あるJS実行=ゲームオーバーだが、鍵とチャンネルは別々に防御できる」という層分離に基づく。

### PQC統合で直接必要な実装注意

- **`script-src 'self' 'wasm-unsafe-eval'`**: WASM `instantiate` に必須。JS eval は封じたまま WASM のみ許可する専用値 — **PQC WASM 導入時の必須変更**
- **`self.crossOriginIsolated` 起動時アサート**: COOP/COEP のサイレント降格を fail-closed 検出
- **CAA DNS レコード**（ブラウザ外・運用）: 証明書発行CAを限定し F-NET-001 を縮小
- **Android Play Integrity API**: バンドルアプリの改竄/非公式配布をサーバー側アテステーション — 「バンドルのみ許可」ポリシーを実効化

### 残存限界

- 完全防止は不可能。実現できるのは「標的型改竄の検知可能性とコスト上昇」。高脅威ユーザーはバンドルクライアントを使う運用線引きは残る。
- ブラウザAPI層で導入可能な防御は網羅済み。残る改善余地はAPIではなくアーキテクチャ層（ブラウザ拡張・ネイティブクライアント・エンクレーブ）のみ — これはwebプラットフォームの構造的上限であり、Tinfoilの分析と一致する結論。

## 9. Signal PQ3 / iMessage からの借用

| 技術 | 借用する点 | Alpartsへの適用 |
|------|-----------|----------------|
| **PQXDH/ハイブリッド握手** | classical+PQを同時必須 | 本設計の複合KEMが同等 |
| **PQ3 staggered rekey** | メッセージ毎に新しいPQ公開鍵を含め定期的に再送 | グループチャンネルではfanout過大 → **DM専用のオプション層**として検討（Phase C） |
| **SPQR/erasure-coded keys** | 順不同・欠損に耐える鍵配布 | staged distribution設計に同じ思想を適用済み |
| **epoch-gated algorithm policy** | Signalの "version floor" | `cryptoSuite` + epoch で同等を実現 |

**ラチェットについて（正直な評価）**: 現行Alpartsはチャンネル共有鍵方式（WhatsApp sender-keys型）で、メッセージ毎のDouble Ratchetは存在しない。PQ3級のpost-compromise securityを導入するには送信者鍵チェーンの追加が必要で、これは設計の別段階（Phase C）。本設計の複合KEM+epoch rotationはHNDLを閉じるが、侵害後の前方秘匿性は別途検討事項。

## 10. 段階的導入計画

| Phase | 内容 | 閉じるリスク |
|-------|------|-------------|
| **A: crypto-agility基盤** | `cryptoSuite`フィールド・エンベロープversion=4・WASM境界・KAT CI・staged key distribution | 将来の移行を可能にする前提工事 |
| **B: ハイブリッド稼働** | 複合KEM + T1/T2署名 + 三重AEAD を epoch>=N で必須化。旧形式は読み取りのみ許容 | F-PQC-001(HNDL)を内容面で閉じる |
| **C: 根幹強化** | SLH-DSAオフライン監査署名(F-TRUST-001解決)・リリース署名hybrid化・バックアップage-pq化・DMラチェット検討 | 信頼アンカーの外部化・残存HNDL面 |
| **D: 検証** | 外部暗号実装監査・相互運用テスト・性能ベンチ（Frodo WASM速度・SLH-DSA署名時間） | 実装品質の第三者保証 |

## 11. 未決定事項（要チーム判断）

1. **QR-UOVの実装ソース**: NIST提出実装のみか、外部監査済みが出るまで待つか。帯域コスト（sig ~数KB〜10KB・pk ~40KB級、要実測確認）も含め、T1採用かT2+限定かの判断材料。リスク限定ならT2+のみ使用を推奨。
2. **AEAD最内層のAES-GCM存続**: 現行は三重構成（AES-GCM ⊂ XChaCha ⊂ AEGIS）だが、FIPS環境不要ならAES層を外して二重にする選択肢。層を外す場合はスイートIDで構成を固定すること（混在防止）。
3. **DMラチェット（Phase C）**: やるかやらないか。やるなら Signal Double Ratchet+ML-KEM定期rekey（PQ3型）が最も参照実装が豊富。
4. **鍵透明性ログ**: F-E2E-001を閉じるための外部検証機構を入れるか。Sigstore流用（web bundle検証と共通基盤）も選択肢。
5. **SLH-DSAオフライン署名の運用**: HSM/エアギャップ/閾値署名のどれにするか。
6. **ブラウザ検証器の配信経路**: ブートストラップ循環（検証器自体もサーバー配信）への対処 — 検証器をピン留めSWに置くか拡張機能として配るか。拡張機能は配布・アップデート管理の運用コストがかかる。
7. **マスター鍵の導出・保護方式**: パスワード+ユーザー名導出 / パスキー(WebAuthn prf) / TOTP / Signal型PIN+エスクロー のいずれか（§2「マスター鍵の導出・保護方式」参照）。**開発チームの判断に委任。実装がAIエージェントの場合は必ずユーザーに確認すること**（§2の指示ブロック参照）。
