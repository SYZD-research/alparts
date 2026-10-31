# tamarin — 端末承認・復旧コード・パスキーの記号モデル（M4T）

M4・M4s は「署名・確認コードの照合・復旧データの暗号化は安全」と仮定して、サーバーの判定とセッションの状態を調べています。`device_approval.spthy` はその仮定の部分を、ネットワークとサーバーそのものを攻撃者とする Dolev-Yao モデルで検査します。MLS そのものは対象外で、Alparts 独自の手順だけを扱います。

## 写した実装

| 手順 | 実装 |
| --- | --- |
| 端末の識別鍵と確認コード（識別鍵の SHA-256 の先頭 96 bit） | client `crypto.service.ts`、`DeviceApprovalPage.tsx`、`AccountSecurityDialog.tsx` |
| セッションの証明（サーバーが選ぶチャレンジへの署名） | shared `serializeDeviceChallengeProof` |
| 承認・復旧設定・復旧の決定への署名 | shared `serializeDeviceDecision`、client `directory.service.ts` `deviceDecision` |
| ディレクトリの検証（register / approve / recovery-config / recovery） | client `directory-verifier.ts` `verifyDirectoryEntries` |
| 復旧コード（復旧署名鍵の暗号化、取り出しトークン、履歴アーカイブ鍵） | client `recovery.service.ts`、`recovery-crypto.ts` |
| パスキーの PRF で包んだ履歴の保存用の鍵（2026-10-30 まで包んでいたのは復旧コード） | client `passkey-vault.ts` |

正直な端末は、自分が承認済みかどうかにかかわらず承認や復旧の設定を署名でき、復元する端末はディレクトリの復旧鍵を引きません。どちらも正直な側にできることを増やすだけなので HOLDS の証明は弱くならず、Tamarin が承認の連鎖を際限なくさかのぼるのを防ぎます（復元側が開ける暗号文は、その復旧鍵を付加データで結び付けている）。

省いたもの：ディレクトリのハッシュ連鎖と head（順序と巻き戻しの検出。M10 とクライアントのテストが扱う）、失効と `expire`（承認を取り消すだけ）。正直なクライアントは、どれかが受け入れうるエントリをすべて合わせた1つの見え方を共有するとしています。サーバーが見せる分岐した見え方はその一部なので、ここで証明した性質はどの見え方でも成り立ちます。確認コードの 96 bit への切り詰めは、完全なハッシュとして扱います。

## 補題と変種

| 検査 | 期待 | 内容 |
| --- | --- | --- |
| DA | HOLDS | 利用者の端末が承認済みとして受け入れる識別鍵は、端末の鍵か復旧コードが漏れない限り、その利用者自身の端末のもの。パスキーが漏れても成り立つ |
| DA-compared | HOLDS | 確認コードを比べたうえでの承認は、サーバーがどの端末を示しても、利用者が見たコードの端末を指す |
| HS | HOLDS | すべてのアーカイブと、送られてきた取り出しトークンを持つサーバーでも、コードかパスキーなしには履歴の鍵を読めない |
| HS-passkey | LIMIT | 履歴の鍵を包んだパスキーを使える者（認証器、または同期先のアカウント）は、保存された記録を手に入れれば履歴を読める（サーバーは記録を承認済みの端末にだけ渡す） |
| DA-tricked | LIMIT | コードを比べずに承認すると、サーバーの端末を承認する（M4 D4、`-D=TRICKED`） |
| DA-tofu | LIMIT | 初めてそのアカウントを見る端末は、サーバーが見せる最初の端末を受け入れる（`-D=TOFU`） |
| DA-identity-ctl | CONTROL | 決定が端末 ID だけを指すと、別の見え方で同じ ID に攻撃者の鍵を登録して承認を使い回せる（`-D=CTL_NO_IDENTITY`） |
| DA-proof-ctl | CONTROL | セッションの証明がチャレンジだけに署名すると、承認済みの端末にログインのチャレンジとして承認を署名させられる（`-D=CTL_UNTAGGED_PROOF`） |
| HS-token-ctl | CONTROL | 取り出しトークンがコードそのものだと、最初の復元でサーバーがコードを知る（`-D=CTL_RAW_TOKEN`） |
| DA-passkey-ctl | CONTROL | 2026-10-30 より前の設計（パスキーで復旧コードそのものを包む）では、パスキーだけで新しい端末を承認できる（`-D=CTL_PASSKEY_WRAPS_CODE`） |

`exec_approval`・`exec_restore_code`・`exec_restore_passkey` は、正直な手順が漏えいなしに実行できることの確認です。成り立たなければモデルが強すぎるため MODEL-GAP になります。

DA は3つの版から `-D` で1つを選びます。`REUSE_DA` は他の補題が DA を前提にしてよい版で、DA も同時に証明する既定の実行だけで使います（Tamarin は reuse の補題を、その実行で証明していなくても前提にするため）。`PLAIN_DA` は前提にしない版で、DA が偽になる変種で使います。`CTL_PASSKEY_WRAPS_CODE` では、旧設計でも成り立つパスキーを例外に含めた DA を前提にして、攻撃の探索を絞ります。直接実行するときは `-D=REUSE_DA` などを付けます。

## 実行

```bash
python3 formal-model/run.py M4T
tamarin-prover --prove=DA -D=TRICKED -D=PLAIN_DA formal-model/tamarin/device_approval.spthy   # 1つの変種を直接
```

Tamarin 1.10 以降と Maude（3.2 以降）が PATH に必要です。全変種で約4分かかります。Tamarin はリリースのバイナリ、Homebrew（`brew install tamarin-prover/tap/tamarin-prover`）、Nix（`nix-env -iA nixpkgs.tamarin-prover`）のいずれかで入れます。環境変数 `TAMARIN` で実行ファイルを指定できます。ツールがない、整形式の警告が出る、解析が終わらない場合は MODEL-GAP です。

リリースのバイナリが使えない環境では、ソース（タグ 1.12.0）から cabal でビルドできます。リポジトリ直下に `lib/` の各パッケージを並べた `cabal.project` を置き、`LANG=C.UTF-8` で `cabal build exe:tamarin-prover` を実行します。GHC 9.4 では `--allow-newer=base,template-haskell,...` と `constraints: crypton <1.0` が必要でした。
