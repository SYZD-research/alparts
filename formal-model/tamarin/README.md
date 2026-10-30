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
| パスキーの PRF で包んだ復旧コード | client `passkey-vault.ts` |

省いたもの：ディレクトリのハッシュ連鎖と head（順序と巻き戻しの検出。M10 とクライアントのテストが扱う）、失効と `expire`（承認を取り消すだけ）。正直なクライアントは、どれかが受け入れうるエントリをすべて合わせた1つの見え方を共有するとしています。サーバーが見せる分岐した見え方はその一部なので、ここで証明した性質はどの見え方でも成り立ちます。確認コードの 96 bit への切り詰めは、完全なハッシュとして扱います。

## 補題と変種

| 検査 | 期待 | 内容 |
| --- | --- | --- |
| DA | HOLDS | 利用者の端末が承認済みとして受け入れる識別鍵は、端末の鍵・復旧コード・パスキーのどれかが漏れない限り、その利用者自身の端末のもの |
| DA-compared | HOLDS | 確認コードを比べたうえでの承認は、サーバーがどの端末を示しても、利用者が見たコードの端末を指す |
| HS | HOLDS | すべてのアーカイブと、送られてきた取り出しトークンを持つサーバーでも、コードかパスキーなしには履歴の鍵を読めない |
| DA-passkey | LIMIT | 復旧の計画を包んだパスキーを使える者（認証器、または同期先のアカウント）は、コードなしで新しい端末を承認できる |
| DA-tricked | LIMIT | コードを比べずに承認すると、サーバーの端末を承認する（M4 D4、`-D=TRICKED`） |
| DA-tofu | LIMIT | 初めてそのアカウントを見る端末は、サーバーが見せる最初の端末を受け入れる（`-D=TOFU`） |
| DA-identity-ctl | CONTROL | 決定が端末 ID だけを指すと、別の見え方で同じ ID に攻撃者の鍵を登録して承認を使い回せる（`-D=CTL_NO_IDENTITY`） |
| DA-proof-ctl | CONTROL | セッションの証明がチャレンジだけに署名すると、承認済みの端末にログインのチャレンジとして承認を署名させられる（`-D=CTL_UNTAGGED_PROOF`） |
| HS-token-ctl | CONTROL | 取り出しトークンがコードそのものだと、最初の復元でサーバーがコードを知る（`-D=CTL_RAW_TOKEN`） |

`exec_approval`・`exec_restore_code`・`exec_restore_passkey` は、正直な手順が漏えいなしに実行できることの確認です。成り立たなければモデルが強すぎるため MODEL-GAP になります。

## 実行

```bash
python3 formal-model/run.py M4T
tamarin-prover --prove -D=TRICKED formal-model/tamarin/device_approval.spthy   # 1つの変種を直接
```

Tamarin 1.10 以降と Maude（3.2 以降）が PATH に必要です。Tamarin はリリースのバイナリ、Homebrew（`brew install tamarin-prover/tap/tamarin-prover`）、Nix（`nix-env -iA nixpkgs.tamarin-prover`）のいずれかで入れます。環境変数 `TAMARIN` で実行ファイルを指定できます。ツールがない、整形式の警告が出る、解析が終わらない場合は MODEL-GAP です。
