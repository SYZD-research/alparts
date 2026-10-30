# quint — 状態探索モデルの Quint 版（TLC で検査）

自作の Python 探索器で調べていたモデルを Quint で書き直し、Apalache に含まれる TLC で全探索します。Python 版と同じ状態・遷移を写しているので、両者の到達状態数・破れる性質・最短反例の長さが一致するはずです。各モデルの `agree` 検査がこれを確かめ、一致しなければ MODEL-GAP にします（どちらかの実装の誤りで、設計についての結果ではないため）。そのうえで、Python 版では重すぎた規模（再送や端末の数、版数）を追加の HOLDS 検査として調べます。

| モデル | Quint | Python 版 | 内容 |
| --- | --- | --- | --- |
| M3rQ | `m3r_own_commit.qnt` | `m3r_own_commit.py` | 応答が失われた自分の commit。5変種で状態数（311 / 683 / 731 / 2,012 / 326）・違反・最短反例が一致。再送5回・タブの途中終了3回まで広げた変種（29,278 / 148,392 状態）でも K1・K2 が成り立つ |

## 書き方

- 状態は1つのレコード変数 `s` にまとめ、Python の `NamedTuple` とフィールドを1対1に対応させます。`None` は空文字列で表します。
- リストの順序も Python と同じにします（`requests` から1件を取り除き、段階を進めたものを末尾に足す、など）。順序を変えると状態数が一致しなくなります。
- 変種は定数を与えたインスタンスのモジュール（`module implementation { import m3r(...).* }`）にします。`tlc.check(spec, main, [性質])` がモジュール名で選びます。
- 性質は `val` で書き、`tlc.check` が TLC の INVARIANT に渡します。破れたときは TLC の反例（アクション名と変わったフィールド）を表示します。

## 実行

```bash
formal-model/quint/setup-tools.sh            # quint を formal-model/.tools に、Apalache を ~/.quint に入れる
python3 formal-model/run.py M3rQ
quint run --main implementation --invariant K1 formal-model/quint/m3r_own_commit.qnt   # 乱択シミュレーション
```

`quint run` は既定で Rust 版の評価器を GitHub から取得します。取得できない環境では `--backend typescript` を付けます。

Java 17 以降が必要です。`QUINT`・`APALACHE_JAR` でツールの場所を、`TLC_WORKERS`（既定 1。1 なら反例が最短）・`TLC_HEAP`（既定 4G）で TLC の設定を変えられます。GitHub のリリースに届かない環境では、`ghcr.io/apalache-mc/apalache:v0.62.4` イメージの `/opt/apalache` を `~/.quint/apalache-dist-0.62.4/apalache` に置いても動きます。ツールがない、出力に判定がない、要求していない性質が破れたと報告された場合は MODEL-GAP です。
