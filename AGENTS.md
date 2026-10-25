# UI 文言ポリシー

- ユーザーが結果を理解したり操作を選んだりするために不要な、実装上の技術情報を UI に表示しない。
- 技術情報を省略したことや、画面を簡略化したことを説明する文言も UI に追加しない。必要なユーザー向け情報だけを直接表示する。
- エラーや状態は、何が起きたかと、必要であれば次に何をすればよいかを、短く平易な言葉で伝える。
- プロトコル名、暗号方式、内部 ID、保存形式、同期処理、開発者向け用語を通常の UI 文言に含めない。
- セキュリティやデータ消失に関わる警告は残す。ただし実装の説明ではなく、ユーザーが判断すべき危険と操作を平易に示す。
- 開発者だけが必要とする診断情報は、UI ではなくログ、テスト、ドキュメントに置く。

# dirdoc

This repository describes its directories and files with dirdoc. If `dirdoc` is not on PATH, it is usually at `~/go/bin/dirdoc`. The descriptions live in the `.dirdoc/` directory of each documented directory.

## Reading

- `dirdoc <dir>` shows a directory's summary, tree and the table of contents of each file; `dirdoc <file>` shows a file in detail; `dirdoc '<file>#<id>'` shows one type or function. Add `--brief` for less, `--full` for every document, `-f json` for JSON.
- `[[…]]` is a reference. Pass what is inside to `dirdoc '…'` to open it.  Paths in a reference are relative to the documented directory; start them with `/` to resolve from the project root, e.g. `[[/packages/server/src/app.ts#createApp]]`.
- Search with `dirdoc search <words>`. The files in `.dirdoc/` are compressed, so grep cannot search them.
- Never read or write the files in `.dirdoc/` directly.

## Writing

When you change code, update its description too. Write descriptions in Japanese, keeping identifiers and file names as they are.

- To change part of a document, write only the changes and apply them with `--merge`. Entries are matched by id (or by the id derived from the name); `delete = true` removes one.

  ```bash
  dirdoc compile src/main.rs --merge - <<'EOF'
  [[functions]]
  name = "check_stdout()"
  summary = "Tell whether stdout is a terminal"
  EOF
  ```

- To rewrite a document: `dirdoc export <target> > /tmp/x.toml`, edit it, then `dirdoc compile <target> /tmp/x.toml`. When there is no description yet, export prints a template.
- Finish with `dirdoc check`.

## The source format (TOML)

A file (PFD):

```toml
summary = "What this file is for"

[[types]]                      # classes, structs, ...
name = "Config"
summary = "One-line description"

[[functions]]
name = "check_stdout()"        # the id is the part before "(", "<" or "[" (or set id = "...")
summary = "One-line description"
document = '''
Markdown body. Reference others with [[#MAX_AGENTS]], [[other.rs#parse]] or [[dir/]].
'''

[[variables]]
name = "MAX_AGENTS"
summary = "What it is for"
```

A directory (DSD) has `summary`, `tree` (in the style of the `tree` command; `[[#id]]` links a line to an entry and text after ` # ` is a note) and `[[dsd]]` entries (`id`, `name`, `document`).
