# Security audit status

最終文書更新: 2026-08-27

この文書は、2026-08-16の過去audit記録、2026-08-26のscoped scan、2026-08-27のrepository-wide standard scan、および完了前に停止したDeep Security Scanから回収したfindingの修正を分離する。いずれも独立外部reviewまたは正式仕様全体へのsecurity approvalではない。

## Audit timeline

| Checkpoint | Scope | 状態 | 現在の扱い |
| --- | --- | --- | --- |
| 2026-08-16 repository audit | 当時のspecification、limitations、server/client/shared、deployment、lockfile、HTTP/WebSocket、crypto envelope、migration | 完了（historical） | 下記findingは当時のtreeで修正・検証された記録。後続変更へ自動継承しない |
| 2026-08-26 / 27 backup/restore実動検証 | 一意な使い捨てPostgreSQL 16/MinIO、age artifact、非特権restore owner、空bucket | 完了（scoped verification） | 最新runは `20260827T051348Z-e8e85d921692`。Backup mechanicsだけのevidenceで、repository security scanではない |
| 2026-08-26 scoped standard security scan | Server設定、deployment、Docker build contextを中心とする単一pass | 完了（scoped） | scan `89d4eb37-0b86-4bf8-b449-7b04551bd14d`。下記2件を修正済み。Repository全体の最終scanではない |
| 2026-08-27 current-tree standard security scan | 最終統合後のrepository全体、single pass | **完了・全finding修正済み** | scan `1e2517d2-1dad-4360-9e0d-855dfd224047`。Medium 4 / Low 3、Critical/Highなし。下記で修正・再検証を記録 |
| 2026-08-27 partial Deep Security Scan | repository全体 | **orchestration失敗・finding保存済み** | Child scan `c677fed2-242f-40e5-92c9-26e44f2de49d`。34 findingを23根本原因へ整理して修正したが、parent discovery manifest/集約は完了しておらず、completed Deep Scanとは扱わない |

## 2026-08-16 historical audit

### 当時remediate済みと記録されたfinding

| Severity | Finding | 2026-08-16時点の記録 |
| --- | --- | --- |
| Critical | Workspace/channel/message/file BOLA・IDOR | Fail-closed workspace/channel/message middlewareとservice-level checkへ修正 |
| Critical | Unauthorized WebSocket room join / event injection | DB-backed session、room/event authorization、validation、throttlingへ修正 |
| Critical | Channel key不在時のplaintext fallback | Fallbackを削除し、per-device wrapped channel-key distributionへ修正 |
| High | Client-controlled event/device/cross-channel reference | Strict schema、session-bound device、contextual signature、same-channel checkへ修正 |
| High | Logout後も有効なJWT、DB/localStorageのplaintext token | Hashed DB session、HttpOnly cookie、live verification、socket disconnectへ修正 |
| High | Public registration、invite無視、weak default secret、auth throttling欠如 | Invite/bootstrap policy、strong-secret validation、rate limitへ修正 |
| High | Attachment upload/download authorization、object key/size/content handling | Uploader-bound reservation、size policy、object verification、forced download、expiry cleanupへ修正 |
| Critical/High | 17 known dependency vulnerabilities | 当時のlockfileでproduction/development `pnpm audit` が0と記録 |
| High | Extractable device private keyをplaintext JWK保存 | Non-extractable WebCrypto keyのIndexedDB保存とlegacy record削除へ修正 |
| Medium | Unbounded HTTP/pagination/crypto/file/WebSocket input | Byte/count/time/rate boundを追加 |
| Medium | External Markdown image tracking / global presence disclosure | Automatic image fetchを停止し、presenceをshared workspaceへscope |
| Medium | Racy/unverifiable audit chain / default infrastructure credential | Canonical HMAC chain、DB lock、startup verification、required secret、loopback binding、pinned imageへ修正 |

### 当時のverification記録

- `pnpm typecheck`
- `pnpm build`
- `pnpm test`
- `pnpm audit --audit-level low`
- 隔離PostgreSQL/MinIO integration: authorization、private WebSocket room、signed ciphertext、cross-user delete/attachment rejection、cookie、logout/revoke、WebSocket disconnect、audit-chain verification
- `git diff --check`

これらは2026-08-16時点の記録である。Lockfile、migration、authorization、attachment、client stateなどが更新された現treeについて、dependency 0件または全試験成功をこの記録から推論しない。

## 2026-08-16以降のsecurity-relevant変更

以下はcurrent code/documentのtruth auditで確認した実装事項であり、最終security scanのfinding/resultではない。

- Security-sensitive state mutationとaudit appendの同一transaction化、PostgreSQL advisory lockによるchain直列化、audit閲覧自体の監査。
- HMAC付きaudit checkpointとstartup/readiness検証。PostgreSQL operatorからwrite/delete authorityを分離したmountに置いた場合だけoperator-independentである。
- One-time invitationの管理UI、role preview/effective reason、session/device失効UI、DM/group DM。
- Deterministic event projector、encrypted IndexedDB draft/outbox、fixed idempotency keyによるreconnect送信、loaded plaintextだけのlocal search。
- Category/channel permission overrideの両revision付きpreview/commit、room/rekey効果、client管理UIと失権cleanup。
- Client attachmentのfile key、filename暗号化、固定chunk AEAD、resume/retry/download decrypt、期限切れ時のattempt rotation。
- Quiesced PostgreSQL custom dump + MinIO objectを一つのmanifestへ収集するage backupと、空の隔離targetだけを対象にするrestore verification。
- Signed message/attachment author binding、principal/generation固定outbox、user共有WebSocket budget、authorization lock中の全room grant、DB transaction外のbounded object I/O。

Backupは2026-08-27のrun `20260827T051348Z-e8e85d921692` で、25 table、2 object、134 bytesのmanifest/checksum/count/reference/redownload SHA一致を確認した。これはPITR、WORM、off-site、artifact provenance、client decryptability、full DRを検証していない。

## 2026-08-26 scoped standard scan

Scan ID: `89d4eb37-0b86-4bf8-b449-7b04551bd14d`

| Finding ID | Severity | 内容 | 修正 |
| --- | --- | --- | --- |
| `csf_1cebb5f0879b9f5fdfa7df10` | Medium | systemd配置でlistener hostが明示されず、意図しないinterfaceへbindし得た | `BIND_HOST`を既定loopback・IP literal限定とし、systemdは`127.0.0.1`、Dockerだけ`0.0.0.0`を明示 |
| `csf_ab4b70c4f0556aa0d80ca301` | Low | Docker build contextが`.env.*`を十分に除外していなかった | `.dockerignore`で`.env*`、`**/.env*`、`.commandcode`等を除外し、`.gitignore`もsecret artifactを明示除外 |

このscanはscopedな通常の単一pass監査であり、最終repository-wide scanまたは独立外部reviewの代替ではない。

## Final repository-wide standard scan — 完了

- Scan ID: `1e2517d2-1dad-4360-9e0d-855dfd224047`
- Workflow: repository-wide Standard / single pass
- Base revision: `f1a726b0133b8de75bb2326c16e7bf89944d0579`
- Snapshot digest: `codex-security-snapshot/v1:sha256:9d97dddcbffcaefd5184c3ad066309d3f52319ad6906709f487182bab0ca0e53`
- Coverage: complete
- Reported severity: Medium 4、Low 3、Critical/High 0
- このStandard scanとは別に、後述する未完了Deep Security Scan由来の修正を実施した

| Finding ID | Severity | 内容 | 修正・検証 |
| --- | --- | --- | --- |
| `csf_fd112f42631f6b38a5cf7823` | Medium | Signed envelopeが表示authorを暗号学的にbindingしていない | Protocol v2のmessage/attachment署名・AADへ`authorId`を追加し、server/client双方でauthenticated user/device bindingを検証。Tamper vectorとintegration成功 |
| `csf_eb711e2d8e5dda501d55d5e4` | Medium | Outboxの非同期lifecycleがaccount/device切替を跨ぎ得る | Immutable principal/device/generation、per-scope persistence queue、reset guardを導入。暗号化前後・read直後・put直前までcurrent lifecycleを検査し、client race試験成功 |
| `csf_19f5f3ec79685f2502a17aef` | Medium | 並列socketでper-socket rate budgetを乗算できる | User+bucket共有rate state、20,000 entry上限、16 socket/user・2,048 total cap、idempotent releaseを実装し、multi-socket試験成功 |
| `csf_c67cafbbdf447cf2e74bcfd7` | Medium | 遅いobject storage I/OがDB transaction/connectionを占有し得る | Remote I/OをDB transaction外へ分離し、短い再認可/quota transaction、8 active/32 pending gate、transport timeout、per-upload serializationを導入。Expired queued workが後で実行されない試験を含め成功 |
| `csf_44e98e880135b37c60c3e6e1` | Low | 認可確認後に遅延したroom joinが失効後に適用され得る | Client joinと全server-driven `socketsJoin` を共通helperへ集約し、workspace SHARE lock中の再認可・joinを強制。独立patch reviewが初期修正の迂回経路を検出し、追加修正後のstale/legitimate grant試験成功 |
| `csf_9054b3e80121401bbb9733c7` | Low | Backup credentialがchild argvに現れる | PostgreSQLはmode `0600` libpq service file、MinIOはstdin alias importへ変更し、loaded secretのchild environment継承も停止。Capture試験と実`pg_dump`/`pg_restore` roundtrip成功 |
| `csf_9c1658a335c940f917de3378` | Low | Restore前のsparse/expanded archive resource制限不足 | Extract前にencrypted/decrypted bytes、entry数、per-file/aggregate logical bytes、type/path、compact sparse metadataを検査。悪性controlと通常PAX roundtrip試験成功 |

Remediation後にfresh migration、skipなしPostgreSQL/MinIO integration、server 35件、client 67件、typecheck、build、production dependency audit（known vulnerability 0）、license inventory、shell syntax、backup security、OCI runtime/readiness/non-root、隔離backup/restore、`git diff --check`を実行した。Internal independent patch reviewerは初期room-join修正のserver-driven迂回を報告し、全raw joinを共通moduleへ集約した後に再検証した。

TAC advisory取得は認証されていない実行環境のため利用できなかった。Scan自体のsealed local artifactsとcoverageは完了しているが、この制約と未実施の独立外部reviewはrelease conclusionに残す。今後の変更へ本結果を自動継承しない。

## 未完了Deep Security Scanから回収したfinding — remediation

- Child scan ID: `c677fed2-242f-40e5-92c9-26e44f2de49d`
- Saved result: High 1 / Medium 23 / Low 10、計34 finding
- Scan状態: `failed`。Discovery orchestrationのparent manifestとDeep集約は完了していない
- Remediation単位: 重複・同一境界を統合した23の根本原因

下表の「修正」は保存済みfindingへのremediation記録であり、Deep Scanのcompletionや未発見脆弱性がないことを示さない。

| 根本原因 | Finding ID | 修正した共有境界 |
| --- | --- | --- |
| Former memberによるrekey outage | `csf_f38f57b32878db98f99ab8d5` | Device revokeを一度限りにし、現在membershipとlatest epochのeligible deviceだけをrotation対象にした。Membership removal後に回復済みchannelを再凍結できない回帰を追加 |
| Split epoch / poisoned wrap | `csf_72141c4d20a7ca8f9d34977b`, `csf_46d64b42898c55158c107972`, `csf_647684ebd2c9d56363f72e3f` | Frozen recipient snapshotを持つ`pending` epochを提案し、全required recipientがserver発行のexact delivery ID・distributor・commitmentへ署名ackした場合だけatomicに`active`へ昇格する二段階protocolへ変更。Per-distributor delivery candidateはimmutable、pendingはwrite不可、競合候補は選択ack時に除去する。ManagerまたはDM participantによる署名abortと単調version retryも追加 |
| Stolen sessionによるdecrypt device追加 | `csf_da198afb2a64ed1284fbd5a8` | Session-bound one-time challengeとdevice署名proofを必須化し、新identity登録にcurrent-password step-upを追加。既存identity bindingにもproofを要求 |
| Generic channel API経由のDM改変 | `csf_46cca0c394251583d9cafee3` | Create/update/delete/member/category/permission-overrideのgeneric service境界でDMを拒否し、DM participant modelを専用APIだけに限定 |
| Workspaceごとにresetするuser attachment quota | `csf_977c9d43ac8155beb0d30429` | Finalized/pending byte集計をaccount-wideへ変更し、global user advisory lock下で複数workspaceを合算 |
| Member管理のcapability/hierarchy/consent bypass | `csf_eb7e8394183096a3ce3503ca`, `csf_6caae826cfbbd306eb80f5f4`, `csf_04486e0aa1885d9d1304884c`, `csf_40850c1c2eeeb3b4a7203bf6` | Removeをworkspace lock内の`KICK_MEMBERS`・strict role hierarchyへ変更。Unused direct-add routeを削除し、参加は権限委譲を検査する招待acceptへ統一 |
| Reaction eventの永続増幅 | `csf_295f58a31177186b1ce67eaa` | `(message,user,emoji)` current-state tableへcompactし、1 user/messageあたり20 emoji上限とmessage lockを追加 |
| Device fan-out exhaustion | `csf_f10a251a200481033ba6b210`, `csf_d1b3a4c07e828c9d75d27b97` | 1 user 8 active device、1 workspace 50 member、atomic recipient 400の整合したadmission上限を全関連経路へ追加 |
| Parser前のbody resource exhaustion | `csf_6d920fbfef4dfde82c1ead7e` | JSON/chunk parser前にContent-Length/Transfer-Encoding、source/global request、aggregate byte leaseを検査し、予約・UUID確認前のbufferingを制限 |
| Download streamがgateを早期解放 | `csf_820b0ea72c655cf81ecbc658`, `csf_5863ef3465997eb7e7f5f9f5`, `csf_d8e951c7e564f0e4da998a7b` | Object-storageとHTTP download leaseをend/close/error/abortまで保持し、global 8 / user 2上限、inactivity・absolute deadlineを追加 |
| Source変更によるpassword throttle bypass | `csf_8120f3af9a5b343045a73fa8`, `csf_8a16d68cf43ebaa89fb99e9a` | Normalized account、source、account+sourceの独立budgetをloginへ適用 |
| Tenant APIによるglobal audit scan/leak | `csf_d6f15bbb9841d96bbbea2f0e` | Tenant routeからglobal rescanを除去し、起動時検証済みのcoarse `{valid}` cacheだけを返すよう変更 |
| Required audit checkpointの再bless | `csf_946dae7f9681235b9da31c01` | Required checkpoint欠落を空chainでもfail closedにし、初期化を明示operator commandへ分離。通常append/checkpoint更新は同じDB advisory lock内で、現在の外部anchorのHMACとDB tailがそのdescendantであることを証明してからCAS相当で置換する。切断・rollbackはsticky integrity failureとしてwrite/readinessを拒否し、通常処理から再署名しない |
| WebSocket cap前のDB work | `csf_eccd88ff6f54ab61def79f0b` | Engine.IO preflightでpending/source/global leaseとserial-attempt budgetをDB照会前に取得し、session照会を一回へ統合。Active sessionはexpiry/device bindingを保持 |
| Browser import不能JWKのdirectory poison | `csf_b1d44ccf3fabc247d950ba50` | RSA/P-256 public JWKをcanonicalizeし、`key_ops`/`ext`/curve/useを厳密検査。Legacy lookupもbounded semantic matchへ限定 |
| One-person DMによるmember-removal veto | `csf_595bfd76168fae18bdcd5524` | DMは2人以上のdistinct participantを必須化し、workspace removal時に対象のDM/private membershipをauthoritativeにcleanup |
| Channel-state N+1 amplification | `csf_1799dbb64fc45cf98d725ab9` | Workspace channel/category上限とcreate lockを追加し、channel stateをset-based queryへ変更。Routeにもuser rate limitを追加 |
| VIEW_CHANNELS喪失後のworkspace room再join | `csf_6a281af26bcd80a89a77dab8`, `csf_8fa6f55612873320d3396463` | Handshake hydrationとserver-driven joinを共通effective-`VIEW_CHANNELS` predicate・authorization lockへ統一 |
| Invitation revokeのstale authority | `csf_134711d140c04b701e20199c` | Workspace/invitation lock取得後にcurrent `MANAGE_MEMBERS`を再検査 |
| Audit GETのside effect / CSRF | `csf_c9ee4bc8fd47e8e12629f2e2`, `csf_ccf63048ed307a9b02ddfed6` | Audit閲覧・integrity操作をPOSTへ変更し、既存のexact-Origin protectionへ通した |
| Unauthenticated broadcast mention intent | `csf_6e531ef09ae72f000e0a4320` | Message protocol v3でbroadcast flagをsignature/AADへbindingし、serverで`MENTION_EVERYONE`を検査。Legacy v2はbroadcast扱いしない |
| Client mutation projectionの認証不足 | `csf_045303da11b74f8bd64e6360` | Edit/delete signatureとbase author/targetを検証し、未検証eventをquarantine。Unsigned delete合成を廃止し、REST mutation responseも送信時に作ったlocal signed envelopeとsecurity-relevant fieldが完全一致した場合だけ`cryptoVerified`としてprojectorへ渡す |
| Development launcherのshell injection | `csf_9e62a73319b8bce1fd7b7dd0` | `just_run.sh`を安全な`dev.sh` execへ変更し、`.env`はallowlist parserでdataとして処理 |

Remediation後、fresh PostgreSQL 16へmigration `0000`〜`0012`を適用し、fresh PostgreSQL/MinIO integration 2/2、server 49/49、client 77/77、全workspace typecheck/build、production dependency audit（known vulnerability 0）、license JSON、backup security、shell syntax、migration journal、`git diff --check`を現treeで確認した。Integrationには自己ackだけではpendingから遷移しないこと、競合candidate上書き拒否、署名abortと単調version retry、全required recipientのexact ACKによる正規activation、外部checkpoint anchor row切断時のmutation rollback・audit非追記・checkpoint非置換・readiness失敗を含む。

別エージェントによる最終read-only bypass reviewは、保存済み34 findingすべてをsource-to-sinkで再確認し、具体的に悪用可能な残存bypassを報告しなかった。特にactivation直前のcurrent membership/device snapshot再照合、active epochだけのmessage/file write、REST responseのlocal signed envelope完全一致、audit anchor-to-tail descendant proofとsticky latchを確認した。Scanのcanonical `findings.json` / `report.md` は履歴保持のため変更せず、修正結果はscan artifact配下の独立した `artifacts/fix_report.md` に記録した。

## Release conclusion

現時点の結論は **Prototype / formal production use未承認** である。MLS、approval/key transparency、WebAuthn/OIDC、desktop/mobile、Restricted profile、HA、PITR/WORM/off-site/automatic DR、retention/export、signed updates、media、Bot/Webhook、独立外部security reviewなどのarchitectural blockerはlocalized findingの修正とは別であり、`LIMITATIONS.md` と `THREAT_MODEL.md` に残る。
