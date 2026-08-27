# LIMITATIONS.md — Phase 1 Prototype 制限事項

最終更新: 2026-08-27

> **現在の境界**
>
> - Client: Webのみ（React/TypeScript SPA）
> - Server: Linux上のsingle-node / single-process Node.js + PostgreSQL + MinIO
> - Crypto: basic per-channel epoch key（MLSではない）
> - Product: text-centered + 最大8人P2P音声のsmall-team prototype

このリポジトリは `SPECIFICATION.md` の初期正式版を完成させたものではなく、正式運用へ承認されていない。Prototypeのfresh integration/release gateと通常のrepository-wide single-pass security scanは完了し、その後、完了前に停止したDeep Security Scanから保存された34件を23の根本原因へ整理して現treeへ修正した。Deep Scanの集約manifestは完了しておらず、この修正作業はformal architecture blockerまたは独立外部reviewを完了した意味ではない。ゼロデイ、認証情報、Embargo情報などの高影響秘密へ使用しないこと。

## 現在利用できるPrototype境界

- Webクライアントでworkspace/category/channel、private channel、基本的な暗号化text message、返信、編集、削除、reaction、pin、bookmarkを利用できる。
- 1対1 DM/group DMのAPI、鍵受信者となるmember model、一覧・作成UIがある。
- message eventはREST/Socketの耐久化後経路から取り込まれ、client projectorが`(createdAt, id)`順序、重複排除、edit/delete/reaction/pin stateを決定的に投影する。
- workspace作成・一覧・member removal、category/channel管理、private member管理、role CRUD/割当/変更preview/有効権限理由、session/device一覧と失効UIがある。
- Category/channel role permission overrideはallow/deny/inherit、適用前preview、override・認可の両revision、実効権限理由、失権時のroom退出とrekey、公式clientの局所消去に対応する。
- Attachmentはfile別key、暗号化filename、5 MiB chunk AEAD、中断再開、取消、短命予約、opaque download復号、危険形式警告に対応する。Protocol-levelの複数chunk中断再開からdownload SHA一致を隔離PostgreSQL/MinIOで確認している。
- 音声はchannelに紐づく最大8人のP2P WebRTC meshとして、参加・退出、ミュート、音声検出／プッシュトゥトーク、入出力device切替、発言者・接続品質表示に対応する。Signalingの参加認可・中継・失権退出を隔離integrationで確認している。
- 招待は一回限り、期限付き、個別失効、任意email bindingに対応し、管理UIで作成・一覧・失効できる。tokenの配送はoperatorによる安全なout-of-band共有であり、email配送機能はない。
- channel別draftと未送信outboxは暗号化してIndexedDBへ保存される。同じidempotency keyでonline復帰時に再送し、queued/sending/failedを区別する。
- 検索UIは、このbrowser tabがすでに読み込み、復号してmemoryへ保持しているmessageだけを検索する。検索語はHTTP/WebSocketへ送信しない。
- auditはcanonical HMAC chain、state変更と同一transactionのappend、起動時検証、監査閲覧の自己監査、HMAC付きcheckpointを備える。Required modeの初期checkpointは明示operator commandでのみprovisionする。通常append/checkpoint更新は外部anchorからDB tailまでの連続性を同じlock内で検証し、欠落・rollback・tail切断時は起動/readiness/writeをfail closedにする。
- 手動のmigration前backup gateは、PostgreSQL custom-format dumpとMinIOの最新objectを一つのmanifest/checksumへまとめ、age recipientへ暗号化する。空の隔離DB/bucketだけを対象にrestore/count/reference/object SHAを検証するscriptがある。

上記は対応するunit/integrationまたは隔離実動試験がある機能境界の説明であり、正式要件ID全体の適合宣言ではない。

## 実施済みの最終確認

### Final repository-wide security gate

通常のrepository-wide single-pass scan `1e2517d2-1dad-4360-9e0d-855dfd224047` はMedium 4件・Low 3件（Critical/Highなし）を報告し、全件を修正した。その後のDeep Security Scan child `c677fed2-242f-40e5-92c9-26e44f2de49d` はorchestration完了前に失敗したが、保存された34 finding（High 1 / Medium 23 / Low 10）は欠落なく23の根本原因へ整理し、共有境界で修正した。これは「Deep Scan完了」または「finding 0」の宣言ではない。現treeの修正・検証記録は `SECURITY_AUDIT.md` に分離する。

## 主要な制限

### 認証、端末、承認

- 認証は招待制email/passwordであり、WebAuthn/Passkey、OIDC、一般の管理操作のstep-up、管理者へのphishing-resistant authenticator強制はない。新しいdevice identityの登録だけはcurrent passwordとsession-bound one-time challengeへのdevice署名を要求する。
- sessionは1つのactive deviceへbindingされ、既存identityへのbindingにもdevice署名を要求するが、新端末を既存端末で承認するworkflow、端末attestation、組織支援型・閾値型recoveryはない。
- destructive operation、policy変更、recovery、組織exportの二者承認はない。
- Workspace管理は作成・一覧・member removalまでで、workspace rename/delete/icon update/owner transfer、組織policy管理はない。

### E2EEと鍵管理

- Message/attachmentはbrowserでAES-256-GCM暗号化し、message protocol v3では認証user ID、mutation target、broadcast-mention flagを含むcontext付きenvelopeへP-256 device keyで署名する。Server/clientはuser-device bindingを再確認し、channel keyがない場合はplaintextへfallbackせず停止する。旧protocol v1 ciphertextは互換復号せずfail closedになり、protocol v2 messageはlegacy互換としてbroadcast mention権限を持たない。
- Basic per-channel epochはmember/device失効後の将来鍵配布を止めるためのPrototype方式である。RFC 9420 MLS相当のmessage-level forward secrecyまたはpost-compromise securityを提供しない。
- Channel epochはfrozen recipient snapshotを持つ`pending`として提案され、全required recipient deviceが署名・復号・commitmentを検証し、server発行のexact delivery IDとdistributorへ署名ackした場合だけatomicに`active`となる。`pending`はmessage/attachment write資格を持たず、per-distributor delivery candidateはimmutableである。中断時はmanagerまたはDM participantが署名abortし、次回は単調増加versionで再提案する。ただしappend-only transparencyやindependent witnessはない。
- 全required端末のackをactivation barrierにするため、offline端末が残ると新epochは有効化されない。Operatorが黙ってbarrierを迂回する仕組みはなく、管理者は不要端末を失効させたうえでpending epochをabortし、次versionを再提案する必要がある。
- 新しい端末へ自動配布するのは現在epochのchannel keyだけで、参加前・端末登録前の過去epoch keyを既存端末から安全にbackfillするworkflowはない。過去履歴を必ず復旧できるとは表示しない。
- 1 userは最大8 active device、1 workspaceは最大50 member、1回のchannel-key配布は最大400 active recipient deviceで、paginationまたは複数batchを跨ぐatomic commitはない。複数端末を含む実recipientがこの上限へ達すると新epochを配布できないため、正式capacity planningまではsmall-team運用に限定する。
- Device directoryにappend-only transparency log、consistency proof、independent witness、split-view検出がない。悪性serverが利用者ごとに異なるdirectoryを提示する脅威を形式的に閉じていない。
- Server/operatorはuser/workspace/channel membership、device routing、message/attachment ID・時刻、ciphertext size、attachment MIME type・chunk count・upload/download timing、opaque storage keyを観測できる。完全なmetadata inventory/public disclosureはなく、配送拒否、削除、rollback、可用性妨害も可能である。正規受信者によるcopy、screenshot、外部撮影、受信済みdataの完全遠隔消去も防止できない。

### Browser local stateとoffline

- Device private keyとdraft/outbox用AES-GCM keyはいずれもnon-extractable WebCrypto `CryptoKey`としてsame-origin IndexedDBへstructured clone保存される。OS keychain、TPM、Secure Enclave相当の別trust boundaryではない。
- Draft/outboxのciphertextとその復号keyが同じoriginのIndexedDBにあるため、disk上の単純な平文露出は避けても、compromised originが配信するJavaScriptはkeyをexportせずに暗号操作へ利用できる。
- Logout/user切替は復号済みmemory stateとkey cacheを消すが、同じ有効deviceで再開できるよう暗号化recordは残る。browser profile削除やIndexedDB喪失からの復旧、複数端末draft同期、Service Workerによるfull offline history cacheはない。
- Outboxの非同期保存・送信・削除は開始時のuser/device/generationへ固定し、principal切替後のcallbackを破棄する。同じ有効device向けの暗号化recordを保持する設計であり、logoutだけでbrowser disk上のrecordを物理消去する保証ではない。
- 接続中にchannel/workspace accessを失った場合、direct通知を受けた公式clientは該当message/thread、draft/outbox、添付task、同期state、active deviceの永続channel keyを局所消去する。ただし通知を受ける前にoffline・終了・改変されたclient、browser backup、受信済みcopyまで遠隔消去する保証はなく、再接続時reconciliationもclientが保持しているscope情報の範囲に限られる。

### 履歴、検索、通知

- Searchはロード済み復号messageのin-memory検索だけである。全履歴・複数workspace検索、file抽出text、暗号化永続index、端末間index同期、破損時再構築はない。
- Read position、unread、favorite/mute/hide/bookmarkは同期する。Mention数はclientが実際にロード・復号できた範囲でのみ数え、境界不明時に完全な件数を装わない。
- Thread panelはこの端末で読み込み・復号済みの同一channel返信だけを表示し、serverから完全なthreadを追加取得しない。UUID形式のmessage linkは認可確認後に最大20 pageの履歴を遡る範囲だけを開ける。大量貼り付けは2,000 bytesまたは20行以上で確認previewを表示する。Role/channel mentionとRestricted向けcopy/export確認はない。
- Presence/typing/readをuserまたはworkspace単位で無効化する設定と、notificationのcategory継承はない。Notification levelはchannel単位のall/mentions/noneに限られる。
- Push通知、background sync、notification本文policyはない。

### 添付と外部content

- Serverはobjectをinline表示せず、authorization確認後にopaque attachmentとして返す。Web clientはMarkdown imageを自動取得しない。
- Client attachment flowは上記Prototype境界で利用できる。OS quarantine属性、sandboxed malware/PoC viewer、archive bomb/image parser防御、endpoint malware analysisはない。
- File System Access API非対応browserでは100 MiBを超えるdownloadを保存できず、それ以下はmemory上のBlob fallbackを使う。対応browserは逐次書き込みを使う。
- ServerはJSON/chunk bodyをparser前のContent-Length、aggregate byte、source/user、concurrency budgetへ通し、download/object-storage leaseをstream終端まで保持する。これはsingle-process内のresource boundであり、distributed edge protectionや無制限に遅い正規downloadを保証するものではない。
- Server-side malware scanはE2EE plaintextを持たないため実施できない。安全性を保証する表示をしてはならない。

### 音声通話

- 音声本文はbrowser間のWebRTC DTLS-SRTPでpairwiseに暗号化され、application serverはmedia pathへ入らない。TURNを設定した場合もrelayはDTLS-SRTP本文を復号しない。録音機能は実装せず、既定で録音しない。
- Socket.IO serverは現在channelを閲覧でき、active deviceへbindingされた参加者だけを最大8人までfresh call-participant IDで登録する。Offer/answer SDPとICE candidateは送信端末のP-256 keyで署名し、channel、送受信participant、sender device、単調sequenceへbindingする。受信clientはdevice directoryのuser-device bindingと署名を検証し、参加中のsenderごとに旧sequence/replayを拒否する。Serverは署名本文を変更せず対象participantへだけ中継し、channel room退出・失権・disconnect時にvoice registryからも除去する。
- 第三者ICE serviceは既定で設定しない。`VOICE_ICE_SERVERS_JSON=[]` のままではdirect candidateで到達できるnetworkに限られ、Internet/NAT越しの接続性は保証しない。必要なSTUN/TURNはoperatorがセルフホストし、TURN credentialはauthenticated participantへ開示されるものとして短命化する。
- P2P meshのため送受信帯域とpeer connection数は参加人数に比例し、上限は8人である。正式な同時接続capacity、長時間soak、全browser/mobile network、TURN failover、QoSは検証していない。Peer同士は相手のnetwork addressをICE情報から観測し得て、server/TURN/operatorは参加者、時刻、SDP/ICE、traffic量などのmetadataを観測できる。
- 専用の常設voice channel type、SFU、SFrame、映像、camera切替、画面共有、録音・録画と継続表示、録音Bot、通話group-key ceremonyは未実装である。Pairwise DTLS keyはpeer connectionごとに新規確立されるが、`MEDIA-08..13` 全体、特にmalicious directory serverに対するkey transparencyと正式なparticipant-change rekeyを完了したとは扱わない。

### Audit

- PostgreSQL内のHMAC chainは改変検出に役立つが、DB operatorが末尾rowをcheckpointごと消せる配置では末尾切断を独立検出できない。
- `AUDIT_CHECKPOINT_PATH` がPostgreSQL operatorとはwrite/delete権限を分離したmountまたはstorageに置かれた場合だけ、operator-independent checkpointと呼べる。同じhostの通常fileやsystemd `StateDirectory`だけなら、事故検出の改善に留まる。
- Required checkpointの初期provisionは `pnpm --filter @alparts/server audit:checkpoint:init` を明示実行する。通常の起動・appendは欠落したcheckpointを自動再作成せず、現在anchorより前へ切断されたDB suffixを新しい正史として再署名しない。
- 外部SIEM/WORM監査保管、転送欠落alert、保持期間、backup取得・削除の集中監査、export approvalはない。
- `AUDIT_INTEGRITY_KEY` を失うとchainを正しく検証できない。DB dumpとは別の暗号化資産として管理する必要がある。

### Backup、restore、availability

- 2026-08-27に一意な使い捨てPostgreSQL 16/MinIO環境でbackup→非特権の空DB/空bucketへのrestore roundtripを実施し、run `20260827T051348Z-e8e85d921692` の25 table、2 object、134 bytesについてmanifest/checksum/count/reference/redownload SHA一致を確認した。PostgreSQL credentialはmode `0600`のlibpq service file、MinIO credentialはstdin経由の一時configで渡し、child argv/environmentへsecretを継承しない。
- Scriptは手動起動後のdump、encryption、restore mechanics、整合性検証を自動化するが、application停止、schedule、retention、artifact搬送、migration、cleanup、full application recoveryを自動化しない。PostgreSQLとMinIOに共通transactionはないため、backup中はwriteを停止しなければならない。
- Restoreはextract前にarchive entry数、単一fileとaggregateのexpanded bytes、entry type/path、compact sparse表現を検査する。既定1 TiBはprotocol ceilingにすぎず、operatorはstaging filesystemのquotaと安全な空き容量以下へ設定する必要がある。
- PITR/WAL archive、MinIO version history、WORM/object lock、off-site replication、自動週次restore、RTO/RPO、failover、四半期DRはない。成功したroundtripはDB rowと最新ciphertext objectをその隔離先へ再現できたことだけを示す。
- Single process/single DBであり、HA、broker、DB failover、rolling update、single-nodeからclusterへの移行実証はない。
- Object-storage requestには既定10秒・最大60秒のheader/stream inactivity timeoutと、単一node内のactive/pending work上限がある。Remote I/OはDB transaction外で行い、DB commit後のobject orphanはcleanupで回収するが、PostgreSQLとMinIOの分散transactionは提供しない。Download開始後に権限が失効しても、すでに送信開始したciphertext streamを遠隔回収することはできない。
- WebSocketのrate/socket budgetとroom-join serialization、attachment upload serialization、object-storage gateはいずれもprocess-localである。現在はsingle-process前提であり、複数instance化する前に共有coordinationへ置換しなければならない。

### 配布、data governance、UX assurance

- Repository/package metadataは現在 `UNLICENSED` であり、project codeの利用・改変・再配布を許諾していない。Production依存のlicense inventoryは取得済みだが、権利者によるproject license選定と法務確認が終わるまで `DEP-08` / `OSS-02` を満たさない。
- OCI image/systemd例はあるが、SBOM、SLSA provenance、release signing、downgrade prevention、signed updater、multi-architecture release pipelineはない。
- Retention policy engine、server/client cache lifecycle、user data export、organization export、二者承認、legal holdはない。
- Restricted / Embargoed profileは実装されていない。Web禁止、参加後のみの履歴、外部user approval、閾値recovery、通知本文制限などをpolicyとして強制できない。
- WCAG 2.2 AA、日本語/英語、keyboard-only、screen reader、timezone/RTLについて包括的な自動・手動監査はない。
- 独立外部security review、72時間soak、正式capacity planning、operational SLAは未実施である。

## 正式仕様上の延期blocker

| 領域 | 状態 |
| --- | --- |
| MLS、key transparency、independent witness、既存端末approval | 延期 |
| WebAuthn/Passkey、OIDC、step-up、二者approval、recovery | 延期 |
| Windows/Linux/macOS desktop、iOS/Android、OS secure storage | 延期 |
| HA、broker、DB failover、cluster migration、PITR/WORM/off-site/自動DR | 延期 |
| Retention、user/org export、Restricted profile | 延期 |
| SBOM/SLSA、release signing、signed update/downgrade protection | 延期 |
| Project license選定、copyright/third-party notice、再配布条件の法務確認 | 延期 |
| P2P音声以外のmedia（専用voice channel、video/screen sharing、SFrame、self-hosted SFU、recording controls） | 延期 |
| Bot/Webhook identity、scoped API、external integration | 延期 |
| 独立外部security review、full accessibility/i18n/performance assurance | 延期 |

## N/A

`NET-03` のservice間mTLSは、現在のapplicationが単一processでservice間network boundaryを持たないためN/Aである。PostgreSQL/MinIOへのremote接続はこのN/Aに含まれず、authenticated TLSとleast-privilege credentialが必要である。将来processを分割した場合はmTLS/service identity設計を再開する。

詳細な依存順と完了条件は `IMPLEMENTATION_TODO.md`、trust boundaryは `THREAT_MODEL.md`、監査履歴・standard scan・未完了Deep Scan由来の修正結果は `SECURITY_AUDIT.md`、backup操作は `docs/BACKUP.md` を参照する。
