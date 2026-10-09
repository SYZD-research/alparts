# LIMITATIONS.md — Phase 1 Prototype 制限事項

最終更新: 2026-10-07

> **現在の境界**
>
> - Client: Web、およびWindows・Linux・macOS desktop（React/TypeScript + Electron）
> - Server: Linux上のsingle-node / single-process Node.js + PostgreSQL + S3互換オブジェクトストレージ（推奨はSeaweedFS）
> - Crypto: channelごとに継続するMLS group（group protocol 4）+ separate encrypted archive keys
> - Product: text-centered + 最大8人P2P音声のsmall-team prototype

このリポジトリは `SPECIFICATION.md` の初期正式版を完成させたものではなく、正式運用へ承認されていない。2026-08-30に公式npx CLIのDeep Security Scanはartifact packagingまで完了し、13 canonical finding / 15 report instanceを出力した。Coverageはtime ceilingとdeferred reconciliationにより`partial`で、検出根本原因を現treeで修正しても、formal architecture blockerまたは独立外部reviewを完了した意味ではない。ゼロデイ、認証情報、Embargo情報などの高影響秘密へ使用しないこと。

## 現在利用できるPrototype境界

- Webおよびdesktopクライアントでworkspace/category/channel、private channel、基本的な暗号化text message、返信、編集、削除、reaction、pin、bookmarkを利用できる。
- 1対1 DM/group DMのAPI、鍵受信者となるmember model、一覧・作成UIがある。
- message eventはREST/Socketの耐久化後経路から取り込まれ、client projectorが`(createdAt, id)`順序、重複排除、edit/delete/reaction/pin stateを決定的に投影する。
- workspace作成・一覧・member removal、category/channel管理、private member管理、role CRUD/割当/変更preview/有効権限理由、session/device一覧と失効UIがある。
- Category/channel role permission overrideはallow/deny/inherit、適用前preview、override・認可の両revision、実効権限理由、失権時のroom退出とrekey、公式clientの局所消去に対応する。
- Attachmentはfile別key、暗号化filename、5 MiB chunk AEAD、中断再開、取消、短命予約、opaque download復号、危険形式警告に対応する。Desktop保存では平文をbounded native streamへ渡し、危険形式にWindows/macOSの隔離属性またはLinuxの非実行権限を付ける。Protocol-levelの複数chunk中断再開からdownload SHA一致を隔離PostgreSQL/MinIOで確認している。
- 音声はchannelに紐づく最大8人のP2P WebRTC meshとして、参加・退出、ミュート、音声検出／プッシュトゥトーク、入出力device切替、発言者・接続品質表示に対応する。Signalingの参加認可・中継・失権退出を隔離integrationで確認している。
- 招待は一回限り、期限付き、個別失効、任意email bindingに対応し、管理UIで作成・一覧・失効できる。tokenの配送はoperatorによる安全なout-of-band共有であり、email配送機能はない。
- channel別draftと未送信outboxは暗号化してIndexedDBへ保存される。同じidempotency keyと同一署名済みrequestで、上限付きexponential backoff+jitterによりonline復帰時に再送し、queued/sending/failedを区別する。Outboxはactive deviceごとに100件を上限とする。
- 検索UIは、このbrowser tabがすでに読み込み、復号してmemoryへ保持しているmessageだけを検索する。検索語はHTTP/WebSocketへ送信しない。
- auditはcanonical HMAC chain、state変更と同一transactionのappend、起動時検証、監査閲覧の自己監査、HMAC付きcheckpointを備える。Required modeの初期checkpointは明示operator commandでのみprovisionする。通常append/checkpoint更新は外部anchorからDB tailまでの連続性を同じlock内で検証し、欠落・rollback・tail切断時は起動/readiness/writeをfail closedにする。
- Migration前backup gateは、PostgreSQL custom-format dumpとオブジェクトストレージの最新objectを一つのmanifest/checksumへまとめ、age recipientへ暗号化する。空の隔離DB/bucketだけを対象にrestore/count/reference/object SHAを検証する。Single-host用のdaily systemd schedule、non-overlap/restart trap、安全なlocal retentionもある。

上記は対応するunit/integrationまたは隔離実動試験がある機能境界の説明であり、正式要件ID全体の適合宣言ではない。

## 実施済みの最終確認

### Final repository-wide security gate

通常のrepository-wide single-pass scan `1e2517d2-1dad-4360-9e0d-855dfd224047` はMedium 4件・Low 3件（Critical/Highなし）を報告し、当時のtreeで全件を修正した。2026-08-30の公式Deep Security Scan `160868a8-5398-4707-ac05-e4c99c18fdd8` はpre-change revisionから13 canonical finding / 15 instance（Medium 10 / Low 5）を報告し、artifactはsealed/completedだがcoverageはpartialである。現treeの根本修正と検証は `SECURITY_AUDIT.md` と `docs/RISK_REGISTER.md` に分離し、「finding 0」またはexhaustiveとは宣言しない。

実装・保証・移行の詳細は[account/group security](../security/ACCOUNT_AND_GROUP_SECURITY.md)を参照。

## 主要な制限

### 認証、端末、承認

- 招待制のpassword認証に加えて、Web版のPasskeyと重要操作のstep-upを実装した。Passkey登録後のpassword fallbackは禁止する。Passwordはstep-up付きで変更でき、変更時は他のsessionを終了する。Passkeyを登録した利用者はpasswordでのloginを無効にでき、運用者はCLIでpasswordを再設定できる（再設定はpassword loginを有効に戻し、全passkeyを削除し、全sessionを終了する。端末は残るので、本人が見覚えのない端末を失効させる）。Step-upはsessionごとに15分あたり120操作まで、本人確認の失敗はこれとは別に15分あたり10回までに制限する（盗まれたsessionが上限を使い切っても、本人の別sessionからの確認と失効は妨げられない）。OIDC、組織による認証器数の強制、nativeアプリのWebAuthn連携は未実装。
- bcryptは固定2本のWorker threadで実行し、active 2 / pending 16 / 待機5秒を超えると503でrejectする。保存hashの形式/costを処理前に検証し、実行が30秒を超えたWorkerは失敗として終了する。新端末step-upのKDFはaudit/key/DB row lockより前に完了させる。これはsingle-processのCPU隔離であり、複数replicaを合算したrate limitや外部DDoS防御ではない。
- Sessionは1つの端末にbindingされ、追加端末は既存端末の承認または復旧コードによる確認が必要。端末attestationと組織支援型・閾値型recoveryは未実装。
- 新端末登録時のpending epoch cleanup（group protocol 4以降は新しいpending epochを作らず、migration 0023で残りを中止済み）は最大50 workspace membershipを安定順にlockし、各workspaceの最大300 channel内でset-basedに実施する。他tenantがaccount-globalな小さい上限を消費して端末回復を恒久妨害する設計ではないが、上限全体を処理する登録は通常より高latencyになり得てstatement timeout内に完了しなければ安全にrollbackする。
- destructive operation、policy変更、recovery、組織exportの二者承認はない。
- Workspace管理は作成・一覧・member removalまでで、workspace rename/delete/icon update/owner transfer、組織policy管理はない。

### E2EEと鍵管理

- Message/attachmentはbrowserでAES-256-GCM暗号化し、message protocol v3では認証user ID、mutation target、broadcast-mention flagを含むcontext付きenvelopeへP-256 device keyで署名する。Server/clientはuser-device bindingを再確認し、channel keyがない場合はplaintextへfallbackせず停止する。旧protocol v1 ciphertextは互換復号せずfail closedになり、protocol v2 messageはlegacy互換としてbroadcast mention権限を持たない。
- Message protocol v5（現在のclient）は、編集・削除・引用・forum返信の対象を作者と署名済みidempotency keyでも指す。旧client（v3/v4）のeventと、idempotency key署名以前のmessageへの参照はserver IDだけで対象を指すため、悪意あるserverはそれらを同じ作者の別messageへ付け替えて表示させられる（形式モデルM9、RISK_REGISTER R-051）。参照のないmessageは従来の形式で署名するが、更新されていないclientはv5 eventを検証できない。そのため更新済みclientによる編集・削除を反映せず、引用とforum返信を検証できないmessageとして表示する。desktop・Android appは同梱のclientを使うため、app自体の更新が必要である。
- Channel keyはMLSライブラリのgroup/commit/Welcome/exporterで作る。Channelごとに一つのMLS groupを継続し、端末の追加・削除と定期更新をcommitで反映する（group protocol 4、[ADR 0012](../adr/0012-continuous-mls-groups.md)）。長期の履歴鍵を別途保存するため、message単位の完全なforward secrecyは主張しない。他のMLS実装との相互運用、external commit/join、MLS application messageによるmessage単位のratchetは提供しない。独立reviewは未実施。
- Serverはchannelごとにcommitを順序付け、1 versionに1 commitだけを、直前versionとそのtranscriptのcompare-and-swapで受理する。受理したcommitはその場で`active`になり、pending、全員の受領確認、abortはない。Serverはcommit envelopeの署名、roster、Add/Removeとpackageの一致、Welcomeの宛先、UpdatePathのleaf credentialを検証するが、MLSの秘密値（path secret、exporter）は検証できない。同じbyte列の再送には同じ結果を返す。端末directoryの追記型chainとclient checkpoint照合を実装したが、独立witnessはない。
- Offline端末は書き込みを止めない（例外は、移行直後のchannelで最初のgroupを待つ間。次項）。戻った端末は保存されたcommit logを順に処理して追いつく。書き込みが止まるのは、groupに資格を失った端末（失効・未承認・channel閲覧権の喪失）が残っている間と、group更新（genesis、Remove付きcommit、空commit）が24時間受理されていない間だけで、onlineの利用可能なmember 1台がRemoveまたは更新のcommitを出せば再開する。送信する端末自身が利用可能なmemberなら、公式clientは送信前にそのcommitを出す。追加待ちの端末は書き込みを止めない。
- 新しく資格を得た端末（新端末、channelを新たに閲覧できるようになったuserの端末、移行後の最初のgroupに入らなかった端末）はpackageを公開し、onlineのmemberに追加されるのを待つ。追加されたversionから読める。資格を得てから追加されるまでに書かれたmessageは、同じaccountの暗号化履歴archiveに含まれる場合を除き、その端末では読めない（HIST-01は未達）。移行直後のchannelは、最後の鍵の受信者だった、まだ資格のある端末がすべてpackageを公開するか、そのchannelで最初のpackageが公開されてから24時間経つまで最初のgroupを作れず、その間は書き込めない。
- 正しく署名されたcommitやWelcomeを処理できなかった端末、またはlocalのgroup stateを失った端末は、導出済みの鍵を残したまま参加し直しを要求する（rejoin。server・clientとも1端末1 channelあたり24時間に3回まで）。次のcommitでほかの利用可能なmemberが同じ端末を外して追加し直す。
- 次のいずれかの場合に限り、step-upと端末署名を伴う明示操作で新しいgroupを始められる（fresh start）: 利用可能なmemberがいない、または72時間誰もonlineでない（資格のある端末）、自分の参加し直しの要求が30分進まない（その端末）、追加・削除・参加し直しが15分進まない（channel管理者・DM参加者）。それ以前のmessageは、鍵または履歴archiveを持たない端末では読めないままになる。Channel管理者（DMではほかの参加者）へ通知する。Operatorが条件を迂回する仕組みはない。
- 侵害後の回復（CRYPTO-04）はgroup protocol 3より狭い。UpdatePath付きcommitで更新されるのはcommitした端末自身のleafとpath secretだけで、書き込む端末は自分のleafを少なくとも7日ごとに更新し、ほかの端末も自分がRemoveや24時間の更新をcommitしたときには更新されるが、そうしたcommitをしない端末のleafは削除されるまで更新されない。Protocol 3は各versionで全参加端末の新しいpackageからgroupを作り直していた。
- 端末がgroupへ追加された後、一度もそのgroupに参加しないうちに外された場合（例: offlineの間に追加され、そのまま閲覧権を失った）、その期間のversionの鍵は端末がcommit logから得られず、利用者が保存した履歴archiveからだけ復元できる。端末は現在のmembershipから参加する（形式モデルM3のKA-unjoined）。
- 履歴archiveを復元したgroup外の端末を失効させても、現在のversionの鍵はその端末に残る。Group外の端末の失効はcommitを要求しないため、次のcommit（最長でも24時間ごとの更新）まで新しいmessageもその鍵で暗号化される。失効した端末はserverからmessageを取得できないので、影響はserverを信頼しない前提のときに限られる（形式モデルM3のKC-dev-restore）。
- 資格のある悪意あるmemberは、特定の端末だけが処理できないcommitや開けないWelcomeを出し、rejoinを強いることができる（MLSのinsider DoS）。Serverはこれを検出できない。各versionのcommitter deviceは監査に記録され、対処は管理者によるmember除外と、必要ならfresh startである。
- 保管済み復旧コードで、事前にserverへ暗号化保存した履歴鍵を復元できる。Accountへのloginは別途必要。未保存の履歴、復旧コードも全端末も失った履歴、失権したchannelは復旧できない。管理者代理復旧はない。
- 1 userは最大8 active device、1 workspaceは最大50 member、1 channelのgroupは最大400 member device（50×8と一致）である。最初のgroupは最大400端末を1 commitで追加し、commitのpaginationや複数batchを跨ぐatomic commitはない。正式capacity planningまではsmall-team運用に限定する。
- 端末directoryは署名付き追記chainとlocal checkpointを照合し、group commitが運ぶdirectory headおよび任意の端末間確認でsplit viewを検出する。Serverがcommit履歴を端末ごとに分岐させた場合は、分岐したcommitが検証済みversionにつながらない時点で検出し、その会話の処理を止める（その時点まで検出できない）。初回はTOFUであり、互いに照合されないviewや初回anchorの偽装を独立witnessなしに検出できるとは主張しない。過去のmessage/attachment/key distributorの公開鍵は履歴検証に使える。
- 移行前のgroup protocol 3のkey packageは、まだ読んでいないv3履歴を後で読めるように端末に残す。最後のv3 version（最初のgroupができる前のactive version）より後のversion用のpackageは、端末がgroupのない状態のchannelを見た時点、または最初にgroupを見た時点で削除する。ただし、最初のgroupが存在した間ずっとofflineで、その後fresh startで置き換わった後に初めてonlineになった端末は、最初のgroupの開始versionを知る手段がなく、置き換え後のgroupの開始versionより前のpackageを残す。悪意あるserverとそのchannelのmemberが共謀すると、そのpackageでv3 epochを偽造し、その端末だけに最初のgroupの期間のmessageを別の内容として表示させうる（ほかの端末への内容の漏えいはない）。
- Group protocol 4のversionの鍵は端末が自分のgroupから導出し、commit logは1 page最大16 version・約4 MiBで取得する。一度group protocol 4のgroupを検証したchannelでは、それ以降のversionについてserverからの旧方式の配送を受け付けない（downgrade拒否）。それより前（v2/v3）の鍵の取得は`scope=current`を使い、履歴は1 request最大64 unique version、response最大864 deliveryで明示取得する。更新前tab向けのqueryなし経路は新しい順に最大16のactive/pending/retired epochだけを返しdeprecation headerを付けるため、長期間更新されないtabがそれより古い履歴を取得できる保証はない。
- Server/operatorはuser/workspace/channel membership、device routing、message/attachment ID・時刻、ciphertext size、attachment MIME type・chunk count・upload/download timing、opaque storage keyを観測できる。完全なmetadata inventory/public disclosureはなく、配送拒否、削除、rollback、可用性妨害も可能である。正規受信者によるcopy、screenshot、外部撮影、受信済みdataの完全遠隔消去も防止できない。

### Client local stateとoffline

- Web版ではdevice private keyとdraft/outbox用AES-GCM keyをnon-extractable WebCrypto `CryptoKey`としてsame-origin IndexedDBへstructured clone保存する。Desktop版ではprivate JWK、channel key、draft/outbox keyをOS保護領域でwrapし、IndexedDBにはpublic identityまたはopaque pointerだけを置く。Linuxで保護されたsecret serviceを利用できない場合、desktopはfail closedで開始しない。
- Web版ではdraft/outboxのciphertextとその復号keyが同じoriginのIndexedDBにある。Desktop版を含め、compromised client codeはkeyをexportできなくても正規process内で暗号操作へ利用できるため、client code侵害をOS保護領域だけで防ぐものではない。
- Logout/user切替は復号済みmemory stateとkey cacheを消すが、同じ有効deviceで再開できるよう暗号化recordは残る。browser profile喪失後は保存済み復旧コードと暗号化済み履歴に限り復元できる。複数端末draft同期とService Workerによるfull offline history cacheはない。
- Outboxの非同期保存・送信・削除は開始時のuser/device/generationへ固定し、principal切替後のcallbackを破棄する。同じ有効device向けの暗号化recordを保持する設計であり、logoutだけでbrowser disk上のrecordを物理消去する保証ではない。
- Message projectorの「検証済み」はnetwork JSONのbooleanではなくprocess-localな到達不能markerで伝播する。同じevent IDへ異なる署名済みenvelopeが届いた場合はlast-write-winsにせずsticky conflictとしてquarantineする。Reload/reconciliationが必要になり得る一方、依存するdirectory/keyを取得不能なeventを検証済みとして昇格しない。
- Browser APIはresponse bodyを含む総時間を60秒に制限し、scope取消をnetwork requestへ伝播する。Outboxはdeviceごと100件で新規受付を停止し、overflowを暗黙削除しない。Draft永続化はchannelごとに実行中1件と最新待機1件へcoalesceする。Message検証はchannelごとに実行中1件＋coalesced待機1件、cancel-awareな30秒、暗号処理64件/batchで、取消後も実処理が終了するまでは容量slotを保持する。常駐eventは1,000/channel・5,000/global・32 channelまでである。未ロードchannelのrealtime eventは保持せずRESTで再同期し、履歴window到達時は暗黙に無制限保持せずUI errorで停止する。Realtime認可処理、voice signaling/ICE、attachment runtime、channel-key scope履歴にも有限上限があり、上限時はfail-closed、明示error、または再接続reconciliationへ縮退する。
- 接続中にchannel/workspace accessを失った場合、direct通知を受けた公式clientは該当message/thread、draft/outbox、添付task、同期state、active deviceの永続channel keyを局所消去する。ただし通知を受ける前にoffline・終了・改変されたclient、browser backup、受信済みcopyまで遠隔消去する保証はなく、再接続時reconciliationもclientが保持しているscope情報の範囲に限られる。

### 履歴、検索、通知

- Searchはロード済み復号messageのin-memory検索だけである。全履歴・複数workspace検索、file抽出text、暗号化永続index、端末間index同期、破損時再構築はない。
- Read position、unread、favorite/mute/hide/bookmarkは同期する。Mention数はclientが実際にロード・復号できた範囲でのみ数え、境界不明時に完全な件数を装わない。
- Thread panelはこの端末で読み込み・復号済みの同一channel返信だけを表示し、serverから完全なthreadを追加取得しない。UUID形式のmessage linkは認可確認後に最大20 pageかつ上記1,000-event resident windowの範囲だけを開ける。大量貼り付けは2,000 bytesまたは20行以上で確認previewを表示する。Role/channel mentionとRestricted向けcopy/export確認はない。
- Forumはforum channelのchannel keyで全postを暗号化する。後から参加したmember・端末は、他channelと同じく参加前のpost/replyを復号できない（UIは「この端末では読めない投稿」と表示する）。Post一覧の検索は読み込み・復号済みpostのtitle/本文だけが対象である。Tag名、post作成者、時刻、返信数、lock/resolved/pin状態、post単位の既読時刻はserverが知る。
- Presence/typing/readをuserまたはworkspace単位で無効化する設定と、notificationのcategory継承はない。Notification levelはchannel単位のall/mentions/noneに限られる。
- Push通知、background sync、notification本文policyはない。

### 添付と外部content

- Serverはobjectをinline表示せず、authorization確認後にopaque attachmentとして返す。Web clientはMarkdown imageを自動取得しない。署名・AEAD検証済みの添付については、SVGを除く許可済みraster MIMEを25 MiBまで端末内の短命Blob URLでプレビューする。
- Client attachment flowは上記Prototype境界で利用できる。OS quarantine属性、sandboxed malware/PoC viewer、archive bomb/image parser防御、endpoint malware analysisはない。
- File System Access API非対応browserでは100 MiBを超えるdownloadを保存できず、それ以下はmemory上のBlob fallbackを使う。対応browserは逐次書き込みを使う。
- ServerはJSON/chunk bodyをparser前のContent-Length、aggregate byte、source/user、concurrency budgetへ通し、download/object-storage leaseをstream終端まで保持する。これはsingle-process内のresource boundであり、distributed edge protectionや無制限に遅い正規downloadを保証するものではない。
- Server-side malware scanはE2EE plaintextを持たないため実施できない。安全性を保証する表示をしてはならない。

### 音声通話

- 音声本文はbrowser間のWebRTC DTLS-SRTPでpairwiseに暗号化され、application serverはmedia pathへ入らない。TURNを設定した場合もrelayはDTLS-SRTP本文を復号しない。録音機能は実装せず、既定で録音しない。
- Socket.IO serverは現在channelを閲覧でき、active deviceへbindingされた参加者だけを最大8人までfresh call-participant IDで登録する。Offer/answer SDPとICE candidateは送信端末のP-256 keyで署名し、channel、送受信participant、sender device、単調sequenceへbindingする。受信clientはdevice directoryのuser-device bindingと署名を検証し、参加中のsenderごとに旧sequence/replayを拒否する。Serverは署名本文を変更せず対象participantへだけ中継し、channel room退出・失権・disconnect時にvoice registryからも除去する。
- 第三者ICE serviceは既定で設定しない。`VOICE_ICE_SERVERS_JSON=[]` のままではdirect candidateで到達できるnetworkに限られ、Internet/NAT越しの接続性は保証しない。必要なSTUN/TURNはoperatorがセルフホストし、TURN credentialはauthenticated participantへ開示されるものとして短命化する。
- P2P meshのため送受信帯域とpeer connection数は参加人数に比例し、上限は8人である。正式な同時接続capacity、長時間soak、全browser/mobile network、TURN failover、QoSは検証していない。Peer同士は相手のnetwork addressをICE情報から観測し得て、server/TURN/operatorは参加者、時刻、SDP/ICE、traffic量などのmetadataを観測できる。
- 専用の常設voice channel type、clientのSFU対応、SFrame、映像、camera切替、画面共有、録音・録画と継続表示、録音Bot、通話group-key ceremonyは未実装である。Serverにはmediasoupを使うSFU（`VOICE_SFU_ENABLED`、既定で無効）があるが、DTLS-SRTPをserver側で終端するため、serverが通話音声を復号できる（`MEDIA-08` を満たさない。形式モデル M8 VE2、RISK_REGISTER R-052）。有効にする前にframe暗号化が必要。Pairwise DTLS keyはpeer connectionごとに新規確立されるが、`MEDIA-08..13` 全体、特にmalicious directory serverに対するkey transparencyと正式なparticipant-change rekeyを完了したとは扱わない。

### Audit

- PostgreSQL内のHMAC chainは改変検出に役立つが、DB operatorが末尾rowをcheckpointごと消せる配置では末尾切断を独立検出できない。
- `AUDIT_CHECKPOINT_PATH` がPostgreSQL operatorとはwrite/delete権限を分離したmountまたはstorageに置かれた場合だけ、operator-independent checkpointと呼べる。同じhostの通常fileやsystemd `StateDirectory`だけなら、事故検出の改善に留まる。
- 再起動後の巻き戻し検知には、別 bucket の永続 head (`AUDIT_HEAD_BUCKET` / `AUDIT_HEAD_OBJECT_KEY`) を保全する。DB・checkpoint file・head の全保存先を同時に巻き戻す権限を持つ攻撃者は、この局所的な検証だけでは検知できない。head は通常のアプリデータ復元対象に含めない。
- Required checkpointの初期provisionは `pnpm --filter @alparts/server audit:checkpoint:init` を明示実行する。通常の起動・appendは欠落したcheckpointを自動再作成せず、現在anchorより前へ切断されたDB suffixを新しい正史として再署名しない。
- Message create/edit/delete/replay、reaction/pin、preference/bookmarkとsecurity/administration mutationはaudit rowとatomic commitする。Read positionとprovisional upload chunk registration/cleanupは個別audit eventを生成しないが、同じprocess-local fail-closed admissionを通る。Presenceとdevice activity timestampはadvisoryで、認可・key・quota・retention・recovery判断に使わず、gate saturationを避けるため対象外である。
- 外部SIEM/WORM監査保管、転送欠落alert、保持期間、backup取得・削除の集中監査、export approvalはない。
- `AUDIT_INTEGRITY_KEY` を失うとchainを正しく検証できない。DB dumpとは別の暗号化資産として管理する必要がある。

### Backup、restore、availability

- 2026-08-27に一意な使い捨てPostgreSQL 16/MinIO環境でbackup→非特権の空DB/空bucketへのrestore roundtripを実施し、run `20260827T051348Z-e8e85d921692` の25 table、2 object、134 bytesについてmanifest/checksum/count/reference/redownload SHA一致を確認した。PostgreSQL credentialはmode `0600`のlibpq service file、MinIO credentialはstdin経由の一時configで渡し、child argv/environmentへsecretを継承しない。
- 2026-08-30のcurrent-tree再検証では、run `20260830T094605Z-3e2bb09737cb` が現行29-table schemaと128-byte object 1件をage artifactへ保存し、非特権の空DB/空bucketで`VERIFIED`となった。欠落参照objectと不正なtarget名は復元前にfail closedとなった。
- Script/systemdはapplication stop/start、daily schedule、local retention、dump/encryption/整合性検証を自動化する。Artifactのoff-host/off-region搬送、scheduled restore、migration、failed restore cleanup、full application recoveryは自動化しない。PostgreSQLとオブジェクトストレージに共通transactionはないため、backup中は全writerを停止しなければならない。
- Restoreはextract前にarchive entry数、単一fileとaggregateのexpanded bytes、entry type/path、compact sparse表現を検査する。既定1 TiBはprotocol ceilingにすぎず、operatorはstaging filesystemのquotaと安全な空き容量以下へ設定する必要がある。
- PITR/WAL archive、object version history、WORM/object lock、off-site replication、自動週次restore、RTO/RPO、failover、四半期DRはない。成功したroundtripはDB rowと最新ciphertext objectをその隔離先へ再現できたことだけを示す。
- Single process/single DBであり、HA、broker、DB failover、rolling update、single-nodeからclusterへの移行実証はない。
- Startup/readinessはbundled migration journalに加えてPostgreSQL 16の`public` catalog（relation/column/constraint/index/trigger/policy/function/type/view）を最大4,096 descriptorでexact fingerprint照合する。Dedicated Alparts databaseを要求し、永続的なcovered schema driftはfail closedになるが、row corruption、role/grant drift、`public`外object、physical durability、probe間だけ変更する悪性DBAを検出する仕組みではない。PostgreSQL major upgradeにはreview済みmigration/restore rehearsal/fingerprint更新が必要である。
- Object-storage requestには既定10秒・最大60秒のheader/stream inactivity timeoutと、単一node内のactive/pending work上限がある。Remote I/OはDB transaction外で行い、DB commit後のobject orphanはcleanupで回収するが、PostgreSQLとオブジェクトストレージの分散transactionは提供しない。Download開始後に権限が失効しても、すでに送信開始したciphertext streamを遠隔回収することはできない。
- WebSocketのrate/socket budgetとroom-join serialization、attachment upload serialization、object-storage gateはいずれもprocess-localである。起動時のPostgreSQL session lockで同一DBへの二重起動を拒否し、所有権を失うと受付を停止する。監査commitからcheckpoint保存まで別lockを保持し、次のprocessは終了を待つ。`DB_POOL_MAX >= 2`と専用接続1本が必要。transaction-pooling proxyは未対応。複数instance化する前に共有coordinationへ置換しなければならない。
- 追加のdurable上限は、1 channel 1,000 pin、1 message 20 distinct emoji・1 user/message 20 reaction・合計1,000 reaction、pending upload 16/user・200/workspaceである。Audited/guarded authoritative commitは共通でprocess内active 1・waiting 64・待機30秒、upload operationは4/upload・64/processに制限する。これは単一processで意図したcorrectness bottleneckであり、大規模write throughputの実測はない。これらは保持期間やarchive workflowの代替ではない。
- Message履歴とaudit履歴そのものには自動retentionがない。Unread集計はDB上でexact countを行い、audit起動検証は1,000行ずつ走査するため、長期大規模運用のlatency/起動時間は未計測である。Channelごとのcommit log、使用済みpackage ID、group node keyの記録は削除しない。これらが長期間蓄積する環境を含むsoak/capacity試験とlifecycle設計は残る。

### 配布、data governance、UX assurance

- Project codeはAGPL-3.0-only（package metadataも同じ）で公開している。配布される依存（server・client・desktopのElectron・AndroidのAndroidX）はすべてAGPL-3.0と両立するlicense（MIT・ISC・BSD・Apache-2.0・BlueOak-1.0.0・0BSD）であることを確認した。配布物へのthird-party noticeの同梱が終わるまで `DEP-08` / `OSS-02` を満たさない。
- OCI/systemd/production Compose、pinned CI、SBOM生成、dependency/secret/CodeQL/Trivy gateはあるが、SLSA provenance、release signing、downgrade prevention、signed updater、multi-architecture release pipelineはない。
- Retention policy engine、server/client cache lifecycle、user data export、organization export、二者承認、legal holdはない。
- Restricted / Embargoed profileは実装されていない。Web禁止、参加後のみの履歴、外部user approval、閾値recovery、通知本文制限などをpolicyとして強制できない。
- WCAG 2.2 AA、日本語/英語、keyboard-only、screen reader、timezone/RTLについて包括的な自動・手動監査はない。
- 独立外部security review、72時間soak、正式capacity planning、operational SLAは未実施である。

## 正式仕様上の延期blocker

| 領域 | 状態 |
| --- | --- |
| Group protocolの独立review、independent witness、message単位のforward secrecy、UpdatePath付きcommitをしないmemberへの侵害後回復 | 残作業。Channelごとに継続するMLS group、端末approval、directory検証は実装済み |
| OIDC、native WebAuthn、二者approval、組織支援型recovery | 残作業。Web Passkey、step-up、利用者管理の履歴recoveryは実装済み |
| iOS/Android、desktop配布署名・notarization・署名検証update | 延期 |
| HA、broker、DB failover、cluster migration、PITR/WORM/off-site/自動DR | 延期 |
| Retention、user/org export、Restricted profile | 延期 |
| SBOM/SLSA、release signing、signed update/downgrade protection | 延期 |
| Project license選定、copyright/third-party notice、再配布条件の法務確認 | 延期 |
| P2P音声以外のmedia（専用voice channel、video/screen sharing、SFrame、self-hosted SFU、recording controls） | 延期 |
| Bot/Webhook identity、scoped API、external integration | 延期 |
| 独立外部security review、full accessibility/i18n/performance assurance | 延期 |

## N/A

`NET-03` のservice間mTLSは、現在のapplicationが単一processでservice間network boundaryを持たないためN/Aである。PostgreSQL/オブジェクトストレージへのremote接続はこのN/Aに含まれず、authenticated TLSとleast-privilege credentialが必要である。将来processを分割した場合はmTLS/service identity設計を再開する。

詳細な依存順と完了条件は `IMPLEMENTATION_TODO.md`、canonical trust boundaryは `docs/security/THREAT_MODEL.md`、監査履歴とDeep Scan修正結果は `SECURITY_AUDIT.md`、残存riskは `docs/RISK_REGISTER.md`、backup操作は `docs/BACKUP.md` を参照する。
