# Phase 1 Prototype threat model (legacy location)

最終更新: 2026-09-04

Canonical/current threat model: [`docs/security/THREAT_MODEL.md`](../security/THREAT_MODEL.md). The material below remains as the detailed Phase 1 protocol baseline; where it conflicts, the canonical model, current code/tests, and risk register take precedence.

対象はWindows・macOS・Linux desktop / Web / single-node / basic per-channel key / text中心＋最大8人P2P音声のprototypeである。`SPECIFICATION.md` の正式運用版に対するthreat modelまたはsecurity approvalではない。

## Assets

- message・draft・outbox・attachmentのplaintext
- 通話音声、microphone device、WebRTC DTLS key、SDP/ICEとnetwork address metadata
- device private key、channel key、attachment file key、local-state key
- password、session cookie、invitation token、device enrollment data
- workspace/private-channel membership、device directory、presence、routing metadata
- PostgreSQL row、オブジェクトストレージのobject、audit chain、audit integrity key、external checkpoint
- encrypted backup artifact、age identity、deployment credential、configuration
- source、dependency、build/release artifact

## Adversaries

- 未認証Internet client、別workspaceの認証user
- malicious/removed workspace member、盗まれたsessionを持つ攻撃者
- compromised browser profile、改ざんされたdesktop配布物、またはclient JavaScriptを実行できる攻撃者
- PostgreSQL、オブジェクトストレージ、backup storage、application hostのoperatorまたは侵害者
- malicious dependency/build/release actor
- malicious call participant、STUN/TURNまたはsignaling operator
- 誤設定や誤操作を行う正規operator

## Trust boundaries

1. **Browser origin:** plaintextとclient keyはbrowser processに存在する。Non-extractable `CryptoKey`はexportを防ぐが、同一originで実行されるcodeからの利用を防がない。CSPとthird-party script排除はriskを下げるが、origin compromiseを閉じない。
1a. **Desktop host:** rendererは署名対象の同梱UIだけを読み込み、sandbox/context isolation下で狭いIPCを使う。Private materialはOS保護領域でwrapするが、実行中rendererまたは改ざん済み配布物は正規操作としてkeyを利用できる。IPC、package署名、OS account、endpoint integrityは独立した境界である。
2. **Browser ↔ ingress:** TLSはreverse proxy/deployment edgeの責任である。TLSの内側でも、すべてのREST/WebSocket actionにlive sessionとresource authorizationが必要である。
3. **Application process:** serverはrouting、membership、device、object metadataを扱い、availabilityとkey directory提示を制御する。Message plaintextを保持しないことはmetadata confidentiality、availability、rollback resistanceを意味しない。
4. **PostgreSQL / オブジェクトストレージ:** message confidentialityについてuntrusted storeとして扱う。Remote接続はauthenticated TLSとleast-privilege credentialを必要とする。Attachmentはclient crypto unit vectorと隔離PostgreSQL/オブジェクトストレージのprotocol-level resume/download SHAを組み合わせて検証するが、store自体はupload byteが正しいplaintextから生成されたことを証明できない。
5. **Workspace / channel:** workspace membershipがpublic channelの最低境界で、private channelはexplicit membershipを追加要求する。Role/overrideと暗号group membershipの不一致時は安全側へ停止しなければならない。
6. **Device enrollment / key distribution:** sessionはactive deviceへbindingする。新しいidentityの登録はsession-bound challengeへのdevice署名とcurrent passwordを要求し、既存identityへのbindingはそのdevice署名を要求する。新端末登録時の旧pending epoch整理（group protocol 4以降はpending epochを作らない）は最大50 workspaceを安定順にlockし、各最大300 channel内でset-based reconciliationする。Channelごとに継続するMLS groupへAddできるのは、channelを閲覧できるuserの承認済み・未失効deviceのpackageだけで、Addするcommitを作れるのはgroupのmember deviceだけである（serverは単独でmemberを追加できない）。Directoryは追記型chainとclient checkpointで検証するが独立witnessはないため、server提示directoryを第三者が独立検証することはできない。
7. **Audit checkpoint:** PostgreSQL chainとcheckpointが別のfailure/authority domainにある場合だけ末尾切断への独立証拠になる。同一operatorが両方をwrite/deleteできる配置は独立境界ではない。
8. **Backup / restore:** published artifactはage recipientへ暗号化されるが、audit key、deployment credential、browser device keyは別資産である。PostgreSQL credentialはprivate libpq service file、オブジェクトストレージのcredentialはstaging配下のmode `0600`一時configに留める。Restoreは明示した空の使い捨てDB/bucketだけを対象にする。Recipient encryptionは作成者のauthenticityを証明しない。
9. **WebRTC peer / ICE:** 音声本文はparticipant browser間のDTLS-SRTPでpairwiseに暗号化する。Application serverは署名付きSDP/ICEだけを中継し、設定されたSTUN/TURNはnetwork traversalまたは暗号化packet relayを行う。正規peerは受信音声と相手のICE由来network metadataを観測でき、compromised endpointは当然plaintextへ到達する。

## 実装・検証済みの不変条件

- Protected REST routeはDB-backed live sessionを確認し、workspace/channel/message/file操作はresource membershipとpermissionを再評価する。
- WebSocket handshakeはtokenのDB照会前にsource別・global pending leaseとserial-attempt budgetを取得する。Room joinとsensitive eventはlive session/device bindingとchannel authorizationを確認する。Rate budgetは同一userのsocket間で共有し、socket数を単一process内で制限する。Client/server起点のroom grantはworkspace authorization lock中に再確認・joinし、遅延grantが失効後にroom accessを復活させない。
- Access喪失・channel削除は、削除前に閲覧できたuserのidentity roomへ直接通知してからchannel roomを離脱させる。公式clientは該当scopeの復号memory、暗号化draft/outbox、添付task、active-device channel keyをbest-effortで局所消去する。
- Official clientはchannel keyがない状態でplaintext messageへfallbackしない。
- Message/attachment ciphertextはAES-256-GCMのcontextual AADを使う。Message protocol v3のP-256 device signatureは認証author ID、mutation target、broadcast-mention flagを含むrouting/crypto metadataをcoverし、server/clientはdeviceとauthor userのbindingを照合する。現在のclientが署名するprotocol v5は、編集・削除・引用するmessageとforum投稿の最初のmessageを、server IDに加えてその作者と作者が署名したidempotency keyでも指す。Serverはこの組を各eventと一緒に配信し、clientは署名した対象のmessageにだけ編集・削除を適用し、引用・返信を表示する。旧client（v3/v4）のeventと、idempotency key署名以前のmessageへの参照はserver IDだけで対象を指し、引き続き受理する（形式モデルM9、RISK_REGISTER R-051）。Attachment signature v3は所属messageの署名済みidempotency keyも含み、clientは検証済みmessageの同じkeyに対してのみfileを開く（旧v2 signatureはserver割当のmessage IDへの束縛として引き続き受理）。同じchannel・author・署名済みidempotency keyを持つ2件目の検証済みeventはreplayとして隔離する。
- Group protocol 4では、serverはchannelごとにMLS groupのcommitを順序付ける。1 versionに1 commitだけを、直前versionとそのtranscriptのcompare-and-swapで、key protocol・workspace・channelのlock下に受理し、受理したcommitは同じtransactionで`active`になる（pending、受領確認、abortはない）。Commit envelopeはcommitter deviceのP-256署名でversion、直前transcript、group ID、epoch、commit、Welcome、追加package、削除device、roster、directory head、SHA-256 key commitmentを束縛する。Serverはenvelope署名、roster計算、Add/Removeとpackageの一致、Welcomeの宛先、UpdatePathのleaf credentialを検証するが、path secretやexporter秘密は検証できない。Protocol 2/3の`pending/active/retired/aborted`状態と署名付きdeliveryは履歴として残る。
- Serverはactiveなcurrent versionで、送信deviceがgroupのcurrent memberである場合だけmessage writeを受理し、古いversionは`KEY_VERSION_STALE`で拒否する。Groupに資格を失ったdevice（失効、未承認、channel閲覧権の喪失）が残る間と、group更新が24時間受理されていない間は新規message writeを停止し（添付の確定には24時間の条件を適用しない）、Remove/更新commitの受理で再開する。Offline deviceと追加待ちのdeviceはwriteを止めない。Versionは再利用しない。Device/member/channel/category数とgroup size（最大400 device）をsmall-team上限内へ固定する。
- 利用可能なmemberがいない、または規定時間進まないchannelは旧ciphertextを復旧可能と表示せず、`historyRecoveryRequired`を返す。Step-upと端末署名を伴うfresh startは将来write用の新しいgroupだけを始められる。公式clientのcurrent key照会、最大64 versionの履歴batch、最大64 deviceの署名鍵照会と、deprecation付き16-version/400-device rollout bridgeはすべて有限である。
- Event projectorはimmutable event IDをdeduplicateし、`(createdAt, id)`で決定的に並べる。Base plaintextとedit/deleteは端末側の署名・AEAD検証完了前に投影しない。検証済みprovenanceはnetwork fieldではなくprocess-local markerで、REST mutation responseもlocal signed envelopeと完全一致した場合だけ取り込む。同じIDの非同一署名envelopeはsticky conflictへquarantineし、reaction/pinはbounded current-state snapshotとして扱う。
- Session tokenはHttpOnly/SameSite cookieで配送し、server DBにはSHA-256 hashだけを保存する。Logout/device/session revokeはlive checkへ反映する。
- Invitationはrandom tokenのhashだけを保存し、一回限り・期限付き・個別失効・任意email bindingを強制する。
- Draft/outboxはuser/device/purpose/scopeをAADへ含め、same-origin IndexedDBに保存したnon-extractable AES-GCM `CryptoKey`で暗号化する。非同期outbox処理は開始時のprincipal/device/generationへ固定し、reset後の保存・送信・削除callbackを受理しない。Logout/user切替時は復号済みmemoryとkey cacheをclearする。
- Audit appendはPostgreSQL advisory lockで直列化し、message create/edit/delete/replay、reaction/pin、preference/bookmarkを含むsecurity-sensitive state mutationと同じtransactionへ入れる。Read positionとprovisional upload chunk registration/cleanupは個別eventを生成しないが同じauthoritative-write admissionを通す。起動時にchainとconfigured checkpointを検証し、audit閲覧も監査する。Required checkpointの初期化は明示operator commandだけが行う。通常appendとcheckpoint更新は同じlock内で現在anchorのHMACとDB tailへのdescendant関係を検証し、欠落・rollback・tail切断はsticky failureとしてreadiness/以後のauthoritative writeをfail closedにして通常処理から再作成・再署名しない。Presence/device activity timestampは認可等に使わないadvisory stateとしてこのgate外に置く。
- Backup scriptはquiesce assertion、private libpq service、tool/server major一致、private staging、checksum/manifest、age recipient encryption、既存artifact非上書きを強制する。Restore scriptはextract前のentry/logical-byte/sparse/path/type上限と、target名・空DB・空bucket・非特権ownerを検査し、drop/clean/migrationを実行しない。
- Runtimeはbundled migration timestamp/hash列と、最大4,096 descriptorのPostgreSQL 16 `public` catalog fingerprintをrepeatable-read snapshotで照合する。Persistentなcovered schema driftはstartup/readinessをfail closedにするが、row data、role/grant、physical durability、probe間だけのDBA変更は別controlである。
- JSON/attachment bodyはparser前にContent-Length、aggregate bytes、concurrent request、source/user budgetを確認する。Object storage transportはactive/pending workを制限し、response header待ちとstream inactivityを設定上限内でtimeoutする。Download leaseとobject-storage leaseはresponse stream終端まで保持する。Remote object I/OをDB transaction中に実行せず、resume/finalizeでは短いauthorization/quota transaction間でobjectを照合してcommit直前に再確認する。同一uploadのmutationは単一process内で直列化する。
- Workspace membershipの追加は一回限りinvitation consent経路だけに限定し、member removalは専用`KICK_MEMBERS`とrole hierarchyをworkspace lock取得後に再確認する。DMは2人以上のdistinct participantを要求し、generic channel mutation/permission overrideから隔離する。
- Category/channel permission overrideはallow/deny継承、private membership、owner保護、両revision、適用前preview、room退出、rekeyをfresh integration matrixで検証する。
- Attachmentはfile別key、暗号化filename、固定chunk AEAD、resume/retry/finalize、opaque download decrypt、危険形式警告を実装し、複数chunkの中断再開からdownload SHA一致までを検証する。Desktopはopaque native handleへchunk保存し、形式にかかわらずすべての保存fileへOS隔離属性（WindowsのZone情報、macOSのquarantine）を付け、Linuxでは非実行権限で保存する。危険形式はUIで追加の確認を求める。
- Voice signalingはlive session、active device、channel authorization、channel room、最大8 participant registryへbindingし、参加ごとにfresh participant IDを発行する。SDP/ICE envelopeはchannel・sender/target participant・sender device・単調sequenceを含めてP-256署名し、受信clientがdevice directory binding、exact shape、signature、sender別sequenceを検証する。失権またはroom退出はregistryとofficial clientのlocal media/peer connectionを終了させる。Media本文はP2P DTLS-SRTPに留まり、serverはrelay対象を変更できても署名済みDTLS fingerprintを無検出で書き換えられない。

## Residual risks / formal blockers

- Channelごとに継続するMLS groupを使うが、履歴用の鍵を保持するためmessage単位のforward secrecyは提供しない。侵害後の回復はUpdatePath付きcommitをしたdevice自身のleafに限られ、そうしたcommitをしないdeviceは削除されるまで回復しない。資格のある悪意あるmemberはgroup内でサービス妨害（rejoinの強制）ができる。
- 新しく追加されたdeviceは追加されたversionから読む。それより前の履歴は同じaccountの暗号化履歴archiveから復元できる範囲に限り、全member deviceと復旧コードを失った場合の旧ciphertextは復旧不能である。1 workspaceは50 member、1 userは8 active device、1 groupは最大400 member deviceである。Small-team境界を超えるcapacityと履歴復旧は未保証である。
- Append-only key transparency、consistency proof、independent witness、existing-device approvalがなく、malicious serverのsplit viewを形式的に検出できない。
- WebAuthn/Passkey、OIDC、一般の管理操作step-up、二者approval、閾値recoveryがない。新device identityの登録だけはcurrent-password step-upを実装しているが、password/session compromiseは主要riskとして残る。
- Web版のsame-origin IndexedDB keyはOS secure storageではない。Desktop版はOS保護領域を利用するが、実行中client、browser extension、改ざん済みpackage、OS account、endpoint compromiseはplaintext/key利用へ到達しうる。
- Loaded-message search以外のencrypted persistent index、cross-device sync、full offline cacheがない。
- Server/operatorはmembership、device routing、message/attachment IDと時刻、ciphertext size、attachment MIME type・chunk count・transfer timing、opaque storage keyなどのmetadataを観測する。完全なmetadata inventory/public disclosureはない。
- Presence/typing/readをuserまたはworkspace単位で無効化する設定、notificationのcategory継承、Push/background deliveryはない。
- File System Access API非対応browserのdownloadは100 MiB以下のBlob fallbackに限られる。Desktopは隔離属性相当を付けるが、安全な検体viewer、archive/image parser防御はない。
- Workspace管理は作成・一覧・member removalまでで、rename/delete/owner transferや組織policy管理はない。
- Audit checkpointのoperator independenceは別権限mountの場合だけ成立し、external SIEM/WORM/retention alertはない。
- Backup roundtripはDB rowと最新ciphertext objectの再現だけを検証する。PITR、WORM、off-site、scheduled restore、RTO/RPO、full application DRはない。
- Single-node/single-DBで、HA、broker、failover、rolling upgrade、cluster migrationはない。
- 音声はP2P DTLS-SRTPか、operatorが有効にした場合のSFU（各frameを送信端末でSFrame暗号化し、参加・退出ごとに通話keyを替える。ADR 0014）だけで、映像、画面共有、録音表示はない。Device directory transparencyがないため、malicious serverによるidentity split viewを通話でも形式的に閉じていない（SFU通話ではserverが偽のdeviceや自分のdeviceを参加者として加えればframe keyを受け取れる。加えたdeviceは参加者として表示される）。SFU通話のframe keyは対称keyで、serverの協力があれば参加者は他の参加者の音声を装える。P2P peer/IP metadata露出、SFU通話でserverが見る参加者と発言の時刻、TURN credential配布、NAT到達性、mesh scalabilityも残存riskである。
- Retention/export、Restricted profile、signed update/SLSA、mobile、Bot/Webhook、独立外部security reviewはない。
- Project codeはAGPL-3.0-onlyで公開している。配布物へのthird-party noticeの同梱は未完了である。
- Authorized recipientによるcopy/screenshot、受信済みdataの完全消去、serverに対する完全metadata秘匿は提供しない。

これらは `SPECIFICATION.md` が想定する高保証production useのrelease blockerである。詳細なstatusとacceptance conditionは `IMPLEMENTATION_TODO.md`、運用制限は `LIMITATIONS.md` を参照する。
