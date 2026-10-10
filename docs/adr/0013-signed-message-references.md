# ADR 0013: Message references name the signed event (message protocol v5)

- **Status:** Implemented; independent security acceptance pending
- **Date:** 2026-10-09
- **Context source:** formal model M9 ([re-verification record](../../formal-model/REVERIFICATION.ja.md)), [RISK_REGISTER](../RISK_REGISTER.md) R-051

## Context

Edits, deletions and quotes name their target by its server-assigned message id, and forum replies, edits and deletions name their post the same way (protocol v3, forum v4). A message signs its own fields but not its id, which the server assigns after signing. A server that serves two messages of the same author under each other's ids could therefore show an edit on the other message, apply a deletion to it, show a quote quoting it, or list a reply under the other post, without forging a signature. The client projector and the forum view resolved references by id only.

## Decision

Clients sign message protocol v5 for every event that references another message: edits, deletions and quotes, and in a forum every reply, edit and deletion. It is the only layout accepted for such an event. An event without references (a message, or the first message of a post) keeps the v3/v4 layout, which signs the same fields.

- **What is signed.** Besides the v3/v4 fields, the envelope signs `refBinding`: the author and the signed idempotency key of the message `refMessageId` names (null when there is none), and in a forum `postBinding`: the same pair for the post's first message. The layout says `text` or `forum` and is never shared with v3/v4, so a signature cannot be presented in another layout. Within a channel the server keeps one event per author and idempotency key and cannot sign for an author, so it cannot give the pair to another event.
- **Server.** The pair is not stored. The server derives it from the referenced row when it checks a write and when it serves an event (`hydrateMessageEvents`, `insertCryptoEvent`), so no migration is needed. A write that references another message is accepted only when its signature verifies in v5 with the derived pair. A referenced message stored without a signed idempotency key cannot be named, so a reference to it is refused. A write without references verifies in either layout.
- **Client.** The client verifies an event that references another message only in v5, with the served pair (`message-envelope.ts`); other events verify in either layout. An edit or a deletion that does not verify is dropped, and a quote or a reply that does not verify is shown as a message that could not be verified. A process-local marker records that v5 verified. The projector applies an edit or a deletion only to the message with the signed pair. `quotedMessage` returns null when the message under the quoted id is not the one signed for, and the message then shows that the original cannot be shown. `belongsToPost` lists a reply only under the post it was signed for. The pair a client signs is that of the loaded message under the id, verified or not: it only narrows where the event applies, so a message that could not be verified can still be deleted or quoted. A message stored without a signed idempotency key cannot be named; the client says that it cannot be edited, deleted, quoted or replied to. Queued messages store the pair when they are queued.
- **Files.** A file's signature binds its message's signed idempotency key (attachment layout v3). The unbound v2 layout, which named the message by server id only, is refused by the server and by the client.

## Consequences

For v5 histories the server can no longer move an edit, a deletion, a quote or a reply (M9 MI-edit, MI-delete, MI-quote, MI-reply hold over every bounded history), and served honestly every reference still shows where it was signed for (MI-honest).

The older layouts no longer count for references, so the server cannot move those either. It refuses them for new writes, and the client neither applies them nor shows them as verified: MI-edit-legacy, MI-reply-legacy, MI-quote-legacy and MI-delete-legacy hold over the same histories in the older layout. MI-legacy-ctl shows what the client accepted before. Files are refused the same way (MI-file-v2, MI-file-v2-ctl).

This was decided before the first release, so no installed client depends on the older layouts. A client from before v5 can no longer edit, delete, quote or reply, and does not apply such events from current clients. Messages stored without a signed idempotency key cannot be referenced; the API has required the key for every new message.
