# ADR 0013: Message references name the signed event (message protocol v5)

- **Status:** Implemented; independent security acceptance pending
- **Date:** 2026-10-09
- **Context source:** formal model M9 ([re-verification record](../../formal-model/REVERIFICATION.ja.md)), [RISK_REGISTER](../RISK_REGISTER.md) R-051

## Context

Edits, deletions and quotes name their target by its server-assigned message id, and forum replies, edits and deletions name their post the same way (protocol v3, forum v4). A message signs its own fields but not its id, which the server assigns after signing. A server that serves two messages of the same author under each other's ids could therefore show an edit on the other message, apply a deletion to it, show a quote quoting it, or list a reply under the other post, without forging a signature. The client projector and the forum view resolved references by id only.

## Decision

Current clients sign message protocol v5 for every event that references another message: edits, deletions and quotes, and in a forum every reply, edit and deletion. An event without references (a message, or the first message of a post) keeps the v3/v4 layout, which signs the same fields, so clients that have not been updated still verify it.

- **What is signed.** Besides the v3/v4 fields, the envelope signs `refBinding`: the author and the signed idempotency key of the message `refMessageId` names (null when there is none), and in a forum `postBinding`: the same pair for the post's first message. The layout says `text` or `forum` and is never shared with v3/v4, so a signature cannot be presented in another layout. Within a channel the server keeps one event per author and idempotency key and cannot sign for an author, so it cannot give the pair to another event.
- **Server.** The pair is not stored. The server derives it from the referenced row when it checks a write and when it serves an event (`hydrateMessageEvents`, `insertCryptoEvent`), so no migration is needed. A write is accepted when its signature verifies in v5 with the derived pair, or in the older layout.
- **Client.** The client verifies an event in v5 with the served pair and in the older layout (the layouts never share bytes, so the order only saves work), and records in a process-local marker whether v5 verified. For a v5 event the projector applies an edit or a deletion only to the message with the signed pair; `quotedMessage` returns null when the message under the quoted id is not the one signed for, and the message shows that the original cannot be shown; `belongsToPost` lists a reply only under the post it was signed for. Older events keep naming their target by id. The pair a client signs is that of the loaded message under the id, verified or not: it only narrows where the event applies, so a message that could not be verified can still be deleted or quoted. A message sent before idempotency keys were signed has no pair, and references to it use the older layout. Queued messages store the pair when they are queued.

## Consequences

For v5 histories the server can no longer move an edit, a deletion, a quote or a reply (M9 MI-edit, MI-delete, MI-quote, MI-reply hold over every bounded history), and served honestly every reference still shows where it was signed for (MI-honest).

Events signed by older clients, and references to messages from before signed idempotency keys, still name their target by id only and remain movable; this is a documented limit (MI-*-legacy). Clients that have not been updated still verify messages without references, but not v5 events: they do not apply edits and deletions made with updated clients, and show their quotes and forum replies as messages that could not be verified. The desktop and Android clients bundle the Web client, so they need their own update. The server still accepts the older layout for new writes; refusing new v3/v4 references whose target can be named would narrow the limit to events written before the update, at the cost of refusing edits, deletions, quotes and forum replies from clients that have not been updated.
