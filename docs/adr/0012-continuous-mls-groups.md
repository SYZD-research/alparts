# ADR 0012: One continuing MLS group per channel (group protocol 4)

- **Status:** Implemented; independent security acceptance pending
- **Date:** 2026-10-07
- **Supersedes:** the group-protocol part of [ADR 0011](./0011-account-group-security.md): fresh RFC 9420 groups per application epoch and the preserved exact-delivery/all-recipient activation barrier. Device approval, directory transparency, passkeys and user-controlled recovery from ADR 0011 stay in force.

## Context

Group protocol 3 built a new MLS group for every key version and kept the protocol-2 barrier: a version became active only after every required recipient device had signed an acknowledgement of its exact delivery. One offline or abandoned device could therefore stop all writes in a conversation until it came online or was revoked, and every membership change and the daily refresh needed fresh packages from every participant. Keeping the barrier was the defence against split epochs and poisoned deliveries.

## Decision

Keep one continuing RFC 9420 group per channel, through pinned `ts-mls` and the fixed suite. Devices are added, removed and refreshed with commits.

- **Ordering, not acknowledgement.** The server accepts exactly one commit per key version (compare-and-swap on the version and the previous transcript) under the existing key-protocol, workspace and channel locks, so commits are ordered against authorization changes. An accepted commit is active immediately. There is no pending state, acknowledgement or abort. A retry with the same bytes gets the same answer.
- **What the server checks.** The committer device and its P-256 envelope signature; that the committer is a usable member and its leaf sent the commit; that the proposals match the signed lists of added and removed devices; the roster arithmetic; the Welcome's recipients; the UpdatePath leaf credential; current directory heads; and that every added package equals its published, signed, canonical, single-use package. It cannot check secrets.
- **Writes.** Messages use exactly the active version and must come from a current member. Writes stop only while the group still contains a device that is no longer eligible (revoked, unapproved, or its user lost access), or when no group refresh (genesis, a commit with a Remove, or an empty commit) has been accepted for 24 hours. Any one online usable member lifts the block. Offline devices and devices waiting to be added never block writes.
- **Faults the server cannot see.** A device that cannot process a correctly signed, chain-consistent commit or Welcome, or that lost its state, asks to be added again (rejoin); the next commit removes and re-adds it. Where nobody can do that, a step-up fresh start replaces the group, allowed only when no usable member exists or none has been online for 72 hours, when the caller's own rejoin request has waited 30 minutes, or for a manager (DM participant) when membership changes have stalled for 15 minutes.
- **Equivocation and downgrade.** Clients pin the last verified version and transcript. Contradicting signed history stops work and keeps local state. Once a device verified a protocol-4 group for a channel, it accepts keys for those versions only from that group or from recovered keys with the verified commitment.
- **Migration.** Migration `0023_continuous_mls_groups.sql` adds the group tables, aborts pending protocol-2/3 epochs and marks channels with an active epoch so that their next write needs a group. A migrated channel's first group waits up to 24 hours for the still-eligible recipients of its last key. The per-epoch write routes answer `410 UPDATE_REQUIRED`. Protocol 1–3 history stays readable.

## Consequences

Offline participants no longer block writes. A new device reads from the version that added it; earlier messages are available to it only through the account's recovery archive, and messages written before it was added stay unreadable otherwise.

Post-compromise security is narrower than in protocol 3. A commit with an UpdatePath refreshes only the committer's own leaf; writers refresh theirs at least every seven days, while members that never make such a commit are healed only when they are removed. An eligible malicious member can deny service inside a group (insider denial of service); recovery is rejoin, fresh start and administrators removing the member, and audit names the committer of every version. Archive retention still rules out per-message forward secrecy. The commit log is kept without compaction. External commits and joins, interoperability with other MLS implementations and an independent witness are not provided.

The [protocol and migration document](../security/ACCOUNT_AND_GROUP_SECURITY.md) defines bounds, failure behavior, configuration and verification. Independent cryptographic review remains a release gate.
