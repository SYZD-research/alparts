"""M7: forum posts, replies and moderation (2026-10-09).

Written from services/message.service.ts (createMessage / deleteMessage for
forum channels), services/forum.service.ts (lock, resolve) and the client's
post list (stores/forum.store.ts applyState -> forum-model.ts
placeForumPost, forum:post-removed). Every forum write runs in one audited
transaction and the audit gate admits one at a time, so each operation is an
atomic step; the server broadcasts the post's state (forum:post-updated) or
its removal (forum:post-removed) after commit, and a client applies them in
order.

Actors: A and B (members with the default Member role: VIEW, SEND,
CREATE_POSTS, EDIT, DELETE), M (MANAGE_CHANNELS). A writes up to two posts;
A and M write up to two replies, each optionally quoting a post; A, B and M
may try every deletion. (Posts by B and replies by B add only symmetric
states.)

  FI1  replyCount equals the number of the post's live replies
  FI2  no reply is added to a deleted post, nor by a non-manager to a locked one
  FI3  only the author edits; the author or a manager deletes
  FI4  a quote stays inside its post
  FV1  a client's post list never shows a post after it was deleted
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import NamedTuple

from common import record

ACTORS = ('A', 'B', 'M')
MANAGERS = frozenset({'M'})


class St(NamedTuple):
    posts: tuple          # per post: (author, locked, deleted, reply_count)
    replies: tuple        # (post, author, deleted, quoted)  quoted: None | ('root', post) | ('reply', index)
    listed: frozenset     # posts the viewer's client lists
    bad: frozenset        # ghost: properties broken by a step


@dataclass(frozen=True)
class V:
    live_check: bool = True          # CONTROL: False lets a reply into a deleted post
    lock_check: bool = True          # CONTROL: False lets a non-manager reply to a locked post
    delete_rights: bool = True       # CONTROL: False lets anyone delete a reply
    same_post_quote: bool = True     # CONTROL: False accepts a quote from another post
    deleted_post_state: bool = False  # CONTROL (before 2026-10-09): deleting a reply of a deleted post broadcast its state
    max_posts: int = 2
    max_replies: int = 2


def initial() -> St:
    return St((), (), frozenset(), frozenset())


def _post(s: St, p: int, **change) -> tuple:
    author, locked, deleted, count = s.posts[p]
    values = dict(author=author, locked=locked, deleted=deleted, count=count) | change
    return s.posts[:p] + ((values['author'], values['locked'], values['deleted'], values['count']),) + s.posts[p + 1:]


def successors(s: St, v: V):
    out = []
    if len(s.posts) < v.max_posts:
        for actor in ('A',):
            p = len(s.posts)
            out.append((f'{actor} creates post P{p}', s._replace(posts=s.posts + ((actor, False, False, 0),),
                                                                    listed=s.listed | {p})))
    for p, (author, locked, deleted, count) in enumerate(s.posts):
        if len(s.replies) < v.max_replies:
            quotes = [None, ('root', p)]
            if not v.same_post_quote:
                quotes += [('root', q) for q in range(len(s.posts)) if q != p]
            for actor in ('A', 'M'):
                if v.live_check and deleted:
                    continue
                if v.lock_check and locked and actor not in MANAGERS:
                    continue
                for quote in quotes:
                    in_post = quote is None or (quote[0] == 'root' and quote[1] == p) or (
                        quote[0] == 'reply' and s.replies[quote[1]][0] == p)
                    if v.same_post_quote and not in_post:
                        continue
                    if quote and quote[0] == 'root' and s.posts[quote[1]][2]:
                        continue       # a deleted message cannot be quoted
                    bad = set()
                    if deleted or (locked and actor not in MANAGERS):
                        bad.add('FI2')
                    if not in_post:
                        bad.add('FI4')
                    t = s._replace(posts=_post(s, p, count=count + 1), replies=s.replies + ((p, actor, False, quote),),
                                   bad=s.bad | bad)
                    # forum:post-updated: the viewer places the post in its list
                    t = t._replace(listed=t.listed | {p})
                    out.append((f'{actor} replies in P{p}' + (f' quoting {quote[0]} {quote[1]}' if quote else ''), t))
        for actor in ACTORS:
            # delete the post (root): author or manager
            if not deleted and (actor == author or actor in MANAGERS):
                t = s._replace(posts=_post(s, p, deleted=True), listed=s.listed - {p})   # forum:post-removed
                out.append((f'{actor} deletes post P{p}', t))
        if not deleted:
            t = s._replace(posts=_post(s, p, locked=not locked), listed=s.listed | {p})
            out.append((f'M {"unlocks" if locked else "locks"} P{p}', t))
    for i, (p, author, deleted, quote) in enumerate(s.replies):
        if deleted:
            continue
        for actor in ACTORS:
            allowed = actor == author or actor in MANAGERS
            if v.delete_rights and not allowed:
                continue
            post_author, locked, post_deleted, count = s.posts[p]
            replies = s.replies[:i] + ((p, author, True, quote),) + s.replies[i + 1:]
            t = s._replace(replies=replies, posts=_post(s, p, count=max(count - 1, 0)),
                           bad=s.bad | ({'FI3'} if not allowed else set()))
            if not post_deleted or v.deleted_post_state:
                t = t._replace(listed=t.listed | {p})          # forum:post-updated
            out.append((f'{actor} deletes reply R{i} of P{p}', t))
    return out


def violations(s: St):
    out = [(prop, f'{prop} broken by the last step') for prop in sorted(s.bad)]
    for p, (_, _, deleted, count) in enumerate(s.posts):
        live = sum(1 for r in s.replies if r[0] == p and not r[2])
        if count != live:
            out.append(('FI1', f'P{p} counts {count} replies, {live} are live'))
        if deleted and p in s.listed:
            out.append(('FV1', f'the viewer lists P{p} after it was deleted'))
    return out


def bfs(v: V):
    start = initial()
    parent = {start: None}
    found = {}
    queue = deque([start])
    while queue:
        s = queue.popleft()
        for prop, message in violations(s):
            found.setdefault(prop, (s, message))
        for label, nxt in successors(s, v):
            if nxt not in parent:
                parent[nxt] = (s, label)
                queue.append(nxt)
    return parent, found


def trace(parent, s):
    steps = []
    while parent[s] is not None:
        s, label = parent[s]
        steps.append(label)
    return list(reversed(steps))


def run() -> None:
    print('== M7: forum posts, replies and moderation ==')
    parent, found = bfs(V())
    print(f'  M7 implementation: {len(parent):,} states (two posts, two replies, A, B and a manager)')

    def holds(check_id, title, prop):
        hit = found.get(prop)
        record('M7', check_id, title, 'HOLDS', hit is not None,
               witness=(trace(parent, hit[0]) + ['=> ' + hit[1]]) if hit else [])

    holds('FI1', 'a post\'s reply count equals its live replies (deleting a reply of a deleted post included)', 'FI1')
    holds('FI2', 'no reply enters a deleted post, nor a locked post unless a manager writes it', 'FI2')
    holds('FI3', 'only the author or a manager deletes a reply', 'FI3')
    holds('FI4', 'a quote stays inside its post', 'FI4')
    holds('FV1', 'a client\'s post list never shows a post after it was deleted', 'FV1')
    for check_id, title, prop, variant in (
        ('FI2-ctl1', 'without the live-post check a reply enters a deleted post', 'FI2', V(live_check=False)),
        ('FI2-ctl2', 'without the lock check a member replies to a locked post', 'FI2', V(lock_check=False)),
        ('FI3-ctl', 'without the author-or-manager rule a member deletes another member\'s reply', 'FI3',
         V(delete_rights=False)),
        ('FI4-ctl', 'without the same-post rule a reply quotes another post', 'FI4', V(same_post_quote=False)),
        ('FV1-ctl', 'before the fix: deleting a reply of a deleted post broadcast its state and the post reappeared',
         'FV1', V(deleted_post_state=True)),
    ):
        p2, f2 = bfs(variant)
        hit = f2.get(prop)
        record('M7', check_id, title, 'CONTROL', hit is not None,
               witness=(trace(p2, hit[0]) + ['=> ' + hit[1]]) if hit else [])


if __name__ == '__main__':
    run()
