"""M3s: the fresh-start stall rule (c) over time (2026-10-26).

M3 folds the 15-minute wait of rule (c) into its fresh-start guard: a manager
may replace the group whenever an addition, a rejoin or a remove is pending.
That keeps every unsafe fresh start in, but cannot tell a fresh start that came
too early from one that came in time. This run adds the clocks, on top of M3's
own transitions (m3_key_epochs.transitions):

  tick        15 minutes pass (one step, whatever else waits).
  server      what mls-group-rules.ts pendingSince reads, at tick granularity:
              each package's age (packageAddableSince; a rejoin counts from
              its package, published with the request), each revocation's age
              (revokedAt, read first), each member's access_lost_at
              (key-epoch-state.ts refreshMemberAccessLoss, migration 0026: set
              when the member's user loses the channel, kept while the user
              stays without it, cleared when the user sees it again; a new
              group's members start without one), and the clamp:
              pendingSince = max(earliest, genesis) since fc9ec50.
  truth       independent of all that: which pending additions, rejoins and
              removes have been pending, without a break, for 15 minutes since
              the current group began (a member can act on a change only
              from the group's genesis on).

  KS-sound    a manager replaces the group by rule (c) alone only when some
              change has truly waited 15 minutes in the current group.
  KS-keep     an ordinary commit that leaves a change pending that had truly
              waited does not take rule (c) away.

Controls: clamping to the active version instead of the genesis (before
0b0fb41: any commit restarted the clock, GHSA-3qj2-5q79-8vj6), no clamp
(between 0b0fb41 and fc9ec50: a new group could be replaced again at once),
keeping a lost viewer's packages (before 0b0fb41 / 1f25f82), and one time for
the whole group (before migration 0026: mls_groups.remove_required_at, set
when a member's user first lost the channel and kept while any such member
remained, so a later loss counted from an earlier one that had been undone;
R-057).

Bounds: X (the manager) keeps the channel; Y and Z gain and lose it up to four
times; one device change; groups up to 4 versions; no unreadable envelope.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from typing import NamedTuple

from common import record
from m3_key_epochs import (NO_PKG, REVOKED, USER_DEVICES, USER_OF, State, Variant, bits, has_group, initial, label,
                           members, transitions, view)

STALL_REASON = 'manager, changes stalled'


class SState(NamedTuple):
    base: State
    pkg_old: int        # devices whose current package is 15 minutes old (or older)
    rev_old: int        # revoked devices revoked 15 minutes ago (or earlier)
    rr: int             # control: the group's remove_required_at, 0 null, 1 set, 2 set 15 minutes ago or more
    lost: int           # members whose access_lost_at is set
    lost_old: int       # members whose access_lost_at is 15 minutes old (or older)
    ref_old: bool       # the clamp's reference (genesis, or the active version) is 15 minutes old
    waited_add: int     # truth: pending additions and rejoins that waited 15 minutes in the current group
    waited_rem: int     # truth: pending removes that waited 15 minutes in the current group


@dataclass(frozen=True)
class StallRules:
    clamp: str = 'genesis'       # 'genesis' (fc9ec50), 'active' (before 0b0fb41), 'none' (0b0fb41..fc9ec50)
    purge_on_loss: bool = True
    loss_time: str = 'member'    # 'member' (access_lost_at, 0026), 'group' (remove_required_at before 0026)


def base_variant(rules: StallRules) -> Variant:
    return Variant(max_log=4, poison_budget=0, max_viewer_changes=4, max_device_changes=1, view_users=(1, 2),
                   purge_on_loss=rules.purge_on_loss)


def lost_members(s: State) -> int:
    lost = 0
    for u in range(len(USER_DEVICES)):
        if not s.viewers >> u & 1:
            lost |= USER_DEVICES[u]
    return members(s) & lost


def member_loss(nxt: State) -> int:
    """refreshMemberAccessLoss after a change of who sees the channel: members whose
    user sees it have no time, the others have one (new for the user who just
    lost it, kept otherwise; s_transitions tracks which times are old)."""
    return sum(1 << d for d in bits(members(nxt)) if not nxt.viewers >> USER_OF[d] & 1)


def stall_permitted(s: SState, rules: StallRules, v: Variant) -> bool:
    """freshStartPermitted (c): now - max(earliest pending, reference) >= 15 minutes."""
    if not has_group(s.base):
        return False
    w = view(s.base, v)
    old = bool(w.pending_add & s.pkg_old)
    for d in bits(w.required_remove):
        if s.base.status[d] == REVOKED:
            old |= bool(s.rev_old >> d & 1)
        else:
            old |= s.rr == 2 if rules.loss_time == 'group' else bool(s.lost_old >> d & 1)
    return old and (rules.clamp == 'none' or s.ref_old)


def truly_stalled(s: SState, v: Variant) -> bool:
    w = view(s.base, v)
    return bool(s.waited_add & w.pending_add or s.waited_rem & w.required_remove)


def s_initial(v: Variant) -> SState:
    return SState(initial(v), 0, 0, 0, 0, 0, False, 0, 0)


def s_transitions(s: SState, rules: StallRules, v: Variant):
    for action, nxt, _ in transitions(s.base, v):
        kind = action[0]
        if kind == 'create' and action[4].endswith(STALL_REASON) and '; ' not in action[4]:
            if not stall_permitted(s, rules, v):
                continue                    # only rule (c) applies, and the 15 minutes have not passed
        created, committed = kind == 'create', kind == 'commit'
        pkg_old = sum(1 << d for d in bits(s.pkg_old) if nxt.pkg[d] == s.base.pkg[d] != NO_PKG)
        rev_old = sum(1 << d for d in bits(s.rev_old) if nxt.status[d] == REVOKED)
        rr, lost, lost_old = 0, 0, 0
        if rules.loss_time == 'group':
            if created or committed:
                rr = 0                      # a new group, or an accepted commit, owes no remove
            elif kind == 'view':
                rr = (s.rr or 1) if lost_members(nxt) else 0
            else:
                rr = s.rr
        elif not created:                   # a new group's members start without a time
            lost = member_loss(nxt) if kind == 'view' else s.lost & members(nxt)
            fresh = USER_DEVICES[action[1]] if kind == 'view' else 0
            lost_old = s.lost_old & lost & ~fresh
        ref_old = s.ref_old and not created and not (committed and rules.clamp == 'active')
        w = view(nxt, v)
        waited_add = 0 if created else s.waited_add & w.pending_add
        waited_rem = 0 if created else s.waited_rem & w.required_remove
        yield action, SState(nxt, pkg_old, rev_old, rr, lost, lost_old, ref_old, waited_add, waited_rem)
    w = view(s.base, v)
    group = has_group(s.base)
    packaged = sum(1 << d for d in range(len(s.base.pkg)) if s.base.pkg[d] != NO_PKG)
    revoked = sum(1 << d for d in range(len(s.base.status)) if s.base.status[d] == REVOKED)
    ticked = SState(s.base, packaged, revoked, 2 if s.rr else 0, s.lost, s.lost, group,
                    s.waited_add | (w.pending_add if group else 0), s.waited_rem | (w.required_remove if group else 0))
    if ticked != s:
        yield ('tick',), ticked


def s_label(s: SState, v: Variant, action) -> str:
    return 'clock: 15 minutes pass' if action[0] == 'tick' else label(s.base, v, action)


def explore(rules: StallRules, stop: frozenset = frozenset()):
    v = base_variant(rules)
    start = s_initial(v)
    parent = {start: None}
    found = {}
    queue = deque([start])
    transitions_seen = 0
    while queue and not (stop and stop <= found.keys()):
        s = queue.popleft()
        permitted = stall_permitted(s, rules, v)
        stalled = truly_stalled(s, v)
        for action, nxt in s_transitions(s, rules, v):
            transitions_seen += 1
            if action[0] == 'create' and action[4].endswith(STALL_REASON) and '; ' not in action[4] and not stalled:
                found.setdefault('KS-sound', (s, action, 'a manager replaced the group by rule (c) although no '
                                                         'change had waited 15 minutes in the current group'))
            if action[0] == 'commit' and permitted and truly_stalled(nxt, v) and not stall_permitted(nxt, rules, v):
                found.setdefault('KS-keep', (s, action, 'an ordinary commit left a change pending that had waited '
                                                        '15 minutes, and rule (c) no longer allows a fresh start'))
            if nxt not in parent:
                parent[nxt] = (s, action)
                queue.append(nxt)
    return parent, found, transitions_seen, v


def trace(parent, s, v):
    steps = []
    while parent[s] is not None:
        s, action = parent[s]
        steps.append(s_label(s, v, action))
    return list(reversed(steps))


def run() -> None:
    print('== M3s: the fresh-start stall rule over time (exhaustive) ==')
    t0 = time.time()
    parent, found, count, v = explore(StallRules())
    stalled = sum(1 for s in parent if stall_permitted(s, StallRules(), v))
    print(f'     implementation: {len(parent):,} states, {count:,} transitions, rule (c) open in {stalled:,}, '
          f'{time.time() - t0:.0f}s')

    def report(check_id, title, expect, prop, result):
        parent, found, _, v = result
        hit = found.get(prop)
        record('M3s', check_id, title, expect, hit is not None,
               witness=(trace(parent, hit[0], v) + [s_label(hit[0], v, hit[1]), '=> ' + hit[2]]) if hit else [])

    result = (parent, found, count, v)
    report('KS-sound', 'a manager replaces the group by rule (c) only when an addition, rejoin or remove has waited '
                       '15 minutes in the current group', 'HOLDS', 'KS-sound', result)
    report('KS-keep', 'an ordinary commit that leaves such a change pending does not restart the manager\'s wait',
           'HOLDS', 'KS-keep', result)
    for check_id, title, prop, rules in (
        ('KS-keep-ctl', 'before 0b0fb41: counting from the active version, any commit restarted the wait '
                        '(GHSA-3qj2-5q79-8vj6)', 'KS-keep', StallRules(clamp='active')),
        ('KS-sound-ctl', 'between 0b0fb41 and fc9ec50: without the genesis clamp a new group could be replaced at once',
         'KS-sound', StallRules(clamp='none')),
        ('KS-purge-ctl', 'before 0b0fb41: a package kept while its user could not see the channel counted as '
                         'waiting from before access returned', 'KS-sound', StallRules(purge_on_loss=False)),
        ('KS-loss-ctl', 'before migration 0026: one time for the whole group counted a later loss of access from '
                        'an earlier one that had been undone (R-057)', 'KS-sound', StallRules(loss_time='group')),
    ):
        report(check_id, title, 'CONTROL', prop, explore(rules, stop=frozenset({prop})))


if __name__ == '__main__':
    run()
