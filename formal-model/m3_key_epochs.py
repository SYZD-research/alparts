"""M3: continuous per-channel MLS groups (group protocol 4) — exhaustive exploration.

Mirrors the v4 rules of services/mls-group-rules.ts (deriveMembership,
freshStartPermitted, planCommitAdmission), mls-group.service.ts
(publishMemberPackage, admitGroupCommit, listGroupCommits), mls-group-gate.ts
(authorizeGroupWrite) and the client's syncLocked / catchUp / joinAt /
requestRejoin / commitLocked / createLocked / runMaintenance
(packages/client/src/services/mls-group.service.ts):

  publish     an eligible device that is not a member publishes a package;
              background maintenance does so without syncing first (a
              migrated channel then starts its 24-hour genesis wait). A member
              publishes only to ask to be added again (rejoin), after it
              dropped its group state.
  genesis     no continuous group yet: an eligible device with a package
              creates it with its own package and any packaged eligible
              devices. Still-eligible recipients of the pre-v4 epoch must be
              included while they have a package, or until the wait expires.
  commit      a usable member (eligible, no open rejoin request) whose local
              state is at the current version commits. The server orders
              commits: version = latest + 1 and previous = active (CAS). The
              commit must remove every member that is no longer eligible,
              may add any subset of pending packages (a rejoin requester is
              removed and re-added), and is empty only when the group key is
              24 h old. Removes and empty commits refresh the group key;
              add-only ones do not. Accepted means active at once.
  fresh start a new group (step-up) by an eligible device that is not a
              usable member and holds no group state: (a) no usable member
              is online, (b) its own rejoin request waits, or (c) a manager
              while additions, removes or rejoins are pending. Every member
              of the old group leaves it at that version.
  sync        a device that may read the channel processes every version of
              the ordered log it may read (it was a member at that version,
              or the version removed it). Removed: it keeps its keys and drops
              the group; re-added by the same envelope, or a member without
              group state: it joins from the Welcome of the version that added
              it (its current membership only).
  unreadable  a commit or Welcome that every other device fails to process
              (a buggy or malicious insider; budget 1). The failing device
              keeps its keys and drops its group; it asks to be added again
              unless the envelope belongs to a membership before its current
              one (then it joins its current membership).
  write gate  the active version is a continuous group, the key version is
              the active one, the writer is a current member, every member is
              eligible (M ⊆ E) and the group key is less than 24 h old.
  viewer +/-, device approve/revoke, clocks (24 h key age, 24 h genesis wait),
  Y1 going offline for good, restore (a device learns every key its user's
  devices derived or restored: history backup).

Waiting 15 minutes (manager fresh start), 30 minutes (own rejoin) and 72 hours
(nobody usable seen) is folded into the guarded fresh-start transition; the
72-hour case is reached only by a device that never acts again. These are
reachability abstractions, not response-time guarantees. Package lifetimes,
rate and rejoin limits, the 7-day leaf refresh, attachments, lost responses
(the pending record adopts the own envelope at the next sync) and the
client's equivocation checks against a lying server are not modelled.

Messages are not state: KC and KC-dev are checked in every state where some
device can write, against every device that can derive the active key (its
members, now or by catching up later), holds it, or can obtain it from its
user's backups. This covers every later reader of a message written then.

eligible = approved, non-revoked devices of current viewers.
Knowledge is permanent: a device keeps every key it ever derived or restored.
The initial state is a migrated channel: a pre-v4 epoch v1 held by X1 and Y1;
X and Y see the channel, Z does not; X2 exists only in the second-device run.
"""
from __future__ import annotations

import time
from array import array
from collections import Counter, deque
from dataclasses import dataclass
from typing import NamedTuple

from common import record

DEVICES = ('X1', 'X2', 'Y1', 'Z1')
USER_OF = (0, 0, 1, 2)
USERS = ('X', 'Y', 'Z')
MANAGER_USERS = 0b001                  # X holds MANAGE_CHANNELS
N = len(DEVICES)
LOST = 2                               # Y1 in the lost-device variant
ABSENT, UNAPPROVED, APPROVED, REVOKED = 0, 1, 2, 3
LEGACY, CREATE, COMMIT = 0, 1, 2
NO_PKG, PKG, REJOIN_PKG = 0, 1, 2
BROKEN, NO_STATE = -1, 0
DEVICE_BITS = tuple(1 << d for d in range(N))
COUNTS: Counter = Counter()             # how often the safety checks had something to check
USER_DEVICES = tuple(sum(1 << d for d in range(N) if USER_OF[d] == u) for u in range(len(USERS)))


class Entry(NamedTuple):
    kind: int          # LEGACY | CREATE | COMMIT
    genesis: int       # version of the group's genesis (0 for the pre-v4 epoch)
    roster: int        # device mask after this version
    added: int         # devices added by this version (CREATE: the whole roster)
    poisoner: int      # committer of an unreadable envelope, or -1
    parent: int        # previousVersion


class State(NamedTuple):
    viewers: int       # user mask
    status: tuple      # per device: UNAPPROVED | APPROVED | REVOKED
    log: tuple         # accepted versions; log[v - 1] is version v
    pkg: tuple         # per device: NO_PKG | PKG | REJOIN_PKG (published, valid)
    local: tuple       # per device: BROKEN | NO_STATE | version of its local group state
    derived: tuple     # per device: version mask of keys derived from the group
    restored: tuple    # per device: version mask of keys restored from backups
    stale: bool        # 24 h since the last group-key refresh
    genesis_wait: int  # 0 not requested, 1 waiting, 2 expired
    viewer_changes: int
    device_changes: int
    lost: bool         # Y1 has gone offline for good


@dataclass(frozen=True)
class Variant:
    max_log: int = 6                   # versions including the pre-v4 v1
    poison_budget: int = 1
    second_device: bool = False        # X2 exists (waits for approval) and history restore is modelled
    lose_device: bool = False          # Y1 may go permanently offline (at any point)
    max_viewer_changes: int = 2
    max_device_changes: int = 2
    gate_removal: bool = True          # writes need every member eligible
    cas: bool = True                   # one commit per version (compare-and-swap)
    rejoin: bool = True                # a member may ask to be added again
    fresh_start: bool = True
    former_member_log: bool = True     # the log is served for every version the device was a member at
    leave_ended_unreadable: bool = True  # an unreadable envelope of an ended membership is not a rejoin
    idle_fresh_start: bool = True      # (a) also when every usable member has been offline for 72 h
    malicious_server: bool = False     # the server ignores channel visibility


def bits(mask: int) -> list[int]:
    return [d for d in range(N) if mask >> d & 1]


def names(mask: int) -> str:
    return '{' + ','.join(DEVICES[d] for d in bits(mask)) + '}'


def initial(v: Variant) -> State:
    return State(
        viewers=0b011,
        status=(APPROVED, UNAPPROVED if v.second_device else ABSENT, APPROVED, APPROVED),
        log=(Entry(LEGACY, 0, 0b0101, 0, -1, 0),),
        pkg=(NO_PKG,) * N,
        local=(NO_STATE,) * N,
        derived=(1 << 1, 0, 1 << 1, 0),
        restored=(0,) * N,
        stale=False,
        genesis_wait=0,
        viewer_changes=0,
        device_changes=0,
        lost=False,
    )


# === Derived views ===

_ELIGIBLE: dict = {}


def eligible(s: State, v: Variant) -> int:
    key = (s.viewers, s.status, v.malicious_server)
    mask = _ELIGIBLE.get(key)
    if mask is None:
        mask = 0
        for d in range(N):
            if s.status[d] == APPROVED and (v.malicious_server or s.viewers >> USER_OF[d] & 1):
                mask |= DEVICE_BITS[d]
        _ELIGIBLE[key] = mask
    return mask


def can_read(s: State, v: Variant, d: int) -> bool:
    """listGroupCommits: an approved device of a user who can see the channel."""
    return s.status[d] == APPROVED and bool(v.malicious_server or s.viewers >> USER_OF[d] & 1)


def acting(s: State, d: int) -> bool:
    return not (s.lost and d == LOST)


def has_group(s: State) -> bool:
    return s.log[-1].kind != LEGACY


def members(s: State) -> int:
    return s.log[-1].roster if has_group(s) else 0


def pkg_mask(s: State, kinds=(PKG, REJOIN_PKG)) -> int:
    return sum(DEVICE_BITS[d] for d in range(N) if s.pkg[d] in kinds)


def removed_at(log: tuple, version: int) -> int:
    """Devices whose membership ends at `version` (a rejoin ends and restarts one)."""
    entry, prev = log[version - 1], log[version - 2]
    if entry.kind == CREATE:
        return prev.roster if prev.kind != LEGACY else 0
    return (prev.roster & ~entry.roster) | (entry.added & prev.roster)


def poisoned_for(entry: Entry, d: int) -> bool:
    return entry.poisoner >= 0 and entry.poisoner != d


def span_start(log: tuple, d: int) -> int:
    """Version that added `d` to the current group (d must be a current member)."""
    b = DEVICE_BITS[d]
    for version in range(len(log), 0, -1):
        if log[version - 1].added & b:
            return version
    raise AssertionError('member without an adding version')


def visible(s: State, v: Variant, d: int, version: int) -> bool:
    """listGroupCommits / listGroupMembers: which versions the device may read."""
    log, b = s.log, DEVICE_BITS[d]
    entry, prev = log[version - 1], log[version - 2]
    if not v.former_member_log:
        # Control: only versions of the device's current membership.
        return bool(members(s) & b and entry.roster & b and entry.genesis == log[-1].genesis
                    and version >= span_start(log, d))
    return bool(entry.roster & b or (prev.kind != LEGACY and prev.roster & b))


class View(NamedTuple):
    eligible: int
    members: int
    rejoin_open: int
    usable: int
    pending_add: int
    required_remove: int


def view(s: State, v: Variant) -> View:
    e, m = eligible(s, v), members(s)
    rejoin = pkg_mask(s, (REJOIN_PKG,)) & m
    packaged = pkg_mask(s)
    return View(e, m, rejoin, m & e & ~rejoin, e & packaged & (~m | rejoin), m & ~e)


def can_send(s: State, v: Variant, d: int, w: View | None = None) -> bool:
    """authorizeGroupWrite plus the client holding the active version."""
    if not has_group(s) or s.stale or s.local[d] != len(s.log):
        return False
    w = w or view(s, v)
    b = DEVICE_BITS[d]
    if not (w.members & b and w.eligible & b):
        return False
    return not v.gate_removal or w.members & ~w.eligible == 0


# === Transitions ===
# Each yields (action, next_state, kind); kind is 'step' (an ordinary protocol
# step), 'fresh' (fresh start) or 'other' (authorization, devices, faults, sends).

def _set(t: tuple, i: int, value) -> tuple:
    return t[:i] + (value,) + t[i + 1:]


def _accept(s: State, entry: Entry, committer: int, ended: int, refresh: bool) -> State:
    log = s.log + (entry,)
    version = len(log)
    pkg = tuple(NO_PKG if entry.added >> d & 1 else p for d, p in enumerate(s.pkg))
    # A device that dropped its group (unreadable envelope) starts over once
    # its membership ends or a new one begins (it then joins from the Welcome);
    # a rejoin ends and restarts it in one version.
    restart = ended | entry.added
    local = tuple(NO_STATE if (restart >> d & 1 and value == BROKEN) else value for d, value in enumerate(s.local))
    local = _set(local, committer, version)
    derived = _set(s.derived, committer, s.derived[committer] | 1 << version)
    return s._replace(log=log, pkg=pkg, local=local, derived=derived, stale=False if refresh else s.stale)


def _submasks(mask: int):
    sub = mask
    while True:
        yield sub
        if sub == 0:
            return
        sub = (sub - 1) & mask


def _poison_options(s: State, v: Variant, committer: int):
    yield -1
    if sum(entry.poisoner >= 0 for entry in s.log) < v.poison_budget:
        yield committer


def _process(s: State, v: Variant, d: int, version: int) -> tuple[State, str]:
    log, b = s.log, DEVICE_BITS[d]
    entry = log[version - 1]
    if entry.kind == CREATE or removed_at(log, version) & b:
        if entry.added & b:
            return _welcome(s, d, version, 'removed and re-added: ')
        return s._replace(local=_set(s.local, d, NO_STATE)), 'removed (keeps its keys)'
    if poisoned_for(entry, d):
        # syncLocked: the envelope belongs to a membership before the device's
        # current one (it was removed, or the group replaced, and it was added
        # again later): it leaves that group behind and joins its current
        # membership. Otherwise it asks to be added again (requestRejoin; a
        # device that is not a member then only publishes a package).
        earlier = members(s) & b and span_start(log, d) > version
        if earlier and v.leave_ended_unreadable:
            return s._replace(local=_set(s.local, d, NO_STATE)), 'cannot read it; that membership already ended'
        return s._replace(local=_set(s.local, d, BROKEN)), 'cannot read it, drops the group'
    return s._replace(local=_set(s.local, d, version), derived=_set(s.derived, d, s.derived[d] | 1 << version)), 'ok'


def _welcome(s: State, d: int, version: int, prefix: str = '') -> tuple[State, str]:
    if poisoned_for(s.log[version - 1], d):
        return s._replace(local=_set(s.local, d, BROKEN)), prefix + 'Welcome unreadable, drops the group'
    return s._replace(local=_set(s.local, d, version), derived=_set(s.derived, d, s.derived[d] | 1 << version)), prefix + 'joined'


def _sync(s: State, v: Variant, d: int) -> tuple[State, list[str]]:
    """syncLocked: process every version the device may read, in order; when
    the group is left or not held yet, join from the Welcome of the version
    that added the device. Stops at an unreadable envelope (the device then
    holds no group state) or at the first version it may not read."""
    latest, b, notes = len(s.log), DEVICE_BITS[d], []
    for _ in range(4 * latest + 4):
        local = s.local[d]
        if 0 < local < latest and visible(s, v, d, local + 1):
            s, outcome = _process(s, v, d, local + 1)
            notes.append(f'v{local + 1} {outcome}')
        elif local == NO_STATE and members(s) & b and visible(s, v, d, span_start(s.log, d)):
            start = span_start(s.log, d)
            s, outcome = _welcome(s, d, start)
            notes.append(f'v{start} {outcome}')
        else:
            return s, notes
    raise AssertionError('catch-up does not terminate')


def transitions(s: State, v: Variant):
    w = view(s, v)
    latest = len(s.log)
    group = has_group(s)
    room = latest < v.max_log
    packaged = pkg_mask(s)

    for d in range(N):
        if not acting(s, d):
            continue
        b = DEVICE_BITS[d]
        local = s.local[d]
        member = bool(w.members & b)
        readable = can_read(s, v, d)

        # Sync: catch up through the log, joining from a Welcome that adds it.
        if readable:
            nxt, notes = _sync(s, v, d)
            if notes:
                yield ('sync', d), nxt, 'step'

        # Publish a package (background maintenance does so for any channel
        # where the device is eligible and not a member, without syncing it
        # first); a member only to ask to be added again after it dropped
        # its group state (requestRejoin).
        if w.eligible & b and s.pkg[d] == NO_PKG:
            if not member:
                wait = s.genesis_wait if group else max(s.genesis_wait, 1)
                yield ('publish', d, 'package'), s._replace(pkg=_set(s.pkg, d, PKG), genesis_wait=wait), 'step'
            elif local == BROKEN and v.rejoin:
                yield ('publish', d, 'rejoin request'), s._replace(pkg=_set(s.pkg, d, REJOIN_PKG)), 'step'

        # Genesis of the channel's first continuous group.
        if room and not group and w.eligible & b and s.pkg[d] != NO_PKG:
            previous = s.log[-1].roster & w.eligible
            for others in _submasks(w.eligible & packaged & ~b):
                added = b | others
                missing = previous & ~added
                if missing & packaged or (missing and s.genesis_wait < 2):
                    continue
                for poisoner in _poison_options(s, v, d):
                    entry = Entry(CREATE, latest + 1, added, added, poisoner, latest)
                    yield (('create', d, added, poisoner >= 0, 'genesis'), _accept(s, entry, d, 0, True),
                           'step' if poisoner < 0 else 'other')

        # Fresh start (step-up) of an existing group.
        if room and group and v.fresh_start and w.eligible & b and not w.usable & b and s.pkg[d] != NO_PKG and local <= NO_STATE:
            idle = DEVICE_BITS[LOST] if s.lost and v.idle_fresh_start else 0
            reasons = []
            if w.usable & ~idle == 0:
                reasons.append('nobody usable online')
            if w.rejoin_open & b:
                reasons.append('own rejoin waits')
            if MANAGER_USERS >> USER_OF[d] & 1 and (w.pending_add | w.required_remove | w.rejoin_open):
                reasons.append('manager, changes stalled')
            if reasons:
                for others in _submasks(w.pending_add & ~b):
                    added = b | others
                    for poisoner in _poison_options(s, v, d):
                        entry = Entry(CREATE, latest + 1, added, added, poisoner, latest)
                        yield (('create', d, added, poisoner >= 0, 'fresh start: ' + '; '.join(reasons)),
                               _accept(s, entry, d, w.members, True), 'fresh' if poisoner < 0 else 'other')

        # Ordinary commit by a usable member at the current version.
        current = 0 < local and s.log[local - 1].kind != LEGACY and s.log[local - 1].genesis == s.log[-1].genesis
        if room and group and w.usable & b and current and (local == latest or not v.cas):
            for added in _submasks(w.pending_add):
                removed = w.required_remove | (added & w.members)
                if not (added or removed or s.stale):
                    continue          # KEY_ROTATION_NOT_REQUIRED
                roster = (w.members & ~removed) | added
                refresh = bool(removed) or not added
                for poisoner in _poison_options(s, v, d):
                    entry = Entry(COMMIT, s.log[-1].genesis, roster, added, poisoner, local)
                    yield (('commit', d, added, removed, poisoner >= 0), _accept(s, entry, d, removed, refresh),
                           'step' if poisoner < 0 else 'other')

        if v.second_device and s.status[d] == APPROVED:
            pooled = 0
            for x in bits(USER_DEVICES[USER_OF[d]]):
                pooled |= s.derived[x] | s.restored[x]
            new = pooled & ~(s.derived[d] | s.restored[d])
            if new:
                yield ('restore', d), s._replace(restored=_set(s.restored, d, s.restored[d] | new)), 'other'

    if s.viewer_changes < v.max_viewer_changes:
        for u in range(len(USERS)):
            viewers = s.viewers ^ (1 << u)
            if viewers:
                yield ('view', u, bool(viewers >> u & 1)), s._replace(
                    viewers=viewers, viewer_changes=s.viewer_changes + 1), 'other'
    if s.device_changes < v.max_device_changes:
        for d in range(N):
            if s.status[d] == UNAPPROVED:
                yield ('approve', d), s._replace(status=_set(s.status, d, APPROVED),
                                                 device_changes=s.device_changes + 1), 'other'
            elif s.status[d] == APPROVED:
                yield ('revoke', d), s._replace(status=_set(s.status, d, REVOKED),
                                                device_changes=s.device_changes + 1), 'other'
    if group and not s.stale:
        yield ('clock', 'the group key reaches 24 hours'), s._replace(stale=True), 'step'
    if not group and s.genesis_wait == 1:
        yield ('clock', 'the 24-hour genesis wait ends'), s._replace(genesis_wait=2), 'step'
    if v.lose_device and not s.lost:
        yield ('lost', LOST), s._replace(lost=True), 'other'


def label(s: State, v: Variant, action) -> str:
    kind = action[0]
    if kind == 'sync':
        return f'{DEVICES[action[1]]}: sync (' + '; '.join(_sync(s, v, action[1])[1]) + ')'
    if kind == 'publish':
        return f'{DEVICES[action[1]]}: publish {action[2]}'
    if kind == 'create':
        _, d, added, poisoned, why = action
        return f'{DEVICES[d]}: {why} with {names(added)}' + (' [unreadable for others]' if poisoned else '')
    if kind == 'commit':
        _, d, added, removed, poisoned = action
        parts = [f'add {names(added)}'] if added else []
        parts += [f'remove {names(removed)}'] if removed else []
        return f'{DEVICES[d]}: commit ' + (', '.join(parts) or 'key refresh') + (
            ' [unreadable for others]' if poisoned else '')
    if kind == 'restore':
        return f'{DEVICES[action[1]]}: restore history'
    if kind == 'view':
        return f'authz: {USERS[action[1]]} {"gains" if action[2] else "loses"} view'
    if kind == 'approve':
        return f'{DEVICES[action[1]]}: approved'
    if kind == 'revoke':
        return f'{DEVICES[action[1]]}: revoked'
    if kind == 'clock':
        return f'clock: {action[1]}'
    if kind == 'lost':
        return f'{DEVICES[action[1]]}: goes offline for good'
    return repr(action)


# === Safety properties ===

def _spans(log: tuple, d: int):
    """(start, end) membership spans of d in continuous groups; end is exclusive."""
    b, spans, start = DEVICE_BITS[d], [], None
    for version in range(2, len(log) + 1):
        if log[version - 1].kind == LEGACY:
            continue
        if start is not None and removed_at(log, version) & b:
            spans.append((start, version))
            start = None
        if start is None and log[version - 1].added & b:
            start = version
    if start is not None:
        spans.append((start, len(log) + 1))
    return spans


def _catch_up(s: State, v: Variant, d: int) -> int:
    """Keys d derives by processing the log on its own (sync, catch-up, join)."""
    return _sync(s, v, d)[0].derived[d]


def key_availability(s: State, v: Variant):
    """KA: for every device that may read the log, the versions of each
    membership it joined (or currently holds) that it cannot derive by
    processing the log. Versions from an unreadable envelope on (until the
    device is added again) are exempt. Separately, memberships that ended
    before the device ever joined them (KA-unjoined)."""
    missing, unjoined = [], []
    for d in range(N):
        if not acting(s, d) or not can_read(s, v, d):
            continue
        reachable = None
        for start, end in _spans(s.log, d):
            stop = next((x for x in range(start, end) if poisoned_for(s.log[x - 1], d)), end)
            need = sum(1 << x for x in range(start, stop))
            if not need:
                continue
            if need & ~s.derived[d]:
                COUNTS['catch-up'] += 1      # the device still has to read these from the log
            if reachable is None:
                reachable = _catch_up(s, v, d)
            lacking = need & ~reachable
            if not lacking:
                continue
            versions = [x for x in range(start, stop) if lacking >> x & 1]
            joined = end == len(s.log) + 1 or s.derived[d] >> start & 1
            (missing if joined else unjoined).append((d, start, end, versions))
    return missing, unjoined


def safety_violations(s: State, v: Variant):
    out = []
    w = view(s, v)
    writers = [d for d in range(N) if acting(s, d) and can_send(s, v, d, w)]
    if writers:
        COUNTS['writable'] += 1
        # A message may be sent now under the active version. Its key can be
        # derived by every member of that version (now or by catching up
        # later), is held by whoever derived or restored it, and can reach
        # every other device of their users through backups.
        version = len(s.log)
        roster = s.log[-1].roster
        derived = sum(DEVICE_BITS[d] for d in range(N) if s.derived[d] >> version & 1)
        restored = sum(DEVICE_BITS[d] for d in range(N) if s.restored[d] >> version & 1)
        writer = DEVICES[writers[0]]
        for u in range(len(USERS)):
            reach = USER_DEVICES[u] & (roster | derived | restored)
            if reach and not s.viewers >> u & 1:
                out.append(('KC', f'{writer} can write under v{version}, whose key {names(reach)} of {USERS[u]} '
                                  f'can derive or hold although {USERS[u]} cannot see the channel'))
        revoked = sum(DEVICE_BITS[d] for d in range(N) if s.status[d] == REVOKED)
        if revoked & (roster | derived):
            out.append(('KC-dev', f'{writer} can write under v{version}, whose key revoked '
                                  f'{names(revoked & (roster | derived))} can derive or holds'))
        if revoked & restored & ~(roster | derived):
            out.append(('KC-dev-restore', f'{writer} can write under v{version}, whose key revoked '
                                          f'{names(revoked & restored & ~(roster | derived))} restored from a backup'))
    last = s.log[-1]
    if last.kind != LEGACY and last.parent != len(s.log) - 1:
        out.append(('KI', f'v{len(s.log)} extends v{last.parent}, not the active v{len(s.log) - 1}: the chain forks'))
    missing, unjoined = key_availability(s, v)
    for d, start, end, versions in missing:
        out.append(('KA', f'{DEVICES[d]} was a member at v{versions} (membership v{start}..v{end - 1}) '
                          f'but cannot derive those keys from the log'))
    for d, start, end, versions in unjoined:
        out.append(('KA-unjoined', f'{DEVICES[d]} was added at v{start} and removed at v{end} before it joined; '
                                   f'the log never gives it v{versions}'))
    return out


# === Exploration ===

class Graph:
    def __init__(self):
        self.states: list[State] = []
        self.index: dict[State, int] = {}
        self.parent = array('i')
        self.edges_from = array('i')
        self.edges_to = array('i')
        self.edges_fresh = bytearray()
        self.transitions = 0

    def trace(self, i: int, v: Variant) -> list[str]:
        steps = []
        while self.parent[i] >= 0:
            p = self.parent[i]
            target = self.states[i]
            steps.append(next(label(self.states[p], v, a) for a, nxt, _ in transitions(self.states[p], v)
                              if nxt == target))
            i = p
        return list(reversed(steps))


def explore(v: Variant, *, safety: bool = True, edges: bool = False, stop: frozenset = frozenset(),
            progress: bool = False):
    """Breadth-first over every reachable state. Returns the graph and the
    first violation found per property (state index, message). With `stop`,
    exploration ends once all those properties were violated (controls)."""
    g = Graph()
    start = initial(v)
    g.states.append(start)
    g.index[start] = 0
    g.parent.append(-1)
    found: dict[str, tuple[int, str]] = {}
    queue = deque([0])
    while queue:
        i = queue.popleft()
        if progress and i % 500_000 == 0 and i:
            print(f'       ... {i:,} of {len(g.states):,} states', flush=True)
        s = g.states[i]
        if safety:
            hits = safety_violations(s, v)
            for prop, message in hits:
                found.setdefault(prop, (i, message))
            if stop and stop <= found.keys():
                break
            if any(prop in stop for prop, _ in hits):
                continue          # a control's counterexample needs no successors
        for _, nxt, kind in transitions(s, v):
            g.transitions += 1
            j = g.index.get(nxt)
            if j is None:
                j = len(g.states)
                g.states.append(nxt)
                g.index[nxt] = j
                g.parent.append(i)
                queue.append(j)
            if edges and kind != 'other':
                g.edges_from.append(i)
                g.edges_to.append(j)
                g.edges_fresh.append(kind == 'fresh')
    return g, found


# === Liveness ===

def working_member(s: State, v: Variant, w: View) -> bool:
    """An online usable member whose own catch-up reaches the current version
    without an unreadable envelope: it can commit for everybody else."""
    latest = len(s.log)
    for d in bits(w.usable):
        if not acting(s, d) or not can_read(s, v, d):
            continue
        local = s.local[d]
        if local == BROKEN:
            continue
        first = local + 1 if local > 0 else span_start(s.log, d)
        if not any(poisoned_for(s.log[x - 1], d) for x in range(first, latest + 1)):
            return True
    return False


def liveness(g: Graph, v: Variant, headroom: int = 2):
    """For every state with room for `headroom` more versions and every online
    eligible device: protocol steps alone (no authorization or device changes,
    no faults) reach a state where that device can write. Where an online
    usable member can still follow the log ('KL' states, and every state
    before the first group) fresh start is not used; otherwise ('orphan'
    states) it is. Backward fixpoints over the explored graph."""
    n = len(g.states)
    starts = array('i', bytes(4 * (n + 1)))
    for j in g.edges_to:
        starts[j + 1] += 1
    for i in range(n):
        starts[i + 1] += starts[i]
    fill = array('i', starts)
    preds = array('i', bytes(4 * len(g.edges_to)))
    fresh = bytearray(len(g.edges_to))
    for k, (i, j) in enumerate(zip(g.edges_from, g.edges_to)):
        preds[fill[j]] = i
        fresh[fill[j]] = g.edges_fresh[k]
        fill[j] += 1
    del fill

    sendable = bytearray(n)      # device mask that can write now
    online = bytearray(n)        # online eligible devices of checked states
    classes = bytearray(n)       # 0 not checked, 1 KL, 2 orphan
    for i, s in enumerate(g.states):
        w = view(s, v)
        sendable[i] = sum(DEVICE_BITS[d] for d in range(N) if can_send(s, v, d, w))
        if len(s.log) + headroom <= v.max_log:
            online[i] = w.eligible & ~(DEVICE_BITS[LOST] if s.lost else 0)
            classes[i] = 1 if not has_group(s) or working_member(s, v, w) else 2

    def fixpoint(d: int, with_fresh: bool) -> bytearray:
        b = DEVICE_BITS[d]
        good = bytearray(n)
        work = []
        for i in range(n):
            if sendable[i] & b:
                good[i] = 1
                work.append(i)
        while work:
            j = work.pop()
            for k in range(starts[j], starts[j + 1]):
                i = preds[k]
                if not good[i] and (with_fresh or not fresh[k]):
                    good[i] = 1
                    work.append(i)
        return good

    stuck = {1: [], 2: []}
    checked = {1: 0, 2: 0}
    for d in range(N):
        b = DEVICE_BITS[d]
        relevant = [i for i in range(n) if online[i] & b]
        if not relevant:
            continue
        plain = fixpoint(d, False)
        with_fresh = fixpoint(d, True) if v.fresh_start else plain
        for i in relevant:
            cls = classes[i]
            checked[cls] += 1
            if not (plain if cls == 1 else with_fresh)[i]:
                stuck[cls].append((i, d))
        del plain, with_fresh
    return stuck, checked


# === Run ===

def _first_stuck(g: Graph, v: Variant, items):
    if not items:
        return []
    i, d = min(items, key=lambda item: (len(g.states[item[0]].log), item[0]))
    return g.trace(i, v) + [f'=> {DEVICES[d]} cannot reach a state where it can write']


# Exhaustive runs: (name, variant). Each checks the safety properties on every
# reachable state and the liveness properties on the explored graph.
RUNS = (
    # Every device, authorization and device change (2 + 2), and Y1 may go
    # offline for good at any point.
    ('main', Variant(max_log=6, poison_budget=0, lose_device=True)),
    # One unreadable commit or Welcome, with 1 + 1 changes.
    ('faults', Variant(max_log=6, poison_budget=1, max_viewer_changes=1, max_device_changes=1)),
    # X2 waits for approval; history restore between X's devices.
    ('second-device', Variant(max_log=5, poison_budget=0, second_device=True, max_viewer_changes=0)),
)


def run() -> None:
    print('== M3: continuous channel groups (exhaustive) ==')
    found: dict[str, list[str]] = {}
    stuck = {'KL': [], 'KL-orphan': [], 'KL-lost': []}
    for name, variant in RUNS:
        COUNTS.clear()
        t0 = time.time()
        g, hits = explore(variant, edges=True)
        explored = time.time() - t0
        live, pairs = liveness(g, variant)
        lost_pairs = 0
        for cls, prop in ((1, 'KL'), (2, 'KL-orphan')):
            for i, d in live[cls]:
                stuck['KL-lost' if g.states[i].lost else prop].append((name, d, g, i, variant))
        if variant.lose_device:
            lost_pairs = sum(1 for i, s in enumerate(g.states) if s.lost and len(s.log) + 2 <= variant.max_log)
        for prop, (i, message) in hits.items():
            found.setdefault(prop, [f'[{name}]'] + g.trace(i, variant) + ['=> ' + message])
        groups = sum(1 for s in g.states if has_group(s))
        fresh = sum(1 for s in g.states if sum(e.kind == CREATE for e in s.log) > 1)
        poisoned = sum(1 for s in g.states if any(e.poisoner >= 0 for e in s.log))
        lost = (f', Y1 offline for good in {sum(1 for s in g.states if s.lost):,} ({lost_pairs:,} with room '
                f'for two more versions)') if variant.lose_device else ''
        print(f'     {name}: {len(g.states):,} states, {g.transitions:,} transitions ({len(g.edges_to):,} protocol '
              f'steps), {explored:.0f}s + {time.time() - t0 - explored:.0f}s liveness; group in {groups:,}, fresh '
              f'start in {fresh:,}, unreadable envelope in {poisoned:,}{lost}; writable in '
              f'{COUNTS["writable"]:,}, catch-up obligations {COUNTS["catch-up"]:,}; '
              f'{pairs[1]:,} + {pairs[2]:,} (state, device) liveness pairs')
        del g, hits, live

    def holds(check_id, title, prop):
        record('M3', check_id, title, 'HOLDS', prop in found, witness=found.get(prop, []))

    holds('KC', 'whenever a message can be written, only devices of users who can see the channel can derive or '
                'hold its key (removal, joining, fresh start, restore)', 'KC')
    holds('KC-dev', 'whenever a message can be written, no revoked device can derive or holds its key from the group',
          'KC-dev')
    holds('KI', 'the server accepts one commit per version: the version chain never forks', 'KI')
    holds('KA', 'a device that may read the channel derives, from the commit log alone, every version of each '
                'membership it joined (versions from an envelope it could not read on are exempt)', 'KA')
    record('M3', 'KA-unjoined', 'a membership that ended before the device joined it is not recovered from the log '
                                '(only from the user\'s backups)', 'LIMIT', 'KA-unjoined' in found,
           witness=found.get('KA-unjoined', []))
    record('M3', 'KC-dev-restore', 'a device that restored its user\'s backups and was then revoked holds the current '
                                   'key until the next commit (at most 24 hours)', 'LIMIT', 'KC-dev-restore' in found,
           witness=found.get('KC-dev-restore', []))
    for prop, title in (
        ('KL', 'while one online usable member can follow the log, every online eligible device reaches a writable '
               'state by protocol steps alone (no fresh start)'),
        ('KL-orphan', 'with no such member (none left, or none able to read an envelope), a fresh start makes every '
                      'online eligible device writable again'),
        ('KL-lost', 'a member that goes offline for good (Y1) never blocks the others: every online eligible device '
                    'still reaches a writable state'),
    ):
        items = stuck[prop]
        witness = []
        if items:
            name, d, g, i, variant = min(items, key=lambda item: (len(item[2].states[item[3]].log), item[3]))
            witness = [f'[{name}]'] + g.trace(i, variant) + [f'=> {DEVICES[d]} cannot reach a state where it can write']
        record('M3', prop, title, 'HOLDS', bool(items), f'{len(items)} stuck (state, device) pairs' if items else '',
               witness=witness)
    stuck.clear()

    small = dict(max_log=4, max_viewer_changes=1, max_device_changes=1, poison_budget=0)

    def control(check_id, title, expect, prop, variant):
        g, hits = explore(variant, stop=frozenset({prop}))
        hit = hits.get(prop)
        record('M3', check_id, title, expect, hit is not None,
               witness=(g.trace(hit[0], variant) + ['=> ' + hit[1]]) if hit else [])

    control('KC-server', 'a server that ignores channel visibility can let a non-viewer\'s device derive the key of '
                         'messages written later (F-E2E-001)', 'LIMIT', 'KC', Variant(malicious_server=True, **small))
    control('KC-ctl', 'writing before the Remove is accepted lets a user who lost the channel read new messages',
            'CONTROL', 'KC', Variant(gate_removal=False, **small))
    control('KC-dev-ctl', 'writing before the Remove is accepted lets a revoked device read new messages',
            'CONTROL', 'KC-dev', Variant(gate_removal=False, **small))
    control('KI-ctl', 'without the version compare-and-swap, two commits extend the same version', 'CONTROL', 'KI',
            Variant(cas=False, **small))
    control('KA-ctl', 'serving the log only to current members leaves a device removed while offline without keys of '
                      'versions it was a member at', 'CONTROL', 'KA', Variant(former_member_log=False, **small))
    control('KA-rejoin-ctl', 'asking to be added again when an envelope of an already ended membership cannot be '
                             'read leaves the device out of the membership that added it (client before the fix)',
            'CONTROL', 'KA', Variant(leave_ended_unreadable=False, max_log=5, max_viewer_changes=1,
                                     max_device_changes=1))

    for check_id, title, variant, cls, lost_only in (
        ('KL-poison-ctl', 'without rejoin and fresh start, a device that cannot read one envelope never writes again',
         Variant(rejoin=False, fresh_start=False, max_log=5, max_viewer_changes=0, max_device_changes=0), 1, False),
        ('KL-orphan-ctl', 'without fresh start, a channel whose usable members are gone stays unwritable',
         Variant(fresh_start=False, poison_budget=0, max_log=5), 2, False),
        ('KL-lost-ctl', 'without the 72-hour rule, a member that went offline for good keeps a non-manager waiting',
         Variant(lose_device=True, idle_fresh_start=False, poison_budget=0, max_log=5), 2, True),
    ):
        g, _ = explore(variant, safety=False, edges=True)
        live, _ = liveness(g, variant)
        items = [(i, d) for i, d in live[cls] if g.states[i].lost or not lost_only]
        record('M3', check_id, title, 'CONTROL', bool(items), f'{len(items)} stuck (state, device) pairs',
               witness=_first_stuck(g, variant, items))
        del g, live


if __name__ == '__main__':
    run()
