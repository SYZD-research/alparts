"""M6: profiles, avatars and per-workspace profile warnings (commit 39cad98).

Four parts, each written from the implementation and checked against the
requirement text rather than against its own guard:

  M6a  warnings and the one-time clearing request (profile.service.ts)
       explicit-state search over flag/unflag/deny/appeal/edit/role/leave/join
  M6b  the same request under interleaved transactions (row-lock usage)
  M6c  who sees a warned member's avatar (client gate + avatar route)
  M6d  avatar object lifecycle: put -> transaction -> delete, with failures
       (DB must never reference a missing object: backup.sh stops on it)

The PNG sanitizer is checked against the real code in conformance.py-style
harness `conformance/avatar-harness.mts` (M6e).
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace

from common import record
from harness import HarnessError, require_rows, run_harness

INF = float('inf')

# ---------------------------------------------------------------------------
# M6a: warnings and the clearing request
# ---------------------------------------------------------------------------

# Role catalog: name -> (position, MANAGE_MEMBERS, VIEW_AUDIT_LOG). "none" means no role.
ROLES = {
    'none': (None, False, False),
    'audit': (0, False, True),
    'mod': (1, True, False),
    'admin': (2, True, False),
}
WORKSPACES = ('W1', 'W2')
OWNER0 = 'O'


@dataclass(frozen=True)
class Rules:
    change_check: str = 'timestamp'     # 'timestamp' (implementation) | 'revision' (alternative)
    noop_edit_bumps: bool = False       # CONTROL (before fix): an unchanged save set profileUpdatedAt
    unreadable_avatar_counts: bool = False  # CONTROL (before the 2026-10-09 fix): re-uploading the same picture
                                            # while the stored one could not be read counted as a change
    skew: int = 0                       # CONTROL (before fix): profileUpdatedAt used the app clock
    rank_check: bool = True             # CONTROL: False drops the strictly-higher-rank rule
    global_once: bool = True            # CONTROL: False makes the request once per workspace
    cascade_on_leave: bool = False      # CONTROL: leaving deletes the member's warnings
    owner_transfer: bool = False        # CONTROL: hypothetical ownership transfer


@dataclass(frozen=True)
class A:
    members: frozenset          # (w, u)
    roles: frozenset            # ((w, u), role)
    owners: tuple               # ((w, owner), ...)
    flags: frozenset            # (w, u, status, flagged_at, flag_rev)
    content: int                # T's profile content (ghost for the requirement)
    rev: int                    # proposed: revision bumped only by a real change
    pua: int | None             # users.profile_updated_at (app clock)
    used: bool                  # users.flag_appeal_used_at IS NOT NULL
    appeals: int                # ghost: successful requests by T
    changed_since: frozenset    # ghost: workspaces whose warning on T saw a real change afterwards
    clock: int


def a_initial() -> A:
    members = {(w, u) for w in WORKSPACES for u in ('O', 'A', 'T')} | {('W1', 'B')}
    roles = {(('W1', 'A'), 'admin'), (('W2', 'A'), 'admin'), (('W1', 'B'), 'mod')}
    return A(frozenset(members), frozenset(roles), tuple((w, OWNER0) for w in WORKSPACES),
             frozenset(), 0, 0, None, False, 0, frozenset(), 0)


def owner_of(s: A, w: str) -> str:
    return dict(s.owners)[w]


def role_of(s: A, w: str, u: str) -> str:
    return dict(s.roles).get((w, u), 'none')


def rank(s: A, w: str, u: str) -> float:
    """profile.service.ts rank(): owner = +inf, otherwise max role position, -1 without roles."""
    if owner_of(s, w) == u:
        return INF
    position = ROLES[role_of(s, w, u)][0]
    return -1 if position is None else position


def can_manage(s: A, w: str, u: str) -> bool:
    return owner_of(s, w) == u or ((w, u) in s.members and ROLES[role_of(s, w, u)][1])


def guard(s: A, rules: Rules, w: str, actor: str, target: str) -> bool:
    """assertFlagAuthority as implemented."""
    if (w, target) not in s.members or (w, actor) not in s.members:
        return False
    if not can_manage(s, w, actor):
        return False
    if target == actor or target == owner_of(s, w):
        return False
    if rules.rank_check and owner_of(s, w) != actor and rank(s, w, target) >= rank(s, w, actor):
        return False
    return True


def spec_authority(s: A, w: str, actor: str, target: str) -> bool:
    """Requirement: MANAGE_MEMBERS holders and the owner; only strictly lower members; never the owner."""
    owner = owner_of(s, w)
    if target in (owner, actor) or (w, target) not in s.members:
        return False
    if actor == owner:
        return True
    return ROLES[role_of(s, w, actor)][1] and rank(s, w, target) < rank(s, w, actor)


def flag_of(s: A, w: str, u: str):
    for f in s.flags:
        if f[0] == w and f[1] == u:
            return f
    return None


def a_transitions(s: A, rules: Rules):
    """Yields (actor, label, next, kind, violations) for every allowed operation."""
    now = s.clock
    tick = dict(clock=now + 1)
    users = ('O', 'A', 'B', 'T')
    for w in WORKSPACES:
        # warnings
        for actor in users:
            for target in ('B', 'T'):
                if not guard(s, rules, w, actor, target):
                    continue
                bad = [] if spec_authority(s, w, actor, target) else ['A4']
                current = flag_of(s, w, target)
                if current is None:
                    flags = s.flags | {(w, target, 'none', now, s.rev)}
                    changed = s.changed_since - {w} if target == 'T' else s.changed_since
                    yield actor, f'flag({w},{target})', replace(s, flags=flags, changed_since=changed, **tick), 'flag', bad
                else:
                    yield actor, f'unflag({w},{target})', replace(s, flags=s.flags - {current}, **tick), 'unflag', bad
                    if current[2] == 'pending':
                        denied = (w, target, 'denied', current[3], current[4])
                        yield actor, f'deny({w},{target})', replace(s, flags=(s.flags - {current}) | {denied}, **tick), 'deny', bad
        # the owner changes roles of B and T
        for target in ('B', 'T'):
            if (w, target) in s.members:
                for role in ROLES:
                    if role != role_of(s, w, target):
                        roles = {r for r in s.roles if r[0] != (w, target)}
                        if role != 'none':
                            roles.add(((w, target), role))
                        yield owner_of(s, w), f'role({w},{target},{role})', replace(s, roles=frozenset(roles), **tick), 'role', []
        # leave / join (never the owner)
        for u in ('B', 'T'):
            if (w, u) in s.members and owner_of(s, w) != u:
                flags = s.flags
                if rules.cascade_on_leave:
                    flags = frozenset(f for f in flags if not (f[0] == w and f[1] == u))
                roles = frozenset(r for r in s.roles if r[0] != (w, u))
                removed = [f for f in s.flags if f not in flags]
                yield u, f'leave({w})', replace(s, members=s.members - {(w, u)}, roles=roles, flags=flags, **tick), 'leave', \
                    ['A6'] if removed else []
            elif (w, u) not in s.members:
                yield u, f'join({w})', replace(s, members=s.members | {(w, u)}, **tick), 'join', []
        # hypothetical ownership transfer
        if rules.owner_transfer:
            for u in ('A', 'T'):
                if (w, u) in s.members and owner_of(s, w) != u:
                    owners = tuple((x, u if x == w else o) for x, o in s.owners)
                    yield owner_of(s, w), f'transfer({w},{u})', replace(s, owners=owners, **tick), 'transfer', []
        # T's clearing request
        current = flag_of(s, w, 'T')
        if (w, 'T') in s.members and current is not None:
            once_ok = not s.used if rules.global_once else True
            if rules.change_check == 'timestamp':
                changed_ok = s.pua is not None and s.pua > current[3]
            else:
                changed_ok = s.rev > current[4]
            if once_ok and current[2] == 'none' and changed_ok:
                bad = []
                if s.appeals >= 1:
                    bad.append('A1')
                if w not in s.changed_since:
                    bad.append('A3')
                pending = (w, 'T', 'pending', current[3], current[4])
                yield 'T', f'appeal({w})', replace(s, flags=(s.flags - {current}) | {pending}, used=True,
                                                   appeals=s.appeals + 1, **tick), 'appeal', bad
    # T edits the profile (value may equal the current one: an unchanged save)
    for value in (0, 1):
        real = value != s.content
        if not real and not rules.noop_edit_bumps:
            # isCurrentAvatar: the same picture while the stored one cannot be
            # read. The fixed code fails the upload; before, it was a change.
            if rules.unreadable_avatar_counts:
                yield 'T', f'upload the same picture ({value}) while the stored one cannot be read', replace(
                    s, pua=now + rules.skew, **tick), 'edit', []
            continue
        changed = s.changed_since | {f[0] for f in s.flags if f[1] == 'T'} if real else s.changed_since
        yield 'T', f'edit({value})', replace(s, content=value, rev=s.rev + (1 if real else 0), pua=now + rules.skew,
                                             changed_since=changed, **tick), 'edit', []


def a_state_violations(s: A, rules: Rules) -> list[str]:
    bad = []
    # A5: every warning on a current member can be cleared by some current member.
    for f in s.flags:
        w, u = f[0], f[1]
        if (w, u) in s.members and not any(guard(s, rules, w, actor, u) for actor in ('O', 'A', 'B', 'T')):
            bad.append('A5')
    # A7 (limit): T can read the audit log of a workspace that warned T.
    for f in s.flags:
        if f[1] == 'T' and (f[0], 'T') in s.members and ROLES[role_of(s, f[0], 'T')][2]:
            bad.append('A7')
    return bad


def a_explore(rules: Rules, depth: int):
    start = a_initial()
    seen = {start: None}
    queue = deque([(start, 0)])
    found: dict[str, list[str]] = {}
    while queue:
        s, d = queue.popleft()
        for prop in a_state_violations(s, rules):
            found.setdefault(prop, _trace(seen, s))
        if d >= depth:
            continue
        for actor, label, nxt, _kind, bad in a_transitions(s, rules):
            for prop in bad:
                found.setdefault(prop, _trace(seen, s) + [f'{actor}: {label}'])
            if nxt not in seen:
                seen[nxt] = (s, f'{actor}: {label}')
                queue.append((nxt, d + 1))
    return found, len(seen)


def _trace(seen, state):
    steps = []
    while seen.get(state):
        state, step = seen[state]
        steps.append(step)
    return list(reversed(steps))


# ---------------------------------------------------------------------------
# M6b: two clearing requests (W1, W2) and an unflag, interleaved
# ---------------------------------------------------------------------------

def b_explore(row_lock: bool):
    """
    requestProfileAppeal = read(users.used, flag) ; write(used, flag=pending) ; commit.
    Workspace locks are 'share' and different workspaces, so they do not
    serialize the two requests. With FOR UPDATE on the users row the read
    waits for the other transaction's commit.
    """
    # state: (pc1, pc2, seen_used1, seen_used2, used, flags(W1,W2), appeals, lock_holder)
    start = ('idle', 'idle', None, None, False, ('none', 'none'), 0, None)
    seen = {start: None}
    queue = deque([start])
    worst = 0
    witness = []
    while queue:
        s = queue.popleft()
        pc1, pc2, r1, r2, used, flags, appeals, holder = s
        if appeals > worst:
            worst, witness = appeals, _trace(seen, s)
        for i, (pc, r) in enumerate(((pc1, r1), (pc2, r2))):
            nxt = None
            if pc == 'idle':
                if row_lock and holder not in (None, i):
                    continue
                read_used = used
                nxt = ('read', read_used, i if row_lock else holder)
            elif pc == 'read':
                if not r and flags[i] == 'none':
                    new_flags = tuple('pending' if j == i else f for j, f in enumerate(flags))
                    nxt = ('done', r, None if row_lock else holder, True, new_flags, appeals + 1)
                else:
                    nxt = ('done', r, None if row_lock else holder, used, flags, appeals)
            if nxt is None:
                continue
            if nxt[0] == 'read':
                new_pc, new_r, new_holder = nxt
                state = list(s)
                state[i] = new_pc
                state[2 + i] = new_r
                state[7] = new_holder
            else:
                new_pc, new_r, new_holder, new_used, new_flags, new_appeals = nxt
                state = list(s)
                state[i] = new_pc
                state[4], state[5], state[6], state[7] = new_used, new_flags, new_appeals, new_holder
            state = tuple(state)
            if state not in seen:
                seen[state] = (s, f'request{i + 1}: {new_pc}')
                queue.append(state)
    return worst, witness


# ---------------------------------------------------------------------------
# M6c: who sees a warned member's avatar
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class C:
    t_in: frozenset       # workspaces T belongs to
    v_in: frozenset       # workspaces viewer V belongs to
    flagged: bool         # warning on T in W1
    message: bool         # T wrote a message in W1 (stays after T leaves)
    snapshot: tuple       # V's member list of W1: (T listed, T flagged) as last delivered
    cached: bool          # V's browser holds T's avatar bytes


def c_explore(fixed_client: bool, route_check: bool):
    """
    Rendering rule (MessageItem/UserList): hide T's avatar in W1 when W1's
    member list marks T as flagged. The member list lists current members only.
    Route rule (openAvatar): served to V iff V == T or they share a workspace.
    fixed_client: the workspace also reports warned users who are no longer members.
    """
    start = C(frozenset({'W1', 'W2'}), frozenset({'W1', 'W2'}), False, False, (True, False), False)
    seen = {start: None}
    queue = deque([start])
    found: dict[str, list[str]] = {}

    def served(s: C) -> bool:
        return (not route_check) or bool(s.t_in & s.v_in)

    def server_snapshot(s: C):
        listed = 'W1' in s.t_in
        return (listed, s.flagged and (listed or fixed_client))

    while queue:
        s = queue.popleft()
        fresh = s.snapshot == server_snapshot(s)
        listed, marked = s.snapshot
        hidden = marked
        # V looks at W1: message avatar of T (only while V is still in W1)
        if 'W1' in s.v_in and s.message and not hidden and (served(s) or s.cached):
            if s.flagged and fresh:
                found.setdefault('V1', _trace(seen, s) + ['V: opens W1 and sees T\'s avatar next to the message'])
            if s.flagged and not fresh:
                found.setdefault('V2', _trace(seen, s) + ['V: stale member list shows T\'s avatar'])
        if not (s.t_in & s.v_in) and s.cached:
            found.setdefault('V4', _trace(seen, s) + ['V: still holds T\'s avatar with no shared workspace'])
        if not (s.t_in & s.v_in) and served(s):
            found.setdefault('V3', _trace(seen, s) + ['V: GET /users/T/avatar succeeds'])
        moves = []
        moves.append(('M', 'flag(W1,T)' if not s.flagged else 'unflag(W1,T)', replace(s, flagged=not s.flagged)))
        if 'W1' in s.t_in:
            moves.append(('T', 'post in W1', replace(s, message=True)))
        for w in ('W1', 'W2'):
            if w in s.t_in:
                moves.append(('T', f'leave({w})', replace(s, t_in=s.t_in - {w})))
            else:
                moves.append(('T', f'join({w})', replace(s, t_in=s.t_in | {w})))
            if w in s.v_in:
                moves.append(('V', f'leave({w})', replace(s, v_in=s.v_in - {w})))
            else:
                moves.append(('V', f'join({w})', replace(s, v_in=s.v_in | {w})))
        moves.append(('server', 'deliver member list', replace(s, snapshot=server_snapshot(s))))
        if served(s):
            moves.append(('V', 'fetch avatar', replace(s, cached=True)))
        for actor, label, nxt in moves:
            if nxt not in seen:
                seen[nxt] = (s, f'{actor}: {label}')
                queue.append(nxt)
    return found, len(seen)


# ---------------------------------------------------------------------------
# M6d: avatar object lifecycle
# ---------------------------------------------------------------------------

def d_explore(row_lock: bool, recheck_on_error: bool, failures: frozenset):
    """
    setAvatar (x2, same user) and removeAvatar (x1) run concurrently.
      upload: put(new) -> tx [lock row, read old, write new, commit] -> on success delete old
                                                                     -> on error  delete new
      remove: tx [lock row, read old, write null, commit] -> delete old
    Failures: 'ambiguous' (commit succeeds, caller sees an error),
              'rollback', 'delete_fail' (best-effort delete lost), 'crash'.
    recheck_on_error: the implementation (after the fix) re-reads the row on error
    and deletes new only if the row does not reference it (else treats it as
    success). The re-read takes FOR UPDATE, so it waits for a commit still in
    flight and sees the settled value, as this step assumes. If the re-read
    itself fails, the object is kept (an orphan, never a dangling row).
    """
    procs = ('U1', 'U2', 'R')
    start = (('start',) * 3, (None,) * 3, (None,) * 3, frozenset({'K0'}), 'K0', None)
    # state: (pcs, olds, errs, objects, db_key, lock)
    seen = {start: None}
    queue = deque([start])
    found: dict[str, list[str]] = {}
    while queue:
        s = queue.popleft()
        pcs, olds, errs, objects, db_key, lock = s
        if db_key is not None and db_key not in objects:
            found.setdefault('S1', _trace(seen, s))
        if all(pc in ('done', 'crashed') for pc in pcs):
            referenced = {db_key} - {None}
            if objects - referenced:
                key = 'S2' if not ({'crash', 'delete_fail'} & failures) else 'S3'
                found.setdefault(key, _trace(seen, s) + [f'end: stored={sorted(objects)} referenced={sorted(referenced)}'])
        for i, name in enumerate(procs):
            pc = pcs[i]
            new = f'K{i + 1}' if name != 'R' else None
            steps = []

            def st(pc_=None, old=None, err=None, objs=None, key=None, lk='keep', _i=i):
                p = list(pcs); o = list(olds); e = list(errs)
                if pc_ is not None: p[_i] = pc_
                if old is not None: o[_i] = old
                if err is not None: e[_i] = err
                return (tuple(p), tuple(o), tuple(e), objs if objs is not None else objects,
                        db_key if key is None else key, lock if lk == 'keep' else lk)

            if pc == 'start':
                if name == 'R':
                    steps.append(('begin', st('tx', lk=lock)))
                else:
                    steps.append((f'put {new}', st('tx', objs=objects | {new}, lk=lock)))
            elif pc == 'tx':
                if row_lock:
                    if lock not in (None, name):
                        continue
                    steps.append(('lock + read old', st('write', old=db_key or '-', lk=name)))
                else:
                    steps.append(('read old', st('write', old=db_key or '-', lk=lock)))
            elif pc == 'write':
                value = new
                release = None if row_lock else lock
                steps.append(('commit', st('after', err='ok', key=value if value else '__NULL__', lk=release)))
                if 'rollback' in failures:
                    steps.append(('rollback (error)', st('after', err='rolled', lk=release)))
                if 'ambiguous' in failures:
                    steps.append(('commit, but caller sees error', st('after', err='ambiguous',
                                                                      key=value if value else '__NULL__', lk=release)))
            elif pc == 'after':
                old = olds[i] if olds[i] != '-' else None
                err = errs[i]
                if err == 'ok':
                    targets = [old] if old else []
                else:
                    if name == 'R':
                        targets = []
                    elif recheck_on_error and db_key == new:
                        targets = [old] if old else []       # it did commit
                    else:
                        targets = [new]
                remaining = objects - set(targets)
                steps.append((f'delete {targets or "-"}', st('done', objs=remaining)))
                if 'delete_fail' in failures and targets:
                    steps.append(('delete lost', st('done')))
            if 'crash' in failures and pc not in ('done', 'crashed', 'start'):
                p = list(pcs); p[i] = 'crashed'
                steps.append(('crash', (tuple(p), olds, errs, objects, db_key, None if lock == name else lock)))
            for label, nxt in steps:
                nxt = nxt[:4] + ((None if nxt[4] == '__NULL__' else nxt[4]),) + nxt[5:]
                if nxt not in seen:
                    seen[nxt] = (s, f'{name}: {label}')
                    queue.append(nxt)
    return found, len(seen)


# ---------------------------------------------------------------------------
# M6e: PNG sanitizer against the real implementation
# ---------------------------------------------------------------------------

def e_run():
    try:
        cases = require_rows(run_harness('avatar-harness.mts'), 22)
        expected = {
            'valid-rgba', 'valid-rgb', 'valid-split-idat', 'ancillary-text-dropped',
            'trailing-after-zlib', 'second-zlib-stream', 'chunk-after-iend', 'bytes-after-iend',
            'ancillary-between-idat', 'wrong-size', '16-bit', 'palette', 'plte-in-truecolor',
            'interlaced', 'bad-crc', 'filter-5', 'short-pixels', 'extra-pixels',
            'truncated-zlib', 'no-idat', 'no-signature', 'bomb-200MB',
        }
        if {c.get('name') for c in cases} != expected:
            raise HarnessError('Avatar corpus cases missing or duplicated')
        for case in cases:
            expectation = ('accept' if case['name'] in {'valid-rgba', 'valid-rgb', 'valid-split-idat', 'ancillary-text-dropped'}
                           else 'observe' if case['name'] in {'trailing-after-zlib', 'second-zlib-stream'} else 'reject')
            if (case.get('expect') != expectation
                    or case.get('verdict') not in ('accept', 'reject')
                    or type(case.get('trailing')) is not int or case['trailing'] < 0
                    or type(case.get('extraChunks')) is not bool
                    or type(case.get('ms')) not in (int, float) or not 0 <= case['ms'] < float('inf')):
                raise HarnessError('Malformed avatar result')
    except HarnessError as error:
        record('M6', 'E1', 'avatar sanitizer harness', 'HOLDS', False, str(error), incomplete=True)
        return
    wrong_verdict = [f"{c['name']}: expected {c['expect']}, got {c['verdict']}" for c in cases
                     if c['expect'] in ('accept', 'reject') and c['verdict'] != c['expect']]
    record('M6', 'E1', 'accepts exactly the well-formed 256x256 RGB/RGBA PNGs of the corpus', 'HOLDS',
           bool(wrong_verdict), '; '.join(wrong_verdict))
    smuggled = [f"{c['name']}: {c['trailing']} byte(s) outside the image data are stored and served"
                for c in cases if c['verdict'] == 'accept' and (c['trailing'] > 0 or c['extraChunks'])]
    record('M6', 'E2', 'an accepted avatar carries nothing but the image (no bytes beyond the pixel stream)',
           'HOLDS', bool(smuggled), '; '.join(smuggled))
    bomb = [c for c in cases if c['name'].startswith('bomb')]
    slow = [f"{c['name']}: {c['ms']:.0f} ms" for c in bomb if c['verdict'] != 'reject' or c['ms'] > 500]
    record('M6', 'E3', 'the corpus decompression bomb is rejected within 500 ms', 'HOLDS', bool(slow), '; '.join(slow))


# ---------------------------------------------------------------------------

def concurrent_noop(recheck: bool):
    """Two requests saving B over A, and one warning; enumerate all preflight /
    locked-write / warning interleavings. A real content change is a ghost
    timestamp separate from the persisted timestamp used to admit appeals.
    The same schedule applies to replacing or removing an avatar.
    """
    initial = (0, 0, 0, None, (0, 0), 0)  # content, actual change, stamp, warning, PCs, clock
    queue = deque([(initial, [])])
    seen = {initial}
    while queue:
        (content, changed, stamp, warning, pcs, clock), trace = queue.popleft()
        if warning is not None and stamp > warning and changed <= warning:
            return trace
        moves = []
        if warning is None:
            moves.append(('warn current content', (content, changed, stamp, clock + 1, pcs, clock + 1)))
        for i, pc in enumerate(pcs):
            next_pcs = list(pcs)
            if pc == 0:
                next_pcs[i] = 2 if content == 1 else 1
                moves.append((f'save{i}: preflight reads {content}',
                              (content, changed, stamp, warning, tuple(next_pcs), clock + 1)))
            elif pc == 1:
                next_pcs[i] = 2
                new_stamp = clock + 1 if content != 1 or not recheck else stamp
                new_change = clock + 1 if content != 1 else changed
                moves.append((f'save{i}: locked save B (current={content})',
                              (1, new_change, new_stamp, warning, tuple(next_pcs), clock + 1)))
        for label, state in moves:
            if state not in seen:
                seen.add(state)
                queue.append((state, trace + [label]))
    return []


def run(depth: int = 5) -> None:
    print('== M6: profiles, avatars and profile warnings ==')
    impl = Rules()
    race = concurrent_noop(recheck=True)
    record('M6', 'A3-concurrent', 'stale preflight reads cannot count an identical save after a warning', 'HOLDS',
           bool(race), witness=race)
    race = concurrent_noop(recheck=False)
    record('M6', 'A3-concurrent-ctl', 'without the locked recheck, two identical saves bypass the change requirement',
           'CONTROL', bool(race), witness=race)

    found, states = a_explore(impl, depth)
    print(f'  M6a implementation: {states} states (depth {depth})')
    record('M6', 'A1', 'one clearing request per account, across all workspaces', 'HOLDS', 'A1' in found,
           witness=found.get('A1'))
    record('M6', 'A4', 'only MANAGE_MEMBERS/owner can warn, clear or deny, and only strictly lower members', 'HOLDS',
           'A4' in found, witness=found.get('A4'))
    record('M6', 'A5', 'every warning on a current member can be cleared by someone in that workspace', 'HOLDS',
           'A5' in found, witness=found.get('A5'))
    record('M6', 'A6', 'leaving, rejoining or editing never removes a warning', 'HOLDS', 'A6' in found,
           witness=found.get('A6'))
    record('M6', 'A3', 'a request is possible only after the profile actually changed since the warning', 'HOLDS',
           'A3' in found, witness=found.get('A3'))
    record('M6', 'A7', 'a warned member with audit-log access can see who warned them', 'LIMIT', 'A7' in found,
           'accepted: audit-log readers must be trusted; owners remove the permission otherwise', found.get('A7'))
    fixed, _ = a_explore(Rules(change_check='revision', skew=2), depth)
    record('M6', 'A3r', 'alternative: a profile revision is also immune to clock differences', 'HOLDS',
           'A3' in fixed or 'A1' in fixed, witness=fixed.get('A3'))

    for check, title, rules, prop in (
        ('A4-ctl', 'without the rank rule a lower manager can warn a higher one', Rules(rank_check=False), 'A4'),
        ('A1-ctl', 'with a per-workspace allowance two requests succeed', Rules(global_once=False), 'A1'),
        ('A6-ctl', 'if leaving deleted warnings, leave+rejoin would clear one', Rules(cascade_on_leave=True), 'A6'),
        ('A5-ctl', 'if ownership could move to a warned member, nobody could clear it', Rules(owner_transfer=True), 'A5'),
        ('A3-ctl1', 'before the fix: an unchanged save counted as a change', Rules(noop_edit_bumps=True), 'A3'),
        ('A3-ctl2', 'before the fix: an app clock ahead of the DB clock counted an earlier edit', Rules(skew=2), 'A3'),
        ('A3-ctl3', 'before the fix: the same picture uploaded while the stored one could not be read counted as '
                    'a change', Rules(unreadable_avatar_counts=True), 'A3'),
    ):
        control, _ = a_explore(rules, depth)
        record('M6', check, title, 'CONTROL', prop in control, witness=control.get(prop))

    worst, witness = b_explore(row_lock=True)
    record('M6', 'B1', 'concurrent requests in two workspaces: still one (users row FOR UPDATE)', 'HOLDS', worst > 1, witness=witness)
    worst, witness = b_explore(row_lock=False)
    record('M6', 'B1-ctl', 'without the row lock both concurrent requests succeed', 'CONTROL', worst > 1, witness=witness)

    found, states = c_explore(fixed_client=True, route_check=True)
    print(f'  M6c implementation: {states} states')
    record('M6', 'V1', 'with an up-to-date client, a warned member\'s avatar is never shown in that workspace', 'HOLDS',
           'V1' in found, 'warned-users lists former members too', found.get('V1'))
    record('M6', 'V2', 'until the change reaches a client, its old member list still shows the avatar', 'LIMIT',
           'V2' in found, witness=found.get('V2'))
    record('M6', 'V3', 'the avatar route serves only the owner and users sharing a workspace', 'HOLDS', 'V3' in found,
           witness=found.get('V3'))
    record('M6', 'V4', 'a viewer keeps an already-fetched avatar after no longer sharing a workspace', 'LIMIT',
           'V4' in found, 'in-memory cache for the session; HTTP cache up to 24 h', found.get('V4'))
    control, _ = c_explore(fixed_client=False, route_check=True)
    record('M6', 'V1-ctl', 'before the fix: a former member\'s messages showed the avatar again', 'CONTROL',
           'V1' in control, witness=control.get('V1'))
    control, _ = c_explore(fixed_client=True, route_check=False)
    record('M6', 'V3-ctl', 'without the shared-workspace check anyone can fetch it', 'CONTROL', 'V3' in control,
           witness=control.get('V3'))

    found, states = d_explore(row_lock=True, recheck_on_error=False, failures=frozenset({'rollback'}))
    print(f'  M6d implementation (clean failures): {states} states')
    record('M6', 'S1', 'with clean commits/rollbacks the row never points at a missing object', 'HOLDS', 'S1' in found,
           witness=found.get('S1'))
    record('M6', 'S2', 'with clean commits/rollbacks no object is left unreferenced', 'HOLDS', 'S2' in found,
           witness=found.get('S2'))
    fixed, _ = d_explore(row_lock=True, recheck_on_error=True, failures=frozenset({'rollback', 'ambiguous', 'delete_fail', 'crash'}))
    record('M6', 'S1a', 'with ambiguous commits, lost deletes and crashes the row never points at a missing object', 'HOLDS',
           'S1' in fixed, 'the error path re-reads the row (FOR UPDATE) before deleting the new object', fixed.get('S1'))
    control, _ = d_explore(row_lock=True, recheck_on_error=False, failures=frozenset({'rollback', 'ambiguous'}))
    record('M6', 'S1a-ctl', 'before the fix: an ambiguous commit deleted the referenced object', 'CONTROL',
           'S1' in control, witness=control.get('S1'))
    record('M6', 'S3', 'crashes or lost deletes leave unreferenced objects behind', 'LIMIT', 'S3' in fixed,
           'storage leak only; bounded by 10 uploads/hour/user', fixed.get('S3'))
    control, _ = d_explore(row_lock=False, recheck_on_error=False, failures=frozenset())
    record('M6', 'S2-ctl', 'without FOR UPDATE two concurrent uploads orphan an object', 'CONTROL', 'S2' in control,
           witness=control.get('S2'))

    e_run()


if __name__ == '__main__':
    run()
