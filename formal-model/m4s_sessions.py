"""M4s: account credentials and sessions under concurrent requests (2026-10-09, 2026-10-26).

Written from the implementation at commit ce09b19, updated for 619f934:

  step-up use (T1)   middleware/step-up.ts -> consumeStepUp: the session is
                     live, bound to an approved device, the grant matches.
                     finishStepUp takes a passkey of the account's owner, or
                     the current password only while the account has no
                     passkey (PASSKEY_REQUIRED).
  mutation (T2)      auth.service.ts changePassword / revokeSession(s): one
                     audited transaction, run after the route's own work
                     (new-password KDF, audit queue). assertStepUpStillValid
                     checks the session again.
  operator reset     scripts/reset-password.ts -> account-state.service.ts:
                     new password, password login on, every session and
                     every passkey deleted (since 2026-10-09); devices
                     nobody approved are retired by the server, approved
                     ones are kept: revoking one needs a device-signed
                     entry.
                     Exclusive DRAIN lock: it runs between audited
                     transactions, never inside one.
  socket handshake   websocket/index.ts: io.use reads the session, then the
                     connection handler joins `session:<id>`; revocation
                     deletes the row, then disconnects that room.
  budgets            routes/passkeys.ts: confirmations (240 requests) and
                     failed confirmations (10) per 15 minutes. A session can
                     use up its budget at will, again in every window.

Audited transactions are serialized (one gate slot), so each T2, each
revocation and the reset are atomic steps; the gaps are between T1 and T2 of
one request and between the handshake's read and its room join.

Actors: the user U (session SU), an attacker X holding a stolen session SX
and the original password p0 (as after a phishing or a stolen laptop).

M4p (2026-10-26) adds what a passkey X registered during a takeover can do
(c55ea5e, 3bfc550): sessions record the passkey they were opened with,
deleting a passkey ends them (passkey.service deletePasskey), a passkey login
commits only while its passkey still exists (the counter compare-and-swap in
advanceCounter), and the commit of every confirmed change, a passkey
registration included, checks again that the credential used still exists
(validateStepUpAuthentication).
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import NamedTuple

from common import record


class St(NamedTuple):
    password: str                 # current password
    known: frozenset              # who knows it
    sessions: frozenset           # live sessions: (id, owner)
    passkeys: frozenset           # owners with a registered passkey
    requests: tuple               # (owner, session, kind, arg, phase) phase: 'T1' -> 'T2'
    sockets: tuple                # (session, phase) phase: 'read' -> 'joined' | 'checked' ; or None when closed
    next_id: int
    events: frozenset             # ghost: 'user-changed', 'reset'
    started: int
    stale_commit: bool            # ghost: a T2 committed for a session that was no longer live
    spent: frozenset = frozenset()  # confirmation budgets X keeps used up, by key


@dataclass(frozen=True)
class V:
    t2_session_check: bool = True      # CONTROL: False commits T2 without rechecking (before 2026-10-09)
    socket_recheck: bool = True        # CONTROL: False skips the recheck after the room join (before 2026-10-09)
    budget_per_session: bool = True    # CONTROL: False counts confirmations per account (before 2026-10-09)
    reset_removes_passkeys: bool = True  # CONTROL: False keeps every passkey on reset (before 2026-10-09)
    attacker_passkey: bool = False     # the attacker registered a passkey beforehand
    max_started: int = 4
    reset: bool = True


def initial(v: V) -> St:
    return St('p0', frozenset({'U', 'X'}), frozenset({('SU', 'U'), ('SX', 'X')}),
              frozenset({'X'}) if v.attacker_passkey else frozenset(), (), (), 0, frozenset(), 0, False)


def live(s: St, session: str) -> bool:
    return any(sid == session for sid, _ in s.sessions)


def owner_sessions(s: St, owner: str):
    return [sid for sid, o in s.sessions if o == owner]


def budget_key(session: str, v: V) -> str:
    return session if v.budget_per_session else 'account'


def _disconnect(s: St, sessions: set) -> St:
    """Revocation closes the sockets in each `session:<id>` room."""
    return s._replace(sockets=tuple(None if sock and sock[1] in ('joined', 'checked') and sock[0] in sessions else sock
                                    for sock in s.sockets))


def can_confirm(s: St, owner: str) -> bool:
    """finishStepUp: a passkey of the owner, or the current password while the account has none."""
    return owner in s.passkeys if s.passkeys else owner in s.known


def successors(s: St, v: V):
    out = []
    # New requests from a live session of U or X.
    if s.started < v.max_started:
        for owner in ('U', 'X'):
            for session in owner_sessions(s, owner):
                if budget_key(session, v) in s.spent or not can_confirm(s, owner):
                    continue                  # the step-up is refused (429, PASSKEY_REQUIRED, a wrong password)
                pw = 'pU' if owner == 'U' else 'pX'
                if not any(r[0] == owner and r[2] == 'change' for r in s.requests):
                    out.append((f'{owner} on {session}: PUT /auth/password ({pw}) passes step-up (T1)',
                                s._replace(requests=s.requests + ((owner, session, 'change', pw, 'T2'),), started=s.started + 1)))
                if owner == 'U':
                    for target in owner_sessions(s, 'X'):
                        out.append((f'U on {session}: DELETE /auth/sessions/{target} passes step-up (T1)',
                                    s._replace(requests=s.requests + ((owner, session, 'revoke', target, 'T2'),), started=s.started + 1)))
        # A socket handshake for one of X's sessions (X keeps reconnecting).
        for session in owner_sessions(s, 'X'):
            if not any(sock and sock[0] == session for sock in s.sockets):
                out.append((f'X opens a socket for {session} (handshake reads the session)',
                            s._replace(sockets=s.sockets + ((session, 'read'),), started=s.started + 1)))
        # Logins with what an actor knows.
        for owner in ('U', 'X'):
            if owner in s.known and not owner_sessions(s, owner):
                sid = f'{owner}{s.next_id}'
                out.append((f'{owner} logs in with the password', s._replace(sessions=s.sessions | {(sid, owner)},
                                                                         next_id=s.next_id + 1, started=s.started + 1)))
            if owner in s.passkeys and not owner_sessions(s, owner):
                sid = f'{owner}{s.next_id}'
                out.append((f'{owner} logs in with a passkey', s._replace(sessions=s.sessions | {(sid, owner)},
                                                                      next_id=s.next_id + 1, started=s.started + 1)))
    # X uses up the confirmation budget of its session (wrong passwords, challenge requests).
    for session in owner_sessions(s, 'X'):
        if budget_key(session, v) not in s.spent:
            out.append((f'X on {session}: wrong passwords and challenge requests use up the confirmation budget',
                        s._replace(spent=s.spent | {budget_key(session, v)})))
    # T2 of a pending request: one audited transaction.
    for i, (owner, session, kind, arg, _) in enumerate(s.requests):
        rest = s.requests[:i] + s.requests[i + 1:]
        if v.t2_session_check and not live(s, session):
            out.append((f'{owner}: T2 refused, {session} is gone', s._replace(requests=rest)))
            continue
        stale = s.stale_commit or not live(s, session)
        if kind == 'change':
            ended = {sid for sid, _ in s.sessions if sid != session}
            t = s._replace(password=arg, known=frozenset({owner}), requests=rest, stale_commit=stale,
                           sessions=frozenset(e for e in s.sessions if e[0] == session),
                           events=s.events | ({'user-changed'} if owner == 'U' else set()))
            out.append((f'{owner}: T2 commits the password change ({arg}), ends {sorted(ended)}', _disconnect(t, ended)))
        elif kind == 'revoke':
            t = s._replace(requests=rest, stale_commit=stale, sessions=frozenset(e for e in s.sessions if e[0] != arg))
            out.append((f'{owner}: T2 commits revocation of {arg}', _disconnect(t, {arg})))
    # Operator reset (between audited transactions).
    if v.reset and 'reset' not in s.events:
        t = s._replace(password='pO', known=frozenset({'U'}), sessions=frozenset(), events=s.events | {'reset'},
                       passkeys=frozenset() if v.reset_removes_passkeys else s.passkeys)
        out.append(('operator: reset-password (new password to U, every session ends'
                    + (', every passkey removed)' if v.reset_removes_passkeys else ')'),
                    _disconnect(t, {sid for sid, _ in s.sessions})))
    # Socket handshake steps.
    for i, sock in enumerate(s.sockets):
        if sock is None:
            continue
        session, phase = sock
        sockets = list(s.sockets)
        if phase == 'read':
            if not live(s, session):
                sockets[i] = None
                out.append((f'handshake for {session}: session gone, refused', s._replace(sockets=tuple(sockets))))
            else:
                sockets[i] = (session, 'device')
                out.append((f'handshake for {session}: session read', s._replace(sockets=tuple(sockets))))
        elif phase == 'device':
            sockets[i] = (session, 'joined')
            out.append((f'socket for {session}: connection handler joins session:{session}', s._replace(sockets=tuple(sockets))))
        elif phase == 'joined' and v.socket_recheck:
            sockets[i] = (session, 'checked') if live(s, session) else None
            out.append((f'socket for {session}: rechecks its session', s._replace(sockets=tuple(sockets))))
    return out


def violations(s: St, v: V):
    out = []
    if s.stale_commit:
        out.append(('AS1', 'a sensitive change committed for a session that had already ended'))
    if 'user-changed' in s.events and 'X' not in s.passkeys and ('X' in s.known or owner_sessions(s, 'X')):
        out.append(('AS2', f'after U changed the password, X knows the current password ({s.password}) or holds a session'))
    if 'reset' in s.events and ('X' in s.known or owner_sessions(s, 'X')):
        prop = 'AS3-pk' if 'X' in s.passkeys and 'X' not in s.known else 'AS3'
        out.append((prop, f'after the operator reset, X knows the current password ({s.password}) or holds a session'))
    if owner_sessions(s, 'X') and any(budget_key(sid, v) in s.spent for sid in owner_sessions(s, 'U')):
        out.append(('AS4', 'X used up the confirmations of U\'s session: U can neither confirm a change nor revoke X'))
    for sock in s.sockets:
        if sock and sock[1] in ('joined', 'checked') and not live(s, sock[0]):
            settled = not v.socket_recheck or sock[1] == 'checked'
            if settled:
                out.append(('WS1', f'a connected socket remains for ended session {sock[0]}'))
    return out


def bfs(v: V, stop=frozenset()):
    start = initial(v)
    parent = {start: None}
    found = {}
    queue = deque([start])
    while queue:
        s = queue.popleft()
        hits = violations(s, v)
        for prop, message in hits:
            found.setdefault(prop, (s, message))
        if stop and stop <= found.keys():
            break
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


# ---------------------------------------------------------------------------
# M4p: passkeys a takeover added, their sessions and their deletion
# ---------------------------------------------------------------------------

class PSt(NamedTuple):
    password: str                 # 'p0' | 'pU' | 'pX'
    known: frozenset              # who knows it
    passkeys: frozenset           # 'kU', 'kX', 'kX2' (the letter names the owner)
    sessions: frozenset           # (id, owner, via) via: 'pw' or the passkey it was opened with
    requests: tuple               # (owner, session, kind, arg, credential) waiting for T2 (or a passkey login's commit)
    next_id: int
    started: int
    user_changed: bool            # U's password change is the latest one
    stale: str = ''               # ghost: a commit whose confirming passkey was already deleted


@dataclass(frozen=True)
class PV:
    t2_credential_check: bool = True   # CONTROL: False checks only the session at commit (before 2026-10-09 / c55ea5e)
    register_recheck: bool = True      # CONTROL: False registers without checking the confirmation again (before 3bfc550)
    delete_ends_sessions: bool = True  # CONTROL: False deletes only the passkey row (before c55ea5e)
    login_counter_cas: bool = True     # CONTROL: False commits a passkey login whose passkey is gone
    owner_passkey: bool = True         # U has a passkey of its own
    max_started: int = 5


def p_initial(v: PV) -> PSt:
    keys = frozenset({'kU', 'kX'}) if v.owner_passkey else frozenset({'kX'})
    return PSt('p0', frozenset({'U', 'X'}), keys, frozenset({('SU', 'U', 'pw'), ('SX', 'X', 'pw')}), (), 0, 0, False)


def _owner_of(key: str) -> str:
    return key[1]


def p_live(s: PSt, session: str) -> bool:
    return any(sid == session for sid, _, _ in s.sessions)


def p_credentials(s: PSt, owner: str):
    """What finishStepUp accepts: an own passkey, or the current password while the account has none."""
    if s.passkeys:
        return [k for k in sorted(s.passkeys) if _owner_of(k) == owner]
    return [f'pw:{s.password}'] if owner in s.known else []


def p_credential_holds(s: PSt, credential: str) -> bool:
    """validateStepUpAuthentication: the same passkey, or the same password and no passkey."""
    if credential.startswith('pw:'):
        return not s.passkeys and credential[3:] == s.password
    return credential in s.passkeys


def p_successors(s: PSt, v: PV):
    out = []
    if s.started < v.max_started:
        for sid, owner, _ in sorted(s.sessions):
            for credential in p_credentials(s, owner):
                def request(kind, arg, label):
                    if not any(r[0] == owner and r[2] == kind for r in s.requests):
                        out.append((f'{owner} on {sid}: {label} passes step-up with {credential} (T1)',
                                    s._replace(requests=s.requests + ((owner, sid, kind, arg, credential),),
                                               started=s.started + 1)))
                request('change', 'p' + owner, 'PUT /auth/password')
                if owner == 'U':
                    for key in sorted(s.passkeys):
                        if _owner_of(key) == 'X':
                            request('delete', key, f'DELETE /passkeys/{key}')
                elif 'kX2' not in s.passkeys:
                    request('register', 'kX2', 'registers passkey kX2')
        for owner in ('U', 'X'):
            if any(o == owner for _, o, _ in s.sessions):
                continue
            if owner in s.known:
                out.append((f'{owner} logs in with the password', s._replace(
                    sessions=s.sessions | {(f'{owner}{s.next_id}', owner, 'pw')}, next_id=s.next_id + 1,
                    started=s.started + 1)))
            for key in sorted(s.passkeys):
                if _owner_of(key) == owner and not any(r[2] == 'login' and r[0] == owner for r in s.requests):
                    out.append((f'{owner} signs in with {key} (assertion verified)', s._replace(
                        requests=s.requests + ((owner, None, 'login', key, key),), started=s.started + 1)))
    for i, (owner, sid, kind, arg, credential) in enumerate(s.requests):
        rest = s.requests[:i] + s.requests[i + 1:]
        if kind == 'login':
            if v.login_counter_cas and arg not in s.passkeys:
                out.append((f'{owner}: login with {arg} refused (the passkey is gone)', s._replace(requests=rest)))
                continue
            out.append((f'{owner}: login with {arg} commits', s._replace(
                requests=rest, sessions=s.sessions | {(f'{owner}{s.next_id}', owner, arg)}, next_id=s.next_id + 1)))
            continue
        if not p_live(s, sid):
            out.append((f'{owner}: T2 refused, {sid} is gone', s._replace(requests=rest)))
            continue
        check = v.register_recheck if kind == 'register' else v.t2_credential_check
        if check and not p_credential_holds(s, credential):
            out.append((f'{owner}: T2 refused, {credential} no longer holds (428)', s._replace(requests=rest)))
            continue
        stale = s.stale or (f'{owner} {kind} committed after {credential} was deleted'
                            if not credential.startswith('pw:') and credential not in s.passkeys else '')
        if kind == 'change':
            ended = {(i2, o, via) for i2, o, via in s.sessions if i2 != sid}
            out.append((f'{owner}: T2 commits the password change ({arg}), ends {sorted(e[0] for e in ended)}',
                        s._replace(password=arg, known=frozenset({owner}), requests=rest, stale=stale,
                                   sessions=s.sessions - ended, user_changed=owner == 'U')))
        elif kind == 'delete':
            if len(s.passkeys) <= 1:
                out.append((f'U: T2 refused, {arg} is the last passkey', s._replace(requests=rest)))
                continue
            ended = {e for e in s.sessions if e[2] == arg and e[0] != sid} if v.delete_ends_sessions else set()
            out.append((f'U: T2 deletes {arg}' + (f', ends {sorted(e[0] for e in ended)}' if ended else ''),
                        s._replace(passkeys=s.passkeys - {arg}, sessions=s.sessions - ended, requests=rest,
                                   stale=stale)))
        elif kind == 'register':
            out.append((f'X: T2 registers {arg}', s._replace(passkeys=s.passkeys | {arg}, requests=rest, stale=stale)))
    return out


def p_violations(s: PSt):
    out = []
    for sid, owner, via in s.sessions:
        if via != 'pw' and via not in s.passkeys:
            out.append(('PK1', f'session {sid} of {owner} opened with {via} outlives the passkey'))
    if s.stale:
        out.append(('AS1-pk', s.stale))
    x_keys = any(_owner_of(k) == 'X' for k in s.passkeys)
    if s.user_changed and not x_keys and ('X' in s.known or any(o == 'X' for _, o, _ in s.sessions)):
        out.append(('AS2-pk', f'after U changed the password and deleted X\'s passkeys, X knows the password '
                              f'({s.password}) or holds a session'))
    return out


def p_bfs(v: PV):
    start = p_initial(v)
    parent = {start: None}
    found = {}
    queue = deque([start])
    while queue:
        s = queue.popleft()
        for prop, message in p_violations(s):
            found.setdefault(prop, (s, message))
        for label, nxt in p_successors(s, v):
            if nxt not in parent:
                parent[nxt] = (s, label)
                queue.append(nxt)
    return parent, found


def passkey_run() -> None:
    results = {}
    for name, v in (('implementation', PV()), ('deletion keeps sessions', PV(delete_ends_sessions=False)),
                    ('login without the counter check', PV(login_counter_cas=False)),
                    ('commit checks the session only', PV(t2_credential_check=False)),
                    ('registration without the recheck', PV(register_recheck=False)),
                    ('owner without a passkey', PV(owner_passkey=False))):
        results[name] = p_bfs(v)
        print(f'  M4p {name}: {len(results[name][0]):,} states')

    def check(check_id, title, expect, prop, name):
        parent, found = results[name]
        hit = found.get(prop)
        record('M4s', check_id, title, expect, hit is not None,
               witness=(trace(parent, hit[0]) + ['=> ' + hit[1]]) if hit else [])

    check('PK1', 'no session opened with a passkey outlives the passkey (a login still committing included)', 'HOLDS',
          'PK1', 'implementation')
    check('AS1-pk', 'a change confirmed with a passkey, a passkey registration included, commits only while that '
                    'passkey exists', 'HOLDS', 'AS1-pk', 'implementation')
    check('AS2-pk', "once U changed the password and deleted the passkeys X added, X never knows the password or "
                    'holds a session again', 'HOLDS', 'AS2-pk', 'implementation')
    check('PK1-ctl', 'before the 2026-10-22 fix: deleting a passkey left the sessions opened with it', 'CONTROL',
          'PK1', 'deletion keeps sessions')
    check('AS2-pk-ctl', 'before the fix: a session X opened with its passkey survived U changing the password and '
                        'deleting that passkey', 'CONTROL', 'AS2-pk', 'deletion keeps sessions')
    check('PK1-login-ctl', 'without the counter compare-and-swap, a passkey login verified before the deletion commits '
                           'after it', 'CONTROL', 'PK1', 'login without the counter check')
    check('AS1-pk-ctl', 'without the credential check at commit, X\'s change confirmed with its passkey commits after U '
                        'deleted that passkey', 'CONTROL', 'AS1-pk', 'commit checks the session only')
    check('AS1-pk-register-ctl', 'before 3bfc550: a passkey registration confirmed with a passkey that was then '
                                 'deleted still committed', 'CONTROL', 'AS1-pk', 'registration without the recheck')
    parent, _ = results['owner without a passkey']
    cleared = [state for state in parent if 'kX' not in state.passkeys]
    record('M4s', 'AS4-pk', 'while X has a passkey and U has none, U cannot confirm anything (a confirmation needs a '
           'passkey), so only the operator reset removes X\'s passkey', 'LIMIT', not cleared,
           'finishStepUp refuses the password while the account has a passkey (PASSKEY_REQUIRED)')


def run() -> None:
    print('== M4s: credentials, sessions and sockets under concurrent requests ==')
    results = {}
    for name, v in (('implementation', V()), ('attacker passkey', V(attacker_passkey=True)),
                    ('before the fix', V(t2_session_check=False, socket_recheck=False, budget_per_session=False)),
                    ('attacker passkey, before the fix', V(attacker_passkey=True, reset_removes_passkeys=False))):
        results[name] = bfs(v)
        print(f'  M4s {name}: {len(results[name][0]):,} states')

    def check(check_id, title, expect, prop, name, detail=''):
        parent, found = results[name]
        hit = found.get(prop)
        record('M4s', check_id, title, expect, hit is not None, detail,
               witness=(trace(parent, hit[0]) + ['=> ' + hit[1]]) if hit else [])

    check('AS1', 'a password change, password-login change or session revocation commits only while the session '
                 'that confirmed it is live', 'HOLDS', 'AS1', 'implementation')
    check('AS2', 'once U changed the password from its session, X (without a passkey) never knows the current '
                 'password or holds a session again', 'HOLDS', 'AS2', 'implementation')
    check('AS3', 'after an operator reset, X (without a passkey) never knows the current password or holds a session',
          'HOLDS', 'AS3', 'implementation')
    check('WS1', 'once a session ends and its sockets are closed, no socket of that session stays connected',
          'HOLDS', 'WS1', 'implementation')
    check('AS4', 'a session that uses up its confirmations (wrong passwords, challenge requests) never keeps U\'s own '
                 'session from confirming, for example to revoke it', 'HOLDS', 'AS4', 'implementation')
    for prop in ('AS3', 'AS3-pk'):
        check(prop if prop == 'AS3-pk' else 'AS3-pk-sessions',
              'after an operator reset, X never signs in again, even with a passkey it registered before (the reset '
              'removes passkeys)' if prop == 'AS3-pk' else
              'with a passkey of X registered before, X still never knows the password or holds a session after '
              'the reset', 'HOLDS', prop, 'attacker passkey')
    check('AS1-ctl', 'before the fix: a change confirmed before its session ended still committed', 'CONTROL',
          'AS1', 'before the fix')
    check('AS2-ctl', 'before the fix: X\'s change confirmed before U\'s change committed after it and ended U\'s '
                     'session', 'CONTROL', 'AS2', 'before the fix')
    check('AS3-ctl', 'before the fix: X\'s change confirmed before the operator reset replaced the reset password',
          'CONTROL', 'AS3', 'before the fix')
    check('WS1-ctl', 'before the fix: a socket whose handshake read the session before it ended stayed connected',
          'CONTROL', 'WS1', 'before the fix')
    check('AS4-ctl', 'before the fix: the budgets were counted per account, so X\'s stolen session kept U from '
                     'confirming and from revoking it', 'CONTROL', 'AS4', 'before the fix')
    check('AS3-pk-ctl', 'before the fix: the reset kept every passkey, and the one X registered signed X in again',
          'CONTROL', 'AS3-pk', 'attacker passkey, before the fix')
    passkey_run()


if __name__ == '__main__':
    run()
