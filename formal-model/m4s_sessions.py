"""M4s: account credentials and sessions under concurrent requests (2026-10-09).

Written from the implementation at commit ce09b19:

  step-up use (T1)   middleware/step-up.ts -> consumeStepUp: the session is
                     live, bound to an approved device, the grant matches.
  mutation (T2)      auth.service.ts changePassword / setPasswordLogin /
                     revokeSession(s): one audited transaction, run after the
                     route's own work (new-password KDF, audit queue).
  operator reset     scripts/reset-password.ts -> account-state.service.ts:
                     new password, password login on, every session deleted,
                     passkeys and devices kept. Exclusive DRAIN lock: it runs
                     between audited transactions, never inside one.
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


def successors(s: St, v: V):
    out = []
    # New requests from a live session of U or X.
    if s.started < v.max_started:
        for owner in ('U', 'X'):
            for session in owner_sessions(s, owner):
                if budget_key(session, v) in s.spent:
                    continue                  # the step-up is refused (429)
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
        t = s._replace(password='pO', known=frozenset({'U'}), sessions=frozenset(), events=s.events | {'reset'})
        out.append(('operator: reset-password (new password to U, every session ends)',
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


def run() -> None:
    print('== M4s: credentials, sessions and sockets under concurrent requests ==')
    results = {}
    for name, v in (('implementation', V()), ('attacker passkey', V(attacker_passkey=True)),
                    ('before the fix', V(t2_session_check=False, socket_recheck=False, budget_per_session=False))):
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
    check('AS3-pk', 'a passkey X registered before the reset still signs X in afterwards (the reset keeps passkeys '
                    'and devices)', 'LIMIT', 'AS3-pk', 'attacker passkey',
          'reset-password resets the password and ends sessions; revoke X\'s devices and passkeys as well')
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


if __name__ == '__main__':
    run()
