"""M4: devices, approval and sessions — attacker capability analysis.

Mirrors device.service.ts (registerDevice, approveDevice, revokeDevice),
recovery.service.ts (restoreDevice), auth/passkey session creation and
account disabling:

  register  needs a valid session and either the current password
            (password sessions always, passkey sessions optionally) or a
            passkey session younger than 10 minutes (F-P2F-012).
            The first device the account ever has is approved at once (TOFU).
  approve   signed by an approved, non-revoked device of the same account,
            through a session bound to that device; never self-approval.
  restore   recovery code + a session bound to the unapproved device.
  revoke    by an approved device; kills sessions bound to the revoked device;
            a revoked identity is never approved again.
  disable   operator action; every session becomes invalid.

For every combination of attacker capabilities the model computes whether the
attacker can end up controlling an approved device, and compares that with the
specification:
    reachable  <=>  can_register and (recovery_code or account_has_no_device)
    can_register = knows_password or fresh_passkey_cookie
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace
from itertools import product

from common import record

CAPABILITIES = ('password', 'recovery_code', 'stale_cookie', 'fresh_cookie')


@dataclass(frozen=True)
class State:
    devices: tuple          # ((id, controller, status), ...)
    sessions: frozenset     # {(holder, method, fresh, bound_device)}; equal sessions are indistinguishable
    ever_had_device: bool
    disabled: bool = False


def initial(fresh_account: bool) -> State:
    if fresh_account:
        return State(devices=(), sessions=frozenset({('L', 'passkey', True, None)}), ever_had_device=False)
    return State(devices=(('L1', 'L', 'approved'),), sessions=frozenset({('L', 'passkey', True, 'L1')}), ever_had_device=True)


MAX_SESSIONS = 4


def _add(state, session):
    if session in state.sessions or len(state.sessions) >= MAX_SESSIONS:
        return None
    return replace(state, sessions=state.sessions | {session})


@dataclass(frozen=True)
class Rules:
    passkey_freshness: bool = True     # F-P2F-012
    tofu: bool = True
    user_can_be_tricked: bool = False  # L approves a device it does not control


def transitions(state: State, caps: frozenset, rules: Rules):
    if state.disabled:
        return
    status = {d: s for d, _, s in state.devices}
    controller = {d: c for d, c, _ in state.devices}
    knows_password = {'L': True, 'Att': 'password' in caps}
    has_recovery = {'L': True, 'Att': 'recovery_code' in caps}

    # logins
    for holder in ('L', 'Att'):
        if knows_password[holder]:
            nxt = _add(state, (holder, 'password', False, None))
            if nxt:
                yield f'{holder}: password login', nxt
    nxt = _add(state, ('L', 'passkey', True, None))
    if nxt:
        yield 'L: passkey login', nxt

    # stolen cookies (copies of one of L's sessions)
    for holder, method, fresh, bound in state.sessions:
        if holder != 'L' or method != 'passkey':
            continue
        wanted = ('fresh_cookie' in caps and fresh) or ('stale_cookie' in caps and not fresh)
        nxt = _add(state, ('Att', method, fresh, bound)) if wanted else None
        if nxt:
            yield f'Att: steals {"fresh" if fresh else "stale"} passkey cookie', nxt

    # time passes: passkey sessions age past the enrollment window
    if any(fresh for _, _, fresh, _ in state.sessions):
        aged = frozenset((h, m, False, b) for h, m, _, b in state.sessions)
        yield 'time passes (10 minutes)', replace(state, sessions=aged)

    # register a device on a session
    for session in sorted(state.sessions, key=repr):
        holder, method, fresh, bound = session
        allowed = knows_password[holder] or (method == 'passkey' and (fresh or not rules.passkey_freshness))
        if not allowed or sum(1 for _, c, _ in state.devices if c == holder) >= 1:
            continue
        device = f'{holder}{len(state.devices) + 1}'
        approved = rules.tofu and not state.ever_had_device
        sessions = (state.sessions - {session}) | {(holder, method, fresh, device)}
        yield f'{holder}: registers {device} ({"approved by TOFU" if approved else "pending approval"})', replace(
            state, devices=state.devices + ((device, holder, 'approved' if approved else 'unapproved'),),
            sessions=sessions, ever_had_device=True)

    # approve / restore / revoke
    for holder, _, _, bound in sorted(state.sessions, key=repr):
        if bound is None or status.get(bound) is None:
            continue
        if status[bound] == 'approved' and controller[bound] == holder:
            for target, _, s in state.devices:
                honest_choice = holder == 'Att' or controller[target] == 'L' or rules.user_can_be_tricked
                if s == 'unapproved' and target != bound and honest_choice:
                    yield f'{holder}: approves {target} with {bound}', replace(
                        state, devices=tuple((d, c, 'approved' if d == target else st) for d, c, st in state.devices))
            for target, _, s in state.devices:
                if s == 'approved' and target != bound:
                    yield f'{holder}: revokes {target}', replace(
                        state, devices=tuple((d, c, 'revoked' if d == target else st) for d, c, st in state.devices),
                        sessions=frozenset(x for x in state.sessions if x[3] != target))
        if status[bound] == 'unapproved' and controller[bound] == holder and has_recovery[holder]:
            yield f'{holder}: restores {bound} with the recovery code', replace(
                state, devices=tuple((d, c, 'approved' if d == bound else st) for d, c, st in state.devices))

    yield 'operator disables the account', replace(state, disabled=True, sessions=frozenset())


def explore(caps, rules, fresh_account):
    start = initial(fresh_account)
    parent = {start: None}
    queue = deque([start])
    while queue:
        state = queue.popleft()
        for label, nxt in transitions(state, caps, rules):
            if nxt not in parent:
                parent[nxt] = (state, label)
                queue.append(nxt)
    return parent


def trace(parent, state):
    steps = []
    while parent[state]:
        state, label = parent[state]
        steps.append(label)
    return list(reversed(steps))


def attacker_wins(state):
    return any(c == 'Att' and s == 'approved' for _, c, s in state.devices)


def spec(caps, fresh_account):
    can_register = 'password' in caps or 'fresh_cookie' in caps
    return can_register and ('recovery_code' in caps or fresh_account)


def compare(rules: Rules):
    mismatches, tofu_hits, safety = [], [], []
    for flags in product([False, True], repeat=len(CAPABILITIES)):
        caps = frozenset(c for c, f in zip(CAPABILITIES, flags) if f)
        for fresh_account in (False, True):
            parent = explore(caps, rules, fresh_account)
            wins = [s for s in parent if attacker_wins(s)]
            if bool(wins) != spec(caps, fresh_account):
                witness = trace(parent, wins[0]) if wins else []
                mismatches.append((sorted(caps), fresh_account, bool(wins), witness))
            if wins and fresh_account and 'recovery_code' not in caps:
                tofu_hits.append((sorted(caps), trace(parent, wins[0])))
            for state in parent:
                live = {d for d, _, s in state.devices if s != 'revoked'}
                if any(b is not None and b not in live for _, _, _, b in state.sessions):
                    safety.append(('session bound to a revoked device', trace(parent, state)))
                if state.disabled and state.sessions:
                    safety.append(('session on a disabled account', trace(parent, state)))
    return mismatches, tofu_hits, safety


def run() -> None:
    print('== M4: devices, approval and sessions (all attacker capability sets) ==')
    mismatches, tofu_hits, safety = compare(Rules())
    witness = []
    for caps, fresh, wins, steps in mismatches:
        witness.append(f'caps={caps} account_without_devices={fresh}: model says attacker {"wins" if wins else "cannot win"}')
        witness.extend(f'    {s}' for s in steps)
    record('M4', 'D1', 'the attacker gets an approved device exactly when the specification allows it '
           f'({2 ** len(CAPABILITIES) * 2} capability/account combinations)', 'HOLDS', bool(mismatches), witness=witness)
    record('M4', 'D2', 'no session survives revocation of its device or account disabling', 'HOLDS', bool(safety),
           witness=[safety[0][0]] + safety[0][1] if safety else [])
    record('M4', 'D3', 'a stolen fresh passkey cookie on an account that never had a device yields an approved device (TOFU)',
           'LIMIT', bool(tofu_hits), witness=tofu_hits[0][1] if tofu_hits else [])

    tricked, _, _ = compare(Rules(user_can_be_tricked=True))
    record('M4', 'D4', 'a user who approves an unrecognised device (skipping the confirmation code) hands over access',
           'LIMIT', bool(tricked), witness=tricked[0][3] if tricked else [])

    control, _, _ = compare(Rules(passkey_freshness=False))
    record('M4', 'D1-ctl', 'without the 10-minute passkey window a stale cookie plus a recovery code is enough', 'CONTROL',
           any('stale_cookie' in caps and 'fresh_cookie' not in caps and 'password' not in caps for caps, _, _, _ in control))


if __name__ == '__main__':
    run()
