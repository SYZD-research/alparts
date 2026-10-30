"""M4: devices, approval and sessions — attacker capability analysis.

Mirrors device.service.ts (registerDevice, approveDevice, revokeDevice,
expireUnapprovedDevice), recovery.service.ts (restoreDevice), auth/passkey
session creation and account disabling:

  register  needs a valid session and either the current password
            (password sessions always, passkey sessions optionally) or a
            passkey session younger than 10 minutes (F-P2F-012). Once the
            user turns password login off, the password no longer counts.
            The first device the account ever has is approved at once (TOFU).
  approve   signed by an approved, non-revoked device of the same account,
            through a session bound to that device; never self-approval.
  restore   recovery code + a session bound to the unapproved device.
  revoke    by an approved device; kills sessions bound to the revoked device;
            a revoked identity is never approved again.
  expire    by the server alone, with no signature (directory entry `expire`):
            retires a device that nobody approved, and only such a device.
            registerDevice does it for the oldest pending device when the
            account is at its limit of 8 devices (pending ones count), and the
            operator reset (account-state.service.ts) for all of them; the
            sessions bound to the device end with it. An approved device is
            never retired this way, and a retired identity is never
            registered again.
  disable   operator action; every session becomes invalid.

For every combination of attacker capabilities, and for accounts with
password login on and off, the model computes whether the attacker can end up
controlling an approved device, and compares that with the specification:
    reachable  <=>  can_register and (recovery_code or account_has_no_device)
    can_register = (knows_password and password_login_on) or fresh_passkey_cookie
                   or users_passkey
The user's passkey (the authenticator, or the account that syncs it) signs
in, but since 2026-10-30 it opens only the history key, not the recovery code
(passkey-vault wrapArchiveKey), so it does not restore a device.
With password login on, L may turn it off (with a passkey); that ends every
session opened with the password (auth.service setPasswordLogin).

M4L explores the device limit (scaled down from 8 to 3; pendingDevicesToRetire
does not depend on it) with `expire`, the operator reset and an owner L who
lost its only approved device while an attacker who knows the password
registers devices: L must still be able to add a device and restore it with
the recovery code (LK1), and no registration retires an approved device (ES1).
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace
from itertools import product

from common import record

CAPABILITIES = ('password', 'recovery_code', 'stale_cookie', 'fresh_cookie', 'passkey')


@dataclass(frozen=True)
class State:
    devices: tuple          # ((id, controller, status), ...)
    sessions: frozenset     # {(holder, method, fresh, bound_device)}; equal sessions are indistinguishable
    ever_had_device: bool
    disabled: bool = False
    password_off: bool = False


def initial(fresh_account: bool, password_off: bool = False) -> State:
    if fresh_account:
        return State(devices=(), sessions=frozenset({('L', 'passkey', True, None)}), ever_had_device=False,
                     password_off=password_off)
    return State(devices=(('L1', 'L', 'approved'),), sessions=frozenset({('L', 'passkey', True, 'L1')}),
                 ever_had_device=True, password_off=password_off)


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
    password_off_checked: bool = True  # the password no longer counts once password login is off (6b3c01d)
    passkey_wraps_code: bool = False   # CONTROL: before 2026-10-30 the passkey unwrapped the recovery code


def transitions(state: State, caps: frozenset, rules: Rules):
    if state.disabled:
        return
    status = {d: s for d, _, s in state.devices}
    controller = {d: c for d, c, _ in state.devices}
    knows_password = {'L': True, 'Att': 'password' in caps}
    # The user's passkey opens the history key only; before 2026-10-30 it opened the code itself.
    has_recovery = {'L': True, 'Att': 'recovery_code' in caps or (rules.passkey_wraps_code and 'passkey' in caps)}
    # verifyCurrentPasswordSnapshot answers a correct password like a wrong one once login is off
    password_counts = {h: knows and (not state.password_off or not rules.password_off_checked)
                       for h, knows in knows_password.items()}

    # logins
    for holder in ('L', 'Att'):
        if knows_password[holder] and not state.password_off:
            nxt = _add(state, (holder, 'password', False, None))
            if nxt:
                yield f'{holder}: password login', nxt
    for holder in ('L', 'Att') if 'passkey' in caps else ('L',):
        nxt = _add(state, (holder, 'passkey', True, None))
        if nxt:
            yield f'{holder}: passkey login', nxt

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
        allowed = password_counts[holder] or (method == 'passkey' and (fresh or not rules.passkey_freshness))
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

    # L turns password login off with a passkey confirmation: password sessions end
    if not state.password_off and any(h == 'L' and m == 'passkey' for h, m, _, _ in state.sessions):
        yield 'L turns password login off', replace(
            state, password_off=True, sessions=frozenset(x for x in state.sessions if x[1] != 'password'))

    yield 'operator disables the account', replace(state, disabled=True, sessions=frozenset())


def explore(caps, rules, fresh_account, password_off=False):
    start = initial(fresh_account, password_off)
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


def spec(caps, fresh_account, password_off=False):
    can_register = ('password' in caps and not password_off) or 'fresh_cookie' in caps or 'passkey' in caps
    return can_register and ('recovery_code' in caps or fresh_account)


def compare(rules: Rules):
    mismatches, tofu_hits, safety = [], [], []
    for flags in product([False, True], repeat=len(CAPABILITIES)):
        caps = frozenset(c for c, f in zip(CAPABILITIES, flags) if f)
        for fresh_account, password_off in product((False, True), repeat=2):
            parent = explore(caps, rules, fresh_account, password_off)
            wins = [s for s in parent if attacker_wins(s)]
            if bool(wins) != spec(caps, fresh_account, password_off):
                witness = trace(parent, wins[0]) if wins else []
                mismatches.append((sorted(caps), fresh_account, password_off, bool(wins), witness))
            if wins and fresh_account and 'recovery_code' not in caps:
                tofu_hits.append((sorted(caps), trace(parent, wins[0])))
            for state in parent:
                live = {d for d, _, s in state.devices if s != 'revoked'}
                if any(b is not None and b not in live for _, _, _, b in state.sessions):
                    safety.append(('session bound to a revoked device', trace(parent, state)))
                if state.disabled and state.sessions:
                    safety.append(('session on a disabled account', trace(parent, state)))
                if state.password_off and any(m == 'password' for _, m, _, _ in state.sessions):
                    safety.append(('password session after password login was turned off', trace(parent, state)))
    return mismatches, tofu_hits, safety


# ---------------------------------------------------------------------------
# M4L: the device limit, `expire` and the operator reset (0824246)
# ---------------------------------------------------------------------------

LIMIT = 3            # MAX_ACTIVE_DEVICES_PER_USER is 8; pendingDevicesToRetire does not depend on it


@dataclass(frozen=True)
class LState:
    devices: tuple           # ((id, controller, status), ...) oldest first; status approved | pending | retired | revoked
    lost: frozenset          # approved devices of L that L can no longer use
    sessions: frozenset      # {(holder, bound device or None)}
    att_password: bool       # the attacker still knows the password
    registrations: tuple     # (by L, by Att)
    reset: bool = False


@dataclass(frozen=True)
class LRules:
    expire_at_limit: bool = True       # registration retires the oldest pending devices instead of refusing
    reset_retires_pending: bool = True  # the operator reset retires every pending device
    approved_never_retired: bool = True  # only pending devices make room (pendingDevicesToRetire)


L_REGISTRATIONS, ATT_REGISTRATIONS = 2, 4


def lockout_initial() -> LState:
    # L lost its only approved device; the attacker knows the password (no recovery code).
    return LState(devices=(('L1', 'L', 'approved'),), lost=frozenset({'L1'}), sessions=frozenset({('L', None)}),
                  att_password=True, registrations=(0, 0))


def devices_to_retire(state: LState, rules: LRules):
    """pendingDevicesToRetire over the active devices, oldest first; None refuses the registration."""
    active = [(d, s) for d, _, s in state.devices if s in ('approved', 'pending')]
    surplus = len(active) + 1 - LIMIT
    if surplus <= 0:
        return []
    if not rules.expire_at_limit:
        return None
    candidates = [d for d, s in active if s == 'pending' or not rules.approved_never_retired]
    return candidates[:surplus] if len(candidates) >= surplus else None


def _retire(state: LState, ids, status='retired') -> LState:
    return replace(state, devices=tuple((d, c, status if d in ids else s) for d, c, s in state.devices),
                   sessions=frozenset(x for x in state.sessions if x[1] not in ids))


def lockout_transitions(state: LState, rules: LRules, only_l: bool = False):
    """Every step; with only_l, L's own steps, whose registrations the exploration bound does not limit."""
    status = {d: s for d, _, s in state.devices}
    holders = ('L',) if only_l else ('L', 'Att')
    for holder in holders:
        if holder == 'L' or state.att_password:
            if (holder, None) not in state.sessions:
                yield f'{holder}: password login', replace(state, sessions=state.sessions | {(holder, None)})
    for holder, bound in sorted(state.sessions, key=repr):
        if holder not in holders:
            continue
        index = 0 if holder == 'L' else 1
        budget = L_REGISTRATIONS if holder == 'L' else ATT_REGISTRATIONS
        # registerDevice with the current password (the attacker's stops working after the reset)
        if (only_l or state.registrations[index] < budget) and (holder == 'L' or state.att_password):
            retire = devices_to_retire(state, rules)
            if retire is not None:
                device = f'{holder}{len(state.devices) + 1}'
                nxt = _retire(state, set(retire))
                counts = tuple(n + (i == index) for i, n in enumerate(state.registrations))
                nxt = replace(nxt, devices=nxt.devices + ((device, holder, 'pending'),), registrations=counts,
                              sessions=(nxt.sessions - {(holder, bound)}) | {(holder, device)})
                note = f', retires {", ".join(retire)}' if retire else ''
                yield f'{holder}: registers {device}{note}', nxt
        if holder != 'L' or bound is None:
            continue
        # restoreDevice: the recovery code and a session bound to L's pending device
        if status.get(bound) == 'pending':
            yield f'L: restores {bound} with the recovery code', replace(
                state, devices=tuple((d, c, 'approved' if d == bound else s) for d, c, s in state.devices))
        # revokeDevice: a decision signed by an approved device L can use
        if status.get(bound) == 'approved' and bound not in state.lost:
            for target, _, s in state.devices:
                if target != bound and s in ('approved', 'pending'):
                    yield f'L: revokes {target} with {bound}', _retire(state, {target}, 'revoked')
            yield f'L: loses {bound}', replace(state, lost=state.lost | {bound},
                                               sessions=frozenset(x for x in state.sessions if x[1] != bound))
    if not only_l and not state.reset:
        nxt = replace(state, reset=True, att_password=False, sessions=frozenset())
        if rules.reset_retires_pending:
            nxt = _retire(nxt, {d for d, _, s in state.devices if s == 'pending'})
        yield 'operator resets the password', nxt


def usable(state: LState) -> bool:
    return any(c == 'L' and s == 'approved' and d not in state.lost for d, c, s in state.devices)


def lockout_explore(rules: LRules):
    start = lockout_initial()
    parent = {start: None}
    queue = deque([start])
    retired_approved = []
    while queue:
        state = queue.popleft()
        approved = {d for d, _, s in state.devices if s == 'approved'}
        for label, nxt in lockout_transitions(state, rules):
            if 'registers' in label and any(s == 'retired' for d, _, s in nxt.devices if d in approved):
                retired_approved.append(trace(parent, state) + [label])
            if nxt not in parent:
                parent[nxt] = (state, label)
                queue.append(nxt)
    stuck = [state for state in parent if not recovers(state, rules)]
    return parent, stuck, retired_approved


def recovers(state: LState, rules: LRules, steps: int = 4) -> bool:
    """Can L alone (log in, register, restore, revoke) reach an approved device it can use?"""
    frontier, seen = [state], {state}
    for _ in range(steps + 1):
        if any(usable(s) for s in frontier):
            return True
        frontier = [nxt for s in frontier for label, nxt in lockout_transitions(s, rules, only_l=True)
                    if not label.startswith('L: loses') and nxt not in seen and not seen.add(nxt)]
    return False


def full_of_approved(state: LState) -> bool:
    return sum(1 for _, _, s in state.devices if s == 'approved') >= LIMIT


def lockout_run() -> None:
    parent, stuck, retired_approved = lockout_explore(LRules())
    print(f'  M4L device limit {LIMIT}: {len(parent):,} states')
    open_stuck = [s for s in stuck if not full_of_approved(s)]
    record('M4', 'LK1', 'an owner who lost every approved device, while an attacker who knows the password registers '
           'devices, can still add a device and restore it with the recovery code (the operator reset included)', 'HOLDS',
           bool(open_stuck), witness=trace(parent, open_stuck[0]) if open_stuck else [])
    record('M4', 'ES1', 'a registration never retires an approved device', 'HOLDS', bool(retired_approved),
           witness=retired_approved[0] if retired_approved else [])
    full = [s for s in stuck if full_of_approved(s)]
    record('M4', 'LK-full', 'once every place holds an approved device the owner can no longer use, it cannot add one '
           '(freeing a place takes a decision signed by an approved device)', 'LIMIT', bool(full),
           witness=trace(parent, full[0]) if full else [])
    parent, stuck, _ = lockout_explore(LRules(expire_at_limit=False, reset_retires_pending=False))
    open_stuck = [s for s in stuck if not full_of_approved(s)]
    record('M4', 'LK1-ctl', 'before the 2026-10-22 fix: devices nobody approved filled the account, and neither a new '
           'device nor the operator reset got the owner back in', 'CONTROL', bool(open_stuck),
           witness=trace(parent, open_stuck[0]) if open_stuck else [])
    _, _, retired_approved = lockout_explore(LRules(approved_never_retired=False))
    record('M4', 'ES1-ctl', 'if the oldest device made room whatever its state, a registration would retire an approved '
           'device', 'CONTROL', bool(retired_approved), witness=retired_approved[0] if retired_approved else [])


def run() -> None:
    print('== M4: devices, approval and sessions (all attacker capability sets) ==')
    mismatches, tofu_hits, safety = compare(Rules())
    witness = []
    for caps, fresh, password_off, wins, steps in mismatches:
        witness.append(f'caps={caps} account_without_devices={fresh} password_login_off={password_off}: '
                       f'model says attacker {"wins" if wins else "cannot win"}')
        witness.extend(f'    {s}' for s in steps)
    record('M4', 'D1', 'the attacker gets an approved device exactly when the specification allows it '
           f'({2 ** len(CAPABILITIES) * 4} capability/account combinations, password login on and off)', 'HOLDS',
           bool(mismatches), witness=witness)
    record('M4', 'D2', 'no session survives revocation of its device, account disabling, or (for password sessions) '
           'turning password login off', 'HOLDS', bool(safety), witness=[safety[0][0]] + safety[0][1] if safety else [])
    record('M4', 'D3', 'a stolen fresh passkey cookie on an account that never had a device yields an approved device (TOFU)',
           'LIMIT', bool(tofu_hits), witness=tofu_hits[0][1] if tofu_hits else [])

    tricked, _, _ = compare(Rules(user_can_be_tricked=True))
    record('M4', 'D4', 'a user who approves an unrecognised device (skipping the confirmation code) hands over access',
           'LIMIT', bool(tricked), witness=tricked[0][4] if tricked else [])

    control, _, _ = compare(Rules(passkey_freshness=False))
    record('M4', 'D1-ctl', 'without the 10-minute passkey window a stale cookie plus a recovery code is enough', 'CONTROL',
           any('stale_cookie' in caps and 'fresh_cookie' not in caps and 'password' not in caps
               for caps, _, _, _, _ in control))
    control, _, _ = compare(Rules(password_off_checked=False))
    hits = [(caps, steps) for caps, _, password_off, wins, steps in control
            if password_off and wins and 'fresh_cookie' not in caps]
    record('M4', 'D1-pw-ctl', 'before the 2026-10-22 fix: with password login off, a stolen cookie and the password '
           'still registered a device', 'CONTROL', bool(hits), witness=hits[0][1] if hits else [])
    control, _, _ = compare(Rules(passkey_wraps_code=True))
    hits = [(caps, steps) for caps, _, _, wins, steps in control if wins and 'recovery_code' not in caps]
    record('M4', 'D1-passkey-ctl', 'before 2026-10-30: the user\'s passkey alone (the authenticator, or the account '
           'that syncs it) registered a device and restored it without the recovery code', 'CONTROL', bool(hits),
           witness=hits[0][1] if hits else [])
    lockout_run()


if __name__ == '__main__':
    run()
