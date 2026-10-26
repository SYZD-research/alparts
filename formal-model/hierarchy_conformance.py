"""M2c: compare M2's predicates with the actual TypeScript guards.

HC1 compares the superior-loss predicate with assertNoSuperiorAccessLoss on
sampled model transitions. HC2 compares the category-change, role-override and
invitation-role predicates with assertCategoryChangeAuthority,
assertRoleOverridesHeld and mayGrantInvitationRole on states sampled from the
M2x run (MENTION_EVERYONE held by some roles only). Neither shows that every
service entry point invokes the guard; service-audit.mts and the integration
tests probe the entry points.
"""
from collections import Counter
from dataclasses import replace
import random

from common import PERM, record
from conformance import to_json
from harness import HarnessError, require_rows, run_harness
from m2_hierarchy import (EXTENDED, INITIAL, category_change_ok, check_transition, may_grant_invitation_role,
                          m2x_focus, role_overrides_held, transitions)


def run(seed: int = 20260929, rounds: int = 100, per_round: int = 30):
    print('== M2c: model/implementation conformance (hierarchy guards) ==')
    rng = random.Random(seed)
    state = INITIAL
    payload, expected, labels = [], [], []
    operations = Counter()
    def append(before, actor, label, after):
        before_ws, after_ws = before.workspace(), after.workspace()
        losses = any(prop == 'H2' for prop, _ in check_transition(before_ws, after_ws, actor))
        payload.append({**to_json(before_ws), 'guard': {'actor': actor, 'after': to_json(after_ws)}})
        expected.append(not losses)
        labels.append(f'{actor}: {label}')
        operations[label.split('(')[0]] += 1

    covered = set()
    for before in (INITIAL, replace(INITIAL, cat=(('k1', 'Administrator', PERM['ATTACH_FILES'], 0),))):
        for actor, label, after in transitions(before):
            op = label.split('(')[0]
            losses = any(prop == 'H2' for prop, _ in check_transition(before.workspace(), after.workspace(), actor))
            if op in {'privacy', 'moveChannel', 'deleteChannel', 'deleteCategory'} and (op, losses) not in covered:
                covered.add((op, losses))
                append(before, actor, label, after)
    for step in range(rounds):
        if step % 5 == 0:
            state = INITIAL
        moves = list(transitions(state))
        if not moves:
            state = INITIAL
            continue
        for actor, label, after in rng.sample(moves, min(per_round, len(moves))):
            append(state, actor, label, after)
        # Only follow management changes admitted by M2's superior guard.
        reachable = [move for move in moves if not any(prop == 'H2' for prop, _ in
                     check_transition(state.workspace(), move[2].workspace(), move[0]))]
        state = rng.choice(reachable)[2] if reachable else INITIAL
    try:
        result = run_harness('authz-harness.mts', payload)
        if not isinstance(result, dict):
            raise HarnessError('Missing hierarchy result envelope')
        output = require_rows(result.get('results'), len(payload))
        if not payload or any(type(row.get('allowed')) is not bool for row in output):
            raise HarnessError('Empty or malformed hierarchy comparisons')
    except HarnessError as error:
        record('M2c', 'HC1', 'real superior guard equals M2 predicate', 'HOLDS', False,
               str(error), incomplete=True)
        return
    differences = [f'{label}: model allowed={want}, implementation allowed={row["allowed"]}'
                   for label, want, row in zip(labels, expected, output, strict=True) if want != row['allowed']]
    # Both decisions must occur; otherwise a constant allow/deny mutant passes.
    record('M2c', 'HC0', 'the corpus exercises allowed and refused changes', 'CONTROL',
           set(expected) == {False, True} and {row['allowed'] for row in output} == {False, True})
    print(f'     {len(payload)} transitions; operations={dict(sorted(operations.items()))}')
    record('M2c', 'HC1', 'real superior guard equals M2 predicate', 'HOLDS', bool(differences), witness=differences)
    guard_checks(seed)


def _rows(state, category):
    return [[r, a, d] for t, r, a, d in state.cat if t == category] if category else []


def guard_cases(state):
    """(label, kind, model decision, check payload) for every candidate in one state."""
    ws = state.workspace()
    roles = {n: (p, pos) for n, p, pos in state.roles}
    out = []
    for actor in sorted(ws.members):
        for channel, category, _ in state.layout:
            for destination in (None, *state.categories):
                if destination != category:
                    out.append((f'{actor}: move {channel} {category}->{destination}', 'categoryChange',
                                category_change_ok(state, ws, actor, category, destination),
                                {'kind': 'categoryChange', 'actor': actor, 'from': _rows(state, category),
                                 'to': _rows(state, destination)}))
        for category in state.categories:
            out.append((f'{actor}: delete category {category}', 'categoryChange',
                        category_change_ok(state, ws, actor, category, None),
                        {'kind': 'categoryChange', 'actor': actor, 'from': _rows(state, category), 'to': []}))
        for name, (permissions, position) in roles.items():
            if name == 'Owner':
                continue
            for action in ('assign', 'unassign'):
                out.append((f'{actor}: {action} {name}', 'roleOverrides',
                            role_overrides_held(state, ws, actor, name, action),
                            {'kind': 'roleOverrides', 'actor': actor, 'action': action,
                             'categories': [[a, d] for _, r, a, d in state.cat if r == name],
                             'channels': [[c, a, d] for c, r, a, d in state.chan if r == name]}))
            named = name != 'Member'
            out.append((f'{actor}: invite to {name}', 'invitationRole',
                        may_grant_invitation_role(ws, actor, permissions, position, named),
                        {'kind': 'invitationRole', 'actor': actor, 'permissions': permissions, 'position': position,
                         'named': named}))
    return out


def guard_checks(seed: int, steps: int = 40) -> None:
    rng = random.Random(seed + 1)
    states, state = [INITIAL, EXTENDED], EXTENDED
    for step in range(steps):
        moves = list(transitions(state, focus=m2x_focus))
        if step % 10 == 9 or not moves:
            state = EXTENDED
            continue
        state = rng.choice(moves)[2]
        states.append(state)
    cases = [case + (s,) for s in dict.fromkeys(states) for case in guard_cases(s)]
    payload = [{**to_json(s.workspace()), 'check': check} for _, _, _, check, s in cases]
    try:
        result = run_harness('authz-harness.mts', payload)
        if not isinstance(result, dict):
            raise HarnessError('Missing guard result envelope')
        output = require_rows(result.get('results'), len(payload))
        if any(type(row.get('allowed')) is not bool for row in output):
            raise HarnessError('Malformed guard comparisons')
    except HarnessError as error:
        record('M2c', 'HC2', 'real category-change, role-override and invitation-role checks equal the M2 predicates',
               'HOLDS', False, str(error), incomplete=True)
        return
    kinds = Counter((kind, want) for _, kind, want, _, _ in cases)
    differences = [f'{label}: model allowed={want}, implementation allowed={row["allowed"]}'
                   for (label, _, want, _, _), row in zip(cases, output, strict=True) if want != row['allowed']]
    print(f'     {len(cases)} guard decisions over {len(dict.fromkeys(states))} states; '
          + ', '.join(f'{kind} {"allowed" if want else "refused"} {n}' for (kind, want), n in sorted(kinds.items())))
    record('M2c', 'HC2-0', 'each of the three checks is exercised with allowed and refused cases', 'CONTROL',
           all(kinds[(kind, True)] and kinds[(kind, False)] for kind in ('categoryChange', 'roleOverrides', 'invitationRole')))
    record('M2c', 'HC2', 'real category-change, role-override and invitation-role checks equal the M2 predicates',
           'HOLDS', bool(differences), witness=differences[:20])


if __name__ == '__main__':
    import common
    run()
    raise SystemExit(0 if all(result.ok for result in common.RESULTS) else 1)
