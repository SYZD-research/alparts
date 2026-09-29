"""M2c: compare M2's superior-loss predicate with the actual TypeScript guard.

This verifies the guard on sampled model transitions, NOT that every service
entry point invokes it. service-audit.mts separately probes omitted operations.
"""
from collections import Counter
from dataclasses import replace
import random

from common import PERM, record
from conformance import to_json
from harness import HarnessError, require_rows, run_harness
from m2_hierarchy import INITIAL, check_transition, transitions


def run(seed: int = 20260929, rounds: int = 100, per_round: int = 30):
    print('== M2c: model/implementation conformance (superior guard) ==')
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


if __name__ == '__main__':
    import common
    run()
    raise SystemExit(0 if all(result.ok for result in common.RESULTS) else 1)
