"""M3Q: M3 rewritten in Quint and checked by TLC (quint/m3_key_epochs.qnt).

The Quint spec keeps the state and transitions of m3_key_epochs.py, so the two
explorers must agree on every exploration: the same number of reachable
states, the same properties violated, and counterexamples of the same length
(both search breadth-first; TLC with one worker). Every step of a TLC
counterexample is also replayed through the Python transitions, which both
checks it and gives it the Python labels. A disagreement is reported as
MODEL-GAP, not as a result about the design.

Safety (KC, KC-dev, KI, KA and the limits KA-unjoined, KC-dev-restore) and
their controls are checked by TLC. The liveness family (KL, KL-orphan,
KL-lost and their controls) asks whether protocol steps alone can still reach
a writable state from every state (a backward fixpoint over the state graph).
TLC checks invariants and temporal properties under fairness, not this kind of
reachability: under fairness the bounded number of versions is used up by
other commits, so a fairness formulation fails for reasons of the bounds, not
the design. Those checks stay in m3_key_epochs.py (M3).

The check `large` explores the second-device run with six versions instead of
five (about 6.2 million states, beyond what the Python runs explore); set
M3Q_LARGE=0 to skip it.
"""
from __future__ import annotations

import os
import time

import m3_key_epochs as py
import tlc
from common import record
from harness import HarnessError

SPEC = 'm3_key_epochs.qnt'
HOLDS = ('KC', 'KCdev', 'KI', 'KA')
LIMITS = ('KAunjoined', 'KCdevRestore')
PROPERTIES = HOLDS + LIMITS
PY_NAME = {'KC': 'KC', 'KCdev': 'KC-dev', 'KI': 'KI', 'KA': 'KA', 'KAunjoined': 'KA-unjoined',
           'KCdevRestore': 'KC-dev-restore'}
RUNS = {'main': 'main', 'faults': 'faults', 'secondDevice': 'second-device'}
SMALL = dict(max_log=4, max_viewer_changes=1, max_device_changes=1, poison_budget=0)
CONTROLS = {
    'maliciousServer': py.Variant(malicious_server=True, **SMALL),
    'noRemovalGate': py.Variant(gate_removal=False, **SMALL),
    'noCas': py.Variant(cas=False, **SMALL),
    'currentMemberLog': py.Variant(former_member_log=False, **SMALL),
    'rejoinEnded': py.Variant(leave_ended_unreadable=False, max_log=5, max_viewer_changes=1, max_device_changes=1),
}
LARGE = py.Variant(max_log=6, poison_budget=0, second_device=True, max_viewer_changes=0)


def mask(items, shift=lambda x: x) -> int:
    return sum(1 << shift(x) for x in items)


def to_py(state: dict) -> py.State:
    """The Python State that a TLC state stands for."""
    s = state['s']
    return py.State(
        viewers=mask(s['viewers']),
        status=tuple(s['status']),
        log=tuple(py.Entry(e['kind'], e['genesis'], mask(e['roster']), mask(e['added']), e['poisoner'], e['parent'])
                  for e in s['log']),
        pkg=tuple(s['pkg']),
        local=tuple(s['local']),
        derived=tuple(mask(x) for x in s['derived']),
        restored=tuple(mask(x) for x in s['restored']),
        stale=s['stale'],
        genesis_wait=s['genesisWait'],
        viewer_changes=s['viewerChanges'],
        device_changes=s['deviceChanges'],
        lost=s['lost'],
    )


def replay(trace, v: py.Variant) -> list[str]:
    """Python labels of a TLC counterexample; raises HarnessError when a step is not a Python transition."""
    states = [to_py(state) for _, state in trace]
    if states[0] != py.initial(v):
        raise HarnessError('the TLC counterexample does not start in the Python initial state')
    labels = []
    for before, after in zip(states, states[1:]):
        action = next((a for a, nxt, _ in py.transitions(before, v) if nxt == after), None)
        if action is None:
            raise HarnessError(f'a TLC step is not a Python transition: {before} -> {after}')
        labels.append(py.label(before, v, action))
    return labels


def run() -> None:
    print('== M3Q: continuous channel groups (Quint + TLC) ==')
    workers = int(os.environ.get('TLC_WORKERS', '2'))
    variants = dict(py.RUNS)
    mismatches = []
    found: dict[str, list[str]] = {}
    try:
        for main, name in RUNS.items():
            v = variants[name]
            t0 = time.time()
            g, hits = py.explore(v)
            states, took_py = len(g.states), time.time() - t0
            lengths = {prop: len(g.trace(i, v)) for prop, (i, _) in hits.items()}
            del g
            # One full exploration checks every property Python never saw violated; each
            # property Python did see violated gets its own run, which stops at the first violation.
            absent = [prop for prop in PROPERTIES if PY_NAME[prop] not in hits]
            present = [prop for prop in PROPERTIES if PY_NAME[prop] in hits]
            t0 = time.time()
            full = tlc.check(SPEC, main, absent, keep=PROPERTIES, workers=workers, timeout=4 * 3600)
            runs = {prop: tlc.check(SPEC, main, [prop], keep=PROPERTIES, workers=1, timeout=4 * 3600)
                    for prop in present}
            print(f'     {main}: TLC {full.states:,} states ({time.time() - t0:.0f}s), Python {states:,} '
                  f'({took_py:.0f}s); violated: {", ".join(present) or "none"}')
            if not full.complete:
                mismatches.append(f'{main}: TLC found {full.violated}, which Python never reached')
                found.setdefault(full.violated, [f'[{main}]'] + replay(full.trace, v))
            elif full.states != states:
                mismatches.append(f'{main}: TLC {full.states:,} states, Python {states:,}')
            for prop, got in runs.items():
                if got.violated is None:
                    mismatches.append(f'{main} {prop}: violated in Python, not in TLC')
                    continue
                labels = replay(got.trace, v)
                if len(labels) != lengths[PY_NAME[prop]]:
                    mismatches.append(f'{main} {prop}: shortest counterexample {len(labels)} steps in TLC, '
                                      f'{lengths[PY_NAME[prop]]} in Python')
                found.setdefault(prop, [f'[{main}]'] + labels)

        controls = {}
        for main, v in CONTROLS.items():
            props = ('KC', 'KCdev') if main == 'noRemovalGate' else (
                ('KI',) if main == 'noCas' else ('KA',) if main != 'maliciousServer' else ('KC',))
            for prop in props:
                got = tlc.check(SPEC, main, [prop], keep=PROPERTIES, workers=1)
                g, hits = py.explore(v, stop=frozenset({PY_NAME[prop]}))
                expected = hits.get(PY_NAME[prop])
                labels = replay(got.trace, v) if got.violated else []
                if (got.violated is not None) != (expected is not None):
                    mismatches.append(f'{main} {prop}: TLC {got.violated is not None}, Python {expected is not None}')
                elif expected is not None and len(labels) != len(g.trace(expected[0], v)):
                    mismatches.append(f'{main} {prop}: shortest counterexample {len(labels)} steps in TLC, '
                                      f'{len(g.trace(expected[0], v))} in Python')
                controls[main, prop] = labels if got.violated else None

        # Beyond the Python runs: the second-device run with six versions (about 6.2 million
        # states, 25 minutes with two workers). Skipped with M3Q_LARGE=0.
        large = None
        if os.environ.get('M3Q_LARGE', '1') != '0':
            t0 = time.time()
            large = tlc.check(SPEC, 'secondDeviceLarge', list(HOLDS), keep=PROPERTIES, workers=workers,
                              timeout=8 * 3600)
            print(f'     secondDeviceLarge: TLC {large.states:,} states ({time.time() - t0:.0f}s)')
            large_witness = ['[secondDeviceLarge]'] + replay(large.trace, LARGE) if large.violated else []
    except HarnessError as error:
        record('M3Q', 'tools', 'Quint and TLC ran, and their counterexamples replay in Python', 'HOLDS', False,
               str(error), incomplete=True)
        return

    record('M3Q', 'agree', 'TLC and the Python explorer find the same states, violations and shortest '
                           'counterexamples in every exploration', 'HOLDS', False,
           '; '.join(mismatches), incomplete=bool(mismatches))

    def holds(check_id, title, prop):
        record('M3Q', check_id, title, 'HOLDS', prop in found, witness=found.get(prop, []))

    holds('KC', 'whenever a message can be written, only devices of users who can see the channel can derive or '
                'hold its key (removal, joining, fresh start, restore)', 'KC')
    holds('KC-dev', 'whenever a message can be written, no revoked device can derive or holds its key from the group',
          'KCdev')
    holds('KI', 'the server accepts one commit per version: the version chain never forks', 'KI')
    holds('KA', 'a device that may read the channel derives, from the commit log alone, every version of each '
                'membership it joined (versions from an envelope it could not read on are exempt)', 'KA')
    record('M3Q', 'KA-unjoined', 'a membership that ended before the device joined it is not recovered from the log '
                                 '(only from the user\'s backups)', 'LIMIT', 'KAunjoined' in found,
           witness=found.get('KAunjoined', []))
    record('M3Q', 'KC-dev-restore', 'a device that restored its user\'s backups and was then revoked holds the current '
                                    'key until the next commit (at most 24 hours)', 'LIMIT', 'KCdevRestore' in found,
           witness=found.get('KCdevRestore', []))

    def control(check_id, title, expect, main, prop):
        labels = controls[main, prop]
        record('M3Q', check_id, title, expect, labels is not None, witness=labels or [])

    control('KC-server', 'a server that ignores channel visibility can let a non-viewer\'s device derive the key of '
                         'messages written later (F-E2E-001)', 'LIMIT', 'maliciousServer', 'KC')
    control('KC-ctl', 'writing before the Remove is accepted lets a user who lost the channel read new messages',
            'CONTROL', 'noRemovalGate', 'KC')
    control('KC-dev-ctl', 'writing before the Remove is accepted lets a revoked device read new messages',
            'CONTROL', 'noRemovalGate', 'KCdev')
    control('KI-ctl', 'without the version compare-and-swap, two commits extend the same version', 'CONTROL',
            'noCas', 'KI')
    control('KA-ctl', 'serving the log only to current members leaves a device removed while offline without keys of '
                      'versions it was a member at', 'CONTROL', 'currentMemberLog', 'KA')
    control('KA-rejoin-ctl', 'asking to be added again when an envelope of an already ended membership cannot be '
                             'read leaves the device out of the membership that added it (client before the fix)',
            'CONTROL', 'rejoinEnded', 'KA')
    if large is not None:
        record('M3Q', 'large', 'KC, KC-dev, KI and KA also hold in the second-device run with six versions '
                               '(beyond the Python runs)', 'HOLDS', large.violated is not None,
               f'violated: {large.violated}' if large.violated else '', witness=large_witness)


if __name__ == '__main__':
    run()
