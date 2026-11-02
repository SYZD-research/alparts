"""M3sQ: M3s rewritten in Quint and checked by TLC (quint/m3s_stall.qnt).

The Quint spec reuses the M3 Quint state and transitions and adds the clocks
of m3s_stall.py, so the two explorers must agree: the same number of
reachable states, the same properties violated, and counterexamples of the
same length (both breadth-first; TLC with one worker). Every step of a TLC
counterexample is replayed through the Python transitions, which checks it
and gives it the Python labels. A disagreement is reported as MODEL-GAP.

KS-sound and KS-keep are properties of a transition; in the Quint spec they
are invariants of the state the transition leaves (some allowed move from
here would break them), which is where m3s_stall.py records them too.
"""
from __future__ import annotations

import os
import time

import m3_quint
import m3s_stall as py
import tlc
from common import record
from harness import HarnessError

SPEC = 'm3s_stall.qnt'
PROPERTIES = ('KSsound', 'KSkeep')
PY_NAME = {'KSsound': 'KS-sound', 'KSkeep': 'KS-keep'}
CONTROLS = {
    'activeClamp': (py.StallRules(clamp='active'), 'KSkeep'),
    'noClamp': (py.StallRules(clamp='none'), 'KSsound'),
    'keepPackages': (py.StallRules(purge_on_loss=False), 'KSsound'),
    'groupLossTime': (py.StallRules(loss_time='group'), 'KSsound'),
}


def mask(items) -> int:
    return sum(1 << x for x in items)


def to_py(state: dict) -> py.SState:
    base = next(value for name, value in state.items() if name != 'c')
    c = state['c']
    return py.SState(m3_quint.to_py({'s': base}), mask(c['pkgOld']), mask(c['revOld']), c['rr'], mask(c['lostAt']),
                     mask(c['lostOld']), c['refOld'], mask(c['waitedAdd']), mask(c['waitedRem']))


def trigger(s: py.SState, rules: py.StallRules, v, prop: str):
    """The transition from `s` that m3s_stall.py.explore records for `prop`, or None."""
    permitted = py.stall_permitted(s, rules, v)
    for action, nxt in py.s_transitions(s, rules, v):
        stall_only = action[0] == 'create' and action[4].endswith(py.STALL_REASON) and '; ' not in action[4]
        if prop == 'KSsound' and stall_only and not py.truly_stalled(s, v):
            return action
        if (prop == 'KSkeep' and action[0] == 'commit' and permitted and py.truly_stalled(nxt, v)
                and not py.stall_permitted(nxt, rules, v)):
            return action
    return None


def replay(trace, rules: py.StallRules, prop: str | None = None) -> list[str]:
    """Python labels of a TLC counterexample (and the violating transition); HarnessError when one does not replay."""
    v = py.base_variant(rules)
    states = [to_py(state) for _, state in trace]
    if states[0] != py.s_initial(v):
        raise HarnessError('the TLC counterexample does not start in the Python initial state')
    labels = []
    for before, after in zip(states, states[1:]):
        action = next((a for a, nxt in py.s_transitions(before, rules, v) if nxt == after), None)
        if action is None:
            raise HarnessError(f'a TLC step is not a Python transition: {before} -> {after}')
        labels.append(py.s_label(before, v, action))
    if prop:
        action = trigger(states[-1], rules, v, prop)
        if action is None:
            raise HarnessError(f'the last TLC state has no transition that violates {prop} in Python')
        labels.append(py.s_label(states[-1], v, action))
    return labels


def run() -> None:
    print('== M3sQ: the fresh-start stall rule over time (Quint + TLC) ==')
    workers = int(os.environ.get('TLC_WORKERS', '2'))
    mismatches = []
    witnesses: dict[tuple[str, str], list[str] | None] = {}
    try:
        rules = py.StallRules()
        t0 = time.time()
        parent, found, _, v = py.explore(rules)
        states, took_py = len(parent), time.time() - t0
        lengths = {prop: len(py.trace(parent, hit[0], v)) + 1 for prop, hit in found.items()}
        del parent
        absent = [prop for prop in PROPERTIES if PY_NAME[prop] not in found]
        t0 = time.time()
        full = tlc.check(SPEC, 'implementation', absent, keep=PROPERTIES, workers=workers, timeout=4 * 3600)
        print(f'     implementation: TLC {full.states:,} states ({time.time() - t0:.0f}s), Python {states:,} '
              f'({took_py:.0f}s)')
        if not full.complete:
            mismatches.append(f'implementation: TLC found {full.violated}, which Python never reached')
            witnesses['implementation', full.violated] = replay(full.trace, rules, full.violated)
        elif full.states != states:
            mismatches.append(f'implementation: TLC {full.states:,} states, Python {states:,}')
        for prop in PROPERTIES:
            if PY_NAME[prop] in found:
                got = tlc.check(SPEC, 'implementation', [prop], keep=PROPERTIES, workers=1)
                witnesses['implementation', prop] = replay(got.trace, rules, prop) if got.violated else None
                if got.violated is None:
                    mismatches.append(f'implementation {prop}: violated in Python, not in TLC')
                elif len(witnesses['implementation', prop]) != lengths[PY_NAME[prop]]:
                    mismatches.append(f'implementation {prop}: shortest counterexample differs')

        for main, (rules, prop) in CONTROLS.items():
            got = tlc.check(SPEC, main, [prop], keep=PROPERTIES, workers=1)
            parent, found, _, v = py.explore(rules, stop=frozenset({PY_NAME[prop]}))
            labels = replay(got.trace, rules, prop) if got.violated else None
            witnesses[main, prop] = labels
            hit = found.get(PY_NAME[prop])
            if (labels is not None) != (hit is not None):
                mismatches.append(f'{main} {prop}: TLC {labels is not None}, Python {hit is not None}')
            elif hit is not None and len(labels) != len(py.trace(parent, hit[0], v)) + 1:
                mismatches.append(f'{main} {prop}: shortest counterexample {len(labels)} steps in TLC, '
                                  f'{len(py.trace(parent, hit[0], v)) + 1} in Python')
            del parent
    except HarnessError as error:
        record('M3sQ', 'tools', 'Quint and TLC ran, and their counterexamples replay in Python', 'HOLDS', False,
               str(error), incomplete=True)
        return

    record('M3sQ', 'agree', 'TLC and the Python explorer find the same states, violations and shortest '
                            'counterexamples in every run', 'HOLDS', False,
           '; '.join(mismatches), incomplete=bool(mismatches))

    def report(check_id, title, expect, main, prop):
        labels = witnesses.get((main, prop))
        record('M3sQ', check_id, title, expect, labels is not None,
               witness=(labels[:-1] + ['=> ' + labels[-1]]) if labels else [])

    report('KS-sound', 'a manager replaces the group by rule (c) only when an addition, rejoin or remove has waited '
                       '15 minutes in the current group', 'HOLDS', 'implementation', 'KSsound')
    report('KS-keep', 'an ordinary commit that leaves such a change pending does not restart the manager\'s wait',
           'HOLDS', 'implementation', 'KSkeep')
    report('KS-keep-ctl', 'before 0b0fb41: counting from the active version, any commit restarted the wait '
                          '(GHSA-3qj2-5q79-8vj6)', 'CONTROL', 'activeClamp', 'KSkeep')
    report('KS-sound-ctl', 'between 0b0fb41 and fc9ec50: without the genesis clamp a new group could be replaced at '
                           'once', 'CONTROL', 'noClamp', 'KSsound')
    report('KS-purge-ctl', 'before 0b0fb41: a package kept while its user could not see the channel counted as '
                           'waiting from before access returned', 'CONTROL', 'keepPackages', 'KSsound')
    report('KS-loss-ctl', 'before migration 0026: one time for the whole group counted a later loss of access from '
                          'an earlier one that had been undone (R-057)', 'CONTROL', 'groupLossTime', 'KSsound')


if __name__ == '__main__':
    run()
