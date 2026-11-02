"""M3rQ: M3r rewritten in Quint and checked by TLC (quint/m3r_own_commit.qnt).

The Quint spec keeps the state and transitions of m3r_own_commit.py, so the
two explorers must agree: the same number of reachable states for every
variant, the same properties violated, and counterexamples of the same length
(both search breadth-first). A disagreement means a bug in one of them and is
reported as MODEL-GAP, not as a result about the design.
"""
from __future__ import annotations

import m3r_own_commit as py
import tlc
from common import record
from harness import HarnessError

SPEC = 'm3r_own_commit.qnt'
PROPERTIES = ('K1', 'K2')
VARIANTS = {
    'implementation': py.V(transient_refusal=False),
    'transient': py.V(),
    'transientStamp': py.V(stamp_before_send=True),
    'lateStamp': py.V(stamp_before_send=True, late_requests=True),
    'beforeFix': py.V(replay_recheck=False, transient_refusal=False),
    # Larger than m3r_own_commit.py runs: up to five sends and three closed tabs.
    'implementationLarge': py.V(transient_refusal=False, max_sends=5, max_crashes=3),
    'transientStampLarge': py.V(stamp_before_send=True, max_sends=5, max_crashes=3),
}


def run() -> None:
    print('== M3rQ: own group commits with lost answers (Quint + TLC) ==')
    try:
        runs = {(main, prop): tlc.check(SPEC, main, [prop], keep=PROPERTIES, workers=1) for main in VARIANTS for prop in PROPERTIES}
        full = {main: tlc.check(SPEC, main, [], keep=PROPERTIES, workers=1) for main in VARIANTS}
    except HarnessError as error:
        record('M3rQ', 'tools', 'Quint and TLC ran', 'HOLDS', False, str(error), incomplete=True)
        return
    for main in VARIANTS:
        print(f'  M3rQ {main}: {full[main].states:,} states')

    # The Python explorer is the reference the rewrite must reproduce.
    mismatches = []
    for main, variant in VARIANTS.items():
        parent, found = py.bfs(variant)
        if not full[main].complete or full[main].states != len(parent):
            mismatches.append(f'{main}: TLC {full[main].states:,} states, Python {len(parent):,}')
        for prop in PROPERTIES:
            got = runs[main, prop]
            if (got.violated is not None) != (prop in found):
                mismatches.append(f'{main} {prop}: TLC {"violated" if got.violated else "holds"}, '
                                  f'Python {"violated" if prop in found else "holds"}')
            elif prop in found and len(got.trace) - 1 != len(py.trace(parent, found[prop][0])):
                mismatches.append(f'{main} {prop}: shortest counterexample {len(got.trace) - 1} steps in TLC, '
                                  f'{len(py.trace(parent, found[prop][0]))} in Python')
    record('M3rQ', 'agree', 'TLC and the Python explorer find the same states, violations and shortest '
                            'counterexamples in every variant', 'HOLDS', False,
           '; '.join(mismatches), incomplete=bool(mismatches))

    def check(check_id, title, expect, prop, main, detail=''):
        got = runs[main, prop]
        record('M3rQ', check_id, title, expect, got.violated is not None, detail,
               witness=tlc.describe(got.trace, flatten='s') if got.violated else [])

    check('K2', 'a resend of an accepted envelope always gets the replay answer, whichever check sees it taken',
          'HOLDS', 'K2', 'implementation')
    check('K1', 'A never loses the state of its own accepted commit (closed tab, resend, B racing) when refusals '
                'follow the state', 'HOLDS', 'K1', 'implementation')
    check('K1-transient', 'a resend refused for a passing reason while a send from a closed tab is still '
                          'outstanding makes A drop its record; when that send is accepted, A must rejoin',
          'LIMIT', 'K1', 'transient', 'the closed tab never stamped its send; proposed: stamp a send before it starts')
    check('K1-stamp', 'with each send stamped before it starts, transient refusals no longer lose the state', 'HOLDS',
          'K1', 'transientStamp')
    check('K1-late', 'even with stamps, a request that outlives the five minutes the client allows can be accepted '
                     'after A gave it up', 'LIMIT', 'K1', 'lateStamp',
          'OWN_ENVELOPE_IN_FLIGHT_MS assumes server timeouts that bound each statement, not the request')
    for prop in PROPERTIES:
        check(f'{prop}-large', f'{prop} still holds with up to five sends and three closed tabs', 'HOLDS', prop,
              'implementationLarge')
    check('K1-stamp-large', 'with stamps, transient refusals do not lose the state with up to five sends and three '
                            'closed tabs either', 'HOLDS', 'K1', 'transientStampLarge')
    check('K2-ctl', 'before the fix: a resend that passed the replay check just before its first send was accepted '
                    'got 409', 'CONTROL', 'K2', 'beforeFix')


if __name__ == '__main__':
    run()
