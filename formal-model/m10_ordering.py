"""M10: what a client can tell when a malicious server withholds or reorders
signed message events (message protocol v6, 2026-10-27).

conformance/sequence-harness.mts runs the real client order checks
(packages/client/src/stores/message-projector.ts: analyzeEventOrder and the
projection's v6 edit chain) on every history a server can build from a fixed
set of genuine v6 events: which events it serves and in which order, loaded
as the whole channel ('complete'), as its newest page ('suffix') or as a
forum's posts ('forum'). Signatures are assumed unforgeable, so every event
that verifies is a genuine envelope (M9 covers what the server makes up).

What v6 signs: each event's number among its device's events in the channel
(the server takes only the next one), the newest event of another device it
had received (seenHeads), and for an edit the version it replaces. "X
happened before Y" is the transitive closure of a lower number on the same
device and a named head. The checks:

  MO-order   in any window, events served against the order the served
             events themselves sign are noticed, and in a complete window any
             order against what happened (MO-order-complete);
  MO-drop    in a complete window, withholding an event that a served event
             happened after is noticed;
  MO-edit    a message shows a served edit of it, or says it cannot;
  MO-honest  an honest history is not flagged (complete), nor is its newest
             page (MO-honest-suffix);
and the limits the model must reach:
  MO-tail    withholding a device's newest events, that no served event came
             after, goes unnoticed (phase 2 narrows this);
  MO-suffix  in the newest page alone, a withheld event can pass for an older
             one (it is noticed once older pages reach the channel's start);
  MO-forum   a forum loads posts one by one, so a gap there means nothing;
  MO-order-hidden  in a page or a forum, events reordered with the event that
             shows their order withheld go unnoticed (phase 2 narrows this).
The 'split' run is the server that claimed to refuse an event it stored, so
that device A signed a second event under its number 2: each member served
one of them sees nothing wrong (MO-split, a limit in phase 1), and a member
served both notices (MO-split-seen). The 'no-sequence' run is the client
before v6, which must fail MO-order and MO-drop (control).
"""
from __future__ import annotations

from common import record
from harness import HarnessError, run_harness

PROPERTIES = (
    'MO-honest', 'MO-honest-suffix', 'MO-order', 'MO-order-complete', 'MO-order-hidden', 'MO-drop', 'MO-edit', 'MO-tail',
    'MO-suffix', 'MO-forum', 'MO-split', 'MO-split-seen',
)
RUNS = (('v6', None), ('split', 'split'), ('control', 'no-sequence'))


def run() -> None:
    print('== M10: withheld and reordered message events (real client order checks) ==')
    results: dict[str, dict] = {}
    total = 0
    try:
        for key, mutation in RUNS:
            out = run_harness('sequence-harness.mts', {'mutation': mutation} if mutation else {})
            minimum = 4 if key == 'split' else 1000
            if not isinstance(out, dict) or set(out.get('results', {})) != set(PROPERTIES) or out.get('histories', 0) < minimum:
                raise HarnessError(f'sequence harness returned incomplete results for {key}')
            total += out['histories']
            results[key] = out['results']
    except HarnessError as error:
        for prop in PROPERTIES:
            record('M10', prop, 'sequence harness', 'HOLDS', False, str(error), incomplete=True)
        return
    print(f'  M10 implementation: {total:,} served histories (v6, a split view, and the client before v6)')

    def check(check_id, hit, title, expect, detail=''):
        record('M10', check_id, title, expect, hit['violations'] > 0,
               detail or (f'{hit["violations"]} histories' if hit['violations'] else ''), witness=hit['example'] or [])

    v6, split, control = results['v6'], results['split'], results['control']
    check('MO-order', v6['MO-order'], 'events served against the order they sign are noticed, in any window', 'HOLDS')
    check('MO-order-complete', v6['MO-order-complete'], 'events served out of the order they happened in are noticed '
                                                        '(whole channel loaded)', 'HOLDS')
    check('MO-drop', v6['MO-drop'], 'withholding an event that a served event came after is noticed (whole channel loaded)', 'HOLDS')
    check('MO-edit', v6['MO-edit'], 'a message shows a served edit of it, or says that its latest version cannot be shown', 'HOLDS')
    check('MO-honest', v6['MO-honest'], 'an honest history is shown with its latest edit and flagged nowhere', 'HOLDS')
    check('MO-honest-suffix', v6['MO-honest-suffix'], 'the newest page of an honest history is flagged nowhere', 'HOLDS')
    check('MO-split-seen', split['MO-split-seen'], 'a member served two events under one device number notices', 'HOLDS')
    check('MO-tail', v6['MO-tail'], 'withholding a device\'s newest events, that nothing served came after, goes unnoticed', 'LIMIT',
          'phase 1: noticed only when the device or someone who saw them writes again')
    check('MO-suffix', v6['MO-suffix'], 'in the newest page alone, a withheld event can pass for an older one', 'LIMIT',
          'noticed once older pages reach the channel\'s first event')
    check('MO-forum', v6['MO-forum'], 'in a forum, loaded post by post, a withheld event is not noticed', 'LIMIT',
          'forum windows are not runs of consecutive events; order is still checked')
    check('MO-order-hidden', v6['MO-order-hidden'], 'in a page or a forum, events reordered with the event in between '
                                                    'withheld go unnoticed', 'LIMIT',
          'phase 1 names one head per event; noticed once the whole channel is loaded')
    check('MO-split', split['MO-split'], 'a server that claimed to refuse an event it stored can show members different '
                                         'events under one device number', 'LIMIT',
          'phase 1: noticed only by a member who is served both')
    check('MO-order-ctl', control['MO-order-complete'], 'before v6: events served out of order go unnoticed', 'CONTROL')
    check('MO-drop-ctl', control['MO-drop'], 'before v6: withheld events go unnoticed', 'CONTROL')


if __name__ == '__main__':
    run()
