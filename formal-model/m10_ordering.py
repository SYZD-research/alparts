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
(the server refuses a number already used), the newest event it had received
of each other device (seenHeads, up to eight), and for an edit the version it
replaces. "X happened before Y" is the transitive closure of a lower number
on the same device and having received X. Clients also remember, per
channel, the newest number and key received of each device
(channel-memory.ts). The checks:

  MO-order   in any window, events served against the order the served
             events themselves sign are noticed, and in a complete window any
             order against what happened (MO-order-complete); in a page or a
             forum also with the event in between withheld (MO-order-hidden,
             which the phase 1 client with one head per event fails: control);
  MO-drop    in a complete window, withholding an event that a served event
             happened after is noticed;
  MO-forged-number  unsigned events the server adds, claiming any number of
             a device anywhere, do not hide what MO-drop notices;
  MO-edit    a message shows the newest served edit of it, or says it cannot;
  MO-rollback  a member who received the whole history before notices an
             event withheld later, in a complete window or when the page holds
             an earlier event of its device;
  MO-split-seen / -named / -remembered  a member notices two events under
             one device number when served both, when a later event names the
             other, or when it received the other before;
  MO-honest  an honest history is not flagged (complete), nor is its newest
             page (MO-honest-suffix), nor a forum list that holds a post and
             its latest edit only (MO-honest-forum);
and the limits the model must reach:
  MO-tail    withholding a device's newest events, that no served event came
             after, goes unnoticed by a member who never received them;
  MO-suffix  in the newest page alone, a withheld event can pass for an older
             one (it is noticed once older pages reach the channel's start);
  MO-forum   a forum loads posts one by one, so a gap there means nothing;
  MO-rollback-page  a page that holds no earlier event of a device cannot
             tell that a remembered event of it is gone;
  MO-split   a server that claimed to refuse an event it stored (so device A
             signed a second event under its number 2) can show each member
             one of them, and nothing else names either.
Runs: 'v6' (the client as it is), 'split', 'memory' (a member who received
the whole history before), 'single-head' (phase 1, control) and
'no-sequence' (the client before v6, which must fail MO-order and MO-drop).
"""
from __future__ import annotations

from common import record
from harness import HarnessError, run_harness

PROPERTIES = (
    'MO-honest', 'MO-honest-suffix', 'MO-honest-forum', 'MO-forged-number', 'MO-order', 'MO-order-complete', 'MO-order-hidden', 'MO-drop', 'MO-edit', 'MO-tail',
    'MO-suffix', 'MO-forum', 'MO-split', 'MO-split-seen', 'MO-split-named', 'MO-split-remembered', 'MO-rollback', 'MO-rollback-page',
)
RUNS = (('v6', None), ('split', 'split'), ('memory', 'memory'), ('single-head', 'single-head'), ('control', 'no-sequence'))


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
    print(f'  M10 implementation: {total:,} served histories (v6, a split view, a member who received everything before, '
          'and the clients of phase 1 and before v6)')

    def check(check_id, hit, title, expect, detail=''):
        record('M10', check_id, title, expect, hit['violations'] > 0,
               detail or (f'{hit["violations"]} histories' if hit['violations'] else ''), witness=hit['example'] or [])

    v6, split, memory, single, control = (results[key] for key in ('v6', 'split', 'memory', 'single-head', 'control'))
    check('MO-order', v6['MO-order'], 'events served against the order they sign are noticed, in any window', 'HOLDS')
    check('MO-order-complete', v6['MO-order-complete'], 'events served out of the order they happened in are noticed '
                                                        '(whole channel loaded)', 'HOLDS')
    check('MO-drop', v6['MO-drop'], 'withholding an event that a served event came after is noticed (whole channel loaded)', 'HOLDS')
    check('MO-forged-number', v6['MO-forged-number'], 'unsigned events claiming a device\'s numbers do not hide a withheld event',
          'HOLDS')
    check('MO-edit', v6['MO-edit'], 'a message shows the newest served edit of it, or something says otherwise', 'HOLDS')
    check('MO-honest', v6['MO-honest'], 'an honest history is shown with its latest edit and flagged nowhere', 'HOLDS')
    check('MO-honest-suffix', v6['MO-honest-suffix'], 'the newest page of an honest history is flagged nowhere', 'HOLDS')
    check('MO-honest-forum', v6['MO-honest-forum'], 'a forum list (a post and its latest edit only) shows the latest edit, flagged nowhere',
          'HOLDS')
    check('MO-split-seen', split['MO-split-seen'], 'a member served two events under one device number notices', 'HOLDS')
    check('MO-tail', v6['MO-tail'], 'withholding a device\'s newest events, that nothing served came after, goes unnoticed', 'LIMIT',
          'noticed once the device or someone who received them writes again, or by a member who received them before (MO-rollback)')
    check('MO-suffix', v6['MO-suffix'], 'in the newest page alone, a withheld event can pass for an older one', 'LIMIT',
          'noticed once older pages reach the channel\'s first event')
    check('MO-forum', v6['MO-forum'], 'in a forum, loaded post by post, a withheld event is not noticed', 'LIMIT',
          'forum windows are not runs of consecutive events; order is still checked')
    check('MO-order-hidden', v6['MO-order-hidden'], 'in a page or a forum, events reordered with the event in between '
                                                    'withheld are noticed (heads name every device received)', 'HOLDS')
    check('MO-order-hidden-ctl', single['MO-order-hidden'], 'phase 1 (one head per event): such a reorder goes unnoticed', 'CONTROL')
    check('MO-split-named', split['MO-split-named'], 'a member served one event under a device number notices once a later '
                                                     'event names the other', 'HOLDS')
    check('MO-split-remembered', split['MO-split-remembered'], 'a member who received one event under a device number '
                                                               'notices when served the other', 'HOLDS')
    check('MO-rollback', memory['MO-rollback'], 'events received before and withheld later are noticed (whole channel loaded, '
                                                'or the page holds an earlier event of their device)', 'HOLDS')
    check('MO-rollback-page', memory['MO-rollback-page'], 'events received before are not noticed missing in a page that '
                                                          'holds no earlier event of their device', 'LIMIT',
          'noticed once the page reaches an event of the device, or the channel\'s first event')
    check('MO-split', split['MO-split'], 'a server that claimed to refuse an event it stored can show members different '
                                         'events under one device number', 'LIMIT',
          'noticed by a member served both, one that received the other before, or once a later event names the other')
    check('MO-order-ctl', control['MO-order-complete'], 'before v6: events served out of order go unnoticed', 'CONTROL')
    check('MO-drop-ctl', control['MO-drop'], 'before v6: withheld events go unnoticed', 'CONTROL')


if __name__ == '__main__':
    run()
