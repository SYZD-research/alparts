"""M10Q: M10 rewritten in Quint and checked by TLC (quint/m10_ordering.qnt).

The Quint spec writes the client's order checks (analyzeEventOrder,
compareWithRemembered, projectMessageWindow with the v6 edit chain,
rememberHeads) from packages/client/src/stores, and lets TLC serve every
history of the genuine events that m10_ordering.py serves. Each state holds
a history and what the client shows of it, so the checks are invariants.

The `agree` check compares the model with the real code, history by
history: for every history that conformance/sequence-harness.mts runs, the
windows' verdicts (noticed or not, the version of A1 shown) and the unsigned
claims of MO-forged-number that go unnoticed must be the same. A
disagreement, or a harness that cannot run, is reported as MODEL-GAP.
"""
from __future__ import annotations

import tlc
from common import record
from harness import HarnessError, run_harness

SPEC = 'm10_ordering.qnt'
# Quint main module -> the mutation of sequence-harness.mts it rewrites.
MAINS = {'v6': None, 'split': 'split', 'memory': 'memory', 'singleHead': 'single-head', 'noSequence': 'no-sequence'}
# (check id, main, Quint property, expectation, title, detail): the checks of m10_ordering.py.
CHECKS = (
    ('MO-order', 'v6', 'MO_order', 'HOLDS', 'events served against the order they sign are noticed, in any window', ''),
    ('MO-order-complete', 'v6', 'MO_order_complete', 'HOLDS',
     'events served out of the order they happened in are noticed (whole channel loaded)', ''),
    ('MO-drop', 'v6', 'MO_drop', 'HOLDS',
     'withholding an event that a served event came after is noticed (whole channel loaded)', ''),
    ('MO-forged-number', 'v6', 'MO_forged_number', 'HOLDS',
     'unsigned events claiming a device\'s numbers do not hide a withheld event', ''),
    ('MO-edit', 'v6', 'MO_edit', 'HOLDS', 'a message shows the newest served edit of it, or something says otherwise', ''),
    ('MO-honest', 'v6', 'MO_honest', 'HOLDS', 'an honest history is shown with its latest edit and flagged nowhere', ''),
    ('MO-honest-suffix', 'v6', 'MO_honest_suffix', 'HOLDS', 'the newest page of an honest history is flagged nowhere', ''),
    ('MO-honest-forum', 'v6', 'MO_honest_forum', 'HOLDS',
     'a forum list (a post and its latest edit only) shows the latest edit, flagged nowhere', ''),
    ('MO-split-seen', 'split', 'MO_split_seen', 'HOLDS', 'a member served two events under one device number notices', ''),
    ('MO-tail', 'v6', 'MO_tail', 'LIMIT',
     'withholding a device\'s newest events, that nothing served came after, goes unnoticed',
     'noticed once the device or someone who received them writes again, or by a member who received them before '
     '(MO-rollback)'),
    ('MO-suffix', 'v6', 'MO_suffix', 'LIMIT', 'in the newest page alone, a withheld event can pass for an older one',
     'noticed once older pages reach the channel\'s first event'),
    ('MO-forum', 'v6', 'MO_forum', 'LIMIT', 'in a forum, loaded post by post, a withheld event is not noticed',
     'forum windows are not runs of consecutive events; order is still checked'),
    ('MO-order-hidden', 'v6', 'MO_order_hidden', 'HOLDS',
     'in a page or a forum, events reordered with the event in between withheld are noticed', ''),
    ('MO-order-hidden-ctl', 'singleHead', 'MO_order_hidden', 'CONTROL',
     'phase 1 (one head per event): such a reorder goes unnoticed', ''),
    ('MO-split-named', 'split', 'MO_split_named', 'HOLDS',
     'a member served one event under a device number notices once a later event names the other', ''),
    ('MO-split-remembered', 'split', 'MO_split_remembered', 'HOLDS',
     'a member who received one event under a device number notices when served the other', ''),
    ('MO-rollback', 'memory', 'MO_rollback', 'HOLDS',
     'events received before and withheld later are noticed (whole channel loaded, or the page holds an earlier '
     'event of their device)', ''),
    ('MO-rollback-page', 'memory', 'MO_rollback_page', 'LIMIT',
     'events received before are not noticed missing in a page that holds no earlier event of their device',
     'noticed once the page reaches an event of the device, or the channel\'s first event'),
    ('MO-split', 'split', 'MO_split', 'LIMIT',
     'a server that claimed to refuse an event it stored can show members different events under one device number',
     'noticed by a member served both, one that received the other before, or once a later event names the other'),
    ('MO-order-ctl', 'noSequence', 'MO_order_complete', 'CONTROL', 'before v6: events served out of order go unnoticed', ''),
    ('MO-drop-ctl', 'noSequence', 'MO_drop', 'CONTROL', 'before v6: withheld events go unnoticed', ''),
)
# The windows of a harness verdict -> the view fields of the Quint state.
VIEWS = {'complete': 'c', 'suffix': 's', 'forum': 'f',
         'complete+remembered': 'cr', 'suffix+remembered': 'sr', 'forum+remembered': 'fr'}
# The member of the memory run received everything before: every window remembers.
MEMORY_VIEWS = {'complete+remembered': 'c', 'suffix+remembered': 's'}


def explore(main: str):
    """Check the properties of `main`; returns ({property: Run}, the complete run with every state dumped)."""
    keep = sorted({prop for _, m, prop, _, _, _ in CHECKS if m == main})
    holds = [prop for _, m, prop, expect, _, _ in CHECKS if m == main and expect == 'HOLDS']
    runs = {}
    # The HOLDS properties together: a violated one is set aside and the rest checked again.
    while True:
        got = tlc.check(SPEC, main, holds, keep=keep, workers=2, dump=True)
        if got.violated is None:
            full = got
            for prop in holds:
                runs[prop] = got
            break
        runs[got.violated] = got
        holds.remove(got.violated)
    for _, m, prop, expect, _, _ in CHECKS:
        if m == main and expect != 'HOLDS':
            runs[prop] = tlc.check(SPEC, main, [prop], keep=keep, workers=2)
    return runs, full


def witness(main: str, run) -> list[str]:
    state = run.trace[-1][1]
    view = state['view']
    lines = [f'serve {", ".join(state["order"]) or "nothing"}']
    windows = MEMORY_VIEWS if main == 'memory' else VIEWS if main == 'split' else dict(list(VIEWS.items())[:3])
    for name, field in windows.items():
        shown = view[field]
        lines.append(f'{name} window: {"noticed" if shown["noticed"] else "nothing noticed"}, '
                     f'A1 shows {shown["a1"] or "no text"}')
    if view['forgedMissed']:
        lines.append(f'unnoticed unsigned claims: {view["forgedMissed"]}')
    return lines


def compare(main: str, dumped: list[dict], verdicts: list[dict]) -> list[str]:
    """Where the model and the real code differ on the histories the harness ran."""
    states = {tuple(s['order']): s['view'] for s in dumped if s['ready']}
    views = MEMORY_VIEWS if main == 'memory' else VIEWS
    out = []
    for row in verdicts:
        order = tuple(row['order'])
        view = states.get(order)
        if view is None:
            out.append(f'{main} {",".join(order)}: not a state of the model')
            continue
        for window, shown in row['views'].items():
            if window not in views:
                out.append(f'{main} {",".join(order)}: the harness showed an unknown window {window}')
            elif view[views[window]] != shown:
                out.append(f'{main} {",".join(order)} {window}: model {view[views[window]]}, code {shown}')
        missed = {(m['device'], m['claimed'], m['slot']) for m in row['forgedMissed']}
        modelled = {(m['device'], m['claimed'], m['slot']) for m in view['forgedMissed']}
        if row['forgedTrials'] != view['forgedTrials'] or missed != modelled:
            out.append(f'{main} {",".join(order)}: unsigned claims: model {view["forgedTrials"]} tried, '
                       f'{sorted(modelled)} unnoticed; code {row["forgedTrials"]} tried, {sorted(missed)} unnoticed')
    return out


def run() -> None:
    print('== M10Q: withheld and reordered message events (Quint + TLC) ==')
    try:
        explored = {main: explore(main) for main in MAINS}
    except HarnessError as error:
        record('M10Q', 'tools', 'Quint and TLC ran', 'HOLDS', False, str(error), incomplete=True)
        return
    for main, (_, full) in explored.items():
        print(f'  M10Q {main}: {full.states:,} states')

    # The model against the real client code, history by history.
    try:
        mismatches, compared = [], 0
        for main, mutation in MAINS.items():
            payload = {'verdicts': True, **({'mutation': mutation} if mutation else {})}
            out = run_harness('sequence-harness.mts', payload)
            verdicts = out.get('verdicts') if isinstance(out, dict) else None
            if not isinstance(verdicts, list) or not verdicts:
                raise HarnessError(f'sequence harness returned no verdicts for {main}')
            compared += len(verdicts)
            mismatches += compare(main, explored[main][1].dumped, verdicts)
        record('M10Q', 'agree', f'the model shows what the real client code shows in all {compared:,} served histories '
                                '(every window, the version of A1, unsigned claims)', 'HOLDS', False,
               '; '.join(mismatches[:5]) + (f' (and {len(mismatches) - 5} more)' if len(mismatches) > 5 else ''),
               incomplete=bool(mismatches))
    except HarnessError as error:
        record('M10Q', 'agree', 'the model shows what the real client code shows, history by history', 'HOLDS', False,
               str(error), incomplete=True)

    for check_id, main, prop, expect, title, detail in CHECKS:
        got = explored[main][0][prop]
        record('M10Q', check_id, title, expect, got.violated == prop, detail,
               witness=witness(main, got) if got.violated == prop else [])


if __name__ == '__main__':
    run()
