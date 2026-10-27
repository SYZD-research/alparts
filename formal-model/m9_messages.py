"""M9: what a client shows from signed message events served by a malicious
server (2026-10-09, protocol v5 added the same day).

conformance/projector-harness.mts runs the real client projector and display
rules (packages/client/src/stores/message-projector.ts: the projection,
quotedMessage, belongsToPost) on every history a server can build from a
fixed set of genuine signed events: which events it serves, their server ids
(permuted), their times, and a second delivery that repeats an event under
the same id or a new one. Signatures and AEAD are assumed unforgeable, so an
event that verifies is a genuine envelope. Two scenarios: a forum (two posts by
A, a reply by B, an edit of the first post, a deletion of the second) and a
text channel (two messages by A, one with a file signed for it and one with a
file in the unbound v2 layout, a quote by B, an edit, a deletion).

The server can also serve what no author signed (a second pass over the same
scenarios, in every order, with honest ids or two events under each other's
ids, and no second delivery): events of other types (system, reaction, an
unknown type), edits and deletions that never verify, unsigned messages (not
verified yet, or verified to fail), and a genuine message with its references
changed to name another served event or none. The signature of such a message
fails, so the client keeps it as a message it could not verify, with the
quote or the post the server chose; the author's genuine edit of it is served
too. The pass fails if it never serves such a message with a quote, a place
under a post or an edit that the client could have honoured, so that
MI-unverified cannot hold for want of a case.

What the protocol signs: the event's own fields (type, channel, author,
device, key version, idempotency key, the server id of its target, and in a
forum the server id of its post). It does not sign the event's own id or
time, so a server can serve one message under another's id. v5 envelopes
also sign what the target id and the post id name: the author and signed
idempotency key of that event, which the server cannot give to another event.
Each history is run with every event in v6 (what current clients sign: v5's
bindings on every event, plus the device's number and, for an edit, the
version it replaces), in v5, and in the older layout (v3/v4). Since 2026-10-09 an event that names another message counts
only in v5: the server refuses the older layout for it, and so does the
client's verification (message-envelope.ts), which the harness runs. Files
sign the message id and the message's signed idempotency key; the unbound v2
layout is refused the same way. The control runs the older histories with the
client before that refusal (older layouts verified, v2 files opened by id).
"""
from __future__ import annotations

from common import record
from harness import HarnessError, run_harness

PROPERTIES = (
    'MI-replay', 'MI-redate', 'MI-edit', 'MI-reply', 'MI-quote', 'MI-delete', 'MI-honest',
    'MI-file-v3', 'MI-file-v2', 'MI-latest', 'MI-forged', 'MI-unverified',
)
PROTOCOLS = ('v6', 'v5', 'older')
SCENARIOS = ('forum', 'text')
# (results key, protocol, mutation): the client as it is, then the older histories with the client before the refusal.
RUNS = [(protocol, protocol, None) for protocol in PROTOCOLS] + [('control', 'older', 'accept-older-layouts')]


def run() -> None:
    print('== M9: message events from a malicious server (real projector) ==')
    results: dict[str, dict[str, dict]] = {key: {} for key, _, _ in RUNS}
    total = 0
    try:
        for key, protocol, mutation in RUNS:
            for scenario in SCENARIOS:
                payload = {'scenario': scenario, 'maxSecondDelivery': 1, 'protocol': protocol}
                if mutation:
                    payload['mutation'] = mutation
                out = run_harness('projector-harness.mts', payload)
                if not isinstance(out, dict) or set(out.get('results', {})) != set(PROPERTIES) or out.get('histories', 0) < 1000:
                    raise HarnessError(f'projector harness returned incomplete results for {key} {scenario}')
                total += out['histories']
                for prop, value in out['results'].items():
                    entry = results[key].setdefault(prop, {'violations': 0, 'example': None})
                    entry['violations'] += value['violations']
                    if value['example'] and (entry['example'] is None or len(value['example']) < len(entry['example'])):
                        entry['example'] = [f'[{key} {scenario}]'] + value['example']
    except HarnessError as error:
        for prop in PROPERTIES:
            record('M9', prop, 'projector harness', 'HOLDS', False, str(error), incomplete=True)
        return
    print(f'  M9 implementation: {total:,} served histories over {len(SCENARIOS)} scenarios x {len(PROTOCOLS)} layouts, '
          'and the older layout with the client before the refusal (control)')

    def merged(prop):
        """Both layouts together, with the client as it is (properties that do not depend on the layout)."""
        hits = [results[protocol][prop] for protocol in PROTOCOLS]
        examples = [hit['example'] for hit in hits if hit['example']]
        return {'violations': sum(hit['violations'] for hit in hits), 'example': min(examples, key=len) if examples else None}

    def check(check_id, hit, title, expect, detail=''):
        record('M9', check_id, title, expect, hit['violations'] > 0,
               detail or (f'{hit["violations"]} histories' if hit['violations'] else ''), witness=hit['example'] or [])

    v6, v5, older, control = results['v6'], results['v5'], results['older'], results['control']
    check('MI-replay', merged('MI-replay'), 'one signed operation is shown at most once (a copy under another id is quarantined)', 'HOLDS')
    check('MI-redate', merged('MI-redate'), 'an event the client already holds, sent again under its id with another time, '
                                            'changes nothing the client shows', 'HOLDS')
    check('MI-file-v3', merged('MI-file-v3'), 'a file opens only on the message it was signed with', 'HOLDS')
    check('MI-file-v2', merged('MI-file-v2'), 'a file in the unbound v2 layout opens on no message (refused)', 'HOLDS')
    check('MI-forged', merged('MI-forged'), 'what the server makes up (events of other types, an edit or a deletion nobody signed) '
                                            'changes nothing the client shows, and an unsigned message changes nothing about the others', 'HOLDS')
    check('MI-unverified', merged('MI-unverified'), 'a message that did not verify (or has not yet) shows no text, not even a verified '
                                                    'edit of it, no quote and no place under a post', 'HOLDS')
    for name, layout in (('v6', v6), ('v5', v5)):
        suffix = '' if name == 'v5' else '-v6'
        check(f'MI-edit{suffix}', layout['MI-edit'], f'{name}: edited text is shown on the message the edit was signed for', 'HOLDS')
        check(f'MI-reply{suffix}', layout['MI-reply'], f'{name}: a forum reply is shown under the post it was signed for', 'HOLDS')
        check(f'MI-quote{suffix}', layout['MI-quote'], f'{name}: a quote shows the message it was signed for, or that it cannot be shown', 'HOLDS')
        check(f'MI-delete{suffix}', layout['MI-delete'], f'{name}: a deletion removes only the message it was signed for', 'HOLDS')
        # Not vacuous: the checks above are not met by dropping events. Served
        # honestly, every edit, deletion, quote and reply shows where it belongs.
        check(f'MI-honest{suffix}', layout['MI-honest'],
              f'{name}: served honestly, every edit, deletion, quote and reply is shown where it was signed for', 'HOLDS')
    check('MI-edit-legacy', older['MI-edit'], 'older layout (v3/v4): an edit is never shown on another message (refused)', 'HOLDS')
    check('MI-reply-legacy', older['MI-reply'], 'older layout: a forum reply is never shown under another post (refused)', 'HOLDS')
    check('MI-quote-legacy', older['MI-quote'], 'older layout: a quote never shows another message (refused)', 'HOLDS')
    check('MI-delete-legacy', older['MI-delete'], 'older layout: a deletion never removes another message (refused)', 'HOLDS')
    moved = sum(control[prop]['violations'] for prop in ('MI-edit', 'MI-reply', 'MI-quote', 'MI-delete'))
    example = min((control[prop]['example'] for prop in ('MI-edit', 'MI-reply', 'MI-quote', 'MI-delete') if control[prop]['example']),
                  key=len, default=None)
    check('MI-legacy-ctl', {'violations': moved, 'example': example},
          'before the refusal: in the older layout, edits, deletions, quotes and replies could be moved to another message',
          'CONTROL')
    check('MI-file-v2-ctl', control['MI-file-v2'], 'before the refusal: a v2 file could be moved to another message of the same author',
          'CONTROL')
    check('MI-latest', v5['MI-latest'], 'v5: served once in a server-chosen order, a message can show an older version '
                                        '(v5 envelopes carry no per-device number)', 'LIMIT',
          'v5 events in history keep this limit; new events are signed in v6')
    check('MI-latest-v6', v6['MI-latest'], 'v6: served once in any order, a message shows its latest edit '
                                           '(an edit names the version it replaces; M10 covers withheld edits)', 'HOLDS')


if __name__ == '__main__':
    run()
