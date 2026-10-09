"""M9: what a client shows from signed message events served by a malicious
server (2026-10-09, protocol v5 added the same day).

conformance/projector-harness.mts runs the real client projector and display
rules (packages/client/src/stores/message-projector.ts: the projection,
quotedMessage, belongsToPost) on every history a server can build from a
fixed set of genuine signed events: which events it serves, their server ids
(permuted), their times, and a second delivery that repeats an event under
the same id or a new one. Signatures and AEAD are assumed unforgeable, so only
genuine envelopes are served. Two scenarios: a forum (two posts by A, a reply
by B, an edit of the first post, a deletion of the second) and a text channel
(two messages by A with a v3 and a legacy v2 file, a quote by B, an edit, a
deletion).

What the protocol signs: the event's own fields (type, channel, author,
device, key version, idempotency key, the server id of its target, and in a
forum the server id of its post). It does not sign the event's own id or
time, so a server can serve one message under another's id. v5 envelopes
(current clients) also sign what the target id and the post id name: the
author and signed idempotency key of that event, which the server cannot give
to another event. Each history is run with every event in v5 and with every
event in the older layout (v3/v4, still accepted from older clients). Files
sign the message id and, since c2321ab, the message's signed idempotency key.
"""
from __future__ import annotations

from common import record
from harness import HarnessError, run_harness

PROPERTIES = (
    'MI-replay', 'MI-redate', 'MI-edit', 'MI-reply', 'MI-quote', 'MI-delete', 'MI-honest',
    'MI-file-v3', 'MI-file-v2', 'MI-latest',
)
PROTOCOLS = ('v5', 'legacy')
SCENARIOS = ('forum', 'text')


def run() -> None:
    print('== M9: message events from a malicious server (real projector) ==')
    results: dict[str, dict[str, dict]] = {protocol: {} for protocol in PROTOCOLS}
    total = 0
    try:
        for protocol in PROTOCOLS:
            for scenario in SCENARIOS:
                out = run_harness('projector-harness.mts', {'scenario': scenario, 'maxSecondDelivery': 1, 'protocol': protocol})
                if not isinstance(out, dict) or set(out.get('results', {})) != set(PROPERTIES) or out.get('histories', 0) < 1000:
                    raise HarnessError(f'projector harness returned incomplete results for {protocol} {scenario}')
                total += out['histories']
                for prop, value in out['results'].items():
                    entry = results[protocol].setdefault(prop, {'violations': 0, 'example': None})
                    entry['violations'] += value['violations']
                    if value['example'] and (entry['example'] is None or len(value['example']) < len(entry['example'])):
                        entry['example'] = [f'[{protocol} {scenario}]'] + value['example']
    except HarnessError as error:
        for prop in PROPERTIES:
            record('M9', prop, 'projector harness', 'HOLDS', False, str(error), incomplete=True)
        return
    print(f'  M9 implementation: {total:,} served histories over {len(SCENARIOS)} scenarios x {len(PROTOCOLS)} layouts')

    def merged(prop):
        """Both layouts together (properties that do not depend on the layout)."""
        hits = [results[protocol][prop] for protocol in PROTOCOLS]
        examples = [hit['example'] for hit in hits if hit['example']]
        return {'violations': sum(hit['violations'] for hit in hits), 'example': min(examples, key=len) if examples else None}

    def check(check_id, hit, title, expect, detail=''):
        record('M9', check_id, title, expect, hit['violations'] > 0,
               detail or (f'{hit["violations"]} histories' if hit['violations'] else ''), witness=hit['example'] or [])

    v5, legacy = results['v5'], results['legacy']
    check('MI-replay', merged('MI-replay'), 'one signed operation is shown at most once (a copy under another id is quarantined)', 'HOLDS')
    check('MI-redate', merged('MI-redate'), 'an event the client already holds, sent again under its id with another time, '
                                            'changes nothing the client shows', 'HOLDS')
    check('MI-file-v3', merged('MI-file-v3'), 'a v3 file opens only on the message it was signed with', 'HOLDS')
    check('MI-edit', v5['MI-edit'], 'v5: edited text is shown on the message the edit was signed for', 'HOLDS')
    check('MI-reply', v5['MI-reply'], 'v5: a forum reply is shown under the post it was signed for', 'HOLDS')
    check('MI-quote', v5['MI-quote'], 'v5: a quote shows the message it was signed for, or that it cannot be shown', 'HOLDS')
    check('MI-delete', v5['MI-delete'], 'v5: a deletion removes only the message it was signed for', 'HOLDS')
    # Not vacuous: the checks above are not met by dropping events. Served
    # honestly, every edit, deletion, quote and reply shows where it belongs.
    check('MI-honest', merged('MI-honest'), 'served honestly, every edit, deletion, quote and reply is shown where it was signed for', 'HOLDS')
    legacy_detail = 'THREAT_MODEL: envelopes from older clients (v3/v4) name their targets by server id only; ' \
                    'the same histories in v5 hold (MI-edit, MI-reply, MI-quote, MI-delete)'
    check('MI-edit-legacy', legacy['MI-edit'], 'older clients: an edit can be shown on another message of the same author (documented)',
          'LIMIT', legacy_detail)
    check('MI-reply-legacy', legacy['MI-reply'], 'older clients: a forum reply can be shown under another post (documented)',
          'LIMIT', legacy_detail)
    check('MI-quote-legacy', legacy['MI-quote'], 'older clients: a quote can show another message (documented)', 'LIMIT', legacy_detail)
    check('MI-delete-legacy', legacy['MI-delete'], 'older clients: a deletion can remove another message (documented)',
          'LIMIT', legacy_detail)
    check('MI-file-v2', merged('MI-file-v2'), 'a legacy v2 file can be moved to another message of the same author (documented)', 'LIMIT',
          'THREAT_MODEL: files signed by older clients are still accepted for the server-assigned message id')
    check('MI-latest', merged('MI-latest'), 'served once in a server-chosen order, a message can show an older version '
                                            '(reordering and omission are documented as undetected)', 'LIMIT',
          'THREAT_MODEL: envelopes carry no per-sender sequence number')


if __name__ == '__main__':
    run()
