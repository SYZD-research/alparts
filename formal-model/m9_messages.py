"""M9: what a client shows from signed message events served by a malicious
server (2026-10-09).

conformance/projector-harness.mts runs the real client projector
(packages/client/src/stores/message-projector.ts) on every history a server
can build from a fixed set of genuine signed events: which events it serves,
their server ids (permuted), their times, and a second delivery that repeats
an event under the same id or a new one. Signatures and AEAD are assumed
unforgeable, so only genuine envelopes are served. Two scenarios: a forum
(two posts by A, a reply by B, an edit of the first post) and a text channel
(two messages by A with a v3 and a legacy v2 file, a quote by B, an edit).

What the protocol signs: the event's own fields (type, channel, author,
device, key version, idempotency key, the server id of its target, and in a
forum the server id of its post). It does not sign the event's own id or
time. Files sign the message id and, since c2321ab, the message's signed
idempotency key.
"""
from __future__ import annotations

from common import record
from harness import HarnessError, run_harness

PROPERTIES = ('MI-replay', 'MI-redate', 'MI-edit', 'MI-reply', 'MI-quote', 'MI-file-v3', 'MI-file-v2', 'MI-latest')


def run() -> None:
    print('== M9: message events from a malicious server (real projector) ==')
    results: dict[str, dict] = {}
    total = 0
    try:
        for scenario in ('forum', 'text'):
            out = run_harness('projector-harness.mts', {'scenario': scenario, 'maxSecondDelivery': 1})
            if not isinstance(out, dict) or set(out.get('results', {})) != set(PROPERTIES) or out.get('histories', 0) < 1000:
                raise HarnessError(f'projector harness returned incomplete results for {scenario}')
            total += out['histories']
            for prop, value in out['results'].items():
                entry = results.setdefault(prop, {'violations': 0, 'example': None})
                entry['violations'] += value['violations']
                if value['example'] and (entry['example'] is None or len(value['example']) < len(entry['example'])):
                    entry['example'] = [f'[{scenario}]'] + value['example']
    except HarnessError as error:
        for prop in PROPERTIES:
            record('M9', prop, 'projector harness', 'HOLDS', False, str(error), incomplete=True)
        return
    print(f'  M9 implementation: {total:,} served histories over 2 scenarios')

    def check(prop, title, expect, detail=''):
        hit = results[prop]
        record('M9', prop, title, expect, hit['violations'] > 0,
               detail or (f'{hit["violations"]} histories' if hit['violations'] else ''), witness=hit['example'] or [])

    check('MI-replay', 'one signed operation is shown at most once (a copy under another id is quarantined)', 'HOLDS')
    check('MI-redate', 'an event the client already holds, sent again under its id with another time, changes '
                       'nothing the client shows', 'HOLDS')
    check('MI-file-v3', 'a v3 file opens only on the message it was signed with', 'HOLDS')
    check('MI-edit', 'edited text is shown on the message the edit was signed for', 'HOLDS',
          'edits name their target by server id; the target message does not sign its own id')
    check('MI-reply', 'a forum reply is shown under the post it was signed for', 'HOLDS',
          'replies name their post by server id; the post\'s first message does not sign its own id')
    check('MI-quote', 'a quote shows the message it was signed for', 'HOLDS',
          'quotes name their target by server id only')
    check('MI-file-v2', 'a legacy v2 file can be moved to another message of the same author (documented)', 'LIMIT',
          'THREAT_MODEL: files signed by older clients are still accepted for the server-assigned message id')
    check('MI-latest', 'served once in a server-chosen order, a message can show an older version '
                       '(reordering and omission are documented as undetected)', 'LIMIT',
          'THREAT_MODEL: envelopes carry no per-sender sequence number')


if __name__ == '__main__':
    run()
