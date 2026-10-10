"""M3r: an own group commit whose answer may be lost (2026-10-09).

M3 does not model lost answers ("応答が失われた自分の commit の採用"). This
model covers them for one version V, written from:

  server  services/mls-group.service.ts admitGroupCommit: a replay check
          (stored envelope at V has the same transcript -> 200 replay), then
          checks without locks (version still free, membership, packages:
          a taken version answers 409), then under the locks the version
          compare-and-swap (taken by these bytes -> replay, else 409, free ->
          accept). Each read is atomic; requests interleave between them.
  client  services/mls-group.service.ts submitOwnEnvelope / sendOwnEnvelope /
          settlePending: the envelope is saved with the state it leads to and
          sent; 2xx adopts it; no answer stamps `unsettledAt`; an answered
          refusal deletes the record unless an earlier unanswered send is
          less than five minutes old; catch-up adopts the record when the log
          holds its transcript, otherwise drops it. A device that finds its
          own commit in the log without its record cannot process it (its own
          UpdatePath) and asks to be added again.

Device A has two tabs (one IndexedDB record, one Web Lock): a tab can close
in the middle of a send; its request goes on at the server. Device B can
commit the same version (an ordinary race).
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import NamedTuple

from common import record


class St(NamedTuple):
    stored: str | None        # envelope accepted at V
    record: tuple | None      # A's saved own envelope: (name, unsettled)  unsettled: None | 'recent' | 'old'
    built: int                # A's envelopes built so far: e1, e2, ...
    requests: tuple           # (sender, envelope, stage)  stage 0: replay check, 1: unlocked checks, 2: locked
    tab: str                  # A's tab: 'idle' | 'sending' (its request is the last of A's in requests)
    adopted: str | None       # what A adopted at V
    rejoin: bool              # ghost: A met its own accepted commit without its record
    answers: tuple            # ghost: (envelope, answer) given to A's requests
    crashes: int
    sends: int
    b_sent: bool


@dataclass(frozen=True)
class V:
    replay_recheck: bool = True      # CONTROL: False answers 409 when the unlocked checks find V taken (before the fix)
    stamp_before_send: bool = False  # proposed client change: mark a send as possibly outstanding before it starts
    transient_refusal: bool = True   # a resend can be refused without the state changing (429, 401, ...)
    late_requests: bool = False      # a request can outlive five minutes at the server (no admission deadline)
    max_sends: int = 3
    max_crashes: int = 1
    competitor: bool = True


def initial(v: V) -> St:
    return St(None, None, 0, (), 'idle', None, False, (), 0, 0, False)


def a_envelope(name: str) -> bool:
    return name.startswith('e')


def successors(s: St, v: V):
    out = []
    # A builds an envelope when it has no record and nothing is decided yet.
    if s.record is None and s.adopted is None and s.tab == 'idle' and s.built < 2 and s.stored is None:
        name = f'e{s.built + 1}'
        out.append((f'A builds and saves {name}', s._replace(record=(name, None), built=s.built + 1)))
    # A sends its saved envelope (first send or resend of the same bytes).
    if s.record is not None and s.tab == 'idle' and s.sends < v.max_sends and s.adopted is None:
        name, unsettled = s.record
        rec = (name, 'recent') if v.stamp_before_send else s.record
        req = ('A', name, 0, s.sends)
        out.append((f'A sends {name}', s._replace(record=rec, requests=s.requests + (req,), tab='sending', sends=s.sends + 1)))
    # The tab closes in the middle of a send: no answer will be handled.
    if s.tab == 'sending' and s.crashes < v.max_crashes:
        out.append(('A\'s tab closes during the send (its request goes on)', s._replace(tab='idle', crashes=s.crashes + 1)))
    # B commits V once.
    if v.competitor and not s.b_sent:
        out.append(('B sends its commit b for V', s._replace(requests=s.requests + (('B', 'b', 0, 99),), b_sent=True)))
    # Five minutes pass and a stamp becomes old. With bounded requests every
    # send it covers has ended by then; otherwise one can still be in flight.
    outstanding = any(r[0] == 'A' for r in s.requests)
    if s.record is not None and s.record[1] == 'recent' and (v.late_requests or not outstanding):
        out.append(('five minutes pass' + (' (a send is still in flight)' if outstanding else ''),
                    s._replace(record=(s.record[0], 'old'))))
    # Server steps of every request.
    for i, (sender, name, stage, tag) in enumerate(s.requests):
        rest = s.requests[:i] + s.requests[i + 1:]
        if stage == 0:
            if s.stored == name:
                out.append(_answer(s, rest, sender, name, tag, 'replay', v))
            elif v.transient_refusal and sender == 'A' and tag > 0:
                out.append(_answer(s, rest, sender, name, tag, 'refused (transient)', v))
                out.append((f'server: {name} passes the replay check', s._replace(requests=rest + ((sender, name, 1, tag),))))
            else:
                out.append((f'server: {name} passes the replay check', s._replace(requests=rest + ((sender, name, 1, tag),))))
        elif stage == 1:
            if s.stored is not None:
                if v.replay_recheck and s.stored == name:
                    out.append(_answer(s, rest, sender, name, tag, 'replay', v))
                else:
                    out.append(_answer(s, rest, sender, name, tag, '409', v))
            else:
                out.append((f'server: {name} passes the unlocked checks', s._replace(requests=rest + ((sender, name, 2, tag),))))
        elif stage == 2:
            if s.stored is None:
                t = s._replace(stored=name)
                out.append(_answer(t, rest, sender, name, tag, 'accepted', v))
            elif s.stored == name:
                out.append(_answer(s, rest, sender, name, tag, 'replay', v))
            else:
                out.append(_answer(s, rest, sender, name, tag, '409', v))
    # A catches up from the log once V is taken.
    if s.stored is not None and s.adopted is None and s.tab == 'idle':
        if s.record is not None and s.record[0] == s.stored:
            out.append((f'A catches up: the log holds its own {s.stored}, adopts it', s._replace(adopted=s.stored, record=None)))
        elif a_envelope(s.stored):
            out.append((f'A catches up: the log holds its own {s.stored} but A no longer has its state', s._replace(
                adopted='rejoin', rejoin=True, record=None)))
        else:
            out.append((f'A catches up: {s.stored} won, A drops its record', s._replace(adopted=s.stored, record=None)))
    return out


def _answer(s: St, rest: tuple, sender: str, name: str, tag: int, answer: str, v: V):
    label = f'server answers {answer} to {sender}\'s {name}'
    if sender != 'A':
        return label, s._replace(requests=rest)
    t = s._replace(requests=rest, answers=s.answers + ((name, answer),))
    # Only the tab that sent the last request handles its answer.
    last = max((r[3] for r in s.requests if r[0] == 'A'), default=-1)
    if s.tab != 'sending' or tag != last:
        return label + ' (nobody waits for it)', t
    t = t._replace(tab='idle')
    if answer in ('accepted', 'replay'):
        if t.record is not None and t.record[0] == name:
            return label + ', A adopts it', t._replace(adopted=name, record=None)
        return label, t
    if t.record is not None and t.record[0] == name:
        if t.record[1] == 'recent':
            return label + ', A keeps the record (an earlier send may be outstanding)', t
        return label + ', A deletes the record', t._replace(record=None)
    return label, t


def violations(s: St, v: V):
    out = []
    if s.rejoin:
        out.append(('K1', 'A\'s own commit was accepted after A dropped the state it leads to: A must ask to be added again'))
    for name, answer in s.answers:
        if answer == '409' and s.stored == name:
            out.append(('K2', f'a resend of the accepted {name} got 409 instead of the replay answer'))
    return out


def bfs(v: V):
    start = initial(v)
    parent = {start: None}
    found = {}
    queue = deque([start])
    while queue:
        s = queue.popleft()
        for prop, message in violations(s, v):
            found.setdefault(prop, (s, message))
        for label, nxt in successors(s, v):
            if nxt not in parent:
                parent[nxt] = (s, label)
                queue.append(nxt)
    return parent, found


def trace(parent, s):
    steps = []
    while parent[s] is not None:
        s, label = parent[s]
        steps.append(label)
    return list(reversed(steps))


def run() -> None:
    print('== M3r: own group commits with lost answers ==')
    runs = {
        'implementation': V(transient_refusal=False),
        'transient refusals': V(),
        'transient refusals, stamp before send': V(stamp_before_send=True),
        'late requests, stamp before send': V(stamp_before_send=True, late_requests=True),
        'before the fix': V(replay_recheck=False, transient_refusal=False),
    }
    results = {}
    for name, variant in runs.items():
        results[name] = bfs(variant)
        print(f'  M3r {name}: {len(results[name][0]):,} states')

    def check(check_id, title, expect, prop, name, detail=''):
        parent, found = results[name]
        hit = found.get(prop)
        record('M3r', check_id, title, expect, hit is not None, detail,
               witness=(trace(parent, hit[0]) + ['=> ' + hit[1]]) if hit else [])

    check('K2', 'a resend of an accepted envelope always gets the replay answer, whichever check sees it taken',
          'HOLDS', 'K2', 'implementation')
    check('K1', 'A never loses the state of its own accepted commit (closed tab, resend, B racing) when refusals '
                'follow the state', 'HOLDS', 'K1', 'implementation')
    check('K1-transient', 'a resend refused for a passing reason (429, an expired session) while a send from a closed '
                          'tab is still outstanding makes A drop its record; when that send is accepted, A must '
                          'rejoin', 'LIMIT', 'K1', 'transient refusals',
          'the closed tab never stamped its send; proposed: stamp a send before it starts')
    check('K1-stamp', 'with each send stamped before it starts, transient refusals no longer lose the state', 'HOLDS',
          'K1', 'transient refusals, stamp before send')
    check('K1-late', 'even with stamps, a request that outlives the five minutes the client allows (nothing bounds a '
                     'request once the server admitted it) can be accepted after A gave it up', 'LIMIT', 'K1',
          'late requests, stamp before send',
          'OWN_ENVELOPE_IN_FLIGHT_MS assumes server timeouts that bound each statement, not the request')
    check('K2-ctl', 'before the fix: a resend that passed the replay check just before its first send was accepted '
                    'got 409', 'CONTROL', 'K2', 'before the fix')


if __name__ == '__main__':
    run()
