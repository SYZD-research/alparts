"""M8: voice calls - room grants, call registries and the SFU (2026-10-09).

Written from the implementation at commit ce09b19:

  M8a  room grants, the P2P call registry, the SFU socket sessions and the
       voice presence watch, under every interleaving of their await points
       with authorization revocation and disconnect
       (websocket/voice.handler.ts, websocket/room-membership.ts, the
       revocation routes). Explicit-state search.
  M8b  the SFU coordinator (voice/*.ts) run as real code against a scripted
       stand-in for mediasoup (conformance/voice-sfu-harness.mts): every
       interleaving of joins, leaves, transports, producers and consumers.
  M8c  who can obtain call audio: P2P (signed SDP, DTLS-SRTP between the
       endpoints, TURN relays ciphertext) versus the SFU (DTLS ends at the
       server).

Common assumptions: one Node.js process, so a synchronous run between two
awaits is atomic; Socket.IO's in-memory adapter emits 'leave-room'
synchronously from socket.leave / socketsLeave / disconnect; PostgreSQL
advisory locks: a shared holder excludes the exclusive one. New shared
requests are granted whenever no exclusive lock is held, which allows more
interleavings than PostgreSQL's FIFO queue (safety carries over).
"""
from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass
from typing import NamedTuple

from common import record
from harness import HarnessError, run_harness

CH = ('C1', 'C2')


# ---------------------------------------------------------------------------
# M8a: room grants, P2P registry, SFU sessions and presence watch
# ---------------------------------------------------------------------------

class S(NamedTuple):
    auth: frozenset         # committed: channels the user may see and join (VIEW + CONNECT_VOICE)
    rooms: frozenset        # Socket.IO rooms of the user's socket: ('ch', c) | ('pr', c)
    connected: bool
    reg: tuple | None       # VoiceParticipantRegistry entry of the socket: (channel, participantId)
    sfu: tuple | None       # attachVoiceSfuEvents `sessions` entry of the socket: (channel, participantId)
    coord: frozenset        # VoiceCoordinator sessions: (participantId, channel)
    lock: int               # workspace advisory lock: n shared holders, -1 exclusive
    threads: tuple          # in-flight handlers: (kind, channel, pc, a, b)
    started: int            # socket events sent so far
    revs: tuple             # per channel: 0 none, 1 exclusive held, 2 committed (rooms not yet left), 3 rooms left
    disc: bool
    pid: int                # next participant id
    acked: frozenset        # SFU participants whose join was acknowledged
    leaked: frozenset       # ghost: channels whose presence was sent after their rooms were left
    watched: bool


@dataclass(frozen=True)
class Variant:
    max_ops: int = 3
    ops: tuple = ('J1', 'J2', 'S1', 'S2', 'L1', 'SL1', 'CL1', 'W')
    lock: bool = True                 # CONTROL: False checks authorization without the workspace lock
    p2p_postcondition: bool = True    # CONTROL: False registers a P2P participant without rechecking the room
    sfu_listener: bool = True         # CONTROL: False drops the SFU 'leave-room' listener
    watch_room_filter: bool = True    # CONTROL: False lists every checked channel (before the 2026-10-09 fix)
    revoke: tuple = CH                # channels whose access is revoked once during the run


def m8a_initial() -> S:
    return S(frozenset(CH), frozenset(), True, None, None, frozenset(), 0, (), 0, (0, 0), False, 0,
             frozenset(), frozenset(), False)


def _release(s: S) -> S:
    """attachVoiceSfuEvents release(): drop the socket session, leave the coordinator."""
    if s.sfu is None:
        return s
    pid = s.sfu[1]
    return s._replace(sfu=None, coord=frozenset(e for e in s.coord if e[0] != pid))


def _leave_room(s: S, room: tuple, v: Variant) -> S:
    """socket.leave / socketsLeave: the adapter emits 'leave-room' synchronously."""
    if room not in s.rooms:
        return s
    s = s._replace(rooms=s.rooms - {room})
    if room[0] == 'ch':
        if s.reg is not None and s.reg[0] == room[1]:          # VoiceSignalingHub.removeIfChannelRoomLeft
            s = s._replace(reg=None)
        if v.sfu_listener and s.sfu is not None and s.sfu[0] == room[1]:   # SFU leave-room listener
            s = _release(s)
    return s


def _set_thread(s: S, i: int, thread) -> S:
    threads = list(s.threads)
    if thread is None:
        del threads[i]
    else:
        threads[i] = thread
    return s._replace(threads=tuple(threads))


def _can_share(s: S, v: Variant) -> bool:
    return not v.lock or s.lock >= 0


def _take_share(s: S, v: Variant) -> S:
    return s._replace(lock=s.lock + 1) if v.lock else s


def _drop_share(s: S, v: Variant) -> S:
    return s._replace(lock=s.lock - 1) if v.lock else s


def _sfu_fail(s: S, c: str, pid: int) -> S:
    """catch block of voice:sfu:join."""
    if s.sfu == (c, pid):
        return _release(s)
    return s._replace(coord=frozenset(e for e in s.coord if e[0] != pid))


def _step(s: S, i: int, v: Variant):
    """One run of a handler between two awaits. Threads: (kind, channel, pc, a, b)."""
    kind, c, pc, a, b = s.threads[i]
    if kind == 'J':                                  # voice:join (P2P), a = result/previous entry, b = read
        if pc == 0:                                  # authorizeSocketChannel (no lock)
            if c not in s.auth:
                return 'join preflight denied', _set_thread(s, i, None)
            return 'join preflight ok', _set_thread(s, i, (kind, c, 1, a, b))
        if pc == 1:
            if not _can_share(s, v):
                return None
            return 'join takes shared lock', _set_thread(_take_share(s, v), i, (kind, c, 2, a, b))
        if pc == 2:                                  # getChannelAuthorizationFromStore
            return 'join reads access', _set_thread(s, i, (kind, c, 3, a, c in s.auth))
        if pc == 3:                                  # check, then socket.join([channel, presence])
            if not s.connected or not b:
                return 'join denied under lock', _set_thread(s, i, (kind, c, 5, False, b))
            s = s._replace(rooms=s.rooms | {('ch', c), ('pr', c)})
            return f'join enters rooms of {c}', _set_thread(s, i, (kind, c, 4, a, b))
        if pc == 4:
            ok = s.connected and ('ch', c) in s.rooms and ('pr', c) in s.rooms
            return 'join transaction result', _set_thread(s, i, (kind, c, 5, ok, b))
        if pc == 5:
            return 'join commits', _set_thread(_drop_share(s, v), i, (kind, c, 6, a, b))
        if pc == 6:                                  # registry.join + postcondition in one turn
            if not a:
                return 'join answers FORBIDDEN', _set_thread(s, i, None)
            current = s.reg
            if current is not None and current[0] == c:
                previous, joined = None, False
            else:
                previous, joined = current, True
                s = s._replace(reg=(c, s.pid), pid=s.pid + 1)
            if v.p2p_postcondition and (not s.connected or ('ch', c) not in s.rooms):
                s = s._replace(reg=previous)         # rollbackJoin
                return 'join rolled back (room gone)', _set_thread(s, i, None)
            if previous is not None and joined:
                return f'join registers in {c}, leaves {previous[0]}', _set_thread(s, i, (kind, c, 7, previous, b))
            return f'join registers in {c}', _set_thread(s, i, None)
        if pc == 7:
            s = _leave_room(s, ('ch', a[0]), v)
            return f'join leaves previous room {a[0]}', _set_thread(s, i, None)
    if kind == 'S':                                  # voice:sfu:join, a = participant id, b = read/result
        pid = a
        if pc == 1:
            if c not in s.auth:
                return 'sfu preflight denied', _set_thread(s, i, (kind, c, 7, a, False))
            return 'sfu preflight ok', _set_thread(s, i, (kind, c, 2, a, b))
        if pc == 2:
            if not _can_share(s, v):
                return None
            return 'sfu takes shared lock', _set_thread(_take_share(s, v), i, (kind, c, 3, a, b))
        if pc == 3:
            return 'sfu reads access', _set_thread(s, i, (kind, c, 4, a, c in s.auth))
        if pc == 4:
            if not s.connected or not b:
                return 'sfu denied under lock', _set_thread(s, i, (kind, c, 6, a, False))
            s = s._replace(rooms=s.rooms | {('ch', c)})
            return f'sfu enters room of {c}', _set_thread(s, i, (kind, c, 5, a, b))
        if pc == 5:
            ok = s.connected and ('ch', c) in s.rooms
            return 'sfu transaction result', _set_thread(s, i, (kind, c, 6, a, ok))
        if pc == 6:
            return 'sfu commits', _set_thread(_drop_share(s, v), i, (kind, c, 7, a, b))
        if pc == 7:
            if not b or s.sfu != (c, pid):
                return 'sfu join FORBIDDEN', _set_thread(_sfu_fail(s, c, pid), i, None)
            s = s._replace(coord=s.coord | {(pid, c)})          # joinParticipant, synchronous part
            return f'sfu coordinator session p{pid}', _set_thread(s, i, (kind, c, 8, a, b))
        if pc == 8:                                  # router ready; joinParticipant continuation
            if (pid, c) not in s.coord:
                return 'sfu join cancelled', _set_thread(_sfu_fail(s, c, pid), i, None)
            return 'sfu router ready', _set_thread(s, i, (kind, c, 9, a, b))
        if pc == 9:
            if not s.connected or s.sfu != (c, pid) or ('ch', c) not in s.rooms:
                return 'sfu join FORBIDDEN after router', _set_thread(_sfu_fail(s, c, pid), i, None)
            return f'sfu join acknowledged (p{pid})', _set_thread(s._replace(acked=s.acked | {pid}), i, None)
    if kind == 'W':                                  # voice:watch [C1, C2], a = index, b = (listed, read/result)
        listed, r = b
        if pc == 1:
            if a == len(CH):
                return 'watch replies', _watch_reply(_set_thread(s, i, None), listed, v)
            if not s.connected:
                return 'watch stops (disconnected)', _set_thread(s, i, None)
            if CH[a] not in s.auth:
                return f'watch preflight denies {CH[a]}', _set_thread(s, i, (kind, c, 1, a + 1, b))
            return f'watch preflight ok {CH[a]}', _set_thread(s, i, (kind, c, 2, a, b))
        if pc == 2:
            if not _can_share(s, v):
                return None
            return 'watch takes shared lock', _set_thread(_take_share(s, v), i, (kind, c, 3, a, b))
        if pc == 3:
            return f'watch reads access to {CH[a]}', _set_thread(s, i, (kind, c, 4, a, (listed, CH[a] in s.auth)))
        if pc == 4:
            if not s.connected or not r:
                return f'watch denies {CH[a]} under lock', _set_thread(s, i, (kind, c, 6, a, (listed, False)))
            s = s._replace(rooms=s.rooms | {('pr', CH[a])})
            return f'watch enters presence room of {CH[a]}', _set_thread(s, i, (kind, c, 5, a, b))
        if pc == 5:
            ok = s.connected and ('pr', CH[a]) in s.rooms
            return 'watch transaction result', _set_thread(s, i, (kind, c, 6, a, (listed, ok)))
        if pc == 6:
            listed = listed + ((CH[a],) if r else ())
            return 'watch commits', _set_thread(_drop_share(s, v), i, (kind, c, 1, a + 1, (listed, None)))
    raise AssertionError((kind, pc))


def _watch_reply(s: S, channels: tuple, v: Variant) -> S:
    if not s.connected:
        return s
    sent = [c for c in channels if not v.watch_room_filter or ('pr', c) in s.rooms]
    leaked = {c for c in sent if s.revs[CH.index(c)] == 3}
    return s._replace(leaked=s.leaked | leaked) if leaked else s


def m8a_successors(s: S, v: Variant):
    out = []
    for i in range(len(s.threads)):
        step = _step(s, i, v)
        if step is not None:
            out.append(step)
    if s.connected and s.started < v.max_ops:
        for op in v.ops:
            c = CH[int(op[-1]) - 1] if op[-1].isdigit() else None
            t = s._replace(started=s.started + 1)
            if op.startswith('J'):
                out.append((f'event voice:join {c}', t._replace(threads=t.threads + (('J', c, 0, None, None),))))
            elif op.startswith('S') and not op.startswith('SL'):
                if t.sfu is not None:
                    continue                       # ALREADY_JOINED, nothing changes
                t = t._replace(sfu=(c, t.pid), pid=t.pid + 1)
                out.append((f'event voice:sfu:join {c} (p{s.pid})',
                            t._replace(threads=t.threads + (('S', c, 1, s.pid, None),))))
            elif op.startswith('L'):
                if t.reg is None or t.reg[0] != c:
                    continue
                t = _leave_room(t._replace(reg=None), ('ch', c), v)
                out.append((f'event voice:leave {c}', t))
            elif op.startswith('SL'):
                if t.sfu is None or t.sfu[0] != c:
                    continue
                out.append((f'event voice:sfu:leave {c}', _release(t)))
            elif op.startswith('CL'):
                out.append((f'event channel:leave {c}', _leave_room(t, ('ch', c), v)))
            elif op == 'W' and not s.watched:
                out.append(('event voice:watch [C1, C2]',
                            t._replace(watched=True, threads=t.threads + (('W', None, 1, 0, ((), None)),))))
    for k, c in enumerate(CH):
        if c not in v.revoke:
            continue
        r = s.revs[k]
        revs = list(s.revs)
        if r == 0 and (not v.lock or s.lock == 0):
            revs[k] = 1
            out.append((f'revoke {c}: exclusive lock', s._replace(revs=tuple(revs), lock=-1 if v.lock else 0)))
        elif r == 1:
            revs[k] = 2
            out.append((f'revoke {c}: commit', s._replace(revs=tuple(revs), auth=s.auth - {c}, lock=0)))
        elif r == 2:
            revs[k] = 3
            t = _leave_room(s._replace(revs=tuple(revs)), ('pr', c), v)
            out.append((f'revoke {c}: leaveUserChannelRooms', _leave_room(t, ('ch', c), v)))
    if s.connected and not s.disc:
        t = s
        for room in sorted(s.rooms):
            t = _leave_room(t, room, v)
        t = _release(t._replace(connected=False, disc=True))
        out.append(('disconnect', t))
    return out


def m8a_violations(s: S, v: Variant):
    out = []
    if s.reg is not None and (not s.connected or ('ch', s.reg[0]) not in s.rooms):
        out.append(('VP1', f'P2P participant in {s.reg[0]} without being in its room'))
    for room in s.rooms:
        c = room[1]
        if not s.connected:
            out.append(('VP2', f'disconnected socket still in {room}'))
        elif c not in s.auth and s.revs[CH.index(c)] != 2:
            out.append(('VP2', f'socket in {room} after its access was revoked and its rooms were left'))
    if s.sfu is not None and s.sfu[1] in s.acked and (('ch', s.sfu[0]) not in s.rooms or (s.sfu[1], s.sfu[0]) not in s.coord):
        out.append(('VP3', f'acknowledged SFU session p{s.sfu[1]} without room or coordinator session'))
    inflight = {t[3] for t in s.threads if t[0] == 'S'}
    for pid, c in s.coord:
        if (s.sfu is None or s.sfu[1] != pid) and pid not in inflight:
            out.append(('VP3', f'coordinator keeps p{pid} in {c} with no socket session'))
    if s.leaked:
        out.append(('VP4', f'voice:watch reply lists participants of {sorted(s.leaked)} after the socket left its rooms'))
    for k, c in enumerate(CH):
        if s.revs[k] == 3 and not any(t[1] == c or t[0] == 'W' for t in s.threads):
            if s.reg is not None and s.reg[0] == c or s.sfu is not None and s.sfu[0] == c \
                    or any(e[1] == c for e in s.coord) or any(r[1] == c for r in s.rooms):
                out.append(('VP6', f'call state for {c} remains after revocation and every handler finished'))
    return out


def bfs(initial, successors, violations, stop=frozenset()):
    states = {initial: None}
    order = [initial]
    found = {}
    queue = deque([initial])
    transitions = 0
    while queue:
        s = queue.popleft()
        hits = violations(s)
        for prop, message in hits:
            found.setdefault(prop, (s, message))
        if stop and stop <= found.keys():
            break
        if any(prop in stop for prop, _ in hits):
            continue
        for label, nxt in successors(s):
            transitions += 1
            if nxt not in states:
                states[nxt] = (s, label)
                order.append(nxt)
                queue.append(nxt)
    return states, found, transitions


def trace(states, s) -> list[str]:
    steps = []
    while states[s] is not None:
        s, label = states[s]
        steps.append(label)
    return list(reversed(steps))


def run_m8a() -> None:
    impl = Variant()
    states, found, transitions = bfs(m8a_initial(), lambda s: m8a_successors(s, impl),
                                     lambda s: m8a_violations(s, impl))
    print(f'  M8a implementation: {len(states):,} states, {transitions:,} transitions '
          f'(user socket, {impl.max_ops} events from {", ".join(impl.ops)}, both channels revoked, disconnect)')

    def holds(check_id, title, prop, found=found, states=states):
        hit = found.get(prop)
        record('M8', check_id, title, 'HOLDS', hit is not None,
               witness=(trace(states, hit[0]) + ['=> ' + hit[1]]) if hit else [])

    holds('VP1', 'a P2P call participant is always in the call room of its channel', 'VP1')
    holds('VP2', 'the socket is in a call or presence room only while it may join the channel '
                 '(or until the revocation\'s room removal runs)', 'VP2')
    holds('VP3', 'every SFU coordinator session belongs to the socket\'s current SFU session or to a join still '
                 'in progress; an acknowledged one is in the call room', 'VP3')
    holds('VP4', 'a voice:watch reply never lists the participants of a channel whose rooms the socket already '
                 'left on revocation', 'VP4')
    holds('VP6', 'after revocation and once its handlers finish, no call state of the channel remains', 'VP6')

    def control(check_id, title, prop, variant):
        st, fd, _ = bfs(m8a_initial(), lambda s: m8a_successors(s, variant), lambda s: m8a_violations(s, variant),
                        stop=frozenset({prop}))
        hit = fd.get(prop)
        record('M8', check_id, title, 'CONTROL', hit is not None,
               witness=(trace(st, hit[0]) + ['=> ' + hit[1]]) if hit else [])

    control('VP4-ctl', 'before the fix: a watch reply listed a channel revoked while later channels were checked',
            'VP4', Variant(watch_room_filter=False, revoke=('C1', 'C2')))
    control('VP2-ctl', 'checking authorization without the workspace lock lets a join enter a room after the '
                       'revocation left it', 'VP2', Variant(lock=False, revoke=('C1',)))
    control('VP1-ctl', 'registering a P2P participant without rechecking the room keeps a participant after '
                       'revocation', 'VP1', Variant(p2p_postcondition=False, revoke=('C1',)))
    control('VP6-ctl', 'without the SFU leave-room listener the SFU session outlives the revocation', 'VP6',
            Variant(sfu_listener=False, revoke=('C1',)))


# ---------------------------------------------------------------------------
# M8b: the SFU coordinator, real code against a scripted mediasoup
# ---------------------------------------------------------------------------

ALL_OPS = ['join', 'leave', 'transport', 'connect', 'produce', 'consume', 'resume', 'closeProducer', 'close']
M8B_RUNS = [
    ('one channel', dict(maxOps=6, maxJoins=2, channels=['X'], ops=['join', 'leave', 'transport', 'produce', 'consume', 'resume'])),
    ('one channel, failing requests', dict(maxOps=5, maxJoins=2, channels=['X'], failures=True,
                                            ops=['join', 'leave', 'transport', 'produce', 'consume'])),
    ('two channels', dict(maxOps=5, maxJoins=2, channels=['X', 'Y'], ops=['join', 'leave', 'transport', 'produce', 'consume'])),
    ('speaker and listener', dict(maxOps=4, maxJoins=3, channels=['X'], scenario='speaker-listener', ops=ALL_OPS)),
    ('speaker and listener, failing requests', dict(maxOps=3, maxJoins=3, channels=['X'], scenario='speaker-listener',
                                                    failures=True, ops=ALL_OPS)),
    ('listener in another channel', dict(maxOps=4, maxJoins=3, channels=['X', 'Y'], scenario='two-channels', ops=ALL_OPS)),
    ('five speakers', dict(maxOps=5, maxJoins=5, channels=['X'], scenario='five-speakers', ops=['produce'])),
]
M8B_CONTROLS = [
    ('I3-ctl', 'without closing transports on leave, a departed participant keeps a transport', 'I3',
     'leave-keeps-transports', 'one channel'),
    ('I6-ctl', 'without closing the router of an emptied channel, the router stays open', 'I6',
     'empty-channel-keeps-router', 'one channel'),
    ('I3c-ctl', 'creating consumers without the reservation and recheck leaves a consumer unregistered', 'I3',
     'consumer-without-recheck', 'speaker and listener'),
    ('I4-ctl', 'producers created without the pending reservation exceed the four-speaker limit', 'I4',
     'producer-without-reservation', 'five speakers'),
]
M8B_PROPERTIES = [
    ('I1', 'media flows only between a producer and a consumer of the same channel and router'),
    ('I2', 'media flows only to and from participants whose session is current'),
    ('I3', 'every open transport, producer and consumer is registered and belongs to a current session (no leak)'),
    ('I4', 'at most four producers per channel and four consumers per participant'),
    ('I5', 'a session never keeps a closed router; a channel has at most one open router'),
    ('I6', 'once nothing is pending, no router stays open for a channel without participants'),
    ('I7', 'after close() every object is closed, in Node and in the worker'),
    ('J1', 'a join that succeeds leaves its session on a live router'),
]


def run_m8b() -> None:
    base = dict(workers=1, failures=False)
    by_run = {}
    try:
        for name, options in M8B_RUNS:
            out = run_harness('voice-sfu-harness.mts', {**base, **options})
            if not isinstance(out, dict) or not out.get('complete') or out.get('states', 0) < 10:
                raise HarnessError(f'SFU harness did not finish {name}: {str(out)[:200]}')
            by_run[name] = out
            print(f'  M8b {name}: {out["states"]:,} states, {out["executions"]:,} executions of the real coordinator')
        controls = {}
        for check_id, _, prop, mutation, run_name in M8B_CONTROLS:
            options = dict(next(o for n, o in M8B_RUNS if n == run_name))
            controls[check_id] = run_harness('voice-sfu-harness.mts', {**base, **options, 'mutation': mutation,
                                                                      'stop': [prop]})
    except HarnessError as error:
        for prop, title in M8B_PROPERTIES:
            record('M8', prop, title, 'HOLDS', False, str(error), incomplete=True)
        return
    for prop, title in M8B_PROPERTIES:
        hits = [(name, v) for name, out in by_run.items() for v in out['violations'] if v['property'] == prop]
        witness = [f'[{hits[0][0]}]'] + hits[0][1]['trace'] + ['=> ' + hits[0][1]['message']] if hits else []
        record('M8', prop, title, 'HOLDS', bool(hits), witness=witness)
    for check_id, title, prop, _, _ in M8B_CONTROLS:
        hit = next((v for v in controls[check_id].get('violations', []) if v['property'] == prop), None)
        record('M8', check_id, title, 'CONTROL', hit is not None,
               witness=(hit['trace'] + ['=> ' + hit['message']]) if hit else [])


# ---------------------------------------------------------------------------
# M8c: who can obtain call audio
# ---------------------------------------------------------------------------

def audio_readers(mode: str, capability: str) -> set[str]:
    """Parties that end up holding the SRTP keys of A's audio to B.

    P2P: A and B run DTLS-SRTP with each other. Each accepts the peer's DTLS
    certificate only if its fingerprint is in an SDP signed by the peer's
    device key, which it looks up in the directory the server serves
    (voice.store.ts processIncomingSignal). TURN relays SRTP packets.
    SFU: the client runs DTLS-SRTP with the server's WebRtcTransport, whose
    DTLS parameters the server sends (transport-manager.ts); the SFU decrypts
    and re-encrypts every packet. No frame encryption is applied above SRTP.
    """
    readers = {'A', 'B'}
    if mode == 'sfu':
        readers.add('server')               # the SFU terminates DTLS in either case
        return readers
    if capability == 'directory':
        readers.add('server')               # a substituted device key signs the server's own SDP
    return readers


def run_m8c() -> None:
    for capability, label in (('relay', 'relays and drops signaling'), ('turn', 'operates the TURN relay')):
        readers = audio_readers('p2p', capability)
        record('M8', f'VE1-{capability}', f'P2P calls: a server that {label} cannot obtain call audio', 'HOLDS',
               'server' in readers)
    record('M8', 'VE1-directory', 'P2P calls: a server that serves a false device directory can take part in the '
                                  'DTLS handshake (as F-E2E-001 for messages)', 'LIMIT',
           'server' in audio_readers('p2p', 'directory'),
           'signed SDP is checked against the directory the server itself serves')
    record('M8', 'VE2', 'SFU calls: only the participants obtain call audio', 'HOLDS',
           'server' in audio_readers('sfu', 'relay'),
           'the SFU ends DTLS-SRTP, so the server process reads every frame. Not reachable today: clients do not '
           'use the SFU and VOICE_SFU_ENABLED is false by default. Decide before wiring it: frame encryption '
           '(SFrame / encoded transforms keyed from the channel\'s MLS exporter) or a documented change of the '
           'threat model')


def run() -> None:
    print('== M8: voice calls (room grants, call registries, SFU) ==')
    run_m8a()
    run_m8b()
    run_m8c()


if __name__ == '__main__':
    run()
