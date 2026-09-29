"""M3: channel key epochs — exhaustive exploration of the E2EE key protocol.

Mirrors key.service.ts (commitChannelKeyDistribution, acknowledgeChannelKey,
getChannelKeyRecipientState), key-epoch-state.ts and message.service.ts:

  propose     no pending; proposer eligible; with an active epoch only when
              rotation is required and the proposer accepted the active
              epoch (or no eligible holder is left and the proposer may
              manage the channel). Recipients = eligible snapshot, all
              required. Sets the rotation flag (old epoch stops writes).
  fresh-start manager/DM only, rotation or pending required, not by a holder
              of a healthy active epoch; aborts any pending epoch.
  ack         recipient of a pending epoch learns the key; the last required
              ack activates only if recipients still equal the eligible set,
              otherwise aborts and keeps the rotation flag.
  fetch       recipient device of a current viewer learns the key of a
              pending/active/retired epoch (F-KEY-001 fix).
  backfill    legacy (protocol 2) active epoch only, flag clear, no revoked
              recipient: a new device of an original roster user is added as
              a non-required recipient.
  send        protocol 3 active epoch, flag clear, recipients == eligible,
              no revoked recipient, sender accepted.
  viewer +/-, device approve/revoke: abort pending, rotation required.
  restore     a device learns every key its user's devices hold (backup).
  stall       an eligible manager aborts a pending epoch after 15 minutes.
              An orphan's non-manager may fresh-start after the same delay.
  expire      after 24 hours, an active MLS epoch requires rotation.

Waiting 15 minutes is folded into the guarded abort/fresh-start transition;
the 24-hour threshold is represented by the effective rotation flag. These
are reachability abstractions, not a wall-clock response-time guarantee.

eligible = approved, non-revoked devices of current viewers.
Knowledge is permanent: a device keeps every key it ever learned.
The initial state is a migrated channel: a legacy protocol-2 epoch v1 held by
X1 and Y1 with one message already sent to {X, Y}.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace

from common import record

USERS = ('X', 'Y', 'Z')
DEVICES = {'X1': 'X', 'X2': 'X', 'Y1': 'Y', 'Z1': 'Z'}
MANAGERS = {'X'}                       # hold MANAGE_CHANNELS
MAX_EPOCHS = 4


@dataclass(frozen=True)
class Epoch:
    version: int
    status: str                 # pending | active | retired | aborted
    recipients: frozenset
    required: frozenset
    accepted: frozenset
    protocol: int = 3


@dataclass(frozen=True)
class State:
    viewers: frozenset
    devices: tuple              # ((device, none|unapproved|approved|revoked), ...)
    epochs: tuple
    rotation: bool
    known: tuple                # ((device, frozenset(versions)), ...)
    messages: frozenset         # {(version, frozenset(viewers at send))}
    viewer_changes: int = 0     # bounded so the state space stays finite
    device_changes: int = 0

    def status(self, device):
        return dict(self.devices)[device]

    def eligible(self):
        return frozenset(d for d, s in self.devices if s == 'approved' and DEVICES[d] in self.viewers)

    def knows(self, device):
        return dict(self.known)[device]

    def active(self):
        return next((e for e in self.epochs if e.status == 'active'), None)

    def pending(self):
        return next((e for e in self.epochs if e.status == 'pending'), None)

    def revoked_recipient(self, epoch):
        return any(self.status(d) == 'revoked' for d in epoch.recipients)

    def effective_rotation(self):
        active = self.active()
        return self.rotation or (active is not None and (
            active.protocol < 3 or active.recipients != self.eligible() or self.revoked_recipient(active)))


@dataclass(frozen=True)
class Variant:
    activation_recheck: bool = True       # isRecipientSnapshotStillAuthorized at activation
    send_roster_check: bool = True        # rotation flag / isEpochRosterCurrent / revoked recipient at send
    retired_fetch: bool = True            # F-KEY-001 fix
    malicious_server: bool = False        # server lies about membership and skips its own checks
    lost_device: str | None = None        # an approved device that never acts again
    max_epochs: int = MAX_EPOCHS          # smaller for variants that only need a counterexample
    orphan_fresh_start: bool = True       # non-managers may fresh-start an orphaned channel


INITIAL = State(
    viewers=frozenset({'X', 'Y'}),
    devices=(('X1', 'approved'), ('X2', 'none'), ('Y1', 'approved'), ('Z1', 'approved')),
    epochs=(Epoch(1, 'active', frozenset({'X1', 'Y1'}), frozenset({'X1', 'Y1'}), frozenset({'X1', 'Y1'}), protocol=2),),
    rotation=False,
    known=tuple((d, frozenset({1}) if d in ('X1', 'Y1') else frozenset()) for d in DEVICES),
    messages=frozenset({(1, frozenset({'X', 'Y'}))}),
)


def _learn(state, device, version):
    return tuple((d, k | {version} if d == device else k) for d, k in state.known)


def _abort_pending(epochs):
    return tuple(replace(e, status='aborted', accepted=frozenset()) if e.status == 'pending' else e for e in epochs)


def _set_device(state, device, status):
    return tuple((d, status if d == device else s) for d, s in state.devices)


def _new_epoch(state, epochs, proposer, roster, label):
    epoch = Epoch(len(epochs) + 1, 'pending', frozenset(roster), frozenset(roster), frozenset())
    return label + f' v{epoch.version} to {sorted(roster)}', replace(
        state, epochs=epochs + (epoch,), rotation=True, known=_learn(state, proposer, epoch.version))


def senders(state: State, v: Variant):
    """Devices the send guard (message.service.ts) currently admits."""
    active = state.active()
    if active is None or active.protocol != 3:
        return []
    roster_ok = not state.rotation and active.recipients == state.eligible() and not state.revoked_recipient(active)
    if not (roster_ok or not v.send_roster_check or v.malicious_server):
        return []
    return [d for d in sorted(active.accepted) if d != v.lost_device and state.status(d) == 'approved']


def transitions(state: State, v: Variant):
    eligible = state.eligible()
    pending, active = state.pending(), state.active()
    acting = [d for d in DEVICES if d != v.lost_device]
    server_checks = not v.malicious_server
    rosters = [eligible] if server_checks else sorted(
        {eligible | {extra} for extra in DEVICES if state.status(extra) == 'approved'}, key=sorted)

    if len(state.epochs) < v.max_epochs:
        holders = active.accepted & eligible if active else frozenset()
        for proposer in acting:
            if proposer not in eligible:
                continue
            manager = DEVICES[proposer] in MANAGERS
            # ordinary proposal
            if pending is None and (active is None or (
                    state.effective_rotation() and (proposer in active.accepted or (not holders and manager)))):
                for roster in rosters:
                    yield _new_epoch(state, state.epochs, proposer, roster, f'{proposer}: propose')
            # fresh start (step-up): managers, or any viewer once no eligible
            # device holds the active key. A pending proposal must first stall.
            orphaned = active is not None and not holders and v.orphan_fresh_start
            if (manager or orphaned) and ((active and state.effective_rotation()) or pending) and not (
                    active and pending is None and proposer in active.accepted):
                for roster in rosters:
                    wait = ' (after 15 minutes)' if not manager and pending else ''
                    yield _new_epoch(state, _abort_pending(state.epochs), proposer, roster, f'{proposer}: fresh-start{wait}')

    # ack; the last required ack activates or aborts
    if pending is not None:
        for device in sorted(pending.recipients - pending.accepted):
            if device not in acting or state.status(device) != 'approved' or (server_checks and DEVICES[device] not in state.viewers):
                continue
            accepted = pending.accepted | {device}
            known = _learn(state, device, pending.version)
            epochs, rotation, label = list(state.epochs), state.rotation, f'{device}: ack v{pending.version}'
            if pending.required <= accepted:
                if not v.activation_recheck or v.malicious_server or pending.recipients == eligible:
                    epochs = [replace(e, status='retired') if e.status == 'active' else e for e in epochs]
                    epochs = [replace(e, status='active', accepted=accepted) if e.version == pending.version else e for e in epochs]
                    rotation, label = False, label + ' -> active'
                else:
                    epochs = list(_abort_pending(tuple(epochs)))
                    label += ' -> aborted (roster changed)'
            else:
                epochs = [replace(e, accepted=accepted) if e.version == pending.version else e for e in epochs]
            yield label, replace(state, epochs=tuple(epochs), rotation=rotation, known=known)

    # fetch without acknowledging
    for epoch in state.epochs:
        if epoch.status == 'aborted' or (epoch.status == 'retired' and not v.retired_fetch):
            continue
        for device in sorted(epoch.recipients):
            allowed = state.status(device) == 'approved' and (not server_checks or DEVICES[device] in state.viewers)
            if device in acting and allowed and epoch.version not in state.knows(device):
                yield f'{device}: fetch v{epoch.version} ({epoch.status})', replace(state, known=_learn(state, device, epoch.version))

    # legacy backfill of a new device of an original roster user
    if active is not None and active.protocol == 2 and not state.rotation and not state.revoked_recipient(active):
        original_users = {DEVICES[d] for d in active.required}
        for device in sorted(eligible - active.recipients):
            if DEVICES[device] in original_users:
                epochs = tuple(replace(e, recipients=e.recipients | {device}) if e is active else e for e in state.epochs)
                yield f'backfill v{active.version} to {device}', replace(state, epochs=epochs)

    # send
    for device in senders(state, v):
        message = (active.version, state.viewers)
        if message not in state.messages:
            yield f'{device}: send under v{active.version} (viewers {sorted(state.viewers)})', replace(
                state, messages=state.messages | {message})

    # authorization changes
    if state.viewer_changes < 2:
        for user in USERS:
            viewers = state.viewers ^ {user}
            if viewers:
                yield f'authz: {user} {"loses" if user in state.viewers else "gains"} view', replace(
                    state, viewers=viewers, epochs=_abort_pending(state.epochs), rotation=True,
                    viewer_changes=state.viewer_changes + 1)

    # device lifecycle
    if state.device_changes < 2:
        for device, status in state.devices:
            if status == 'none':
                yield f'{device}: register', replace(state, devices=_set_device(state, device, 'unapproved'),
                                                     device_changes=state.device_changes + 1)
            elif status == 'unapproved':
                yield f'{device}: approved', replace(state, devices=_set_device(state, device, 'approved'),
                                                     epochs=_abort_pending(state.epochs), device_changes=state.device_changes + 1)
            elif status == 'approved' and device != v.lost_device:
                yield f'{device}: revoked', replace(state, devices=_set_device(state, device, 'revoked'),
                                                    epochs=_abort_pending(state.epochs), rotation=True,
                                                    device_changes=state.device_changes + 1)

    # history restore within one user
    for device in acting:
        if state.status(device) == 'approved':
            pooled = frozenset().union(*(state.knows(d) for d in DEVICES if DEVICES[d] == DEVICES[device]))
            if pooled - state.knows(device):
                yield f'{device}: restore history', replace(
                    state, known=tuple((d, k | pooled if d == device else k) for d, k in state.known))

    # Clock threshold: effective_rotation and the send-time age guard both see
    # this state as requiring rotation even though the DB flag may remain false.
    if active is not None and active.protocol == 3 and not state.rotation:
        yield 'clock: active epoch reaches 24 hours', replace(state, rotation=True)

    # The abort endpoint requires an eligible manager and its device signature.
    # It is never an unconditional recovery action when all managers are gone.
    if pending is not None:
        for device in sorted(eligible):
            if device in acting and DEVICES[device] in MANAGERS:
                yield f'{device}: abort stalled v{pending.version} (after 15 minutes)', replace(
                    state, epochs=_abort_pending(state.epochs), rotation=True)


def violations(state: State, v: Variant):
    out = []
    for version, viewers in state.messages:
        for device in DEVICES:
            if version in state.knows(device) and DEVICES[device] not in viewers:
                out.append(('KC', f'{device} ({DEVICES[device]}) holds the key of a v{version} message sent to {sorted(viewers)}'))
    if v.lost_device is None:
        options = None
        for epoch in state.epochs:
            if epoch.status not in ('active', 'retired'):
                continue
            for device in epoch.recipients:
                if (state.status(device) == 'approved' and DEVICES[device] in state.viewers
                        and epoch.version not in state.knows(device)):
                    if options is None:
                        options = [label for label, _ in transitions(state, v)]
                    if not any(label.startswith(f'{device}: fetch v{epoch.version} ') for label in options):
                        out.append(('KA', f'{device} cannot obtain the v{epoch.version} ({epoch.status}) key it was given'))
    if sum(e.status == 'pending' for e in state.epochs) > 1 or sum(e.status == 'active' for e in state.epochs) > 1:
        out.append(('KI', 'more than one pending or active epoch'))
    return out


def explore(v: Variant):
    parent = {INITIAL: None}
    queue = deque([INITIAL])
    found = {}
    while queue:
        state = queue.popleft()
        for prop, message in violations(state, v):
            found.setdefault(prop, (state, message))
        for label, nxt in transitions(state, v):
            if nxt not in parent:
                parent[nxt] = (state, label)
                queue.append(nxt)
    return parent, found


def trace(parent, state):
    steps = []
    while parent[state]:
        state, label = parent[state]
        steps.append(label)
    return list(reversed(steps))


PROTOCOL_STEPS = ('propose', 'fresh-start', 'ack', 'fetch', 'abort stalled', 'restore', 'backfill')


def stuck_states(parent, v: Variant):
    """Liveness: from every state with an acting eligible device and room for
    two more epochs, protocol steps alone (no authorization or device changes)
    must reach a state where a message can be sent. Computed as a backward
    fixpoint over the explored graph, so memory stays linear."""
    from array import array
    states = list(parent)
    index = {state: i for i, state in enumerate(states)}
    good = bytearray(len(states))
    edges_from, edges_to = array('i'), array('i')
    for i, state in enumerate(states):
        if senders(state, v):
            good[i] = 1
        for label, nxt in transitions(state, v):
            if any(step in label for step in PROTOCOL_STEPS):
                j = index.get(nxt)
                if j is not None:
                    edges_from.append(i)
                    edges_to.append(j)
    del index
    # predecessor lists in CSR form (counting sort; int32 arrays only)
    n = len(states)
    starts = array('i', bytes(4 * (n + 1)))
    for j in edges_to:
        starts[j + 1] += 1
    for i in range(n):
        starts[i + 1] += starts[i]
    fill = array('i', starts)
    preds = array('i', bytes(4 * len(edges_to)))
    for i, j in zip(edges_from, edges_to):
        preds[fill[j]] = i
        fill[j] += 1
    del fill, edges_from, edges_to
    work = [i for i in range(len(states)) if good[i]]
    while work:
        j = work.pop()
        for k in range(starts[j], starts[j + 1]):
            i = preds[k]
            if not good[i]:
                good[i] = 1
                work.append(i)
    stuck = []
    for i, state in enumerate(states):
        acting = state.eligible() - ({v.lost_device} if v.lost_device else set())
        if acting and len(state.epochs) <= v.max_epochs - 2 and not good[i]:
            stuck.append(state)
    return stuck


def run() -> None:
    print('== M3: channel key epochs (exhaustive) ==')
    base = Variant()
    parent, found = explore(base)
    stats = {
        'messages': sum(1 for s in parent if len(s.messages) > 1),
        'retired': sum(1 for s in parent if any(e.status == 'retired' for e in s.epochs)),
        'backfilled': sum(1 for s in parent if any(e.recipients != e.required for e in s.epochs)),
    }
    print(f'     explored {len(parent)} states; new messages in {stats["messages"]}, retired epochs in {stats["retired"]}, '
          f'backfilled recipients in {stats["backfilled"]}')

    def show(check_id, title, expect, prop, result):
        par, fnd = result
        hit = fnd.get(prop)
        witness = trace(par, hit[0]) + ['=> ' + hit[1]] if hit else []
        record('M3', check_id, title, expect, hit is not None, witness=witness)

    show('KC', 'a message key is only ever held by devices of viewers at send time (removal, joining, restore)',
         'HOLDS', 'KC', (parent, found))
    show('KA', 'a recipient that is still an approved viewer can always obtain a key it was given', 'HOLDS', 'KA', (parent, found))
    show('KI', 'at most one pending and one active epoch', 'HOLDS', 'KI', (parent, found))
    stuck = stuck_states(parent, base)

    def can_recover(state):
        active = state.active()
        eligible = state.eligible()
        holder = active is not None and bool(active.accepted & eligible)
        manager = any(DEVICES[d] in MANAGERS for d in eligible)
        return active is None or holder or manager

    recoverable = [s for s in stuck if can_recover(s)]
    orphaned = [s for s in stuck if not can_recover(s)]
    record('M3', 'KL', 'while an eligible key holder or manager remains, protocol steps alone reach a sendable state', 'HOLDS',
           bool(recoverable), witness=(trace(parent, recoverable[0]) if recoverable else []))
    record('M3', 'KL-orphan', 'a channel left only with non-manager members who never held the active key can resume by itself',
           'HOLDS', bool(orphaned), f'{len(orphaned)} reachable states', witness=(trace(parent, orphaned[0]) if orphaned else []))

    del parent, found, stuck
    orphan_ctl = Variant(orphan_fresh_start=False, max_epochs=3)
    orphan_parent, _ = explore(orphan_ctl)
    orphan_stuck = [st for st in stuck_states(orphan_parent, orphan_ctl) if not can_recover(st)]
    record('M3', 'KL-orphan-ctl', 'without the orphaned-channel fresh start, such a channel stays unwritable', 'CONTROL',
           bool(orphan_stuck))
    del orphan_parent, orphan_stuck

    lost = Variant(lost_device='Y1')
    lost_parent, _ = explore(lost)
    lost_stuck = stuck_states(lost_parent, lost)
    record('M3', 'KL-lost', 'a permanently offline approved device blocks new epochs until it is revoked (F-KEY-007)',
           'LIMIT', bool(lost_stuck), witness=(trace(lost_parent, lost_stuck[0]) if lost_stuck else []))
    del lost_parent, lost_stuck

    show('KC-server', 'a server that misreports membership can give a non-viewer the key (F-E2E-001)', 'LIMIT', 'KC',
         explore(Variant(malicious_server=True, max_epochs=3)))
    show('KC-ctl1', 'without the activation re-check and send-time check, a removed member keeps reading', 'CONTROL', 'KC',
         explore(Variant(activation_recheck=False, send_roster_check=False, max_epochs=3)))
    show('KC-ctl2', 'without the send-time roster check, a removed member keeps reading', 'CONTROL', 'KC',
         explore(Variant(send_roster_check=False, max_epochs=3)))
    show('KA-ctl', 'without retired-delivery fetch, a backfilled recipient loses its key (the F-KEY-001 bug)', 'CONTROL', 'KA',
         explore(Variant(retired_fetch=False, max_epochs=3)))


if __name__ == '__main__':
    run()
