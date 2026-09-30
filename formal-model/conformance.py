"""M1c: the Python evaluator must agree with the real TypeScript implementation.

Random workspaces (roles, overrides, private/voice channels, owner) are
evaluated by authz.py and by getChannelAuthorizationFromSnapshot /
captureChannelViewersFromSnapshot via conformance/authz-harness.mts.
Any mismatch means the model does not describe the implementation.
"""
from __future__ import annotations

import random

from authz import Channel, Role, Workspace, channel_mask, viewers
from common import ALL_PERMS, CHANNEL_SCOPED, PERM, record
from harness import HarnessError, require_rows, run_harness


def random_mask(rng: random.Random, universe: int, density: float) -> int:
    return sum(bit for bit in (1 << i for i in range(19)) if universe & bit and rng.random() < density)


def random_workspace(rng: random.Random) -> Workspace:
    users = [f'u{i}' for i in range(rng.randint(1, 4))]
    roles = {f'r{i}': Role(f'r{i}', random_mask(rng, ALL_PERMS, 0.4), rng.randint(0, 100)) for i in range(rng.randint(1, 4))}
    members = {u: frozenset(r for r in roles if rng.random() < 0.5) for u in users}
    channels = {}
    for i in range(rng.randint(1, 3)):
        channels[f'c{i}'] = Channel(f'c{i}', rng.choice([None, 'k0', 'k1']), rng.random() < 0.3, rng.random() < 0.3)
    cat, chan = {}, {}
    for role in roles:
        for category in ('k0', 'k1'):
            if rng.random() < 0.4:
                cat[(category, role)] = (random_mask(rng, CHANNEL_SCOPED, 0.3), random_mask(rng, CHANNEL_SCOPED, 0.3))
        for channel in channels:
            if rng.random() < 0.4:
                chan[(channel, role)] = (random_mask(rng, CHANNEL_SCOPED, 0.3), random_mask(rng, CHANNEL_SCOPED, 0.3))
    private = {c: frozenset(u for u in users if rng.random() < 0.5) for c, ch in channels.items() if ch.private}
    return Workspace(rng.choice(users), roles, members, channels, cat, chan, private)


def to_json(ws: Workspace) -> dict:
    return {
        'owner': ws.owner,
        'roles': {n: {'permissions': r.permissions, 'position': r.position} for n, r in ws.roles.items()},
        'members': {u: sorted(rs) for u, rs in ws.members.items()},
        'channels': {n: {'category': c.category, 'private': c.private, 'voice': c.voice} for n, c in ws.channels.items()},
        'categoryOverrides': [[t, r, a, d] for (t, r), (a, d) in ws.category_overrides.items()],
        'channelOverrides': [[t, r, a, d] for (t, r), (a, d) in ws.channel_overrides.items()],
        'privateMembers': {c: sorted(us) for c, us in ws.private_members.items()},
    }


def _allow_wins_mask(ws: Workspace, user: str, channel: str) -> int:
    # Mutant: within a level, allow beats deny.
    ch = ws.channels[channel]
    roles = [r for r in ws.members[user] if r in ws.roles]
    mask = 0
    for role in roles:
        mask |= ws.roles[role].permissions
    for overrides, target in ((ws.category_overrides, ch.category), (ws.channel_overrides, channel)):
        if target is None:
            continue
        allow = deny = 0
        for role in roles:
            a, d = overrides.get((target, role), (0, 0))
            allow |= a
            deny |= d
        mask = (mask & ~deny) | allow
    return mask | CHANNEL_SCOPED if user == ws.owner else mask


def run(cases: int = 400, seed: int = 20260929) -> None:
    print('== M1c: model/implementation conformance (authorization) ==')
    if cases < 1:
        raise ValueError('At least one conformance case is required')
    rng = random.Random(seed)
    workspaces = [random_workspace(rng) for _ in range(cases)]
    try:
        result = run_harness('authz-harness.mts', [to_json(ws) for ws in workspaces])
        if not isinstance(result, dict):
            raise HarnessError('Expected authorization harness metadata and results')
        if result.get('permissions') != PERM or result.get('channelScopedMask') != CHANNEL_SCOPED:
            raise HarnessError('Python permission constants differ from the TypeScript implementation')
        outputs = require_rows(result.get('results'), len(workspaces))
        for ws, out in zip(workspaces, outputs, strict=True):
            if not isinstance(out.get('masks'), dict) or set(out['masks']) != set(ws.members) | {'__nonmember__'}:
                raise HarnessError('Missing or unexpected user results')
            for user, masks in out['masks'].items():
                if not isinstance(masks, dict) or set(masks) != set(ws.channels) | {'__missing_channel__'} or any(type(mask) is not int for mask in masks.values()):
                    raise HarnessError('Missing or malformed channel masks')
                if masks['__missing_channel__'] != -1 or (user == '__nonmember__' and any(mask != -1 for mask in masks.values())):
                    raise HarnessError('Unknown channel or non-member unexpectedly authorized')
            if not isinstance(out.get('viewers'), dict) or set(out['viewers']) != set(ws.channels) or not all(isinstance(v, list) and all(isinstance(u, str) for u in v) for v in out['viewers'].values()):
                raise HarnessError('Missing or malformed viewer results')
    except HarnessError as error:
        record('M1c', 'C1', 'Python evaluator equals TypeScript implementation', 'HOLDS', False,
               str(error), incomplete=True)
        return
    mismatches = []
    for index, (ws, out) in enumerate(zip(workspaces, outputs, strict=True)):
        for user in ws.members:
            for channel in ws.channels:
                expected = channel_mask(ws, user, channel)
                actual = out['masks'][user][channel]
                if (expected if expected is not None else -1) != actual:
                    mismatches.append(f'case {index} {user}/{channel}: model={expected} impl={actual}')
        for channel in ws.channels:
            if sorted(viewers(ws, channel)) != sorted(out['viewers'].get(channel, [])):
                mismatches.append(f'case {index} viewers {channel}: model={sorted(viewers(ws, channel))} impl={out["viewers"].get(channel)}')
    comparisons = sum(len(ws.members) * len(ws.channels) for ws in workspaces)
    # CONTROL: an evaluator with allow-wins instead of deny-wins must disagree.
    mutated = 0
    for ws, out in zip(workspaces, outputs, strict=True):
        for user in ws.members:
            for channel in ws.channels:
                if _allow_wins_mask(ws, user, channel) != out['masks'][user][channel]:
                    mutated += 1
    record('M1c', 'C0', 'an allow-wins evaluator is detected as non-conforming', 'CONTROL', mutated > 0,
           f'{mutated} mismatches for the mutant')
    record('M1c', 'C1', f'Python evaluator equals TypeScript implementation ({cases} random workspaces, {comparisons} masks)',
           'HOLDS', bool(mismatches), f'{len(mismatches)} mismatches' if mismatches else '', mismatches)


if __name__ == '__main__':
    import argparse
    import common
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cases', type=int, default=400)
    parser.add_argument('--seed', type=int, default=20260929)
    args = parser.parse_args()
    run(args.cases, args.seed)
    raise SystemExit(0 if all(result.ok for result in common.RESULTS) else 1)
