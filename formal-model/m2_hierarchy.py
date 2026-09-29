"""M2: role hierarchy — exhaustive exploration of management operations.

State: roles, assignments, category/channel overrides, membership.
Actors: every non-owner member. Operations and their preconditions copy
role.service.ts, permission-override.service.ts, workspace.service.ts and the
route gates (requireWorkspacePermission / requireChannelPermission).

Per-transition properties (actor a, member u):
  H1 no escalation   bits u gains are held by a (or are u's own workspace
                     baseline being restored); u's rank rises only below a.
  H2 superior safety a member ranked >= a (u != a) keeps membership, workspace
                     bits, channel bits and channel visibility.
  H3 owner safety    the owner never loses anything.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace
from itertools import product

from authz import Channel, Role, Workspace, channel_mask, highest_position, visible, workspace_mask
from common import PERM, names, record

VIEW, SEND = PERM['VIEW_CHANNELS'], PERM['SEND_MESSAGES']
MR, MC, KICK = PERM['MANAGE_ROLES'], PERM['MANAGE_CHANNELS'], PERM['KICK_MEMBERS']
USED = [VIEW, SEND, MR, MC, KICK]
ALL_USED = sum(USED)
SCOPED = [VIEW, SEND]
STANDARD = {'Owner', 'Administrator', 'SecurityManager', 'Member', 'Guest', 'Integration'}
TARGETS = [('category', 'k1'), ('category', 'k2'), ('channel', 'c1'), ('channel', 'c2')]


def subsets(bits):
    for flags in product([0, 1], repeat=len(bits)):
        yield sum(b for b, f in zip(bits, flags) if f)


@dataclass(frozen=True)
class State:
    roles: tuple            # ((name, perms, position), ...)
    members: tuple          # ((user, (role, ...)), ...)
    cat: tuple              # ((category, role, allow, deny), ...)
    chan: tuple             # ((channel, role, allow, deny), ...)
    private: tuple = ('A', 'M', 'O')   # explicit members of private channel c2
    private_c1: tuple = ()
    layout: tuple = (('c1', 'k1', False), ('c2', 'k1', True))
    categories: tuple = ('k1', 'k2')

    def workspace(self) -> Workspace:
        return Workspace(
            owner='O',
            roles={n: Role(n, p, pos) for n, p, pos in self.roles},
            members={u: frozenset(rs) for u, rs in self.members},
            channels={c: Channel(c, category, private=private) for c, category, private in self.layout},
            category_overrides={(t, r): (a, d) for t, r, a, d in self.cat},
            channel_overrides={(t, r): (a, d) for t, r, a, d in self.chan},
            private_members={'c1': frozenset(self.private_c1), 'c2': frozenset(self.private)},
        )


INITIAL = State(
    roles=(('Owner', ALL_USED, 100), ('Administrator', ALL_USED, 90), ('Manager', VIEW | SEND | MR | MC | KICK, 60),
           ('Member', VIEW | SEND, 50)),
    members=(('O', ('Member', 'Owner')), ('A', ('Administrator', 'Member')), ('M', ('Manager', 'Member')), ('U', ('Member',))),
    cat=(), chan=(),
)


def _set_members(state, user, roles):
    members = tuple(sorted((u, rs) for u, rs in state.members if u != user)
                    + ([(user, tuple(sorted(roles)))] if roles is not None else []))
    return replace(state, members=members)


def transitions(state: State, unassign_rank_check: bool = True, only_actor: str | None = None,
                only_ops: tuple[str, ...] | None = None):
    """Yield (actor, description, next_state) for every permitted operation."""
    for actor, label, nxt in _transitions(state, unassign_rank_check):
        if only_actor and actor != only_actor:
            continue
        if only_ops and label.split('(')[0] not in only_ops:
            continue
        yield actor, label, nxt


def _transitions(state: State, unassign_rank_check: bool = True):
    ws = state.workspace()
    roles = {n: (p, pos) for n, p, pos in state.roles}
    for actor in sorted(ws.members):
        if actor == ws.owner:
            continue
        perms = workspace_mask(ws, actor)
        top = highest_position(ws, actor)
        positions = sorted({pos for pos in (10, 55, 59, 70, 85) if pos < top})

        if perms & MR:
            # createRole: position < actor, permissions subset of actor (assertCanCreateOrAssign)
            if 'R' not in roles:
                for p in subsets([b for b in USED if perms & b]):
                    for pos in positions:
                        yield actor, f'createRole(R, {names(p)}, pos={pos})', replace(state, roles=state.roles + (('R', p, pos),))
            for name, (p0, pos0) in roles.items():
                if name == 'Owner' or pos0 >= top:
                    continue                                   # assertRoleCanBeManaged
                # updateRole: new permissions/position again bounded by the actor
                for p in subsets([b for b in USED if perms & b]):
                    for pos in positions:
                        if (p, pos) != (p0, pos0):
                            new_roles = tuple((n, p if n == name else q, pos if n == name else r) for n, q, r in state.roles)
                            yield actor, f'updateRole({name}, {names(p)}, pos={pos})', replace(state, roles=new_roles)
                # deleteRole: custom, unassigned, no overrides
                in_use = any(name in rs for _, rs in state.members) or any(r == name for _, r, _, _ in state.cat + state.chan)
                if name not in STANDARD and not in_use:
                    yield actor, f'deleteRole({name})', replace(state, roles=tuple(x for x in state.roles if x[0] != name))
                # assign / unassign
                for user, held in state.members:
                    if name not in held and (p0 & ~perms) == 0:
                        yield actor, f'assign({user}, {name})', _set_members(state, user, held + (name,))
                    if name in held:
                        target_ok = user == actor or highest_position(ws, user) < top
                        if target_ok or not unassign_rank_check:
                            yield actor, f'unassign({user}, {name})', _set_members(state, user, tuple(r for r in held if r != name))

        # permission overrides (category needs workspace VIEW|MANAGE_CHANNELS,
        # channel needs channel-level MANAGE_CHANNELS on a visible channel)
        for kind, target in TARGETS:
            if kind == 'category':
                if target not in state.categories:
                    continue
                if (perms & (VIEW | MC)) != (VIEW | MC):
                    continue
                authority = perms
                current_table = {(t, r): (a, d) for t, r, a, d in state.cat}
            else:
                if target not in ws.channels:
                    continue
                cm = channel_mask(ws, actor, target)
                if not visible(ws, actor, target) or not cm & MC:
                    continue
                authority = perms & cm
                current_table = {(t, r): (a, d) for t, r, a, d in state.chan}
            for name, (_, pos0) in roles.items():
                if name == 'Owner' or pos0 >= top:
                    continue
                old = current_table.get((target, name), (0, 0))
                options = [(a, d) for a in subsets(SCOPED) for d in subsets(SCOPED)] + [None]
                for option in options:
                    new = option or (0, 0)
                    if option is None and (target, name) not in current_table:
                        continue
                    if option is not None and option == old:
                        continue
                    affected = new[0] | new[1] | old[0] | old[1]
                    if affected & ~authority:
                        continue
                    table = {k: v for k, v in current_table.items() if k != (target, name)}
                    if option is not None:
                        table[(target, name)] = option
                    rows = tuple(sorted((t, r, a, d) for (t, r), (a, d) in table.items()))
                    label = f'{kind}Override({target}, {name}, allow={names(new[0])}, deny={names(new[1])})' if option else f'deleteOverride({target}, {name})'
                    yield actor, label, replace(state, cat=rows) if kind == 'category' else replace(state, chan=rows)

        # remove a private channel member (channel.service removeChannelMember):
        # channel-level MANAGE_CHANNELS on the visible private channel, at least
        # one explicit member must remain
        for channel, category, private in state.layout:
            if not visible(ws, actor, channel) or not (channel_mask(ws, actor, channel) or 0) & MC:
                continue
            field = 'private' if channel == 'c2' else 'private_c1'
            members = getattr(state, field)
            if private and len(members) > 1:
                for user in members:
                    yield actor, f'removePrivateMember({channel}, {user})', replace(
                        state, **{field: tuple(u for u in members if u != user)})
            layout = tuple((c, cat, not p if c == channel else p) for c, cat, p in state.layout)
            yield actor, f'privacy({channel}, {not private})', replace(
                state, layout=layout, **{field: (actor,) if not private else ()})
            for destination in (None, *state.categories):
                if destination != category:
                    layout = tuple((c, destination if c == channel else cat, p) for c, cat, p in state.layout)
                    yield actor, f'moveChannel({channel}, {destination})', replace(state, layout=layout)
            yield actor, f'deleteChannel({channel})', replace(
                state, layout=tuple(row for row in state.layout if row[0] != channel))
        if (perms & (VIEW | MC)) == (VIEW | MC):
            for category in state.categories:
                yield actor, f'deleteCategory({category})', replace(
                    state, categories=tuple(c for c in state.categories if c != category),
                    layout=tuple((c, None if cat == category else cat, p) for c, cat, p in state.layout),
                    cat=tuple(row for row in state.cat if row[0] != category))

        # kick: KICK_MEMBERS and strictly higher rank (assertMemberRemovalAuthorized)
        if perms & KICK:
            for user, _ in state.members:
                if user != actor and user != ws.owner and top > highest_position(ws, user):
                    yield actor, f'kick({user})', _set_members(state, user, None)


def observe(ws: Workspace):
    out = {}
    for u in ws.members:
        out[u] = (workspace_mask(ws, u), highest_position(ws, u),
                  {c: (channel_mask(ws, u, c), visible(ws, u, c)) for c in ws.channels})
    return out


def check_transition(before: Workspace, after: Workspace, actor: str):
    """Return the list of violated properties for one transition."""
    violations = []
    b, a = observe(before), observe(after)
    actor_perms = b[actor][0]
    actor_top = b[actor][1]
    for user, (ws_b, top_b, chans_b) in b.items():
        superior = user != actor and top_b >= actor_top
        if user not in a:
            if superior:
                violations.append(('H2', f'{user} was removed'))
            if user == before.owner:
                violations.append(('H3', 'owner removed'))
            continue
        ws_a, top_a, chans_a = a[user]
        gained = ws_a & ~ws_b
        if gained & ~actor_perms:
            violations.append(('H1', f'{user} gained workspace bits {names(gained & ~actor_perms)} not held by {actor}'))
        if top_a > top_b and top_a >= actor_top:
            violations.append(('H1', f'{user} rank rose to {top_a} >= {actor} ({actor_top})'))
        for channel, (mask_b, vis_b) in chans_b.items():
            mask_a, vis_a = chans_a.get(channel, (0, False))
            gained = mask_a & ~mask_b
            if gained & ~(actor_perms | ws_b):
                violations.append(('H1', f'{user} gained {names(gained)} on {channel}'))
            lost = channel not in chans_a or (mask_b & ~mask_a) or (vis_b and not vis_a)
            if lost and superior:
                violations.append(('H2', f'{user} (rank {top_b}) lost {names(mask_b & ~mask_a)}{" and visibility" if vis_b and not vis_a else ""} on {channel}'))
            if lost and user == before.owner:
                violations.append(('H3', f'owner lost {names(mask_b & ~mask_a)} on {channel}'))
        if ws_b & ~ws_a and superior:
            violations.append(('H2', f'{user} (rank {top_b}) lost workspace bits {names(ws_b & ~ws_a)}'))
        if ws_b & ~ws_a and user == before.owner:
            violations.append(('H3', 'owner lost workspace bits'))
    return violations


# Operations checked by assertNoSuperiorAccessLoss (authorization.service.ts).
GUARDED = {'updateRole', 'assign', 'unassign', 'categoryOverride', 'channelOverride', 'deleteOverride',
           'removePrivateMember', 'privacy', 'moveChannel', 'deleteChannel', 'deleteCategory'}


def explore(depth: int, unassign_rank_check: bool = True, superior_guard: bool = True, initial=INITIAL, **focus):
    seen = {initial: None}
    queue = deque([(initial, 0)])
    found = {}          # (property, operation kind) -> (trace, message)
    transitions_checked = 0
    while queue:
        state, d = queue.popleft()
        before = state.workspace()
        for actor, label, nxt in transitions(state, unassign_rank_check, **focus):
            violations = check_transition(before, nxt.workspace(), actor)
            if superior_guard and label.split('(')[0] in GUARDED and any(p == 'H2' for p, _ in violations):
                continue            # the server refuses this operation
            transitions_checked += 1
            for prop, message in violations:
                key = (prop, label.split('(')[0])
                if key not in found:
                    trace = _trace(seen, state) + [f'{actor}: {label}']
                    found[key] = (trace, message)
            if nxt not in seen and d + 1 < depth:
                seen[nxt] = (state, f'{actor}: {label}')
                queue.append((nxt, d + 1))
            elif nxt not in seen:
                seen[nxt] = (state, f'{actor}: {label}')
    return found, len(seen), transitions_checked


def _trace(seen, state):
    steps = []
    while seen.get(state):
        state, step = seen[state]
        steps.append(step)
    return list(reversed(steps))


def run(depth: int = 2) -> None:
    print(f'== M2: role hierarchy (exhaustive, depth {depth}) ==')
    found, states, checked = explore(depth)
    print(f'     explored {states} states, checked {checked} transitions')

    def report(check_id, title, expect, keys):
        hits = {k: v for k, v in found.items() if keys(k)}
        witness = []
        for (prop, op), (trace, message) in sorted(hits.items()):
            witness.append(f'[{op}] {message}')
            witness.extend(f'    {step}' for step in trace)
        record('M2', check_id, title, expect, bool(hits), witness=witness)

    report('H1', 'no management operation grants a permission the actor lacks', 'HOLDS', lambda k: k[0] == 'H1')
    report('H3', 'the owner never loses permissions, visibility or membership', 'HOLDS', lambda k: k[0] == 'H3')
    report('H2a', 'unassign, kick and private-member removal never affect an equal-or-higher member', 'HOLDS',
           lambda k: k[0] == 'H2' and k[1] in ('unassign', 'kick', 'removePrivateMember'))
    report('H2b', 'no other operation affects an equal-or-higher member', 'HOLDS',
           lambda k: k[0] == 'H2' and k[1] not in ('unassign', 'kick', 'removePrivateMember'))

    focused, states3, checked3 = explore(3, only_actor='M', only_ops=('createRole', 'channelOverride', 'assign'))
    print(f'     focused depth 3 (actor M; createRole/channelOverride/assign): {states3} states, {checked3} transitions')
    hits = {k: v for k, v in focused.items() if k == ('H2', 'assign')}
    witness = []
    for (_, op), (trace, message) in hits.items():
        witness.append(f'[{op}] {message}')
        witness.extend(f'    {step}' for step in trace)
    record('M2', 'H2c', 'assigning a role never reduces an equal-or-higher member', 'HOLDS', bool(hits), witness=witness)

    unguarded, _, _ = explore(depth, superior_guard=False)
    record('M2', 'H2b-ctl', 'without assertNoSuperiorAccessLoss, overrides and role edits reduce a superior', 'CONTROL',
           any(k[0] == 'H2' and k[1] not in ('unassign', 'kick', 'removePrivateMember') for k in unguarded))
    record('M2', 'H2d-ctl', 'without the guard, a lower channel manager removes a superior from a private channel', 'CONTROL',
           any(k == ('H2', 'removePrivateMember') for k in unguarded))
    for operation in ('privacy', 'moveChannel', 'deleteChannel'):
        record('M2', f'H2-{operation}-ctl', f'without the guard, {operation} can reduce superior access', 'CONTROL',
               ('H2', operation) in unguarded)
    # Distinct initial family: the superior gets a bit only from the category.
    # The ordinary initial roles already contain every SCOPED bit, so deleting
    # a category there cannot exercise loss of a category-only grant.
    category_grant = replace(INITIAL, cat=(('k1', 'Administrator', PERM['ATTACH_FILES'], 0),))
    guarded, _, _ = explore(1, initial=category_grant, only_ops=('deleteCategory', 'moveChannel'))
    record('M2', 'H2-category-grant', 'moving/deleting a category preserves category-only superior grants', 'HOLDS',
           any(k[0] == 'H2' for k in guarded))
    weak_category, _, _ = explore(1, initial=category_grant, superior_guard=False, only_ops=('deleteCategory',))
    record('M2', 'H2-deleteCategory-ctl', 'without the guard, deleting a category removes a superior grant', 'CONTROL',
           ('H2', 'deleteCategory') in weak_category)

    weak, _, _ = explore(depth, unassign_rank_check=False, superior_guard=False)
    record('M2', 'H2a-ctl', 'without the F-P2F-040 rank check, unassign affects a superior', 'CONTROL',
           any(k == ('H2', 'unassign') for k in weak))


if __name__ == '__main__':
    run()
