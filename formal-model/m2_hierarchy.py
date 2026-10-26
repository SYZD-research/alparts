"""M2: role hierarchy — exhaustive exploration of management operations.

State: roles, assignments, category/channel overrides, membership, pending
invitations. Actors: every non-owner member. Operations and their
preconditions copy role.service.ts, permission-override.service.ts,
channel.service.ts, workspace.service.ts, invitation.service.ts and the route
gates (requireWorkspacePermission / requireChannelPermission).

Per-transition properties (actor a, member u):
  H1 no escalation   bits u gains are held by a (or are u's own workspace
                     baseline being restored); u's rank rises only below a.
                     A member who joins through an invitation starts from
                     nothing, and a is the invitation's creator.
  H2 superior safety a member ranked >= a (u != a) keeps membership, workspace
                     bits, channel bits, channel visibility and (on a voice
                     channel) the call.
  H3 owner safety    the owner never loses anything.
  H4 override authority  the category- and channel-level override rows that
                     apply to a channel change only for roles ranked below a
                     and only on bits a holds (in the workspace for a category
                     row, in the channel for a channel row): what the override
                     API lets a write itself.
  H7 invitations     no one joins through an invitation whose creator is no
                     longer a member or no longer holds MANAGE_MEMBERS.
  H8 private channels  every private channel keeps an explicit member who is
                     a member of the workspace.

Since 2026-10-22 the server also refuses, with the override API's own checks,
a channel move or category deletion that changes overrides the actor could not
write (assertCategoryChangeAuthority), a category deletion over channels the
actor cannot see and manage (assertCategoryChannelsManageable), a role
assignment that grants (or an unassignment that lifts) override bits the
actor lacks (assertRoleOverridesHeld), and an invitation to a role whose
overrides grant such bits, checked again when it is used
(inviterHoldsRoleOverrides, assertCreatorMayStillInvite). Removing a member
drops their private-channel rows, hands a private channel they were the last
member of to the owner, and revokes their invitations.

The main run's overrides range over VIEW_CHANNELS and SEND_MESSAGES, which
every initial role holds, so it cannot see a grant of a bit the actor never
held. The M2x run adds MENTION_EVERYONE (held by the owner and administrators
only), override rows an administrator wrote on that bit and on the manager's
own role, invitations and an outside account N.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace
from itertools import product

from authz import Channel, Role, Workspace, channel_mask, highest_position, key_recipient, visible, workspace_mask
from common import PERM, names, record

VIEW, SEND = PERM['VIEW_CHANNELS'], PERM['SEND_MESSAGES']
MR, MC, KICK = PERM['MANAGE_ROLES'], PERM['MANAGE_CHANNELS'], PERM['KICK_MEMBERS']
MM, ME = PERM['MANAGE_MEMBERS'], PERM['MENTION_EVERYONE']
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
    invites: tuple = ()     # pending invitations: ((creator, role), ...)
    outsiders: tuple = ()   # accounts that may join through an invitation

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

# M2x: a bit only the owner and administrators hold, override rows an
# administrator wrote (on that bit, and on the manager's own role), a role
# that carries a channel override, invitations and an outside account N.
EXTENDED = State(
    roles=(('Owner', ALL_USED | MM | ME, 100), ('Administrator', ALL_USED | MM | ME, 90),
           ('Manager', VIEW | SEND | MR | MC | KICK | MM, 60), ('Member', VIEW | SEND, 50), ('Helper', VIEW | SEND, 40)),
    members=(('O', ('Member', 'Owner')), ('A', ('Administrator', 'Member')), ('M', ('Manager', 'Member')), ('U', ('Member',))),
    cat=(('k1', 'Manager', 0, SEND), ('k2', 'Manager', 0, VIEW), ('k2', 'Member', ME, 0)),
    chan=(('c1', 'Helper', ME, 0),),
    layout=(('c1', 'k1', False), ('c2', 'k2', True)),
    outsiders=('N',),
)


@dataclass(frozen=True)
class Rules:
    """The server's checks; a control turns one off."""
    unassign_rank_check: bool = True   # F-P2F-040
    category_authority: bool = True    # assertCategoryChangeAuthority (move, category deletion)
    category_channels: bool = True     # assertCategoryChannelsManageable (category deletion)
    role_overrides: bool = True        # assertRoleOverridesHeld (assign, unassign, invitations)
    creator_recheck: bool = True       # assertCreatorMayStillInvite when an invitation is used
    revoke_invites: bool = True        # removeMember revokes the removed member's invitations
    owner_handover: bool = True        # removeMember hands an orphaned private channel to the owner


RULES = Rules()


def _set_members(state, user, roles):
    members = tuple(sorted((u, rs) for u, rs in state.members if u != user)
                    + ([(user, tuple(sorted(roles)))] if roles is not None else []))
    return replace(state, members=members)


def _role_table(state):
    return {n: (p, pos) for n, p, pos in state.roles}


def override_authority(ws: Workspace, actor: str, role: str, affected: int, roles, mask: int | None = None) -> bool:
    """assertOverrideRoleAuthority: below the actor, and only bits it holds."""
    if role == 'Owner':
        return False
    if actor == ws.owner:
        return True
    perms = workspace_mask(ws, actor) if mask is None else mask
    return roles[role][1] < highest_position(ws, actor) and not affected & ~perms


def category_change_ok(state: State, ws: Workspace, actor: str, old: str | None, new: str | None) -> bool:
    """assertCategoryChangeAuthority(snapshotBefore, actor, overrides of old, overrides of new)."""
    if actor == ws.owner:
        return True
    rows = lambda category: {r: (a, d) for t, r, a, d in state.cat if t == category} if category else {}
    before, after, roles = rows(old), rows(new), _role_table(state)
    for role in set(before) | set(after):
        o, n = before.get(role, (0, 0)), after.get(role, (0, 0))
        if o == n:
            continue
        if role not in roles or not override_authority(ws, actor, role, o[0] | o[1] | n[0] | n[1], roles):
            return False
    return True


def category_channels_manageable(state: State, ws: Workspace, actor: str, category: str) -> bool:
    """assertCategoryChannelsManageable: every channel of the category is visible with MANAGE_CHANNELS."""
    if actor == ws.owner:
        return True
    return all(visible(ws, actor, c) and channel_mask(ws, actor, c) & MC
               for c, k, _ in state.layout if k == category)


def role_overrides_held(state: State, ws: Workspace, actor: str, role: str, action: str) -> bool:
    """assertRoleOverridesHeld: assigning needs the bits the role's rows allow, unassigning the bits they deny."""
    if actor == ws.owner:
        return True
    perms = workspace_mask(ws, actor)
    touched = (lambda a, d: a) if action == 'assign' else (lambda a, d: d)
    for _, r, a, d in state.cat:
        if r == role and touched(a, d) & ~perms:
            return False
    for c, r, a, d in state.chan:
        if r == role:
            held = perms & (channel_mask(ws, actor, c) if c in ws.channels else perms)
            if touched(a, d) & ~held:
                return False
    return True


def may_grant_invitation_role(ws: Workspace, inviter: str, permissions: int, position: int, named: bool) -> bool:
    """mayGrantInvitationRole."""
    if inviter == ws.owner:
        return True
    perms = workspace_mask(ws, inviter)
    if permissions & ~perms:
        return False
    return not named or (position < highest_position(ws, inviter) and bool(perms & MR))


def may_invite(state: State, ws: Workspace, inviter: str, role: str, rules: Rules = RULES) -> bool:
    """getInvitationRole at creation, assertCreatorMayStillInvite at use (the default role is unnamed)."""
    roles = _role_table(state)
    if inviter not in ws.members or role not in roles or role == 'Owner':
        return False
    if inviter == ws.owner:
        return True
    if not workspace_mask(ws, inviter) & MM:
        return False
    permissions, position = roles[role]
    if not may_grant_invitation_role(ws, inviter, permissions, position, role != 'Member'):
        return False
    return role == 'Member' or not rules.role_overrides or role_overrides_held(state, ws, inviter, role, 'assign')


def transitions(state: State, unassign_rank_check: bool = True, only_actor: str | None = None,
                only_ops: tuple[str, ...] | None = None, rules: Rules = RULES, focus=None):
    """Yield (actor, description, next_state) for every permitted operation."""
    if not unassign_rank_check:
        rules = replace(rules, unassign_rank_check=False)
    for actor, label, nxt in _transitions(state, rules):
        if only_actor and actor != only_actor:
            continue
        if only_ops and label.split('(')[0] not in only_ops:
            continue
        if focus and not focus(actor, label.split('(')[0]):
            continue
        yield actor, label, nxt


def _remove_member(state: State, ws: Workspace, user: str, rules: Rules) -> State:
    """workspace.service removeMember: rows, the owner hand-over, invitations, roles."""
    updates = {}
    for field, channel in (('private_c1', 'c1'), ('private', 'c2')):
        rows = getattr(state, field)
        if user not in rows:
            continue
        remaining = tuple(u for u in rows if u != user)
        orphaned = channel in ws.channels and ws.channels[channel].private \
            and not any(u in ws.members for u in remaining)
        updates[field] = remaining + (ws.owner,) if orphaned and rules.owner_handover else remaining
    if rules.revoke_invites:
        updates['invites'] = tuple(i for i in state.invites if i[0] != user)
    return _set_members(replace(state, **updates), user, None)


def _transitions(state: State, rules: Rules):
    ws = state.workspace()
    roles = _role_table(state)
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
                # assign / unassign (assertCanCreateOrAssign, assertMemberCanBeManaged, assertRoleOverridesHeld)
                for user, held in state.members:
                    if name not in held and (p0 & ~perms) == 0:
                        if not rules.role_overrides or role_overrides_held(state, ws, actor, name, 'assign'):
                            yield actor, f'assign({user}, {name})', _set_members(state, user, held + (name,))
                    if name in held:
                        target_ok = user == actor or highest_position(ws, user) < top
                        if (target_ok or not rules.unassign_rank_check) and (
                                not rules.role_overrides or role_overrides_held(state, ws, actor, name, 'unassign')):
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

        # channel changes (channel.service): channel-level MANAGE_CHANNELS on
        # the visible channel. Removing a private member needs one explicit
        # member to remain.
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
                if destination == category:
                    continue
                if rules.category_authority and not category_change_ok(state, ws, actor, category, destination):
                    continue
                layout = tuple((c, destination if c == channel else cat, p) for c, cat, p in state.layout)
                yield actor, f'moveChannel({channel}, {destination})', replace(state, layout=layout)
            # The schema cascades the channel's override and member rows.
            yield actor, f'deleteChannel({channel})', replace(
                state, layout=tuple(row for row in state.layout if row[0] != channel),
                chan=tuple(row for row in state.chan if row[0] != channel), **{field: ()})
        if (perms & (VIEW | MC)) == (VIEW | MC):
            for category in state.categories:
                if rules.category_channels and not category_channels_manageable(state, ws, actor, category):
                    continue
                if rules.category_authority and not category_change_ok(state, ws, actor, category, None):
                    continue
                yield actor, f'deleteCategory({category})', replace(
                    state, categories=tuple(c for c in state.categories if c != category),
                    layout=tuple((c, None if cat == category else cat, p) for c, cat, p in state.layout),
                    cat=tuple(row for row in state.cat if row[0] != category))

        # kick: KICK_MEMBERS and strictly higher rank (assertMemberRemovalAuthorized)
        if perms & KICK:
            for user, _ in state.members:
                if user != actor and user != ws.owner and top > highest_position(ws, user):
                    yield actor, f'kick({user})', _remove_member(state, ws, user, rules)

        # invitations (MANAGE_MEMBERS); one pending at a time keeps the run small
        if state.outsiders and not state.invites and perms & MM:
            for name in roles:
                if may_invite(state, ws, actor, name, rules):
                    yield actor, f'createInvitation({name})', replace(state, invites=((actor, name),))

    # using an invitation: the creator's authority is checked again under the lock
    for creator, name in state.invites:
        for outsider in state.outsiders:
            if rules.creator_recheck and not may_invite(state, ws, creator, name, rules):
                continue
            joined = _set_members(replace(state, invites=tuple(i for i in state.invites if i != (creator, name)),
                                          outsiders=tuple(o for o in state.outsiders if o != outsider)),
                                  outsider, (name,))
            yield creator, f'useInvitation({outsider}, {name})', joined


def observe(ws: Workspace):
    out = {}
    for u in ws.members:
        out[u] = (workspace_mask(ws, u), highest_position(ws, u),
                  {c: (channel_mask(ws, u, c), visible(ws, u, c), key_recipient(ws, u, c)) for c in ws.channels})
    return out


def _applied_rows(ws: Workspace, channel: str):
    """Per role, the category-level and channel-level rows that apply to the channel."""
    category = ws.channels[channel].category
    return ({r: ws.category_overrides.get((category, r), (0, 0)) for r in ws.roles} if category else {},
            {r: ws.channel_overrides.get((channel, r), (0, 0)) for r in ws.roles})


def check_transition(before: Workspace, after: Workspace, actor: str):
    """Return the list of violated properties for one transition."""
    violations = []
    b, a = observe(before), observe(after)
    actor_perms, actor_top = b[actor][:2] if actor in b else (0, -1)
    for user, (ws_a, top_a, chans_a) in a.items():
        if user in b:
            continue
        # joined through an invitation: everything it holds is a gain
        if ws_a & ~actor_perms:
            violations.append(('H1', f'{user} joined with workspace bits {names(ws_a & ~actor_perms)} not held by {actor}'))
        if top_a >= actor_top:
            violations.append(('H1', f'{user} joined at rank {top_a} >= {actor} ({actor_top})'))
        for channel, (mask_a, _, _) in chans_a.items():
            if mask_a & ~actor_perms:
                violations.append(('H1', f'{user} joined with {names(mask_a & ~actor_perms)} on {channel}'))
        if actor not in after.members or (actor != after.owner and not workspace_mask(after, actor) & MM):
            violations.append(('H7', f'{user} joined through an invitation of {actor}, who no longer may invite'))
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
        for channel, (mask_b, vis_b, key_b) in chans_b.items():
            mask_a, vis_a, key_a = chans_a.get(channel, (0, False, False))
            gained = mask_a & ~mask_b
            if gained & ~(actor_perms | ws_b):
                violations.append(('H1', f'{user} gained {names(gained)} on {channel}'))
            lost = channel not in chans_a or (mask_b & ~mask_a) or (vis_b and not vis_a) or (key_b and not key_a)
            if lost and superior:
                violations.append(('H2', f'{user} (rank {top_b}) lost {names(mask_b & ~mask_a)}{" and visibility" if vis_b and not vis_a else ""} on {channel}'))
            if lost and user == before.owner:
                violations.append(('H3', f'owner lost {names(mask_b & ~mask_a)} on {channel}'))
        if ws_b & ~ws_a and superior:
            violations.append(('H2', f'{user} (rank {top_b}) lost workspace bits {names(ws_b & ~ws_a)}'))
        if ws_b & ~ws_a and user == before.owner:
            violations.append(('H3', 'owner lost workspace bits'))
    if actor != before.owner and actor in b:
        for channel in before.channels:
            if channel not in after.channels:
                continue
            (cat_b, chan_b), (cat_a, chan_a) = _applied_rows(before, channel), _applied_rows(after, channel)
            authorities = ((cat_b, cat_a, actor_perms, 'category'),
                           (chan_b, chan_a, actor_perms & (channel_mask(before, actor, channel) or 0), 'channel'))
            for rows_b, rows_a, mask, level in authorities:
                for role in set(rows_b) | set(rows_a):
                    o, n = rows_b.get(role, (0, 0)), rows_a.get(role, (0, 0))
                    if o == n:
                        continue
                    if role not in before.roles or not override_authority(
                            before, actor, role, o[0] | o[1] | n[0] | n[1],
                            {r: (x.permissions, x.position) for r, x in before.roles.items()}, mask):
                        violations.append(('H4', f'{level} row of {role} on {channel} changed from {names(o[0])}/{names(o[1])} '
                                                 f'to {names(n[0])}/{names(n[1])} beyond what {actor} may write'))
    for channel, ch in after.channels.items():
        if ch.private and not after.private_members.get(channel, frozenset()) & set(after.members):
            violations.append(('H8', f'private channel {channel} has no explicit member left in the workspace'))
    return violations


# Operations checked by assertNoSuperiorAccessLoss (authorization.service.ts).
GUARDED = {'updateRole', 'assign', 'unassign', 'categoryOverride', 'channelOverride', 'deleteOverride',
           'removePrivateMember', 'privacy', 'moveChannel', 'deleteChannel', 'deleteCategory'}


def explore(depth: int, unassign_rank_check: bool = True, superior_guard: bool = True, initial=INITIAL,
            rules: Rules = RULES, **focus):
    if not unassign_rank_check:
        rules = replace(rules, unassign_rank_check=False)
    seen = {initial: None}
    queue = deque([(initial, 0)])
    found = {}          # (property, operation kind) -> (trace, message)
    transitions_checked = 0
    while queue:
        state, d = queue.popleft()
        before = state.workspace()
        for actor, label, nxt in transitions(state, rules=rules, **focus):
            violations = check_transition(before, nxt.workspace(), actor)
            if superior_guard and label.split('(')[0] in GUARDED and any(p == 'H2' for p, _ in violations):
                continue            # the server refuses this operation
            transitions_checked += 1
            for prop, message in violations:
                key = (prop, operation_kind(label))
                if key not in found:
                    trace = _trace(seen, state) + [f'{actor}: {label}']
                    found[key] = (trace, message)
            if nxt not in seen and d + 1 < depth:
                seen[nxt] = (state, f'{actor}: {label}')
                queue.append((nxt, d + 1))
            elif nxt not in seen:
                seen[nxt] = (state, f'{actor}: {label}')
    return found, len(seen), transitions_checked


def operation_kind(label: str) -> str:
    """The operation of a label; an invitation to the default role is its own kind (see H1-default-invite)."""
    op = label.split('(')[0]
    return 'useDefaultInvitation' if op == 'useInvitation' and label.endswith(', Member)') else op


def _trace(seen, state):
    steps = []
    while seen.get(state):
        state, step = seen[state]
        steps.append(step)
    return list(reversed(steps))


def _witness(hits):
    witness = []
    for (_, op), (trace, message) in sorted(hits.items()):
        witness.append(f'[{op}] {message}')
        witness.extend(f'    {step}' for step in trace)
    return witness


# M2x: the manager M acts (its role edits are covered by the main run), the
# administrator A assigns and removes roles and members, and N joins.
M2X_OPS = {'assign', 'unassign', 'categoryOverride', 'channelOverride', 'deleteOverride', 'removePrivateMember',
           'privacy', 'moveChannel', 'deleteChannel', 'deleteCategory', 'kick', 'createInvitation', 'useInvitation'}


def m2x_focus(actor: str, op: str) -> bool:
    if op == 'useInvitation':
        return True
    if actor == 'M':
        return op in M2X_OPS
    return actor == 'A' and op in ('kick', 'assign', 'unassign')


def run(depth: int = 2) -> None:
    print(f'== M2: role hierarchy (exhaustive, depth {depth}) ==')
    found, states, checked = explore(depth)
    print(f'     explored {states} states, checked {checked} transitions')

    def report(check_id, title, expect, keys, source=None):
        hits = {k: v for k, v in (found if source is None else source).items() if keys(k)}
        record('M2', check_id, title, expect, bool(hits), witness=_witness(hits))

    report('H1', 'no management operation grants a permission the actor lacks', 'HOLDS', lambda k: k[0] == 'H1')
    report('H3', 'the owner never loses permissions, visibility or membership', 'HOLDS', lambda k: k[0] == 'H3')
    report('H2a', 'unassign, kick and private-member removal never affect an equal-or-higher member', 'HOLDS',
           lambda k: k[0] == 'H2' and k[1] in ('unassign', 'kick', 'removePrivateMember'))
    report('H2b', 'no other operation affects an equal-or-higher member', 'HOLDS',
           lambda k: k[0] == 'H2' and k[1] not in ('unassign', 'kick', 'removePrivateMember'))
    report('H4', 'overrides that apply to a channel change only as the actor could write them', 'HOLDS',
           lambda k: k[0] == 'H4')
    report('H8', 'every private channel keeps an explicit member of the workspace (removal hands it to the owner)',
           'HOLDS', lambda k: k[0] == 'H8')

    focused, states3, checked3 = explore(3, only_actor='M', only_ops=('createRole', 'channelOverride', 'assign'))
    print(f'     focused depth 3 (actor M; createRole/channelOverride/assign): {states3} states, {checked3} transitions')
    report('H2c', 'assigning a role never reduces an equal-or-higher member', 'HOLDS',
           lambda k: k == ('H2', 'assign'), focused)

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
    # The category-change check also refuses this deletion (the row is on a
    # higher role), so the control turns both checks off.
    weak_category, _, _ = explore(1, initial=category_grant, superior_guard=False,
                                  rules=Rules(category_authority=False), only_ops=('deleteCategory',))
    record('M2', 'H2-deleteCategory-ctl', 'without the guard and the category-change check, deleting a category '
           'removes a superior grant', 'CONTROL', ('H2', 'deleteCategory') in weak_category)

    weak, _, _ = explore(depth, unassign_rank_check=False, superior_guard=False)
    record('M2', 'H2a-ctl', 'without the F-P2F-040 rank check, unassign affects a superior', 'CONTROL',
           any(k == ('H2', 'unassign') for k in weak))
    # A private channel M created is one only M belongs to (channel creation is
    # not an M2 operation, and a lower manager cannot make one private later:
    # that takes a superior's access).
    created = replace(INITIAL, layout=(('c1', 'k1', True), ('c2', 'k1', True)), private_c1=('M',))
    handed, states_h, _ = explore(depth, initial=created)
    print(f'     private channel created by M, depth {depth}: {states_h} states')
    record('M2', 'H8-created', 'removing the creator and only member of a private channel hands it to the owner',
           'HOLDS', any(k[0] in ('H3', 'H8') for k in handed),
           witness=_witness({k: v for k, v in handed.items() if k[0] in ('H3', 'H8')}))
    unhanded, _, _ = explore(1, initial=created, rules=Rules(owner_handover=False), only_ops=('kick',))
    record('M2', 'H8-ctl', 'before the 2026-10-22 fix: removing the last member of a private channel left it to nobody',
           'CONTROL', ('H8', 'kick') in unhanded, witness=_witness({k: v for k, v in unhanded.items() if k[0] == 'H8'}))

    m2x_run(depth=3)


def m2x_run(depth: int = 3) -> None:
    found, states, checked = explore(depth, initial=EXTENDED, focus=m2x_focus)
    print(f'     M2x depth {depth} (MENTION_EVERYONE, invitations; M acts, A removes, N joins): '
          f'{states} states, {checked} transitions')

    def report(check_id, title, expect, keys):
        hits = {k: v for k, v in found.items() if keys(k)}
        record('M2', check_id, title, expect, bool(hits), witness=_witness(hits))

    # The default role is exempt from the override check
    # (inviterHoldsRoleOverrides): it is what every member starts from.
    ordinary = lambda k: k[1] != 'useDefaultInvitation'
    report('H1x', 'M2x: no move, category deletion, assignment or invitation grants a bit the actor lacks', 'HOLDS',
           lambda k: k[0] == 'H1' and ordinary(k))
    report('H2x', 'M2x: no operation affects an equal-or-higher member', 'HOLDS', lambda k: k[0] == 'H2')
    report('H4x', 'M2x: overrides that apply to a channel change only as the actor could write them', 'HOLDS',
           lambda k: k[0] == 'H4')
    report('H7', 'no one joins through an invitation whose creator was removed or lost MANAGE_MEMBERS', 'HOLDS',
           lambda k: k[0] == 'H7')
    report('H8x', 'M2x: every private channel keeps an explicit member of the workspace', 'HOLDS',
           lambda k: k[0] == 'H8')
    report('H1-default-invite', 'an invitation to the default Member role gives the overrides written for Member, '
           'including bits its creator lacks (the role every member starts from)', 'LIMIT',
           lambda k: k == ('H1', 'useDefaultInvitation'))

    controls = (
        ('H1-move-ctl', 'before the 2026-10-22 fix: moving a channel applied an allow the actor lacks',
         ('H1', 'moveChannel'), Rules(category_authority=False)),
        ('H4-move-ctl', "before the fix: moving a channel out of a category lifted a deny on the actor's own role",
         ('H4', 'moveChannel'), Rules(category_authority=False)),
        ('H4-deleteCategory-ctl', 'before the fix: deleting a category dropped the deny that hid its channels from '
         'the actor', ('H4', 'deleteCategory'), Rules(category_authority=False, category_channels=False)),
        ('H1-assign-ctl', 'before the fix: assigning a role gave the bits its channel override allows',
         ('H1', 'assign'), Rules(role_overrides=False)),
        ('H1-invite-ctl', 'before the 2026-10-22 fix: an invitation to a role gave the bits its overrides allow',
         ('H1', 'useInvitation'), Rules(role_overrides=False)),
        ('H7-ctl', 'before the 2026-10-22 fix: an invitation still worked after its creator lost the right to invite',
         ('H7', 'useDefaultInvitation'), Rules(creator_recheck=False, revoke_invites=False)),
    )
    for check_id, title, key, rules in controls:
        weak, _, _ = explore(depth, initial=EXTENDED, focus=m2x_focus, rules=rules)
        record('M2', check_id, title, 'CONTROL', key in weak, witness=_witness({key: weak[key]}) if key in weak else [])


if __name__ == '__main__':
    run()
