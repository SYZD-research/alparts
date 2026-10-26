"""Concrete authorization evaluator, mirroring
packages/server/src/services/authorization.service.ts line for line:

  workspace mask  = OR of the member's role permissions
  category level  = (mask | OR allow) & ~OR deny   over the member's roles only
  channel level   = same, applied to the category result
  owner           = channel result | CHANNEL_SCOPED
  visible         = member && (public || private member) && VIEW
                    (isVisibleChannelAuthorization: channel list and rooms)
  key recipient   = visible && (voice => CONNECT_VOICE)
                    (isChannelKeyRecipient: a voice channel's call and keys)

The conformance test (conformance.py) runs this evaluator and the real
TypeScript implementation on the same random inputs and requires equality.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from common import CHANNEL_SCOPED, CONNECT, VIEW


@dataclass(frozen=True)
class Role:
    name: str
    permissions: int
    position: int


@dataclass(frozen=True)
class Channel:
    name: str
    category: str | None
    private: bool = False
    voice: bool = False


@dataclass
class Workspace:
    owner: str
    roles: dict[str, Role]
    members: dict[str, frozenset[str]]                    # user -> role names
    channels: dict[str, Channel]
    category_overrides: dict[tuple[str, str], tuple[int, int]] = field(default_factory=dict)   # (category, role) -> (allow, deny)
    channel_overrides: dict[tuple[str, str], tuple[int, int]] = field(default_factory=dict)    # (channel, role) -> (allow, deny)
    private_members: dict[str, frozenset[str]] = field(default_factory=dict)                  # channel -> users


def workspace_mask(ws: Workspace, user: str) -> int:
    mask = 0
    for role in ws.members.get(user, frozenset()):
        if role in ws.roles:
            mask |= ws.roles[role].permissions
    return mask


def highest_position(ws: Workspace, user: str) -> float:
    if user == ws.owner:
        return 1_000_001
    return max([-1] + [ws.roles[r].position for r in ws.members.get(user, frozenset()) if r in ws.roles])


def _level(mask: int, overrides: dict, target: str | None, roles: frozenset[str]) -> int:
    allow = deny = 0
    if target is not None:
        for role in roles:
            a, d = overrides.get((target, role), (0, 0))
            allow |= a
            deny |= d
    return (mask | allow) & ~deny


def channel_mask(ws: Workspace, user: str, channel: str) -> int | None:
    if user not in ws.members:
        return None
    ch = ws.channels[channel]
    roles = frozenset(r for r in ws.members[user] if r in ws.roles)
    mask = workspace_mask(ws, user)
    mask = _level(mask, ws.category_overrides, ch.category, roles)
    mask = _level(mask, ws.channel_overrides, channel, roles)
    if user == ws.owner:
        mask |= CHANNEL_SCOPED
    return mask


def is_private_member(ws: Workspace, user: str, channel: str) -> bool:
    return not ws.channels[channel].private or user in ws.private_members.get(channel, frozenset())


def visible(ws: Workspace, user: str, channel: str) -> bool:
    mask = channel_mask(ws, user, channel)
    return mask is not None and is_private_member(ws, user, channel) and bool(mask & VIEW)


def key_recipient(ws: Workspace, user: str, channel: str) -> bool:
    if not visible(ws, user, channel):
        return False
    return not ws.channels[channel].voice or bool(channel_mask(ws, user, channel) & CONNECT)


def viewers(ws: Workspace, channel: str) -> frozenset[str]:
    return frozenset(u for u in ws.members if visible(ws, u, channel))


def key_recipients(ws: Workspace, channel: str) -> frozenset[str]:
    return frozenset(u for u in ws.members if key_recipient(ws, u, channel))
