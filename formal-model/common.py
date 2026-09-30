"""Shared result bookkeeping and the permission constants mirrored from the code.

Every check has one of three expectations:

  HOLDS    a design property; a violation is a design breakdown (FINDING).
  LIMIT    a documented limitation; the model must reach it. If it cannot,
           the model is too weak to be trusted for that area.
  CONTROL  a deliberately weakened model must break. This proves that the
           corresponding HOLDS check is not passing vacuously.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# packages/shared/src/constants/index.ts
PERM = {
    'SEND_MESSAGES': 1 << 0, 'EDIT_MESSAGES': 1 << 1, 'DELETE_MESSAGES': 1 << 2,
    'ADD_REACTIONS': 1 << 3, 'MENTION_EVERYONE': 1 << 4, 'PIN_MESSAGES': 1 << 5,
    'VIEW_CHANNELS': 1 << 6, 'MANAGE_CHANNELS': 1 << 7, 'MANAGE_MEMBERS': 1 << 8,
    'KICK_MEMBERS': 1 << 9, 'BAN_MEMBERS': 1 << 10, 'MANAGE_WORKSPACE': 1 << 11,
    'MANAGE_ROLES': 1 << 12, 'VIEW_AUDIT_LOG': 1 << 13, 'ATTACH_FILES': 1 << 14,
    'MANAGE_WEBHOOKS': 1 << 15, 'MANAGE_BOTS': 1 << 16, 'CONNECT_VOICE': 1 << 17,
    'CREATE_POSTS': 1 << 18,
}
ALL_PERMS = 0
for _bit in PERM.values():
    ALL_PERMS |= _bit

# authorization.service.ts CHANNEL_SCOPED_PERMISSION_MASK
CHANNEL_SCOPED = (
    PERM['VIEW_CHANNELS'] | PERM['SEND_MESSAGES'] | PERM['EDIT_MESSAGES']
    | PERM['DELETE_MESSAGES'] | PERM['ADD_REACTIONS'] | PERM['MENTION_EVERYONE']
    | PERM['PIN_MESSAGES'] | PERM['ATTACH_FILES'] | PERM['CONNECT_VOICE']
    | PERM['CREATE_POSTS']
)
VIEW = PERM['VIEW_CHANNELS']
CONNECT = PERM['CONNECT_VOICE']


def names(mask: int) -> str:
    return '|'.join(name for name, bit in PERM.items() if mask & bit) or '0'


@dataclass
class Result:
    model: str
    check_id: str
    title: str
    expect: str          # HOLDS | LIMIT | CONTROL
    violated: bool       # a counterexample / violating state was found
    detail: str = ''
    witness: list[str] = field(default_factory=list)
    incomplete: bool = False  # missing/invalid evidence is never a proof

    @property
    def ok(self) -> bool:
        if self.incomplete:
            return False
        # HOLDS must not be violated; LIMIT and CONTROL must be.
        return (not self.violated) if self.expect == 'HOLDS' else self.violated

    @property
    def verdict(self) -> str:
        if self.incomplete:
            return 'MODEL-GAP'
        if self.expect == 'HOLDS':
            return 'PASS' if self.ok else 'FINDING'
        if self.expect == 'LIMIT':
            return 'LIMIT' if self.ok else 'MODEL-GAP'
        return 'PASS' if self.ok else 'VACUOUS'


RESULTS: list[Result] = []


def record(model: str, check_id: str, title: str, expect: str, violated: bool,
           detail: str = '', witness: list[str] | None = None, *, incomplete: bool = False) -> Result:
    result = Result(model, check_id, title, expect, violated, detail, witness or [], incomplete)
    RESULTS.append(result)
    mark = {'PASS': 'ok ', 'LIMIT': 'lim', 'FINDING': '!! ', 'MODEL-GAP': '?? ', 'VACUOUS': '?? '}[result.verdict]
    print(f'  [{mark}] {check_id} {title} -> {result.verdict}')
    if result.verdict in ('FINDING', 'LIMIT', 'MODEL-GAP', 'VACUOUS'):
        if detail:
            print(f'        {detail}')
        for line in result.witness[:12]:
            print(f'          {line}')
    return result
