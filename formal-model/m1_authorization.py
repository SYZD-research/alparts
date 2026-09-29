"""M1: authorization mask algebra, proved for ALL inputs with Z3.

One member holds up to R roles. Each role has workspace permissions and its
own category and channel override (allow, deny). This is the symbolic form of
authz.py, which conformance.py ties to the TypeScript implementation.
"""
from __future__ import annotations

from z3 import And, BitVec, BitVecVal, Bool, If, Not, Or, Solver, sat

from common import ALL_PERMS, CHANNEL_SCOPED, CONNECT, PERM, VIEW, names, record

R = 3
W = 32


def bv(value: int):
    return BitVecVal(value, W)


def subset(mask, bound: int):
    return mask & ~bv(bound) == 0


class Member:
    """Symbolic member with R roles, overrides, owner/private/voice flags."""

    def __init__(self, tag: str, validate_overrides: bool = True):
        self.held = [Bool(f'{tag}.held{i}') for i in range(R)]
        self.perms = [BitVec(f'{tag}.perm{i}', W) for i in range(R)]
        self.cat = [(BitVec(f'{tag}.ca{i}', W), BitVec(f'{tag}.cd{i}', W)) for i in range(R)]
        self.chan = [(BitVec(f'{tag}.ha{i}', W), BitVec(f'{tag}.hd{i}', W)) for i in range(R)]
        self.owner = Bool(f'{tag}.owner')
        self.private = Bool(f'{tag}.private')
        self.private_member = Bool(f'{tag}.private_member')
        self.voice = Bool(f'{tag}.voice')
        bound = CHANNEL_SCOPED if validate_overrides else ALL_PERMS
        self.constraints = [subset(p, ALL_PERMS) for p in self.perms]
        for a, d in self.cat + self.chan:
            self.constraints += [subset(a, bound), subset(d, bound)]

    def _or(self, values):
        out = bv(0)
        for held, value in zip(self.held, values):
            out = out | If(held, value, bv(0))
        return out

    def workspace(self):
        return self._or(self.perms)

    def category_level(self):
        return (self.workspace() | self._or([a for a, _ in self.cat])) & ~self._or([d for _, d in self.cat])

    def channel_allow(self):
        return self._or([a for a, _ in self.chan])

    def channel_deny(self):
        return self._or([d for _, d in self.chan])

    def mask(self):
        m = (self.category_level() | self.channel_allow()) & ~self.channel_deny()
        return If(self.owner, m | bv(CHANNEL_SCOPED), m)

    def visible(self, private_gate: bool = True):
        m = self.mask()
        gate = Or(Not(self.private), self.private_member) if private_gate else Bool('true_gate') == Bool('true_gate')
        return And(gate, m & bv(VIEW) != 0, Or(Not(self.voice), m & bv(CONNECT) != 0))


def prove(check_id, title, expect, *assertions, member=None, show=None):
    solver = Solver()
    if member is not None:
        solver.add(*member.constraints)
    solver.add(*assertions)
    violated = solver.check() == sat
    witness = []
    if violated and show is not None:
        model = solver.model()
        witness = show(model)
    record('M1', check_id, title, expect, violated, witness=witness)


def run() -> None:
    print('== M1: authorization algebra (all inputs, Z3) ==')
    m = Member('m')
    not_owner = Not(m.owner)

    prove('A1', 'a held channel-level deny always removes the bit (non-owner)', 'HOLDS',
          not_owner, m.mask() & m.channel_deny() != 0, member=m)
    prove('A2', 'a held channel-level allow always grants unless also denied there', 'HOLDS',
          m.channel_allow() & ~m.channel_deny() & ~m.mask() != 0, member=m)
    prove('A3', 'overrides never change workspace-scope bits (MANAGE_*, AUDIT, KICK, ...)', 'HOLDS',
          (m.mask() ^ m.workspace()) & bv(ALL_PERMS & ~CHANNEL_SCOPED) != 0, member=m)
    prove('A4', 'a private channel is invisible to non-members, including the owner', 'HOLDS',
          m.private, Not(m.private_member), m.visible(), member=m)
    prove('A5', 'a voice channel is never visible without CONNECT_VOICE', 'HOLDS',
          m.voice, m.visible(), m.mask() & bv(CONNECT) == 0, member=m)
    prove('A6', 'the owner can never be denied a channel-scoped bit', 'HOLDS',
          m.owner, m.mask() & bv(CHANNEL_SCOPED) != bv(CHANNEL_SCOPED), member=m)

    # Design facts used by M2 (expected to be reachable).
    lo, hi = 0, 1
    prove('A7', 'a deny on a low role overrides an allow from a higher role held by the same member',
          'LIMIT', not_owner, m.held[lo], m.held[hi],
          m.perms[hi] & bv(VIEW) != 0, m.chan[lo][1] & bv(VIEW) != 0, m.mask() & bv(VIEW) == 0, member=m)

    before, after = Member('b'), Member('a')
    same = [before.owner == after.owner, before.private == after.private,
            before.private_member == after.private_member, before.voice == after.voice]
    for i in range(R):
        same += [before.perms[i] == after.perms[i], before.cat[i][0] == after.cat[i][0], before.cat[i][1] == after.cat[i][1],
                 before.chan[i][0] == after.chan[i][0], before.chan[i][1] == after.chan[i][1]]
    # "after" holds every role "before" holds, plus possibly more.
    grows = [Or(Not(before.held[i]), after.held[i]) for i in range(R)]
    solver_args = before.constraints + after.constraints + same + grows
    prove('A8', 'adding a role can remove channel visibility (evaluation is not monotone in roles)', 'LIMIT',
          *solver_args, before.visible(), Not(after.visible()))

    # Controls: removing a safety mechanism must break the matching property.
    prove('A4-ctl', 'without the private-membership gate a non-member sees a private channel', 'CONTROL',
          m.private, Not(m.private_member), m.visible(private_gate=False), member=m)
    weak = Member('w', validate_overrides=False)
    prove('A3-ctl', 'without override mask validation an override grants a workspace-scope bit', 'CONTROL',
          (weak.mask() ^ weak.workspace()) & bv(ALL_PERMS & ~CHANNEL_SCOPED) != 0, member=weak)
    prove('A6-ctl', 'without the owner grant the owner can be locked out', 'CONTROL',
          m.owner, ((m.category_level() | m.channel_allow()) & ~m.channel_deny()) & bv(VIEW) == 0, member=m)


if __name__ == '__main__':
    run()
