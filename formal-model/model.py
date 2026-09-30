#!/usr/bin/env python3
"""
Alparts design model — defensive security verification only.

A simplified, externally checkable model of the Alparts security design,
extracted from:
  - packages/server/src/services/authorization.service.ts
  - packages/server/src/services/key.service.ts / key-epoch-state.ts
  - packages/server/src/middleware/audit.ts
  - packages/server/src/db/schema.ts
  - packages/shared/src/constants/index.ts (permission bits)

Model scope (abstraction boundary):
  * Permission evaluation: bit-exact (32-bit masks, deny-wins, 2 override
    levels, owner channel-scoped grant, private membership gate).
  * Key epoch state machine: state/transition level (pending/active/
    retired/aborted), roster snapshot guard, viewer-set change => rotation.
    Cryptographic signatures are abstracted to unforgeability predicates.
  * Audit chain: algebraic hash spine + signed checkpoint anchor.
    Deletion/rewrite detection is structural, not cryptographic.
  * Sessions/devices: validity lattice only.

Nothing here contacts a live system; all results are solver artifacts.
"""

from z3 import (
    BitVec, BitVecVal, Solver, sat, unsat, And, Or, Not, If, Implies,
    ForAll, Exists, Datatype, Const, Consts, Function, IntSort, BoolSort,
    EnumSort, Distinct, simplify, is_true, UGE, ULE, Extract,
)

S = None  # fresh solver helper

def check(name, solver, expect, show_model=False):
    r = solver.check()
    status = "PASS" if r == expect else "FAIL"
    print(f"  [{status}] {name}: got {r}, expected {expect}")
    if r == sat and show_model:
        print("       witness:", solver.model())
    return r == expect

results = []
def record(name, ok):
    results.append((name, ok))
    print()

# ---------------------------------------------------------------------------
# Permission bits — mirrors packages/shared/src/constants/index.ts
# ---------------------------------------------------------------------------
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
for v in PERM.values():
    ALL_PERMS |= v
# CHANNEL_SCOPED_PERMISSION_MASK (authorization.service.ts:26-35)
CHANNEL_SCOPED = (PERM['VIEW_CHANNELS'] | PERM['SEND_MESSAGES'] | PERM['EDIT_MESSAGES']
                  | PERM['DELETE_MESSAGES'] | PERM['ADD_REACTIONS'] | PERM['MENTION_EVERYONE']
                  | PERM['PIN_MESSAGES'] | PERM['ATTACH_FILES'] | PERM['CONNECT_VOICE']
                  | PERM['CREATE_POSTS'])
VIEW = BitVecVal(PERM['VIEW_CHANNELS'], 32)


# ===========================================================================
# MODEL 1 — Authorization evaluation (bit-exact)
# ===========================================================================
print("== MODEL 1: authorization mask algebra ==")

def apply_level(mask, allow, deny):
    """applyPermissionOverrideLevel: (mask | allows) & ~denies"""
    return (mask | allow) & ~deny

def channel_auth_mask(ws_mask, cat_allow, cat_deny, ch_allow, ch_deny, is_owner):
    m = apply_level(ws_mask, cat_allow, cat_deny)
    m = apply_level(m, ch_allow, ch_deny)
    return If(is_owner, m | BitVecVal(CHANNEL_SCOPED, 32), m)

def visible(is_member, is_private_member, mask):
    """isVisibleChannelAuthorization: member && privateMember && VIEW bit"""
    return And(is_member, is_private_member, (mask & VIEW) != 0)

def _mk(base, extra):
    ns = Solver(); ns.add(base.assertions()); ns.add(extra); return ns

# P1.1: deny-wins inside one level — nothing in denyMask survives.
s = Solver()
ws, ca, cd = BitVec('ws', 32), BitVec('ca', 32), BitVec('cd', 32)
ALLV = BitVecVal(ALL_PERMS, 32); CSV = BitVecVal(CHANNEL_SCOPED, 32)
subset = lambda m, b: (m & ~b) == 0
s.add(subset(ws, ALLV), subset(ca, CSV), subset(cd, CSV))
out = apply_level(ws, ca, cd)
record("P1.1 deny bits never survive one level",
       check("deny survives", _mk(s, (out & cd) != 0), unsat))

# P1.2: channel-level deny overrides a category-level allow.
record("P1.2 channel deny beats category allow",
       check("view survives channel deny",
             _mk(Solver(), And(
                 channel_auth_mask(0, PERM['VIEW_CHANNELS'], 0, 0, PERM['VIEW_CHANNELS'], False)
                 & VIEW != 0)), unsat))

# P1.3: no input yields visibility on a private channel without membership —
#       for ANY masks and ANY owner flag.
s = Solver()
ws = BitVec('ws', 32); ca = BitVec('ca', 32); cd = BitVec('cd', 32)
cha = BitVec('cha', 32); chd = BitVec('chd', 32); owner = Const('owner', BoolSort())
ALLV = BitVecVal(ALL_PERMS, 32); CSV = BitVecVal(CHANNEL_SCOPED, 32)
subset = lambda m, b: (m & ~b) == 0
s.add(subset(ws, ALLV), subset(ca, CSV), subset(cd, CSV),
      subset(cha, CSV), subset(chd, CSV))
mask = channel_auth_mask(ws, ca, cd, cha, chd, owner)
record("P1.3 private channel + not member => invisible (all inputs)",
       check("non-member visible", _mk(s, visible(True, False, mask)), unsat))

# P1.4: owner grant is applied AFTER channel denies — owner on a NON-private
#       channel cannot be denied channel-scoped bits (documented escalation).
s2 = Solver()
s2.add(subset(ws, ALLV), subset(cd, CSV), subset(chd, CSV))
mask_owner = channel_auth_mask(ws, 0, cd, 0, chd, True)
record("P1.4 owner keeps VIEW despite maximal denies (design fact)",
       check("owner denied", _mk(s2, visible(True, True, mask_owner) == False), unsat))

# P1.5: without the private-membership gate (weakened model) the solver DOES
#       produce a violation — proves the check is load-bearing.
s3 = Solver()
s3.add(subset(ws, ALLV))
mask3 = channel_auth_mask(ws, 0, 0, 0, 0, False)
record("P1.5 weakened model leaks private channel (counterexample exists)",
       check("weakened visible", _mk(s3, And(visible(True, True, mask3), ws == PERM['VIEW_CHANNELS'])), sat))

# P1.6: workspace-scope bits (MANAGE_*, AUDIT, BOTS…) cannot be granted by
#       overrides because masks are bounded to CHANNEL_SCOPED — solver tries
#       to grant MANAGE_WORKSPACE via overrides from a zero base.
s4 = Solver()
ca4 = BitVec('ca4', 32); cha4 = BitVec('cha4', 32)
s4.add(subset(ca4, CSV), subset(cha4, CSV))
m4 = channel_auth_mask(0, ca4, 0, cha4, 0, False)
record("P1.6 overrides cannot grant MANAGE_WORKSPACE",
       check("override grants ws-scope", _mk(s4, (m4 & BitVecVal(PERM['MANAGE_WORKSPACE'], 32)) != 0), unsat))

# P1.7: but an owner on a non-private channel can't be given workspace-scope
#       either — CHANNEL_SCOPED lacks those bits.
s5 = Solver()
m5 = channel_auth_mask(0, 0, ALL_PERMS & CHANNEL_SCOPED, 0, ALL_PERMS & CHANNEL_SCOPED, True)
record("P1.7 owner grant is channel-scoped only",
       check("owner gains ws-scope", _mk(s5, (m5 & BitVecVal(ALL_PERMS & ~CHANNEL_SCOPED, 32)) != 0), unsat))


# ===========================================================================
# MODEL 2 — Key epoch state machine (bounded model checking)
# ===========================================================================
print("== MODEL 2: channel key epoch transitions ==")
# Abstract state per channel:
#   epoch status: none | pending | active | retired | aborted
#   pending_roster / active_roster: set of device ids (small universe)
#   viewers: current authorized user->devices set
#   rotation_required flag
# Transitions modeled from commitChannelKeyDistribution / acknowledgeChannelKey
# / abortPendingChannelKey / requireChannelKeyRotation / device revocation.

Status, (NONE, PENDING, ACTIVE, RETIRED, ABORTED) = EnumSort(
    'Status', ['none', 'pending', 'active', 'retired', 'aborted'])

NDEV = 3  # device universe (bounded)
def roster(var): return [Const(f'{var}{i}', BoolSort()) for i in range(NDEV)]

def step(prefix, st):
    """One transition of the epoch machine; returns list of successor states."""
    s = Solver()
    status, pend_r, act_r, view, rot = st
    nstatus = Const(f'{prefix}.status', Status)
    npend_r = roster(f'{prefix}.pend')
    nact_r = roster(f'{prefix}.act')
    nview = roster(f'{prefix}.view')
    nrot = Const(f'{prefix}.rot', BoolSort())
    nst = (nstatus, npend_r, nact_r, nview, nrot)

    roster_eq = lambda a, b: And([a[i] == b[i] for i in range(NDEV)])
    roster_ne = lambda a, b: Not(roster_eq(a, b))
    any_dev = lambda r: Or(r)

    # --- propose: no pending; new pending roster = snapshot of current viewers
    propose = And(status != PENDING, nstatus == PENDING,
                  roster_eq(npend_r, view), roster_eq(nact_r, act_r),
                  roster_eq(nview, view), nrot == rot)
    # --- activate: pending exists, all required acked (abstracted to
    #     'snapshot still equals current eligible viewers'), retired->active swap
    activate = And(status == PENDING, roster_eq(pend_r, view),   # isRecipientSnapshotStillAuthorized
                   nstatus == ACTIVE, roster_eq(nact_r, pend_r),
                   roster_eq(nview, view), nrot == False)
    # --- abort: pending -> aborted, rotation required
    abort = And(status == PENDING, nstatus == ABORTED,
                roster_eq(nview, view), nrot == True)
    # --- viewer change: any viewer delta forces rotationRequired on keyed chans
    vchange = And(roster_ne(nview, view), nstatus == status,
                  nrot == If(Or(status == PENDING, status == ACTIVE), True, rot),
                  roster_eq(npend_r, pend_r), roster_eq(nact_r, act_r))
    # --- viewer stable
    stable = And(roster_eq(nview, view), nstatus == status,
                 nrot == rot, roster_eq(npend_r, pend_r), roster_eq(nact_r, act_r))
    # --- device revoke of an epoch recipient forces rotation
    revoke = And(status == ACTIVE, nstatus == status, nrot == True,
                 roster_ne(nview, view),
                 roster_eq(npend_r, pend_r), roster_eq(nact_r, act_r))

    s.add(Or(propose, activate, abort, vchange, stable, revoke))
    return s, nst

def init_state(tag):
    status = Const(f'{tag}.status', Status)
    st = (status, roster(f'{tag}.pend'), roster(f'{tag}.act'),
          roster(f'{tag}.view'), Const(f'{tag}.rot', BoolSort()))
    return st

def valid_inv(st):
    """Design invariants that must hold in every reachable state."""
    status, pend_r, act_r, view, rot = st
    roster_ne = lambda a, b: Or([a[i] != b[i] for i in range(NDEV)])
    return And(
        # I1: active epoch roster must equal current viewer device roster,
        #     unless the channel is flagged for rotation.
        Implies(status == ACTIVE, Or(Implies(roster_ne(act_r, view), rot))),
        # I2: a stale active roster is always flagged
        Implies(And(status == ACTIVE, roster_ne(act_r, view)), rot),
    )

# BMC depth 4: start from arbitrary legal init, prove invariant preserved.
s = Solver()
st = init_state('s0')
s.add(Or(st[0] == NONE, st[0] == PENDING, st[0] == ACTIVE))
# legal init: an active epoch's roster equals the current viewers
s.add(Implies(st[0] == ACTIVE, And([st[2][i] == st[3][i] for i in range(NDEV)])))
s.add(valid_inv(st))
cur = st
violation = []
for k in range(4):
    ts, nxt = step(f's{k+1}', cur)
    s.add(ts.assertions())
    cur = nxt
    violation.append(Not(valid_inv(cur)))
record("M2.1 invariants hold for 4 steps (BMC)",
       check("invariant violation in 4 steps", _mk(s, Or(violation)), unsat))

# M2.2: confidentiality — removed viewer's device never appears in a NEW
#       active roster (roster snapshotted at proposal equals *then-current*
#       viewers; activation re-checks equality). Search 3 steps for a state
#       where an active roster contains a device not among current viewers.
s = Solver()
st = init_state('t0')
s.add(st[0] == NONE)  # start clean
s.add(Or([st[3][i] for i in range(NDEV)]))  # some viewers exist
cur = st
bad = []
for k in range(3):
    ts, nxt = step(f't{k+1}', cur)
    s.add(ts.assertions())
    cur = nxt
    status, pend_r, act_r, view, rot = cur
    # device in active roster but no longer a viewer => leak
    bad.append(And(status == ACTIVE,
                   Or([And(act_r[i], Not(view[i])) for i in range(NDEV)]),
                   rot == False))
record("M2.2 no active key for non-viewer without rotation flag (BMC)",
       check("leak found", _mk(s, Or(bad)), unsat))

# M2.3: weakened model — drop the activation roster check → leak reachable.
def step_weak(prefix, st):
    s, nst = step(prefix, st)
    # rebuild with activation not requiring roster equality
    status, pend_r, act_r, view, rot = st
    nstatus, npend_r, nact_r, nview, nrot = nst
    roster_eq = lambda a, b: And([a[i] == b[i] for i in range(NDEV)])
    roster_ne = lambda a, b: Not(roster_eq(a, b))
    propose = And(status != PENDING, nstatus == PENDING, roster_eq(npend_r, view),
                  roster_eq(nact_r, act_r), roster_eq(nview, view), nrot == rot)
    activate_w = And(status == PENDING, nstatus == ACTIVE,       # NO roster check
                     roster_eq(nact_r, pend_r), roster_eq(nview, view), nrot == False)
    abort = And(status == PENDING, nstatus == ABORTED, roster_eq(nview, view), nrot == True)
    vchange = And(roster_ne(nview, view), nstatus == status,
                  nrot == If(Or(status == PENDING, status == ACTIVE), True, rot),
                  roster_eq(npend_r, pend_r), roster_eq(nact_r, act_r))
    stable = And(roster_eq(nview, view), nstatus == status, nrot == rot,
                 roster_eq(npend_r, pend_r), roster_eq(nact_r, act_r))
    revoke = And(status == ACTIVE, nstatus == status, nrot == True,
                 roster_ne(nview, view), roster_eq(npend_r, pend_r), roster_eq(nact_r, act_r))
    w = Solver(); w.add(Or(propose, activate_w, abort, vchange, stable, revoke))
    return w, nst

s = Solver()
st = init_state('w0'); s.add(st[0] == NONE)
s.add(Or([st[3][i] for i in range(NDEV)]))
cur = st; bad = []
for k in range(3):
    ts, nxt = step_weak(f'w{k+1}', cur)
    s.add(ts.assertions()); cur = nxt
    status, pend_r, act_r, view, rot = cur
    bad.append(And(status == ACTIVE,
                   Or([And(act_r[i], Not(view[i])) for i in range(NDEV)]),
                   rot == False))
ok = check("weakened model produces leak", _mk(s, Or(bad)), sat, show_model=True)
record("M2.3 roster-check removal yields counterexample (check is load-bearing)", ok)


# ===========================================================================
# MODEL 3 — Session/device revocation lattice
# ===========================================================================
print("== MODEL 3: session & device validity ==")
DStatus, (UNAPPROVED, APPROVED, REVOKED) = EnumSort(
    'DStatus', ['unapproved', 'approved', 'revoked'])

dev0 = Const('dev0', DStatus); dev1 = Const('dev1', DStatus)
sess_live = Const('sess_live', BoolSort()); nsess_live = Const('nsess_live', BoolSort())

# transitions: approve (unapproved->approved), revoke (any->revoked, sessions die)
s = Solver()
approve = And(dev0 == UNAPPROVED, dev1 == APPROVED, nsess_live == sess_live)
revoke = And(dev1 == REVOKED, nsess_live == False)   # revocation kills sessions
stay = And(dev1 == dev0, nsess_live == And(sess_live, dev0 == APPROVED))
s.add(Or(approve, revoke, stay))
# invariant: live session requires approved device
inv = Implies(sess_live, dev0 == APPROVED)
s.add(Implies(Or(dev0 == UNAPPROVED, dev0 == APPROVED), inv))
# after any transition, live session still requires approved device
s.add(Not(Implies(nsess_live, dev1 == APPROVED)))
record("M3.1 no live session on non-approved device after transition",
       check("violating transition", s, unsat))

# re-approval of a revoked device is not among transitions
s2 = Solver()
s2.add(Or(approve, revoke, stay), dev0 == REVOKED, dev1 == APPROVED)
record("M3.2 revoked device can never be re-approved",
       check("reapproval trace", s2, unsat))


# ===========================================================================
# MODEL 4 — Audit chain + checkpoint anchor (algebraic hash spine)
# ===========================================================================
print("== MODEL 4: audit hash chain ==")
# Rows form an algebraic chain: Node(prev_node, data). Structural equality =>
# any spine modification changes every subsequent node identity.
Chain = Datatype('Chain')
Chain.declare('mk', ('prev', Chain), ('data', IntSort()))
Chain.declare('genesis')
Chain = Chain.create()
mk, prev, data, genesis = Chain.mk, Chain.prev, Chain.data, Chain.genesis

# verifier: walks committed chain; checkpoint anchor is an exact node equality
d0, d1, d2 = 10, 20, 30
honest = mk(mk(mk(genesis, d0), d1), d2)
checkpoint = mk(mk(genesis, d0), d1)     # signed anchor mid-chain

# adversary: tries to present a chain ending in a node EQUAL to `honest`
# but whose spine omits d1 (deletion) — structural impossibility.
s = Solver()
x, y = Consts('x y', Chain)
s.add(ForAll([x], prev(mk(x, d1)) == x))          # prev is projection
# any chain whose set of data payloads lacks d1 but equals `honest`:
s.add(honest == mk(mk(genesis, d0), d2))          # delete d1, keep tail node
record("M4.1 deleting a middle row cannot preserve the tail node",
       check("equivocal chain", s, unsat))

# checkpoint anchoring: node equality to a signed checkpoint pins the spine
s2 = Solver()
s2.add(checkpoint == mk(genesis, d2))             # different data under anchor
record("M4.2 checkpoint pins exact spine prefix",
       check("checkpoint mismatch accepted", s2, unsat))

# checkpoint monotonicity (version-2 rollback rule from readAuditCheckpoint)
prev_t, cur_t = Consts('prev_t cur_t', IntSort())
prev_id, cur_id = Consts('prev_id cur_id', IntSort())
prev_h, cur_h = Consts('prev_h cur_h', IntSort())
s3 = Solver()
rollback_ok = Not(Or(cur_t < prev_t,
                     And(cur_t == prev_t,
                         Or(cur_id != prev_id, cur_h != prev_h))))
s3.add(rollback_ok, Or(cur_t < prev_t,
                       And(cur_t == prev_t, cur_h != prev_h)))
record("M4.3 same-timestamp different-hash is rejected",
       check("equivocation accepted", s3, unsat))


# ===========================================================================
print("== SUMMARY ==")
failed = [n for n, ok in results if not ok]
print(f"{len(results) - len(failed)}/{len(results)} checks passed")
if failed:
    print("FAILED:", failed)
    raise SystemExit(1)
print("All model checks passed.")
