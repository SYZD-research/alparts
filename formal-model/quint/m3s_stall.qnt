// M3s in Quint: the fresh-start stall rule (c) over time.
//
// A rewrite of m3s_stall.py on top of m3_key_epochs.qnt: the M3 state `s`
// and its transitions (`moves`) are reused unchanged, and a second variable
// `c` holds the clocks of m3s_stall.py SState. Together they mirror SState
// field by field, so that TLC finds the same number of states.
//
//   tick    15 minutes pass (one step, whatever else waits).
//   server  what mls-group-rules.ts pendingSince reads, at tick granularity:
//           package ages, revocation ages, each member's access_lost_at and
//           the clamp pendingSince = max(earliest, genesis).
//   truth   which pending additions, rejoins and removes have truly waited
//           15 minutes in the current group.
module m3s {
  const CLAMP: str       // "genesis" (fc9ec50), "active" (before 0b0fb41), "none" (0b0fb41..fc9ec50)
  const PURGE: bool      // losing the channel drops the user's packages
  const LOSS_TIME: str   // "member" (access_lost_at, 0026), "group" (remove_required_at before 0026)

  // base_variant in m3s_stall.py: X (the manager) keeps the channel; Y and Z
  // gain and lose it up to four times; one device change; 4 versions.
  import m3(MAX_LOG = 4, POISON_BUDGET = 0, SECOND_DEVICE = false, LOSE_DEVICE = false, MAX_VIEWER_CHANGES = 4,
            MAX_DEVICE_CHANGES = 1, GATE_REMOVAL = true, CAS = true, REJOIN = true, FRESH_START = true,
            FORMER_MEMBER_LOG = true, LEAVE_ENDED_UNREADABLE = true, IDLE_FRESH_START = true,
            MALICIOUS_SERVER = false, PURGE_ON_LOSS = PURGE, VIEW_USERS = Set(1, 2)) as B from "./m3_key_epochs"

  type Clock = {
    pkgOld: Set[int],     // devices whose current package is 15 minutes old (or older)
    revOld: Set[int],     // revoked devices revoked 15 minutes ago (or earlier)
    rr: int,              // control: the group's remove_required_at, 0 null, 1 set, 2 set 15 minutes ago or more
    lostAt: Set[int],     // members whose access_lost_at is set
    lostOld: Set[int],    // members whose access_lost_at is 15 minutes old (or older)
    refOld: bool,         // the clamp's reference (genesis, or the active version) is 15 minutes old
    waitedAdd: Set[int],  // truth: pending additions and rejoins that waited 15 minutes in the current group
    waitedRem: Set[int],  // truth: pending removes that waited 15 minutes in the current group
  }

  var c: Clock

  pure def lostMembers(st: B::State): Set[int] = B::members(st).filter(d => not(st.viewers.contains(B::USER_OF[d])))

  // freshStartPermitted (c): now - max(earliest pending, reference) >= 15 minutes.
  pure def permitted(st: B::State, ck: Clock): bool = {
    val w = B::view(st)
    val old = w.pendingAdd.intersect(ck.pkgOld) != Set() or w.requiredRemove.exists(d =>
      if (st.status[d] == B::REVOKED) ck.revOld.contains(d)
      else if (LOSS_TIME == "group") ck.rr == 2
      else ck.lostOld.contains(d))
    B::hasGroup(st) and old and (CLAMP == "none" or ck.refOld)
  }

  pure def trulyStalled(st: B::State, ck: Clock): bool = {
    val w = B::view(st)
    ck.waitedAdd.intersect(w.pendingAdd) != Set() or ck.waitedRem.intersect(w.requiredRemove) != Set()
  }

  // The clocks after an M3 move from `st` (s_transitions in m3s_stall.py).
  pure def after(st: B::State, ck: Clock, m: B::Move): Clock = {
    val nxt = m.target
    val created = m.kind == "create"
    val committed = m.kind == "commit"
    val isView = m.kind == "view"
    val w = B::view(nxt)
    val memberLoss = LOSS_TIME == "member" and not(created)
    val lostAt = if (not(memberLoss)) Set() else if (isView) lostMembers(nxt) else ck.lostAt.intersect(B::members(nxt))
    val fresh = if (isView) B::userDevices(m.user) else Set()
    {
      pkgOld: ck.pkgOld.filter(d => nxt.pkg[d] == st.pkg[d] and st.pkg[d] != B::NO_PKG),
      revOld: ck.revOld.filter(d => nxt.status[d] == B::REVOKED),
      rr: if (LOSS_TIME != "group" or created or committed) 0
          else if (isView) (if (lostMembers(nxt) != Set()) (if (ck.rr == 0) 1 else ck.rr) else 0)
          else ck.rr,
      lostAt: lostAt,
      lostOld: if (memberLoss) ck.lostOld.intersect(lostAt).exclude(fresh) else Set(),
      refOld: ck.refOld and not(created) and not(committed and CLAMP == "active"),
      waitedAdd: if (created) Set() else ck.waitedAdd.intersect(w.pendingAdd),
      waitedRem: if (created) Set() else ck.waitedRem.intersect(w.requiredRemove),
    }
  }

  // The M3 moves m3s_stall.py keeps: a fresh start by rule (c) alone needs the 15 minutes.
  pure def allowed(st: B::State, ck: Clock): Set[B::Move] =
    B::moves(st).filter(m => not(m.kind == "create" and m.stallOnly) or permitted(st, ck))

  pure def ticked(st: B::State, ck: Clock): Clock = {
    val w = B::view(st)
    val group = B::hasGroup(st)
    {
      pkgOld: B::DEVICES.filter(d => st.pkg[d] != B::NO_PKG),
      revOld: B::DEVICES.filter(d => st.status[d] == B::REVOKED),
      rr: if (ck.rr != 0) 2 else 0,
      lostAt: ck.lostAt,
      lostOld: ck.lostAt,
      refOld: group,
      waitedAdd: ck.waitedAdd.union(if (group) w.pendingAdd else Set()),
      waitedRem: ck.waitedRem.union(if (group) w.requiredRemove else Set()),
    }
  }

  action init = all {
    B::s' = B::initial,
    c' = { pkgOld: Set(), revOld: Set(), rr: 0, lostAt: Set(), lostOld: Set(), refOld: false,
           waitedAdd: Set(), waitedRem: Set() },
  }

  action move = {
    nondet m = allowed(B::s, c).oneOf()
    all { B::s' = m.target, c' = after(B::s, c, m) }
  }

  action tick = all { ticked(B::s, c) != c, B::s' = B::s, c' = ticked(B::s, c) }

  action step = any { move, tick }

  // KS-sound: a manager replaces the group by rule (c) alone only when some
  // change has truly waited 15 minutes in the current group.
  val KSsound = trulyStalled(B::s, c) or not(allowed(B::s, c).exists(m => m.kind == "create" and m.stallOnly))
  // KS-keep: an ordinary commit that leaves a truly waited change pending does not take rule (c) away.
  val KSkeep = not(permitted(B::s, c)) or allowed(B::s, c).forall(m =>
    m.kind != "commit" or not(trulyStalled(m.target, after(B::s, c, m))) or permitted(m.target, after(B::s, c, m)))
}

// The runs of m3s_stall.py run().
module implementation {
  import m3s(CLAMP = "genesis", PURGE = true, LOSS_TIME = "member").*
}
module activeClamp {
  import m3s(CLAMP = "active", PURGE = true, LOSS_TIME = "member").*
}
module noClamp {
  import m3s(CLAMP = "none", PURGE = true, LOSS_TIME = "member").*
}
module keepPackages {
  import m3s(CLAMP = "genesis", PURGE = false, LOSS_TIME = "member").*
}
module groupLossTime {
  import m3s(CLAMP = "genesis", PURGE = true, LOSS_TIME = "group").*
}
