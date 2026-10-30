// M3 in Quint: continuous per-channel MLS groups (group protocol 4).
//
// A rewrite of m3_key_epochs.py with the same state and transitions, so that
// TLC finds the same number of states. The state is one record that mirrors
// the Python State tuple field by field; device and version bit masks are
// sets, per-device tuples are lists indexed by device.
//
//   devices  0 X1, 1 X2, 2 Y1, 3 Z1; users 0 X (manager), 1 Y, 2 Z
//   server   mls-group-rules.ts (deriveMembership, freshStartPermitted,
//            planCommitAdmission), mls-group.service.ts, mls-group-gate.ts
//   client   mls-group.service.ts syncLocked / catchUp / joinAt /
//            requestRejoin / commitLocked / createLocked / runMaintenance
//
// The transitions are the pure function `moves`, which m3s_stall.qnt reuses;
// each move carries the kind of step it is, as the Python actions do.
//
// Safety (KC, KC-dev, KC-dev-restore, KI, KA, KA-unjoined) is checked here.
// The liveness family (KL, KL-orphan, KL-lost) is a reachability question
// (from every state, protocol steps alone can lead to a writable state) that
// TLC cannot ask; it stays in m3_key_epochs.py.
module m3 {
  // Variant switches (class Variant in m3_key_epochs.py).
  const MAX_LOG: int                 // versions including the pre-v4 v1
  const POISON_BUDGET: int
  const SECOND_DEVICE: bool          // X2 exists (waits for approval) and history restore is modelled
  const LOSE_DEVICE: bool            // Y1 may go permanently offline (at any point)
  const MAX_VIEWER_CHANGES: int
  const MAX_DEVICE_CHANGES: int
  const GATE_REMOVAL: bool           // writes need every member eligible
  const CAS: bool                    // one commit per version (compare-and-swap)
  const REJOIN: bool                 // a member may ask to be added again
  const FRESH_START: bool
  const FORMER_MEMBER_LOG: bool      // the log is served for every version the device was a member at
  const LEAVE_ENDED_UNREADABLE: bool // an unreadable envelope of an ended membership is not a rejoin
  const IDLE_FRESH_START: bool       // (a) also when every usable member has been offline for 72 h
  const MALICIOUS_SERVER: bool       // the server ignores channel visibility
  const PURGE_ON_LOSS: bool          // losing the channel drops the user's packages (2026-10-21)
  const VIEW_USERS: Set[int]         // users whose access may change

  pure val DEVICES: Set[int] = 0.to(3)
  pure val USER_OF: List[int] = [0, 0, 1, 2]
  pure val USERS: Set[int] = 0.to(2)
  pure val MANAGER_USERS: Set[int] = Set(0)
  pure val LOST: int = 2
  pure val ABSENT: int = 0
  pure val UNAPPROVED: int = 1
  pure val APPROVED: int = 2
  pure val REVOKED: int = 3
  pure val LEGACY: int = 0
  pure val CREATE: int = 1
  pure val COMMIT: int = 2
  pure val NO_PKG: int = 0
  pure val PKG: int = 1
  pure val REJOIN_PKG: int = 2
  pure val BROKEN: int = -1
  pure val NO_STATE: int = 0

  type Entry = {
    kind: int,          // LEGACY | CREATE | COMMIT
    genesis: int,       // version of the group's genesis (0 for the pre-v4 epoch)
    roster: Set[int],   // devices after this version
    added: Set[int],    // devices added by this version (CREATE: the whole roster)
    poisoner: int,      // committer of an unreadable envelope, or -1
    parent: int,        // previousVersion
  }
  type State = {
    viewers: Set[int],        // users who see the channel
    status: List[int],        // per device: ABSENT | UNAPPROVED | APPROVED | REVOKED
    log: List[Entry],         // accepted versions; log[v - 1] is version v
    pkg: List[int],           // per device: NO_PKG | PKG | REJOIN_PKG
    local: List[int],         // per device: BROKEN | NO_STATE | version of its local group state
    derived: List[Set[int]],  // per device: versions whose key it derived from the group
    restored: List[Set[int]], // per device: versions whose key it restored from backups
    stale: bool,              // 24 h since the last group-key refresh
    genesisWait: int,         // 0 not requested, 1 waiting, 2 expired
    viewerChanges: int,
    deviceChanges: int,
    lost: bool,               // Y1 has gone offline for good
  }
  // kind: sync | publish | create | commit | restore | view | approve | revoke | clock | lost
  // cls: "step" (ordinary protocol step), "fresh" (fresh start) or "other"
  // stallOnly: a fresh start allowed by rule (c) alone; user: the user of a view change
  type Move = { kind: str, dev: int, user: int, stallOnly: bool, cls: str, target: State }

  var s: State

  // === Derived views ===

  pure def toggle(xs: Set[int], x: int): Set[int] = if (xs.contains(x)) xs.exclude(Set(x)) else xs.union(Set(x))
  pure def userDevices(u: int): Set[int] = DEVICES.filter(d => USER_OF[d] == u)
  pure def last(st: State): Entry = st.log[st.log.length() - 1]
  pure def eligible(st: State): Set[int] =
    DEVICES.filter(d => st.status[d] == APPROVED and (MALICIOUS_SERVER or st.viewers.contains(USER_OF[d])))
  // listGroupCommits: an approved device of a user who can see the channel.
  pure def canRead(st: State, d: int): bool =
    st.status[d] == APPROVED and (MALICIOUS_SERVER or st.viewers.contains(USER_OF[d]))
  pure def acting(st: State, d: int): bool = not(st.lost and d == LOST)
  pure def hasGroup(st: State): bool = last(st).kind != LEGACY
  pure def members(st: State): Set[int] = if (hasGroup(st)) last(st).roster else Set()
  pure def pkgMask(st: State, kinds: Set[int]): Set[int] = DEVICES.filter(d => kinds.contains(st.pkg[d]))

  // Devices whose membership ends at `version` (a rejoin ends and restarts one).
  pure def removedAt(log: List[Entry], version: int): Set[int] = {
    val entry = log[version - 1]
    val prev = log[version - 2]
    if (entry.kind == CREATE) (if (prev.kind != LEGACY) prev.roster else Set())
    else prev.roster.exclude(entry.roster).union(entry.added.intersect(prev.roster))
  }

  pure def poisonedFor(entry: Entry, d: int): bool = entry.poisoner >= 0 and entry.poisoner != d

  // Version that added `d` to the current group (d must be a current member).
  pure def spanStart(log: List[Entry], d: int): int =
    range(1, log.length() + 1).foldl(0, (acc, v) => if (log[v - 1].added.contains(d)) v else acc)

  // listGroupCommits / listGroupMembers: which versions the device may read.
  pure def visible(st: State, d: int, version: int): bool = {
    val entry = st.log[version - 1]
    val prev = st.log[version - 2]
    if (not(FORMER_MEMBER_LOG))
      members(st).contains(d) and entry.roster.contains(d) and entry.genesis == last(st).genesis
        and version >= spanStart(st.log, d)
    else entry.roster.contains(d) or (prev.kind != LEGACY and prev.roster.contains(d))
  }

  type View = { eligible: Set[int], members: Set[int], rejoinOpen: Set[int], usable: Set[int],
                pendingAdd: Set[int], requiredRemove: Set[int] }

  pure def view(st: State): View = {
    val e = eligible(st)
    val m = members(st)
    val rejoin = pkgMask(st, Set(REJOIN_PKG)).intersect(m)
    val packaged = pkgMask(st, Set(PKG, REJOIN_PKG))
    { eligible: e, members: m, rejoinOpen: rejoin, usable: m.intersect(e).exclude(rejoin),
      pendingAdd: e.intersect(packaged).intersect(DEVICES.exclude(m).union(rejoin)),
      requiredRemove: m.exclude(e) }
  }

  // authorizeGroupWrite plus the client holding the active version.
  pure def canSend(st: State, w: View, d: int): bool =
    hasGroup(st) and not(st.stale) and st.local[d] == st.log.length()
      and w.members.contains(d) and w.eligible.contains(d)
      and (not(GATE_REMOVAL) or w.members.subseteq(w.eligible))

  // === Transitions ===

  pure def withLocal(st: State, d: int, value: int): State = { ...st, local: st.local.replaceAt(d, value) }
  pure def derive(st: State, d: int, version: int): State =
    { ...st, local: st.local.replaceAt(d, version), derived: st.derived.replaceAt(d, st.derived[d].union(Set(version))) }

  pure def accept(st: State, entry: Entry, committer: int, ended: Set[int], refresh: bool): State = {
    val log = st.log.append(entry)
    val version = log.length()
    // A device that dropped its group starts over once its membership ends or
    // a new one begins; a rejoin ends and restarts it in one version.
    val restart = ended.union(entry.added)
    val local = st.local.indices().fold(st.local, (l, d) =>
      if (restart.contains(d) and st.local[d] == BROKEN) l.replaceAt(d, NO_STATE) else l)
    val pkg = st.pkg.indices().fold(st.pkg, (p, d) => if (entry.added.contains(d)) p.replaceAt(d, NO_PKG) else p)
    { ...st, log: log, pkg: pkg, local: local.replaceAt(committer, version),
      derived: st.derived.replaceAt(committer, st.derived[committer].union(Set(version))),
      stale: if (refresh) false else st.stale }
  }

  pure def poisonOptions(st: State, committer: int): Set[int] =
    if (st.log.foldl(0, (n, e) => if (e.poisoner >= 0) n + 1 else n) < POISON_BUDGET) Set(-1, committer)
    else Set(-1)

  pure def welcome(st: State, d: int, version: int): State =
    if (poisonedFor(st.log[version - 1], d)) withLocal(st, d, BROKEN) else derive(st, d, version)

  pure def process(st: State, d: int, version: int): State = {
    val entry = st.log[version - 1]
    if (entry.kind == CREATE or removedAt(st.log, version).contains(d))
      if (entry.added.contains(d)) welcome(st, d, version) else withLocal(st, d, NO_STATE)
    else if (poisonedFor(entry, d)) {
      // The envelope belongs to a membership before the device's current one:
      // it leaves that group behind and joins its current membership.
      // Otherwise it asks to be added again.
      val earlier = members(st).contains(d) and spanStart(st.log, d) > version
      if (earlier and LEAVE_ENDED_UNREADABLE) withLocal(st, d, NO_STATE) else withLocal(st, d, BROKEN)
    }
    else derive(st, d, version)
  }

  // One step of syncLocked; the state stays as it is once nothing is left to do.
  pure def syncStep(st: State, d: int): State = {
    val local = st.local[d]
    val latest = st.log.length()
    if (0 < local and local < latest and visible(st, d, local + 1)) process(st, d, local + 1)
    else if (local == NO_STATE and members(st).contains(d) and visible(st, d, spanStart(st.log, d)))
      welcome(st, d, spanStart(st.log, d))
    else st
  }

  // syncLocked: process every version the device may read, in order, and join
  // from the Welcome of the version that added it.
  pure def sync(st: State, d: int): State =
    range(0, 4 * st.log.length() + 4).foldl({ st: st, done: false }, (acc, i) =>
      if (acc.done) acc
      else {
        val t = syncStep(acc.st, d)
        { st: t, done: t == acc.st }
      }).st

  pure def mv(kind: str, d: int, cls: str, target: State): Move =
    { kind: kind, dev: d, user: -1, stallOnly: false, cls: cls, target: target }

  pure def deviceMoves(st: State, w: View, d: int): Set[Move] = {
    val local = st.local[d]
    val member = w.members.contains(d)
    val latest = st.log.length()
    val group = hasGroup(st)
    val room = latest < MAX_LOG
    val packaged = pkgMask(st, Set(PKG, REJOIN_PKG))
    // Sync: catch up through the log, joining from a Welcome that adds it.
    val synced = sync(st, d)
    val syncMoves = if (canRead(st, d) and synced != st) Set(mv("sync", d, "step", synced)) else Set()
    // Publish a package; a member only to ask to be added again.
    val publishMoves =
      if (w.eligible.contains(d) and st.pkg[d] == NO_PKG and not(member))
        Set(mv("publish", d, "step", { ...st, pkg: st.pkg.replaceAt(d, PKG),
          genesisWait: if (group or st.genesisWait >= 1) st.genesisWait else 1 }))
      else if (w.eligible.contains(d) and st.pkg[d] == NO_PKG and member and local == BROKEN and REJOIN)
        Set(mv("publish", d, "step", { ...st, pkg: st.pkg.replaceAt(d, REJOIN_PKG) }))
      else Set()
    // Genesis of the channel's first continuous group.
    val genesisMoves =
      if (room and not(group) and w.eligible.contains(d) and st.pkg[d] != NO_PKG) {
        val previous = last(st).roster.intersect(w.eligible)
        w.eligible.intersect(packaged).exclude(Set(d)).powerset().map(others => {
          val added = others.union(Set(d))
          val missing = previous.exclude(added)
          if (missing.intersect(packaged) != Set() or (missing != Set() and st.genesisWait < 2)) Set()
          else poisonOptions(st, d).map(p => mv("create", d, if (p < 0) "step" else "other",
            accept(st, { kind: CREATE, genesis: latest + 1, roster: added, added: added, poisoner: p, parent: latest },
                   d, Set(), true)))
        }).flatten()
      } else Set()
    // Fresh start (step-up) of an existing group.
    val idle = if (st.lost and IDLE_FRESH_START) Set(LOST) else Set()
    val nobody = w.usable.exclude(idle) == Set()
    val ownRejoin = w.rejoinOpen.contains(d)
    val stalled = MANAGER_USERS.contains(USER_OF[d])
      and w.pendingAdd.union(w.requiredRemove).union(w.rejoinOpen) != Set()
    val freshMoves =
      if (room and group and FRESH_START and w.eligible.contains(d) and not(w.usable.contains(d))
          and st.pkg[d] != NO_PKG and local <= NO_STATE and (nobody or ownRejoin or stalled))
        w.pendingAdd.exclude(Set(d)).powerset().map(others => {
          val added = others.union(Set(d))
          poisonOptions(st, d).map(p => {
            ...mv("create", d, if (p < 0) "fresh" else "other",
              accept(st, { kind: CREATE, genesis: latest + 1, roster: added, added: added, poisoner: p, parent: latest },
                     d, w.members, true)),
            stallOnly: stalled and not(nobody) and not(ownRejoin) })
        }).flatten()
      else Set()
    // Ordinary commit by a usable member at the current version.
    val current = 0 < local and st.log[local - 1].kind != LEGACY and st.log[local - 1].genesis == last(st).genesis
    val commitMoves =
      if (room and group and w.usable.contains(d) and current and (local == latest or not(CAS)))
        w.pendingAdd.powerset().map(added => {
          val removed = w.requiredRemove.union(added.intersect(w.members))
          if (added == Set() and removed == Set() and not(st.stale)) Set()   // KEY_ROTATION_NOT_REQUIRED
          else {
            val roster = w.members.exclude(removed).union(added)
            val refresh = removed != Set() or added == Set()
            poisonOptions(st, d).map(p => mv("commit", d, if (p < 0) "step" else "other",
              accept(st, { kind: COMMIT, genesis: last(st).genesis, roster: roster, added: added, poisoner: p,
                           parent: local }, d, removed, refresh)))
          }
        }).flatten()
      else Set()
    // History restore from the user's backups.
    val pooled = userDevices(USER_OF[d]).fold(Set(), (acc, x) => acc.union(st.derived[x]).union(st.restored[x]))
    val fresh = pooled.exclude(st.derived[d].union(st.restored[d]))
    val restoreMoves =
      if (SECOND_DEVICE and st.status[d] == APPROVED and fresh != Set())
        Set(mv("restore", d, "other", { ...st, restored: st.restored.replaceAt(d, st.restored[d].union(fresh)) }))
      else Set()
    syncMoves.union(publishMoves).union(genesisMoves).union(freshMoves).union(commitMoves).union(restoreMoves)
  }

  pure def moves(st: State): Set[Move] = {
    val w = view(st)
    val group = hasGroup(st)
    val perDevice = DEVICES.filter(d => acting(st, d)).map(d => deviceMoves(st, w, d)).flatten()
    val viewMoves =
      if (st.viewerChanges < MAX_VIEWER_CHANGES)
        VIEW_USERS.filter(u => toggle(st.viewers, u) != Set()).map(u => {
            val gains = not(st.viewers.contains(u))
            val viewers = toggle(st.viewers, u)
            // purgeLostViewerPackages: packages and rejoin requests go.
            val pkg = if (not(gains) and PURGE_ON_LOSS)
                        st.pkg.indices().fold(st.pkg, (p, d) => if (USER_OF[d] == u) p.replaceAt(d, NO_PKG) else p)
                      else st.pkg
            { kind: "view", dev: -1, user: u, stallOnly: false, cls: "other",
              target: { ...st, viewers: viewers, pkg: pkg, viewerChanges: st.viewerChanges + 1 } }
          })
      else Set()
    val deviceChangeMoves =
      if (st.deviceChanges < MAX_DEVICE_CHANGES)
        DEVICES.filter(d => st.status[d] == UNAPPROVED or st.status[d] == APPROVED).map(d =>
          if (st.status[d] == UNAPPROVED)
            mv("approve", d, "other", { ...st, status: st.status.replaceAt(d, APPROVED), deviceChanges: st.deviceChanges + 1 })
          else
            mv("revoke", d, "other", { ...st, status: st.status.replaceAt(d, REVOKED), deviceChanges: st.deviceChanges + 1 }))
      else Set()
    val clockMoves =
      if (group and not(st.stale)) Set(mv("clock", -1, "step", { ...st, stale: true }))
      else if (not(group) and st.genesisWait == 1) Set(mv("clock", -1, "step", { ...st, genesisWait: 2 }))
      else Set()
    val lostMoves = if (LOSE_DEVICE and not(st.lost)) Set(mv("lost", LOST, "other", { ...st, lost: true })) else Set()
    perDevice.union(viewMoves).union(deviceChangeMoves).union(clockMoves).union(lostMoves)
  }

  // The initial state: a migrated channel, a pre-v4 epoch v1 held by X1 and Y1;
  // X and Y see the channel, Z does not.
  pure val initial: State = {
    viewers: Set(0, 1),
    status: [APPROVED, if (SECOND_DEVICE) UNAPPROVED else ABSENT, APPROVED, APPROVED],
    log: [{ kind: LEGACY, genesis: 0, roster: Set(0, 2), added: Set(), poisoner: -1, parent: 0 }],
    pkg: [NO_PKG, NO_PKG, NO_PKG, NO_PKG],
    local: [NO_STATE, NO_STATE, NO_STATE, NO_STATE],
    derived: [Set(1), Set(), Set(1), Set()],
    restored: [Set(), Set(), Set(), Set()],
    stale: false, genesisWait: 0, viewerChanges: 0, deviceChanges: 0, lost: false,
  }

  action init = s' = initial

  action step = {
    nondet m = moves(s).oneOf()
    s' = m.target
  }

  // === Safety properties ===

  // Membership spans (start, end) of d in continuous groups; end is exclusive.
  pure def spans(log: List[Entry], d: int): List[{ start: int, end: int }] = {
    val acc = range(2, log.length() + 1).foldl({ spans: List(), start: 0 }, (a, v) =>
      if (log[v - 1].kind == LEGACY) a
      else {
        val closed = if (a.start > 0 and removedAt(log, v).contains(d))
                       { spans: a.spans.append({ start: a.start, end: v }), start: 0 } else a
        if (closed.start == 0 and log[v - 1].added.contains(d)) { ...closed, start: v } else closed
      })
    if (acc.start > 0) acc.spans.append({ start: acc.start, end: log.length() + 1 }) else acc.spans
  }

  // KA: versions of each membership the device must derive from the log
  // (versions from an unreadable envelope on are exempt) but cannot.
  // joined: false when the membership ended before the device joined it (KA-unjoined).
  pure def lacking(st: State, joined: bool): bool =
    DEVICES.exists(d => acting(st, d) and canRead(st, d) and {
      val reachable = sync(st, d).derived[d]
      spans(st.log, d).foldl(false, (found, sp) => found or {
        val stop = range(sp.start, sp.end).foldl(sp.end, (x, v) =>
          if (x == sp.end and poisonedFor(st.log[v - 1], d)) v else x)
        val missing = range(sp.start, stop).foldl(false, (m, v) => m or not(reachable.contains(v)))
        val isJoined = sp.end == st.log.length() + 1 or st.derived[d].contains(sp.start)
        missing and isJoined == joined
      })
    })

  // Who can derive, hold or restore the key of the active version, when some device can write.
  pure def writable(st: State): bool = {
    val w = view(st)
    DEVICES.exists(d => acting(st, d) and canSend(st, w, d))
  }
  pure def holders(st: State): Set[int] = {
    val version = st.log.length()
    last(st).roster.union(DEVICES.filter(d => st.derived[d].contains(version)))
  }
  pure def restorers(st: State): Set[int] = DEVICES.filter(d => st.restored[d].contains(st.log.length()))
  pure def revoked(st: State): Set[int] = DEVICES.filter(d => st.status[d] == REVOKED)

  // KC: only devices of users who can see the channel can derive or hold the key of a message written now.
  val KC = not(writable(s)) or USERS.forall(u =>
    userDevices(u).intersect(holders(s).union(restorers(s))) == Set() or s.viewers.contains(u))
  // KC-dev: no revoked device can derive or holds that key from the group.
  val KCdev = not(writable(s)) or revoked(s).intersect(holders(s)) == Set()
  // KC-dev-restore (LIMIT): a revoked device restored that key from a backup.
  val KCdevRestore = not(writable(s)) or revoked(s).intersect(restorers(s)).exclude(holders(s)) == Set()
  // KI: the version chain never forks.
  val KI = last(s).kind == LEGACY or last(s).parent == s.log.length() - 1
  // KA: a device that may read the channel derives every version of each membership it joined from the log.
  val KA = not(lacking(s, true))
  // KA-unjoined (LIMIT): a membership that ended before the device joined it.
  val KAunjoined = not(lacking(s, false))
}

// The explorations of m3_key_epochs.py RUNS.
module main {
  import m3(MAX_LOG = 6, POISON_BUDGET = 0, SECOND_DEVICE = false, LOSE_DEVICE = true, MAX_VIEWER_CHANGES = 2,
            MAX_DEVICE_CHANGES = 2, GATE_REMOVAL = true, CAS = true, REJOIN = true, FRESH_START = true,
            FORMER_MEMBER_LOG = true, LEAVE_ENDED_UNREADABLE = true, IDLE_FRESH_START = true,
            MALICIOUS_SERVER = false, PURGE_ON_LOSS = true, VIEW_USERS = Set(0, 1, 2)).*
}
module faults {
  import m3(MAX_LOG = 6, POISON_BUDGET = 1, SECOND_DEVICE = false, LOSE_DEVICE = false, MAX_VIEWER_CHANGES = 1,
            MAX_DEVICE_CHANGES = 1, GATE_REMOVAL = true, CAS = true, REJOIN = true, FRESH_START = true,
            FORMER_MEMBER_LOG = true, LEAVE_ENDED_UNREADABLE = true, IDLE_FRESH_START = true,
            MALICIOUS_SERVER = false, PURGE_ON_LOSS = true, VIEW_USERS = Set(0, 1, 2)).*
}
module secondDevice {
  import m3(MAX_LOG = 5, POISON_BUDGET = 0, SECOND_DEVICE = true, LOSE_DEVICE = false, MAX_VIEWER_CHANGES = 0,
            MAX_DEVICE_CHANGES = 2, GATE_REMOVAL = true, CAS = true, REJOIN = true, FRESH_START = true,
            FORMER_MEMBER_LOG = true, LEAVE_ENDED_UNREADABLE = true, IDLE_FRESH_START = true,
            MALICIOUS_SERVER = false, PURGE_ON_LOSS = true, VIEW_USERS = Set(0, 1, 2)).*
}

// Limits and controls (small = max_log 4, one viewer and one device change, no unreadable envelope).
module maliciousServer {
  import m3(MAX_LOG = 4, POISON_BUDGET = 0, SECOND_DEVICE = false, LOSE_DEVICE = false, MAX_VIEWER_CHANGES = 1,
            MAX_DEVICE_CHANGES = 1, GATE_REMOVAL = true, CAS = true, REJOIN = true, FRESH_START = true,
            FORMER_MEMBER_LOG = true, LEAVE_ENDED_UNREADABLE = true, IDLE_FRESH_START = true,
            MALICIOUS_SERVER = true, PURGE_ON_LOSS = true, VIEW_USERS = Set(0, 1, 2)).*
}
module noRemovalGate {
  import m3(MAX_LOG = 4, POISON_BUDGET = 0, SECOND_DEVICE = false, LOSE_DEVICE = false, MAX_VIEWER_CHANGES = 1,
            MAX_DEVICE_CHANGES = 1, GATE_REMOVAL = false, CAS = true, REJOIN = true, FRESH_START = true,
            FORMER_MEMBER_LOG = true, LEAVE_ENDED_UNREADABLE = true, IDLE_FRESH_START = true,
            MALICIOUS_SERVER = false, PURGE_ON_LOSS = true, VIEW_USERS = Set(0, 1, 2)).*
}
module noCas {
  import m3(MAX_LOG = 4, POISON_BUDGET = 0, SECOND_DEVICE = false, LOSE_DEVICE = false, MAX_VIEWER_CHANGES = 1,
            MAX_DEVICE_CHANGES = 1, GATE_REMOVAL = true, CAS = false, REJOIN = true, FRESH_START = true,
            FORMER_MEMBER_LOG = true, LEAVE_ENDED_UNREADABLE = true, IDLE_FRESH_START = true,
            MALICIOUS_SERVER = false, PURGE_ON_LOSS = true, VIEW_USERS = Set(0, 1, 2)).*
}
module currentMemberLog {
  import m3(MAX_LOG = 4, POISON_BUDGET = 0, SECOND_DEVICE = false, LOSE_DEVICE = false, MAX_VIEWER_CHANGES = 1,
            MAX_DEVICE_CHANGES = 1, GATE_REMOVAL = true, CAS = true, REJOIN = true, FRESH_START = true,
            FORMER_MEMBER_LOG = false, LEAVE_ENDED_UNREADABLE = true, IDLE_FRESH_START = true,
            MALICIOUS_SERVER = false, PURGE_ON_LOSS = true, VIEW_USERS = Set(0, 1, 2)).*
}
module rejoinEnded {
  import m3(MAX_LOG = 5, POISON_BUDGET = 1, SECOND_DEVICE = false, LOSE_DEVICE = false, MAX_VIEWER_CHANGES = 1,
            MAX_DEVICE_CHANGES = 1, GATE_REMOVAL = true, CAS = true, REJOIN = true, FRESH_START = true,
            FORMER_MEMBER_LOG = true, LEAVE_ENDED_UNREADABLE = false, IDLE_FRESH_START = true,
            MALICIOUS_SERVER = false, PURGE_ON_LOSS = true, VIEW_USERS = Set(0, 1, 2)).*
}
