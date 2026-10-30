// M10 in Quint: what a client can tell when a malicious server withholds or
// reorders signed message events (message protocol v6).
//
// A rewrite of m10_ordering.py / conformance/sequence-harness.mts. The server
// serves genuine v6 events (signatures cannot be forged) in an order it picks;
// TLC explores every served history by appending one unserved event per step,
// so each state is one history. For every state the client's view is
// computed by the rules of packages/client/src/stores/message-projector.ts
// (analyzeEventOrder, compareWithRemembered, projectMessageWindow with the v6
// edit chain) and channel-memory.ts (rememberHeads), written from that code:
//
//   window   'complete' (the whole channel), 'suffix' (the newest page),
//            'forum' (posts loaded one by one);
//   noticed  the channel notice, or a shown message with a sequence notice
//            or an uncertain edit;
//   a1       the version of message A1 shown ("none" when A1 is not shown,
//            "" when it shows no text).
//
// The view is kept in the state next to the history. It is a function of
// the history, so it adds no states; m10_quint.py compares it, history by
// history, with what the real client code shows (sequence-harness.mts).
// Deletions and v5/older layouts other than the pre-v6 control are not modelled.
module m10data {
  // A genuine event: `seen` is the event its writer had just received;
  // an edit names the message it edits (`ref`) and the version it replaces.
  type G = { name: str, device: str, seq: int, kind: str, ref: str, replaces: str, seen: str }

  // The genuine history of sequence-harness.mts, in the order it was written.
  pure val GENUINE7: List[G] = [
    { name: "A1", device: "A", seq: 1, kind: "message", ref: "", replaces: "", seen: "" },
    { name: "B1", device: "B", seq: 1, kind: "message", ref: "", replaces: "", seen: "A1" },
    { name: "A2", device: "A", seq: 2, kind: "edit", ref: "A1", replaces: "A1", seen: "B1" },
    { name: "C1", device: "C", seq: 1, kind: "message", ref: "", replaces: "", seen: "B1" },
    { name: "B2", device: "B", seq: 2, kind: "message", ref: "", replaces: "", seen: "A2" },
    { name: "A3", device: "A", seq: 3, kind: "message", ref: "", replaces: "", seen: "B2" },
    { name: "A4", device: "A", seq: 4, kind: "edit", ref: "A1", replaces: "A2", seen: "C1" },
  ]
}

module m10 {
  import m10data.*
  // "v6" | "split" | "memory" | "singleHead" | "noSequence" (the mutations of sequence-harness.mts)
  const MUTATION: str
  // The genuine history, in the order it was written (three devices A, B, C).
  const HISTORY: List[G]

  // A head: an event of another device named in seenHeads.
  type H = { device: str, seq: int, key: str }
  // An event as the client holds it after verification. key is its signed
  // idempotency key (the event's name; a forged one is "forged").
  type E = {
    name: str, device: str, seq: int,  // seq 0: no number
    sequenced: bool,                   // the v6 signature verified
    verified: bool, bound: bool,       // the signature verified; v5 or later layout
    kind: str, ref: str, refAuthor: str, refKey: str, supersedes: str, heads: List[H], key: str,
  }
  type W = { contiguous: bool, complete: bool }
  type V = { noticed: bool, a1: str }
  type Forged = { device: str, claimed: int, slot: int }
  type View = { c: V, s: V, f: V, cr: V, sr: V, fr: V, forgedMissed: Set[Forged], forgedTrials: int }
  // What the projector holds for a message.
  type P = { kind: str, key: str, origin: str, content: str, verified: bool, author: str, notice: str, uncertain: bool }

  val COMPLETE: W = { contiguous: true, complete: true }
  val SUFFIX: W = { contiguous: true, complete: false }
  val FORUM: W = { contiguous: false, complete: false }
  val DEVICES = ["A", "B", "C", "D"]

  val FORK: G = { name: "A2x", device: "A", seq: 2, kind: "message", ref: "", replaces: "", seen: "B1" }
  val UNSEQUENCED = MUTATION == "noSequence"
  val SINGLE_HEAD = MUTATION == "singleHead"
  val ALL: List[G] = if (MUTATION == "split") HISTORY.append(FORK) else HISTORY

  pure def inList(l: List[str], x: str): bool = l.foldl(false, (acc, y) => acc or y == x)
  pure def genuine(name: str, among: List[G]): G = among.select(g => g.name == name)[0]

  // happenedBefore in sequence-harness.mts: same device with a lower number,
  // or received (seen), with everything that happened before it. The events
  // are listed in the order written, so one pass in that order suffices.
  pure def pasts(events: List[G]): str -> Set[str] = events.foldl(Map(), (m, g) => {
    val direct = events.foldl(Set(), (s, x) => if (x.device == g.device and x.seq < g.seq) s.union(Set(x.name)) else s)
      .union(if (g.seen != "") Set(g.seen) else Set())
    m.put(g.name, direct.fold(direct, (acc, x) => if (m.keys().contains(x)) acc.union(m.get(x)) else acc))
  })
  val HB: str -> Set[str] = pasts(HISTORY)
  // The fork A2x has its own past (A1, B1).
  val PAST: str -> Set[str] =
    if (MUTATION == "split") HB.put("A2x", pasts(HISTORY.slice(0, 2).append(FORK)).get("A2x")) else HB

  // The heads an event names: the newest event of each other device in its
  // past (the phase 1 client named only `seen`).
  pure def headOf(g: G): H = { device: g.device, seq: g.seq, key: g.name }
  def headsOf(g: G): List[H] =
    if (SINGLE_HEAD) (if (g.seen != "") [headOf(genuine(g.seen, ALL))] else [])
    else DEVICES.foldl([], (out, d) => {
      val mine = ALL.select(x => x.device == d and x.device != g.device and PAST.get(g.name).contains(x.name))
      if (mine.length() == 0) out
      else out.append(headOf(mine.foldl(mine[0], (best, x) => if (x.seq > best.seq) x else best)))
    })

  // A genuine event as served and verified (served() in sequence-harness.mts).
  def served(g: G): E = {
    name: g.name, device: g.device, seq: if (UNSEQUENCED) 0 else g.seq,
    sequenced: not(UNSEQUENCED), verified: true, bound: true,
    kind: g.kind, ref: g.ref,
    refAuthor: if (g.ref != "") genuine(g.ref, ALL).device else "",
    refKey: g.ref,
    supersedes: if (UNSEQUENCED or g.kind != "edit") "" else g.replaces,
    heads: if (UNSEQUENCED) [] else headsOf(g),
    key: g.name,
  }
  // An event nobody signed that claims a number of a device.
  pure def forged(device: str, claimed: int): E = {
    name: "forged", device: device, seq: claimed, sequenced: false, verified: false, bound: false,
    kind: "message", ref: "", refAuthor: "", refKey: "", supersedes: "", heads: [], key: "forged",
  }

  // ---- packages/client/src/stores/message-projector.ts ----

  // claimedSequence: the number an event claims, if it is a valid one.
  pure def claimed(e: E): bool = e.seq >= 1
  // trustsNumber: every event here has a verdict, so only a v6 signature counts.
  pure def trusts(e: E): bool = e.sequenced
  pure def note(current: str, notice: str): str = if (current == "missing") current else notice

  // analyzeEventOrder: a notice ("" | "missing" | "order") for each place.
  pure def analyze(ord: List[E], w: W): List[str] = {
    val idx = ord.indices()
    // The lowest number held of a device (0: none).
    pure def lowest(d: str): int = idx.fold(0, (m, j) =>
      if (claimed(ord[j]) and trusts(ord[j]) and ord[j].device == d and (m == 0 or ord[j].seq < m)) ord[j].seq else m)
    // The first verified v6 event under a device number (-1: none).
    pure def firstAt(d: str, s: int): int = idx.fold(-1, (m, j) =>
      if (ord[j].sequenced and ord[j].device == d and ord[j].seq == s and (m == -1 or j < m)) j else m)
    pure def pendingAt(d: str, s: int): bool =
      idx.exists(j => claimed(ord[j]) and trusts(ord[j]) and not(ord[j].sequenced) and ord[j].device == d and ord[j].seq == s)
    pure def heldAfter(d: str, s: int, i: int): bool =
      idx.exists(j => ord[j].sequenced and claimed(ord[j]) and ord[j].device == d and ord[j].seq <= s and j > i)
    val init = { lastClaimed: Map(), lastVerified: Map(), sequencedSeen: false, notices: [] }
    val result = range(0, ord.length()).foldl(init, (acc, i) => {
      val e = ord[i]
      val gap = claimed(e) and trusts(e) and w.contiguous and
        (if (acc.lastClaimed.keys().contains(e.device)) e.seq > acc.lastClaimed.get(e.device) + 1 else (w.complete and e.seq > 1))
      val n1 = if (gap) "missing" else ""
      val lastClaimed =
        if (claimed(e) and trusts(e) and (not(acc.lastClaimed.keys().contains(e.device)) or e.seq > acc.lastClaimed.get(e.device)))
          acc.lastClaimed.put(e.device, e.seq)
        else acc.lastClaimed
      if (e.sequenced) {
        val behind = acc.lastVerified.keys().contains(e.device) and e.seq <= acc.lastVerified.get(e.device)
        val n2 = if (behind) note(n1, "order") else n1
        val n3 = e.heads.foldl(n2, (n, h) => {
          val a = if (heldAfter(h.device, h.seq, i)) note(n, "order") else n
          val at = firstAt(h.device, h.seq)
          if (at >= 0) (if (ord[at].key != h.key) note(a, "order") else a)
          else if (pendingAt(h.device, h.seq)) a
          else if (w.contiguous and (w.complete or (lowest(h.device) >= 1 and lowest(h.device) < h.seq))) note(a, "missing")
          else a
        })
        { lastClaimed: lastClaimed,
          lastVerified: if (behind) acc.lastVerified else acc.lastVerified.put(e.device, e.seq),
          sequencedSeen: true, notices: acc.notices.append(n3) }
      } else {
        { ...acc, lastClaimed: lastClaimed,
          notices: acc.notices.append(if (e.verified and acc.sequencedSeen) note(n1, "order") else n1) }
      }
    })
    result.notices
  }

  // compareWithRemembered ("" | "missing" | "order").
  pure def compareRemembered(ord: List[E], w: W, remembered: str -> H): str = {
    val idx = ord.indices()
    pure def newest(d: str): int = idx.fold(0, (m, j) =>
      if (claimed(ord[j]) and trusts(ord[j]) and ord[j].device == d and ord[j].seq > m) ord[j].seq else m)
    // keys.set overwrites: the key of the last v6 event under the number.
    pure def keyAt(d: str, s: int): str = idx.fold({ at: -1, key: "" }, (m, j) =>
      if (ord[j].sequenced and ord[j].device == d and ord[j].seq == s and j > m.at) { at: j, key: ord[j].key } else m).key
    val heads = remembered.keys()
    val missing = heads.exists(d => {
      val h = remembered.get(d)
      keyAt(d, h.seq) == "" and w.contiguous and (if (newest(d) == 0) w.complete else newest(d) < h.seq)
    })
    val swapped = heads.exists(d => {
      val h = remembered.get(d)
      keyAt(d, h.seq) != "" and keyAt(d, h.seq) != h.key
    })
    if (missing) "missing" else if (swapped) "order" else ""
  }

  // channel-memory.ts rememberHeads: the newest verified v6 event of each device.
  pure def rememberHeads(events: List[E]): str -> H = events.foldl(Map(), (m, e) =>
    if (not(e.sequenced) or not(claimed(e)) or (m.keys().contains(e.device) and m.get(e.device).seq >= e.seq)) m
    else m.put(e.device, { device: e.device, seq: e.seq, key: e.key }))

  pure def mayEdit(e: E, t: P): bool =
    e.verified and t.kind != "delete" and e.device == t.author and t.verified
    // namesEvent: a v5 or later edit names the very message it edits.
    and (not(e.bound and e.verified) or (t.author == e.refAuthor and t.origin == e.refKey))

  type Acc = {
    proj: str -> P, waiting: str -> List[E], shown: str -> Set[str],
    carried: bool, lastBase: str, channel: str,
  }

  pure def applyEdit(acc: Acc, e: E, tid: str): Acc = {
    ...acc,
    proj: acc.proj.put(tid, { ...acc.proj.get(tid), kind: "edit", content: e.name, key: e.key }),
    shown: acc.shown.put(tid, acc.shown.get(tid).union(Set(e.key))),
  }

  // applyWaitingEdits: each waiting v6 edit that replaces the version shown, in turn.
  pure def applyWaiting(acc: Acc, tid: str): Acc = {
    val rounds = if (acc.waiting.keys().contains(tid)) acc.waiting.get(tid).length() else 0
    range(0, rounds).foldl(acc, (a, _r) => {
      if (not(a.proj.keys().contains(tid)) or a.proj.get(tid).kind == "delete" or not(a.waiting.keys().contains(tid))) a
      else {
        val t = a.proj.get(tid)
        val waiting = a.waiting.get(tid)
        val fits = waiting.indices().filter(k => waiting[k].supersedes == t.key and mayEdit(waiting[k], t))
        if (fits.size() == 0) a
        else {
          val k = fits.fold(waiting.length(), (m, j) => if (j < m) j else m)
          val left = waiting.slice(0, k).concat(waiting.slice(k + 1, waiting.length()))
          applyEdit({ ...a, waiting: a.waiting.put(tid, left) }, waiting[k], tid)
        }
      }
    })
  }

  pure def noteChannel(acc: Acc, notice: str): Acc =
    if (acc.channel == "missing") acc else { ...acc, channel: notice }

  // projectMessageWindow, reduced to what the user sees: whether anything is
  // flagged, and which version of A1 shows.
  pure def project(ord: List[E], w: W, remembered: str -> H): V = {
    val notices = analyze(ord, w)
    val remembering = compareRemembered(ord, w, remembered)
    val start: Acc = {
      proj: Map(), waiting: Map(), shown: Map(), carried: false, lastBase: "",
      channel: remembering,
    }
    val walked = range(0, ord.length()).foldl(start, (acc, i) => {
      val e = ord[i]
      val nt = notices[i]
      if (e.kind == "message") {
        val p = {
          kind: "message", key: e.key, origin: e.key, content: if (e.verified) e.name else "",
          verified: e.verified, author: e.device,
          notice: if (nt == "missing" or acc.carried) "missing" else nt, uncertain: false,
        }
        applyWaiting({ ...acc, proj: acc.proj.put(e.name, p), shown: acc.shown.put(e.name, Set(e.key)),
                       carried: false, lastBase: e.name }, e.name)
      } else {
        val a1 = { ...acc, carried: acc.carried or nt == "missing" }
        val tid = e.ref
        if (tid == "") a1
        else {
          val a2 = if (e.kind == "edit" and e.sequenced and e.verified)
            { ...a1, waiting: a1.waiting.put(tid, (if (a1.waiting.keys().contains(tid)) a1.waiting.get(tid) else []).append(e)) }
            else a1
          if (not(a2.proj.keys().contains(tid))) (if (nt == "order") noteChannel(a2, "order") else a2)
          else {
            val a3 = if (nt == "order" and a2.proj.get(tid).notice == "")
              { ...a2, proj: a2.proj.put(tid, { ...a2.proj.get(tid), notice: "order" }) } else a2
            if (e.sequenced) applyWaiting(a3, tid)
            else if (mayEdit(e, a3.proj.get(tid))) applyWaiting(applyEdit(a3, e, tid), tid)
            else a3
          }
        }
      }
    })
    val carried =
      if (not(walked.carried)) walked
      else if (walked.lastBase != "")
        { ...walked, proj: walked.proj.put(walked.lastBase, { ...walked.proj.get(walked.lastBase), notice: "missing" }) }
      else noteChannel(walked, "missing")
    // A v6 edit of a shown message that never replaced the shown version.
    val settled = carried.waiting.keys().fold(carried, (acc, tid) => {
      if (not(acc.proj.keys().contains(tid)) or acc.proj.get(tid).kind == "delete") acc
      else {
        val t = acc.proj.get(tid)
        val pending = acc.waiting.get(tid).select(ed => mayEdit(ed, t))
        if (pending.length() == 0) acc
        else {
          val newest = pending.select(ed => not(pending.foldl(false, (x, o) => x or o.supersedes == ed.key)))
          val held = acc.shown.get(tid)
          if (not(w.contiguous) and newest.length() == 1 and pending.foldl(true, (x, ed) => x and not(held.contains(ed.supersedes))))
            applyEdit(acc, newest[0], tid)
          else { ...acc, proj: acc.proj.put(tid, { ...t, uncertain: true }) }
        }
      }
    })
    {
      noticed: settled.channel != ""
        or settled.proj.keys().exists(id => settled.proj.get(id).notice != "" or settled.proj.get(id).uncertain),
      a1: if (settled.proj.keys().contains("A1")) settled.proj.get("A1").content else "none",
    }
  }

  // ---- what the server serves ----

  val NONE: V = { noticed: false, a1: "none" }
  val REMEMBERED: str -> H =
    if (MUTATION == "memory") rememberHeads(HISTORY.foldl([], (l, g) => l.append(served(g)))) else Map()
  // The split member who received A1, B1 and A2 before.
  val REMEMBERED_SPLIT: str -> H = rememberHeads(HISTORY.slice(0, 3).foldl([], (l, g) => l.append(served(g))))

  var order: List[str]   // the served history
  var view: View         // what the client shows of it (a function of `order`)

  def events(o: List[str]): List[E] = o.foldl([], (l, n) => l.append(served(genuine(n, ALL))))
  def withheldOf(o: List[str]): List[G] = HISTORY.select(g => not(inList(o, g.name)))
  def withheldPast(o: List[str]): List[G] = withheldOf(o).select(x => o.foldl(false, (acc, n) => acc or HB.get(n).contains(x.name)))
  pure def insertAt(l: List[E], k: int, e: E): List[E] = l.slice(0, k).append(e).concat(l.slice(k, l.length()))

  def viewOf(o: List[str]): View = {
    val ev = events(o)
    val c = project(ev, COMPLETE, REMEMBERED)
    // MO-forged-number: an unsigned event claiming the number of a withheld
    // event, the next one or a huge one, at every place in the history.
    val past = withheldPast(o)
    val trials = if (MUTATION == "v6" and past.length() > 0 and c.noticed)
      past.foldl(Set(), (s, x) => s.union(Set(x.seq, x.seq + 1, 1000000).map(n =>
        range(0, o.length() + 1).foldl(Set(), (t, k) => t.union(Set({ device: x.device, claimed: n, slot: k })))).flatten()))
      else Set()
    val split = MUTATION == "split"
    {
      c: c,
      s: project(ev, SUFFIX, REMEMBERED),
      f: if (MUTATION == "memory") NONE else project(ev, FORUM, REMEMBERED),
      cr: if (split) project(ev, COMPLETE, REMEMBERED_SPLIT) else NONE,
      sr: if (split) project(ev, SUFFIX, REMEMBERED_SPLIT) else NONE,
      fr: if (split) project(ev, FORUM, REMEMBERED_SPLIT) else NONE,
      forgedMissed: trials.filter(t => not(project(insertAt(ev, t.slot, forged(t.device, t.claimed)), COMPLETE, REMEMBERED).noticed)),
      forgedTrials: if (trials.size() == 0) 0 else past.length() * 3 * (o.length() + 1),
    }
  }

  // The first step computes the view of the empty history: Quint's TLA+
  // output walks every definition init reaches, once per path, which the
  // projection makes too many. So the run starts one state earlier, with no
  // view yet (`ready` false), and every property holds there.
  var ready: bool
  val BLANK: V = { noticed: false, a1: "" }

  action init = all {
    order' = [], ready' = false,
    view' = { c: BLANK, s: BLANK, f: BLANK, cr: BLANK, sr: BLANK, fr: BLANK, forgedMissed: Set(), forgedTrials: 0 },
  }

  action start = all { not(ready), ready' = true, order' = order, view' = viewOf(order) }

  action serve = {
    nondet name = ALL.foldl(Set(), (s, g) => if (inList(order, g.name)) s else s.union(Set(g.name))).oneOf()
    val longer = order.append(name)
    all { ready, ready' = true, order' = longer, view' = viewOf(longer) }
  }

  action step = any { start, serve }

  // ---- the ground truth the checks compare with (as sequence-harness.mts) ----

  def position(n: str): int = order.indices().fold(-1, (m, i) => if (order[i] == n) i else m)
  def reordered: bool = order.indices().exists(i => HB.get(order[i]).exists(x => position(x) > i))
  def signsAfter(y: G, x: G): bool = (y.device == x.device and y.seq > x.seq)
    or headsOf(y).foldl(false, (acc, h) => acc or (h.device == x.device and h.seq >= x.seq))
  def reorderedDirectly: bool = order.indices().exists(i => order.indices().exists(j =>
    j > i and signsAfter(genuine(order[i], ALL), genuine(order[j], ALL))))
  val WITHHELD_PAST = withheldPast(order)
  val WITHHELD_TAIL = withheldOf(order).select(x => not(inList(WITHHELD_PAST.foldl([], (l, g) => l.append(g.name)), x.name)))
  def honestRun: bool = order.indices().forall(i => i == 0 or
    HISTORY.indices().exists(k => k > 0 and HISTORY[k].name == order[i] and HISTORY[k - 1].name == order[i - 1]))
  val SERVED = order.length() > 0
  val NAMES = HISTORY.foldl([], (l, g) => l.append(g.name))
  val LAST = HISTORY[HISTORY.length() - 1].name
  def newestEdit: str = order.foldl({ seq: 0, name: "" }, (m, n) => {
    val g = genuine(n, ALL)
    if (g.kind == "edit" and g.ref == "A1" and g.seq > m.seq) { seq: g.seq, name: n } else m
  }).name
  def sameSet(names: List[str]): bool = order.length() == names.length() and names.foldl(true, (acc, n) => acc and inList(order, n))

  // v6, single-head and pre-v6 runs (each property: no state violates it).
  val MO_order = not(ready) or not(SERVED and reorderedDirectly) or (view.c.noticed and view.s.noticed and view.f.noticed)
  val MO_order_complete = not(ready) or not(SERVED and reordered) or view.c.noticed
  val MO_order_hidden = not(ready) or not(SERVED and reordered and not(reorderedDirectly)) or (view.s.noticed and view.f.noticed)
  val MO_drop = not(ready) or not(SERVED and WITHHELD_PAST.length() > 0) or view.c.noticed
  val MO_forged_number = not(ready) or view.forgedMissed.size() == 0
  val MO_edit = not(ready) or not(SERVED and view.c.a1 != "none" and newestEdit != "" and view.c.a1 != newestEdit and not(view.c.noticed))
  val MO_honest = not(ready) or order != NAMES or (not(view.c.noticed) and view.c.a1 == LAST)
  val MO_honest_suffix = not(ready) or not(SERVED and honestRun and order[order.length() - 1] == LAST) or not(view.s.noticed)
  val MO_honest_forum = not(ready) or order != ["A1", "A4"] or (not(view.f.noticed) and view.f.a1 == "A4")
  // Limits: the state that shows the limit must be reachable (the invariant breaks).
  val MO_tail = not(ready) or not(SERVED and WITHHELD_PAST.length() == 0 and WITHHELD_TAIL.length() > 0 and not(reordered)
                    and not(view.c.noticed))
  val MO_suffix = not(ready) or not(SERVED and WITHHELD_PAST.length() > 0 and not(reordered) and not(view.s.noticed))
  val MO_forum = not(ready) or not(SERVED and WITHHELD_PAST.length() > 0 and not(reordered) and not(view.f.noticed))

  // memory run: a member who received the whole history before.
  def traced(complete: bool): bool = withheldOf(order).foldl(false, (acc, x) => acc or complete
    or order.foldl(false, (b, n) => b or (genuine(n, ALL).device == x.device and genuine(n, ALL).seq < x.seq)))
  val WITHHELD = order.length() < HISTORY.length()
  val MO_rollback = not(ready) or not(WITHHELD) or ((view.c.noticed or not(traced(true))) and (view.s.noticed or not(traced(false))))
  val MO_rollback_page = not(ready) or not(WITHHELD) or ((view.c.noticed or traced(true)) and (view.s.noticed or traced(false)))

  // split run: device A signed A2 and A2x under number 2.
  def allNoticed(v: View): bool = v.c.noticed and v.s.noticed and v.f.noticed
  val MO_split = not(ready) or not(order == ["A1", "B1", "A2"] or order == ["A1", "B1", "A2x"]) or view.c.noticed
  val MO_split_seen = not(ready) or not(sameSet(["A1", "B1", "A2", "A2x"])) or allNoticed(view)
  val MO_split_named = not(ready) or not(sameSet(["A1", "B1", "A2x", "B2"])) or allNoticed(view)
  val MO_split_remembered = not(ready) or order != ["A1", "B1", "A2x"] or (view.cr.noticed and view.sr.noticed and view.fr.noticed)
}


module v6 {
  import m10data.*
  import m10(MUTATION = "v6", HISTORY = GENUINE7).*
}

module split {
  import m10data.*
  import m10(MUTATION = "split", HISTORY = GENUINE7).*
}

module memory {
  import m10data.*
  import m10(MUTATION = "memory", HISTORY = GENUINE7).*
}

module singleHead {
  import m10data.*
  import m10(MUTATION = "singleHead", HISTORY = GENUINE7).*
}

module noSequence {
  import m10data.*
  import m10(MUTATION = "noSequence", HISTORY = GENUINE7).*
}
