// M3r in Quint: an own group commit whose answer may be lost.
//
// A rewrite of m3r_own_commit.py with the same state and transitions, so that
// TLC finds the same number of states. The state is one record that mirrors
// the Python St tuple field by field; "" stands for Python's None.
//
//   server  services/mls-group.service.ts admitGroupCommit: replay check,
//           checks without locks, then the version compare-and-swap.
//   client  services/mls-group.service.ts submitOwnEnvelope / sendOwnEnvelope /
//           settlePending and the catch-up from the log.
module m3r {
  // Variant switches (class V in m3r_own_commit.py).
  const REPLAY_RECHECK: bool     // CONTROL: false answers 409 when the unlocked checks find V taken
  const STAMP_BEFORE_SEND: bool  // proposed client change: stamp a send before it starts
  const TRANSIENT_REFUSAL: bool  // a resend can be refused without the state changing (429, 401, ...)
  const LATE_REQUESTS: bool      // a request can outlive five minutes at the server
  const MAX_SENDS: int
  const MAX_CRASHES: int
  const COMPETITOR: bool

  // stage 0: replay check, 1: unlocked checks, 2: locked compare-and-swap
  type Req = { sender: str, name: str, stage: int, tag: int }
  type Answer = { name: str, answer: str }
  type State = {
    stored: str,          // envelope accepted at V
    recName: str,         // A's saved own envelope
    recUnsettled: str,    // "" | "recent" | "old"
    built: int,           // A's envelopes built so far: e1, e2
    requests: List[Req],  // in the order of m3r_own_commit.py
    tab: str,             // "idle" | "sending"
    adopted: str,         // what A adopted at V ("rejoin" when it must be added again)
    rejoin: bool,         // ghost: A met its own accepted commit without its record
    answers: List[Answer],// ghost: answers given to A's requests
    crashes: int,
    sends: int,
    bSent: bool,
  }

  var s: State

  pure def removeAt(l: List[Req], i: int): List[Req] = l.slice(0, i).concat(l.slice(i + 1, l.length()))

  pure def isOwn(name: str): bool = name == "e1" or name == "e2"

  // _answer in m3r_own_commit.py: only the tab that sent the last request handles the answer.
  pure def answer(st: State, rest: List[Req], r: Req, ans: str): State =
    if (r.sender != "A") { ...st, requests: rest }
    else {
      val t = { ...st, requests: rest, answers: st.answers.append({ name: r.name, answer: ans }) }
      val last = st.requests.foldl(-1, (acc, q) => if (q.sender == "A" and q.tag > acc) q.tag else acc)
      if (st.tab != "sending" or r.tag != last) t
      else {
        val u = { ...t, tab: "idle" }
        if (ans == "accepted" or ans == "replay")
          if (u.recName == r.name) { ...u, adopted: r.name, recName: "", recUnsettled: "" } else u
        else if (u.recName == r.name)
          if (u.recUnsettled == "recent") u else { ...u, recName: "", recUnsettled: "" }
        else u
      }
    }

  action init = s' = {
    stored: "", recName: "", recUnsettled: "", built: 0, requests: List(), tab: "idle",
    adopted: "", rejoin: false, answers: List(), crashes: 0, sends: 0, bSent: false,
  }

  // A builds and saves an envelope when it has no record and nothing is decided yet.
  action build = all {
    s.recName == "", s.adopted == "", s.tab == "idle", s.built < 2, s.stored == "",
    s' = { ...s, recName: if (s.built == 0) "e1" else "e2", recUnsettled: "", built: s.built + 1 },
  }

  // A sends its saved envelope (first send or resend of the same bytes).
  action send = all {
    s.recName != "", s.tab == "idle", s.sends < MAX_SENDS, s.adopted == "",
    s' = { ...s,
      recUnsettled: if (STAMP_BEFORE_SEND) "recent" else s.recUnsettled,
      requests: s.requests.append({ sender: "A", name: s.recName, stage: 0, tag: s.sends }),
      tab: "sending", sends: s.sends + 1 },
  }

  // The tab closes in the middle of a send; its request goes on at the server.
  action closeTab = all {
    s.tab == "sending", s.crashes < MAX_CRASHES,
    s' = { ...s, tab: "idle", crashes: s.crashes + 1 },
  }

  // B commits V once.
  action competitorSends = all {
    COMPETITOR, not(s.bSent),
    s' = { ...s, requests: s.requests.append({ sender: "B", name: "b", stage: 0, tag: 99 }), bSent: true },
  }

  // Five minutes pass and a stamp becomes old. With bounded requests every
  // send it covers has ended by then.
  action fiveMinutes = {
    val outstanding = s.requests.foldl(false, (acc, q) => acc or q.sender == "A")
    all {
      s.recName != "", s.recUnsettled == "recent", LATE_REQUESTS or not(outstanding),
      s' = { ...s, recUnsettled: "old" },
    }
  }

  // One server step of one request.
  action serverStep = {
    nondet i = s.requests.indices().oneOf()
    val r = s.requests[i]
    val rest = removeAt(s.requests, i)
    val advance = { ...s, requests: rest.append({ ...r, stage: r.stage + 1 }) }
    any {
      all { r.stage == 0, s.stored == r.name, s' = answer(s, rest, r, "replay") },
      all { r.stage == 0, s.stored != r.name, TRANSIENT_REFUSAL, r.sender == "A", r.tag > 0,
            s' = answer(s, rest, r, "refused") },
      all { r.stage == 0, s.stored != r.name, s' = advance },
      all { r.stage == 1, s.stored != "",
            s' = answer(s, rest, r, if (REPLAY_RECHECK and s.stored == r.name) "replay" else "409") },
      all { r.stage == 1, s.stored == "", s' = advance },
      all { r.stage == 2, s.stored == "", s' = answer({ ...s, stored: r.name }, rest, r, "accepted") },
      all { r.stage == 2, s.stored != "",
            s' = answer(s, rest, r, if (s.stored == r.name) "replay" else "409") },
    }
  }

  // A catches up from the log once V is taken.
  action catchUp = all {
    s.stored != "", s.adopted == "", s.tab == "idle",
    s' = if (s.recName == s.stored) { ...s, adopted: s.stored, recName: "", recUnsettled: "" }
         else if (isOwn(s.stored)) { ...s, adopted: "rejoin", rejoin: true, recName: "", recUnsettled: "" }
         else { ...s, adopted: s.stored, recName: "", recUnsettled: "" },
  }

  action step = any { build, send, closeTab, competitorSends, fiveMinutes, serverStep, catchUp }

  // K1: A never loses the state of its own accepted commit.
  val K1 = not(s.rejoin)
  // K2: a resend of the accepted envelope never gets 409.
  val K2 = s.answers.foldl(true, (acc, a) => acc and not(a.answer == "409" and s.stored == a.name))
  val Always = true
}

// The variants of m3r_own_commit.py run().
module implementation {
  import m3r(REPLAY_RECHECK = true, STAMP_BEFORE_SEND = false, TRANSIENT_REFUSAL = false,
             LATE_REQUESTS = false, MAX_SENDS = 3, MAX_CRASHES = 1, COMPETITOR = true).*
}
module transient {
  import m3r(REPLAY_RECHECK = true, STAMP_BEFORE_SEND = false, TRANSIENT_REFUSAL = true,
             LATE_REQUESTS = false, MAX_SENDS = 3, MAX_CRASHES = 1, COMPETITOR = true).*
}
module transientStamp {
  import m3r(REPLAY_RECHECK = true, STAMP_BEFORE_SEND = true, TRANSIENT_REFUSAL = true,
             LATE_REQUESTS = false, MAX_SENDS = 3, MAX_CRASHES = 1, COMPETITOR = true).*
}
module lateStamp {
  import m3r(REPLAY_RECHECK = true, STAMP_BEFORE_SEND = true, TRANSIENT_REFUSAL = true,
             LATE_REQUESTS = true, MAX_SENDS = 3, MAX_CRASHES = 1, COMPETITOR = true).*
}
module beforeFix {
  import m3r(REPLAY_RECHECK = false, STAMP_BEFORE_SEND = false, TRANSIENT_REFUSAL = false,
             LATE_REQUESTS = false, MAX_SENDS = 3, MAX_CRASHES = 1, COMPETITOR = true).*
}

// Larger bounds than m3r_own_commit.py runs: more resends and closed tabs.
module implementationLarge {
  import m3r(REPLAY_RECHECK = true, STAMP_BEFORE_SEND = false, TRANSIENT_REFUSAL = false,
             LATE_REQUESTS = false, MAX_SENDS = 5, MAX_CRASHES = 3, COMPETITOR = true).*
}
module transientStampLarge {
  import m3r(REPLAY_RECHECK = true, STAMP_BEFORE_SEND = true, TRANSIENT_REFUSAL = true,
             LATE_REQUESTS = false, MAX_SENDS = 5, MAX_CRASHES = 3, COMPETITOR = true).*
}
