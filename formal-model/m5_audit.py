"""M5: audit hash chain, checkpoint and witness — attacker capability matrix.

Mirrors middleware/audit.ts:
  row hash      HMAC_K(prevHash, data); verified row by row (scanAuditRows)
  checkpoint    {logId, logHash, logCreatedAt} HMAC-signed with the same K,
                written after each commit (a crash can leave it one row
                behind); the row must exist with that hash (not "ahead").
  rollback      a checkpoint older than lastAcceptedCheckpoint, or equal time
                with another row/hash, is rejected. lastAcceptedCheckpoint is
                process memory, also persisted in a separate object-store
                bucket after the local checkpoint write. Startup validates
                both anchors and never creates a missing durable head.
  witness       optional offline SLH-DSA signature on {logId, logHash,
                logCreatedAt}; the witnessed row must be present unchanged.

Hashes are structural: ('h', data, prev). Without K an attacker can only
reuse hash values that already exist; with K it can compute any of them.
Attacks are enumerated exhaustively for a chain of N rows:
  delete row i / modify row i / truncate the last j rows,
  each optionally followed by recomputing the tail (needs K),
  combined with: keep checkpoint / replay an older checkpoint copy (needs
  checkpoint-file write) / forge a new checkpoint (needs K and file write),
  with or without a restart, and with or without a witness.
"""
from __future__ import annotations

from dataclasses import dataclass
from itertools import product

from common import record

N = 4
WITNESSED = 2           # the witness lags behind the head


def h(data, prev):
    return ('h', data, prev)


def honest_chain():
    rows, prev = [], None
    for i in range(1, N + 1):
        data = f'e{i}'
        rows.append({'id': i, 'data': data, 'prev': prev, 'hash': h(data, prev)})
        prev = rows[-1]['hash']
    return rows


@dataclass(frozen=True)
class Caps:
    db: bool = False            # database owner (can disable the append-only triggers)
    key: bool = False           # AUDIT_INTEGRITY_KEY
    file: bool = False          # write the checkpoint file (and read old copies)
    restart: bool = False       # can cause a process restart
    head: bool = False          # additionally write/rollback the separate object-store head


@dataclass(frozen=True)
class Checks:
    chain: bool = True
    rollback_memory: bool = True
    durable_head: bool = True


def recompute(rows, start):
    out, prev = [dict(r) for r in rows], (rows[start - 1]['hash'] if start > 0 else None)
    for r in out[start:]:
        r['prev'] = prev
        r['hash'] = h(r['data'], prev)
        prev = r['hash']
    return out


def tampered_chains(chain, caps):
    """Yield (description, rows, earliest_changed_row_id)."""
    if not caps.db:
        return
    for i in range(1, N + 1):
        base = [dict(r) for r in chain if r['id'] != i]
        yield f'delete row {i}', base, i
        if caps.key:
            yield f'delete row {i} and recompute', recompute(base, i - 1), i
        modified = [dict(r) for r in chain]
        modified[i - 1]['data'] = f'forged{i}'
        yield f'modify row {i}', modified, i
        if caps.key:
            yield f'modify row {i} and recompute', recompute(modified, i - 1), i
    for j in range(1, N):
        yield f'truncate last {j}', [dict(r) for r in chain[:-j]], N - j + 1


def verify(rows, checkpoint, last_accepted, witness, checks: Checks, head=None):
    prev = None
    for r in rows:
        if r['prev'] != prev:
            return False
        if checks.chain and r['hash'] != h(r['data'], prev):
            return False
        prev = r['hash']
    # checkpoint signature is checked by the caller (forging needs K)
    if checks.rollback_memory and last_accepted is not None and checkpoint['id'] < last_accepted['id']:
        return False
    anchor = next((r for r in rows if r['id'] == checkpoint['id']), None)
    if anchor is None or anchor['hash'] != checkpoint['hash']:
        return False                    # missing or "ahead of the database chain"
    if checks.durable_head and head is not None:
        anchor = next((r for r in rows if r['id'] == head['id']), None)
        if checkpoint['id'] < head['id'] or anchor is None or anchor['hash'] != head['hash']:
            return False
    if witness is not None:
        row = next((r for r in rows if r['id'] == witness['id']), None)
        if row is None or row['hash'] != witness['hash']:
            return False
    return True


def undetected_attacks(caps: Caps, witness_on: bool, checkpoint_lag: int, checks: Checks = Checks()):
    chain = honest_chain()
    head = N - checkpoint_lag
    current = {'id': head, 'hash': chain[head - 1]['hash']}
    witness = {'id': WITNESSED, 'hash': chain[WITNESSED - 1]['hash']} if witness_on else None
    results = []
    for description, rows, changed in tampered_chains(chain, caps):
        checkpoints = [('keep checkpoint', current)]
        if caps.file:
            checkpoints += [(f'replay old checkpoint @{c}', {'id': c, 'hash': chain[c - 1]['hash']}) for c in range(1, head)]
        if caps.file and caps.key:
            checkpoints += [(f'forge checkpoint @{r["id"]}', {'id': r['id'], 'hash': r['hash']}) for r in rows]
        for (cp_desc, checkpoint), restarted in product(checkpoints, (False, True)):
            if restarted and not caps.restart:
                continue
            last = None if restarted else current
            durable = checkpoint if caps.head else current
            if verify(rows, checkpoint, last, witness, checks, durable):
                results.append((changed, f'{description}; {cp_desc}{"; restart" if restarted else ""}'))
    return results


def run() -> None:
    print('== M5: audit chain, checkpoint and witness (attacker capability matrix) ==')

    def check(check_id, title, expect, caps, witness_on=False, lag=0, checks=Checks(), keep=lambda changed: True):
        hits = [a for changed, a in undetected_attacks(caps, witness_on, lag, checks) if keep(changed)]
        record('M5', check_id, title, expect, bool(hits), witness=hits[:4])

    db = Caps(db=True, restart=True)
    check('AU1', 'a database owner without the key cannot change or remove any checkpointed row', 'HOLDS', db)
    check('AU2', 'with the integrity key, rows up to the checkpoint still cannot be changed', 'HOLDS',
          Caps(db=True, key=True, restart=True), keep=lambda changed: changed <= N)
    check('AU3', 'with key and checkpoint file, rows up to the witness still cannot be changed', 'HOLDS',
          Caps(db=True, key=True, file=True, restart=True, head=True), witness_on=True, keep=lambda changed: changed <= WITNESSED)
    check('AU4a', 'replaying an older checkpoint copy is rejected while the process runs', 'HOLDS',
          Caps(db=True, file=True, restart=False))
    check('AU4b', 'replaying an older checkpoint copy is rejected after a restart', 'HOLDS',
          Caps(db=True, file=True, restart=True))

    check('AU-L1', 'a row committed but not yet checkpointed (crash window) can be removed without the key', 'LIMIT',
          db, lag=1)
    check('AU-L2', 'with key, database, checkpoint file AND object-store head, unwitnessed history can be rewritten',
          'LIMIT', Caps(db=True, key=True, file=True, restart=True, head=True))
    check('AU-L3', 'even with a witness, rows after the witnessed row can be rewritten by a full compromise', 'LIMIT',
          Caps(db=True, key=True, file=True, restart=True, head=True), witness_on=True, keep=lambda changed: changed > WITNESSED)
    check('AU-L4', 'rollback of ALL durable anchors and database cannot be detected locally after restart', 'LIMIT',
          Caps(db=True, file=True, restart=True, head=True))

    check('AU1-ctl', 'without per-row hash verification a database owner can modify rows', 'CONTROL', db, checks=Checks(chain=False))
    check('AU4a-ctl', 'without lastAcceptedCheckpoint an older checkpoint copy is accepted at runtime', 'CONTROL',
          Caps(db=True, file=True, restart=False), checks=Checks(rollback_memory=False, durable_head=False))
    check('AU4b-ctl', 'without the durable head, old checkpoints pass again after restart', 'CONTROL',
          Caps(db=True, file=True, restart=True), checks=Checks(durable_head=False))


if __name__ == '__main__':
    run()
