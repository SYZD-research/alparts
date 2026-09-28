# Alparts Security Audit — Directory Guide

Internal handoff directory. Read `findings/INDEX.md` first — it is the triage master index.

## Layout

```
audit-alparts/
├── README.md                    ← this file
├── findings/
│   ├── INDEX.md                 ← START HERE: severity tables, priority queue, owner map
│   ├── server-keys.md           F-KEY-001..008  (channel key epoch lifecycle)
│   ├── evidence-f-key-001-trace.md  code trace for the worst confirmed bug
│   ├── client-store-audit.md    F-STORE-001..019 (client store/hook races)
│   ├── client-store-perf.md     F-PERF-001 (O(n²) merge)
│   ├── coordinator-notes.md     F-COORD-* + full 8-pass review log
│   ├── crypto-agility-future-threats.md  F-E2E-*, F-PQC-* (HNDL/FS/metadata)
│   ├── nation-state-supply-chain.md      F-NET/F-SUPPLY/F-TRUST/F-CONTAIN/F-MOBILE
│   ├── dependency-vulns.md      F-DEP-* (= F-COORD-001) advisories + remediation
│   ├── display-name-unicode.md  F-INPUT-001 (Unicode/bidi spoofing)
│   ├── crypto-hardening-roadmap.md      prior PQC roadmap (superseded)
│   └── pqc-migration-design.md  selected-algorithm hybrid design + browser trust layer
├── var/ledger.sqlite3           Quus verified ledger (hash-chained events, artifact sha256s)
└── {audit,lint,oxlint,secretlint,test,typecheck}.log   verification command outputs
```

## For the internal team

1. **Triage order**: `INDEX.md` → "Priority action queue" (top 9 are data-loss/one-line fixes), then "Design-level decisions" (need owner sign-off, not bug fixes).
2. **Owner column** suggests area: `server` `client` `crypto` `infra` `process`.
3. **Status**: `Confirmed` = code-verified · `Candidate` = needs runtime confirmation · `Design`/`Rec` = architectural.
4. **PQC work**: `pqc-migration-design.md` — algorithm choices already folded in; open questions in the "未決定事項" section.
5. **Ledger**: read-only integrity record. Verify with `quus get_status` — `valid:true`, events hash-chained; artifact sha256s match current file contents.

## Conventions

- No secrets/keys/dumps stored here — only findings and hashes.
- Production source was never modified; this directory is evidence-only.
