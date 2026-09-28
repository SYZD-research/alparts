# Dependency vulnerability findings — pnpm audit (2026-09-23)

`pnpm audit` exits 1 with 4 moderate advisories, 0 high/critical. CI gate is
`pnpm audit --prod --audit-level high` so these do NOT fail CI, but all four are
real CVE-class issues that deserve fixes.

## F-DEP-001: qs 6.15.3 — two moderate DoS/parser issues via express query parsing

- Paths: `packages/server>express>qs`, `packages/server>express>body-parser>qs`
- Severity: Moderate | Status: Confirmed present; reachable
- Advisories:
  - GHSA-x5fp-wj9c-mxmx — array-limit bypass via bracket-key comma parsing
    (CWE-770), fixed in 6.15.4. Attacker-controlled query strings reach qs via
    Express `req.query` parsing. Bounded by the 512kb body limit only for bodies
    — query strings are not size-limited by express.json, though Express/Node
    cap header+URL size (~16kb default). Still allows array-limit bypass within
    that budget.
  - GHSA-4mjr-xmp4-gh2g — DoS via attacker-controlled isBuffer (CWE-248/703),
    fixed in 6.16.0.
- Reachability: HIGH relative to the others — every GET/HEAD with a query
  string exercises `qs.parse`. The app itself uses few query params, but
  Express parses the query string on every request regardless.
- Remediation: `pnpm up qs@6.16.0` or an override forcing `qs>=6.16.0` for
  express/body-parser. No code change needed.

## F-DEP-002: decode-uri-component 0.2.2 — exponential decode DoS via minio>query-string

- Path: `packages/server>minio>query-string>decode-uri-component`
- Severity: Moderate (environment-dependent) | Status: Confirmed present;
  reachability conditional
- Advisory: GHSA-vcc3-ghjq-m6fr — malformed percent-encoded input causes
  exponential-time decoding (CWE-400/405/407/1176), fixed in 0.4.3.
- Reachability: the vulnerable decode path runs when query-string parses URIs
  inside the MinIO SDK (redirect/response URL handling), i.e. only reachable
  from a hostile or compromised object-storage endpoint — which Alparts's own
  object-storage layer already treats as untrusted (bounded listings, strict
  key regex, deadlines). Consistent with that threat model, this should be
  fixed.
- Remediation: override `decode-uri-component>=0.4.3`, or upgrade `minio` to a
  release that dropped query-string / bumped it.

## F-DEP-003: stream-json 1.9.1 — O(depth²) event-loop DoS via minio

- Path: `packages/server>minio>stream-json`
- Severity: Moderate (environment-dependent) | Status: Confirmed present;
  reachability conditional
- Advisory: GHSA-528h-pc64-c93x — pick/ignore/filter/replace are O(depth²) on
  nested input; a small crafted JSON blocks the event loop for seconds to
  minutes, fixed in 3.4.1.
- Reachability: stream-json is exercised when minio parses streaming
  responses. A hostile MinIO endpoint could send deeply nested JSON and block
  the Node event loop — and importantly, the existing request-deadline/gate
  machinery cannot preempt synchronous CPU burn once the parser is running,
  so this defeats the bounded-I/O defense layer's intent for that window.
- Remediation: upgrade `minio` to a version using stream-json ≥3.4.1, or pnpm
  override `stream-json>=3.4.1` (major-version jump 1.x→3.x — verify minio
  compatibility in a staging run before pinning).

## Notes

- No supply-chain red flags found in the manifest: all runtime deps are pinned
  in pnpm-lock.yaml; Docker base images and CI actions are digest-pinned.
- `pnpm audit --prod --audit-level high` passes today only because all four are
  moderate — consider whether CI should gate on moderate for this threat model.

## Re-verification (deep-pass, nation-state review)

`pnpm audit --prod` and full `pnpm audit` re-run: still exactly 4 moderate
advisories, 0 high/critical. No additional dev-dependency advisories exist.
Installed: express 5.2.1, minio 8.0.7, qs 6.15.3, decode-uri-component 0.2.2,
stream-json 1.9.1.

Additional reachability detail:
- qs: `req.query` is consumed in 6 routes but ALWAYS through zod schemas that
  accept only flat string params (cursor/limit/id). The app uses no extended
  bracket syntax. Therefore `app.set('query parser', 'simple')` switches Express
  to Node's built-in `querystring` and removes qs from the request path
  entirely — cleanest fix, no dependency bump required. An `overrides` entry
  `qs>=6.16.0` is still recommended as defense-in-depth.
- decode-uri-component / stream-json: reachable only from the MinIO SDK's own
  response/URL parsing — requires a hostile or compromised object-storage
  endpoint. Note that the bounded-I/O gate cannot preempt synchronous CPU burn
  once stream-json parses, so a compromised MinIO can stall the event loop
  despite deadlines — consistent with treating object storage as semi-trusted.
- Dependabot configured weekly (npm + github-actions + docker) — update
  pipeline exists; transitive deps need `overrides`, which is why these persist.
- CI gates at `--audit-level high` — for this threat model consider
  `--audit-level moderate` so F-DEP-class advisories fail the build.
