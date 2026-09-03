# Workflow Preferences

## Project Structure
- Expects full monorepo setup when building multi-package applications (shared types, server, client). Confidence: 0.7
- Values TypeScript type checking as a build verification step before considering implementation complete. Confidence: 0.7
- Development environment is WSL2 with Tailscale as the remote-access layer (the Windows host runs its own separate Tailscale node); connectivity/reachability questions should be answered by inspecting the actual environment (bind hosts, listeners, Tailscale status) and must account for WSL networking semantics — a 127.0.0.1 bind inside WSL is not reachable from Windows or the Tailnet without changing the bind host or configuring Tailscale Serve. Dev servers are accessed from the Tailnet via the MagicDNS hostname (e.g. citrus.taila87037.ts.net), so Vite's `server.allowedHosts` must include that hostname or requests are rejected. Confidence: 0.7

## Project Cleanup & Organization
- Prefers a tidy, de-cluttered directory (notably the repo root); expects redundant/non-source files (e.g. wrapper scripts, one-line stub scripts duplicated elsewhere) to be identified and removed. Confidence: 0.75
- When reorganizing markdown documentation, prefers to reduce the repo root to only essential top-level files (e.g. README.md, AGENTS.md) and consolidate all other docs into `docs/` (creating a subdirectory such as `docs/policies/` when there is a name conflict) via `git mv` to preserve history; explicitly requires that relative cross-links be preserved, i.e. rewritten so the move breaks nothing (verify with a repo-wide markdown-link check). Confidence: 0.9
- When reorganizing or cleaning up, prioritizing not breaking anything: before deleting/moving, checks all references (package.json, CI workflows, docs markdown links, `cd $(dirname $0)` relative-path scripts, docker/compose files, git tracking) and leaves intentionally-referenced root files in place (e.g. root .md docs a docs/INDEX links via `../`). Confidence: 0.75
- Refuses to touch directories containing source code (e.g. `packages/`) during cleanup; scope is limited to stray/config/orphan files. Confidence: 0.7
- After any file removal/reorganization, re-runs the same checks CI runs (shell `bash -n` syntax checks, `git diff --check`) to confirm nothing broke. Confidence: 0.7

## Task Management
- Prefers implementation to be broken into numbered steps with clear progression tracking. Confidence: 0.7
- Expects a todo list to be maintained and updated throughout the implementation process. Confidence: 0.65

## Debugging & Error Handling
- Reports errors with minimal context (just the error message/symptom) and expects the assistant to autonomously investigate the root cause, check infrastructure (Docker, DB, ports), and fix without asking for more details. Confidence: 0.85
- Prefers the assistant to proactively run typecheck and verify API endpoints after fixes rather than asking the user to test. Confidence: 0.8
- During DB/infra debugging, work non-destructively: verify against an ephemeral scratch resource (e.g. a fresh database in the same container) rather than mutating live data, mask secrets when inspecting .env, and clean up all temporary scripts, scratch resources, and background processes when done. Confidence: 0.65
