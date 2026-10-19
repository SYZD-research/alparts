# Security Policy

**English** | [日本語](SECURITY.ja.md)

## Supported Versions

Alparts is in active development and does not publish stable releases yet.
Security fixes are provided for the latest commit on the `master` branch only.
Self-hosted instances should update to the latest commit (or apply the fix
commit referenced in the advisory).

| Version           | Supported |
| ----------------- | --------- |
| `master` (latest) | Yes       |
| Older commits     | No        |

## Reporting a Vulnerability

**Preferred — GitHub Private Vulnerability Reporting:**
https://github.com/SYZD-research/alparts/security/advisories/new
Opens a private draft advisory visible only to you and the maintainers, so we
can discuss the fix, request a CVE ID, and publish the advisory in one place.

**Alternative — email:** security@syzd.jp
Please include "Alparts" in the subject line. Reports in English or Japanese
are both welcome.

Please include:

- Description of the vulnerability and its impact
- Affected component(s): server, web client, desktop app, Android app, or the
  cryptographic protocol
- Steps to reproduce / proof of concept
- The commit hash or deployment you tested against

Please do **not**:

- Open public issues or pull requests for security reports
- Test against instances you do not own or operate (Alparts is self-hosted —
  run your own instance per the README)
- Access, modify, or destroy data belonging to other users

## Response Targets

The following are goals, not guarantees. The project is run by a small team,
and the initial acknowledgement in particular may take longer.

- Acknowledgement: we aim for 3 business days (not guaranteed — if you
  receive no response, please re-send your report to security@syzd.jp)
- Triage and severity assessment: we aim for 14 days
- Fix and coordinated disclosure: we target 90 days by default, adjustable
  by mutual agreement depending on complexity

Confirmed issues are published as GitHub Security Advisories with a CVE ID
requested through GitHub. Reporters are credited in the advisory unless they
prefer to remain anonymous.

## Scope

In scope:

- Alparts server (API, authentication/authorization, invitation and
  verification flows, audit log)
- Web, desktop, and Android clients
- End-to-end encryption implementation (key management, device
  approval/verification, history restore, attachment encryption)
- Voice call signaling as implemented by Alparts

Out of scope / generally not accepted:

- Dependency vulnerabilities without a demonstrated exploit path in Alparts
  (Dependabot already tracks known CVEs in dependencies)
- Operator-side misconfiguration: reverse proxy, HTTPS termination, SMTP,
  object storage, operator-provided STUN/TURN servers
- Attacks requiring a compromised server, a compromised client device, or
  physical access to an unlocked device
- Social engineering, phishing, spam
- Denial of service via volumetric or resource-exhaustion attacks
- Missing best practices (security headers, etc.) without demonstrated impact
- Self-XSS or issues requiring unrealistic user interaction

## Safe Harbor

We consider good-faith security research consistent with this policy to be
authorized. We will not pursue legal action against researchers who follow
this policy, and we ask for a reasonable window to address confirmed issues
before public disclosure.
