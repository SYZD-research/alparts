# Workflow Preferences

## Project Structure
- Expects full monorepo setup when building multi-package applications (shared types, server, client). Confidence: 0.7
- Values TypeScript type checking as a build verification step before considering implementation complete. Confidence: 0.7

## Task Management
- Prefers implementation to be broken into numbered steps with clear progression tracking. Confidence: 0.7
- Expects a todo list to be maintained and updated throughout the implementation process. Confidence: 0.65

## Debugging & Error Handling
- Reports errors with minimal context (just the error message/symptom) and expects the assistant to autonomously investigate the root cause, check infrastructure (Docker, DB, ports), and fix without asking for more details. Confidence: 0.85
- Prefers the assistant to proactively run typecheck and verify API endpoints after fixes rather than asking the user to test. Confidence: 0.8
