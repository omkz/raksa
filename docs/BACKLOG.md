# Raksa — MVP Backlog

## Phase 1 — Foundation
- [x] React + TypeScript frontend and FastAPI backend
- [x] Environment/configuration scaffolding
- [x] Health endpoint and tests

## Phase 2 — Demo security flow
- [x] SQL-injection detection heuristic for Python code
- [x] Deterministic SQLite before/after proof harness
- [x] Example vulnerable app and tests

## Phase 3 — Providers
- [x] Nebius Token Factory model adapter
- [x] Tavily security research adapter
- [x] Sandbox adapter interface with demo, Docker, and Nebius providers

## Phase 4 — GitHub workflow
- [x] GitHub App installation flow
- [x] Installation-scoped repository listing and source snapshot
- [x] Branch + PR creation after explicit approval
- [x] Stale-default-branch guard

## Phase 5 — UI
- [x] Connect GitHub and select repository
- [x] Run demo or scan a repository
- [x] Display findings and proposed patch
- [x] Explicit Create PR action

## Follow-up before production
- [ ] End-to-end test against a dedicated GitHub demo repository
- [ ] Verify Nebius Sandbox payload/permissions against the account's enabled beta API
- [ ] Add durable job storage, user authentication, rate limits, and audit logs
- [ ] Expand beyond SQL injection after the end-to-end workflow is reliable
