# Draft PR workflow audit — 2026-10-30

## Confirmed defects and changes

- The original handler used `ScanJob.source_files`, which does not exist. The existing fix correctly reloads bounded source at `base_sha`, applies exact replacements, and publishes only the approved review subset. No migration is necessary. PostgreSQL/HTTP integration now covers the actual serialized job without that field.
- GitHub branch creation precedes PR creation. A failed PR request leaves the deterministic branch behind; the old retry always failed with HTTP 422. Retries now compare its complete tree and sole parent against the reconstructed patch and pinned commit, without overwriting it. An existing open Draft PR is reused; closed, ready, or retargeted PRs are rejected.
- Snapshot errors hid GitHub permission failures, and transport errors escaped as internal errors. Error handling now explains installation access, Contents/Pull requests write permissions, permission approval, rate limits, authentication, and unavailable repositories/commits. Raw remote response bodies are not exposed.
- Snapshot loading treated symlink blobs as source. It now accepts only regular file modes. Publication independently validates paths against the pinned tree and preserves executable modes.
- Pinned snapshot verification previously returned the requested SHA without comparing it with the commit response. It now checks the response SHA. Publication also rechecks the default branch name and SHA before branch creation and before PR creation.
- Review publication now additionally excludes persisted rejected/blocked/context outcomes, even if their IDs occur in the eligibility list. CWE-22/78/94 remain excluded by the existing category allowlist; aggregate changed files are never published for review-only requests.
- PR audit events now carry the scan workspace. React labels review-only PR body text UNVERIFIED instead of presenting it as verification evidence.

## Validation

The integration suite uses the local PostgreSQL test database, FastAPI ASGI requests, and the real GitHub service with `httpx.MockTransport`. It covers persistence, approved file selection, repeated requests, partial failure/retry, stale base before/during publication, pinned SHA mismatch, changed review branch, permissions, symlinks, executable modes, consent, workspace/installation authorization, rejected outcomes, source mismatch, and an existing non-Draft PR.

Run sequentially because tests share and clear the same test database:

```sh
uv run --directory apps/api pytest -q --disable-warnings
uv run --directory apps/api ruff check .
pnpm --dir apps/web build
```

## Limits and operational requirements

- No live remediation PR was created, and live Raksa App installation permissions have not been confirmed. PR #8 was inspected as open and Draft and was not modified, merged, or deployed.
- No code from `omkz/raksa-vulnerable-demo` was fetched or executed during this audit. The added fixtures are inert strings.
- Passing these tests validates orchestration, not AI remediation correctness. Candidate filters and source checks are static heuristics, not security proof; review PRs remain UNVERIFIED.
- GitHub offers no transaction spanning base checks, ref creation, and PR creation. A branch can advance after the last check. Human review and security/regression tests remain required. Concurrent requests may receive a recoverable 422; retry reconciles the existing PR. Failed attempts can leave a validated review branch or unreachable Git objects; no destructive cleanup occurs.
- Snapshot reconstruction still obeys current size/count limits. If limits change or a pinned object becomes unavailable, publication fails closed and may require a fresh scan.

## API references checked through Context7

- [Git tree base object and file modes](https://docs.github.com/en/rest/git/trees)
- [GitHub App permission failures](https://docs.github.com/en/rest/using-the-rest-api/troubleshooting-the-rest-api)
