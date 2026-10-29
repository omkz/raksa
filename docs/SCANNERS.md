# Scanner Platform v1 — OpenGrep

Raksa's first optional adapter executes OpenGrep in a dedicated Docker container
using five **original Raksa rules** (Python shell invocation, JavaScript/TypeScript
dynamic evaluation, DOM HTML sinks, and direct request-parameter file access in
Python and JavaScript). These are *potential* findings, not exploit proofs.

## Installation

On a Linux/amd64 host with Docker installed:

```sh
docker build -f ops/Dockerfile.opengrep -t raksa-opengrep:v1.30.0 .
# Configure the scan worker environment:
OPENGREP_ENABLED=true
OPENGREP_IMAGE=raksa-opengrep:v1.30.0
```

The Dockerfile downloads the official v1.30.0 linux-x86 asset and verifies the
SHA256 published on GitHub releases. The backend uses a fixed command, Docker
network isolation, readonly workspace and filesystem, unprivileged UID, and
limits for CPU, memory, processes, and runtime. For production, use a dedicated
scanner worker with restricted Docker daemon access, pin the resulting image
digest, and independently review image/dependency provenance.

The scanner image unpacks its executable and launches a child process inside
container `/tmp` at startup. Raksa provides a **512 MiB tmpfs** with explicit
`exec,nosuid,nodev` options. The previous 64 MiB limit caused
`No space left on device`; the default `noexec` behavior then caused
`couldn't launch child (exec): Permission denied`. Enabling `exec` permits
execution from this temporary mount; all analyzed repository content remains
read-only and the container has no network access. The tmpfs is memory-backed
and remains subject to the container's **768 MiB memory cap**.
If a scan still fails due to resource pressure, inspect the worker's Docker
stderr and available memory; do not disable network isolation or other sandbox
restrictions to work around it.

OpenGrep is opt-in; no hidden rule registry or internet download is performed
at scanning time. Missing Docker/image or malformed output yields an explicit
scanner error, not an assertion that the repository is safe.

## Constraints

- **Current input is the bounded GitHub API text snapshot**, not complete clone.
  Git history, skipped files, or files above snapshot limits are not scanned.
- Python SQL injection findings from Raksa's existing AST analyzer retain their
  specialist differential exploit/regression verification gate.
- OpenGrep findings can now receive **AI patch proposals** (requires Nemotron)
  with exact source-context validation. These are **not verified** by the current
  SQLi-only gate. Any scan with an accepted OpenGrep patch is **unverified**
  and **ineligible for draft PR creation**, even when a SQLi patch is also present.
- XSS and Path Traversal rules are deliberately high-signal **sink patterns**,
  not complete taint-flow analysis. They cover browser DOM sinks and direct
  request-parameter file reads in selected Python/JS frameworks, but many
  frameworks, indirect flows, and sanitization cases are not covered.
  False positives are possible.
- Rule coverage is minimal. This release does not deliver a comprehensive SAST
  ruleset or full multilang security review.
- OpenGrep engine uses LGPL-2.1. The bundled rules are authored by Raksa; no
  official Semgrep-managed rules are redistributed.

Next adapters (OSV-Scanner, Betterleaks/Gitleaks, Checkov) will use the same
contract after a full isolated checkout and category-specific workflows exist.
