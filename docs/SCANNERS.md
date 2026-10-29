# Scanner Platform v1 — OpenGrep

Raksa's first optional adapter executes OpenGrep in a dedicated Docker container
using two **original Raksa rules** (Python shell invocation, JavaScript/TypeScript
dynamic evaluation). Both are *potential* findings, not exploit proofs.

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

OpenGrep is opt-in; no hidden rule registry or internet download is performed
at scanning time. Missing Docker/image or malformed output yields an explicit
scanner error, not an assertion that the repository is safe.

## Constraints

- **Current input is the bounded GitHub API text snapshot**, not complete clone.
  Git history, skipped files, or files above snapshot limits are not scanned.
- Only Python SQL injection findings from Raksa's existing AST analyzer are
  currently eligible for AI patch generation and exploit/regression verification.
- New OpenGrep findings are reported and stored but are **not auto-remediated**;
  the existing verification gate is unchanged.
- Rule coverage is minimal. This release does not deliver a comprehensive SAST
  ruleset or full multilang security review.
- OpenGrep engine uses LGPL-2.1. The bundled rules are authored by Raksa; no
  official Semgrep-managed rules are redistributed.

Next adapters (OSV-Scanner, Betterleaks/Gitleaks, Checkov) will use the same
contract after a full isolated checkout and category-specific workflows exist.
