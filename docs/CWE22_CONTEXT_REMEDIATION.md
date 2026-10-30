# CWE-22 developer-context remediation — design and security boundaries

A scan may return \`needs_context\` when the allowed file root is unknown. A
developer can now enter a relative application/project directory (e.g.
\`uploads/\`) in the dashboard. Raksa uses an authenticated endpoint to obtain
one new **unverified** Nemotron patch preview against the original pinned Git
commit. The preview does **not** alter the scan, repository or PR eligibility.

## Request

\`\`\`http
POST /api/scans/{scan_id}/context-remediation
Content-Type: application/json

{"finding_id": "<original CWE-22 finding id>", "authorized_root": "uploads/"}
\`\`\`

The request must have an authenticated workspace, the matching GitHub
installation, a completed scan with a pinned \`base_sha\`, and an actual
OpenGrep CWE-22 finding that returned \`AI needs context\`. The root is a
bounded relative POSIX application directory, not a host path. Raksa rejects
absolute directories, \`.\` or \`..\` components, backslashes, control
characters and ambiguous directory notation. This validation concerns the
developer **policy value**; the patched application must independently
validate every **untrusted incoming filename**.

The returned candidate, if one exists, passes exact-context and Python
syntax/import validation. These generic checks are **not CWE-22 security
verification**. The response unconditionally has
\`verification.status="unverified"\` and \`eligible_for_pr=false\`.

## A reference containment design for the demo

The demo's source is \`src/unsafe_path.py\`; therefore the repository's
\`uploads/\` root would be one directory above \`src/\`. The following
**illustrative** Linux-only implementation assumes **flat filenames only**
(no nested directories) and a trusted, non-attacker-writable parent directory
for \`uploads/\`. It is not deployed, executed or inserted into the intentionally
unsafe demo repository.

\`\`\`python
import os
import stat
from pathlib import Path

from flask import abort, request

UPLOADS = Path(__file__).resolve().parents[1] / "uploads"

def read_user_selected_file() -> str:
    name = request.args.get("filename", "")
    # Reject absolute names, path separators, dot components and empty names.
    if (
        not name
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or "\x00" in name
        or Path(name).is_absolute()
    ):
        abort(400)

    # Open relative to a trusted directory descriptor. O_NOFOLLOW blocks
    # a symlink at the final path component; flat names block traversal.
    root_fd = os.open(UPLOADS, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=root_fd,
        )
    finally:
        os.close(root_fd)

    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            abort(400)
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            return handle.read()
    finally:
        if fd >= 0:
            os.close(fd)
\`\`\`

This file-descriptor approach addresses symlink replacement races more
robustly than a check-then-open based solely on \`Path.resolve()\` and
\`is_relative_to()\`. It is Linux-specific and makes a narrower flat-file
product assumption, which must be reviewed by the developer. A production
patch must not silently assume those requirements for another app.

## Security verification work still needed

Before a CWE-22 candidate can be reported as verified, an isolated
category-specific gate should exercise **both baseline and patched code**,
against a temporary fixture repository and fixture files (never execute the
intentionally vulnerable static scan demo). Required checks include:

- A legitimate file directly inside \`uploads/\` can be read successfully.
- \`../secret\`, absolute filenames and nested parent-traversal are rejected.
- A symlink under \`uploads/\` targeting a file outside it cannot be read.
- Dot segments, malformed filenames and special files are rejected.
- File-symlink replacement races must not expose data outside the allowed root.
- Appropriate application errors and expected successful behaviors are tested.

These tests have **not** been added to the current verifier. Until they pass
for a real candidate, Raksa must not mark that candidate \`VERIFIED\` or allow
automated PR creation.
