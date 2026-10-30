"""Fail-closed CWE-22 candidate checks; never execute static vulnerable fixtures.

The scanner's source-match result is insufficient to assert remediation.
Verification of behavior must run in a dedicated, isolated sandbox with
a trusted category-specific harness. This module reports those boundaries
explicitly instead of upgrading an AI proposal to VERIFIED.
"""

import ast
from typing import Any

from app.services.analyzer import validate_patched_python


def assess_cwe22_candidate(
    *, path: str, original: str, patched: str, authorized_root: str
) -> dict[str, Any]:
    """Return explicit static/behavioral evidence status, without executing code."""
    syntax_error = validate_patched_python(path, original, patched)
    if syntax_error:
        return {
            "status": "failed",
            "eligible_for_pr": False,
            "static_recheck": {
                "status": "failed", "passed": False, "message": syntax_error,
            },
            "security_exploit": {
                "status": "not_run", "passed": False,
                "message": "CWE-22 exploit tests were not run.",
            },
            "regression_tests": {
                "status": "not_run", "passed": False,
                "message": "Normal file reads were not tested.",
            },
            "message": "CWE-22 candidate has invalid Python syntax/imports.",
        }

    # Static inspection is never sufficient to prove dataflow constraints.
    try:
        tree = ast.parse(patched, filename=path)
    except SyntaxError:
        # Already handled by validate_patched_python.
        return {
            "status": "failed", "eligible_for_pr": False,
            "message": "CWE-22 candidate is not valid Python.",
        }

    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    open_calls = sum(
        isinstance(n.func, ast.Name) and n.func.id == "open"
        or isinstance(n.func, ast.Attribute) and n.func.attr == "open"
        for n in calls
    )
    fixture = "STATIC SCAN FIXTURE ONLY" in original or (
        "intentionally unsafe; never execute or deploy" in original
    )
    return {
        "status": "unverified",
        "eligible_for_pr": False,
        "static_recheck": {
            "status": "unverified", "passed": False,
            "message": (
                "Candidate parses; CWE-22 containment remains unproven "
                "without sandbox behavioral tests."
            ),
            "details": {
                "source_open_call_count": open_calls,
                "allowed_root": authorized_root,
                "note": "Open call counts are informational, not a security verdict.",
            },
        },
        "security_exploit": {
            "status": "not_run", "passed": False,
            "message": (
                "A trusted isolated test harness must demonstrate that traversal, "
                "absolute paths, and symlink escapes cannot read out-of-root data."
            ),
        },
        "regression_tests": {
            "status": "not_run", "passed": False,
            "message": "Normal in-root file reads must pass independently in sandbox.",
        },
        "message": (
            "CWE-22 candidate passes Python parseability checks only. "
            + (
                "The intentionally unsafe static demo fixture must not be executed. "
                if fixture else
                "A category-specific sandbox differential harness is required. "
            )
            + "Security verification is not completed; PR creation stays disabled."
        ),
    }
