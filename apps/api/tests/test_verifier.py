from typing import Any

import pytest

from app.services.sandbox import SandboxError
from app.services.verifier import (
    VerificationCheck,
    classify_test_result,
    evaluate_verification_gate,
    find_existing_security_test,
    is_security_assertion_failure,
    run_static_recheck,
    validate_security_exploit_test,
    verify_remediation,
)

VULNERABLE_SOURCE = """def search(connection, name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return connection.execute(query).fetchall()
"""

FIXED_SOURCE = """def search(connection, name):
    query = "SELECT * FROM users WHERE name = ?"
    return connection.execute(query, (name,)).fetchall()
"""

REGRESSION_TEST_CONTENT = """import unittest
class MathTests(unittest.TestCase):
    def test_add(self):
        self.assertEqual(1 + 1, 2)
"""

EXPLOIT_TEST_CONTENT = """import unittest
from app import search

class SQLiExploitTest(unittest.TestCase):
    def test_injection_blocked(self):
        conn = None
        payload = "' OR 1=1 --"
        rows = search(conn, payload)
        self.assertEqual(len(rows), 0, "SQL injection payload returned unintended rows")
"""


class DummySandbox:
    def __init__(
        self,
        responses: dict[str, Any] | None = None,
        error: Exception | None = None,
        errors: dict[str, Exception] | None = None,
        provider: str = "docker",
    ):
        self.responses = responses or {}
        self.error = error
        self.errors = errors or {}
        self.provider = provider
        self.calls: list[dict[str, Any]] = []

    async def run_tests(
        self,
        files: dict[str, str],
        *,
        timeout_seconds: int | None = None,
        test_pattern: str | None = None,
    ) -> dict[str, Any]:
        self.calls.append({"files": files, "pattern": test_pattern})
        if self.error:
            raise self.error

        phase = "before" if files.get("app.py") == VULNERABLE_SOURCE else "after"

        if test_pattern and f"{test_pattern}:{phase}" in self.errors:
            raise self.errors[f"{test_pattern}:{phase}"]
        if phase in self.errors:
            raise self.errors[phase]

        if test_pattern and f"{test_pattern}:{phase}" in self.responses:
            return self.responses[f"{test_pattern}:{phase}"]
        if (test_pattern, phase) in self.responses:
            return self.responses[(test_pattern, phase)]
        if test_pattern and test_pattern in self.responses:
            resp = self.responses[test_pattern]
            if isinstance(resp, list):
                return resp.pop(0) if resp else self.responses.get("default", {})
            return resp
        if phase in self.responses:
            return self.responses[phase]
        if "default" in self.responses:
            return self.responses["default"]
        return {
            "provider": "docker",
            "status": "passed",
            "exit_code": 0,
            "stdout": "Ran 2 tests in 0.01s\n\nOK\n",
            "stderr": "",
            "message": "Tests passed.",
        }


class DummyNebius:
    def __init__(self, exploit_test: dict[str, str] | None = None, configured: bool = True):
        self.configured = configured
        self._exploit_test = exploit_test

    async def generate_exploit_test(self, *, path: str, source: str, finding: dict[str, Any]) -> dict[str, str] | None:
        return self._exploit_test


@pytest.mark.asyncio
async def test_successful_verification() -> None:
    """When static recheck passes, exploit reproduces before and passes after, status is verified and PR is allowed."""
    files = {
        "app.py": VULNERABLE_SOURCE,
        "test_math.py": REGRESSION_TEST_CONTENT,
    }
    patched_files = {
        "app.py": FIXED_SOURCE,
        "test_math.py": REGRESSION_TEST_CONTENT,
    }
    findings = [{
        "id": "sqli-1",
        "title": "Potential SQL injection",
        "cwe": "CWE-89",
        "path": "app.py",
        "line": 2,
        "evidence": "SELECT * FROM users",
    }]

    sandbox = DummySandbox(responses={
        "test_raksa_exploit.py:before": {
            "provider": "docker",
            "status": "failed",
            "exit_code": 1,
            "stdout": "Ran 1 test in 0.01s\n\nFAILED (failures=1)\n",
            "stderr": "FAIL: test_injection_blocked (test_raksa_exploit.SQLiExploitTest)\nTraceback (most recent call last):\n  File \"test_raksa_exploit.py\", line 9, in test_injection_blocked\n    self.assertEqual(len(rows), 0, \"SQL injection payload returned unintended rows\")\nAssertionError: 3 != 0 : SQL injection payload returned unintended rows",
        },
        "test_raksa_exploit.py:after": {
            "provider": "docker",
            "status": "passed",
            "exit_code": 0,
            "stdout": "Ran 1 test in 0.01s\n\nOK\n",
            "stderr": "",
        },
        "default": {
            "provider": "docker",
            "status": "passed",
            "exit_code": 0,
            "stdout": "Ran 1 test in 0.01s\n\nOK\n",
            "stderr": "",
        },
    })
    nebius = DummyNebius(exploit_test={
        "path": "test_raksa_exploit.py",
        "content": EXPLOIT_TEST_CONTENT,
        "reason": "Test parameterized query against payload",
    })

    result = await verify_remediation(files, patched_files, findings, sandbox, nebius)

    assert result.status == "verified"
    assert result.eligible_for_pr is True
    assert result.static_recheck.passed is True
    assert result.static_recheck.status == "passed"
    assert result.security_exploit.passed is True
    assert result.security_exploit.status == "passed"
    assert result.regression_tests.passed is True
    assert result.regression_tests.status == "passed"
    assert result.before is not None and result.before["exploit_reproduced"] is True
    assert result.after is not None and result.after["exploit_blocked"] is True


@pytest.mark.asyncio
async def test_failed_exploit_verification() -> None:
    """When security exploit test fails against patched code, remediation is marked failed and PR is disallowed."""
    files = {
        "app.py": VULNERABLE_SOURCE,
        "test_math.py": REGRESSION_TEST_CONTENT,
    }
    patched_files = {
        "app.py": FIXED_SOURCE,
        "test_math.py": REGRESSION_TEST_CONTENT,
    }
    findings = [{"id": "sqli-1", "path": "app.py", "line": 2}]

    sandbox = DummySandbox(responses={
        "test_raksa_exploit.py:before": {
            "provider": "docker",
            "status": "failed",
            "exit_code": 1,
            "stdout": "Ran 1 test in 0.01s\n\nFAILED (failures=1)\n",
            "stderr": "FAIL: test_injection_blocked (test_raksa_exploit.SQLiExploitTest)\nTraceback (most recent call last):\n  File \"test_raksa_exploit.py\", line 9, in test_injection_blocked\n    self.assertEqual(len(rows), 0, \"SQL injection payload returned unintended rows\")\nAssertionError: 3 != 0 : SQL injection payload returned unintended rows",
        },
        "test_raksa_exploit.py:after": {
            "provider": "docker",
            "status": "failed",
            "exit_code": 1,
            "stdout": "Ran 1 test in 0.01s\n\nFAILED (failures=1)\n",
            "stderr": "FAIL: test_injection_blocked (test_raksa_exploit.SQLiExploitTest)\nTraceback (most recent call last):\n  File \"test_raksa_exploit.py\", line 9, in test_injection_blocked\n    self.assertEqual(len(rows), 0, \"SQL injection payload returned unintended rows\")\nAssertionError: 3 != 0 : Exploit was not blocked",
        },
        "default": {
            "provider": "docker",
            "status": "passed",
            "exit_code": 0,
            "stdout": "Ran 1 test in 0.01s\n\nOK\n",
            "stderr": "",
        },
    })
    nebius = DummyNebius(exploit_test={
        "path": "test_raksa_exploit.py",
        "content": EXPLOIT_TEST_CONTENT,
        "reason": "Test parameterized query",
    })

    result = await verify_remediation(files, patched_files, findings, sandbox, nebius)

    assert result.status == "failed"
    assert result.eligible_for_pr is False
    assert result.security_exploit.passed is False
    assert result.security_exploit.status == "failed"
    assert "security exploit test failed" in result.message.lower()


@pytest.mark.asyncio
async def test_failed_regression_tests() -> None:
    """When preexisting regression tests break after applying patch, status is failed and PR is disallowed."""
    files = {
        "app.py": VULNERABLE_SOURCE,
        "test_math.py": REGRESSION_TEST_CONTENT,
    }
    patched_files = {
        "app.py": FIXED_SOURCE,
        "test_math.py": REGRESSION_TEST_CONTENT,
    }
    findings = [{"id": "sqli-1", "path": "app.py", "line": 2}]

    sandbox = DummySandbox(responses={
        "test_raksa_exploit.py:before": {
            "provider": "docker",
            "status": "failed",
            "exit_code": 1,
            "stdout": "Ran 1 test in 0.01s\n\nFAILED (failures=1)\n",
            "stderr": "FAIL: test_injection_blocked (test_raksa_exploit.SQLiExploitTest)\nTraceback (most recent call last):\n  File \"test_raksa_exploit.py\", line 9, in test_injection_blocked\n    self.assertEqual(len(rows), 0, \"SQL injection payload returned unintended rows\")\nAssertionError: 3 != 0 : SQL injection payload returned unintended rows",
        },
        "test_raksa_exploit.py:after": {
            "provider": "docker",
            "status": "passed",
            "exit_code": 0,
            "stdout": "Ran 1 test in 0.01s\n\nOK\n",
            "stderr": "",
        },
        "default": {
            "provider": "docker",
            "status": "failed",
            "exit_code": 1,
            "stdout": "Ran 1 test in 0.01s\n\nFAILED (errors=1)\n",
            "stderr": "TypeError: regression introduced",
        },
    })
    nebius = DummyNebius(exploit_test={
        "path": "test_raksa_exploit.py",
        "content": EXPLOIT_TEST_CONTENT,
        "reason": "Test parameterized query",
    })

    result = await verify_remediation(files, patched_files, findings, sandbox, nebius)

    assert result.status == "failed"
    assert result.eligible_for_pr is False
    assert result.regression_tests.passed is False
    assert result.regression_tests.status == "failed"
    assert "regression tests broke" in result.message.lower()


@pytest.mark.asyncio
async def test_sandbox_errors_gate() -> None:
    """When sandbox raises SandboxError, verification returns error status and disables PR."""
    files = {
        "app.py": VULNERABLE_SOURCE,
        "test_math.py": REGRESSION_TEST_CONTENT,
    }
    patched_files = {
        "app.py": FIXED_SOURCE,
        "test_math.py": REGRESSION_TEST_CONTENT,
    }
    findings = [{"id": "sqli-1", "path": "app.py", "line": 2}]

    sandbox = DummySandbox(error=SandboxError("Docker daemon is unavailable"))
    nebius = DummyNebius(exploit_test={
        "path": "test_raksa_exploit.py",
        "content": EXPLOIT_TEST_CONTENT,
        "reason": "Test exploit",
    })

    result = await verify_remediation(files, patched_files, findings, sandbox, nebius)

    assert result.status == "error"
    assert result.eligible_for_pr is False
    assert "sandbox error" in result.message.lower()


@pytest.mark.asyncio
async def test_unavailable_security_tests_reports_unverified() -> None:
    """If the security exploit test cannot be generated or found, report unverified.

    Unrelated passing regression tests MUST NOT be treated as proof of fix.
    """
    files = {
        "app.py": VULNERABLE_SOURCE,
        "test_math.py": REGRESSION_TEST_CONTENT,
    }
    patched_files = {
        "app.py": FIXED_SOURCE,
        "test_math.py": REGRESSION_TEST_CONTENT,
    }
    findings = [{"id": "sqli-1", "path": "app.py", "line": 2}]

    sandbox = DummySandbox(responses={
        "default": {
            "provider": "docker",
            "status": "passed",
            "exit_code": 0,
            "stdout": "Ran 1 test in 0.01s\n\nOK\n",
            "stderr": "",
        }
    })
    nebius = DummyNebius(exploit_test=None, configured=False)

    result = await verify_remediation(files, patched_files, findings, sandbox, nebius)

    assert result.status == "unverified"
    assert result.eligible_for_pr is False
    assert result.security_exploit.status == "unavailable"
    assert result.security_exploit.passed is False
    assert result.regression_tests.passed is True
    assert "passing unrelated tests does not prove" in result.message.lower()


@pytest.mark.asyncio
async def test_differential_successful_verification() -> None:
    """Successful differential verification records proof and allows PR."""
    files = {
        "app.py": VULNERABLE_SOURCE,
        "test_math.py": REGRESSION_TEST_CONTENT,
    }
    patched_files = {
        "app.py": FIXED_SOURCE,
        "test_math.py": REGRESSION_TEST_CONTENT,
    }
    findings = [{"id": "sqli-1", "path": "app.py", "line": 2}]

    sandbox = DummySandbox(responses={
        "test_raksa_exploit.py:before": {
            "provider": "docker",
            "status": "failed",
            "exit_code": 1,
            "stdout": "Ran 1 test in 0.01s\n\nFAILED (failures=1)\n",
            "stderr": "FAIL: test_injection_blocked (test_raksa_exploit.SQLiExploitTest)\nTraceback (most recent call last):\n  File \"test_raksa_exploit.py\", line 9, in test_injection_blocked\n    self.assertEqual(len(rows), 0, \"SQL injection payload returned unintended rows\")\nAssertionError: 3 != 0 : SQL injection payload returned unintended rows",
        },
        "test_raksa_exploit.py:after": {
            "provider": "docker",
            "status": "passed",
            "exit_code": 0,
            "stdout": "Ran 1 test in 0.01s\n\nOK\n",
            "stderr": "",
        },
        "default": {
            "provider": "docker",
            "status": "passed",
            "exit_code": 0,
            "stdout": "Ran 1 test in 0.01s\n\nOK\n",
            "stderr": "",
        },
    })
    nebius = DummyNebius(exploit_test={
        "path": "test_raksa_exploit.py",
        "content": EXPLOIT_TEST_CONTENT,
        "reason": "Test injection blocked",
    })

    result = await verify_remediation(files, patched_files, findings, sandbox, nebius)

    assert result.status == "verified"
    assert result.eligible_for_pr is True
    assert result.before is not None
    assert result.before["exploit_reproduced"] is True
    assert result.before["outcome"] == "assertion_failure"
    assert result.after is not None
    assert result.after["exploit_blocked"] is True
    assert result.after["outcome"] == "passed"


@pytest.mark.asyncio
async def test_differential_original_test_unexpectedly_passing() -> None:
    """If the original test unexpectedly passes, vulnerability was not reproduced."""
    files = {
        "app.py": VULNERABLE_SOURCE,
        "test_math.py": REGRESSION_TEST_CONTENT,
    }
    patched_files = {
        "app.py": FIXED_SOURCE,
        "test_math.py": REGRESSION_TEST_CONTENT,
    }
    findings = [{"id": "sqli-1", "path": "app.py", "line": 2}]

    sandbox = DummySandbox(responses={
        "test_raksa_exploit.py:before": {
            "provider": "docker",
            "status": "passed",
            "exit_code": 0,
            "stdout": "Ran 1 test in 0.01s\n\nOK\n",
            "stderr": "",
        },
        "test_raksa_exploit.py:after": {
            "provider": "docker",
            "status": "passed",
            "exit_code": 0,
            "stdout": "Ran 1 test in 0.01s\n\nOK\n",
            "stderr": "",
        },
        "default": {
            "provider": "docker",
            "status": "passed",
            "exit_code": 0,
            "stdout": "Ran 1 test in 0.01s\n\nOK\n",
            "stderr": "",
        },
    })
    nebius = DummyNebius(exploit_test={
        "path": "test_raksa_exploit.py",
        "content": EXPLOIT_TEST_CONTENT,
        "reason": "Test exploit",
    })

    result = await verify_remediation(files, patched_files, findings, sandbox, nebius)

    assert result.status == "unverified"
    assert result.eligible_for_pr is False
    assert result.security_exploit.status == "unverified"
    assert result.security_exploit.passed is False
    assert result.before is not None and result.before["exploit_reproduced"] is False
    assert "unexpectedly passed" in result.message.lower() or "not reproduced" in result.message.lower()


@pytest.mark.asyncio
async def test_differential_patched_test_failing() -> None:
    """Patched test failing marks verification failed and prevents PR."""
    files = {
        "app.py": VULNERABLE_SOURCE,
        "test_math.py": REGRESSION_TEST_CONTENT,
    }
    patched_files = {
        "app.py": FIXED_SOURCE,
        "test_math.py": REGRESSION_TEST_CONTENT,
    }
    findings = [{"id": "sqli-1", "path": "app.py", "line": 2}]

    sandbox = DummySandbox(responses={
        "test_raksa_exploit.py:before": {
            "provider": "docker",
            "status": "failed",
            "exit_code": 1,
            "stdout": "Ran 1 test in 0.01s\n\nFAILED (failures=1)\n",
            "stderr": "FAIL: test_injection_blocked (test_raksa_exploit.SQLiExploitTest)\nTraceback (most recent call last):\n  File \"test_raksa_exploit.py\", line 9, in test_injection_blocked\n    self.assertEqual(len(rows), 0, \"SQL injection payload returned unintended rows\")\nAssertionError: 3 != 0 : SQL injection payload returned unintended rows",
        },
        "test_raksa_exploit.py:after": {
            "provider": "docker",
            "status": "failed",
            "exit_code": 1,
            "stdout": "Ran 1 test in 0.01s\n\nFAILED (failures=1)\n",
            "stderr": "FAIL: test_injection_blocked (test_raksa_exploit.SQLiExploitTest)\nTraceback (most recent call last):\n  File \"test_raksa_exploit.py\", line 9, in test_injection_blocked\n    self.assertEqual(len(rows), 0, \"SQL injection payload returned unintended rows\")\nAssertionError: 3 != 0 : Exploit was not blocked",
        },
        "default": {
            "provider": "docker",
            "status": "passed",
            "exit_code": 0,
            "stdout": "Ran 1 test in 0.01s\n\nOK\n",
            "stderr": "",
        },
    })
    nebius = DummyNebius(exploit_test={
        "path": "test_raksa_exploit.py",
        "content": EXPLOIT_TEST_CONTENT,
        "reason": "Test exploit",
    })

    result = await verify_remediation(files, patched_files, findings, sandbox, nebius)

    assert result.status == "failed"
    assert result.eligible_for_pr is False
    assert result.security_exploit.status == "failed"
    assert result.security_exploit.passed is False
    assert result.after is not None and result.after["exploit_blocked"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("stdout", "stderr", "status", "exit_code", "expected_description"),
    [
        (
            "Ran 1 test in 0.00s\n\nFAILED (errors=1)\n",
            "ERROR: test_raksa_exploit (unittest.loader._FailedTest)\nImportError: Failed to import test module\nModuleNotFoundError: No module named 'nonexistent'",
            "failed",
            1,
            "import error",
        ),
        (
            "Ran 1 test in 0.00s\n\nFAILED (errors=1)\n",
            "ERROR: test_raksa_exploit (unittest.loader._FailedTest)\nSyntaxError: invalid syntax",
            "failed",
            1,
            "syntax error",
        ),
        (
            "Ran 0 tests in 0.00s\n\nOK\n",
            "",
            "passed",
            0,
            "discovery error (0 tests)",
        ),
        (
            "",
            "Sandbox timeout reached.",
            "timeout",
            None,
            "timeout",
        ),
        (
            "Ran 1 test in 0.00s\n\nFAILED (errors=1)\n",
            "ERROR: test_exploit\nTypeError: 'NoneType' object is not callable",
            "failed",
            1,
            "unhandled runtime exception",
        ),
    ],
)
async def test_differential_assertion_versus_setup_errors(
    stdout: str,
    stderr: str,
    status: str,
    exit_code: int | None,
    expected_description: str,
) -> None:
    """Setup, import, discovery, timeouts, and unhandled errors must never count as proof of vulnerability."""
    files = {
        "app.py": VULNERABLE_SOURCE,
        "test_math.py": REGRESSION_TEST_CONTENT,
    }
    patched_files = {
        "app.py": FIXED_SOURCE,
        "test_math.py": REGRESSION_TEST_CONTENT,
    }
    findings = [{"id": "sqli-1", "path": "app.py", "line": 2}]

    sandbox = DummySandbox(responses={
        "test_raksa_exploit.py:before": {
            "provider": "docker",
            "status": status,
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
        },
        "default": {
            "provider": "docker",
            "status": "passed",
            "exit_code": 0,
            "stdout": "Ran 1 test in 0.01s\n\nOK\n",
            "stderr": "",
        },
    })
    nebius = DummyNebius(exploit_test={
        "path": "test_raksa_exploit.py",
        "content": EXPLOIT_TEST_CONTENT,
        "reason": "Test exploit",
    })

    result = await verify_remediation(files, patched_files, findings, sandbox, nebius)

    assert result.status == "unverified", f"Expected unverified for {expected_description}"
    assert result.eligible_for_pr is False
    assert result.security_exploit.passed is False
    assert result.security_exploit.status == "unverified"
    assert result.before is not None
    assert result.before["exploit_reproduced"] is False


@pytest.mark.asyncio
async def test_differential_sandbox_failures() -> None:
    """Sandbox errors during before or after execution return error and disable PR."""
    files = {
        "app.py": VULNERABLE_SOURCE,
        "test_math.py": REGRESSION_TEST_CONTENT,
    }
    patched_files = {
        "app.py": FIXED_SOURCE,
        "test_math.py": REGRESSION_TEST_CONTENT,
    }
    findings = [{"id": "sqli-1", "path": "app.py", "line": 2}]
    nebius = DummyNebius(exploit_test={
        "path": "test_raksa_exploit.py",
        "content": EXPLOIT_TEST_CONTENT,
        "reason": "Test exploit",
    })

    # Case 1: Sandbox error on original snapshot
    sandbox_before_err = DummySandbox(
        errors={"test_raksa_exploit.py:before": SandboxError("Docker daemon terminated")}
    )
    res_before = await verify_remediation(files, patched_files, findings, sandbox_before_err, nebius)
    assert res_before.status == "error"
    assert res_before.eligible_for_pr is False
    assert "sandbox error" in res_before.message.lower()

    # Case 2: Sandbox error on patched snapshot
    sandbox_after_err = DummySandbox(
        responses={
            "test_raksa_exploit.py:before": {
                "provider": "docker",
                "status": "failed",
                "exit_code": 1,
                "stdout": "Ran 1 test in 0.01s\n\nFAILED (failures=1)\n",
                "stderr": "FAIL: test_injection_blocked (test_raksa_exploit.SQLiExploitTest)\nTraceback (most recent call last):\n  File \"test_raksa_exploit.py\", line 9, in test_injection_blocked\n    self.assertEqual(len(rows), 0, \"SQL injection payload returned unintended rows\")\nAssertionError: 3 != 0 : SQL injection payload returned unintended rows",
            },
        },
        errors={"test_raksa_exploit.py:after": SandboxError("Container out of memory")},
    )
    res_after = await verify_remediation(files, patched_files, findings, sandbox_after_err, nebius)
    assert res_after.status == "error"
    assert res_after.eligible_for_pr is False
    assert "sandbox error" in res_after.message.lower()


# =========================================================================
# New tests: Strengthened Security Exploit Test Validation
# =========================================================================

TRIVIAL_ASSERT_TEST_1 = """import unittest
from app import search

class ExploitTest(unittest.TestCase):
    def test_exploit(self):
        payload = "' OR 1=1 --"
        search(None, payload)
        self.assertTrue(False)
"""

TRIVIAL_ASSERT_TEST_2 = """import unittest
from app import search

class ExploitTest(unittest.TestCase):
    def test_exploit(self):
        payload = "' OR 1=1 --"
        search(None, payload)
        self.assertEqual(1, 2)
"""

TRIVIAL_ASSERT_TEST_3 = """import unittest
from app import search

class ExploitTest(unittest.TestCase):
    def test_exploit(self):
        payload = "' OR 1=1 --"
        search(None, payload)
        assert False
"""

MISSING_PAYLOAD_TEST = """import unittest
from app import search

class ExploitTest(unittest.TestCase):
    def test_search_normal(self):
        rows = search(None, "alice")
        self.assertEqual(len(rows), 0, "Query returned no rows")
"""

UNRELATED_TARGET_TEST = """import unittest
from math_utils import add

class ExploitTest(unittest.TestCase):
    def test_add(self):
        payload = "' OR 1=1 --"
        res = add(1, 2)
        self.assertEqual(res, 3)
"""

UNRELATED_ASSERT_TEST = """import unittest
from app import search

class ExploitTest(unittest.TestCase):
    def test_exploit(self):
        env = "test_env"
        self.assertEqual(env, "prod", "Environment mismatch")
        payload = "' OR 1=1 --"
        rows = search(None, payload)
        self.assertEqual(len(rows), 0, "SQL injection payload returned unintended rows")
"""

UNUSED_PAYLOAD_TEST = """import unittest
from app import search

class ExploitTest(unittest.TestCase):
    def test_exploit(self):
        payload = "' OR 1=1 --"
        rows = search(None, "alice")
        self.assertEqual(len(rows), 0, "Query returned no rows")
"""

UNRELATED_FN_RESULT_TEST = """import unittest
from app import search

def check_health():
    return "ok"

class ExploitTest(unittest.TestCase):
    def test_exploit(self):
        payload = "' OR 1=1 --"
        rows = search(None, payload)
        status = check_health()
        self.assertEqual(status, "ok")
"""

DIRECT_UNRELATED_CALL_TEST = """import unittest
from app import search

def check_health():
    return "ok"

class ExploitTest(unittest.TestCase):
    def test_exploit(self):
        payload = "' OR 1=1 --"
        search(None, payload)
        self.assertEqual(check_health(), "ok")
"""

VALID_INLINE_PAYLOAD_TEST = """import unittest
from app import search

class ExploitTest(unittest.TestCase):
    def test_exploit(self):
        self.assertEqual(len(search(None, "' OR 1=1 --")), 0)
"""


def test_reject_trivial_assertions_static() -> None:
    """Trivial assertions like assertTrue(False) and assertEqual(1, 2) must be rejected."""
    finding = {"path": "app.py", "evidence": "def search(connection, name):"}

    valid_1, reason_1 = validate_security_exploit_test(TRIVIAL_ASSERT_TEST_1, finding=finding, target_path="app.py")
    assert valid_1 is False
    assert "trivial assertion" in reason_1.lower()

    valid_2, reason_2 = validate_security_exploit_test(TRIVIAL_ASSERT_TEST_2, finding=finding, target_path="app.py")
    assert valid_2 is False
    assert "trivial assertion" in reason_2.lower()

    valid_3, reason_3 = validate_security_exploit_test(TRIVIAL_ASSERT_TEST_3, finding=finding, target_path="app.py")
    assert valid_3 is False
    assert "trivial assertion" in reason_3.lower()


@pytest.mark.asyncio
async def test_reject_trivial_assertions_gate() -> None:
    """Tests with trivial assertions must be rejected by the verifier, returning unverified and disabling PR."""
    files = {"app.py": VULNERABLE_SOURCE}
    patched_files = {"app.py": FIXED_SOURCE}
    findings = [{"id": "sqli-1", "path": "app.py", "line": 2}]

    sandbox = DummySandbox()
    nebius = DummyNebius(exploit_test={
        "path": "test_raksa_exploit.py",
        "content": TRIVIAL_ASSERT_TEST_1,
        "reason": "Trivial test",
    })

    result = await verify_remediation(files, patched_files, findings, sandbox, nebius)
    assert result.status == "unverified"
    assert result.eligible_for_pr is False
    assert "rejected" in result.message.lower() or "rejected" in result.security_exploit.message.lower()


def test_reject_missing_payloads() -> None:
    """Tests without a recognized SQL injection payload must be rejected."""
    finding = {"path": "app.py", "evidence": "def search(connection, name):"}
    is_valid, reason = validate_security_exploit_test(MISSING_PAYLOAD_TEST, finding=finding, target_path="app.py")
    assert is_valid is False
    assert "payload" in reason.lower()


@pytest.mark.asyncio
async def test_reject_missing_payloads_gate() -> None:
    """Gate marks remediation unverified when exploit test lacks SQLi payload."""
    files = {"app.py": VULNERABLE_SOURCE}
    patched_files = {"app.py": FIXED_SOURCE}
    findings = [{"id": "sqli-1", "path": "app.py", "line": 2}]

    sandbox = DummySandbox()
    nebius = DummyNebius(exploit_test={
        "path": "test_raksa_exploit.py",
        "content": MISSING_PAYLOAD_TEST,
        "reason": "Test without payload",
    })

    result = await verify_remediation(files, patched_files, findings, sandbox, nebius)
    assert result.status == "unverified"
    assert result.eligible_for_pr is False
    assert result.security_exploit.passed is False


def test_reject_unrelated_target_code() -> None:
    """Tests that do not exercise target code must be rejected."""
    finding = {"path": "app.py", "evidence": "def search(connection, name):"}
    is_valid, reason = validate_security_exploit_test(UNRELATED_TARGET_TEST, finding=finding, target_path="app.py")
    assert is_valid is False
    assert "target code" in reason.lower()


@pytest.mark.asyncio
async def test_reject_unrelated_assertion_failures() -> None:
    """An arbitrary AssertionError on an unrelated variable must not count as exploit reproduction."""
    files = {"app.py": VULNERABLE_SOURCE}
    patched_files = {"app.py": FIXED_SOURCE}
    findings = [{"id": "sqli-1", "path": "app.py", "line": 2}]

    sandbox = DummySandbox(responses={
        "test_raksa_exploit.py:before": {
            "provider": "docker",
            "status": "failed",
            "exit_code": 1,
            "stdout": "Ran 1 test in 0.01s\n\nFAILED (failures=1)\n",
            "stderr": "FAIL: test_exploit (test_raksa_exploit.ExploitTest)\nTraceback (most recent call last):\n  File \"test_raksa_exploit.py\", line 7, in test_exploit\n    self.assertEqual(env, \"prod\", \"Environment mismatch\")\nAssertionError: 'test_env' != 'prod' : Environment mismatch",
        },
    })
    nebius = DummyNebius(exploit_test={
        "path": "test_raksa_exploit.py",
        "content": UNRELATED_ASSERT_TEST,
        "reason": "Test with unrelated assertion",
    })

    result = await verify_remediation(files, patched_files, findings, sandbox, nebius)
    assert result.status == "unverified"
    assert result.eligible_for_pr is False
    assert result.security_exploit.passed is False
    assert result.before is not None
    assert result.before["exploit_reproduced"] is False
    assert "unrelated" in result.before["message"].lower() or "not prove" in result.message.lower()


def test_is_security_assertion_failure_unit() -> None:
    """Unit test is_security_assertion_failure distinguishing security assertions from unrelated/trivial ones."""
    # 1. Valid security assertion
    valid_out = "FAIL: test_injection\nTraceback (most recent call last):\n  File \"test_raksa_exploit.py\", line 8, in test_injection\n    self.assertEqual(len(rows), 0, \"SQL injection payload returned unintended rows\")\nAssertionError: 3 != 0 : SQL injection payload returned unintended rows"
    is_sec, _ = is_security_assertion_failure(valid_out)
    assert is_sec is True

    # 2. Unrelated environment assertion
    unrelated_out = "FAIL: test_injection\nTraceback (most recent call last):\n  File \"test_raksa_exploit.py\", line 6, in test_injection\n    self.assertEqual(env, \"prod\", \"Environment mismatch\")\nAssertionError: 'test_env' != 'prod' : Environment mismatch"
    is_unrelated, msg = is_security_assertion_failure(unrelated_out)
    assert is_unrelated is False
    assert "does not demonstrate targeted security behavior" in msg

    # 3. Trivial assertion
    trivial_out = "FAIL: test_injection\nTraceback (most recent call last):\n  File \"test_raksa_exploit.py\", line 5, in test_injection\n    self.assertTrue(False)\nAssertionError: False is not true"
    is_triv, msg_triv = is_security_assertion_failure(trivial_out)
    assert is_triv is False
    assert "trivial" in msg_triv.lower()


@pytest.mark.asyncio
async def test_valid_before_after_exploit_behavior() -> None:
    """Requirement 4: Valid before/after exploit behavior confirms reproduction and blocks payload."""
    files = {"app.py": VULNERABLE_SOURCE}
    patched_files = {"app.py": FIXED_SOURCE}
    findings = [{"id": "sqli-1", "path": "app.py", "line": 2}]

    sandbox = DummySandbox(responses={
        "test_raksa_exploit.py:before": {
            "provider": "docker",
            "status": "failed",
            "exit_code": 1,
            "stdout": "Ran 1 test in 0.01s\n\nFAILED (failures=1)\n",
            "stderr": "FAIL: test_injection_blocked (test_raksa_exploit.SQLiExploitTest)\nTraceback (most recent call last):\n  File \"test_raksa_exploit.py\", line 9, in test_injection_blocked\n    self.assertEqual(len(rows), 0, \"SQL injection payload returned unintended rows\")\nAssertionError: 3 != 0 : SQL injection payload returned unintended rows",
        },
        "test_raksa_exploit.py:after": {
            "provider": "docker",
            "status": "passed",
            "exit_code": 0,
            "stdout": "Ran 1 test in 0.01s\n\nOK\n",
            "stderr": "",
        },
    })
    nebius = DummyNebius(exploit_test={
        "path": "test_raksa_exploit.py",
        "content": EXPLOIT_TEST_CONTENT,
        "reason": "Valid exploit test",
    })

    result = await verify_remediation(files, patched_files, findings, sandbox, nebius)
    assert result.status == "verified"
    assert result.eligible_for_pr is True
    assert result.before is not None
    assert result.before["exploit_reproduced"] is True
    assert result.after is not None
    assert result.after["exploit_blocked"] is True


def test_classify_test_result_matrix() -> None:
    """Unit test classification helper across various outputs."""
    # 1. Assertion failure with security evidence
    r_assert = classify_test_result({
        "status": "failed",
        "exit_code": 1,
        "stdout": "Ran 1 test in 0.01s\n\nFAILED (failures=1)\n",
        "stderr": "FAIL: test_exploit (test_raksa_exploit.SQLiExploitTest)\nTraceback (most recent call last):\n  File \"test_raksa_exploit.py\", line 8, in test_exploit\n    self.assertEqual(len(rows), 0, \"SQL injection payload returned rows\")\nAssertionError: 3 != 0 : SQL injection payload returned rows",
    })
    assert r_assert.outcome == "assertion_failure"
    assert r_assert.is_assertion_failure is True
    assert r_assert.is_passed is False

    # 2. Module import error
    r_import = classify_test_result({
        "status": "failed",
        "exit_code": 1,
        "stdout": "Ran 1 test in 0.00s\n\nFAILED (errors=1)\n",
        "stderr": "ERROR: test_raksa_exploit (unittest.loader._FailedTest)\nImportError: cannot import name 'target'",
    })
    assert r_import.outcome == "setup_error"
    assert r_import.is_assertion_failure is False

    # 3. Timeout
    r_timeout = classify_test_result({
        "status": "timeout",
        "exit_code": None,
        "stdout": "",
        "stderr": "Sandbox timeout reached.",
    })
    assert r_timeout.outcome == "timeout"
    assert r_timeout.is_assertion_failure is False

    # 4. Zero tests ran
    r_zero = classify_test_result({
        "status": "passed",
        "exit_code": 0,
        "stdout": "Ran 0 tests in 0.00s\n\nOK\n",
        "stderr": "",
    })
    assert r_zero.outcome == "no_tests_ran"
    assert r_zero.is_assertion_failure is False

    # 5. Passed test
    r_pass = classify_test_result({
        "status": "passed",
        "exit_code": 0,
        "stdout": "Ran 1 test in 0.01s\n\nOK\n",
        "stderr": "",
    })
    assert r_pass.outcome == "passed"
    assert r_pass.is_passed is True
    assert r_pass.is_assertion_failure is False


def test_static_recheck_fails_if_vulnerability_remains() -> None:
    """Static recheck fails if vulnerable SQL pattern still exists on the target path."""
    original_findings = [{"id": "sqli-1", "path": "app.py", "line": 2}]
    patched_files = {"app.py": VULNERABLE_SOURCE}

    check = run_static_recheck(original_findings, patched_files)
    assert check.passed is False
    assert check.status == "failed"
    assert len(check.details["remaining_findings"]) == 1


def test_find_existing_security_test() -> None:
    """Identify existing security exploit test file in repository."""
    findings = [{"id": "sqli-1", "path": "app.py", "line": 2}]
    files = {
        "app.py": VULNERABLE_SOURCE,
        "test_app.py": "from app import search\n# Test SQL injection vulnerability with payload ' OR 1=1 --\n",
        "test_math.py": "import unittest\nclass T(unittest.TestCase):\n    pass\n",
    }
    found = find_existing_security_test(files, findings)
    assert found == "test_app.py"


def test_evaluate_verification_gate_matrix() -> None:
    """Unit test the gate decision matrix under various check combinations."""
    ok_static = VerificationCheck("static_recheck", "passed", True, "ok", {})
    fail_static = VerificationCheck("static_recheck", "failed", False, "failed", {})

    ok_exploit = VerificationCheck("security_exploit_test", "passed", True, "ok", {})
    fail_exploit = VerificationCheck("security_exploit_test", "failed", False, "failed", {})
    unavail_exploit = VerificationCheck("security_exploit_test", "unavailable", False, "unavailable", {})
    unverified_exploit = VerificationCheck("security_exploit_test", "unverified", False, "unverified", {})
    error_exploit = VerificationCheck("security_exploit_test", "error", False, "error", {})

    ok_reg = VerificationCheck("regression_tests", "passed", True, "ok", {})
    fail_reg = VerificationCheck("regression_tests", "failed", False, "failed", {})
    skip_reg = VerificationCheck("regression_tests", "skipped", True, "skipped", {})

    # All pass -> verified
    gate_ok = evaluate_verification_gate(ok_static, ok_exploit, ok_reg, "docker")
    assert gate_ok.status == "verified"
    assert gate_ok.eligible_for_pr is True

    # Skipped regression tests + passed exploit + passed static -> verified
    gate_skip = evaluate_verification_gate(ok_static, ok_exploit, skip_reg, "docker")
    assert gate_skip.status == "verified"
    assert gate_skip.eligible_for_pr is True

    # Unavailable exploit -> unverified
    gate_unavail = evaluate_verification_gate(ok_static, unavail_exploit, ok_reg, "docker")
    assert gate_unavail.status == "unverified"
    assert gate_unavail.eligible_for_pr is False

    # Unverified exploit -> unverified
    gate_unver = evaluate_verification_gate(ok_static, unverified_exploit, ok_reg, "docker")
    assert gate_unver.status == "unverified"
    assert gate_unver.eligible_for_pr is False

    # Error exploit -> error
    gate_err = evaluate_verification_gate(ok_static, error_exploit, ok_reg, "docker")
    assert gate_err.status == "error"
    assert gate_err.eligible_for_pr is False

    # Failed exploit -> failed
    gate_fail_exp = evaluate_verification_gate(ok_static, fail_exploit, ok_reg, "docker")
    assert gate_fail_exp.status == "failed"
    assert gate_fail_exp.eligible_for_pr is False

    # Failed regression -> failed
    gate_fail_reg = evaluate_verification_gate(ok_static, ok_exploit, fail_reg, "docker")
    assert gate_fail_reg.status == "failed"
    assert gate_fail_reg.eligible_for_pr is False

    # Failed static -> failed
    gate_fail_static = evaluate_verification_gate(fail_static, ok_exploit, ok_reg, "docker")
    assert gate_fail_static.status == "failed"
    assert gate_fail_static.eligible_for_pr is False


def test_reject_unused_payload_variable_static() -> None:
    """Exploit test defining payload variable that does not reach target code must be rejected."""
    finding = {"path": "app.py", "evidence": "def search(connection, name):"}
    is_valid, reason = validate_security_exploit_test(UNUSED_PAYLOAD_TEST, finding=finding, target_path="app.py")
    assert is_valid is False
    assert "unused payload variable" in reason.lower()


@pytest.mark.asyncio
async def test_reject_unused_payload_variable_gate() -> None:
    """Gate marks remediation unverified when exploit test contains unused payload variables."""
    files = {"app.py": VULNERABLE_SOURCE}
    patched_files = {"app.py": FIXED_SOURCE}
    findings = [{"id": "sqli-1", "path": "app.py", "line": 2}]

    sandbox = DummySandbox()
    nebius = DummyNebius(exploit_test={
        "path": "test_raksa_exploit.py",
        "content": UNUSED_PAYLOAD_TEST,
        "reason": "Test with unused payload variable",
    })

    result = await verify_remediation(files, patched_files, findings, sandbox, nebius)
    assert result.status == "unverified"
    assert result.eligible_for_pr is False
    assert result.security_exploit.passed is False
    assert "unused payload variable" in result.security_exploit.message.lower()


def test_reject_unrelated_function_result_static() -> None:
    """Exploit tests evaluating unrelated function results must be rejected."""
    finding = {"path": "app.py", "evidence": "def search(connection, name):"}
    is_valid, reason = validate_security_exploit_test(UNRELATED_FN_RESULT_TEST, finding=finding, target_path="app.py")
    assert is_valid is False
    assert "unrelated" in reason.lower()

    is_valid2, reason2 = validate_security_exploit_test(DIRECT_UNRELATED_CALL_TEST, finding=finding, target_path="app.py")
    assert is_valid2 is False
    assert "unrelated" in reason2.lower()


@pytest.mark.asyncio
async def test_reject_unrelated_function_result_gate() -> None:
    """Gate marks remediation unverified when exploit test asserts on unrelated function results."""
    files = {"app.py": VULNERABLE_SOURCE}
    patched_files = {"app.py": FIXED_SOURCE}
    findings = [{"id": "sqli-1", "path": "app.py", "line": 2}]

    sandbox = DummySandbox()
    nebius = DummyNebius(exploit_test={
        "path": "test_raksa_exploit.py",
        "content": UNRELATED_FN_RESULT_TEST,
        "reason": "Test with assertion on unrelated function result",
    })

    result = await verify_remediation(files, patched_files, findings, sandbox, nebius)
    assert result.status == "unverified"
    assert result.eligible_for_pr is False
    assert result.security_exploit.passed is False
    assert "unrelated" in result.security_exploit.message.lower()


def test_runtime_rejects_unrelated_function_assertion() -> None:
    """Runtime failure classifier rejects assertion failures evaluating unrelated function results."""
    failing_output = (
        "FAIL: test_exploit (test_raksa_exploit.ExploitTest)\n"
        "Traceback (most recent call last):\n"
        "  File \"test_raksa_exploit.py\", line 13, in test_exploit\n"
        "    self.assertEqual(status, \"ok\")\n"
        "AssertionError: 'degraded' != 'ok'\n"
    )
    finding = {"path": "app.py", "evidence": "def search(connection, name):"}
    is_sec, msg = is_security_assertion_failure(
        failing_output,
        test_content=UNRELATED_FN_RESULT_TEST,
        finding=finding,
    )
    assert is_sec is False
    assert "unrelated" in msg.lower()


def test_valid_inline_and_derived_exploit_tests() -> None:
    """Exploit tests with inline payload directly in target call and assertions pass validation."""
    finding = {"path": "app.py", "evidence": "def search(connection, name):"}
    is_valid, msg = validate_security_exploit_test(VALID_INLINE_PAYLOAD_TEST, finding=finding, target_path="app.py")
    assert is_valid is True
    assert "valid" in msg.lower()
