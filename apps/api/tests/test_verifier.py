from typing import Any

import pytest

from app.services.sandbox import SandboxError
from app.services.verifier import (
    VerificationCheck,
    classify_test_result,
    evaluate_verification_gate,
    find_existing_security_test,
    run_static_recheck,
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
        self.assertTrue(True)
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
            "stderr": "FAIL: test_exploit\nAssertionError: SQL injection payload altered query semantics",
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
            "stderr": "FAIL: test_exploit\nAssertionError: SQL injection payload altered query semantics",
        },
        "test_raksa_exploit.py:after": {
            "provider": "docker",
            "status": "failed",
            "exit_code": 1,
            "stdout": "Ran 1 test in 0.01s\n\nFAILED (failures=1)\n",
            "stderr": "AssertionError: Exploit was not blocked",
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
            "stderr": "FAIL: test_exploit\nAssertionError: SQL injection reproduced",
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
    """Requirement 7: Successful differential verification records proof and allows PR."""
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
            "stderr": "FAIL: test_injection_blocked\nAssertionError: 3 != 0 : Exploit payload altered query",
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
    """Requirement 7: If the original test unexpectedly passes, vulnerability was not reproduced.

    Remediation is marked unverified and PR creation is prevented.
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
    """Requirement 7: Patched test failing marks verification failed and prevents PR."""
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
            "stderr": "FAIL: test_exploit\nAssertionError: Vulnerability present",
        },
        "test_raksa_exploit.py:after": {
            "provider": "docker",
            "status": "failed",
            "exit_code": 1,
            "stdout": "Ran 1 test in 0.01s\n\nFAILED (failures=1)\n",
            "stderr": "FAIL: test_exploit\nAssertionError: Patch failed to block payload",
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
    """Requirement 4 & 7: Setup, import, discovery, timeouts, and unhandled errors must never count as proof of vulnerability."""
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
    """Requirement 7: Sandbox errors during before or after execution return error and disable PR."""
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
                "stderr": "FAIL: test_exploit\nAssertionError: Reproduced",
            },
        },
        errors={"test_raksa_exploit.py:after": SandboxError("Container out of memory")},
    )
    res_after = await verify_remediation(files, patched_files, findings, sandbox_after_err, nebius)
    assert res_after.status == "error"
    assert res_after.eligible_for_pr is False
    assert "sandbox error" in res_after.message.lower()


def test_classify_test_result_matrix() -> None:
    """Unit test classification helper across various outputs."""
    # 1. Assertion failure
    r_assert = classify_test_result({
        "status": "failed",
        "exit_code": 1,
        "stdout": "Ran 1 test in 0.01s\n\nFAILED (failures=1)\n",
        "stderr": "FAIL: test_exploit\nAssertionError: Query was altered",
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
