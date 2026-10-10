import re
from dataclasses import asdict, dataclass
from typing import Any, Literal

from app.config import settings
from app.services.analyzer import detect_sql_injection
from app.services.sandbox import SandboxError


@dataclass
class VerificationCheck:
    name: str
    status: Literal["passed", "failed", "unverified", "error", "skipped", "unavailable", "not_run"]
    passed: bool
    message: str
    details: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TestClassification:
    outcome: Literal["passed", "assertion_failure", "setup_error", "no_tests_ran", "timeout", "sandbox_error"]
    is_assertion_failure: bool
    is_passed: bool
    message: str
    details: dict[str, Any]


@dataclass
class VerificationGateResult:
    status: Literal["verified", "unverified", "failed", "error"]
    eligible_for_pr: bool
    message: str
    sandbox_provider: str
    static_recheck: VerificationCheck
    security_exploit: VerificationCheck
    regression_tests: VerificationCheck
    tests: dict[str, Any] | None = None
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    details: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "eligible_for_pr": self.eligible_for_pr,
            "message": self.message,
            "sandbox_provider": self.sandbox_provider,
            "static_recheck": self.static_recheck.as_dict(),
            "security_exploit": self.security_exploit.as_dict(),
            "regression_tests": self.regression_tests.as_dict(),
            "static_recheck_passed": self.static_recheck.passed,
            "security_exploit_passed": self.security_exploit.passed,
            "regression_tests_passed": self.regression_tests.passed,
            "tests": self.tests,
            "before": self.before,
            "after": self.after,
            "details": self.details or {},
        }


def run_static_recheck(
    original_findings: list[dict[str, Any]],
    patched_files: dict[str, str],
    max_findings: int = 10,
) -> VerificationCheck:
    """Re-run the static heuristic on patched files to ensure target findings are gone."""
    remaining_findings = detect_sql_injection(patched_files, max_findings=max_findings)
    original_paths = {item["path"] for item in original_findings}
    remaining_for_targets = [item for item in remaining_findings if item["path"] in original_paths]

    if remaining_for_targets:
        return VerificationCheck(
            name="static_recheck",
            status="failed",
            passed=False,
            message=f"Static recheck failed: {len(remaining_for_targets)} potential vulnerability pattern(s) remain on patched paths.",
            details={"remaining_findings": remaining_for_targets},
        )

    return VerificationCheck(
        name="static_recheck",
        status="passed",
        passed=True,
        message="Static recheck passed: no SQL injection patterns detected on patched files.",
        details={"remaining_findings": []},
    )


def is_test_file(path: str) -> bool:
    """Check if a repository path looks like a Python test file."""
    parts = path.split("/")
    filename = parts[-1]
    if not filename.endswith(".py"):
        return False
    return (
        filename.startswith("test_")
        or filename.endswith("_test.py")
        or any(part in {"tests", "test"} for part in parts[:-1])
    )


def find_existing_security_test(
    files: dict[str, str],
    findings: list[dict[str, Any]],
) -> str | None:
    """Identify if any existing test in the repository specifically targets the reported vulnerability."""
    security_keywords = {
        "sqli", "sql_injection", "injection", "vulnerable", "exploit",
        "parameterized", "payload", "cwe-89", "cwe_89",
    }
    target_stems = {finding["path"].replace(".py", "").split("/")[-1] for finding in findings}

    for path, content in files.items():
        if not is_test_file(path):
            continue
        lower_content = content.lower()
        has_security_keyword = any(kw in lower_content for kw in security_keywords)
        targets_file = any(stem in lower_content for stem in target_stems)

        if has_security_keyword and targets_file:
            return path

    return None


def tests_ran(result: dict[str, Any]) -> bool:
    """Verify that test output reports at least one executed test."""
    combined = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"
    match = re.search(r"Ran\s+(\d+)\s+tests?", combined)
    if match:
        return int(match.group(1)) > 0
    return bool(
        re.search(r"\b\d+\s+passed\b", combined, re.I)
        or re.search(r"\b\d+\s+failed\b", combined, re.I)
    )


def classify_test_result(result: dict[str, Any]) -> TestClassification:
    """Distinguish assertion failures from setup errors, import errors, timeouts, and sandbox failures."""
    stdout = str(result.get("stdout") or "")
    stderr = str(result.get("stderr") or "")
    combined = f"{stdout}\n{stderr}"
    status = str(result.get("status") or "").lower()
    exit_code = result.get("exit_code")

    # 1. Timeout
    if status == "timeout" or "sandbox timeout" in combined.lower() or "timed out" in combined.lower():
        return TestClassification(
            outcome="timeout",
            is_assertion_failure=False,
            is_passed=False,
            message="Security test execution timed out.",
            details={"status": status, "exit_code": exit_code},
        )

    # 2. Sandbox error / unexecuted
    if status in {"error", "unavailable"} or (exit_code is None and status != "passed"):
        return TestClassification(
            outcome="sandbox_error",
            is_assertion_failure=False,
            is_passed=False,
            message=str(result.get("message") or "Sandbox execution failed."),
            details={"status": status, "exit_code": exit_code},
        )

    # 3. Discovery errors / No tests ran
    has_loader_failed_test = bool(re.search(r"\b_FailedTest\b|unittest\.loader\._FailedTest", combined))
    ran_match = re.search(r"Ran\s+(\d+)\s+tests?", combined)
    test_count = int(ran_match.group(1)) if ran_match else None

    if (test_count == 0) or (test_count is None and not tests_ran(result)):
        return TestClassification(
            outcome="no_tests_ran",
            is_assertion_failure=False,
            is_passed=False,
            message="No security tests were executed (discovery found 0 tests).",
            details={"status": status, "exit_code": exit_code, "test_count": 0},
        )

    # 4. Import / Syntax / Discovery errors
    has_import_error = bool(re.search(r"\b(?:ImportError|ModuleNotFoundError)\b", combined))
    has_syntax_error = bool(re.search(r"\b(?:SyntaxError|IndentationError)\b", combined))
    has_pytest_collect_error = bool(re.search(r"\bERROR collecting\b|\bcollected 0 items\b", combined))

    if has_loader_failed_test or has_import_error or has_syntax_error or has_pytest_collect_error:
        error_type = (
            "import error"
            if has_import_error
            else "syntax error"
            if has_syntax_error
            else "test discovery error"
        )
        return TestClassification(
            outcome="setup_error",
            is_assertion_failure=False,
            is_passed=False,
            message=f"Security test encountered a {error_type} during test setup or discovery.",
            details={"status": status, "exit_code": exit_code, "error_type": error_type},
        )

    # 5. Clean pass
    is_passed = (
        status == "passed"
        and exit_code == 0
        and not bool(re.search(r"\bFAILED\b", combined))
        and not bool(re.search(r"\bFAIL:\s+", combined))
        and not bool(re.search(r"\bERROR:\s+", combined))
    )
    if is_passed:
        return TestClassification(
            outcome="passed",
            is_assertion_failure=False,
            is_passed=True,
            message="Security test executed and passed.",
            details={"status": status, "exit_code": exit_code},
        )

    # 6. Check for Assertion Failure vs other runtime errors
    has_assertion_error = "AssertionError" in combined
    has_unittest_failure = bool(re.search(r"FAILED\s*\([^)]*failures=\d+", combined) or re.search(r"\bFAIL:\s+", combined))
    only_unittest_errors = bool(re.search(r"FAILED\s*\(\s*errors=\d+\s*\)", combined))

    if only_unittest_errors and not has_assertion_error:
        return TestClassification(
            outcome="setup_error",
            is_assertion_failure=False,
            is_passed=False,
            message="Security test failed with an unhandled exception rather than an assertion failure.",
            details={"status": status, "exit_code": exit_code},
        )

    if has_assertion_error or has_unittest_failure:
        return TestClassification(
            outcome="assertion_failure",
            is_assertion_failure=True,
            is_passed=False,
            message="Security test failed with an assertion failure reproducing the vulnerability.",
            details={"status": status, "exit_code": exit_code},
        )

    # Fallback non-zero exit code without confirmed assertion failure
    return TestClassification(
        outcome="setup_error",
        is_assertion_failure=False,
        is_passed=False,
        message="Security test execution failed without a confirmed assertion failure.",
        details={"status": status, "exit_code": exit_code},
    )


def evaluate_verification_gate(
    static_recheck: VerificationCheck,
    security_exploit: VerificationCheck,
    regression_tests: VerificationCheck,
    sandbox_provider: str,
    tests: dict[str, Any] | None = None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    details: dict[str, Any] | None = None,
) -> VerificationGateResult:
    """Evaluate whether all required verification evidence checks pass.

    Rules:
    1. If any check has error status -> result is error, eligible_for_pr=False.
    2. If security exploit test is unavailable -> result is unverified, eligible_for_pr=False.
       (Do not treat unrelated passing tests as proof).
    3. If security exploit test is not_run or unverified -> result is unverified, eligible_for_pr=False.
    4. If static recheck failed -> result is failed, eligible_for_pr=False.
    5. If security exploit test failed -> result is failed, eligible_for_pr=False.
    6. If regression tests failed -> result is failed, eligible_for_pr=False.
    7. Only when static recheck passed, security exploit test passed (differential proof succeeded),
       and regression tests passed/skipped -> verified, eligible_for_pr=True.
    """
    if static_recheck.status == "error" or security_exploit.status == "error" or regression_tests.status == "error":
        error_msg = next(
            (c.message for c in (static_recheck, security_exploit, regression_tests) if c.status == "error"),
            "Sandbox execution error occurred.",
        )
        return VerificationGateResult(
            status="error",
            eligible_for_pr=False,
            message=f"Verification error: {error_msg}",
            sandbox_provider=sandbox_provider,
            static_recheck=static_recheck,
            security_exploit=security_exploit,
            regression_tests=regression_tests,
            tests=tests,
            before=before,
            after=after,
            details=details,
        )

    if security_exploit.status == "unavailable":
        return VerificationGateResult(
            status="unverified",
            eligible_for_pr=False,
            message="Remediation is unverified: a targeted security exploit test could not be generated or identified. Passing unrelated tests does not prove the vulnerability is fixed.",
            sandbox_provider=sandbox_provider,
            static_recheck=static_recheck,
            security_exploit=security_exploit,
            regression_tests=regression_tests,
            tests=tests,
            before=before,
            after=after,
            details=details,
        )

    if security_exploit.status in {"not_run", "unverified"} or regression_tests.status in {"not_run", "unverified"}:
        unverified_msg = (
            security_exploit.message
            if security_exploit.status in {"not_run", "unverified"}
            else regression_tests.message
        )
        prefix = "" if unverified_msg.startswith("Remediation is unverified") else "Remediation is unverified: "
        return VerificationGateResult(
            status="unverified",
            eligible_for_pr=False,
            message=f"{prefix}{unverified_msg}",
            sandbox_provider=sandbox_provider,
            static_recheck=static_recheck,
            security_exploit=security_exploit,
            regression_tests=regression_tests,
            tests=tests,
            before=before,
            after=after,
            details=details,
        )

    if not static_recheck.passed:
        return VerificationGateResult(
            status="failed",
            eligible_for_pr=False,
            message="Verification failed: static recheck still detects potential vulnerability patterns in patched code.",
            sandbox_provider=sandbox_provider,
            static_recheck=static_recheck,
            security_exploit=security_exploit,
            regression_tests=regression_tests,
            tests=tests,
            before=before,
            after=after,
            details=details,
        )

    if not security_exploit.passed:
        return VerificationGateResult(
            status="failed",
            eligible_for_pr=False,
            message=f"Verification failed: {security_exploit.message}",
            sandbox_provider=sandbox_provider,
            static_recheck=static_recheck,
            security_exploit=security_exploit,
            regression_tests=regression_tests,
            tests=tests,
            before=before,
            after=after,
            details=details,
        )

    if not regression_tests.passed and regression_tests.status != "skipped":
        return VerificationGateResult(
            status="failed",
            eligible_for_pr=False,
            message="Verification failed: regression tests broke after applying the proposed patch.",
            sandbox_provider=sandbox_provider,
            static_recheck=static_recheck,
            security_exploit=security_exploit,
            regression_tests=regression_tests,
            tests=tests,
            before=before,
            after=after,
            details=details,
        )

    # All required checks passed!
    return VerificationGateResult(
        status="verified",
        eligible_for_pr=True,
        message="All verification checks passed: static recheck cleared, differential exploit verification proved mitigation, and regression tests passed without errors.",
        sandbox_provider=sandbox_provider,
        static_recheck=static_recheck,
        security_exploit=security_exploit,
        regression_tests=regression_tests,
        tests=tests,
        before=before,
        after=after,
        details=details,
    )


async def verify_remediation(
    files: dict[str, str],
    patched_files: dict[str, str],
    findings: list[dict[str, Any]],
    sandbox_service: Any,
    nebius_service: Any = None,
    timeout_seconds: int | None = None,
    sandbox_provider: str | None = None,
) -> VerificationGateResult:
    """Orchestrate differential exploit verification, regression testing, and static recheck."""
    provider = (sandbox_provider or getattr(sandbox_service, "provider", None) or settings.sandbox_provider).strip().lower()

    # 1. Static recheck
    static_recheck = run_static_recheck(findings, patched_files, max_findings=settings.max_findings)

    # 2. Identify or generate the targeted security exploit test
    exploit_test_path: str | None = find_existing_security_test(files, findings)
    exploit_test_content: str | None = None
    is_generated_exploit = False

    if not exploit_test_path and nebius_service and getattr(nebius_service, "configured", False) and findings:
        primary_finding = findings[0]
        source = files.get(primary_finding["path"], "")
        generated = await nebius_service.generate_exploit_test(
            path=primary_finding["path"], source=source, finding=primary_finding
        )
        if generated and generated.get("path") and generated.get("content"):
            exploit_test_path = generated["path"]
            exploit_test_content = generated["content"]
            is_generated_exploit = True

    # Check for demo provider or unexecutable sandbox
    if provider == "demo":
        security_exploit = VerificationCheck(
            name="security_exploit_test",
            status="not_run",
            passed=False,
            message="Security exploit test was not run: SANDBOX_PROVIDER is set to demo.",
            details={"provider": "demo"},
        )
        regression_tests = VerificationCheck(
            name="regression_tests",
            status="not_run",
            passed=False,
            message="Regression tests were not run: SANDBOX_PROVIDER is set to demo.",
            details={"provider": "demo"},
        )
        return evaluate_verification_gate(
            static_recheck=static_recheck,
            security_exploit=security_exploit,
            regression_tests=regression_tests,
            sandbox_provider=provider,
        )

    # 3. Security exploit test availability check
    if not exploit_test_path:
        security_exploit = VerificationCheck(
            name="security_exploit_test",
            status="unavailable",
            passed=False,
            message="Security exploit test could not be generated or identified. Passing unrelated tests cannot verify the vulnerability is fixed.",
            details={},
        )
        # Still evaluate regression tests if test suite exists
        existing_tests = [p for p in files.keys() if is_test_file(p)]
        if not existing_tests:
            regression_tests = VerificationCheck(
                name="regression_tests",
                status="skipped",
                passed=True,
                message="No separate regression test suite detected in repository snapshot.",
                details={"test_files": []},
            )
        else:
            try:
                reg_result = await sandbox_service.run_tests(patched_files, timeout_seconds=timeout_seconds)
                reg_ran = tests_ran(reg_result)
                reg_passed = reg_result.get("status") == "passed" and reg_ran
                regression_tests = VerificationCheck(
                    name="regression_tests",
                    status="passed" if reg_passed else "failed",
                    passed=reg_passed,
                    message="Preexisting regression tests passed without errors." if reg_passed else "Regression tests failed after applying patch.",
                    details=reg_result,
                )
            except SandboxError as exc:
                regression_tests = VerificationCheck(
                    name="regression_tests",
                    status="error",
                    passed=False,
                    message=f"Sandbox error while executing regression tests: {exc}",
                    details={"error": str(exc)},
                )
        return evaluate_verification_gate(
            static_recheck=static_recheck,
            security_exploit=security_exploit,
            regression_tests=regression_tests,
            sandbox_provider=provider,
        )

    # 4. Prepare snapshots for differential verification
    before_files = dict(files)
    after_files = dict(patched_files)
    if is_generated_exploit and exploit_test_content:
        before_files[exploit_test_path] = exploit_test_content
        after_files[exploit_test_path] = exploit_test_content
    elif exploit_test_path in files and exploit_test_path not in patched_files:
        after_files[exploit_test_path] = files[exploit_test_path]

    test_pattern = exploit_test_path.split("/")[-1]

    # Step A: Differential verification on ORIGINAL snapshot (Before patch)
    before_result: dict[str, Any]
    try:
        before_result = await sandbox_service.run_tests(
            before_files,
            timeout_seconds=timeout_seconds,
            test_pattern=test_pattern,
        )
    except SandboxError as exc:
        security_exploit = VerificationCheck(
            name="security_exploit_test",
            status="error",
            passed=False,
            message=f"Sandbox error while executing security exploit test before patch: {exc}",
            details={"error": str(exc), "stage": "before"},
        )
        regression_tests = VerificationCheck(
            name="regression_tests",
            status="skipped",
            passed=False,
            message="Regression tests skipped due to sandbox error.",
            details={},
        )
        return evaluate_verification_gate(
            static_recheck=static_recheck,
            security_exploit=security_exploit,
            regression_tests=regression_tests,
            sandbox_provider=provider,
        )

    before_class = classify_test_result(before_result)
    before_reproduced = before_class.is_assertion_failure

    before_evidence: dict[str, Any] = {
        "status": before_result.get("status"),
        "exit_code": before_result.get("exit_code"),
        "outcome": before_class.outcome,
        "exploit_reproduced": before_reproduced,
        "message": before_class.message,
        "stdout": before_result.get("stdout", ""),
        "stderr": before_result.get("stderr", ""),
    }

    after_result: dict[str, Any] | None = None
    after_evidence: dict[str, Any]
    security_exploit: VerificationCheck

    if before_class.outcome == "sandbox_error":
        security_exploit = VerificationCheck(
            name="security_exploit_test",
            status="error",
            passed=False,
            message=f"Sandbox error executing security exploit test before patch: {before_class.message}",
            details={"before": before_evidence},
        )
        after_evidence = {
            "status": "not_run",
            "exit_code": None,
            "outcome": "not_run",
            "exploit_blocked": False,
            "message": "Patched test was not run due to sandbox error on original code.",
            "stdout": "",
            "stderr": "",
        }
    elif before_class.is_passed:
        security_exploit = VerificationCheck(
            name="security_exploit_test",
            status="unverified",
            passed=False,
            message="Security exploit test unexpectedly passed against original unpatched code. The vulnerability was not reproduced.",
            details={"before": before_evidence},
        )
        after_evidence = {
            "status": "not_run",
            "exit_code": None,
            "outcome": "not_run",
            "exploit_blocked": False,
            "message": "Patched snapshot test was not executed because the vulnerability was not reproduced on the original snapshot.",
            "stdout": "",
            "stderr": "",
        }
    elif not before_reproduced:
        # Setup errors, import errors, discovery errors, timeouts
        security_exploit = VerificationCheck(
            name="security_exploit_test",
            status="unverified",
            passed=False,
            message=f"Security exploit test did not reproduce vulnerability on original code ({before_class.message}). Setup and discovery errors do not prove vulnerability.",
            details={"before": before_evidence},
        )
        after_evidence = {
            "status": "not_run",
            "exit_code": None,
            "outcome": "not_run",
            "exploit_blocked": False,
            "message": "Patched snapshot test was not executed because the vulnerability was not reproduced on the original snapshot.",
            "stdout": "",
            "stderr": "",
        }
    else:
        # Before run successfully reproduced the vulnerability via assertion failure!
        # Step B: Differential verification on PATCHED snapshot (After patch)
        try:
            after_result = await sandbox_service.run_tests(
                after_files,
                timeout_seconds=timeout_seconds,
                test_pattern=test_pattern,
            )
        except SandboxError as exc:
            security_exploit = VerificationCheck(
                name="security_exploit_test",
                status="error",
                passed=False,
                message=f"Sandbox error while executing security exploit test after patch: {exc}",
                details={"error": str(exc), "stage": "after", "before": before_evidence},
            )
            regression_tests = VerificationCheck(
                name="regression_tests",
                status="skipped",
                passed=False,
                message="Regression tests skipped due to sandbox error.",
                details={},
            )
            return evaluate_verification_gate(
                static_recheck=static_recheck,
                security_exploit=security_exploit,
                regression_tests=regression_tests,
                sandbox_provider=provider,
                before=before_evidence,
            )

        after_class = classify_test_result(after_result)
        after_blocked = after_class.is_passed

        after_evidence = {
            "status": after_result.get("status"),
            "exit_code": after_result.get("exit_code"),
            "outcome": after_class.outcome,
            "exploit_blocked": after_blocked,
            "message": after_class.message,
            "stdout": after_result.get("stdout", ""),
            "stderr": after_result.get("stderr", ""),
        }

        if after_blocked:
            security_exploit = VerificationCheck(
                name="security_exploit_test",
                status="passed",
                passed=True,
                message="Differential exploit verification succeeded: security test reproduced vulnerability before patch (assertion failed) and passed after patch.",
                details={"before": before_evidence, "after": after_evidence},
            )
        else:
            security_exploit = VerificationCheck(
                name="security_exploit_test",
                status="failed",
                passed=False,
                message=f"Security exploit test failed against patched code: {after_class.message}",
                details={"before": before_evidence, "after": after_evidence},
            )

    # 5. Regression tests execution (run existing tests on patched code)
    existing_tests = [p for p in files.keys() if is_test_file(p)]
    pure_regression_tests = [p for p in existing_tests if p != exploit_test_path]

    regression_tests: VerificationCheck
    combined_test_output: dict[str, Any] | None = after_result or before_result

    if not existing_tests or (exploit_test_path and not pure_regression_tests and not is_generated_exploit):
        # No independent regression suite existed before this remediation
        regression_tests = VerificationCheck(
            name="regression_tests",
            status="skipped",
            passed=True,
            message="No separate regression test suite detected in repository snapshot.",
            details={"test_files": []},
        )
    else:
        try:
            reg_result = await sandbox_service.run_tests(patched_files, timeout_seconds=timeout_seconds)
            if not after_result:
                combined_test_output = reg_result
            reg_ran = tests_ran(reg_result)
            reg_passed = reg_result.get("status") == "passed" and reg_ran
            regression_tests = VerificationCheck(
                name="regression_tests",
                status="passed" if reg_passed else "failed",
                passed=reg_passed,
                message="Preexisting regression tests passed without errors." if reg_passed else "Regression tests failed after applying patch.",
                details=reg_result,
            )
        except SandboxError as exc:
            regression_tests = VerificationCheck(
                name="regression_tests",
                status="error",
                passed=False,
                message=f"Sandbox error while executing regression tests: {exc}",
                details={"error": str(exc)},
            )

    return evaluate_verification_gate(
        static_recheck=static_recheck,
        security_exploit=security_exploit,
        regression_tests=regression_tests,
        sandbox_provider=provider,
        tests=combined_test_output,
        before=before_evidence,
        after=after_evidence,
    )
