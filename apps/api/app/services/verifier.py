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
class VerificationGateResult:
    status: Literal["verified", "unverified", "failed", "error"]
    eligible_for_pr: bool
    message: str
    sandbox_provider: str
    static_recheck: VerificationCheck
    security_exploit: VerificationCheck
    regression_tests: VerificationCheck
    tests: dict[str, Any] | None = None
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
    return bool(re.search(r"\b\d+\s+passed\b", combined, re.I))


def evaluate_verification_gate(
    static_recheck: VerificationCheck,
    security_exploit: VerificationCheck,
    regression_tests: VerificationCheck,
    sandbox_provider: str,
    tests: dict[str, Any] | None = None,
    details: dict[str, Any] | None = None,
) -> VerificationGateResult:
    """Evaluate whether all required verification evidence checks pass.

    Rules:
    1. If any check has error status -> result is error, eligible_for_pr=False.
    2. If security exploit test is unavailable -> result is unverified, eligible_for_pr=False.
       (Do not treat unrelated passing tests as proof).
    3. If security exploit test is not_run -> result is unverified, eligible_for_pr=False.
    4. If static recheck failed -> result is failed, eligible_for_pr=False.
    5. If security exploit test failed -> result is failed, eligible_for_pr=False.
    6. If regression tests failed -> result is failed, eligible_for_pr=False.
    7. Only when static recheck passed, security exploit test passed, and regression tests passed/skipped -> verified, eligible_for_pr=True.
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
            details=details,
        )

    if security_exploit.status in {"not_run", "unverified"} or regression_tests.status in {"not_run", "unverified"}:
        return VerificationGateResult(
            status="unverified",
            eligible_for_pr=False,
            message="Remediation is unverified: test execution was not performed in the configured sandbox provider.",
            sandbox_provider=sandbox_provider,
            static_recheck=static_recheck,
            security_exploit=security_exploit,
            regression_tests=regression_tests,
            tests=tests,
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
            details=details,
        )

    if not security_exploit.passed:
        return VerificationGateResult(
            status="failed",
            eligible_for_pr=False,
            message="Verification failed: security exploit test failed against the remediated code.",
            sandbox_provider=sandbox_provider,
            static_recheck=static_recheck,
            security_exploit=security_exploit,
            regression_tests=regression_tests,
            tests=tests,
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
            details=details,
        )

    # All required checks passed!
    return VerificationGateResult(
        status="verified",
        eligible_for_pr=True,
        message="All verification checks passed: static recheck cleared, security exploit test proved mitigation, and regression tests passed without errors.",
        sandbox_provider=sandbox_provider,
        static_recheck=static_recheck,
        security_exploit=security_exploit,
        regression_tests=regression_tests,
        tests=tests,
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
    """Orchestrate the 3-part verification gate for a proposed remediation."""
    provider = (sandbox_provider or getattr(sandbox_service, "provider", None) or settings.sandbox_provider).strip().lower()

    # 1. Static recheck
    static_recheck = run_static_recheck(findings, patched_files, max_findings=settings.max_findings)

    # 2. Identify or generate the security exploit test
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
    if provider.strip().lower() == "demo":
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

    # 3. Regression tests execution (run existing tests on patched code)
    existing_tests = [p for p in files.keys() if is_test_file(p)]
    # If the exploit test was already an existing file, other files are pure regression tests
    pure_regression_tests = [p for p in existing_tests if p != exploit_test_path]

    regression_tests: VerificationCheck
    combined_test_output: dict[str, Any] | None = None

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
            # Run existing tests against patched files
            reg_result = await sandbox_service.run_tests(patched_files, timeout_seconds=timeout_seconds)
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

    # 4. Security exploit test execution
    security_exploit: VerificationCheck

    if not exploit_test_path:
        # Exploit test could not be identified or generated
        security_exploit = VerificationCheck(
            name="security_exploit_test",
            status="unavailable",
            passed=False,
            message="Security exploit test could not be generated or identified. Passing unrelated tests cannot verify the vulnerability is fixed.",
            details={},
        )
    else:
        # Prepare files containing the security test
        exploit_execution_files = dict(patched_files)
        if is_generated_exploit and exploit_test_content:
            exploit_execution_files[exploit_test_path] = exploit_test_content

        try:
            test_pattern = exploit_test_path.split("/")[-1]
            exp_result = await sandbox_service.run_tests(
                exploit_execution_files,
                timeout_seconds=timeout_seconds,
                test_pattern=test_pattern,
            )
            if not combined_test_output:
                combined_test_output = exp_result
            exp_ran = tests_ran(exp_result)
            exp_passed = exp_result.get("status") == "passed" and exp_ran

            security_exploit = VerificationCheck(
                name="security_exploit_test",
                status="passed" if exp_passed else "failed",
                passed=exp_passed,
                message="Security exploit test passed: vulnerability payload was blocked by remediation." if exp_passed else "Security exploit test failed: exploit payload was not blocked or assertion failed.",
                details=exp_result,
            )
        except SandboxError as exc:
            security_exploit = VerificationCheck(
                name="security_exploit_test",
                status="error",
                passed=False,
                message=f"Sandbox error while executing security exploit test: {exc}",
                details={"error": str(exc)},
            )

    return evaluate_verification_gate(
        static_recheck=static_recheck,
        security_exploit=security_exploit,
        regression_tests=regression_tests,
        sandbox_provider=provider,
        tests=combined_test_output,
    )
