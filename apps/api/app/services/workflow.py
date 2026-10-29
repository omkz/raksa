import difflib
import logging
import uuid
from typing import Any

from app.config import settings
from app.services.analyzer import apply_exact_replacements, detect_sql_injection
from app.scanners.registry import scan_snapshot
from app.services.github_app import github_app
from app.services.nebius import NebiusUnavailable, nebius
from app.services.sandbox import sandbox
from app.services.tavily import tavily
from app.services.verifier import verify_remediation
from app.state import JobOwnershipError, complete_job, fail_job, get_job, update_job

logger = logging.getLogger("raksa.workflow")


async def run_scan_job(
    scan_id: str,
    installation_id: str,
    full_name: str,
    *,
    worker_id: str | None = None,
) -> None:
    job_info = await get_job(scan_id)
    scan_type = str(job_info.get("scan_type", "repository")) if job_info else "repository"
    head_sha = job_info.get("head_sha") if job_info else None
    pr_number = job_info.get("pr_number") if job_info else None
    check_run_id = job_info.get("check_run_id") if job_info else None

    fetch_msg = (
        f"Fetching repository snapshot for PR #{pr_number} ({head_sha[:7]})…"
        if (scan_type == "pull_request" and head_sha and pr_number)
        else "Fetching a bounded repository snapshot…"
    )
    await update_job(
        scan_id,
        expected_worker_id=worker_id,
        status="running",
        stage="fetching",
        message=fetch_msg,
    )
    try:
        files, repo_meta, base_sha = await github_app.get_snapshot(
            installation_id,
            full_name,
            max_files=settings.max_repository_files,
            max_file_bytes=settings.max_file_bytes,
            max_repository_bytes=settings.max_repository_bytes,
            commit_sha=head_sha if (scan_type == "pull_request" and head_sha) else None,
        )
        pr_changed_files: list[str] = []
        if scan_type == "pull_request" and pr_number:
            try:
                pr_changed_files = await github_app.get_pull_request_files(
                    installation_id, full_name, int(pr_number)
                )
            except Exception as exc:
                logger.warning(f"Failed to fetch changed files for PR #{pr_number}: {exc}")

        await update_job(
            scan_id,
            expected_worker_id=worker_id,
            full_name=full_name,
            default_branch=repo_meta.get("default_branch", "main"),
            base_sha=base_sha,
            status="running",
            stage="analyzing",
            message=f"Analyzing {len(files)} source and test files for potential SQL injection…",
            source_files=files,
        )
        native_findings = detect_sql_injection(files, max_findings=settings.max_findings)
        scanner_results = await scan_snapshot(files, max_findings=settings.max_findings)
        scanner_reports = [result.report() for result in scanner_results]
        findings = list(native_findings)
        for scanner_result in scanner_results:
            room = max(0, settings.max_findings - len(findings))
            findings.extend(item.as_dict() for item in scanner_result.findings[:room])
        research: list[dict[str, str]] = []
        if native_findings:
            try:
                research = await tavily.research_sql_injection()
            except Exception as exc:
                research = [{"title": "Security research unavailable", "url": "", "content": f"Tavily request failed: {exc.__class__.__name__}"}]

        summary = ""
        if native_findings and nebius.configured:
            try:
                summary = await nebius.summarize_findings(native_findings, files)
            except NebiusUnavailable as exc:
                summary = str(exc)
        elif not nebius.configured:
            summary = "Nemotron analysis skipped: configure NEBIUS_API_KEY to enable model reasoning and patch proposals."

        proposals: list[dict[str, str]] = []
        candidate_proposals: list[dict[str, str]] = []
        patched_files = dict(files)
        patch_messages: list[str] = []
        if native_findings and nebius.configured:
            await update_job(
                scan_id,
                expected_worker_id=worker_id,
                stage="remediating",
                message="Requesting a constrained remediation proposal from Nemotron…",
            )
            for finding in native_findings[:3]:
                path = finding.get("path", "")
                source = files.get(path, "")
                if not source:
                    patch_messages.append(f"{path}: Source file not found in repository snapshot.")
                    continue
                try:
                    proposal = await nebius.propose_patch(
                        path=path,
                        source=source,
                        finding=finding,
                        diagnostics=patch_messages,
                    )
                    if proposal:
                        candidate_proposals.append(proposal)
                except NebiusUnavailable as exc:
                    patch_messages.append(f"{path}: Nebius unavailable: {exc}")
                    continue
                except Exception as exc:
                    patch_messages.append(f"{path}: Proposal generation failed: {exc}")
                    continue

        if candidate_proposals:
            for prop in candidate_proposals:
                try:
                    patched_files = apply_exact_replacements(patched_files, [prop])
                    proposals.append(prop)
                except ValueError as exc:
                    patch_messages.append(f"Patch rejected by context validation for {prop.get('path')}: {exc}")

        changed_files = {
            path: content for path, content in patched_files.items()
            if path in files and content != files[path]
        }
        patch_diff = _unified_diff(files, patched_files)
        verification: dict[str, Any] = {
            "status": "unverified",
            "sandbox_provider": settings.sandbox_provider,
            "static_recheck_passed": False,
            "tests": None,
            "message": "No remediation was verified. Review the finding and configure an isolated sandbox before requesting a PR.",
            "eligible_for_pr": False,
        }

        if changed_files:
            await update_job(
                scan_id,
                expected_worker_id=worker_id,
                stage="verifying",
                message=f"Running security verification gate via {settings.sandbox_provider}…",
            )
            gate_result = await verify_remediation(
                files=files,
                patched_files=patched_files,
                findings=native_findings,
                sandbox_service=sandbox,
                nebius_service=nebius,
                patches=proposals,
            )
            verification = gate_result.as_dict()
        else:
            if not nebius.configured:
                no_patch_msg = "No validated patch was prepared. Configure NEBIUS_API_KEY to enable model-assisted patch proposals."
            elif patch_messages:
                no_patch_msg = f"No validated patch was prepared. Proposal rejected: {patch_messages[-1]}"
            else:
                no_patch_msg = "No validated patch was prepared. Model proposals could not be validated against repository context."

            verification = {
                "status": "unverified",
                "sandbox_provider": settings.sandbox_provider,
                "static_recheck_passed": False,
                "security_exploit_passed": False,
                "regression_tests_passed": False,
                "static_recheck": {
                    "name": "static_recheck",
                    "status": "not_run",
                    "passed": False,
                    "message": "No patch was prepared to recheck.",
                    "details": {},
                },
                "security_exploit": {
                    "name": "security_exploit_test",
                    "status": "not_run",
                    "passed": False,
                    "message": "No patch was prepared to test.",
                    "details": {},
                },
                "regression_tests": {
                    "name": "regression_tests",
                    "status": "not_run",
                    "passed": False,
                    "message": "No patch was prepared to test.",
                    "details": {},
                },
                "tests": None,
                "message": no_patch_msg,
                "eligible_for_pr": False,
            }

        verification["scanner_runs"] = scanner_reports

        await complete_job(
            scan_id,
            worker_id=worker_id,
            message="Analysis finished.",
            stage="complete",
            findings=findings,
            patches=proposals,
            patched_files=patched_files if changed_files else {},
            changed_files=changed_files,
            diff=patch_diff,
            research=research,
            summary=summary,
            verification=verification,
            patch_messages=patch_messages,
            source_files=files,
        )

        if check_run_id:
            try:
                conc, title, summary_md, detail_text = _format_check_run_output(
                    findings=findings,
                    files_count=len(files),
                    verification=verification,
                    pr_number=int(pr_number) if pr_number else None,
                    head_sha=str(head_sha) if head_sha else None,
                    pr_changed_files=pr_changed_files,
                    summary_text=summary,
                    patch_diff=patch_diff,
                    scanner_reports=scanner_reports,
                )
                await github_app.update_check_run(
                    installation_id,
                    full_name,
                    check_run_id=int(check_run_id),
                    status="completed",
                    conclusion=conc,
                    title=title,
                    summary=summary_md,
                    text=detail_text,
                )
            except Exception as check_exc:
                logger.warning(f"Failed to update GitHub Check Run {check_run_id}: {check_exc}")
    except JobOwnershipError:
        logger.warning(f"Scan job {scan_id} aborted: worker {worker_id} lost ownership lock.")
        raise
    except Exception as exc:
        if check_run_id:
            try:
                is_unsupported = "No supported" in str(exc) or "too large" in str(exc)
                await github_app.update_check_run(
                    installation_id,
                    full_name,
                    check_run_id=int(check_run_id),
                    status="completed",
                    conclusion="neutral" if is_unsupported else "failure",
                    title="Raksa Security Review: " + ("Unsupported Repository" if is_unsupported else "Review Failed"),
                    summary=f"Security review could not be completed: {exc}",
                )
            except Exception as check_exc:
                logger.warning(f"Failed to update GitHub Check Run {check_run_id} on error: {check_exc}")

        if worker_id is None:
            # Standalone call without a worker queue runner
            await fail_job(
                scan_id,
                worker_id=None,
                error=f"{exc.__class__.__name__}: {exc}",
                retryable=False,
            )
        raise


def _unified_diff(original: dict[str, str], modified: dict[str, str]) -> str:
    chunks: list[str] = []
    for path, updated in modified.items():
        if path not in original or original[path] == updated:
            continue
        chunks.extend(difflib.unified_diff(
            original[path].splitlines(keepends=True), updated.splitlines(keepends=True),
            fromfile=f"a/{path}", tofile=f"b/{path}", n=3,
        ))
    return "".join(chunks)


def _tests_ran(result: dict[str, Any]) -> bool:
    combined = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"
    # Require real test evidence; exit code zero with unittest's 'Ran 0 tests' is not enough.
    import re
    match = re.search(r"Ran\s+(\d+)\s+tests?", combined)
    if match:
        return int(match.group(1)) > 0
    # pytest-style output also reports at least one collected/passed test.
    return bool(re.search(r"\b\d+\s+passed\b", combined, re.I))


def _format_check_run_output(
    findings: list[dict[str, Any]],
    files_count: int,
    verification: dict[str, Any],
    pr_number: int | None,
    head_sha: str | None,
    pr_changed_files: list[str],
    summary_text: str = "",
    patch_diff: str = "",
    scanner_reports: list[dict[str, Any]] | None = None,
) -> tuple[str, str, str, str | None]:
    """Return (conclusion, title, summary, text) for a GitHub Check Run."""
    partial_scan = any(s.get("status") in {"partial", "error", "unavailable"} for s in (scanner_reports or []))
    if findings:
        conclusion = "failure"
        count = len(findings)
        title = f"Raksa Security Review: {count} Potential {'Vulnerability' if count == 1 else 'Vulnerabilities'} Detected"
    else:
        conclusion = "neutral" if partial_scan else "success"
        title = ("Raksa Security Review: Scanner Coverage Incomplete" if partial_scan
                 else "Raksa Security Review: No Vulnerabilities Detected")

    lines = [
        "### Raksa Security Review Summary",
        f"- **Analyzed:** {files_count} source/test files",
    ]
    if pr_number:
        lines.append(f"- **Pull Request:** #{pr_number}")
    if head_sha:
        lines.append(f"- **Commit:** `{head_sha[:7]}`")

    if not findings:
        lines.append("\n**Result:** No SQL injection or critical security vulnerabilities detected. Scanner coverage is limited; this is not a complete audit.")
    for scanner in scanner_reports or []:
        lines.append(f"- **{scanner['name']}**: {scanner['status']} ({scanner['finding_count']} finding(s)). {scanner['message']}")
    else:
        lines.append(f"\n#### Findings ({len(findings)})")
        changed_set = set(pr_changed_files or [])
        for i, f in enumerate(findings, 1):
            sev = str(f.get("severity", "medium")).upper()
            title_f = f.get("title", "Potential Vulnerability")
            path = f.get("path", "unknown")
            line = f.get("line", 1)
            cwe = f.get("cwe") or "Unclassified"
            in_diff = " *(modified in this PR)*" if path in changed_set else ""
            evidence = f.get("evidence", "").strip()
            lines.append(f"{i}. **[{sev}] {title_f}** (`{path}:{line}`){in_diff}")
            lines.append(f"   - CWE: {cwe}; scanner: {f.get('scanner', 'raksa')}")
            if evidence:
                lines.append(f"   - Evidence: `{evidence}`")

    v_status = verification.get("status")
    if v_status == "verified":
        lines.append("\n#### Verification: Fix Verified in Sandbox")
        lines.append("- Static AST Recheck: **Passed**")
        lines.append("- Exploit Reproduction: **Passed** (reproduced on baseline, blocked on patch)")
        reg_tests = verification.get("regression_tests") or {}
        if reg_tests.get("passed"):
            lines.append("- Characterization Regression Tests: **Passed**")
    elif findings:
        v_msg = verification.get("message") or "Verification not completed."
        lines.append(f"\n#### Verification: {v_msg}")

    summary_md = "\n".join(lines)

    detail_parts = []
    if summary_text:
        detail_parts.append(f"### Remediation Analysis\n{summary_text}")
    if patch_diff:
        detail_parts.append(f"### Proposed Remediation Patch\n```diff\n{patch_diff}\n```")

    detail_text = "\n\n".join(detail_parts) if detail_parts else None
    return conclusion, title, summary_md, detail_text


def public_job(job: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "id", "status", "stage", "message", "full_name", "default_branch", "base_sha",
        "findings", "patches", "diff", "research", "summary", "verification", "pull_request_url",
        "error", "patch_messages",
    }
    return {key: value for key, value in job.items() if key in allowed}


def new_scan_id() -> str:
    return uuid.uuid4().hex
