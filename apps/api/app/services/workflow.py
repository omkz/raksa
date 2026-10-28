import difflib
import uuid
from typing import Any

from app.config import settings
from app.services.analyzer import apply_exact_replacements, detect_sql_injection
from app.services.github_app import github_app
from app.services.nebius import NebiusUnavailable, nebius
from app.services.sandbox import sandbox
from app.services.tavily import tavily
from app.services.verifier import verify_remediation
from app.state import update_job


async def run_scan_job(scan_id: str, installation_id: str, full_name: str) -> None:
    await update_job(scan_id, status="running", stage="fetching", message="Fetching a bounded repository snapshot…")
    try:
        files, repo_meta, base_sha = await github_app.get_snapshot(
            installation_id,
            full_name,
            max_files=settings.max_repository_files,
            max_file_bytes=settings.max_file_bytes,
            max_repository_bytes=settings.max_repository_bytes,
        )
        await update_job(
            scan_id, full_name=full_name, default_branch=repo_meta.get("default_branch", "main"),
            base_sha=base_sha, status="running", stage="analyzing",
            message=f"Analyzing {len(files)} source and test files for potential SQL injection…",
            source_files=files,
        )
        findings = detect_sql_injection(files, max_findings=settings.max_findings)
        research: list[dict[str, str]] = []
        if findings:
            try:
                research = await tavily.research_sql_injection()
            except Exception as exc:
                research = [{"title": "Security research unavailable", "url": "", "content": f"Tavily request failed: {exc.__class__.__name__}"}]

        summary = ""
        if findings and nebius.configured:
            try:
                summary = await nebius.summarize_findings(findings, files)
            except NebiusUnavailable as exc:
                summary = str(exc)
        elif not nebius.configured:
            summary = "Nemotron analysis skipped: configure NEBIUS_API_KEY to enable model reasoning and patch proposals."

        proposals: list[dict[str, str]] = []
        candidate_proposals: list[dict[str, str]] = []
        patched_files = dict(files)
        patch_messages: list[str] = []
        if findings and nebius.configured:
            await update_job(scan_id, stage="remediating", message="Requesting a constrained remediation proposal from Nemotron…")
            for finding in findings[:3]:
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
            await update_job(scan_id, stage="verifying", message=f"Running security verification gate via {settings.sandbox_provider}…")
            gate_result = await verify_remediation(
                files=files,
                patched_files=patched_files,
                findings=findings,
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

        await update_job(
            scan_id, status="completed", stage="complete", message="Analysis finished.",
            findings=findings, patches=proposals, patched_files=patched_files if changed_files else {},
            changed_files=changed_files, diff=patch_diff, research=research, summary=summary,
            verification=verification, patch_messages=patch_messages,
            source_files=files,
        )
    except Exception as exc:
        await update_job(scan_id, status="failed", stage="failed", message="Repository analysis failed.", error=f"{exc.__class__.__name__}: {exc}")


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


def public_job(job: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "id", "status", "stage", "message", "full_name", "default_branch", "base_sha",
        "findings", "patches", "diff", "research", "summary", "verification", "pull_request_url",
        "error", "patch_messages",
    }
    return {key: value for key, value in job.items() if key in allowed}


def new_scan_id() -> str:
    return uuid.uuid4().hex
