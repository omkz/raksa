import difflib
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from app.config import settings
from app.dependencies import AuthenticatedUser, get_current_user, get_optional_user
from app.schemas import ContextRemediationRequest, CreatePRRequest, ScanRequest
from app.services.analyzer import apply_exact_replacements
from app.services.auth import user_has_workspace_access
from app.services.cwe22_verifier import assess_cwe22_candidate
from app.services.demo_proof import FIXED_SNIPPET, VULNERABLE_SNIPPET, run_demo_proof
from app.services.github_app import GitHubAppError, github_app
from app.services.job_store import (
    create_scan_job,
    get_job,
    list_audit_events,
    put_job,
    record_audit_event,
    update_job,
)
from app.services.nebius import NebiusUnavailable, nebius
from app.services.workflow import new_scan_id, public_job

router = APIRouter(prefix="/api/scans", tags=["scans"])


async def _assert_scan_workspace_access(job: dict[str, Any], auth: AuthenticatedUser) -> None:
    job_ws = job.get("workspace_id")
    if job_ws and job_ws != auth.workspace_id:
        has_access = await user_has_workspace_access(auth.user_id, job_ws)
        if not has_access:
            raise HTTPException(404, "Scan not found.")


@router.post("")
async def create_scan(
    payload: ScanRequest,
    request: Request,
    auth: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, object]:
    installation_id = auth.workspace.get("installation_id") or request.session.get("installation_id")
    if not installation_id:
        raise HTTPException(401, "Connect the Raksa GitHub App first.")
    scan_id = new_scan_id()
    await create_scan_job(
        scan_id=scan_id,
        installation_id=str(installation_id),
        full_name=payload.full_name,
        actor=f"user:{auth.user['login']}",
        workspace_id=auth.workspace_id,
    )
    return {"id": scan_id, "status": "queued"}


@router.get("/{scan_id}")
async def get_scan(
    scan_id: str,
    auth: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, object]:
    job = await get_job(scan_id)
    if not job:
        raise HTTPException(404, "Scan not found.")
    await _assert_scan_workspace_access(job, auth)
    return public_job(job)


@router.get("/{scan_id}/events")
async def get_scan_events(
    scan_id: str,
    auth: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, object]:
    job = await get_job(scan_id)
    if not job:
        raise HTTPException(404, "Scan not found.")
    await _assert_scan_workspace_access(job, auth)
    events = await list_audit_events(scan_id=scan_id)
    return {"scan_id": scan_id, "events": events}


@router.post("/{scan_id}/context-remediation")
async def preview_context_remediation(
    scan_id: str,
    payload: ContextRemediationRequest,
    request: Request,
    auth: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Preview a CWE-22 patch using a developer-approved root at the pinned commit.

    This never updates the scan's patch set, verification, changed files or PR
    eligibility, and never executes repository code.
    """
    job = await get_job(scan_id)
    if not job:
        raise HTTPException(404, "Scan not found.")
    await _assert_scan_workspace_access(job, auth)
    if job.get("status") != "completed" or not job.get("base_sha"):
        raise HTTPException(409, "Complete a scan before answering remediation context.")
    if not job.get("full_name"):
        raise HTTPException(409, "Scan has no repository snapshot.")
    installation_id = auth.workspace.get("installation_id") or request.session.get("installation_id")
    if not installation_id or str(installation_id) != str(job.get("installation_id")):
        raise HTTPException(401, "Reconnect the original GitHub installation.")

    finding = next(
        (item for item in job.get("findings", []) if item.get("id") == payload.finding_id),
        None,
    )
    if finding is None or finding.get("cwe") != "CWE-22" or finding.get("scanner") != "opengrep":
        raise HTTPException(404, "CWE-22 OpenGrep finding not found in this scan.")
    path = str(finding["path"])
    if not any(
        message.startswith(f"{path}:") and "AI needs context:" in message
        for message in (job.get("patch_messages") or [])
    ):
        raise HTTPException(409, "This finding did not request developer context.")
    if any(
        patch.get("finding_id") == payload.finding_id
        for patch in (job.get("patches") or [])
    ):
        raise HTTPException(409, "This finding already has a candidate patch.")
    if not nebius.configured:
        raise HTTPException(503, "Configure NEBIUS_API_KEY first.")

    try:
        files, _meta, snapshot_sha = await github_app.get_snapshot(
            str(installation_id), str(job["full_name"]),
            max_files=settings.max_repository_files,
            max_file_bytes=settings.max_file_bytes,
            max_repository_bytes=settings.max_repository_bytes,
            commit_sha=str(job["base_sha"]),
        )
    except GitHubAppError as exc:
        raise HTTPException(502, "Could not fetch the pinned repository snapshot.") from exc
    if snapshot_sha != job["base_sha"]:
        raise HTTPException(409, "Snapshot commit does not match the original scan.")
    source = files.get(path)
    if source is None:
        raise HTTPException(409, "Scanned file unavailable at the pinned commit.")

    diagnostics: list[str] = []
    try:
        patch = await nebius.propose_patch(
            path=path, source=source, finding=finding, diagnostics=diagnostics,
            security_context={"authorized_root": payload.authorized_root},
        )
    except NebiusUnavailable as exc:
        raise HTTPException(502, "Nemotron remediation proposal unavailable.") from exc

    if patch is not None:
        try:
            patched = apply_exact_replacements({path: source}, [patch])
        except ValueError as exc:
            diagnostics.append(f"{path}: Contextual candidate rejected: {exc}")
            patch = None

    diff = ""
    if patch is not None:
        diff = "".join(difflib.unified_diff(
            source.splitlines(keepends=True),
            patched[path].splitlines(keepends=True),
            fromfile=f"a/{path}", tofile=f"b/{path}",
        ))
    evidence = (
        assess_cwe22_candidate(
            path=path,
            original=source,
            patched=patched[path],
            authorized_root=payload.authorized_root,
        )
        if patch is not None else {
            "status": "unverified",
            "eligible_for_pr": False,
            "message": (
                "No CWE-22 patch candidate was produced. "
                "Category-specific security and regression tests did not run."
            ),
        }
    )
    decision = (
        "patch" if patch is not None
        else "needs_context" if any("AI needs context:" in d for d in diagnostics)
        else "abstain" if any("AI abstained:" in d for d in diagnostics)
        else "rejected"
    )
    await record_audit_event(
        event_type="remediation.context_preview",
        scan_id=scan_id, actor=f"user:{auth.user['login']}",
        details={
            "finding_id": payload.finding_id, "path": path,
            "authorized_root": payload.authorized_root,
            "decision": decision, "base_sha": snapshot_sha,
        },
    )
    return {
        "decision": decision, "finding_id": payload.finding_id,
        "path": path, "authorized_root": payload.authorized_root,
        "base_sha": snapshot_sha,
        "patch": (
            {**patch, "scanner": "opengrep", "cwe": "CWE-22",
             "finding_id": payload.finding_id}
            if patch is not None else None
        ),
        "diff": diff, "diagnostics": diagnostics,
        "verification": evidence,
    }


@router.post("/{scan_id}/pull-request")
async def create_pull_request(
    scan_id: str,
    payload: CreatePRRequest,
    request: Request,
    auth: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, str]:
    job = await get_job(scan_id)
    if not job:
        raise HTTPException(404, "Scan not found.")
    await _assert_scan_workspace_access(job, auth)

    if job.get("status") != "completed":
        raise HTTPException(409, "Wait for the scan to complete before creating a pull request.")
    verification = job.get("verification") or {}
    verified = bool(verification.get("eligible_for_pr"))
    if not verified and not payload.review_only:
        raise HTTPException(409, "Explicit review-only approval is required for unverified patches.")
    if not verified and not verification.get("review_pr_finding_ids"):
        raise HTTPException(409, "No eligible review-only candidates. Re-scan with the current Raksa version.")

    installation_id = auth.workspace.get("installation_id") or request.session.get("installation_id")
    if not installation_id or str(installation_id) != str(job.get("installation_id")):
        raise HTTPException(401, "Reconnect the same GitHub installation used for this scan.")
    if not job.get("changed_files") or not job.get("base_sha"):
        raise HTTPException(409, "This scan has no candidate code changes to publish.")

    pr_files = dict(job["changed_files"])
    pr_title = payload.title
    pr_body = payload.body
    if not verified:
        # Reconstruct only approved review candidates from original source;
        # never publish the scan's aggregate diff with excluded patches.
        from app.services.workflow import reviewable_patch

        allowed_ids = set(verification["review_pr_finding_ids"])
        selected = [
            patch for patch in (job.get("patches") or [])
            if patch.get("finding_id") in allowed_ids and reviewable_patch(patch)
        ]
        if not selected:
            raise HTTPException(409, "No eligible review-only patches remain.")
        original = job.get("source_files") or {}
        if not original or any(patch.get("path") not in original for patch in selected):
            raise HTTPException(409, "Original scan source is unavailable; run a new scan.")
        try:
            selected_patched = apply_exact_replacements(dict(original), selected)
        except ValueError as exc:
            raise HTTPException(409, "Review candidate no longer matches scanned source.") from exc
        pr_files = {
            path: content for path, content in selected_patched.items()
            if path in original and content != original[path]
        }
        if not pr_files:
            raise HTTPException(409, "Selected candidates produced no changes.")
        pr_title = "[UNVERIFIED — REVIEW ONLY] " + payload.title
        pr_body = (
            "## UNVERIFIED — HUMAN REVIEW REQUIRED\n\n"
            "This is a DRAFT PR containing limited AI-proposed code changes. "
            "No category-specific security exploit or regression verification "
            "has been established for these changes. Do NOT merge without review and tests.\n\n"
            "Only selected CWE-89/CWE-79 candidates are included; other findings "
            "and proposed fixes were deliberately excluded.\n\n"
            + payload.body
        )

    try:
        pr = await github_app.create_pull_request(
            str(installation_id),
            str(job["full_name"]),
            expected_base_sha=str(job["base_sha"]),
            files=pr_files,
            title=pr_title,
            body=pr_body,
            scan_id=scan_id,
        )
    except GitHubAppError as exc:
        raise HTTPException(409 if "changed after this scan" in str(exc) else 502, str(exc)) from exc

    await update_job(
        scan_id,
        pull_request_url=pr.get("html_url"),
        stage="pull_request_created",
        message="A draft pull request was created. Review it before merging.",
    )
    await record_audit_event(
        event_type="pull_request.created",
        scan_id=scan_id,
        actor=f"user:{auth.user['login']}",
        details={"html_url": pr.get("html_url"), "branch": pr.get("branch")},
    )
    return {"url": str(pr.get("html_url", "")), "branch": str(pr.get("branch", ""))}


@router.post("/demo/run")
async def run_demo(
    auth: AuthenticatedUser | None = Depends(get_optional_user),
) -> dict[str, object]:
    """Run a deterministic, in-memory SQL-injection proof without external credentials."""
    result = run_demo_proof()
    scan_id = new_scan_id()
    diff = (
        "--- a/app.py\n+++ b/app.py\n@@\n-" + VULNERABLE_SNIPPET.replace("\n", "\n-")
        + "\n+" + FIXED_SNIPPET.replace("\n", "\n+") + "\n"
    )
    workspace_id = auth.workspace_id if auth else "default"
    actor = f"user:{auth.user['login']}" if auth else "demo"

    job = {
        "id": scan_id,
        "workspace_id": workspace_id,
        "status": "completed",
        "stage": "complete",
        "message": "Controlled SQL injection demo completed.",
        "full_name": None,
        "findings": [{
            "id": "demo-sqli",
            "title": "SQL Injection",
            "severity": "high",
            "cwe": "CWE-89",
            "path": "app.py",
            "line": 1,
            "evidence": VULNERABLE_SNIPPET.splitlines()[0],
            "description": "A controlled SQLite proof shows that string interpolation lets the payload alter query semantics.",
            "confidence": 1.0,
            "status": "reproduced",
        }],
        "patches": [{
            "path": "app.py",
            "old_text": VULNERABLE_SNIPPET,
            "new_text": FIXED_SNIPPET,
            "reason": "Use a parameterized SQL query so user input is treated as data.",
        }],
        "diff": diff,
        "research": [],
        "summary": "This demo is a deterministic SQLite proof, not an LLM claim.",
        "verification": {**result, "eligible_for_pr": False, "provider": "local-proof-harness"},
        "pull_request_url": None,
    }
    await put_job(scan_id, job)
    await record_audit_event(
        event_type="scan.demo_completed",
        scan_id=scan_id,
        actor=actor,
        details={"verification": result},
    )
    return public_job(job)
