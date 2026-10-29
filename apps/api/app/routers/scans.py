from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from app.dependencies import AuthenticatedUser, get_current_user, get_optional_user
from app.schemas import CreatePRRequest, ScanRequest
from app.services.auth import user_has_workspace_access
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
    if not (job.get("verification") or {}).get("eligible_for_pr"):
        raise HTTPException(409, "PR creation is disabled because the proposed fix has not passed required verification.")

    installation_id = auth.workspace.get("installation_id") or request.session.get("installation_id")
    if not installation_id or str(installation_id) != str(job.get("installation_id")):
        raise HTTPException(401, "Reconnect the same GitHub installation used for this scan.")
    if not job.get("changed_files") or not job.get("base_sha"):
        raise HTTPException(409, "This scan has no verified code changes to publish.")

    try:
        pr = await github_app.create_pull_request(
            str(installation_id),
            str(job["full_name"]),
            expected_base_sha=str(job["base_sha"]),
            files=dict(job["changed_files"]),
            title=payload.title,
            body=payload.body,
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
