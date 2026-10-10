from fastapi import APIRouter, HTTPException, Request

from app.schemas import CreatePRRequest, ScanRequest
from app.services.demo_proof import FIXED_SNIPPET, VULNERABLE_SNIPPET, run_demo_proof
from app.services.github_app import GitHubAppError, github_app
from app.services.workflow import new_scan_id, public_job, run_scan_job
from app.state import get_job, put_job, update_job

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("")
async def create_scan(payload: ScanRequest, request: Request) -> dict[str, object]:
    installation_id = request.session.get("installation_id")
    if not installation_id:
        raise HTTPException(401, "Connect the Raksa GitHub App first.")
    scan_id = new_scan_id()
    await put_job(scan_id, {
        "id": scan_id, "status": "queued", "stage": "queued", "message": "Scan queued.",
        "full_name": payload.full_name, "installation_id": str(installation_id),
    })
    import asyncio
    asyncio.create_task(run_scan_job(scan_id, str(installation_id), payload.full_name))
    return {"id": scan_id, "status": "queued"}


@router.get("/{scan_id}")
async def get_scan(scan_id: str) -> dict[str, object]:
    job = await get_job(scan_id)
    if not job:
        raise HTTPException(404, "Scan not found or expired after API restart.")
    return public_job(job)


@router.post("/{scan_id}/pull-request")
async def create_pull_request(scan_id: str, payload: CreatePRRequest, request: Request) -> dict[str, str]:
    job = await get_job(scan_id)
    if not job:
        raise HTTPException(404, "Scan not found or expired after API restart.")
    if job.get("status") != "completed":
        raise HTTPException(409, "Wait for the scan to complete before creating a pull request.")
    if not (job.get("verification") or {}).get("eligible_for_pr"):
        raise HTTPException(409, "PR creation is disabled because the proposed fix has not passed required verification.")
    installation_id = request.session.get("installation_id")
    if not installation_id or str(installation_id) != str(job.get("installation_id")):
        raise HTTPException(401, "Reconnect the same GitHub installation used for this scan.")
    if not job.get("changed_files") or not job.get("base_sha"):
        raise HTTPException(409, "This scan has no verified code changes to publish.")
    try:
        pr = await github_app.create_pull_request(
            str(installation_id), str(job["full_name"]),
            expected_base_sha=str(job["base_sha"]),
            files=dict(job["changed_files"]), title=payload.title, body=payload.body, scan_id=scan_id,
        )
    except GitHubAppError as exc:
        raise HTTPException(409 if "changed after this scan" in str(exc) else 502, str(exc)) from exc
    await update_job(scan_id, pull_request_url=pr.get("html_url"), stage="pull_request_created",
                     message="A draft pull request was created. Review it before merging.")
    return {"url": str(pr.get("html_url", "")), "branch": str(pr.get("branch", ""))}


@router.post("/demo/run")
async def run_demo() -> dict[str, object]:
    """Run a deterministic, in-memory SQL-injection proof without external credentials."""
    result = run_demo_proof()
    scan_id = new_scan_id()
    diff = (
        "--- a/app.py\n+++ b/app.py\n@@\n-" + VULNERABLE_SNIPPET.replace("\n", "\n-")
        + "\n+" + FIXED_SNIPPET.replace("\n", "\n+") + "\n"
    )
    job = {
        "id": scan_id, "status": "completed", "stage": "complete",
        "message": "Controlled SQL injection demo completed.", "full_name": None,
        "findings": [{
            "id": "demo-sqli", "title": "SQL Injection", "severity": "high", "cwe": "CWE-89",
            "path": "app.py", "line": 1, "evidence": VULNERABLE_SNIPPET.splitlines()[0],
            "description": "A controlled SQLite proof shows that string interpolation lets the payload alter query semantics.",
            "confidence": 1.0, "status": "reproduced",
        }],
        "patches": [{"path": "app.py", "old_text": VULNERABLE_SNIPPET, "new_text": FIXED_SNIPPET,
                     "reason": "Use a parameterized SQL query so user input is treated as data."}],
        "diff": diff, "research": [], "summary": "This demo is a deterministic SQLite proof, not an LLM claim.",
        "verification": {**result, "eligible_for_pr": False, "provider": "local-proof-harness"},
        "pull_request_url": None,
    }
    await put_job(scan_id, job)
    return public_job(job)
