import json
import logging
import secrets
import uuid
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse

from app.config import settings
from app.dependencies import AuthenticatedUser, get_current_user, get_optional_user
from app.services.auth import set_workspace_installation_id
from app.services.github_app import GitHubAppError, github_app, verify_webhook_signature
from app.state import create_scan_job, get_active_job_by_head_sha, get_job_by_delivery_id

logger = logging.getLogger("raksa.github_router")
router = APIRouter(prefix="/api/github", tags=["github"])


@router.get("/status")
async def github_status(
    request: Request,
    auth: AuthenticatedUser | None = Depends(get_optional_user),
) -> dict[str, object]:
    installation_id = None
    if auth:
        installation_id = auth.workspace.get("installation_id") or request.session.get("installation_id")
    else:
        installation_id = request.session.get("installation_id")

    return {
        "configured": github_app.configured,
        "connected": bool(installation_id),
        "installation_id": str(installation_id) if installation_id else None,
        "app_slug": settings.github_app_slug or None,
        "authenticated": bool(auth),
    }


@router.get("/install-url")
async def github_install_url(
    request: Request,
    auth: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, str]:
    if not github_app.configured:
        raise HTTPException(503, "Configure GITHUB_APP_ID, GITHUB_APP_SLUG, and GITHUB_PRIVATE_KEY(_PATH) first.")
    state = secrets.token_urlsafe(24)
    request.session["github_install_state"] = state
    install_url = f"https://github.com/apps/{settings.github_app_slug}/installations/new?{urlencode({'state': state})}"
    return {"url": install_url}


@router.get("/callback")
async def github_callback(
    request: Request,
    installation_id: str = "",
    setup_action: str = "",
    state: str = "",
    auth: AuthenticatedUser = Depends(get_current_user),
) -> RedirectResponse:
    expected = request.session.pop("github_install_state", None)
    if not expected or not state or not secrets.compare_digest(str(expected), state):
        raise HTTPException(400, "GitHub installation state did not match. Start the connection flow again.")
    if setup_action not in {"install", "update", "request"} or not installation_id.isdigit():
        raise HTTPException(400, "GitHub did not return a valid installation. Try connecting again.")

    # Save to user's workspace and session
    await set_workspace_installation_id(auth.workspace_id, installation_id)
    request.session["installation_id"] = installation_id
    return RedirectResponse(f"{settings.frontend_url.rstrip('/')}/?github=connected", status_code=303)


@router.post("/disconnect")
async def github_disconnect(
    request: Request,
    auth: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, bool]:
    await set_workspace_installation_id(auth.workspace_id, None)
    request.session.pop("installation_id", None)
    return {"connected": False}


@router.get("/repositories")
async def github_repositories(
    request: Request,
    auth: AuthenticatedUser = Depends(get_current_user),
) -> list[dict[str, object]]:
    installation_id = auth.workspace.get("installation_id") or request.session.get("installation_id")
    if not installation_id:
        raise HTTPException(401, "Connect the Raksa GitHub App first.")
    try:
        return await github_app.list_repositories(str(installation_id))
    except GitHubAppError as exc:
        raise HTTPException(502, str(exc)) from exc


@router.post("/webhook")
async def github_webhook(request: Request) -> dict[str, Any]:
    raw_body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")

    # 1. Reject requests in production if webhook secret is missing
    if settings.app_env == "production" and not settings.github_webhook_secret:
        logger.error("GitHub webhook rejected: GITHUB_WEBHOOK_SECRET is not configured in production.")
        raise HTTPException(500, "Webhook secret not configured in production.")

    # 2. Verify webhook signature if secret configured
    if settings.github_webhook_secret:
        if not verify_webhook_signature(raw_body, signature, settings.github_webhook_secret):
            raise HTTPException(401, "Invalid or missing webhook signature.")

    # 2. Verify event type
    event = request.headers.get("X-GitHub-Event")
    if not event:
        raise HTTPException(400, "Missing X-GitHub-Event header.")

    if event == "ping":
        return {"status": "ok", "message": "Pong"}

    if event != "pull_request":
        return {"status": "ignored", "reason": f"Event '{event}' is not handled."}

    # 3. Check delivery ID idempotency
    delivery_id = request.headers.get("X-GitHub-Delivery")
    if delivery_id:
        existing = await get_job_by_delivery_id(delivery_id)
        if existing:
            return {
                "status": "duplicate",
                "scan_id": existing["id"],
                "message": f"Webhook delivery {delivery_id} already processed.",
            }

    # 4. Parse payload and filter actions
    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(400, "Invalid JSON payload.") from exc

    action = payload.get("action")
    if action not in {"opened", "synchronize"}:
        return {
            "status": "ignored",
            "reason": f"Pull request action '{action}' does not trigger a security review.",
        }

    # 5. Extract PR information
    installation_id = str(payload.get("installation", {}).get("id") or "")
    repository = payload.get("repository", {})
    full_name = repository.get("full_name")
    pr = payload.get("pull_request", {})
    pr_number = pr.get("number")
    head = pr.get("head", {})
    head_sha = head.get("sha")
    base = pr.get("base", {})
    base_sha = base.get("sha")

    if not installation_id or not full_name or not pr_number or not head_sha:
        raise HTTPException(400, "Malformed pull_request payload: missing required fields.")

    # 6. Idempotency by commit SHA
    existing_scan = await get_active_job_by_head_sha(full_name, head_sha)
    if existing_scan and existing_scan.get("status") in {"queued", "running", "completed"}:
        return {
            "status": "already_reviewed",
            "scan_id": existing_scan["id"],
            "message": f"Scan for commit {head_sha} is already {existing_scan.get('status')}.",
        }

    # 7. Create Check Run on GitHub
    check_run_id = None
    try:
        check_run = await github_app.create_check_run(
            installation_id,
            full_name,
            head_sha=head_sha,
            name="Raksa Security Review",
            status="in_progress",
            title="Raksa Security Review in progress",
            summary=f"Analyzing pull request #{pr_number} (commit {head_sha[:7]}) for potential security vulnerabilities…",
        )
        check_run_id = check_run.get("id")
    except GitHubAppError as exc:
        logger.warning(f"Could not create Check Run for {full_name}@{head_sha}: {exc}")

    # 8. Create scan job in durable store
    scan_id = f"pr-{uuid.uuid4().hex[:12]}"
    await create_scan_job(
        scan_id=scan_id,
        installation_id=installation_id,
        full_name=full_name,
        workspace_id="default",
        scan_type="pull_request",
        pr_number=pr_number,
        head_sha=head_sha,
        base_sha=base_sha,
        check_run_id=check_run_id,
        delivery_id=delivery_id,
        actor=f"github-pr:{pr_number}",
        message=f"Queued pull request security review for PR #{pr_number} ({head_sha[:7]}).",
    )

    return {
        "status": "queued",
        "scan_id": scan_id,
        "pr_number": pr_number,
        "head_sha": head_sha,
        "check_run_id": check_run_id,
    }
