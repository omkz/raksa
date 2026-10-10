import secrets
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from app.config import settings
from app.services.github_app import GitHubAppError, github_app

router = APIRouter(prefix="/api/github", tags=["github"])


@router.get("/status")
async def github_status(request: Request) -> dict[str, object]:
    installation_id = request.session.get("installation_id")
    return {
        "configured": github_app.configured,
        "connected": bool(installation_id),
        "installation_id": str(installation_id) if installation_id else None,
        "app_slug": settings.github_app_slug or None,
    }


@router.get("/install-url")
async def github_install_url(request: Request) -> dict[str, str]:
    if not github_app.configured:
        raise HTTPException(503, "Configure GITHUB_APP_ID, GITHUB_APP_SLUG, and GITHUB_PRIVATE_KEY(_PATH) first.")
    state = secrets.token_urlsafe(24)
    request.session["github_install_state"] = state
    install_url = f"https://github.com/apps/{settings.github_app_slug}/installations/new?{urlencode({'state': state})}"
    return {"url": install_url}


@router.get("/callback")
async def github_callback(request: Request, installation_id: str = "", setup_action: str = "", state: str = "") -> RedirectResponse:
    expected = request.session.pop("github_install_state", None)
    if not expected or not state or not secrets.compare_digest(str(expected), state):
        raise HTTPException(400, "GitHub installation state did not match. Start the connection flow again.")
    if setup_action not in {"install", "update", "request"} or not installation_id.isdigit():
        raise HTTPException(400, "GitHub did not return a valid installation. Try connecting again.")
    request.session["installation_id"] = installation_id
    return RedirectResponse(f"{settings.frontend_url.rstrip('/')}/?github=connected", status_code=303)


@router.post("/disconnect")
async def github_disconnect(request: Request) -> dict[str, bool]:
    request.session.pop("installation_id", None)
    return {"connected": False}


@router.get("/repositories")
async def github_repositories(request: Request) -> list[dict[str, object]]:
    installation_id = request.session.get("installation_id")
    if not installation_id:
        raise HTTPException(401, "Connect the Raksa GitHub App first.")
    try:
        return await github_app.list_repositories(str(installation_id))
    except GitHubAppError as exc:
        raise HTTPException(502, str(exc)) from exc
