import logging
import secrets
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse

from app.config import settings
from app.dependencies import AuthenticatedUser, get_current_user
from app.services.auth import (
    GitHubOAuthError,
    build_github_oauth_url,
    create_or_update_github_user,
    create_user_session,
    delete_user_session,
    exchange_oauth_code,
    fetch_github_user_profile,
)

logger = logging.getLogger("raksa.auth_router")
router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.get("/login")
async def auth_login(request: Request) -> RedirectResponse:
    if not settings.github_client_id or not settings.github_client_secret:
        raise HTTPException(
            503,
            "GitHub OAuth is not configured. Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET.",
        )
    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state
    oauth_url = build_github_oauth_url(settings.github_client_id, state)
    return RedirectResponse(oauth_url, status_code=307)


@router.get("/callback")
async def auth_callback(
    request: Request,
    code: str = "",
    state: str = "",
    error: str = "",
    error_description: str = "",
) -> RedirectResponse:
    base_url = settings.frontend_url.rstrip("/")

    # 1. Handle user cancellation or GitHub errors
    if error:
        logger.warning(f"GitHub OAuth error returned: {error} - {error_description}")
        err_msg = error_description or error
        return RedirectResponse(f"{base_url}/?auth_error={err_msg}", status_code=303)

    # 2. Timing-safe CSRF state validation
    expected_state = request.session.pop("oauth_state", None)
    if not expected_state or not state or not secrets.compare_digest(str(expected_state), state):
        logger.warning("OAuth callback rejected: state mismatch or missing.")
        return RedirectResponse(f"{base_url}/?auth_error=state_mismatch", status_code=303)

    if not code:
        return RedirectResponse(f"{base_url}/?auth_error=missing_code", status_code=303)

    # 3. Exchange code for access token and fetch user profile
    try:
        access_token = await exchange_oauth_code(
            settings.github_client_id,
            settings.github_client_secret,
            code,
            state,
        )
        profile = await fetch_github_user_profile(access_token)
    except GitHubOAuthError as exc:
        logger.error(f"GitHub OAuth handshake failed: {exc}")
        return RedirectResponse(f"{base_url}/?auth_error={exc}", status_code=303)

    # 4. Upsert user by stable GitHub user ID and establish workspace & session
    user, workspace, role = await create_or_update_github_user(profile)
    session_obj = await create_user_session(user["id"], workspace["id"])

    request.session["session_id"] = session_obj["id"]
    request.session["user_id"] = user["id"]
    if workspace.get("installation_id"):
        request.session["installation_id"] = str(workspace["installation_id"])

    logger.info(f"User {user['login']} (github_id: {user['github_user_id']}) logged in successfully.")
    return RedirectResponse(f"{base_url}/?auth=success", status_code=303)


@router.get("/me")
async def auth_me(auth: AuthenticatedUser = Depends(get_current_user)) -> dict[str, Any]:
    return {
        "authenticated": True,
        "user": auth.user,
        "workspace": {
            "id": auth.workspace["id"],
            "name": auth.workspace["name"],
            "role": auth.role,
            "installation_id": auth.workspace.get("installation_id"),
        },
    }


@router.post("/logout")
async def auth_logout(request: Request) -> dict[str, bool]:
    session_id = request.session.pop("session_id", None)
    if session_id:
        await delete_user_session(str(session_id))
    request.session.clear()
    return {"ok": True}
