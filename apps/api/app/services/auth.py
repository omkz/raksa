import logging
import secrets
from datetime import timedelta
from typing import Any
from urllib.parse import urlencode
from uuid import uuid4

import httpx
from sqlalchemy import delete, select

from app.config import settings
from app.db.models import User, UserSession, Workspace, WorkspaceMember, utc_now
from app.db.session import async_session_scope

logger = logging.getLogger("raksa.auth")


class GitHubOAuthError(Exception):
    """Raised when GitHub OAuth exchange or user info lookup fails."""


def build_github_oauth_url(client_id: str, state: str, redirect_uri: str | None = None) -> str:
    params = {
        "client_id": client_id,
        "state": state,
        "scope": "read:user,user:email",
    }
    if redirect_uri:
        params["redirect_uri"] = redirect_uri
    return f"https://github.com/login/oauth/authorize?{urlencode(params)}"


async def exchange_oauth_code(
    client_id: str,
    client_secret: str,
    code: str,
    state: str,
    redirect_uri: str | None = None,
) -> str:
    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "state": state,
    }
    if redirect_uri:
        payload["redirect_uri"] = redirect_uri

    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(
            "https://github.com/login/oauth/access_token",
            json=payload,
            headers={"Accept": "application/json"},
        )
        if response.status_code != 200:
            raise GitHubOAuthError(f"OAuth token endpoint returned status {response.status_code}")
        data = response.json()

    if "error" in data:
        desc = data.get("error_description", data["error"])
        raise GitHubOAuthError(f"GitHub OAuth error: {desc}")

    token = data.get("access_token")
    if not token:
        raise GitHubOAuthError("GitHub did not return an access token.")
    return str(token)


async def fetch_github_user_profile(access_token: str) -> dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": settings.github_api_version,
        "User-Agent": "raksa-appsec",
    }
    async with httpx.AsyncClient(timeout=15.0) as client:
        user_res = await client.get(f"{settings.github_api_base_url.rstrip('/')}/user", headers=headers)
        if user_res.status_code != 200:
            raise GitHubOAuthError(f"Failed to fetch GitHub user info ({user_res.status_code})")
        user_data = user_res.json()

        email = user_data.get("email")
        if not email:
            try:
                emails_res = await client.get(
                    f"{settings.github_api_base_url.rstrip('/')}/user/emails", headers=headers
                )
                if emails_res.status_code == 200:
                    for item in emails_res.json():
                        if item.get("primary"):
                            email = item.get("email")
                            break
                        if not email and item.get("email"):
                            email = item.get("email")
            except Exception as exc:
                logger.debug(f"Could not fetch user primary email: {exc}")

    return {
        "id": user_data["id"],
        "login": user_data.get("login") or f"user-{user_data['id']}",
        "name": user_data.get("name"),
        "email": email,
        "avatar_url": user_data.get("avatar_url"),
    }


async def create_or_update_github_user(
    gh_profile: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], str]:
    gh_id = int(gh_profile["id"])
    login = str(gh_profile.get("login") or f"user-{gh_id}")
    name = gh_profile.get("name")
    email = gh_profile.get("email")
    avatar = gh_profile.get("avatar_url")

    async with async_session_scope() as session:
        result = await session.execute(select(User).where(User.github_user_id == gh_id))
        user = result.scalar_one_or_none()

        if user:
            user.github_login = login
            user.name = name
            user.email = email
            user.avatar_url = avatar
            user.updated_at = utc_now()
        else:
            user = User(
                id=f"usr_{uuid4().hex[:16]}",
                github_user_id=gh_id,
                github_login=login,
                name=name,
                email=email,
                avatar_url=avatar,
            )
            session.add(user)
            await session.flush()

        # Resolve or create workspace membership
        member_result = await session.execute(
            select(WorkspaceMember, Workspace)
            .join(Workspace, Workspace.id == WorkspaceMember.workspace_id)
            .where(WorkspaceMember.user_id == user.id)
            .order_by(WorkspaceMember.created_at.asc())
        )
        membership = member_result.first()

        if membership:
            member, workspace = membership
            role = member.role
        else:
            ws_id = f"ws_{uuid4().hex[:16]}"
            workspace = Workspace(
                id=ws_id,
                name=f"{login}'s Workspace",
                owner_id=user.id,
            )
            session.add(workspace)
            await session.flush()

            member = WorkspaceMember(
                workspace_id=ws_id,
                user_id=user.id,
                role="owner",
            )
            session.add(member)
            role = "owner"

        user_dict = user.as_dict()
        workspace_dict = workspace.as_dict()

    return user_dict, workspace_dict, role


async def create_user_session(
    user_id: str,
    active_workspace_id: str,
    max_age_seconds: int = 8 * 3600,
) -> dict[str, Any]:
    session_id = secrets.token_urlsafe(32)
    expires_at = utc_now() + timedelta(seconds=max_age_seconds)

    async with async_session_scope() as session:
        user_session = UserSession(
            id=session_id,
            user_id=user_id,
            active_workspace_id=active_workspace_id,
            expires_at=expires_at,
        )
        session.add(user_session)
        await session.flush()
        session_dict = user_session.as_dict()

    return session_dict


async def get_valid_session(
    session_id: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str] | None:
    if not session_id:
        return None

    now = utc_now()
    async with async_session_scope() as session:
        result = await session.execute(
            select(UserSession).where(UserSession.id == session_id)
        )
        user_session = result.scalar_one_or_none()
        if not user_session:
            return None

        # Check expiration
        if user_session.expires_at <= now:
            await session.execute(delete(UserSession).where(UserSession.id == session_id))
            return None

        # Fetch user
        user_result = await session.execute(
            select(User).where(User.id == user_session.user_id)
        )
        user = user_result.scalar_one_or_none()
        if not user:
            await session.execute(delete(UserSession).where(UserSession.id == session_id))
            return None

        # Fetch workspace and verify membership
        target_ws_id = user_session.active_workspace_id
        member_query = (
            select(WorkspaceMember, Workspace)
            .join(Workspace, Workspace.id == WorkspaceMember.workspace_id)
            .where(WorkspaceMember.user_id == user.id)
        )
        if target_ws_id:
            member_query = member_query.where(WorkspaceMember.workspace_id == target_ws_id)

        member_result = await session.execute(member_query)
        membership = member_result.first()

        if not membership and target_ws_id:
            # Fall back to any workspace the user belongs to
            fallback_res = await session.execute(
                select(WorkspaceMember, Workspace)
                .join(Workspace, Workspace.id == WorkspaceMember.workspace_id)
                .where(WorkspaceMember.user_id == user.id)
            )
            membership = fallback_res.first()

        if not membership:
            # Create a personal workspace if none exists
            ws_id = f"ws_{uuid4().hex[:16]}"
            workspace = Workspace(
                id=ws_id,
                name=f"{user.github_login}'s Workspace",
                owner_id=user.id,
            )
            session.add(workspace)
            await session.flush()

            member = WorkspaceMember(
                workspace_id=ws_id,
                user_id=user.id,
                role="owner",
            )
            session.add(member)
            role = "owner"
            user_session.active_workspace_id = ws_id
        else:
            member, workspace = membership
            role = member.role
            user_session.active_workspace_id = workspace.id

        user_session.last_active_at = now
        session_dict = user_session.as_dict()
        user_dict = user.as_dict()
        workspace_dict = workspace.as_dict()

    return session_dict, user_dict, workspace_dict, role


async def delete_user_session(session_id: str) -> None:
    if not session_id:
        return
    async with async_session_scope() as session:
        await session.execute(delete(UserSession).where(UserSession.id == session_id))


async def user_has_workspace_access(user_id: str, workspace_id: str) -> bool:
    if not user_id or not workspace_id:
        return False
    async with async_session_scope() as session:
        result = await session.execute(
            select(WorkspaceMember).where(
                WorkspaceMember.workspace_id == workspace_id,
                WorkspaceMember.user_id == user_id,
            )
        )
        if result.scalar_one_or_none():
            return True

        ws_res = await session.execute(
            select(Workspace).where(Workspace.id == workspace_id, Workspace.owner_id == user_id)
        )
        return bool(ws_res.scalar_one_or_none())


async def set_workspace_installation_id(workspace_id: str, installation_id: str | None) -> None:
    async with async_session_scope() as session:
        result = await session.execute(select(Workspace).where(Workspace.id == workspace_id))
        ws = result.scalar_one_or_none()
        if ws:
            ws.installation_id = installation_id
            ws.updated_at = utc_now()
