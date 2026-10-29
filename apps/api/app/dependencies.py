from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, Request

from app.services.auth import get_valid_session


@dataclass
class AuthenticatedUser:
    user: dict[str, Any]
    workspace: dict[str, Any]
    session: dict[str, Any]
    role: str

    @property
    def user_id(self) -> str:
        return str(self.user["id"])

    @property
    def workspace_id(self) -> str:
        return str(self.workspace["id"])


async def get_current_user(request: Request) -> AuthenticatedUser:
    session_id = request.session.get("session_id")
    if not session_id:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Please log in with GitHub.",
        )

    result = await get_valid_session(str(session_id))
    if not result:
        request.session.clear()
        raise HTTPException(
            status_code=401,
            detail="Session expired or invalid. Please log in again.",
        )

    sess, user, ws, role = result
    return AuthenticatedUser(user=user, workspace=ws, session=sess, role=role)


async def get_optional_user(request: Request) -> AuthenticatedUser | None:
    session_id = request.session.get("session_id")
    if not session_id:
        return None

    result = await get_valid_session(str(session_id))
    if not result:
        request.session.clear()
        return None

    sess, user, ws, role = result
    return AuthenticatedUser(user=user, workspace=ws, session=sess, role=role)
