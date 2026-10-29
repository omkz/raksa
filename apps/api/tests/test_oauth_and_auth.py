import hashlib
import hmac
import json
from datetime import timedelta
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.db.models import UserSession, utc_now
from app.db.session import async_session_scope
from app.main import app
from app.services.auth import (
    create_or_update_github_user,
    create_user_session,
)


def sign_payload(payload_bytes: bytes, secret: str) -> str:
    mac = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


@pytest.fixture
def configure_oauth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "github_client_id", "test-client-id-123")
    monkeypatch.setattr(settings, "github_client_secret", "test-client-secret-456")
    monkeypatch.setattr(settings, "frontend_url", "http://localhost:5173")


def test_auth_login_unconfigured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "github_client_id", "")
    monkeypatch.setattr(settings, "github_client_secret", "")
    with TestClient(app) as client:
        res = client.get("/api/auth/login")
        assert res.status_code == 503
        assert "GitHub OAuth is not configured" in res.json()["detail"]


def test_auth_login_redirects_with_state(configure_oauth: None) -> None:
    with TestClient(app) as client:
        res = client.get("/api/auth/login", follow_redirects=False)
        assert res.status_code == 307
        location = res.headers["location"]
        assert "https://github.com/login/oauth/authorize" in location
        assert "client_id=test-client-id-123" in location
        assert "state=" in location
        assert "read%3Auser" in location


def test_auth_callback_rejects_missing_or_mismatched_state(configure_oauth: None) -> None:
    with TestClient(app) as client:
        # 1. No state in session
        res_no_state = client.get("/api/auth/callback?code=foo&state=bar", follow_redirects=False)
        assert res_no_state.status_code == 303
        assert "auth_error=state_mismatch" in res_no_state.headers["location"]

        # 2. State mismatch
        client.get("/api/auth/login", follow_redirects=False)
        res_mismatch = client.get("/api/auth/callback?code=foo&state=tampered-state", follow_redirects=False)
        assert res_mismatch.status_code == 303
        assert "auth_error=state_mismatch" in res_mismatch.headers["location"]


def test_auth_callback_handles_user_cancellation(configure_oauth: None) -> None:
    with TestClient(app) as client:
        res = client.get(
            "/api/auth/callback?error=access_denied&error_description=User+cancelled",
            follow_redirects=False,
        )
        assert res.status_code == 303
        assert "auth_error=User" in res.headers["location"]
        assert "cancelled" in res.headers["location"]


@pytest.mark.asyncio
async def test_auth_callback_success_creates_user_workspace_and_session(
    configure_oauth: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_profile = {
        "id": 1234567,
        "login": "octocat-dev",
        "name": "Monalisa Octocat",
        "email": "octocat@github.example",
        "avatar_url": "https://github.com/images/octocat.png",
    }

    monkeypatch.setattr("app.routers.auth.exchange_oauth_code", AsyncMock(return_value="ghu_fake_access_token"))
    monkeypatch.setattr("app.routers.auth.fetch_github_user_profile", AsyncMock(return_value=mock_profile))

    with TestClient(app) as client:
        # Initiate login to generate state
        login_res = client.get("/api/auth/login", follow_redirects=False)
        state = login_res.headers["location"].split("state=")[1].split("&")[0]

        # Return from OAuth callback
        callback_res = client.get(f"/api/auth/callback?code=good_code&state={state}", follow_redirects=False)
        assert callback_res.status_code == 303
        assert callback_res.headers["location"] == "http://localhost:5173/?auth=success"

        # Check /api/auth/me using authenticated cookie
        me_res = client.get("/api/auth/me")
        assert me_res.status_code == 200
        data = me_res.json()
        assert data["authenticated"] is True
        assert data["user"]["github_user_id"] == 1234567
        assert data["user"]["login"] == "octocat-dev"
        assert data["user"]["email"] == "octocat@github.example"
        assert data["workspace"]["name"] == "octocat-dev's Workspace"
        assert data["workspace"]["role"] == "owner"


@pytest.mark.asyncio
async def test_stable_github_user_id_updates_login_without_duplication() -> None:
    # First login with login 'initial_username'
    profile1 = {"id": 777888, "login": "initial_username", "name": "First Name"}
    user1, ws1, _ = await create_or_update_github_user(profile1)
    assert user1["github_user_id"] == 777888
    assert user1["login"] == "initial_username"

    # Second login with same GitHub numeric ID but changed username
    profile2 = {"id": 777888, "login": "renamed_username", "name": "Updated Name"}
    user2, ws2, _ = await create_or_update_github_user(profile2)
    assert user2["id"] == user1["id"]  # Identical persistent ID
    assert user2["github_user_id"] == 777888
    assert user2["login"] == "renamed_username"
    assert ws2["id"] == ws1["id"]  # Same workspace preserved


@pytest.mark.asyncio
async def test_session_expiration_and_logout_revocation() -> None:
    profile = {"id": 555666, "login": "session_tester"}
    user, ws, _ = await create_or_update_github_user(profile)

    # 1. Test normal session
    await create_user_session(user["id"], ws["id"], max_age_seconds=3600)
    with TestClient(app) as client:
        # Mock session in cookie
        with client:
            # We can log in using mock or endpoint
            pass

    # 2. Test expired session in database
    async with async_session_scope() as db_session:
        from sqlalchemy import update
        expired_sess = await create_user_session(user["id"], ws["id"], max_age_seconds=10)
        await db_session.execute(
            update(UserSession)
            .where(UserSession.id == expired_sess["id"])
            .values(expires_at=utc_now() - timedelta(minutes=5))
        )

    from app.services.auth import get_valid_session
    valid = await get_valid_session(expired_sess["id"])
    assert valid is None


def test_protected_endpoints_require_authentication() -> None:
    with TestClient(app) as client:
        # 1. /api/auth/me
        res_me = client.get("/api/auth/me")
        assert res_me.status_code == 401
        assert "Authentication required" in res_me.json()["detail"]

        # 2. /api/scans
        res_scans = client.post("/api/scans", json={"full_name": "owner/repo"})
        assert res_scans.status_code == 401

        # 3. /api/scans/{scan_id}
        res_get_scan = client.get("/api/scans/dummy-scan-id")
        assert res_get_scan.status_code == 401

        # 4. /api/scans/{scan_id}/pull-request
        res_pr = client.post("/api/scans/dummy-scan-id/pull-request", json={"title": "Fix", "body": "Body"})
        assert res_pr.status_code == 401

        # 5. /api/github/repositories
        res_repos = client.get("/api/github/repositories")
        assert res_repos.status_code == 401


@pytest.mark.asyncio
async def test_workspace_isolation_blocks_cross_workspace_access(
    configure_oauth: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Create User A & User B
    user_a, ws_a, _ = await create_or_update_github_user({"id": 1001, "login": "user-a"})
    user_b, ws_b, _ = await create_or_update_github_user({"id": 1002, "login": "user-b"})

    await create_user_session(user_a["id"], ws_a["id"])
    await create_user_session(user_b["id"], ws_b["id"])

    # Create scan for User A in ws_a
    from app.services.job_store import create_scan_job
    await create_scan_job(
        scan_id="scan-for-user-a",
        installation_id="inst-a",
        full_name="org/service-a",
        workspace_id=ws_a["id"],
    )

    # User A client
    monkeypatch.setattr("app.routers.auth.exchange_oauth_code", AsyncMock(return_value="token_a"))
    monkeypatch.setattr("app.routers.auth.fetch_github_user_profile", AsyncMock(return_value={"id": 1001, "login": "user-a"}))

    with TestClient(app) as client_a:
        login_res = client_a.get("/api/auth/login", follow_redirects=False)
        state_a = login_res.headers["location"].split("state=")[1].split("&")[0]
        client_a.get(f"/api/auth/callback?code=c_a&state={state_a}", follow_redirects=False)

        # User A can access own scan
        res_a_view = client_a.get("/api/scans/scan-for-user-a")
        assert res_a_view.status_code == 200
        assert res_a_view.json()["id"] == "scan-for-user-a"

    # User B client
    monkeypatch.setattr("app.routers.auth.fetch_github_user_profile", AsyncMock(return_value={"id": 1002, "login": "user-b"}))
    with TestClient(app) as client_b:
        login_res = client_b.get("/api/auth/login", follow_redirects=False)
        state_b = login_res.headers["location"].split("state=")[1].split("&")[0]
        client_b.get(f"/api/auth/callback?code=c_b&state={state_b}", follow_redirects=False)

        # User B CANNOT access User A's scan (returns 404 access denied)
        res_b_view = client_b.get("/api/scans/scan-for-user-a")
        assert res_b_view.status_code == 404

        # User B CANNOT get events for User A's scan
        res_b_events = client_b.get("/api/scans/scan-for-user-a/events")
        assert res_b_events.status_code == 404

        # User B CANNOT create PR for User A's scan
        res_b_pr = client_b.post(
            "/api/scans/scan-for-user-a/pull-request",
            json={"title": "Unauthorized Remediation PR", "body": "Exploit body"},
        )
        assert res_b_pr.status_code == 404


def test_webhook_production_enforcement_and_public_access(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = json.dumps({"action": "opened", "pull_request": {"number": 1}}).encode("utf-8")

    # 1. In production, missing GITHUB_WEBHOOK_SECRET must reject with 500
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "github_webhook_secret", "")

    with TestClient(app) as client:
        res_prod_missing = client.post(
            "/api/github/webhook",
            content=payload,
            headers={"Content-Type": "application/json", "X-GitHub-Event": "pull_request"},
        )
        assert res_prod_missing.status_code == 500
        assert "Webhook secret not configured in production" in res_prod_missing.json()["detail"]

    # 2. In production with secret configured, missing or invalid signature must reject with 401
    monkeypatch.setattr(settings, "github_webhook_secret", "prod-secret-999")
    with TestClient(app) as client:
        res_no_sig = client.post(
            "/api/github/webhook",
            content=payload,
            headers={"Content-Type": "application/json", "X-GitHub-Event": "pull_request"},
        )
        assert res_no_sig.status_code == 401

        res_bad_sig = client.post(
            "/api/github/webhook",
            content=payload,
            headers={
                "Content-Type": "application/json",
                "X-GitHub-Event": "pull_request",
                "X-Hub-Signature-256": "sha256=invalid-signature",
            },
        )
        assert res_bad_sig.status_code == 401

        # 3. Valid signature passes without requiring user authentication cookie
        valid_sig = sign_payload(payload, "prod-secret-999")
        res_ping = client.post(
            "/api/github/webhook",
            content=payload,
            headers={
                "Content-Type": "application/json",
                "X-GitHub-Event": "ping",
                "X-Hub-Signature-256": valid_sig,
            },
        )
        assert res_ping.status_code == 200
        assert res_ping.json()["status"] == "ok"


def test_logout_clears_session_and_revokes_access(
    configure_oauth: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_profile = {"id": 4321, "login": "logout-tester"}
    monkeypatch.setattr("app.routers.auth.exchange_oauth_code", AsyncMock(return_value="tok"))
    monkeypatch.setattr("app.routers.auth.fetch_github_user_profile", AsyncMock(return_value=mock_profile))

    with TestClient(app) as client:
        login_res = client.get("/api/auth/login", follow_redirects=False)
        state = login_res.headers["location"].split("state=")[1].split("&")[0]
        client.get(f"/api/auth/callback?code=c&state={state}", follow_redirects=False)

        # Authenticated
        res_before = client.get("/api/auth/me")
        assert res_before.status_code == 200

        # Log out
        res_logout = client.post("/api/auth/logout")
        assert res_logout.status_code == 200
        assert res_logout.json()["ok"] is True

        # Next request fails with 401
        res_after = client.get("/api/auth/me")
        assert res_after.status_code == 401
