import hashlib
import hmac
import json
import uuid
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.services.github_app import GitHubAppError, github_app, verify_webhook_signature
from app.services.job_store import get_job
from app.services.worker import ScanWorker
from app.services.workflow import run_scan_job


def sign_payload(payload_bytes: bytes, secret: str) -> str:
    mac = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def make_pr_payload(
    action: str = "opened",
    pr_number: int = 42,
    head_sha: str = "6dcb09b5b57875f334f61aebed695e2e4193db5e",
    base_sha: str = "bb6979288f98ed3c6854705a6bbde59c258700fb",
    full_name: str = "owner/repo",
    installation_id: str = "12345",
) -> dict[str, Any]:
    return {
        "action": action,
        "number": pr_number,
        "pull_request": {
            "number": pr_number,
            "title": "Add database queries",
            "head": {"sha": head_sha, "ref": "feature/query-update"},
            "base": {"sha": base_sha, "ref": "main"},
        },
        "repository": {
            "full_name": full_name,
            "name": full_name.split("/")[1],
            "default_branch": "main",
        },
        "installation": {"id": int(installation_id)},
    }


def test_verify_webhook_signature_helper() -> None:
    body = b'{"hello":"world"}'
    secret = "my-test-secret"
    sig = sign_payload(body, secret)

    # Valid signature
    assert verify_webhook_signature(body, sig, secret) is True

    # Invalid signature
    assert verify_webhook_signature(body, "sha256=wrong", secret) is False

    # Missing or empty signature
    assert verify_webhook_signature(body, None, secret) is False
    assert verify_webhook_signature(body, "", secret) is False

    # Corrupted format
    assert verify_webhook_signature(body, "invalid-format", secret) is False

    # No secret configured (dev mode)
    assert verify_webhook_signature(body, None, "") is True


def test_webhook_signature_rejection_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "github_webhook_secret", "secure-webhook-secret-123")
    payload = json.dumps(make_pr_payload()).encode("utf-8")

    with TestClient(app) as client:
        # 1. Missing signature
        res_no_sig = client.post(
            "/api/github/webhook",
            content=payload,
            headers={"Content-Type": "application/json", "X-GitHub-Event": "pull_request"},
        )
        assert res_no_sig.status_code == 401
        assert "Invalid or missing webhook signature" in res_no_sig.json()["detail"]

        # 2. Tampered signature
        res_bad_sig = client.post(
            "/api/github/webhook",
            content=payload,
            headers={
                "Content-Type": "application/json",
                "X-GitHub-Event": "pull_request",
                "X-Hub-Signature-256": "sha256=0000000000000000000000000000000000000000000000000000000000000000",
            },
        )
        assert res_bad_sig.status_code == 401

        # 3. Valid signature
        valid_sig = sign_payload(payload, "secure-webhook-secret-123")
        monkeypatch.setattr(github_app, "create_check_run", AsyncMock(return_value={"id": 999}))
        res_valid = client.post(
            "/api/github/webhook",
            content=payload,
            headers={
                "Content-Type": "application/json",
                "X-GitHub-Event": "pull_request",
                "X-Hub-Signature-256": valid_sig,
            },
        )
        assert res_valid.status_code == 200
        assert res_valid.json()["status"] == "queued"


def test_webhook_event_filtering(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "github_webhook_secret", "")

    with TestClient(app) as client:
        # 1. Missing event header
        res_no_event = client.post("/api/github/webhook", json={"some": "data"})
        assert res_no_event.status_code == 400
        assert "Missing X-GitHub-Event header" in res_no_event.json()["detail"]

        # 2. Ping event
        res_ping = client.post(
            "/api/github/webhook",
            json={"zen": "Keep it simple"},
            headers={"X-GitHub-Event": "ping"},
        )
        assert res_ping.status_code == 200
        assert res_ping.json()["status"] == "ok"

        # 3. Unsupported event (e.g. issues or push)
        res_push = client.post(
            "/api/github/webhook",
            json={"ref": "refs/heads/main"},
            headers={"X-GitHub-Event": "push"},
        )
        assert res_push.status_code == 200
        assert res_push.json()["status"] == "ignored"

        # 4. Pull request event with unsupported action (e.g. closed or labeled)
        closed_payload = make_pr_payload(action="closed")
        res_closed = client.post(
            "/api/github/webhook",
            json=closed_payload,
            headers={"X-GitHub-Event": "pull_request"},
        )
        assert res_closed.status_code == 200
        assert res_closed.json()["status"] == "ignored"
        assert "closed" in res_closed.json()["reason"]


def test_webhook_duplicate_delivery_and_head_sha_idempotency(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "github_webhook_secret", "")
    monkeypatch.setattr(github_app, "create_check_run", AsyncMock(return_value={"id": 101}))

    payload = make_pr_payload(
        action="opened",
        pr_number=55,
        head_sha="aaaabbbbcccc1111222233334444555566667777",
        full_name="org/idempotent-repo",
    )
    delivery_id = str(uuid.uuid4())

    with TestClient(app) as client:
        # First delivery
        res1 = client.post(
            "/api/github/webhook",
            json=payload,
            headers={"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": delivery_id},
        )
        assert res1.status_code == 200
        scan_id = res1.json()["scan_id"]
        assert res1.json()["status"] == "queued"

        # 1. Duplicate delivery ID (GitHub redelivery)
        res_dup_delivery = client.post(
            "/api/github/webhook",
            json=payload,
            headers={"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": delivery_id},
        )
        assert res_dup_delivery.status_code == 200
        assert res_dup_delivery.json()["status"] == "duplicate"
        assert res_dup_delivery.json()["scan_id"] == scan_id

        # 2. Repeated event for the exact same commit SHA (synchronize with same head)
        res_dup_sha = client.post(
            "/api/github/webhook",
            json=payload,
            headers={"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": str(uuid.uuid4())},
        )
        assert res_dup_sha.status_code == 200
        assert res_dup_sha.json()["status"] == "already_reviewed"
        assert res_dup_sha.json()["scan_id"] == scan_id


@pytest.mark.asyncio
async def test_pr_scan_workflow_scans_revision_and_updates_check_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "github_webhook_secret", "")

    # Mock snapshot returning vulnerable PR code at head_sha
    target_head_sha = "abcdef1234567890abcdef1234567890abcdef12"
    vulnerable_code = (
        "import sqlite3\n"
        "def query_user(user_id):\n"
        "    conn = sqlite3.connect(':memory:')\n"
        "    cursor = conn.cursor()\n"
        "    cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n"
        "    return cursor.fetchall()\n"
    )
    files = {"app/api.py": vulnerable_code}
    repo_meta = {"default_branch": "main", "full_name": "corp/service"}

    mock_get_snapshot = AsyncMock(return_value=(files, repo_meta, target_head_sha))
    mock_get_pr_files = AsyncMock(return_value=["app/api.py"])
    mock_create_check_run = AsyncMock(return_value={"id": 88888})
    mock_update_check_run = AsyncMock(return_value={"id": 88888, "status": "completed"})

    monkeypatch.setattr(github_app, "get_snapshot", mock_get_snapshot)
    monkeypatch.setattr(github_app, "get_pull_request_files", mock_get_pr_files)
    monkeypatch.setattr(github_app, "create_check_run", mock_create_check_run)
    monkeypatch.setattr(github_app, "update_check_run", mock_update_check_run)
    monkeypatch.setattr(settings, "nebius_api_key", "")
    monkeypatch.setattr("app.services.workflow.tavily.research_sql_injection", AsyncMock(return_value=[]))

    # Trigger webhook
    payload = make_pr_payload(
        action="synchronize",
        pr_number=77,
        head_sha=target_head_sha,
        full_name="corp/service",
    )
    with TestClient(app) as client:
        res = client.post(
            "/api/github/webhook",
            json=payload,
            headers={"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": str(uuid.uuid4())},
        )
        assert res.status_code == 200
        scan_id = res.json()["scan_id"]

    # Initial check run was created with in_progress
    mock_create_check_run.assert_awaited_once()
    assert mock_create_check_run.call_args.kwargs["head_sha"] == target_head_sha
    assert mock_create_check_run.call_args.kwargs["status"] == "in_progress"

    # Worker executes the scan job
    worker = ScanWorker(worker_id="test-pr-worker", poll_interval=0.1)
    processed = await worker.run_once()
    assert processed is True

    # Confirm get_snapshot was called with commit_sha=head_sha (NOT default branch!)
    mock_get_snapshot.assert_awaited_once_with(
        "12345",
        "corp/service",
        max_files=settings.max_repository_files,
        max_file_bytes=settings.max_file_bytes,
        max_repository_bytes=settings.max_repository_bytes,
        commit_sha=target_head_sha,
    )
    mock_get_pr_files.assert_awaited_once_with("12345", "corp/service", 77)

    # Check Run was updated upon scan completion
    mock_update_check_run.assert_awaited_once()
    call_kwargs = mock_update_check_run.call_args.kwargs
    assert call_kwargs["check_run_id"] == 88888
    assert call_kwargs["status"] == "completed"
    # Because SQL injection was detected in app/api.py, conclusion is "failure"
    assert call_kwargs["conclusion"] == "failure"
    assert "1 Potential Vulnerability Detected" in call_kwargs["title"]
    assert "CWE-89" in call_kwargs["summary"]
    assert "app/api.py" in call_kwargs["summary"]
    assert "(modified in this PR)" in call_kwargs["summary"]

    # Verify job state in database
    job = await get_job(scan_id)
    assert job is not None
    assert job["status"] == "completed"
    assert job["scan_type"] == "pull_request"
    assert job["head_sha"] == target_head_sha
    assert job["pr_number"] == 77
    assert len(job["findings"]) == 1


@pytest.mark.asyncio
async def test_pr_scan_workflow_clean_repository_reports_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "github_webhook_secret", "")
    clean_code = (
        "import sqlite3\n"
        "def query_user(user_id):\n"
        "    conn = sqlite3.connect(':memory:')\n"
        "    cursor = conn.cursor()\n"
        "    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n"
        "    return cursor.fetchall()\n"
    )
    files = {"app/safe.py": clean_code}
    repo_meta = {"default_branch": "main", "full_name": "corp/clean-service"}
    target_sha = "1111222233334444555566667777888899990000"

    mock_get_snapshot = AsyncMock(return_value=(files, repo_meta, target_sha))
    mock_get_pr_files = AsyncMock(return_value=["app/safe.py"])
    mock_create_check_run = AsyncMock(return_value={"id": 777})
    mock_update_check_run = AsyncMock(return_value={"id": 777, "status": "completed"})

    monkeypatch.setattr(github_app, "get_snapshot", mock_get_snapshot)
    monkeypatch.setattr(github_app, "get_pull_request_files", mock_get_pr_files)
    monkeypatch.setattr(github_app, "create_check_run", mock_create_check_run)
    monkeypatch.setattr(github_app, "update_check_run", mock_update_check_run)
    monkeypatch.setattr(settings, "nebius_api_key", "")
    monkeypatch.setattr("app.services.workflow.tavily.research_sql_injection", AsyncMock(return_value=[]))

    payload = make_pr_payload(
        action="opened",
        pr_number=88,
        head_sha=target_sha,
        full_name="corp/clean-service",
    )
    with TestClient(app) as client:
        res = client.post(
            "/api/github/webhook",
            json=payload,
            headers={"X-GitHub-Event": "pull_request"},
        )
        assert res.status_code == 200

    worker = ScanWorker(worker_id="test-clean-worker", poll_interval=0.1)
    processed = await worker.run_once()
    assert processed is True

    # Check Run was updated with "success"
    mock_update_check_run.assert_awaited_once()
    call_kwargs = mock_update_check_run.call_args.kwargs
    assert call_kwargs["conclusion"] == "success"
    assert "No Vulnerabilities Detected" in call_kwargs["title"]
    assert "No SQL injection or critical security vulnerabilities detected" in call_kwargs["summary"]


@pytest.mark.asyncio
async def test_pr_scan_workflow_handles_unsupported_repo_actionably(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "github_webhook_secret", "")
    target_sha = "2222333344445555666677778888999900001111"
    err = GitHubAppError("No supported text source files found within the configured size limits.")
    mock_get_snapshot = AsyncMock(side_effect=err)
    mock_create_check_run = AsyncMock(return_value={"id": 654})
    mock_update_check_run = AsyncMock(return_value={"id": 654, "status": "completed"})

    monkeypatch.setattr(github_app, "get_snapshot", mock_get_snapshot)
    monkeypatch.setattr(github_app, "create_check_run", mock_create_check_run)
    monkeypatch.setattr(github_app, "update_check_run", mock_update_check_run)

    payload = make_pr_payload(
        action="opened",
        pr_number=99,
        head_sha=target_sha,
        full_name="corp/unsupported-repo",
    )
    with TestClient(app) as client:
        res = client.post(
            "/api/github/webhook",
            json=payload,
            headers={"X-GitHub-Event": "pull_request"},
        )
        assert res.status_code == 200

    worker = ScanWorker(worker_id="test-unsupported-worker", poll_interval=0.1)
    processed = await worker.run_once()
    assert processed is True

    # Check run updated with neutral / unsupported repository message
    mock_update_check_run.assert_awaited_once()
    call_kwargs = mock_update_check_run.call_args.kwargs
    assert call_kwargs["conclusion"] == "neutral"
    assert "Unsupported Repository" in call_kwargs["title"]
    assert "No supported" in call_kwargs["summary"]


@pytest.mark.asyncio
async def test_check_run_creation_fails_with_missing_permissions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "github_webhook_secret", "")
    perm_err = GitHubAppError(
        "GitHub App lacks 'Checks: Read and write' permission for org/perm-repo. "
        "Please enable Checks (Read and write) in GitHub App settings."
    )
    mock_create_check_run = AsyncMock(side_effect=perm_err)
    monkeypatch.setattr(github_app, "create_check_run", mock_create_check_run)

    payload = make_pr_payload(
        action="opened",
        pr_number=102,
        head_sha="3333444455556666777788889999000011112222",
        full_name="org/perm-repo",
    )
    with TestClient(app) as client:
        res = client.post(
            "/api/github/webhook",
            json=payload,
            headers={"X-GitHub-Event": "pull_request"},
        )
        # Webhook should gracefully queue scan job even if check-run creation failed due to permission
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "queued"
        assert data["check_run_id"] is None


@pytest.mark.asyncio
async def test_pr_review_never_creates_remediation_pull_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_create_pr = AsyncMock()
    monkeypatch.setattr(github_app, "create_pull_request", mock_create_pr)

    vulnerable_code = (
        "import sqlite3\n"
        "def query_user(user_id):\n"
        "    conn = sqlite3.connect(':memory:')\n"
        "    cursor = conn.cursor()\n"
        "    cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n"
        "    return cursor.fetchall()\n"
    )
    files = {"app/routes.py": vulnerable_code}
    repo_meta = {"default_branch": "main", "full_name": "corp/safety-check"}
    target_sha = "4444555566667777888899990000111122223333"

    mock_get_snapshot = AsyncMock(return_value=(files, repo_meta, target_sha))
    mock_get_pr_files = AsyncMock(return_value=["app/routes.py"])
    mock_update_check_run = AsyncMock(return_value={"id": 555})

    monkeypatch.setattr(github_app, "get_snapshot", mock_get_snapshot)
    monkeypatch.setattr(github_app, "get_pull_request_files", mock_get_pr_files)
    monkeypatch.setattr(github_app, "update_check_run", mock_update_check_run)
    monkeypatch.setattr(settings, "nebius_api_key", "")
    monkeypatch.setattr("app.services.workflow.tavily.research_sql_injection", AsyncMock(return_value=[]))

    scan_id = "pr-safety-test-123"
    await run_scan_job(scan_id, "12345", "corp/safety-check", worker_id=None)

    # CRITICAL: Confirm create_pull_request was NEVER called
    mock_create_pr.assert_not_called()
