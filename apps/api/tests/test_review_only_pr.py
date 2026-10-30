"""Review-only PRs use a pinned GitHub snapshot, not unstored ScanJob sources."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app.dependencies import AuthenticatedUser
from app.routers.scans import create_pull_request
from app.schemas import CreatePRRequest


def _auth() -> AuthenticatedUser:
    return AuthenticatedUser(
        user={"id": "user-1", "login": "reviewer"},
        workspace={"id": "ws-1", "installation_id": "install-1"},
        session={},
        role="owner",
    )


def _original_files() -> dict[str, str]:
    return {
        "app.py": (
            "import sqlite3\n"
            "def search(connection: sqlite3.Connection, name: str):\n"
            "    query = f\"SELECT * FROM users WHERE name = '{name}'\"\n"
            "    return connection.execute(query).fetchall()\n"
        ),
        "src/unsafe_xss.js": (
            "export function show(container, message) {\n"
            "  container.innerHTML = message;\n"
            "}\n"
        ),
        "src/unsafe_path.py": "def read(path):\n    return open(path).read()\n",
    }


def _scan_job() -> dict:
    return {
        "id": "review-scan",
        "workspace_id": "ws-1",
        "installation_id": "install-1",
        "full_name": "owner/demo",
        "base_sha": "a" * 40,
        "status": "completed",
        "verification": {
            "status": "unverified",
            "eligible_for_pr": False,
            "review_pr_finding_ids": ["sql", "xss"],
        },
        "changed_files": {"src/unsafe_path.py": "UNSAFE AGGREGATE DIFF"},
        "patches": [
            {
                "finding_id": "sql",
                "cwe": "CWE-89",
                "path": "app.py",
                "old_text": (
                    "    query = f\"SELECT * FROM users WHERE name = '{name}'\"\n"
                    "    return connection.execute(query).fetchall()"
                ),
                "new_text": (
                    '    query = "SELECT * FROM users WHERE name = ?"\n'
                    "    return connection.execute(query, (name,)).fetchall()"
                ),
            },
            {
                "finding_id": "xss",
                "cwe": "CWE-79",
                "path": "src/unsafe_xss.js",
                "old_text": "container.innerHTML = message",
                "new_text": "container.textContent = message",
            },
            {
                "finding_id": "path",
                "cwe": "CWE-22",
                "path": "src/unsafe_path.py",
                "old_text": "open(path)",
                "new_text": "open(__import__('os').path.basename(path))",
            },
        ],
    }


@pytest.mark.asyncio
async def test_review_only_pr_reloads_pinned_snapshot_and_excludes_unsafe_patches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No source_files key: this reproduces real ScanJob serialization.
    scan = _scan_job()
    mock_snapshot = AsyncMock(return_value=(_original_files(), {}, "a" * 40))
    mock_create = AsyncMock(return_value={
        "html_url": "https://github.com/owner/demo/pull/3",
        "branch": "raksa/fix-review-scan",
    })
    monkeypatch.setattr("app.routers.scans.get_job", AsyncMock(return_value=scan))
    monkeypatch.setattr("app.routers.scans.github_app.get_snapshot", mock_snapshot)
    monkeypatch.setattr("app.routers.scans.github_app.create_pull_request", mock_create)
    monkeypatch.setattr("app.routers.scans.update_job", AsyncMock())
    monkeypatch.setattr("app.routers.scans.record_audit_event", AsyncMock())

    result = await create_pull_request(
        "review-scan",
        CreatePRRequest(review_only=True, title="Review security fixes", body="Human review"),
        MagicMock(session={}),
        _auth(),
    )

    assert result["url"] == "https://github.com/owner/demo/pull/3"
    assert mock_snapshot.await_args.kwargs["commit_sha"] == "a" * 40
    assert mock_snapshot.await_args.args == ("install-1", "owner/demo")
    published = mock_create.await_args.kwargs
    assert set(published["files"]) == {"app.py", "src/unsafe_xss.js"}
    assert 'connection.execute(query, (name,)).fetchall()' in published["files"]["app.py"]
    assert "textContent" in published["files"]["src/unsafe_xss.js"]
    assert published["title"].startswith("[UNVERIFIED")
    assert "Do NOT merge" in published["body"]
    assert published["expected_base_sha"] == "a" * 40


@pytest.mark.asyncio
async def test_review_only_pr_rejects_snapshot_sha_mismatch_without_publishing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.routers.scans.get_job", AsyncMock(return_value=_scan_job()))
    monkeypatch.setattr(
        "app.routers.scans.github_app.get_snapshot",
        AsyncMock(return_value=(_original_files(), {}, "b" * 40)),
    )
    mock_create = AsyncMock()
    monkeypatch.setattr("app.routers.scans.github_app.create_pull_request", mock_create)

    with pytest.raises(HTTPException) as exc:
        await create_pull_request(
            "review-scan",
            CreatePRRequest(review_only=True),
            MagicMock(session={}),
            _auth(),
        )
    assert exc.value.status_code == 409
    mock_create.assert_not_awaited()


@pytest.mark.asyncio
async def test_unverified_pr_requires_explicit_review_only_consent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.routers.scans.get_job", AsyncMock(return_value=_scan_job()))
    mock_snapshot = AsyncMock()
    monkeypatch.setattr("app.routers.scans.github_app.get_snapshot", mock_snapshot)
    with pytest.raises(HTTPException) as exc:
        await create_pull_request(
            "review-scan",
            CreatePRRequest(review_only=False),
            MagicMock(session={}),
            _auth(),
        )
    assert exc.value.status_code == 409
    mock_snapshot.assert_not_awaited()
