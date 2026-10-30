"""CWE-22 human-in-the-loop preview safety and authorization regressions."""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.dependencies import AuthenticatedUser
from app.routers.scans import preview_context_remediation
from app.schemas import ContextRemediationRequest
from app.services.nebius import NebiusService


@pytest.mark.parametrize(
    "root",
    [
        "/etc/", "../uploads/", "uploads/../private/",
        "uploads/./", "C:/uploads/", r"uploads\private",
        "uploads/\nother", "uploads with spaces/", "uploads//nested/",
    ],
)
def test_context_authorized_root_rejects_unsafe_paths(root: str) -> None:
    with pytest.raises(ValidationError):
        ContextRemediationRequest(finding_id="cwe22", authorized_root=root)


@pytest.mark.parametrize("root, normalized", [
    ("uploads/", "uploads/"),
    ("uploads", "uploads/"),
    ("static/uploads/", "static/uploads/"),
])
def test_context_authorized_root_accepts_bounded_relative_policy(
    root: str, normalized: str
) -> None:
    value = ContextRemediationRequest(finding_id="cwe22", authorized_root=root)
    assert value.authorized_root == normalized


def _job() -> dict:
    return {
        "id": "job1",
        "workspace_id": "ws1",
        "installation_id": "inst1",
        "status": "completed",
        "full_name": "owner/demo",
        "base_sha": "sha1",
        "patches": [],
        "patch_messages": [
            "src/unsafe_path.py: AI needs context: Which directory is authorized?"
        ],
        "findings": [{
            "id": "cwe22",
            "path": "src/unsafe_path.py",
            "cwe": "CWE-22",
            "scanner": "opengrep",
            "line": 2,
            "title": "Path traversal",
        }],
    }


def _auth() -> AuthenticatedUser:
    return AuthenticatedUser(
        user={"id": "u1", "login": "tester"},
        workspace={"id": "ws1", "installation_id": "inst1"},
        session={}, role="owner",
    )


@pytest.mark.asyncio
async def test_context_preview_is_unverified_does_not_mutate_job_or_publish(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = "def read(filename):\n    return open(filename).read()\n"
    patch = {
        "path": "src/unsafe_path.py",
        "old_text": "return open(filename).read()",
        "new_text": "return read_from_approved_uploads(filename)",
        "reason": "Candidate only; containment is not verified.",
    }
    original_job = _job()
    load_job = AsyncMock(return_value=original_job)
    audit = AsyncMock()
    snapshot = AsyncMock(return_value=({"src/unsafe_path.py": source}, {}, "sha1"))
    fake_nebius = MagicMock()
    fake_nebius.configured = True
    fake_nebius.propose_patch = AsyncMock(return_value=patch)
    monkeypatch.setattr("app.routers.scans.get_job", load_job)
    monkeypatch.setattr("app.routers.scans.github_app.get_snapshot", snapshot)
    monkeypatch.setattr("app.routers.scans.nebius", fake_nebius)
    monkeypatch.setattr("app.routers.scans.record_audit_event", audit)
    forbid_mutation = AsyncMock(side_effect=AssertionError("must not mutate scan"))
    monkeypatch.setattr("app.routers.scans.update_job", forbid_mutation)

    result = await preview_context_remediation(
        "job1",
        ContextRemediationRequest(finding_id="cwe22", authorized_root="uploads/"),
        MagicMock(session={}),
        _auth(),
    )

    assert result["decision"] == "patch"
    assert result["verification"]["status"] == "unverified"
    assert result["verification"]["eligible_for_pr"] is False
    assert result["patch"]["path"] == "src/unsafe_path.py"
    assert result["patch"]["finding_id"] == "cwe22"
    assert "-    return open(filename).read()" in result["diff"]
    assert "+    return read_from_approved_uploads(filename)" in result["diff"]
    assert result["base_sha"] == "sha1"
    assert original_job["patches"] == []
    forbid_mutation.assert_not_awaited()
    assert snapshot.await_args.kwargs["commit_sha"] == "sha1"
    assert fake_nebius.propose_patch.await_args.kwargs["security_context"] == {
        "authorized_root": "uploads/"
    }
    audit.assert_awaited_once()


@pytest.mark.asyncio
async def test_context_preview_requires_same_workspace_and_installation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.routers.scans.get_job", AsyncMock(return_value=_job()))
    other_workspace = _auth()
    other_workspace.workspace = {"id": "ws2", "installation_id": "inst1"}
    monkeypatch.setattr(
        "app.routers.scans.user_has_workspace_access",
        AsyncMock(return_value=False),
    )
    with pytest.raises(HTTPException) as exc:
        await preview_context_remediation(
            "job1", ContextRemediationRequest(finding_id="cwe22", authorized_root="uploads/"),
            MagicMock(session={}), other_workspace,
        )
    assert exc.value.status_code == 404

    different_install = _auth()
    different_install.workspace = {"id": "ws1", "installation_id": "other"}
    with pytest.raises(HTTPException) as exc:
        await preview_context_remediation(
            "job1", ContextRemediationRequest(finding_id="cwe22", authorized_root="uploads/"),
            MagicMock(session={}), different_install,
        )
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_context_preview_rejects_non_context_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = _job()
    job["patch_messages"] = ["src/unsafe_path.py: AI abstained: no policy"]
    monkeypatch.setattr("app.routers.scans.get_job", AsyncMock(return_value=job))
    with pytest.raises(HTTPException) as exc:
        await preview_context_remediation(
            "job1", ContextRemediationRequest(finding_id="cwe22", authorized_root="uploads/"),
            MagicMock(session={}), _auth(),
        )
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_nebius_context_policy_sent_with_bounded_filename_constraints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    answer = {
        "decision": "needs_context", "path": "src/unsafe_path.py",
        "question": "What project-root anchor should be used for uploads/?",
    }
    service = NebiusService()
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock(
        return_value=MagicMock(
            choices=[MagicMock(message=MagicMock(content=json.dumps(answer)))]
        )
    )
    monkeypatch.setattr(service, "_client", MagicMock(return_value=fake_client))
    diagnostics: list[str] = []
    result = await service.propose_patch(
        path="src/unsafe_path.py", source="def read(name): return open(name).read()\n",
        finding={"scanner": "opengrep", "cwe": "CWE-22", "line": 1},
        diagnostics=diagnostics,
        security_context={"authorized_root": "uploads/"},
    )
    assert result is None
    assert "AI needs context:" in diagnostics[0]
    messages = fake_client.chat.completions.create.await_args.kwargs["messages"]
    supplied = json.loads(messages[1]["content"])["approved_security_policy"]
    assert supplied["authorized_root"] == "uploads/"
    assert "symlink escapes" in " ".join(supplied["constraints"])
    fake_client.chat.completions.create.assert_awaited_once()



@pytest.mark.asyncio
async def test_context_preview_rejects_snapshot_commit_mismatch_before_ai_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.routers.scans.get_job", AsyncMock(return_value=_job()))
    monkeypatch.setattr(
        "app.routers.scans.github_app.get_snapshot",
        AsyncMock(return_value=({"src/unsafe_path.py": "x = 1\n"}, {}, "another-sha")),
    )
    fake_nebius = MagicMock()
    fake_nebius.configured = True
    fake_nebius.propose_patch = AsyncMock()
    monkeypatch.setattr("app.routers.scans.nebius", fake_nebius)
    with pytest.raises(HTTPException) as exc:
        await preview_context_remediation(
            "job1", ContextRemediationRequest(finding_id="cwe22", authorized_root="uploads/"),
            MagicMock(session={}), _auth(),
        )
    assert exc.value.status_code == 409
    fake_nebius.propose_patch.assert_not_awaited()


@pytest.mark.asyncio
async def test_context_preview_needs_more_information_still_unverified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = _job()
    fake_nebius = MagicMock()
    fake_nebius.configured = True

    async def request_more(*, diagnostics: list[str], **kwargs: object) -> None:
        diagnostics.append(
            "src/unsafe_path.py: AI needs context: Is uploads/ relative to a configured app root?"
        )
        return None

    fake_nebius.propose_patch = AsyncMock(side_effect=request_more)
    monkeypatch.setattr("app.routers.scans.get_job", AsyncMock(return_value=job))
    monkeypatch.setattr(
        "app.routers.scans.github_app.get_snapshot",
        AsyncMock(return_value=({"src/unsafe_path.py": "value = 1\n"}, {}, "sha1")),
    )
    monkeypatch.setattr("app.routers.scans.nebius", fake_nebius)
    monkeypatch.setattr("app.routers.scans.record_audit_event", AsyncMock())

    response = await preview_context_remediation(
        "job1", ContextRemediationRequest(finding_id="cwe22", authorized_root="uploads/"),
        MagicMock(session={}), _auth(),
    )
    assert response["decision"] == "needs_context"
    assert response["patch"] is None
    assert response["diff"] == ""
    assert response["verification"]["status"] == "unverified"
    assert response["verification"]["eligible_for_pr"] is False
