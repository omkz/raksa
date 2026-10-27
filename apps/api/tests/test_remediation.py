import json
import sqlite3
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.analyzer import (
    apply_exact_replacements,
    detect_sql_injection,
    validate_patch_proposal,
)
from app.services.nebius import NebiusService
from app.services.workflow import run_scan_job
from app.state import get_job, put_job

VULNERABLE_CODE = (
    "import sqlite3\n\n"
    "def get_user(conn, name):\n"
    "    query = f\"SELECT * FROM users WHERE name = '{name}'\"\n"
    "    return conn.execute(query).fetchall()\n"
)


def test_valid_multiline_parameterized_sql_patch() -> None:
    """A valid multi-line patch replaces both query construction and execution call."""
    findings = detect_sql_injection({"app.py": VULNERABLE_CODE})
    assert len(findings) == 1

    proposal = {
        "path": "app.py",
        "old_text": (
            '    query = f"SELECT * FROM users WHERE name = \'{name}\'"\n'
            '    return conn.execute(query).fetchall()'
        ),
        "new_text": (
            '    query = "SELECT * FROM users WHERE name = ?"\n'
            '    return conn.execute(query, (name,)).fetchall()'
        ),
        "reason": "Parameterize query using SQLite placeholder and pass parameter tuple",
    }

    validated, error = validate_patch_proposal(proposal, "app.py", VULNERABLE_CODE)
    assert error is None
    assert validated == proposal

    patched_files = apply_exact_replacements({"app.py": VULNERABLE_CODE}, [proposal])
    assert "WHERE name = ?" in patched_files["app.py"]
    assert "execute(query, (name,))" in patched_files["app.py"]

    # Recheck detection: finding must be resolved
    recheck_findings = detect_sql_injection(patched_files)
    assert recheck_findings == []

    # Execute with sqlite3 to verify runtime behavior
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (name TEXT)")
    conn.execute("INSERT INTO users VALUES ('alice'), ('bob')")

    scope: dict[str, Any] = {}
    exec(patched_files["app.py"], scope)
    # Expected match
    assert len(scope["get_user"](conn, "alice")) == 1
    # Injection payload blocked by parameterization
    assert len(scope["get_user"](conn, "' OR '1'='1")) == 0


def test_rejection_reasons_all_six_categories() -> None:
    """Validate that every rejection category is precisely identified:
    1. invalid JSON
    2. wrong path
    3. missing replacement text
    4. source context mismatch
    5. non-unique match
    6. unchanged patch
    """
    source = "def foo():\n    return 'secret'\n"

    # 1. Invalid JSON (non-dict proposal)
    val, err = validate_patch_proposal("not a dict", "app.py", source)
    assert val is None
    assert err is not None
    assert "Invalid JSON" in err

    # 2. Wrong path (missing path, wrong target path, unsafe path)
    val, err = validate_patch_proposal({"old_text": "secret", "new_text": "safe"}, "app.py", source)
    assert val is None
    assert err is not None
    assert "Wrong path" in err
    assert "missing" in err

    val, err = validate_patch_proposal({"path": "other.py", "old_text": "secret", "new_text": "safe"}, "app.py", source)
    assert val is None
    assert err is not None
    assert "Wrong path" in err
    assert "targets 'other.py'" in err

    val, err = validate_patch_proposal({"path": "../secret.py", "old_text": "secret", "new_text": "safe"}, "../secret.py", source)
    assert val is None
    assert err is not None
    assert "Wrong path" in err
    assert "Unsafe patch path" in err

    # 3. Missing replacement text (missing old_text or new_text)
    val, err = validate_patch_proposal({"path": "app.py", "old_text": "", "new_text": "safe"}, "app.py", source)
    assert val is None
    assert err is not None
    assert "Missing replacement text" in err
    assert "'old_text' is missing" in err

    val, err = validate_patch_proposal({"path": "app.py", "old_text": "secret", "new_text": ""}, "app.py", source)
    assert val is None
    assert err is not None
    assert "Missing replacement text" in err
    assert "'new_text' is missing" in err

    # 4. Source context mismatch (old_text not found in source)
    val, err = validate_patch_proposal({"path": "app.py", "old_text": "not_in_source", "new_text": "safe"}, "app.py", source)
    assert val is None
    assert err is not None
    assert "Source context mismatch" in err
    assert "old_text was not found" in err

    # 5. Non-unique match (old_text appears multiple times)
    dup_source = "x = 1\nx = 1\n"
    val, err = validate_patch_proposal({"path": "app.py", "old_text": "x = 1", "new_text": "x = 2"}, "app.py", dup_source)
    assert val is None
    assert err is not None
    assert "Non-unique match" in err
    assert "matched 2 times" in err

    # 6. Unchanged patch (identical old and new text, or no source change)
    val, err = validate_patch_proposal({"path": "app.py", "old_text": "return 'secret'", "new_text": "return 'secret'"}, "app.py", source)
    assert val is None
    assert err is not None
    assert "Unchanged patch" in err
    assert "identical" in err


def test_apply_exact_replacements_strict_validation() -> None:
    """apply_exact_replacements strictly enforces path and context rules."""
    files = {"app.py": "def foo():\n    return 'secret'\n"}

    # Unsafe path
    with pytest.raises(ValueError, match="Wrong path"):
        apply_exact_replacements(files, [{"path": "../app.py", "old_text": "secret", "new_text": "safe"}])

    # Missing replacement text
    with pytest.raises(ValueError, match="Missing replacement text"):
        apply_exact_replacements(files, [{"path": "app.py", "old_text": "", "new_text": "safe"}])

    # Unchanged patch
    with pytest.raises(ValueError, match="Unchanged patch"):
        apply_exact_replacements(files, [{"path": "app.py", "old_text": "secret", "new_text": "secret"}])

    # Source context mismatch
    with pytest.raises(ValueError, match="Source context mismatch"):
        apply_exact_replacements(files, [{"path": "app.py", "old_text": "missing_token", "new_text": "safe"}])

    # Non-unique match
    dup_files = {"app.py": "dup = 1\ndup = 1\n"}
    with pytest.raises(ValueError, match="Non-unique match"):
        apply_exact_replacements(dup_files, [{"path": "app.py", "old_text": "dup = 1", "new_text": "dup = 2"}])


@pytest.mark.asyncio
async def test_invalid_model_response_followed_by_valid_retry() -> None:
    """When attempt 1 returns an invalid proposal, a corrective retry is sent with source context and succeeds."""
    nebius = NebiusService()
    mock_client = MagicMock()

    # Attempt 1 returns malformed response (missing old_text)
    attempt1_choice = MagicMock()
    attempt1_choice.message.content = json.dumps({
        "path": "app.py",
        "old_text": "",
        "new_text": "some new text",
    })
    resp1 = MagicMock()
    resp1.choices = [attempt1_choice]

    # Attempt 2 (retry) returns valid proposal
    valid_proposal = {
        "path": "app.py",
        "old_text": (
            '    query = f"SELECT * FROM users WHERE name = \'{name}\'"\n'
            '    return conn.execute(query).fetchall()'
        ),
        "new_text": (
            '    query = "SELECT * FROM users WHERE name = ?"\n'
            '    return conn.execute(query, (name,)).fetchall()'
        ),
        "reason": "Parameterized query",
    }
    attempt2_choice = MagicMock()
    attempt2_choice.message.content = json.dumps(valid_proposal)
    resp2 = MagicMock()
    resp2.choices = [attempt2_choice]

    mock_client.chat.completions.create = AsyncMock(side_effect=[resp1, resp2])
    nebius._client = MagicMock(return_value=mock_client)

    finding = {"path": "app.py", "line": 4, "title": "SQLi"}
    diagnostics: list[str] = []

    proposal = await nebius.propose_patch(
        path="app.py",
        source=VULNERABLE_CODE,
        finding=finding,
        diagnostics=diagnostics,
    )

    assert proposal is not None
    assert proposal["path"] == "app.py"
    assert proposal["new_text"] == valid_proposal["new_text"]

    # Verify 2 calls were made
    assert mock_client.chat.completions.create.call_count == 2
    retry_call_args = mock_client.chat.completions.create.call_args_list[1]
    retry_messages = retry_call_args.kwargs["messages"]
    # 4 messages: system, user, assistant, corrective user
    assert len(retry_messages) == 4
    assert retry_messages[2]["role"] == "assistant"
    assert retry_messages[3]["role"] == "user"
    # Corrective user message contains validation error AND original source context
    assert "Missing replacement text" in retry_messages[3]["content"]
    assert "Original source of app.py" in retry_messages[3]["content"]
    assert "SELECT * FROM users" in retry_messages[3]["content"]

    # Verify diagnostics recorded the retry recovery
    assert any("Initial proposal required retry" in d for d in diagnostics)


@pytest.mark.asyncio
async def test_all_proposals_rejected_with_useful_diagnostic() -> None:
    """When all proposals fail validation, useful diagnostics are preserved."""
    nebius = NebiusService()
    mock_client = MagicMock()

    # Both attempts fail with source context mismatch
    bad_proposal = {
        "path": "app.py",
        "old_text": "non_existent_statement()",
        "new_text": "safe_statement()",
    }
    resp1 = MagicMock()
    resp1.choices = [MagicMock(message=MagicMock(content=json.dumps(bad_proposal)))]
    resp2 = MagicMock()
    resp2.choices = [MagicMock(message=MagicMock(content=json.dumps(bad_proposal)))]

    mock_client.chat.completions.create = AsyncMock(side_effect=[resp1, resp2])
    nebius._client = MagicMock(return_value=mock_client)

    finding = {"path": "app.py", "line": 4, "title": "SQLi"}
    diagnostics: list[str] = []

    proposal = await nebius.propose_patch(
        path="app.py",
        source=VULNERABLE_CODE,
        finding=finding,
        diagnostics=diagnostics,
    )

    assert proposal is None
    assert len(diagnostics) == 1
    assert "Proposal rejected after retry" in diagnostics[0]
    assert "Source context mismatch" in diagnostics[0]


@pytest.mark.asyncio
async def test_failed_proposal_for_one_finding_does_not_prevent_other_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    """A failed proposal for one finding must not block proposals for subsequent findings (partial success)."""
    source_one = (
        "def query_one(conn, name):\n"
        "    q = f\"SELECT * FROM users WHERE name = '{name}'\"\n"
        "    return conn.execute(q).fetchall()\n"
    )
    source_two = (
        "def query_two(conn, role):\n"
        "    q = f\"SELECT * FROM roles WHERE role = '{role}'\"\n"
        "    return conn.execute(q).fetchall()\n"
    )

    files = {
        "one.py": source_one,
        "two.py": source_two,
    }

    class MockNebiusService:
        configured = True

        async def summarize_findings(self, findings: list[dict[str, Any]], repo_files: dict[str, str]) -> str:
            return "Summary"

        async def propose_patch(
            self, *, path: str, source: str, finding: dict[str, Any], diagnostics: list[str] | None = None
        ) -> dict[str, str] | None:
            if path == "one.py":
                if diagnostics is not None:
                    diagnostics.append(f"{path}: Proposal rejected after retry. Initial error: Source context mismatch. Retry error: Source context mismatch.")
                return None
            if path == "two.py":
                return {
                    "path": "two.py",
                    "old_text": (
                        '    q = f"SELECT * FROM roles WHERE role = \'{role}\'"\n'
                        '    return conn.execute(q).fetchall()'
                    ),
                    "new_text": (
                        '    q = "SELECT * FROM roles WHERE role = ?"\n'
                        '    return conn.execute(q, (role,)).fetchall()'
                    ),
                    "reason": "Parameterize query for two.py",
                }
            return None

        async def generate_exploit_test(self, *, path: str, source: str, finding: dict[str, Any]) -> None:
            return None

    monkeypatch.setattr("app.services.workflow.nebius", MockNebiusService())
    monkeypatch.setattr(
        "app.services.workflow.github_app.get_snapshot",
        AsyncMock(return_value=(files, {"default_branch": "main"}, "basesha123")),
    )

    scan_id = "test-multi-finding"
    await put_job(scan_id, {
        "id": scan_id, "status": "queued", "stage": "queued", "message": "Scan queued.",
        "full_name": "owner/repo", "installation_id": "123",
    })

    # Run the workflow
    await run_scan_job(scan_id, "123", "owner/repo")

    job = await get_job(scan_id)
    assert job is not None
    assert job["status"] == "completed"

    # Finding for one.py failed, but two.py patch succeeded!
    assert len(job["patches"]) == 1
    assert job["patches"][0]["path"] == "two.py"
    assert "WHERE role = ?" in job["patched_files"]["two.py"]
    assert "one.py: Proposal rejected after retry" in job["patch_messages"][0]


@pytest.mark.asyncio
async def test_no_validated_patch_does_not_say_configure_nebius_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    """When Nebius IS configured, rejection message must explain the proposal failure, NOT say 'Configure Nebius'."""
    files = {
        "app.py": VULNERABLE_CODE,
    }

    class MockFailingNebiusService:
        configured = True

        async def summarize_findings(self, findings: list[dict[str, Any]], repo_files: dict[str, str]) -> str:
            return "Summary"

        async def propose_patch(
            self, *, path: str, source: str, finding: dict[str, Any], diagnostics: list[str] | None = None
        ) -> dict[str, str] | None:
            if diagnostics is not None:
                diagnostics.append(f"{path}: Proposal rejected after retry. Initial error: Source context mismatch. Retry error: Source context mismatch.")
            return None

        async def generate_exploit_test(self, *, path: str, source: str, finding: dict[str, Any]) -> None:
            return None

    monkeypatch.setattr("app.services.workflow.nebius", MockFailingNebiusService())
    monkeypatch.setattr(
        "app.services.workflow.github_app.get_snapshot",
        AsyncMock(return_value=(files, {"default_branch": "main"}, "basesha123")),
    )

    scan_id = "test-nebius-configured-failure"
    await put_job(scan_id, {
        "id": scan_id, "status": "queued", "stage": "queued", "message": "Scan queued.",
        "full_name": "owner/repo", "installation_id": "123",
    })

    await run_scan_job(scan_id, "123", "owner/repo")

    job = await get_job(scan_id)
    assert job is not None
    assert job["status"] == "completed"
    assert job["patches"] == []
    verification_msg = job["verification"]["message"]
    # MUST NOT show "Configure Nebius" when Nebius is already configured!
    assert "Configure Nebius" not in verification_msg
    assert "No validated patch was prepared" in verification_msg
    assert "Proposal rejected" in verification_msg
