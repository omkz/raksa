"""Regression tests for scanner-aware AI proposals and verification boundaries."""
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.scanners.base import ScannerResult, SecurityFinding
from app.scanners.opengrep import RULES_FILE
from app.services.nebius import NebiusService
from app.services.workflow import run_scan_job
from app.state import get_job, put_job


def test_owned_rules_include_xss_and_request_path_access() -> None:
    rules = RULES_FILE.read_text(encoding="utf-8")
    assert "id: raksa.javascript-html-injection" in rules
    assert "cwe: CWE-79" in rules
    assert "$NODE.innerHTML = $HTML" in rules
    assert "id: raksa.python-request-file-access" in rules
    assert "id: raksa.javascript-request-file-access" in rules
    assert "cwe: CWE-22" in rules
    assert "open(request.args.get($KEY), ...)" in rules


@pytest.mark.asyncio
async def test_opengrep_patch_prompt_is_generic_not_sql_only() -> None:
    service = NebiusService()
    mock_client = MagicMock()
    source = "function render(target, value) { target.innerHTML = value; }\n"
    patch = {
        "path": "src/view.js",
        "old_text": "target.innerHTML = value",
        "new_text": "target.textContent = value",
        "reason": "Avoid inserting unsanitized HTML",
    }
    mock_client.chat.completions.create = AsyncMock(
        return_value=MagicMock(
            choices=[MagicMock(message=MagicMock(content=json.dumps(patch)))]
        )
    )
    service._client = MagicMock(return_value=mock_client)
    result = await service.propose_patch(
        path="src/view.js",
        source=source,
        finding={"scanner": "opengrep", "cwe": "CWE-79", "line": 1, "title": "Potential XSS"},
    )
    assert result == patch
    messages = mock_client.chat.completions.create.call_args.kwargs["messages"]
    assert "XSS" in messages[0]["content"]
    assert "SQL injection" not in messages[0]["content"]
    assert "CWE-79" in messages[1]["content"]


@pytest.mark.asyncio
async def test_mixed_sql_and_opengrep_ai_patches_cannot_pass_sqli_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = {
        "app.py": (
            "import sqlite3\n"
            "def query_users(conn, name):\n"
            "    query = f\"SELECT * FROM users WHERE name = '{name}'\"\n"
            "    return conn.execute(query).fetchall()\n"
        ),
        "view.js": "function render(node, value) {\n  node.innerHTML = value;\n}\n",
    }

    async def propose_patch(
        *, path: str, source: str, finding: dict[str, Any],
        diagnostics: list[str] | None = None,
    ) -> dict[str, str]:
        if path == "view.js":
            return {
                "path": path, "old_text": "node.innerHTML = value",
                "new_text": "node.textContent = value",
                "reason": "Use a text sink instead of HTML",
            }
        return {
            "path": path,
            "old_text": '    query = f"SELECT * FROM users WHERE name = \'{name}\'"',
            "new_text": '    query = "SELECT * FROM users WHERE name = ?"',
            "reason": "Example patch proposal only; not verified",
        }

    fake_nebius = MagicMock()
    fake_nebius.configured = True
    fake_nebius.propose_patch = AsyncMock(side_effect=propose_patch)
    fake_nebius.summarize_findings = AsyncMock(return_value="Static findings are potential.")
    monkeypatch.setattr("app.services.workflow.nebius", fake_nebius)
    monkeypatch.setattr(
        "app.services.workflow.github_app.get_snapshot",
        AsyncMock(return_value=(files, {"default_branch": "main"}, "base123")),
    )
    opengrep_finding = SecurityFinding(
        id="xss-1", title="Potential XSS", severity="medium", path="view.js",
        line=2, evidence="node.innerHTML = value", description="DOM HTML sink",
        confidence=0.65, scanner="opengrep", rule_id="raksa.javascript-html-injection",
        cwe="CWE-79",
    )
    monkeypatch.setattr(
        "app.services.workflow.scan_snapshot",
        AsyncMock(return_value=[ScannerResult("opengrep", "completed", [opengrep_finding])]),
    )
    monkeypatch.setattr(
        "app.services.workflow.tavily.research_sql_injection",
        AsyncMock(return_value=[]),
    )
    gate = AsyncMock(side_effect=AssertionError("SQLi-only gate must not verify mixed patches"))
    monkeypatch.setattr("app.services.workflow.verify_remediation", gate)

    scan_id = "test-mixed-generic-ai-unverified"
    await put_job(scan_id, {
        "id": scan_id, "status": "queued", "stage": "queued", "message": "Scan queued.",
        "full_name": "owner/repo", "installation_id": "123",
    })
    await run_scan_job(scan_id, "123", "owner/repo")

    job = await get_job(scan_id)
    assert job is not None
    assert job["status"] == "completed"
    assert len(job["patches"]) == 2
    assert {p["scanner"] for p in job["patches"]} == {"raksa", "opengrep"}
    assert {p["cwe"] for p in job["patches"]} == {"CWE-89", "CWE-79"}
    assert "node.textContent" in job["patched_files"]["view.js"]
    assert job["verification"]["status"] == "unverified"
    assert job["verification"]["eligible_for_pr"] is False
    assert "manual review" in job["verification"]["message"]
    gate.assert_not_awaited()


def test_patch_api_schema_preserves_scanner_provenance() -> None:
    from app.schemas import PatchProposal

    data = PatchProposal.model_validate({
        "path": "view.js",
        "old_text": "node.innerHTML = value",
        "new_text": "node.textContent = value",
        "reason": "DOM XSS proposal",
        "scanner": "opengrep",
        "cwe": "CWE-79",
        "finding_id": "xss-1",
    }).model_dump()
    assert data["scanner"] == "opengrep"
    assert data["cwe"] == "CWE-79"
    assert data["finding_id"] == "xss-1"


@pytest.mark.asyncio
async def test_opengrep_only_finding_produces_unverified_patch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = {"view.js": "function render(node, value) {\n  node.innerHTML = value;\n}\n"}
    finding = SecurityFinding(
        id="xss-only", title="Potential XSS", severity="medium", path="view.js",
        line=2, evidence="node.innerHTML = value", description="DOM HTML sink",
        confidence=0.65, scanner="opengrep", rule_id="raksa.javascript-html-injection",
        cwe="CWE-79",
    )
    fake_nebius = MagicMock()
    fake_nebius.configured = True
    fake_nebius.summarize_findings = AsyncMock(return_value="Potential XSS.")
    fake_nebius.propose_patch = AsyncMock(return_value={
        "path": "view.js", "old_text": "node.innerHTML = value",
        "new_text": "node.textContent = value", "reason": "Text API",
    })
    monkeypatch.setattr("app.services.workflow.nebius", fake_nebius)
    monkeypatch.setattr(
        "app.services.workflow.github_app.get_snapshot",
        AsyncMock(return_value=(files, {"default_branch": "main"}, "base123")),
    )
    monkeypatch.setattr(
        "app.services.workflow.scan_snapshot",
        AsyncMock(return_value=[ScannerResult("opengrep", "completed", [finding])]),
    )
    gate = AsyncMock(side_effect=AssertionError("Specialist gate cannot verify XSS"))
    monkeypatch.setattr("app.services.workflow.verify_remediation", gate)

    scan_id = "test-opengrep-only-ai-proposal"
    await put_job(scan_id, {
        "id": scan_id, "status": "queued", "stage": "queued", "message": "Scan queued.",
        "full_name": "owner/repo", "installation_id": "123",
    })
    await run_scan_job(scan_id, "123", "owner/repo")
    job = await get_job(scan_id)
    assert job is not None and job["status"] == "completed"
    assert len(job["findings"]) == 1
    assert len(job["patches"]) == 1
    assert job["patches"][0]["scanner"] == "opengrep"
    assert job["verification"]["eligible_for_pr"] is False
    assert job["verification"]["status"] == "unverified"
    gate.assert_not_awaited()
