import subprocess

import pytest

from app.config import settings
from app.scanners.opengrep import OpenGrepScanner, normalize_opengrep


def test_normalization_accepts_only_snapshot_paths() -> None:
    files = {"src/app.py": "import os\nos.system(user_input)\n"}
    payload = {"results": [
        {"check_id": "raksa.python-shell-execution", "path": "/workspace/src/app.py",
         "start": {"line": 2}, "extra": {"severity": "WARNING", "metadata": {"cwe": "CWE-78"}}},
        {"check_id": "unsafe", "path": "/workspace/../../etc/passwd", "start": {"line": 1}},
    ]}
    findings = normalize_opengrep(payload, files, max_findings=10)
    assert len(findings) == 1
    assert findings[0].scanner == "opengrep"
    assert findings[0].cwe == "CWE-78"
    assert findings[0].evidence == "os.system(user_input)"
    assert findings[0].status == "potential"


def test_invalid_output_is_not_clean_result() -> None:
    with pytest.raises(ValueError):
        normalize_opengrep({}, {"app.py": "pass"}, max_findings=10)


@pytest.mark.asyncio
async def test_adapter_is_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "opengrep_enabled", False)
    result = await OpenGrepScanner().scan({"app.py": "pass"}, max_findings=10)
    assert result.status == "skipped"


@pytest.mark.asyncio
async def test_adapter_reports_runner_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "opengrep_enabled", True)
    monkeypatch.setattr("app.scanners.opengrep.shutil.which", lambda _tool: "/usr/bin/docker")

    def fail(_files):
        raise RuntimeError("SECRET SHOULD NOT LEAK")

    monkeypatch.setattr(OpenGrepScanner, "_run_docker", staticmethod(fail))
    result = await OpenGrepScanner().scan({"app.py": "pass"}, max_findings=10)
    assert result.status == "error"
    assert "SECRET" not in result.message


@pytest.mark.asyncio
async def test_adapter_maps_mock_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "opengrep_enabled", True)
    monkeypatch.setattr("app.scanners.opengrep.shutil.which", lambda _tool: "/usr/bin/docker")
    monkeypatch.setattr(OpenGrepScanner, "_run_docker", staticmethod(
        lambda _files: {"results": [{"check_id": "test", "path": "app.js",
            "start": {"line": 1}, "extra": {"message": "Dynamic execution"}}], "errors": []}
    ))
    result = await OpenGrepScanner().scan({"app.js": "eval(input);\n"}, max_findings=10)
    assert result.status == "completed"
    assert result.findings[0].title == "Dynamic execution"


def test_clean_pr_check_is_success_when_scanner_disabled() -> None:
    from app.services.workflow import _format_check_run_output

    conclusion, title, summary, _ = _format_check_run_output(
        findings=[],
        files_count=1,
        verification={"status": "unverified"},
        pr_number=42,
        head_sha="a" * 40,
        pr_changed_files=[],
        scanner_reports=[{
            "name": "opengrep", "status": "skipped",
            "finding_count": 0, "message": "OpenGrep disabled.",
        }],
    )
    assert conclusion == "success"
    assert "No Vulnerabilities Detected" in title
    assert "#### Findings (0)" not in summary
    assert "opengrep" in summary


def test_incomplete_scanner_coverage_is_neutral_not_success() -> None:
    from app.services.workflow import _format_check_run_output

    conclusion, title, summary, _ = _format_check_run_output(
        findings=[],
        files_count=1,
        verification={"status": "unverified"},
        pr_number=42,
        head_sha="a" * 40,
        pr_changed_files=[],
        scanner_reports=[{
            "name": "opengrep", "status": "unavailable",
            "finding_count": 0, "message": "Docker CLI not available.",
        }],
    )
    assert conclusion == "neutral"
    assert "Scanner Coverage Incomplete" in title
    assert "#### Findings (0)" not in summary
    assert "**opengrep**: unavailable" in summary


def test_check_run_renders_static_finding_and_its_scanner() -> None:
    from app.services.workflow import _format_check_run_output

    finding = {
        "title": "Dynamic execution",
        "severity": "medium",
        "cwe": "CWE-94",
        "scanner": "opengrep",
        "path": "app.js",
        "line": 1,
        "evidence": "eval(input)",
    }
    conclusion, title, summary, _ = _format_check_run_output(
        findings=[finding],
        files_count=1,
        verification={"status": "unverified", "message": "No fix verified."},
        pr_number=42,
        head_sha="a" * 40,
        pr_changed_files=["app.js"],
        scanner_reports=[{
            "name": "opengrep", "status": "completed",
            "finding_count": 1, "message": "Rule scan completed.",
        }],
    )
    assert conclusion == "failure"
    assert "Potential Vulnerability Detected" in title
    assert "#### Findings (1)" in summary
    assert "CWE-94; scanner: opengrep" in summary
    assert "Dynamic execution" in summary
    assert "No SQL injection or critical security vulnerabilities detected" not in summary


def test_docker_runner_has_enough_tmpfs_space_without_relaxing_isolation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Self-extracting OpenGrep needs more than 64 MiB in /tmp; keep sandbox limits."""
    executed: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        executed.append(command)
        return subprocess.CompletedProcess(
            command, 0, stdout='{"results": [], "errors": []}', stderr=""
        )

    monkeypatch.setattr("app.scanners.opengrep.subprocess.run", fake_run)
    result = OpenGrepScanner._run_docker({"src/app.py": "import os\nos.system(command)\n"})

    assert result == {"results": [], "errors": []}
    cmd = executed[0]
    assert cmd[cmd.index("--tmpfs") + 1] == "/tmp:rw,nosuid,size=512m"
    assert cmd[cmd.index("--network") + 1] == "none"
    assert "--read-only" in cmd
    assert cmd[cmd.index("--pull") + 1] == "never"
    assert cmd[cmd.index("--user") + 1]
    assert cmd[cmd.index("--cap-drop") + 1] == "ALL"
    assert cmd[cmd.index("--memory") + 1] == "768m"
