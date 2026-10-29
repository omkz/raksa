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
