"""OpenGrep scanner adapter: fixed rules, no network, bounded output."""
import asyncio
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from app.config import settings
from app.scanners.base import ScannerResult, SecurityFinding

RULES_FILE = Path(__file__).with_name("rules") / "raksa.yml"
SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def _safe_path(path: str) -> bool:
    p = PurePosixPath(path)
    return bool(path) and not p.is_absolute() and ".." not in p.parts and "\\" not in path and "\x00" not in path


def normalize_opengrep(payload: dict[str, Any], files: dict[str, str], *,
                       max_findings: int) -> list[SecurityFinding]:
    results = payload.get("results")
    if not isinstance(results, list):
        raise ValueError("Invalid scanner result: missing results array")
    findings: list[SecurityFinding] = []
    seen: set[tuple[str, str, int]] = set()
    for item in results:
        if not isinstance(item, dict):
            continue
        rule_id = str(item.get("check_id") or "")[:255]
        path = str(item.get("path") or "")
        if path.startswith("/workspace/"):
            path = path[len("/workspace/"):]
        if path.startswith("./"):
            path = path[2:]
        if not rule_id or not _safe_path(path) or path not in files:
            continue
        start = item.get("start")
        if not isinstance(start, dict):
            continue
        try:
            line = int(start.get("line"))
        except (ValueError, TypeError):
            continue
        lines = files[path].splitlines()
        if not 1 <= line <= len(lines) or (rule_id, path, line) in seen:
            continue
        seen.add((rule_id, path, line))
        extra = item.get("extra") or {}
        if not isinstance(extra, dict):
            extra = {}
        meta = extra.get("metadata") or {}
        if not isinstance(meta, dict):
            meta = {}
        cwe_value = meta.get("cwe") or ""
        cwe_text = " ".join(str(x) for x in cwe_value) if isinstance(cwe_value, list) else str(cwe_value)
        match = re.search(r"CWE-\d+", cwe_text, re.I)
        message = str(extra.get("message") or "Potential unsafe pattern").strip()[:900]
        token = hashlib.sha256(f"{rule_id}:{path}:{line}".encode()).hexdigest()[:20]
        findings.append(SecurityFinding(
            id=f"og-{token}", scanner="opengrep", rule_id=rule_id,
            title=message[:200], severity=SEVERITY.get(str(extra.get("severity", "WARNING")).upper(), "medium"),
            path=path, line=line, evidence=lines[line - 1].strip()[:300],
            cwe=match.group(0).upper() if match else None,
            description=f"OpenGrep rule {rule_id}: {message} Potential pattern; not exploit-verified.",
            confidence=0.65,
        ))
        if len(findings) >= max_findings:
            break
    return findings


class OpenGrepScanner:
    name = "opengrep"

    async def scan(self, files: dict[str, str], *, max_findings: int) -> ScannerResult:
        if not settings.opengrep_enabled:
            return ScannerResult(self.name, "skipped", message="OpenGrep disabled.")
        if not shutil.which("docker"):
            return ScannerResult(self.name, "unavailable", message="Docker CLI not available.")
        if not files:
            return ScannerResult(self.name, "skipped", message="Empty source snapshot.")
        try:
            payload = await asyncio.to_thread(self._run_docker, files)
            findings = normalize_opengrep(payload, files, max_findings=max_findings)
            errors = payload.get("errors") or []
            if not isinstance(errors, list):
                raise ValueError("Invalid errors field.")
            status = "partial" if errors else "completed"
            message = "Some files/rules could not be analyzed." if errors else "Bounded snapshot scanned using Raksa-owned rules."
            return ScannerResult(self.name, status, findings, message)
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
            return ScannerResult(self.name, "error", message=f"OpenGrep scan failed ({type(exc).__name__}).")

    @staticmethod
    def _run_docker(files: dict[str, str]) -> dict[str, Any]:
        if len(files) > settings.max_repository_files:
            raise ValueError("Too many snapshot files.")
        total_bytes = 0
        with tempfile.TemporaryDirectory(prefix="raksa-opengrep-") as directory:
            root = Path(directory)
            # Docker container runs as an unprivileged user, so it needs
            # traversal access to the temporary parent directory.
            os.chmod(root, 0o755)
            workspace = root / "workspace"
            workspace.mkdir(mode=0o755)
            for path, content in files.items():
                if not _safe_path(path) or not isinstance(content, str):
                    raise ValueError("Unsafe file.")
                raw = content.encode("utf-8")
                total_bytes += len(raw)
                if len(raw) > settings.max_file_bytes or total_bytes > settings.max_repository_bytes:
                    raise ValueError("Snapshot over limit.")
                target = workspace.joinpath(*PurePosixPath(path).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            rules = root / "raksa.yml"
            rules.write_bytes(RULES_FILE.read_bytes())
            cmd = [
                "docker", "run", "--rm", "--pull", "never",
                "--network", "none", "--memory", "768m", "--cpus", "1",
                "--pids-limit", "128", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true",
                "--read-only", "--tmpfs", "/tmp:rw,nosuid,size=64m",
                "--user", f"{os.getuid()}:{os.getgid()}",
                "-e", "HOME=/tmp", "-e", "XDG_CACHE_HOME=/tmp",
                "-v", f"{workspace}:/workspace:ro",
                "-v", f"{rules}:/rules/raksa.yml:ro",
                "-w", "/workspace", settings.opengrep_image,
                "scan", "-f", "/rules/raksa.yml", "--json", "/workspace",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=max(15, min(settings.opengrep_timeout_seconds, 300)),
                                    check=False)
            if result.returncode != 0 or len(result.stdout) > 4_000_000:
                raise RuntimeError("Scanner returned failure or oversized output.")
            try:
                parsed = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                raise ValueError("Invalid scanner JSON.") from exc
            if not isinstance(parsed, dict):
                raise ValueError("Invalid scanner payload.")
            return parsed


opengrep = OpenGrepScanner()
