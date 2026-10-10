import asyncio
import io
import os
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import time
from pathlib import PurePosixPath
from typing import Any

import httpx

from app.config import settings


class SandboxError(RuntimeError):
    pass


def _safe_path(path: str) -> bool:
    p = PurePosixPath(path)
    return bool(path) and not p.is_absolute() and ".." not in p.parts and "\\" not in path and "\x00" not in path


def archive_files(files: dict[str, str]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for path, text in files.items():
            if not _safe_path(path):
                raise SandboxError(f"Unsafe path in sandbox archive: {path}")
            raw = text.encode("utf-8")
            info = tarfile.TarInfo(name=path)
            info.size = len(raw)
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(raw))
    content = stream.getvalue()
    if len(content) > settings.sandbox_max_archive_bytes:
        raise SandboxError("Repository snapshot exceeds the configured sandbox archive limit.")
    return content


class SandboxService:
    async def run_tests(
        self,
        files: dict[str, str],
        *,
        timeout_seconds: int | None = None,
        test_pattern: str | None = None,
    ) -> dict[str, Any]:
        provider = settings.sandbox_provider.strip().lower()
        timeout = max(15, min(timeout_seconds or settings.sandbox_timeout_seconds, 900))
        if provider == "demo":
            return {
                "provider": "demo",
                "status": "not_run",
                "exit_code": None,
                "stdout": "",
                "stderr": "",
                "message": "Repository tests were not executed. Set SANDBOX_PROVIDER=nebius or docker to enable isolated test execution.",
            }
        if provider == "docker":
            return await asyncio.to_thread(self._run_docker, files, timeout, test_pattern)
        if provider == "nebius":
            return await self._run_nebius(files, timeout, test_pattern)
        raise SandboxError(f"Unsupported SANDBOX_PROVIDER: {provider}")

    def _run_docker(self, files: dict[str, str], timeout: int, test_pattern: str | None = None) -> dict[str, Any]:
        """Run a fixed test command in a no-network Docker container; never invokes a repo-provided shell command."""
        if not shutil.which("docker"):
            raise SandboxError("Docker CLI was not found. Install Docker or use the Nebius Sandbox provider.")
        from pathlib import Path

        root = tempfile.TemporaryDirectory(prefix="raksa-workspace-")
        try:
            workspace = root.name
            os.chmod(workspace, 0o755)
            for path, content in files.items():
                if not _safe_path(path):
                    raise SandboxError(f"Unsafe path in repository snapshot: {path}")
                target = Path(workspace).joinpath(*PurePosixPath(path).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            pattern_args = ["-p", test_pattern] if test_pattern and _safe_path(test_pattern) else []
            command = [
                "docker", "run", "--rm", "--network", "none", "--memory", "512m", "--cpus", "1",
                "--pids-limit", "128", "--ulimit", "nofile=1024:1024", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                "--user", "65534:65534", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
                "-e", "PYTHONDONTWRITEBYTECODE=1", "-v", f"{workspace}:/workspace:ro",
                "-w", "/workspace", "python:3.12-slim", "python", "-m", "unittest", "discover", "-v",
                *pattern_args,
            ]
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
                stdout, stderr = result.stdout[-12000:], result.stderr[-12000:]
                return {
                    "provider": "docker", "status": "passed" if result.returncode == 0 else "failed",
                    "exit_code": result.returncode, "stdout": stdout, "stderr": stderr,
                    "message": "Tests executed in a no-network Docker container.",
                }
            except subprocess.TimeoutExpired as exc:
                return {"provider": "docker", "status": "timeout", "exit_code": None,
                        "stdout": str(exc.stdout or "")[-4000:], "stderr": "Sandbox timeout reached.",
                        "message": f"Test execution exceeded {timeout} seconds."}
        finally:
            root.cleanup()

    async def _run_nebius(self, files: dict[str, str], timeout: int, test_pattern: str | None = None) -> dict[str, Any]:
        if not settings.nebius_api_key:
            raise SandboxError("NEBIUS_API_KEY is required for the Nebius Sandbox provider.")
        archive = archive_files(files)
        base = settings.nebius_sandbox_base_url.rstrip("/")
        headers = {"Authorization": f"Bearer {settings.nebius_api_key}"}
        if settings.nebius_project:
            headers["Project"] = settings.nebius_project
        started = time.monotonic()
        async with httpx.AsyncClient(timeout=httpx.Timeout(30, read=timeout + 30)) as client:
            upload = await client.post(
                f"{base}/v1/files", headers={**headers, "Content-Type": "application/octet-stream", "X-Filename": "raksa-repo.tar.gz"}, content=archive,
            )
            if upload.status_code >= 400:
                raise SandboxError(self._api_error("Sandbox file upload", upload))
            uploaded = upload.json()
            file_id = str(uploaded.get("uuid") or uploaded.get("id") or uploaded.get("file_id") or "")
            if not file_id:
                raise SandboxError("Nebius Sandbox upload returned no file identifier; inspect API response schema.")

            pattern_clause = f" -p {shlex.quote(test_pattern)}" if test_pattern and _safe_path(test_pattern) else ""
            shell_command = f"mkdir -p /workspace && tar -xzf /tmp/raksa-repo.tar.gz -C /workspace && cd /workspace && python -m unittest discover -v{pattern_clause}"
            payload = {
                "image": "tag:ubuntu:latest",
                "files": [file_id],
                "shell": True,
                "timeout": timeout,
                "command": shell_command,
            }
            spawn = await client.post(f"{base}/v1/instances", headers=headers, json=payload)
            if spawn.status_code >= 400:
                raise SandboxError(self._api_error("Sandbox instance creation", spawn))
            created = spawn.json()
            instance_id = str(created.get("uuid") or created.get("id") or created.get("instance_id") or "")
            operation_obj = created.get("operation") if isinstance(created.get("operation"), dict) else {}
            operation_id = str(created.get("operation_id") or created.get("operationId") or operation_obj.get("id", ""))
            if not operation_id and instance_id:
                operation_id = instance_id
            if not operation_id:
                raise SandboxError("Nebius Sandbox returned no operation identifier; inspect API response schema.")

            deadline = time.monotonic() + timeout
            operation: dict[str, Any] = created
            while time.monotonic() < deadline:
                status = str(operation.get("status") or operation.get("state") or "").upper()
                if status in {"SUCCESS", "SUCCEEDED", "COMPLETED", "FAILED", "CANCELLED", "CANCELED", "ERROR"}:
                    break
                await asyncio.sleep(2)
                poll = await client.get(f"{base}/v1/operations/{operation_id}", headers=headers)
                if poll.status_code >= 400:
                    raise SandboxError(self._api_error("Sandbox operation polling", poll))
                operation = poll.json()
            else:
                return {"provider": "nebius", "status": "timeout", "exit_code": None,
                        "stdout": "", "stderr": "Operation did not finish before timeout.",
                        "message": f"Nebius Sandbox timed out after {timeout}s.", "instance_id": instance_id,
                        "operation_id": operation_id, "duration_seconds": round(time.monotonic() - started, 2)}

        result = operation.get("metadata", {}).get("result", {}) if isinstance(operation.get("metadata"), dict) else {}
        if not result and isinstance(operation.get("result"), dict):
            result = operation.get("result", {})
        exit_code = result.get("exit_code", result.get("exitCode"))
        try:
            exit_code = int(exit_code) if exit_code is not None else None
        except (TypeError, ValueError):
            exit_code = None
        status = str(operation.get("status") or operation.get("state") or (operation.get("metadata") or {}).get("status") or "").upper()
        passed = status in {"SUCCESS", "SUCCEEDED", "COMPLETED"} and exit_code == 0
        return {
            "provider": "nebius", "status": "passed" if passed else "failed", "exit_code": exit_code,
            "stdout": str(result.get("stdout", ""))[-12000:], "stderr": str(result.get("stderr", ""))[-12000:],
            "message": "Tests executed in a Nebius Token Factory Sandbox.", "instance_id": instance_id,
            "operation_id": operation_id, "duration_seconds": round(time.monotonic() - started, 2),
            "cost": result.get("cost"),
        }

    @staticmethod
    def _api_error(label: str, response: httpx.Response) -> str:
        try:
            detail = response.json()
        except ValueError:
            detail = response.text[:1000]
        return f"{label} failed ({response.status_code}): {str(detail)[:1200]}"


sandbox = SandboxService()
