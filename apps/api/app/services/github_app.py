import base64
import hashlib
import hmac
import time
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import quote

import httpx
import jwt

from app.config import settings

SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".rb", ".php", ".go", ".java", ".sql", ".toml", ".cfg", ".ini", ".yaml", ".yml", ".json", ".txt"}
SOURCE_BASENAMES = {"Makefile", "Dockerfile", "pyproject.toml", "package.json", "requirements.txt", "pytest.ini", "setup.cfg", "Gemfile", "go.mod"}
IGNORED_PARTS = {
    ".git", "node_modules", "vendor", "dist", "build", "coverage", ".venv", "venv",
    "__pycache__", "migrations", "generated", "fixtures", "lockfiles",
    # Teaching / demonstration directories are intentionally vulnerable and must not be patched.
    "examples", "example", "demos", "demo", "samples", "sample",
}


class GitHubAppError(RuntimeError):
    def __init__(self, message: str, *, status_code: int = 502) -> None:
        super().__init__(message)
        self.status_code = status_code


class GitHubAppService:
    def __init__(self) -> None:
        self.base_url = settings.github_api_base_url.rstrip("/")

    @property
    def configured(self) -> bool:
        return bool(settings.github_app_id and settings.github_app_slug and settings.resolved_github_private_key)

    def app_jwt(self) -> str:
        if not self.configured:
            raise GitHubAppError("GitHub App is not configured. Set GITHUB_APP_ID, GITHUB_APP_SLUG, and the private key.")
        now = int(time.time())
        claims = {"iat": now - 30, "exp": now + 540, "iss": settings.github_app_id}
        return jwt.encode(claims, settings.resolved_github_private_key, algorithm="RS256")

    def auth_headers(self, token: str, *, app: bool = False) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": settings.github_api_version,
            "User-Agent": "Raksa-AppSec-Agent",
        }

    async def _request(
        self,
        method: str,
        path: str,
        *,
        token: str,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        app: bool = False,
    ) -> Any:
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.request(
                    method,
                    f"{self.base_url}{path}",
                    headers=self.auth_headers(token, app=app),
                    json=json,
                    params=params,
                )
        except httpx.RequestError as exc:
            raise GitHubAppError(
                "GitHub could not be reached. Retry the request; an existing review branch will be checked safely."
            ) from exc
        if response.status_code >= 400:
            status = response.status_code
            if status == 403 and (response.headers.get("x-ratelimit-remaining") == "0"
                                  or response.headers.get("retry-after")):
                detail = "GitHub rate limit reached. Wait before retrying."
            elif status == 403:
                detail = (
                    "GitHub denied access. Check the original installation's repository access, "
                    "Contents: Read and write and Pull requests: Read and write permissions. "
                    "An installation owner must approve updated App permissions; repository rules may also block writes."
                )
            elif status == 401:
                detail = "GitHub authentication failed. Reconnect the original installation and check the App credentials."
            elif status == 404:
                detail = "GitHub resource unavailable. Check installation repository access and whether the repository or pinned commit still exists."
            elif status == 422:
                detail = "GitHub rejected the request. Check for an existing review branch/PR, repository rules, or no remaining changes."
            else:
                detail = "GitHub request failed. Retry later or check GitHub service status."
            raise GitHubAppError(f"GitHub API returned {status}: {detail}", status_code=status)
        if not response.content:
            return {}
        return response.json()

    async def create_installation_token(self, installation_id: str) -> str:
        data = await self._request(
            "POST", f"/app/installations/{quote(installation_id, safe='')}/access_tokens",
            token=self.app_jwt(), app=True,
        )
        token = data.get("token")
        if not token:
            raise GitHubAppError("GitHub did not return an installation token.")
        return str(token)

    async def list_repositories(self, installation_id: str) -> list[dict[str, Any]]:
        token = await self.create_installation_token(installation_id)
        all_repos: list[dict[str, Any]] = []
        page = 1
        while page <= 10:
            data = await self._request(
                "GET", "/installation/repositories", token=token,
                params={"per_page": 100, "page": page},
            )
            repos = data.get("repositories", [])
            all_repos.extend(repos)
            if len(repos) < 100:
                break
            page += 1
        return [
            {
                "full_name": repo["full_name"],
                "private": bool(repo.get("private")),
                "default_branch": repo.get("default_branch", "main"),
                "html_url": repo.get("html_url", ""),
                "description": repo.get("description"),
            }
            for repo in all_repos
            if repo.get("full_name")
        ]

    async def _installation_request(
        self, installation_id: str, method: str, path: str,
        *, json: dict[str, Any] | None = None, params: dict[str, Any] | None = None,
    ) -> Any:
        token = await self.create_installation_token(installation_id)
        return await self._request(method, path, token=token, json=json, params=params)

    async def get_repository(self, installation_id: str, full_name: str) -> dict[str, Any]:
        self._validate_full_name(full_name)
        owner, repo = full_name.split("/", 1)
        return await self._installation_request(installation_id, "GET", f"/repos/{owner}/{repo}")

    async def get_snapshot(
        self,
        installation_id: str,
        full_name: str,
        *,
        max_files: int,
        max_file_bytes: int,
        max_repository_bytes: int,
        commit_sha: str | None = None,
    ) -> tuple[dict[str, str], dict[str, Any], str]:
        """Fetch a bounded text-only source snapshot from a repository at commit_sha or default branch."""
        meta = await self.get_repository(installation_id, full_name)
        if commit_sha:
            base_sha = str(commit_sha)
        else:
            branch = str(meta.get("default_branch", "main"))
            ref = await self._installation_request(
                installation_id, "GET", f"/repos/{full_name}/git/ref/heads/{quote(branch, safe='/')}",
            )
            base_sha = str(ref["object"]["sha"])

        commit = await self._installation_request(
            installation_id, "GET", f"/repos/{full_name}/git/commits/{base_sha}",
        )
        if commit.get("sha") != base_sha:
            raise GitHubAppError("GitHub snapshot commit does not match the original scan. Rescan before publishing.", status_code=409)
        tree_sha = str(commit["tree"]["sha"])
        tree_data = await self._installation_request(
            installation_id, "GET", f"/repos/{full_name}/git/trees/{tree_sha}", params={"recursive": "1"},
        )
        if tree_data.get("truncated"):
            raise GitHubAppError("Repository tree is too large for the MVP. Use a smaller repository.")

        candidates: list[dict[str, Any]] = []
        for item in tree_data.get("tree", []):
            path = item.get("path", "")
            if item.get("type") != "blob" or item.get("mode") not in {"100644", "100755"} or not path or not is_safe_repo_path(path):
                continue
            pure_path = PurePosixPath(path)
            if pure_path.suffix.lower() not in SOURCE_SUFFIXES and pure_path.name not in SOURCE_BASENAMES:
                continue
            if pure_path.name.lower() in {".env", ".env.local", ".npmrc", ".pypirc"} or pure_path.suffix.lower() in {".lock", ".pem", ".key", ".crt", ".p12"}:
                continue
            if any(part.lower() in IGNORED_PARTS for part in pure_path.parts):
                continue
            size = int(item.get("size", 0) or 0)
            if size <= 0 or size > max_file_bytes:
                continue
            candidates.append(item)
        candidates = candidates[:max_files]

        files: dict[str, str] = {}
        total = 0
        for item in candidates:
            data = await self._installation_request(
                installation_id, "GET", f"/repos/{full_name}/git/blobs/{item['sha']}",
            )
            if data.get("encoding") != "base64":
                continue
            try:
                raw = base64.b64decode(data.get("content", ""), validate=False)
                text = raw.decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
            if len(raw) > max_file_bytes:
                continue
            total += len(raw)
            if total > max_repository_bytes:
                break
            files[str(item["path"])] = text

        if not files:
            raise GitHubAppError("No supported text source files found within the configured size limits.")
        return files, meta, base_sha

    async def create_pull_request(
        self,
        installation_id: str,
        full_name: str,
        *,
        expected_base_sha: str,
        files: dict[str, str],
        title: str,
        body: str,
        scan_id: str,
    ) -> dict[str, Any]:
        """Publish edited files as one commit on a new branch; never update the default branch."""
        self._validate_full_name(full_name)
        if not files:
            raise GitHubAppError("There are no proposed file changes to publish.")
        meta = await self.get_repository(installation_id, full_name)
        default_branch = str(meta.get("default_branch", "main"))
        current_ref = await self._installation_request(
            installation_id, "GET", f"/repos/{full_name}/git/ref/heads/{quote(default_branch, safe='/')}",
        )
        current_sha = str(current_ref["object"]["sha"])
        if current_sha != expected_base_sha:
            raise GitHubAppError("The repository changed after this scan. Rescan the latest default branch before creating a PR.", status_code=409)

        base_commit = await self._installation_request(
            installation_id, "GET", f"/repos/{full_name}/git/commits/{expected_base_sha}",
        )
        base_tree = await self._installation_request(
            installation_id, "GET", f"/repos/{full_name}/git/trees/{base_commit['tree']['sha']}",
            params={"recursive": "1"},
        )
        entries = {item["path"]: item for item in base_tree.get("tree", [])}
        if base_commit.get("sha") != expected_base_sha or base_tree.get("truncated"):
            raise GitHubAppError("Cannot validate the pinned repository tree. Rescan before publishing.", status_code=409)
        for path in files:
            entry = entries.get(path, {})
            if not is_safe_repo_path(path) or entry.get("type") != "blob" or entry.get("mode") not in {"100644", "100755"}:
                raise GitHubAppError("Selected path is not a regular file in the pinned repository.", status_code=409)
        tree_entries: list[dict[str, Any]] = []
        for path, content in files.items():
            if not is_safe_repo_path(path):
                raise GitHubAppError(f"Unsafe repository path rejected: {path}")
            blob = await self._installation_request(
                installation_id, "POST", f"/repos/{full_name}/git/blobs",
                json={"content": content, "encoding": "utf-8"},
            )
            tree_entries.append({"path": path, "mode": entries[path]["mode"], "type": "blob", "sha": blob["sha"]})

        tree = await self._installation_request(
            installation_id, "POST", f"/repos/{full_name}/git/trees",
            json={"base_tree": base_commit["tree"]["sha"], "tree": tree_entries},
        )
        commit = await self._installation_request(
            installation_id, "POST", f"/repos/{full_name}/git/commits",
            json={
                "message": "security: prepare remediation with Raksa",
                "tree": tree["sha"],
                "parents": [expected_base_sha],
            },
        )
        branch_name = f"raksa/fix-{scan_id[:12]}"
        async def assert_base() -> None:
            latest_meta = await self.get_repository(installation_id, full_name)
            latest_ref = await self._installation_request(
                installation_id, "GET", f"/repos/{full_name}/git/ref/heads/{quote(default_branch, safe='/')}",
            )
            if latest_meta.get("default_branch") != default_branch or latest_ref["object"]["sha"] != expected_base_sha:
                raise GitHubAppError("The repository changed after this scan. Rescan before creating a PR.", status_code=409)

        await assert_base()
        try:
            await self._installation_request(
                installation_id, "POST", f"/repos/{full_name}/git/refs",
                json={"ref": f"refs/heads/{branch_name}", "sha": commit["sha"]},
            )
        except GitHubAppError as exc:
            if exc.status_code != 422:
                raise
            # A previous attempt may have created the branch before PR creation failed.
            # Never reset or overwrite it: require the exact expected tree and parent.
            ref = await self._installation_request(
                installation_id, "GET", f"/repos/{full_name}/git/ref/heads/{branch_name}",
            )
            existing = await self._installation_request(
                installation_id, "GET", f"/repos/{full_name}/git/commits/{ref['object']['sha']}",
            )
            if existing.get("tree", {}).get("sha") != tree["sha"] or [p["sha"] for p in existing.get("parents", [])] != [expected_base_sha]:
                raise GitHubAppError("The review branch was changed. It will not be overwritten. Start a fresh scan.", status_code=409) from exc
        await assert_base()
        prs = await self._installation_request(
            installation_id, "GET", f"/repos/{full_name}/pulls",
            params={"head": f"{full_name.split('/')[0]}:{branch_name}", "state": "all"},
        )
        if prs:
            pr = prs[0]
            if pr.get("state") != "open" or not pr.get("draft") or pr.get("base", {}).get("ref") != default_branch:
                raise GitHubAppError("The existing review PR is closed or no longer Draft, or its base changed. Start a fresh scan.", status_code=409)
        else:
            pr = await self._installation_request(
                installation_id, "POST", f"/repos/{full_name}/pulls",
                json={"title": title, "body": body, "head": branch_name, "base": default_branch, "draft": True},
            )
        return {"number": pr.get("number"), "html_url": pr.get("html_url"), "branch": branch_name}

    async def get_pull_request_files(
        self,
        installation_id: str,
        full_name: str,
        pr_number: int,
    ) -> list[str]:
        """Fetch list of changed file paths in a pull request."""
        self._validate_full_name(full_name)
        owner, repo = full_name.split("/", 1)
        files_data = await self._installation_request(
            installation_id, "GET", f"/repos/{owner}/{repo}/pulls/{pr_number}/files",
            params={"per_page": 100},
        )
        if not isinstance(files_data, list):
            return []
        return [str(item.get("filename")) for item in files_data if item.get("filename")]

    async def create_check_run(
        self,
        installation_id: str,
        full_name: str,
        *,
        head_sha: str,
        name: str = "Raksa Security Review",
        status: str = "in_progress",
        title: str = "Raksa Security Review in progress",
        summary: str = "Analyzing pull request for potential vulnerabilities…",
    ) -> dict[str, Any]:
        """Create a GitHub Check Run for the specified PR commit."""
        self._validate_full_name(full_name)
        owner, repo = full_name.split("/", 1)
        payload: dict[str, Any] = {
            "name": name,
            "head_sha": head_sha,
            "status": status,
            "started_at": datetime.now(UTC).isoformat(),
            "output": {
                "title": title,
                "summary": summary,
            },
        }
        try:
            data = await self._installation_request(
                installation_id, "POST", f"/repos/{owner}/{repo}/check-runs", json=payload,
            )
            return dict(data)
        except GitHubAppError as exc:
            if "403" in str(exc):
                raise GitHubAppError(
                    f"GitHub App lacks 'Checks: Read and write' permission for {full_name}. "
                    "Please enable Checks (Read and write) in GitHub App settings."
                ) from exc
            raise

    async def update_check_run(
        self,
        installation_id: str,
        full_name: str,
        *,
        check_run_id: int,
        status: str = "completed",
        conclusion: str = "success",
        title: str,
        summary: str,
        text: str | None = None,
    ) -> dict[str, Any]:
        """Update an existing GitHub Check Run with status, conclusion, and output."""
        self._validate_full_name(full_name)
        owner, repo = full_name.split("/", 1)
        output: dict[str, Any] = {
            "title": title,
            "summary": summary,
        }
        if text:
            output["text"] = text
        payload: dict[str, Any] = {
            "name": "Raksa Security Review",
            "status": status,
            "conclusion": conclusion,
            "completed_at": datetime.now(UTC).isoformat(),
            "output": output,
        }
        try:
            data = await self._installation_request(
                installation_id, "PATCH", f"/repos/{owner}/{repo}/check-runs/{check_run_id}", json=payload,
            )
            return dict(data)
        except GitHubAppError as exc:
            if "403" in str(exc):
                raise GitHubAppError(
                    f"GitHub App lacks 'Checks: Read and write' permission for {full_name}. "
                    "Please enable Checks (Read and write) in GitHub App settings."
                ) from exc
            raise

    @staticmethod
    def _validate_full_name(full_name: str) -> None:
        parts = full_name.split("/")
        if len(parts) != 2 or not all(part and part not in {".", ".."} for part in parts):
            raise GitHubAppError("Expected repository name in owner/repo format.")
        if any(not all(ch.isalnum() or ch in "-_." for ch in part) for part in parts):
            raise GitHubAppError("Invalid repository name.")


def is_safe_repo_path(path: str) -> bool:
    pure = PurePosixPath(path)
    return bool(path) and not pure.is_absolute() and ".." not in pure.parts and "\\" not in path and "\x00" not in path


def verify_webhook_signature(payload_bytes: bytes, signature_header: str | None, secret: str) -> bool:
    """Verify GitHub X-Hub-Signature-256 HMAC-SHA256 signature."""
    if not secret:
        return True
    if not signature_header:
        return False
    parts = signature_header.strip().split("=", 1)
    if len(parts) != 2 or parts[0].lower() != "sha256":
        return False
    mac = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256)
    expected = mac.hexdigest()
    return hmac.compare_digest(parts[1].lower(), expected.lower())


github_app = GitHubAppService()
