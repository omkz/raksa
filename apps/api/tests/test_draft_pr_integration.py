"""Exercise PostgreSQL -> FastAPI -> actual GitHub service with HTTP mocked only.

All fixture source is inert text; no repository code is executed.
"""
import base64
import json
from unittest.mock import AsyncMock

import httpx
import pytest
from test_review_only_pr import _auth, _original_files, _scan_job

from app.dependencies import get_current_user
from app.main import app
from app.services.github_app import github_app
from app.services.job_store import get_job, put_job


class GitHubFixture:
    def __init__(self) -> None:
        self.calls = []
        self.branch = False
        self.pr = None
        self.fail_pr = False
        self.stale = False
        self.changed_branch = False
        self.mode = "100644"
        self.snapshot_sha = "a" * 40
        self.ref_reads = 0
        self.advance_on_read = 0
        self.snapshot_error = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/repos/owner/demo")
        body = json.loads(request.content) if request.content else {}
        self.calls.append((request.method, path, body))
        assert request.headers["authorization"] == "Bearer test-installation-token"
        code = 200
        if path == "":
            data = {"default_branch": "main"}
        elif path == "/git/ref/heads/main":
            self.ref_reads += 1
            sha = "b" * 40 if self.stale or self.ref_reads == self.advance_on_read else "a" * 40
            data = {"object": {"sha": sha}}
        elif path == "/git/commits/" + "a" * 40:
            code = self.snapshot_error or 200
            data = {"sha": self.snapshot_sha, "tree": {"sha": "base-tree"}}
        elif path == "/git/trees/base-tree":
            data = {"tree": [
                {"path": p, "type": "blob", "mode": self.mode, "size": len(c), "sha": str(i)}
                for i, (p, c) in enumerate(_original_files().items())
            ]}
        elif path.startswith("/git/blobs/"):
            source = list(_original_files().values())[int(path.rsplit("/", 1)[1])]
            data = {"encoding": "base64", "content": base64.b64encode(source.encode()).decode()}
        elif path == "/git/blobs":
            data = {"sha": "blob"}
        elif path == "/git/trees":
            assert body["base_tree"] == "base-tree"
            assert {e["path"] for e in body["tree"]} == {"app.py", "src/unsafe_xss.js"}
            data = {"sha": "new-tree"}
        elif path == "/git/commits":
            assert body["parents"] == ["a" * 40]
            data = {"sha": "new-commit"}
        elif path == "/git/refs":
            assert body["ref"] == "refs/heads/raksa/fix-review-scan"
            code = 422 if self.branch else 201
            self.branch = True
            data = {}
        elif path == "/git/ref/heads/raksa/fix-review-scan":
            data = {"object": {"sha": "new-commit"}}
        elif path == "/git/commits/new-commit":
            data = {"tree": {"sha": "foreign-tree" if self.changed_branch else "new-tree"}, "parents": [{"sha": "a" * 40}]}
        elif path == "/pulls" and request.method == "GET":
            data = [self.pr] if self.pr else []
        elif path == "/pulls":
            assert body["draft"] is True
            assert body["title"].startswith("[UNVERIFIED")
            if self.fail_pr:
                code, data = 403, {"message": "Resource not accessible by integration"}
            else:
                self.pr = {"number": 3, "html_url": "https://github.com/owner/demo/pull/3", "draft": True, "state": "open", "base": {"ref": "main"}}
                data = self.pr
        else:
            raise AssertionError((request.method, path))
        return httpx.Response(code, json=data)


@pytest.fixture
async def integration(monkeypatch):
    fixture = GitHubFixture()
    original_client = httpx.AsyncClient
    monkeypatch.setattr("app.services.github_app.httpx.AsyncClient", lambda **kw: original_client(transport=httpx.MockTransport(fixture), **kw))
    token = AsyncMock(return_value="test-installation-token")
    monkeypatch.setattr(github_app, "create_installation_token", token)
    app.dependency_overrides[get_current_user] = _auth
    scan = _scan_job()
    # Even corrupted eligibility IDs cannot authorize excluded categories or rejected outcomes.
    scan["verification"]["review_pr_finding_ids"] += ["path", "shell", "eval"]
    for fid, cwe in [("shell", "CWE-78"), ("eval", "CWE-94")]:
        scan["patches"].append({"finding_id": fid, "cwe": cwe, "path": "src/unsafe_path.py", "old_text": "open(path)", "new_text": "unsafe()"})
    await put_job(scan["id"], scan)
    try:
        async with original_client(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            yield fixture, client
        assert all(c.args == ("install-1",) for c in token.await_args_list)
    finally:
        app.dependency_overrides.clear()


async def publish(client):
    return await client.post("/api/scans/review-scan/pull-request", json={"review_only": True})


async def test_database_http_publication_and_repeat(integration):
    fixture, client = integration
    assert (await publish(client)).status_code == 200
    job = await get_job("review-scan")
    assert "source_files" not in job
    assert job["pull_request_url"] == fixture.pr["html_url"]
    assert job["verification"]["eligible_for_pr"] is False
    assert (await publish(client)).status_code == 200
    assert len([c for c in fixture.calls if c[:2] == ("POST", "/pulls")]) == 1


async def test_retry_after_permission_failure_reuses_validated_branch(integration):
    fixture, client = integration
    fixture.fail_pr = True
    response = await publish(client)
    assert response.status_code == 502
    assert "Pull requests: Read and write" in response.json()["detail"]
    assert fixture.branch
    assert not (await get_job("review-scan"))["pull_request_url"]
    fixture.fail_pr = False
    assert (await publish(client)).status_code == 200


@pytest.mark.parametrize("failure", ["stale", "advance", "changed_branch", "symlink", "snapshot_sha", "snapshot_permission"])
async def test_fail_closed(integration, failure):
    fixture, client = integration
    if failure == "stale":
        fixture.stale = True
    elif failure == "advance":
        fixture.advance_on_read = 2
    elif failure == "changed_branch":
        fixture.branch = fixture.changed_branch = True
    elif failure == "symlink":
        fixture.mode = "120000"
    elif failure == "snapshot_sha":
        fixture.snapshot_sha = "b" * 40
    else:
        fixture.snapshot_error = 403
    response = await publish(client)
    assert response.status_code in {409, 502}
    assert fixture.pr is None
    if failure == "snapshot_permission":
        assert "installation" in response.json()["detail"]


@pytest.mark.parametrize("failure", ["installation", "workspace", "consent", "rejected"])
async def test_authorization_before_github(integration, monkeypatch, failure):
    fixture, client = integration
    scan = await get_job("review-scan")
    if failure == "installation":
        scan["installation_id"] = "other"
    elif failure == "workspace":
        scan["workspace_id"] = "other"
        monkeypatch.setattr("app.routers.scans.user_has_workspace_access", AsyncMock(return_value=False))
    elif failure == "rejected":
        scan["verification"]["finding_outcomes"] = {fid: {"status": "rejected"} for fid in ["sql", "xss"]}
    await put_job("review-scan", {key: scan[key] for key in ("workspace_id", "installation_id", "verification")})
    response = await client.post("/api/scans/review-scan/pull-request", json={"review_only": failure != "consent"})
    assert response.status_code in {401, 404, 409}
    assert not fixture.calls


async def test_executable_file_modes_preserved(integration):
    fixture, client = integration
    fixture.mode = "100755"
    assert (await publish(client)).status_code == 200
    tree = next(body for method, path, body in fixture.calls if (method, path) == ("POST", "/git/trees"))
    assert all(entry["mode"] == "100755" for entry in tree["tree"])


async def test_existing_ready_pr_is_not_reused(integration):
    fixture, client = integration
    assert (await publish(client)).status_code == 200
    fixture.pr["draft"] = False
    response = await publish(client)
    assert response.status_code == 409
    assert "no longer Draft" in response.json()["detail"]


async def test_source_mismatch_never_writes(integration):
    fixture, client = integration
    scan = await get_job("review-scan")
    scan["patches"][0]["old_text"] = "absent.execute(query)"
    await put_job("review-scan", {"patches": scan["patches"]})
    assert (await publish(client)).status_code == 409
    assert not any(method == "POST" for method, _, _ in fixture.calls)
