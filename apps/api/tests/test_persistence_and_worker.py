import asyncio
import uuid
from datetime import timedelta
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete

from app.config import settings
from app.db.models import ScanJob, Workspace
from app.db.session import async_session_scope
from app.main import app
from app.services.job_store import (
    JobOwnershipError,
    claim_next_job,
    complete_job,
    create_scan_job,
    fail_job,
    get_job,
    heartbeat_job,
    list_audit_events,
    reap_stale_jobs,
    record_audit_event,
    release_job,
    update_job,
    utc_now,
)
from app.services.worker import ScanWorker, start_embedded_worker, stop_embedded_worker


def gen_id(prefix: str = "test") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


@pytest.fixture(autouse=True)
async def clean_database_jobs() -> None:
    async with async_session_scope() as session:
        await session.execute(delete(ScanJob))
    yield
    async with async_session_scope() as session:
        await session.execute(delete(ScanJob))


@pytest.mark.asyncio
async def test_job_store_crud_and_persistence() -> None:
    scan_id = gen_id("persist")
    job_data = await create_scan_job(
        scan_id=scan_id,
        installation_id="inst-123",
        full_name="org/repo-a",
        default_branch="main",
        workspace_id="default",
    )
    assert job_data["id"] == scan_id
    assert job_data["status"] == "queued"
    assert job_data["workspace_id"] == "default"

    # Verify retrieval
    retrieved = await get_job(scan_id)
    assert retrieved is not None
    assert retrieved["id"] == scan_id
    assert retrieved["installation_id"] == "inst-123"
    assert retrieved["full_name"] == "org/repo-a"

    # Update job with findings and patches
    await update_job(
        scan_id,
        status="running",
        stage="remediating",
        findings=[
            {
                "id": "find-1",
                "title": "SQL Injection in auth",
                "severity": "critical",
                "cwe": "CWE-89",
                "path": "app/auth.py",
                "line": 42,
                "evidence": "f'SELECT * FROM users WHERE id={user_id}'",
                "description": "Unsanitized user input",
                "confidence": 0.95,
            }
        ],
        patches=[{"path": "app/auth.py", "reason": "Use parameterized query"}],
        changed_files={"app/auth.py": "# fixed auth"},
    )

    updated = await get_job(scan_id)
    assert updated is not None
    assert updated["status"] == "running"
    assert updated["stage"] == "remediating"
    assert len(updated["findings"]) == 1
    assert updated["findings"][0]["id"] == "find-1"
    assert updated["findings"][0]["cwe"] == "CWE-89"
    assert updated["patches"][0]["path"] == "app/auth.py"
    assert updated["changed_files"]["app/auth.py"] == "# fixed auth"


@pytest.mark.asyncio
async def test_worker_claim_next_job_and_locking() -> None:
    job1_id = gen_id("claim-1")
    job2_id = gen_id("claim-2")

    worker_a = gen_id("worker-a")
    worker_b = gen_id("worker-b")
    worker_c = gen_id("worker-c")

    await create_scan_job(scan_id=job1_id, installation_id="111", full_name="org/repo-1")
    await create_scan_job(scan_id=job2_id, installation_id="222", full_name="org/repo-2")

    # Worker A claims first
    claimed_1 = await claim_next_job(worker_a)
    assert claimed_1 is not None
    assert claimed_1["id"] in {job1_id, job2_id}
    assert claimed_1["status"] == "running"
    assert claimed_1["locked_by"] == worker_a
    assert claimed_1["attempts"] == 1

    # Worker B claims second
    claimed_2 = await claim_next_job(worker_b)
    assert claimed_2 is not None
    assert claimed_2["id"] in {job1_id, job2_id}
    assert claimed_2["id"] != claimed_1["id"]
    assert claimed_2["status"] == "running"
    assert claimed_2["locked_by"] == worker_b
    assert claimed_2["attempts"] == 1

    # Worker C finds no queued job ready
    claimed_3 = await claim_next_job(worker_c)
    assert claimed_3 is None


@pytest.mark.asyncio
async def test_worker_heartbeat_updates_timestamp() -> None:
    scan_id = gen_id("hb")
    worker_id = gen_id("worker-live")
    await create_scan_job(scan_id=scan_id, installation_id="111", full_name="org/repo-hb")

    claimed = await claim_next_job(worker_id)
    assert claimed is not None
    assert claimed["id"] == scan_id
    first_hb = claimed["heartbeat_at"]
    assert first_hb is not None

    ok = await heartbeat_job(scan_id, worker_id)
    assert ok is True

    updated = await get_job(scan_id)
    assert updated is not None
    assert updated["heartbeat_at"] is not None


@pytest.mark.asyncio
async def test_reap_stale_jobs_resets_retryable_job() -> None:
    scan_id = gen_id("stale-retry")
    worker_id = gen_id("worker-crashed")
    await create_scan_job(scan_id=scan_id, installation_id="111", full_name="org/repo-stale")

    claimed = await claim_next_job(worker_id)
    assert claimed is not None
    assert claimed["id"] == scan_id

    # Artificially age the heartbeat
    async with async_session_scope() as session:
        from app.db.models import ScanJob

        job = await session.get(ScanJob, scan_id)
        assert job is not None
        job.heartbeat_at = utc_now() - timedelta(seconds=300)
        await session.flush()

    reaped = await reap_stale_jobs(stale_threshold_seconds=60)
    assert scan_id in reaped

    recovered = await get_job(scan_id)
    assert recovered is not None
    assert recovered["status"] == "queued"
    assert recovered["locked_by"] is None
    assert "Worker heartbeat expired" in recovered["message"]


@pytest.mark.asyncio
async def test_reap_stale_jobs_fails_exhausted_job() -> None:
    scan_id = gen_id("stale-exhausted")
    await create_scan_job(scan_id=scan_id, installation_id="111", full_name="org/repo-stale-max")

    # Simulate max attempts reached
    async with async_session_scope() as session:
        from app.db.models import ScanJob

        job = await session.get(ScanJob, scan_id)
        assert job is not None
        job.status = "running"
        job.attempts = 3
        job.max_attempts = 3
        job.locked_by = "worker-dead"
        job.heartbeat_at = utc_now() - timedelta(seconds=300)
        await session.flush()

    reaped = await reap_stale_jobs(stale_threshold_seconds=60)
    assert scan_id in reaped

    failed = await get_job(scan_id)
    assert failed is not None
    assert failed["status"] == "failed"
    assert failed["completed_at"] is not None
    assert "timed out or terminated unexpectedly" in str(failed["error"])


@pytest.mark.asyncio
async def test_fail_job_retryable_schedules_backoff() -> None:
    scan_id = gen_id("fail-retry")
    worker_id = gen_id("worker-t1")
    await create_scan_job(scan_id=scan_id, installation_id="111", full_name="org/repo-retry")
    claimed = await claim_next_job(worker_id)
    assert claimed is not None
    assert claimed["id"] == scan_id

    await fail_job(scan_id, worker_id=worker_id, error="Connection reset by peer", retryable=True)

    job = await get_job(scan_id)
    assert job is not None
    assert job["status"] == "queued"
    assert job["locked_by"] is None
    assert "Rescheduled attempt 2/3" in job["message"]
    assert job["scheduled_at"] is not None


@pytest.mark.asyncio
async def test_fail_job_terminal_when_not_retryable() -> None:
    scan_id = gen_id("fail-terminal")
    worker_id = gen_id("worker-t2")
    await create_scan_job(scan_id=scan_id, installation_id="111", full_name="org/repo-fatal")
    claimed = await claim_next_job(worker_id)
    assert claimed is not None
    assert claimed["id"] == scan_id

    await fail_job(scan_id, worker_id=worker_id, error="Repository not found (404)", retryable=False)

    job = await get_job(scan_id)
    assert job is not None
    assert job["status"] == "failed"
    assert job["stage"] == "failed"
    assert job["error"] == "Repository not found (404)"
    assert job["completed_at"] is not None


@pytest.mark.asyncio
async def test_audit_events_recorded_and_queried_via_api() -> None:
    scan_id = gen_id("audit-scan")
    await create_scan_job(scan_id=scan_id, installation_id="111", full_name="org/audit-repo")

    await record_audit_event(
        event_type="scan.custom_action",
        scan_id=scan_id,
        actor="security_analyst",
        details={"note": "Manual review started"},
    )

    client = TestClient(app)
    response = client.get(f"/api/scans/{scan_id}/events")
    assert response.status_code == 200
    data = response.json()
    assert data["scan_id"] == scan_id
    events = data["events"]
    assert len(events) >= 1
    event_types = [e["event_type"] for e in events]
    assert "scan.custom_action" in event_types


@pytest.mark.asyncio
async def test_scan_worker_run_once_executes_pipeline(monkeypatch: pytest.MonkeyPatch) -> None:
    scan_id = gen_id("worker-run-once")
    await create_scan_job(scan_id=scan_id, installation_id="12345", full_name="owner/repo-run")

    mock_run = AsyncMock()
    monkeypatch.setattr("app.services.worker.run_scan_job", mock_run)

    worker = ScanWorker(worker_id=gen_id("test-run-worker"), poll_interval=0.1)
    processed = await worker.run_once()
    assert processed is True
    mock_run.assert_awaited_once_with(scan_id, "12345", "owner/repo-run", worker_id=worker.worker_id)


@pytest.mark.asyncio
async def test_scan_worker_run_once_catches_retryable_error(monkeypatch: pytest.MonkeyPatch) -> None:
    scan_id = gen_id("worker-retry-err")
    await create_scan_job(scan_id=scan_id, installation_id="12345", full_name="owner/repo-err")

    mock_run = AsyncMock(side_effect=httpx.TimeoutException("Read timed out"))
    monkeypatch.setattr("app.services.worker.run_scan_job", mock_run)

    worker = ScanWorker(worker_id=gen_id("test-err-worker"), poll_interval=0.1)
    processed = await worker.run_once()
    assert processed is True

    job = await get_job(scan_id)
    assert job is not None
    assert job["status"] == "queued"
    assert "Rescheduled attempt 2/3" in job["message"]


@pytest.mark.asyncio
async def test_workspace_association_and_persistence() -> None:
    ws_id = gen_id("ws")
    async with async_session_scope() as session:
        ws = await session.get(Workspace, ws_id)
        if not ws:
            ws = Workspace(id=ws_id, name="Engineering Security Team", owner_id="user_123")
            session.add(ws)
            await session.flush()

    scan_id = gen_id("ws-scan")
    job = await create_scan_job(
        scan_id=scan_id,
        installation_id="999",
        full_name="corp/core-service",
        workspace_id=ws_id,
    )
    assert job["workspace_id"] == ws_id

    retrieved = await get_job(scan_id)
    assert retrieved is not None
    assert retrieved["workspace_id"] == ws_id

    # Verify audit event inherits workspace_id
    events = await list_audit_events(workspace_id=ws_id)
    assert any(e["scan_id"] == scan_id for e in events)


@pytest.mark.asyncio
async def test_expired_worker_fenced_out_from_updating_job() -> None:
    scan_id = gen_id("fence")
    worker_a = gen_id("worker-a")
    worker_b = gen_id("worker-b")

    await create_scan_job(scan_id=scan_id, installation_id="123", full_name="org/fenced-repo")
    claimed_a = await claim_next_job(worker_a)
    assert claimed_a is not None
    assert claimed_a["locked_by"] == worker_a

    # Simulate reaper or second worker taking over the job
    async with async_session_scope() as session:
        job = await session.get(ScanJob, scan_id)
        assert job is not None
        job.locked_by = worker_b
        job.attempts = 2
        await session.flush()

    # Worker A attempts to update the job with fencing check
    with pytest.raises(JobOwnershipError) as exc_info:
        await update_job(scan_id, expected_worker_id=worker_a, stage="remediating")
    assert "lost ownership" in str(exc_info.value)

    # Worker A attempts to complete the job
    completed = await complete_job(scan_id, worker_id=worker_a, message="Done by worker A")
    assert completed is False

    # Worker A attempts to fail the job
    failed = await fail_job(scan_id, worker_id=worker_a, error="Worker A crashed", retryable=False)
    assert failed is False

    # Verify Worker B's lock and running status remain uncorrupted
    current = await get_job(scan_id)
    assert current is not None
    assert current["locked_by"] == worker_b
    assert current["status"] == "running"
    assert current["stage"] == "fetching"


@pytest.mark.asyncio
async def test_graceful_cancellation_releases_job_for_immediate_recovery() -> None:
    scan_id = gen_id("release")
    worker_id = gen_id("worker-stop")
    await create_scan_job(scan_id=scan_id, installation_id="123", full_name="org/cancel-repo")

    claimed = await claim_next_job(worker_id)
    assert claimed is not None
    assert claimed["attempts"] == 1
    assert claimed["status"] == "running"

    released = await release_job(scan_id, worker_id=worker_id, reason="SIGTERM shutdown")
    assert released is True

    recovered = await get_job(scan_id)
    assert recovered is not None
    assert recovered["status"] == "queued"
    assert recovered["stage"] == "queued"
    assert recovered["locked_by"] is None
    # Ensure attempts count was decremented so graceful shutdown doesn't penalize retry limit
    assert recovered["attempts"] == 0

    # Another worker can immediately claim it
    next_worker = gen_id("worker-next")
    reclaimed = await claim_next_job(next_worker)
    assert reclaimed is not None
    assert reclaimed["id"] == scan_id
    assert reclaimed["locked_by"] == next_worker


@pytest.mark.asyncio
async def test_scan_worker_run_once_releases_job_on_cancellation(monkeypatch: pytest.MonkeyPatch) -> None:
    scan_id = gen_id("worker-cancel")
    await create_scan_job(scan_id=scan_id, installation_id="123", full_name="org/worker-cancel")

    mock_run = AsyncMock(side_effect=asyncio.CancelledError())
    monkeypatch.setattr("app.services.worker.run_scan_job", mock_run)

    worker = ScanWorker(worker_id=gen_id("test-cancel-worker"), poll_interval=0.1)
    with pytest.raises(asyncio.CancelledError):
        await worker.run_once()

    # Job must be immediately released to queued state
    job = await get_job(scan_id)
    assert job is not None
    assert job["status"] == "queued"
    assert job["locked_by"] is None

    # Audit event must record scan.released
    events = await list_audit_events(scan_id=scan_id)
    event_types = [e["event_type"] for e in events]
    assert "scan.released" in event_types


@pytest.mark.asyncio
async def test_reap_stale_job_with_null_heartbeat() -> None:
    scan_id = gen_id("null-hb")
    worker_id = gen_id("worker-crashed-fast")
    await create_scan_job(scan_id=scan_id, installation_id="123", full_name="org/fast-crash")

    claimed = await claim_next_job(worker_id)
    assert claimed is not None

    # Simulate worker crashed immediately: heartbeat_at is NULL, locked_at is old
    async with async_session_scope() as session:
        job = await session.get(ScanJob, scan_id)
        assert job is not None
        job.heartbeat_at = None
        job.locked_at = utc_now() - timedelta(seconds=300)
        await session.flush()

    reaped = await reap_stale_jobs(stale_threshold_seconds=60)
    assert scan_id in reaped

    job = await get_job(scan_id)
    assert job is not None
    assert job["status"] == "queued"
    assert job["locked_by"] is None


@pytest.mark.asyncio
async def test_concurrent_job_claims_guarantee_single_consumer() -> None:
    job_ids = [gen_id(f"concurrent-{i}") for i in range(5)]
    for jid in job_ids:
        await create_scan_job(scan_id=jid, installation_id="111", full_name=f"org/{jid}")

    workers = [gen_id(f"worker-c-{i}") for i in range(5)]
    results = await asyncio.gather(*(claim_next_job(w) for w in workers))

    claimed_ids = [r["id"] for r in results if r is not None]
    # Each of the 5 jobs must be claimed exactly once
    assert len(claimed_ids) == 5
    assert set(claimed_ids) == set(job_ids)
    # Each claimed job was assigned to a different worker
    claimed_workers = [r["locked_by"] for r in results if r is not None]
    assert len(set(claimed_workers)) == 5


@pytest.mark.asyncio
async def test_embedded_worker_disabled_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "worker_enabled", False)

    client = TestClient(app)
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["integrations"]["embedded_worker"] is False

    # start_embedded_worker should be a no-op when worker_enabled=False
    worker = await start_embedded_worker()
    assert worker._running is False
    await stop_embedded_worker()
