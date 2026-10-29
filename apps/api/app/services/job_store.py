import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, delete, or_, select
from sqlalchemy.orm import selectinload

from app.config import settings
from app.db.models import AuditEvent, Finding, ScanJob, Workspace
from app.db.session import async_session_scope

logger = logging.getLogger("raksa.job_store")


def utc_now() -> datetime:
    return datetime.now(UTC)


async def get_job(scan_id: str) -> dict[str, Any] | None:
    async with async_session_scope() as session:
        stmt = (
            select(ScanJob)
            .where(ScanJob.id == scan_id)
            .options(selectinload(ScanJob.findings))
        )
        result = await session.execute(stmt)
        job = result.scalar_one_or_none()
        return job.as_dict() if job else None


async def create_scan_job(
    scan_id: str,
    installation_id: str | None = None,
    full_name: str | None = None,
    workspace_id: str = "default",
    actor: str = "system",
    **attrs: Any,
) -> dict[str, Any]:
    async with async_session_scope() as session:
        # Ensure workspace exists
        ws_res = await session.execute(select(Workspace).where(Workspace.id == workspace_id))
        if not ws_res.scalar_one_or_none():
            session.add(Workspace(id=workspace_id, name="Default Workspace"))
            await session.flush()

        job = ScanJob(
            id=scan_id,
            workspace_id=workspace_id,
            installation_id=installation_id,
            full_name=full_name,
            status=attrs.get("status", "queued"),
            stage=attrs.get("stage", "queued"),
            message=attrs.get("message", "Scan queued."),
            max_attempts=attrs.get("max_attempts", settings.worker_max_attempts),
            scheduled_at=attrs.get("scheduled_at", utc_now()),
            findings=[],
        )
        session.add(job)

        event = AuditEvent(
            id=uuid.uuid4().hex,
            workspace_id=workspace_id,
            scan_id=scan_id,
            event_type="scan.created",
            actor=actor,
            details={"full_name": full_name, "installation_id": installation_id},
        )
        session.add(event)
        await session.flush()
        return job.as_dict()


async def put_job(scan_id: str, payload: dict[str, Any]) -> None:
    async with async_session_scope() as session:
        stmt = (
            select(ScanJob)
            .where(ScanJob.id == scan_id)
            .options(selectinload(ScanJob.findings))
        )
        result = await session.execute(stmt)
        job = result.scalar_one_or_none()

        workspace_id = payload.get("workspace_id", "default")
        ws_res = await session.execute(select(Workspace).where(Workspace.id == workspace_id))
        if not ws_res.scalar_one_or_none():
            session.add(Workspace(id=workspace_id, name="Default Workspace"))
            await session.flush()

        if not job:
            job = ScanJob(id=scan_id, workspace_id=workspace_id)
            session.add(job)

        for key, val in payload.items():
            if key in {"findings", "id", "audit_events", "created_at", "updated_at"}:
                continue
            if hasattr(job, key):
                setattr(job, key, val)

        # Handle findings synchronization
        if "findings" in payload and payload["findings"] is not None:
            await _sync_findings(session, scan_id, payload["findings"])

        await session.flush()


class JobOwnershipError(RuntimeError):
    """Raised when an expired or fenced-out worker attempts to update a job it no longer owns."""


async def update_job(
    scan_id: str,
    *,
    expected_worker_id: str | None = None,
    **updates: Any,
) -> None:
    async with async_session_scope() as session:
        stmt = (
            select(ScanJob)
            .where(ScanJob.id == scan_id)
            .options(selectinload(ScanJob.findings))
        )
        result = await session.execute(stmt)
        job = result.scalar_one_or_none()
        if not job:
            return

        if expected_worker_id is not None:
            if job.locked_by != expected_worker_id or job.status != "running":
                msg = (
                    f"Fencing reject: worker {expected_worker_id} lost ownership of job {scan_id} "
                    f"(current status={job.status!r}, locked_by={job.locked_by!r}). Update rejected."
                )
                logger.warning(msg)
                raise JobOwnershipError(msg)

        for key, val in updates.items():
            if key in {"findings", "id", "audit_events", "created_at", "updated_at"}:
                continue
            if hasattr(job, key):
                setattr(job, key, val)

        if "findings" in updates and updates["findings"] is not None:
            await _sync_findings(session, scan_id, updates["findings"])

        # Track audit event on completion or failure
        if updates.get("status") == "completed" and not job.completed_at:
            job.completed_at = utc_now()
            session.add(
                AuditEvent(
                    id=uuid.uuid4().hex,
                    workspace_id=job.workspace_id,
                    scan_id=scan_id,
                    event_type="scan.completed",
                    actor="worker",
                    details={"stage": job.stage, "message": job.message},
                )
            )
        elif updates.get("status") == "failed":
            if not job.completed_at:
                job.completed_at = utc_now()
            session.add(
                AuditEvent(
                    id=uuid.uuid4().hex,
                    workspace_id=job.workspace_id,
                    scan_id=scan_id,
                    event_type="scan.failed",
                    actor="worker",
                    details={"stage": job.stage, "error": job.error or updates.get("error")},
                )
            )

        await session.flush()


async def _sync_findings(session: Any, scan_id: str, findings_data: list[dict[str, Any]]) -> None:
    # Delete previous findings for this scan to avoid orphaned/duplicate entries
    await session.execute(delete(Finding).where(Finding.scan_id == scan_id))
    seen_ids: set[str] = set()
    for item in findings_data:
        fid = str(item.get("id") or f"f-{uuid.uuid4().hex[:12]}")
        if fid in seen_ids:
            fid = f"{fid}-{uuid.uuid4().hex[:4]}"
        seen_ids.add(fid)
        finding = Finding(
            id=fid,
            scan_id=scan_id,
            title=str(item.get("title", "Potential Vulnerability")),
            severity=str(item.get("severity", "medium")),
            cwe=item.get("cwe"),
            path=str(item.get("path", "")),
            line=int(item.get("line", 1)),
            evidence=str(item.get("evidence", "")),
            description=str(item.get("description", "")),
            confidence=float(item.get("confidence", 0.5)),
            status=str(item.get("status", "potential")),
        )
        session.add(finding)


async def claim_next_job(worker_id: str) -> dict[str, Any] | None:
    """Atomically claim the next queued scan job via SELECT ... FOR UPDATE SKIP LOCKED."""
    async with async_session_scope() as session:
        now = utc_now()
        stmt = (
            select(ScanJob)
            .where(
                ScanJob.status == "queued",
                ScanJob.scheduled_at <= now,
            )
            .options(selectinload(ScanJob.findings))
            .order_by(ScanJob.scheduled_at.asc())
            .limit(1)
        )
        # Apply row-level lock if supported by database dialect
        if session.bind and session.bind.dialect.name == "postgresql":
            stmt = stmt.with_for_update(skip_locked=True)

        result = await session.execute(stmt)
        job = result.scalar_one_or_none()
        if not job:
            return None

        job.attempts += 1
        job.status = "running"
        job.locked_by = worker_id
        job.locked_at = now
        job.heartbeat_at = now
        job.stage = "fetching"
        job.message = "Job claimed by background worker; initiating scan pipeline…"

        event = AuditEvent(
            id=uuid.uuid4().hex,
            workspace_id=job.workspace_id,
            scan_id=job.id,
            event_type="scan.started",
            actor=f"worker:{worker_id}",
            details={"attempt": job.attempts, "max_attempts": job.max_attempts},
        )
        session.add(event)
        await session.flush()
        return job.as_dict()


async def heartbeat_job(scan_id: str, worker_id: str) -> bool:
    """Update heartbeat timestamp of an active job to prove worker liveness."""
    async with async_session_scope() as session:
        now = utc_now()
        stmt = select(ScanJob).where(ScanJob.id == scan_id, ScanJob.locked_by == worker_id)
        result = await session.execute(stmt)
        job = result.scalar_one_or_none()
        if job and job.status == "running":
            job.heartbeat_at = now
            return True
        return False


async def complete_job(
    scan_id: str,
    worker_id: str | None = None,
    message: str = "Analysis finished.",
    **attrs: Any,
) -> bool:
    """Mark job completed and release worker lock. Returns True if updated, False if fenced out."""
    async with async_session_scope() as session:
        stmt = (
            select(ScanJob)
            .where(ScanJob.id == scan_id)
            .options(selectinload(ScanJob.findings))
        )
        result = await session.execute(stmt)
        job = result.scalar_one_or_none()
        if not job:
            return False

        if worker_id is not None and job.locked_by != worker_id:
            logger.warning(
                f"Fencing reject: worker {worker_id} cannot complete job {scan_id}; "
                f"lock currently held by {job.locked_by!r} (status={job.status})"
            )
            return False

        now = utc_now()
        job.status = "completed"
        job.stage = attrs.get("stage", "complete")
        job.message = message
        job.completed_at = now
        job.locked_by = None
        job.locked_at = None
        job.heartbeat_at = None

        for k, v in attrs.items():
            if hasattr(job, k) and k not in {"id", "findings", "created_at", "updated_at"}:
                setattr(job, k, v)

        if "findings" in attrs and attrs["findings"] is not None:
            await _sync_findings(session, scan_id, attrs["findings"])

        event = AuditEvent(
            id=uuid.uuid4().hex,
            workspace_id=job.workspace_id,
            scan_id=scan_id,
            event_type="scan.completed",
            actor=f"worker:{worker_id}" if worker_id else "system",
            details={"message": message, "stage": job.stage},
        )
        session.add(event)
        await session.flush()
        return True


async def fail_job(
    scan_id: str,
    worker_id: str | None = None,
    error: str = "",
    retryable: bool = False,
) -> bool:
    """Fail a job or reschedule it if retryable within bounded max attempts. Returns True if updated, False if fenced out."""
    async with async_session_scope() as session:
        stmt = select(ScanJob).where(ScanJob.id == scan_id)
        result = await session.execute(stmt)
        job = result.scalar_one_or_none()
        if not job:
            return False

        if worker_id is not None and job.locked_by != worker_id:
            logger.warning(
                f"Fencing reject: worker {worker_id} cannot fail job {scan_id}; "
                f"lock currently held by {job.locked_by!r} (status={job.status})"
            )
            return False

        now = utc_now()
        if retryable and job.attempts < job.max_attempts:
            backoff_seconds = int(5 * (2 ** (job.attempts - 1)))
            job.status = "queued"
            job.stage = "queued"
            job.message = f"Temporary failure: {error}. Rescheduled attempt {job.attempts + 1}/{job.max_attempts} in {backoff_seconds}s."
            job.scheduled_at = now + timedelta(seconds=backoff_seconds)
            job.locked_by = None
            job.locked_at = None
            job.heartbeat_at = None

            event = AuditEvent(
                id=uuid.uuid4().hex,
                workspace_id=job.workspace_id,
                scan_id=scan_id,
                event_type="scan.retrying",
                actor=f"worker:{worker_id}" if worker_id else "system",
                details={
                    "error": error,
                    "attempt": job.attempts,
                    "max_attempts": job.max_attempts,
                    "rescheduled_for": job.scheduled_at.isoformat(),
                },
            )
            session.add(event)
        else:
            job.status = "failed"
            job.stage = "failed"
            job.error = error
            job.message = f"Investigation could not complete: {error}"
            job.completed_at = now
            job.locked_by = None
            job.locked_at = None
            job.heartbeat_at = None

            event = AuditEvent(
                id=uuid.uuid4().hex,
                workspace_id=job.workspace_id,
                scan_id=scan_id,
                event_type="scan.failed",
                actor=f"worker:{worker_id}" if worker_id else "system",
                details={"error": error, "attempts": job.attempts},
            )
            session.add(event)

        await session.flush()
        return True


async def release_job(
    scan_id: str,
    worker_id: str,
    reason: str = "Worker shutdown",
) -> bool:
    """Release a running job back to queued so another worker can immediately recover it."""
    async with async_session_scope() as session:
        stmt = select(ScanJob).where(ScanJob.id == scan_id, ScanJob.locked_by == worker_id)
        result = await session.execute(stmt)
        job = result.scalar_one_or_none()
        if not job or job.status != "running":
            return False

        if job.attempts > 0:
            job.attempts -= 1

        job.status = "queued"
        job.stage = "queued"
        job.message = f"Scan rescheduled: {reason}"
        job.locked_by = None
        job.locked_at = None
        job.heartbeat_at = None
        job.scheduled_at = utc_now()

        event = AuditEvent(
            id=uuid.uuid4().hex,
            workspace_id=job.workspace_id,
            scan_id=scan_id,
            event_type="scan.released",
            actor=f"worker:{worker_id}",
            details={"reason": reason},
        )
        session.add(event)
        await session.flush()
        return True


async def reap_stale_jobs(stale_threshold_seconds: int = 180) -> list[str]:
    """Find jobs that crashed or timed out and reset or mark them failed with audit diagnostics."""
    reaped_ids: list[str] = []
    async with async_session_scope() as session:
        cutoff = utc_now() - timedelta(seconds=stale_threshold_seconds)
        stmt = select(ScanJob).where(
            ScanJob.status == "running",
            or_(
                ScanJob.heartbeat_at < cutoff,
                and_(ScanJob.heartbeat_at.is_(None), ScanJob.locked_at < cutoff),
            ),
        )
        if session.bind and session.bind.dialect.name == "postgresql":
            stmt = stmt.with_for_update(skip_locked=True)

        result = await session.execute(stmt)
        stale_jobs = result.scalars().all()

        for job in stale_jobs:
            reaped_ids.append(job.id)
            if job.attempts < job.max_attempts:
                job.status = "queued"
                job.stage = "queued"
                job.message = f"Worker heartbeat expired (attempt {job.attempts}/{job.max_attempts}). Job reset to queue for recovery."
                job.scheduled_at = utc_now()
                job.locked_by = None
                job.locked_at = None
                job.heartbeat_at = None
                event = AuditEvent(
                    id=uuid.uuid4().hex,
                    workspace_id=job.workspace_id,
                    scan_id=job.id,
                    event_type="worker.stale_reset",
                    actor="worker_reaper",
                    details={"stale_worker": job.locked_by, "attempt": job.attempts},
                )
                session.add(event)
            else:
                job.status = "failed"
                job.stage = "failed"
                job.error = "Scan worker timed out or terminated unexpectedly without reporting completion."
                job.message = "Scan worker terminated unexpectedly."
                job.completed_at = utc_now()
                job.locked_by = None
                job.locked_at = None
                job.heartbeat_at = None
                event = AuditEvent(
                    id=uuid.uuid4().hex,
                    workspace_id=job.workspace_id,
                    scan_id=job.id,
                    event_type="scan.failed_timeout",
                    actor="worker_reaper",
                    details={"stale_worker": job.locked_by, "attempts": job.attempts},
                )
                session.add(event)

        await session.flush()
    return reaped_ids


async def record_audit_event(
    event_type: str,
    scan_id: str | None = None,
    actor: str = "system",
    details: dict[str, Any] | None = None,
    workspace_id: str | None = None,
) -> dict[str, Any]:
    async with async_session_scope() as session:
        ws_id = workspace_id or "default"
        event = AuditEvent(
            id=uuid.uuid4().hex,
            workspace_id=ws_id,
            scan_id=scan_id,
            event_type=event_type,
            actor=actor,
            details=details or {},
        )
        session.add(event)
        await session.flush()
        return event.as_dict()


async def list_audit_events(
    scan_id: str | None = None,
    workspace_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    async with async_session_scope() as session:
        stmt = select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)
        if scan_id:
            stmt = stmt.where(AuditEvent.scan_id == scan_id)
        if workspace_id:
            stmt = stmt.where(AuditEvent.workspace_id == workspace_id)
        result = await session.execute(stmt)
        return [item.as_dict() for item in result.scalars().all()]
