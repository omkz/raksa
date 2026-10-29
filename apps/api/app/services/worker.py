import asyncio
import logging
import uuid

import httpx

from app.config import settings
from app.services.github_app import GitHubAppError
from app.services.job_store import (
    JobOwnershipError,
    claim_next_job,
    fail_job,
    heartbeat_job,
    reap_stale_jobs,
    release_job,
)
from app.services.nebius import NebiusUnavailable
from app.services.sandbox import SandboxError
from app.services.workflow import run_scan_job

logger = logging.getLogger("raksa.worker")


class ScanWorker:
    def __init__(
        self,
        worker_id: str | None = None,
        poll_interval: float | None = None,
        heartbeat_interval: float | None = None,
        stale_timeout: int | None = None,
    ) -> None:
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex[:8]}"
        self.poll_interval = (
            poll_interval
            if poll_interval is not None
            else settings.worker_poll_interval_seconds
        )
        self.heartbeat_interval = (
            heartbeat_interval
            if heartbeat_interval is not None
            else settings.worker_heartbeat_interval_seconds
        )
        self.stale_timeout = (
            stale_timeout
            if stale_timeout is not None
            else settings.worker_stale_timeout_seconds
        )
        self._running = False
        self._loop_task: asyncio.Task[None] | None = None
        self._active_job_id: str | None = None
        self._heartbeat_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        logger.info(f"ScanWorker {self.worker_id} started (poll={self.poll_interval}s, heartbeat={self.heartbeat_interval}s)")
        self._loop_task = asyncio.create_task(self._run_loop())

    async def stop(self, timeout_seconds: float = 10.0) -> None:
        if not self._running:
            return
        self._running = False
        logger.info(f"ScanWorker {self.worker_id} stopping...")

        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()

        if self._loop_task:
            try:
                await asyncio.wait_for(asyncio.shield(self._loop_task), timeout=timeout_seconds)
            except (TimeoutError, asyncio.CancelledError):
                logger.warning(f"ScanWorker {self.worker_id} loop exceeded graceful stop timeout; cancelling task.")
                self._loop_task.cancel()
            self._loop_task = None
        logger.info(f"ScanWorker {self.worker_id} stopped.")

    async def _run_loop(self) -> None:
        while self._running:
            try:
                processed = await self.run_once()
                if not processed and self._running:
                    await asyncio.sleep(self.poll_interval)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error(f"Unexpected error in worker loop: {exc}", exc_info=True)
                if self._running:
                    await asyncio.sleep(self.poll_interval)

    async def run_once(self) -> bool:
        """Attempt to reap stale jobs and claim + execute one pending job. Returns True if a job was processed."""
        # 1. Periodically reap stale jobs left by crashed workers
        try:
            reaped = await reap_stale_jobs(stale_threshold_seconds=self.stale_timeout)
            if reaped:
                logger.warning(f"Reaped {len(reaped)} stale jobs: {reaped}")
        except Exception as exc:
            logger.error(f"Error reaping stale jobs: {exc}", exc_info=True)

        # 2. Claim next available job atomically
        try:
            job = await claim_next_job(self.worker_id)
        except Exception as exc:
            logger.error(f"Error claiming next job from database: {exc}", exc_info=True)
            return False

        if not job:
            return False

        # 3. Process claimed job with live heartbeat
        scan_id = str(job["id"])
        self._active_job_id = scan_id
        logger.info(f"Worker {self.worker_id} executing job {scan_id} ({job.get('full_name')})")

        self._heartbeat_task = asyncio.create_task(self._run_heartbeat(scan_id))
        try:
            installation_id = str(job.get("installation_id") or "")
            full_name = str(job.get("full_name") or "")
            await run_scan_job(scan_id, installation_id, full_name, worker_id=self.worker_id)
            logger.info(f"Worker {self.worker_id} completed job {scan_id}")
        except JobOwnershipError as exc:
            logger.warning(f"Worker {self.worker_id} fenced out of job {scan_id}: {exc}")
        except asyncio.CancelledError:
            logger.warning(f"Worker {self.worker_id} cancelled during job {scan_id}; releasing job for recovery.")
            await release_job(scan_id, worker_id=self.worker_id, reason="Worker cancelled during shutdown")
            raise
        except Exception as exc:
            logger.error(f"Worker {self.worker_id} job {scan_id} failed with error: {exc}", exc_info=True)
            retryable = self._is_retryable_error(exc)
            await fail_job(
                scan_id,
                worker_id=self.worker_id,
                error=f"{exc.__class__.__name__}: {exc}",
                retryable=retryable,
            )
        finally:
            if self._heartbeat_task and not self._heartbeat_task.done():
                self._heartbeat_task.cancel()
            self._heartbeat_task = None
            self._active_job_id = None

        return True

    async def _run_heartbeat(self, scan_id: str) -> None:
        try:
            while self._running and self._active_job_id == scan_id:
                await asyncio.sleep(self.heartbeat_interval)
                alive = await heartbeat_job(scan_id, self.worker_id)
                if not alive:
                    logger.warning(
                        f"Heartbeat failed for job {scan_id}: lock lost by worker {self.worker_id}."
                    )
                    break
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.warning(f"Failed to record heartbeat for job {scan_id}: {exc}")

    @staticmethod
    def _is_retryable_error(exc: Exception) -> bool:
        """Classify transient infrastructure or rate-limit errors as retryable."""
        if isinstance(exc, (httpx.TimeoutException, httpx.NetworkError)):
            return True
        if isinstance(exc, NebiusUnavailable):
            return True
        if isinstance(exc, SandboxError) and "timeout" in str(exc).lower():
            return True
        if isinstance(exc, GitHubAppError):
            msg = str(exc).lower()
            if "502" in msg or "503" in msg or "504" in msg or "timeout" in msg:
                return True
        return False


_GLOBAL_WORKER: ScanWorker | None = None


def get_worker() -> ScanWorker:
    global _GLOBAL_WORKER
    if _GLOBAL_WORKER is None:
        _GLOBAL_WORKER = ScanWorker()
    return _GLOBAL_WORKER


async def start_embedded_worker() -> ScanWorker:
    worker = get_worker()
    if settings.worker_enabled:
        await worker.start()
    return worker


async def stop_embedded_worker() -> None:
    global _GLOBAL_WORKER
    if _GLOBAL_WORKER is not None:
        await _GLOBAL_WORKER.stop()
        _GLOBAL_WORKER = None
