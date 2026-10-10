import asyncio
from typing import Any

JOBS: dict[str, dict[str, Any]] = {}
JOBS_LOCK = asyncio.Lock()


async def put_job(job_id: str, payload: dict[str, Any]) -> None:
    async with JOBS_LOCK:
        JOBS[job_id] = payload


async def update_job(job_id: str, **updates: Any) -> None:
    async with JOBS_LOCK:
        if job_id in JOBS:
            JOBS[job_id].update(updates)


async def get_job(job_id: str) -> dict[str, Any] | None:
    async with JOBS_LOCK:
        value = JOBS.get(job_id)
        return dict(value) if value else None
