"""Standalone worker process entrypoint for Raksa.

Usage:
    python -m app.worker
"""

import asyncio
import logging
import signal
import sys

from app.db.session import close_db, init_db
from app.services.worker import ScanWorker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("raksa.worker_main")


async def main() -> None:
    logger.info("Initializing database schema...")
    await init_db()

    worker = ScanWorker()
    stop_event = asyncio.Event()

    def _signal_handler() -> None:
        logger.info("Received termination signal. Shutting down worker...")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            pass

    await worker.start()

    await stop_event.wait()
    await worker.stop()
    await close_db()
    logger.info("Worker process exited cleanly.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
