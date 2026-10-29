from app.scanners.base import ScannerResult
from app.scanners.opengrep import opengrep


async def scan_snapshot(files: dict[str, str], *, max_findings: int) -> list[ScannerResult]:
    return [await opengrep.scan(files, max_findings=max_findings)]
