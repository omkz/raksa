from dataclasses import asdict, dataclass, field
from typing import Any, Literal, Protocol


@dataclass(frozen=True)
class SecurityFinding:
    id: str
    title: str
    severity: str
    path: str
    line: int
    evidence: str
    description: str
    confidence: float
    scanner: str
    rule_id: str
    cwe: str | None = None
    status: str = "potential"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScannerResult:
    name: str
    status: Literal["completed", "partial", "skipped", "unavailable", "error"]
    findings: list[SecurityFinding] = field(default_factory=list)
    message: str = ""

    def report(self) -> dict[str, Any]:
        return {"name": self.name, "status": self.status,
                "finding_count": len(self.findings), "message": self.message}


class ScannerAdapter(Protocol):
    name: str

    async def scan(self, files: dict[str, str], *, max_findings: int) -> ScannerResult: ...
