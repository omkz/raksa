from typing import Literal

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str
    app: str
    integrations: dict[str, bool]


class RepositoryItem(BaseModel):
    full_name: str
    private: bool
    default_branch: str
    html_url: str
    description: str | None = None


class ScanRequest(BaseModel):
    full_name: str = Field(min_length=3, max_length=200, pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class Finding(BaseModel):
    id: str
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    cwe: str | None = None
    path: str
    line: int
    evidence: str
    description: str
    confidence: float = Field(ge=0, le=1)
    status: Literal["potential", "reproduced", "fixed", "unverified"] = "potential"


class PatchProposal(BaseModel):
    path: str
    old_text: str
    new_text: str
    reason: str


class ScanResult(BaseModel):
    id: str
    status: Literal["queued", "running", "completed", "failed"]
    stage: str
    message: str
    full_name: str | None = None
    default_branch: str | None = None
    base_sha: str | None = None
    findings: list[Finding] = []
    patches: list[PatchProposal] = []
    diff: str | None = None
    research: list[dict[str, str]] = []
    verification: dict[str, object] | None = None
    pull_request_url: str | None = None
    error: str | None = None


class CreatePRRequest(BaseModel):
    title: str = Field(default="Raksa security remediation", min_length=5, max_length=200)
    body: str = Field(default="This pull request was prepared by Raksa. Please review the code and test evidence carefully.", max_length=8000)
