from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


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


class ContextRemediationRequest(BaseModel):
    """Developer-approved context for one CWE-22 patch preview."""

    finding_id: str = Field(min_length=1, max_length=64)
    authorized_root: str = Field(min_length=1, max_length=256)

    @field_validator("authorized_root")
    @classmethod
    def validate_authorized_root(cls, value: str) -> str:
        # A relative POSIX application-root directory, not a host filesystem path.
        # Exclude shell/control punctuation and special path components; the model
        # must independently validate untrusted request filenames at runtime.
        root = value.rstrip("/")
        parts = root.split("/")
        if (
            not root
            or any(
                part in {"", ".", ".."}
                or not all(char.isascii() and (char.isalnum() or char in "._-") for char in part)
                for part in parts
            )
        ):
            raise ValueError(
                "authorized_root must be a relative application directory such as uploads/"
            )
        return root + "/"


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
    scanner: str = "raksa"
    rule_id: str | None = None


class PatchProposal(BaseModel):
    path: str
    old_text: str
    new_text: str
    reason: str
    scanner: str | None = None
    cwe: str | None = None
    finding_id: str | None = None


class VerificationCheckSchema(BaseModel):
    name: str
    status: Literal["passed", "failed", "unverified", "error", "skipped", "unavailable", "not_run"]
    passed: bool
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class VerificationEvidenceSchema(BaseModel):
    status: Literal["verified", "unverified", "failed", "error"]
    eligible_for_pr: bool
    message: str
    sandbox_provider: str
    static_recheck: VerificationCheckSchema
    security_exploit: VerificationCheckSchema
    regression_tests: VerificationCheckSchema
    static_recheck_passed: bool = False
    security_exploit_passed: bool = False
    regression_tests_passed: bool = False
    tests: dict[str, Any] | None = None
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    details: dict[str, Any] = Field(default_factory=dict)


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
    review_only: bool = False
    title: str = Field(default="Raksa security remediation", min_length=5, max_length=200)
    body: str = Field(default="This pull request was prepared by Raksa. Please review the code and test evidence carefully.", max_length=8000)
