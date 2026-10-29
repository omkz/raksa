from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
    inspect,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(UTC)


class Workspace(Base):
    __tablename__ = "workspaces"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default="default")
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="Default Workspace")
    owner_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        server_default=func.now(),
        onupdate=utc_now,
    )

    scans: Mapped[list["ScanJob"]] = relationship(
        "ScanJob", back_populates="workspace", cascade="all, delete-orphan"
    )

    def as_dict(self) -> dict[str, Any]:
        state = inspect(self)
        expired = state.expired_attributes if state is not None else set()
        created = getattr(self, "created_at", None) if "created_at" not in expired else None
        updated = getattr(self, "updated_at", None) if "updated_at" not in expired else None
        return {
            "id": self.id,
            "name": self.name,
            "owner_id": self.owner_id,
            "created_at": created.isoformat() if created else None,
            "updated_at": updated.isoformat() if updated else None,
        }


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        default="default",
        index=True,
    )
    installation_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    default_branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    base_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)

    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued", index=True)
    stage: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    message: Mapped[str] = mapped_column(Text, nullable=False, default="Scan queued.")
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    diff: Mapped[str | None] = mapped_column(Text, nullable=True)
    pull_request_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    patch_messages: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    patches: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    research: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    verification: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    changed_files: Mapped[dict[str, str] | None] = mapped_column(JSON, nullable=True)

    # Background worker execution & reliability tracking
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    locked_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    scheduled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        server_default=func.now(),
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        server_default=func.now(),
        onupdate=utc_now,
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    workspace: Mapped["Workspace"] = relationship("Workspace", back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )
    audit_events: Mapped[list["AuditEvent"]] = relationship(
        "AuditEvent", back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )

    def as_dict(self) -> dict[str, Any]:
        state = inspect(self)
        expired = state.expired_attributes if state is not None else set()

        def _val(attr: str, fallback: Any = None) -> Any:
            if attr in expired:
                return fallback
            return getattr(self, attr, fallback)

        findings_data: list[dict[str, Any]] = []
        if state is not None and "findings" not in state.unloaded:
            findings_data = [f.as_dict() for f in (self.findings or [])]

        created = _val("created_at")
        updated = _val("updated_at")
        completed = _val("completed_at")
        locked = _val("locked_at")
        heartbeat = _val("heartbeat_at")
        scheduled = _val("scheduled_at")

        return {
            "id": self.id,
            "workspace_id": _val("workspace_id", "default"),
            "installation_id": _val("installation_id"),
            "status": _val("status", "queued"),
            "stage": _val("stage", "queued"),
            "message": _val("message", ""),
            "full_name": _val("full_name"),
            "default_branch": _val("default_branch"),
            "base_sha": _val("base_sha"),
            "findings": findings_data,
            "patches": list(_val("patches") or []),
            "diff": _val("diff"),
            "research": list(_val("research") or []),
            "summary": _val("summary"),
            "verification": _val("verification"),
            "pull_request_url": _val("pull_request_url"),
            "error": _val("error"),
            "patch_messages": list(_val("patch_messages") or []),
            "changed_files": _val("changed_files"),
            "patched_files": _val("changed_files") or {},
            "attempts": _val("attempts", 0),
            "max_attempts": _val("max_attempts", 3),
            "locked_at": locked.isoformat() if locked else None,
            "locked_by": _val("locked_by"),
            "heartbeat_at": heartbeat.isoformat() if heartbeat else None,
            "scheduled_at": scheduled.isoformat() if scheduled else None,
            "created_at": created.isoformat() if created else None,
            "updated_at": updated.isoformat() if updated else None,
            "completed_at": completed.isoformat() if completed else None,
        }


class Finding(Base):
    __tablename__ = "findings"

    scan_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
    )
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    cwe: Mapped[str | None] = mapped_column(String(32), nullable=True)
    path: Mapped[str] = mapped_column(String(512), nullable=False)
    line: Mapped[int] = mapped_column(Integer, nullable=False)
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="potential")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    scan: Mapped["ScanJob"] = relationship("ScanJob", back_populates="findings")

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "title": self.title,
            "severity": self.severity,
            "cwe": self.cwe,
            "path": self.path,
            "line": self.line,
            "evidence": self.evidence,
            "description": self.description,
            "confidence": self.confidence,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("workspaces.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    scan_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    details: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )

    scan: Mapped["ScanJob"] = relationship("ScanJob", back_populates="audit_events")

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "workspace_id": self.workspace_id,
            "scan_id": self.scan_id,
            "event_type": self.event_type,
            "actor": self.actor,
            "details": self.details,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
