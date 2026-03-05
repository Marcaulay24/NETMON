from __future__ import annotations

from datetime import datetime

from sqlalchemy import String, Integer, DateTime, Float, Text, Boolean
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Device(Base):
    __tablename__ = "devices"

    ip: Mapped[str] = mapped_column(String(64), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), default="")
    mac: Mapped[str] = mapped_column(String(64), default="")
    vendor: Mapped[str] = mapped_column(String(255), default="")
    os_name: Mapped[str] = mapped_column(String(255), default="")
    group_tag: Mapped[str] = mapped_column(String(128), default="")
    is_critical: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_ip: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    rule_level: Mapped[int] = mapped_column(Integer, default=0)
    message: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ScanResult(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target: Mapped[str] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(32), default="queued")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    findings_json: Mapped[str] = mapped_column(Text, default="{}")


class FimEvent(Base):
    __tablename__ = "fim_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host: Mapped[str] = mapped_column(String(128), index=True)
    path: Mapped[str] = mapped_column(Text)
    event_type: Mapped[str] = mapped_column(String(32))
    hash_before: Mapped[str] = mapped_column(String(128), default="")
    hash_after: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class IocMatch(Base):
    __tablename__ = "ioc_matches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ioc_type: Mapped[str] = mapped_column(String(32), index=True)
    ioc_value: Mapped[str] = mapped_column(String(512), index=True)
    source_feed: Mapped[str] = mapped_column(String(128), default="manual")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ComplianceEntry(Base):
    __tablename__ = "compliance_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    framework: Mapped[str] = mapped_column(String(64), index=True)
    control_id: Mapped[str] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(16), default="WARN")
    evidence_ref: Mapped[str] = mapped_column(Text, default="")
    owner: Mapped[str] = mapped_column(String(128), default="")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ReportRecord(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_type: Mapped[str] = mapped_column(String(64), index=True)
    classification: Mapped[str] = mapped_column(String(32), default="internal")
    generated_by: Mapped[str] = mapped_column(String(128), default="system")
    file_path: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
