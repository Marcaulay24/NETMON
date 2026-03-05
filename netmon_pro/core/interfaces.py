from __future__ import annotations

from typing import Protocol, Any


class ScannerService(Protocol):
    async def trigger_scan(self, target: str | None = None) -> dict[str, Any]:
        ...


class ComplianceService(Protocol):
    async def compliance_score(self) -> dict[str, Any]:
        ...


class ThreatIntelService(Protocol):
    async def sync_feeds(self) -> dict[str, Any]:
        ...
