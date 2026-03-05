from __future__ import annotations

from dataclasses import dataclass

from netmon_pro.config import AppConfig, load_config
from netmon_pro.db.session import build_engine, build_session_factory, init_db
from netmon_pro.services.compliance import ComplianceServiceImpl
from netmon_pro.services.scanner import AsyncScannerService
from netmon_pro.services.threat_intel import ThreatIntelServiceImpl


@dataclass(slots=True)
class AppContainer:
    config: AppConfig
    engine: object
    session_factory: object
    scanner: AsyncScannerService
    compliance: ComplianceServiceImpl
    threat_intel: ThreatIntelServiceImpl


def build_container(config_path: str = "config.yaml") -> AppContainer:
    cfg = load_config(config_path)
    engine = build_engine(cfg.db.url)
    init_db(engine, enable_wal=cfg.db.wal_mode)
    session_factory = build_session_factory(engine)
    return AppContainer(
        config=cfg,
        engine=engine,
        session_factory=session_factory,
        scanner=AsyncScannerService(max_workers=cfg.scan.max_workers),
        compliance=ComplianceServiceImpl(),
        threat_intel=ThreatIntelServiceImpl(),
    )
