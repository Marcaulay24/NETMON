from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except Exception:
    yaml = None


@dataclass(slots=True)
class AppearanceConfig:
    theme: str = "dark"
    accent: str = "#00d4ff"


@dataclass(slots=True)
class ScanConfig:
    max_workers: int = 64
    rate_limit_pps: int = 800
    schedule_cron: str = "*/30 * * * *"


@dataclass(slots=True)
class ApiConfig:
    host: str = "127.0.0.1"
    port: int = 8091
    api_key: str = "change-me"


@dataclass(slots=True)
class DatabaseConfig:
    url: str = "sqlite:///netmon_modular.db"
    wal_mode: bool = True


@dataclass(slots=True)
class AppConfig:
    appearance: AppearanceConfig = field(default_factory=AppearanceConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    api: ApiConfig = field(default_factory=ApiConfig)
    db: DatabaseConfig = field(default_factory=DatabaseConfig)


def _merge_dataclass(obj: Any, data: dict[str, Any]) -> None:
    for key, value in data.items():
        if not hasattr(obj, key):
            continue
        current = getattr(obj, key)
        if hasattr(current, "__dataclass_fields__") and isinstance(value, dict):
            _merge_dataclass(current, value)
        else:
            setattr(obj, key, value)


def load_config(path: str | Path = "config.yaml") -> AppConfig:
    cfg = AppConfig()
    p = Path(path)
    if not p.exists():
        return cfg
    if yaml is None:
        raise RuntimeError("PyYAML not installed; install pyyaml to use config.yaml")
    payload = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        raise ValueError("config.yaml root must be a mapping")
    _merge_dataclass(cfg, payload)
    return cfg
