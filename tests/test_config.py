from pathlib import Path

from netmon_pro.config import load_config


def test_load_config_defaults_when_missing(tmp_path):
    cfg = load_config(tmp_path / "missing.yaml")
    assert cfg.api.port == 8091


def test_load_config_yaml_override(tmp_path):
    data = """
api:
  port: 9001
scan:
  max_workers: 8
"""
    p = tmp_path / "cfg.yaml"
    p.write_text(data, encoding="utf-8")
    cfg = load_config(p)
    assert cfg.api.port == 9001
    assert cfg.scan.max_workers == 8
