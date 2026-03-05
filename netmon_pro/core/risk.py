from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class RiskInput:
    likelihood: float
    impact: float
    threat_intel_weight: float = 0.0


def normalized_risk_score(inp: RiskInput) -> int:
    """Risk Score = (Likelihood × Impact) + Threat Intel Weight, normalized 0-100."""
    raw = (inp.likelihood * inp.impact) + inp.threat_intel_weight
    return max(0, min(100, int(round(raw))))


def risk_band(score: int) -> str:
    if score <= 30:
        return "GREEN"
    if score <= 60:
        return "YELLOW"
    return "RED"
