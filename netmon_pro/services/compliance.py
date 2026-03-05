from __future__ import annotations

from netmon_pro.core.risk import RiskInput, normalized_risk_score, risk_band


class ComplianceServiceImpl:
    def __init__(self):
        self.frameworks = ["NIST_CSF", "ISO_27001", "PCI_DSS_v4", "CIS_v8"]

    async def compliance_score(self) -> dict:
        score = normalized_risk_score(RiskInput(likelihood=6, impact=7, threat_intel_weight=8))
        return {
            "score": score,
            "band": risk_band(score),
            "frameworks": self.frameworks,
        }
