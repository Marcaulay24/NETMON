from netmon_pro.core.risk import RiskInput, normalized_risk_score, risk_band


def test_risk_score_clamped():
    assert normalized_risk_score(RiskInput(likelihood=100, impact=100, threat_intel_weight=100)) == 100
    assert normalized_risk_score(RiskInput(likelihood=-100, impact=1, threat_intel_weight=0)) == 0


def test_risk_band_ranges():
    assert risk_band(0) == "GREEN"
    assert risk_band(30) == "GREEN"
    assert risk_band(31) == "YELLOW"
    assert risk_band(60) == "YELLOW"
    assert risk_band(61) == "RED"
