"""
Unit tests for the Cybersecurity Heuristics Engine.
Validates URL domain inspection, header mismatch detection, and urgency triggers.
"""

import pytest
from backend.services.heuristics_engine import HeuristicsEngine

@pytest.fixture
def engine():
    return HeuristicsEngine()

def test_url_typosquatting_detection(engine):
    """Verifies that brand-lookalike domains are flagged."""
    res = engine.analyze_urls(["http://verification-chase-update.cc/login"])
    assert res["has_suspicious_url"] is True
    assert any("Brand impersonation" in reason for reason in res["suspicious_links"][0]["reasons"])

def test_url_punycode_detection(engine):
    """Verifies that Punycode homograph domains are flagged."""
    res = engine.analyze_urls(["http://xn--pple-43d.com/auth"])
    assert res["has_suspicious_url"] is True
    assert "IDN Homograph/Unicode spoofing domain (Punycode)" in res["suspicious_links"][0]["reasons"]

def test_header_anomaly_detection(engine):
    """Verifies that mismatched From and Reply-To addresses are flagged."""
    headers = {
        "From": "billing@paypal.com",
        "Reply-To": "hacker@malicious-site.net"
    }
    anomalies = engine.analyze_headers(headers)
    assert len(anomalies) > 0
    assert "From address does not match Reply-To" in anomalies[0]

def test_text_urgency_trigger(engine):
    """Verifies that urgent, threat-coercing language triggers warnings."""
    text = "Dear customer, your account will be suspended within 24 hours unless you log in immediately."
    res = engine.analyze_text(text)
    assert "Creates a strong sense of urgency or immediate penalty" in res["indicators"]
    assert "suspended" in res["highlight_words"]
    assert "immediately" in res["highlight_words"]
