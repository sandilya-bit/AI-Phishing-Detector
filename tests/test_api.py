"""
Unit tests for FastAPI endpoints.
Tests scan routes, history logging, and stats aggregation.
"""

import os
import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_api_routes_status():
    """Verifies history and stats routes load correctly."""
    response = client.get("/api/v1/history")
    assert response.status_code == 200
    
    response = client.get("/api/v1/stats")
    assert response.status_code == 200

def test_scan_pasted_text_legitimate():
    """Tests scanning a simple legitimate text email."""
    response = client.post(
        "/api/v1/scan",
        data={"text": "Subject: Project update\nHi Team, here is the weekly project update. See you tomorrow!"}
    )
    assert response.status_code == 200
    json_data = response.json()
    assert "analysis" in json_data
    assert json_data["email_details"]["subject"] == "Project update"
    assert json_data["analysis"]["threat_level"] in ["SAFE", "MEDIUM"]

def test_scan_pasted_text_phishing():
    """Tests scanning an email text containing phishing indicators."""
    response = client.post(
        "/api/v1/scan",
        data={"text": "Subject: URGENT action required!\nVerify your bank account immediately at http://chase-security-update-lock.cc/login"}
    )
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["analysis"]["risk_score"] > 50
    assert json_data["analysis"]["threat_level"] in ["HIGH", "CRITICAL"]
    assert len(json_data["explainability"]["indicators"]) > 0
