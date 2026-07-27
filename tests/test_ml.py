"""
Unit tests for the Machine Learning service.
Verifies inference format, fallback logic, and prediction outputs.
"""

import pytest
from backend.services.ml_service import MLService

@pytest.fixture
def ml_service():
    return MLService()

def test_prediction_output_structure(ml_service):
    """Verifies that the predict method returns all necessary keys and types."""
    sample_text = "Subject: Invoice Overdue\nPlease review the attached invoice and pay immediately."
    res = ml_service.predict(sample_text)
    
    assert "label" in res
    assert "confidence" in res
    assert "probabilities" in res
    assert "prediction_time_ms" in res
    assert "model_used" in res
    
    assert res["label"] in ["phishing", "spam", "legitimate"]
    assert isinstance(res["confidence"], float)
    assert 0.0 <= res["confidence"] <= 1.0
    
    probs = res["probabilities"]
    assert "phishing" in probs
    assert "spam" in probs
    assert "legitimate" in probs

def test_prediction_empty_input(ml_service):
    """Verifies that empty strings are classified as legitimate safely."""
    res = ml_service.predict("")
    assert res["label"] == "legitimate"
    assert res["confidence"] == 1.0
