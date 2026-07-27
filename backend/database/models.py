"""
SQLAlchemy models for PhishGuard AI.
Stores email scan logs and metadata.
"""

from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from datetime import datetime
from backend.database.db import Base

class ScanHistory(Base):
    __tablename__ = "scan_history"
    
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, default="Pasted Text")
    sender = Column(String, default="Unknown Sender")
    recipient = Column(String, default="Unknown Recipient")
    subject = Column(String, default="No Subject")
    date_sent = Column(String, default="N/A")
    body_preview = Column(Text, nullable=True)
    
    # Model predictions
    threat_category = Column(String, index=True)  # phishing, spam, legitimate
    confidence = Column(Float)
    risk_score = Column(Integer)  # 0 to 100
    threat_level = Column(String, index=True)  # SAFE, MEDIUM, HIGH, CRITICAL
    prediction_time_ms = Column(Float)
    model_used = Column(String)
    
    # JSON-encoded parameters (lists or objects stored as text)
    indicators = Column(Text, default="[]")
    scam_types = Column(Text, default="[]")
    suspicious_links = Column(Text, default="[]")
    
    created_at = Column(DateTime, default=datetime.utcnow)
