"""
Database engine configuration and session manager for PhishGuard AI.
Uses SQLite for simple, lightweight file-based storage.
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from backend.core.config import settings

# Create engine
engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False}  # Required for SQLite multi-thread access
)

# Create session maker
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Declarative Base
Base = declarative_base()

def get_db():
    """Dependency generator for database sessions in FastAPI routes."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initializes database tables."""
    Base.metadata.create_all(bind=engine)
