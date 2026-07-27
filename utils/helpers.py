"""
General helper utilities, sanitizers, and validation logic.
"""

import os
import re
import html
import logging

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.log"), encoding="utf-8")
    ]
)
logger = logging.getLogger("PhishGuardAI")

def sanitize_text(text: str) -> str:
    """Sanitizes text content to prevent XSS attacks and injection."""
    if not text:
        return ""
    # Remove HTML tags or escape them
    clean = html.escape(text)
    # Remove null bytes
    clean = clean.replace("\x00", "")
    return clean

def sanitize_html_tags(text: str) -> str:
    """Removes HTML scripts and tags completely while leaving raw content."""
    if not text:
        return ""
    clean = re.sub(r'<script.*?>.*?</script>', '', text, flags=re.DOTALL | re.IGNORECASE)
    clean = re.sub(r'<[^>]*>', '', clean)
    return clean

def validate_file_extension(filename: str, allowed_extensions: set) -> bool:
    """Checks if the uploaded file has a permitted extension."""
    if not "." in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in allowed_extensions

def calculate_text_stats(text: str) -> dict:
    """Calculates general statistics of email body text."""
    words = text.split()
    word_count = len(words)
    char_count = len(text)
    
    # Simple line count
    lines = text.splitlines()
    line_count = len([l for l in lines if l.strip()])
    
    return {
        "word_count": word_count,
        "char_count": char_count,
        "line_count": line_count
    }
