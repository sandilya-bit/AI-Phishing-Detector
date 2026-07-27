"""
Email parser service for PhishGuard AI.
Supports extracting email metadata (From, To, Subject, Date, Headers), body, links,
and attachments from .txt, .eml, and .msg files.
"""

import os
import email
from email import policy
import re
import html
from utils.helpers import logger, sanitize_text

# Regex to extract links from HTML or text
LINK_REGEX = re.compile(
    r'href=[\'"]?([^\'" >]+)[\'"]?|https?://[^\s<>"\']+',
    re.IGNORECASE
)

def parse_txt_file(file_content: str) -> dict:
    """Parses plain text content as an email."""
    # Attempt to extract subject if it starts with "Subject:"
    subject = "No Subject"
    body = file_content
    lines = file_content.splitlines()
    
    for line in lines[:3]:  # Check first few lines for header-like fields
        if line.lower().startswith("subject:"):
            subject = line[8:].strip()
            body = "\n".join(lines[1:])
            break
            
    return {
        "subject": sanitize_text(subject),
        "from": "Unknown Sender",
        "to": "Undisclosed Recipients",
        "date": "N/A",
        "body": sanitize_text(body),
        "headers": {},
        "attachments": [],
        "links": list(set(re.findall(r'https?://[^\s<>"\']+', body))),
        "email_id": "Generated-TXT-ID"
    }

def parse_eml_file(file_bytes: bytes) -> dict:
    """Parses .eml files using standard Python email libraries."""
    try:
        # Parse the message with policy.default to handle modern unicode/standards
        msg = email.message_from_bytes(file_bytes, policy=policy.default)
        
        # Extract headers
        subject = msg.get("Subject", "No Subject")
        sender = msg.get("From", "Unknown Sender")
        recipient = msg.get("To", "Undisclosed Recipients")
        date_str = msg.get("Date", "Unknown Date")
        message_id = msg.get("Message-ID", "N/A")
        
        # Flatten headers dictionary
        headers = {}
        for key, val in msg.items():
            headers[key] = str(val)
            
        body = ""
        attachments = []
        
        # Extract body & attachments
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                
                # Check for attachments
                if "attachment" in content_disposition or part.get_filename():
                    filename = part.get_filename()
                    if filename:
                        attachments.append(filename)
                    continue
                
                # Extract text or HTML body
                if content_type == "text/plain" and not body:
                    body = part.get_content()
                elif content_type == "text/html":
                    # Keep html content temporarily for link extraction, but fallback to it if plain text not found
                    html_content = part.get_content()
                    if not body:
                        # Simple regex strip HTML tags to get text representation
                        body = re.sub(r'<[^>]*>', '', html_content)
        else:
            body = msg.get_content()
            
        # Clean up body text
        body = body or ""
        
        # Extract links
        links = []
        # Find all href and raw urls
        raw_links = LINK_REGEX.findall(body)
        for link in raw_links:
            if link:
                clean_link = link.strip()
                if clean_link.startswith(("http://", "https://")):
                    links.append(clean_link)
        
        return {
            "subject": sanitize_text(subject),
            "from": sanitize_text(sender),
            "to": sanitize_text(recipient),
            "date": sanitize_text(date_str),
            "body": sanitize_text(body.strip()),
            "headers": headers,
            "attachments": attachments,
            "links": list(set(links)),
            "email_id": sanitize_text(message_id)
        }
    except Exception as e:
        logger.error(f"Error parsing EML file: {e}")
        raise ValueError(f"Failed to parse EML file: {str(e)}")

def parse_msg_file(file_bytes: bytes) -> dict:
    """Parses Outlook .msg files. Falls back to string extraction if extract-msg is missing."""
    try:
        import extract_msg
        from io import BytesIO
        
        msg = extract_msg.Message(BytesIO(file_bytes))
        
        subject = msg.subject or "No Subject"
        sender = msg.sender or "Unknown Sender"
        recipient = msg.to or "Undisclosed Recipients"
        date_str = msg.date or "Unknown Date"
        body = msg.body or ""
        
        attachments = []
        if msg.attachments:
            for att in msg.attachments:
                attachments.append(att.filename or "unnamed_attachment")
                
        # Extract links
        links = [l.strip() for l in re.findall(r'https?://[^\s<>"\']+', body) if l]
        
        return {
            "subject": sanitize_text(subject),
            "from": sanitize_text(sender),
            "to": sanitize_text(recipient),
            "date": sanitize_text(date_str),
            "body": sanitize_text(body.strip()),
            "headers": {k: str(v) for k, v in msg.header.items()} if msg.header else {},
            "attachments": attachments,
            "links": list(set(links)),
            "email_id": sanitize_text(msg.messageId or "N/A")
        }
    except ImportError:
        logger.warning("extract-msg library is not installed. Using fallback binary parser for Outlook .msg file.")
        # Fallback binary string parser (inspect unicode block elements for common mail patterns)
        try:
            content_str = file_bytes.decode('utf-16-le', errors='ignore')
        except Exception:
            content_str = file_bytes.decode('utf-8', errors='ignore')
            
        # Extract headers using regex from decoded strings
        subject_match = re.search(r'Subject:\s*(.*)', content_str, re.IGNORECASE)
        from_match = re.search(r'From:\s*(.*)', content_str, re.IGNORECASE)
        to_match = re.search(r'To:\s*(.*)', content_str, re.IGNORECASE)
        
        subject = subject_match.group(1).strip() if subject_match else "Outlook Message (Fallback parsed)"
        sender = from_match.group(1).strip() if from_match else "Unknown Outlook Sender"
        recipient = to_match.group(1).strip() if to_match else "Undisclosed Recipients"
        
        # Clean up junk from text
        body = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\xff]', '', content_str)
        # Keep letters and space strings
        body_slice = body[:8000] # truncate giant files
        
        links = [l.strip() for l in re.findall(r'https?://[^\s<>"\']+', body_slice) if l]
        
        return {
            "subject": sanitize_text(subject),
            "from": sanitize_text(sender),
            "to": sanitize_text(recipient),
            "date": "Unknown Date",
            "body": "Outlook MSG file parsed in compatibility mode.\n\n" + sanitize_text(body_slice.strip()[:2000]),
            "headers": {},
            "attachments": [],
            "links": list(set(links)),
            "email_id": "Outlook-Fallback-ID"
        }
    except Exception as e:
        logger.error(f"Error parsing MSG file: {e}")
        raise ValueError(f"Failed to parse Outlook MSG file: {str(e)}")

def parse_email_upload(filename: str, file_bytes: bytes) -> dict:
    """Entry point for parsing uploaded email files based on extension."""
    ext = filename.rsplit(".", 1)[1].lower() if "." in filename else ""
    
    if ext == "txt":
        return parse_txt_file(file_bytes.decode('utf-8', errors='ignore'))
    elif ext == "eml":
        return parse_eml_file(file_bytes)
    elif ext == "msg":
        return parse_msg_file(file_bytes)
    else:
        raise ValueError(f"Unsupported file extension: {ext}")
