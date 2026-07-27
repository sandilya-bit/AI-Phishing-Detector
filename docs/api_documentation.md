# API Endpoint Documentation

This manual documents the REST API endpoints provided by the PhishGuard AI backend.

---

## 1. Scan Email Request
Uploads a file or accepts pasted raw text to perform threat analysis.

- **URL Endpoint**: `/api/v1/scan`
- **Method**: `POST`
- **Headers**: `Content-Type: multipart/form-data`
- **Parameters**:
  - `file`: (Optional) Uploaded email file (supports `.txt`, `.eml`, `.msg`).
  - `text`: (Optional) Raw email string (if copy-pasting content).
  
> [!IMPORTANT]
> One of `file` or `text` is strictly required. File sizes must be under 5MB.

### Success Response Example (200 OK)
```json
{
  "id": 1,
  "filename": "phishing_sample.eml",
  "email_details": {
    "from": "support@micros0ft-secure.com",
    "to": "user@example.com",
    "subject": "URGENT: Confirm account security activity now!",
    "date": "Wed, 22 Jul 2026 10:42:00 +0000",
    "email_id": "Generated-EML-ID",
    "body": "Dear User, We noticed suspicious activity...",
    "links_count": 1,
    "attachments_count": 0,
    "attachments": []
  },
  "analysis": {
    "prediction": "PHISHING",
    "confidence": 0.987,
    "risk_score": 92,
    "threat_level": "CRITICAL",
    "threat_color": "red",
    "prediction_time_ms": 12.45,
    "model_used": "TF-IDF + Logistic Regression (Fallback)",
    "probabilities": {
      "phishing": 0.987,
      "spam": 0.011,
      "legitimate": 0.002
    }
  },
  "explainability": {
    "indicators": [
      "Contains brand-impersonating typosquatted domains",
      "Creates a strong sense of urgency or immediate penalty"
    ],
    "scam_types": ["Password Reset Scam"],
    "highlight_words": ["urgent", "verify", "suspended"],
    "suspicious_links": [
      {
        "url": "http://verification-portal-microsoft-secure.cc/verify",
        "reasons": ["Brand impersonation of 'microsoft'", "Suspicious TLD extension"]
      }
    ]
  },
  "recommendations": [
    "DO NOT click on any links in this email.",
    "DO NOT download or open any attachments.",
    "Report this email immediately to your security team."
  ],
  "timestamp": "2026-07-22T10:14:48.123456"
}
```

---

## 2. Retrieve Scan History logs
Returns a list of past scans sorted in descending order of creation.

- **URL Endpoint**: `/api/v1/history`
- **Method**: `GET`
- **Query Parameters**:
  - `limit`: (Optional, default=50) Number of records to return.

### Response Example (200 OK)
```json
[
  {
    "id": 1,
    "filename": "phishing_sample.eml",
    "subject": "URGENT: Confirm account security activity now!",
    "sender": "support@micros0ft-secure.com",
    "threat_category": "phishing",
    "confidence": 0.987,
    "risk_score": 92,
    "threat_level": "CRITICAL",
    "model_used": "TF-IDF + Logistic Regression (Fallback)",
    "created_at": "2026-07-22T10:14:48.123456",
    "indicators": ["Suspicious Link", "Urgency Detected"]
  }
]
```

---

## 3. History File Export
Downloads predictions in CSV, JSON, or text PDF format.

- **URL Endpoint**: `/api/v1/history/export/{file_type}`
- **Method**: `GET`
- **Path Parameters**:
  - `file_type`: Must be `csv`, `json`, or `pdf`.

---

## 4. Aggregate Dashboard Statistics
Compiles dashboard charts, weekly detection counts, and avg model speeds.

- **URL Endpoint**: `/api/v1/stats`
- **Method**: `GET`

---

## 5. Admin Login Verification
Simple authentication validation.

- **URL Endpoint**: `/api/v1/admin/login`
- **Method**: `POST`
- **Payload**:
  ```json
  {
    "username": "admin",
    "password": "your_password"
  }
  ```
