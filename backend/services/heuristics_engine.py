"""
Cybersecurity Heuristics Engine for PhishGuard AI.
Analyzes email text, headers, and URLs to detect social engineering indicators,
credential harvesting, typosquatting, urgency, and specific scam types.
"""

import re
from urllib.parse import urlparse

# Typosquatting/Impersonation brands list
COMMON_BRANDS = [
    "microsoft", "office365", "outlook", "google", "gmail", "chase", "bankofamerica",
    "paypal", "netflix", "amazon", "dhl", "fedex", "apple", "facebook", "yahoo"
]

# Shortened URL patterns
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "rebrand.ly", "is.gd", "buff.ly", "adf.ly"}

class HeuristicsEngine:
    def __init__(self):
        # Compiled patterns for efficiency
        self.urgency_pattern = re.compile(
            r'\b(urgent|immediately|action required|expires?|suspended|lock(ed)?|24 hours|3 hours|penalty|freeze|disabled|unauthorized|unusual activity)\b',
            re.IGNORECASE
        )
        self.credential_pattern = re.compile(
            r'\b(verify (your )?account|login|sign in|credentials?|password reset|verify identity|update payment|confirm details)\b',
            re.IGNORECASE
        )
        self.financial_pattern = re.compile(
            r'\b(wire transfer|outstanding invoice|payment due|refund|lottery|win cash|overdue|bank account|routing number|credit card|amount due|transaction approved)\b',
            re.IGNORECASE
        )
        self.scam_patterns = {
            "Password Reset Scam": re.compile(r'password reset|reset your password|secure your account now', re.IGNORECASE),
            "Fake Invoice": re.compile(r'invoice #|outstanding invoice|amount due|past due|quickbooks', re.IGNORECASE),
            "Bank Scam": re.compile(r'bank alert|unusual activity|account lock|wire transfer|chase|bank of america', re.IGNORECASE),
            "Prize Scam": re.compile(r'won the lottery|lottery prize|selected as a winner|grand prize|million dollars', re.IGNORECASE),
            "Delivery Scam": re.compile(r'fedex|dhl|parcel delivery|package hold|shipping address|customs fee', re.IGNORECASE),
            "CEO Fraud / BEC": re.compile(r'are you at your desk|purchase gift cards|wire transfer supplier|executive officer|confidential wire', re.IGNORECASE)
        }

    def analyze_urls(self, links: list) -> dict:
        """Analyzes links for suspicious patterns: typosquatting, Unicode homographs, IP hosts, shorteners."""
        suspicious_links = []
        indicators = []
        typosquatting_detected = False
        unicode_attack_detected = False
        shortened_url_detected = False
        ip_host_detected = False
        
        for url in links:
            try:
                parsed = urlparse(url)
                host = parsed.netloc.lower()
                
                if not host:
                    continue
                
                url_indicators = []
                
                # 1. IP address in hostname
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
                    ip_host_detected = True
                    url_indicators.append("IP address used as host")
                    
                # 2. Unicode/Punycode homograph attacks
                if host.startswith("xn--"):
                    unicode_attack_detected = True
                    url_indicators.append("IDN Homograph/Unicode spoofing domain (Punycode)")
                    
                # 3. Shortened URL
                if host in SHORTENERS or any(sh in host for sh in SHORTENERS):
                    shortened_url_detected = True
                    url_indicators.append("Shortened link hide redirect destination")
                    
                # 4. Typosquatting / Brand Impersonation
                # Check if it contains a common brand name but is not the official domain (e.g. microsoft-secure.cc)
                for brand in COMMON_BRANDS:
                    if brand in host:
                        # Exclude legitimate domains
                        legit_domains = [f"{brand}.com", f"{brand}.net", f"www.{brand}.com", f"mail.{brand}.com", f"login.{brand}.com"]
                        if host not in legit_domains and not host.endswith(f".{brand}.com"):
                            typosquatting_detected = True
                            url_indicators.append(f"Brand impersonation / Typosquatting of '{brand}'")
                
                if url_indicators:
                    suspicious_links.append({
                        "url": url,
                        "reasons": url_indicators
                    })
                    
            except Exception:
                continue
                
        if typosquatting_detected:
            indicators.append("Contains brand-impersonating typosquatted domains")
        if unicode_attack_detected:
            indicators.append("Contains punycode unicode domains (IDN Homograph attack)")
        if shortened_url_detected:
            indicators.append("Contains shortened URLs hiding the final destination")
        if ip_host_detected:
            indicators.append("Contains raw IP address hosts instead of domain names")
            
        return {
            "suspicious_links": suspicious_links,
            "indicators": indicators,
            "has_suspicious_url": len(suspicious_links) > 0
        }

    def analyze_headers(self, headers: dict) -> list:
        """Checks for header discrepancies (e.g. From vs Reply-To mismatch, SPF/DKIM flags)."""
        anomalies = []
        
        # Check from and reply-to mismatch
        from_header = headers.get("From", "").lower()
        reply_to_header = headers.get("Reply-To", "").lower()
        
        if from_header and reply_to_header:
            # Extract email addresses
            from_addr = re.findall(r'[\w\.-]+@[\w\.-]+', from_header)
            reply_addr = re.findall(r'[\w\.-]+@[\w\.-]+', reply_to_header)
            
            if from_addr and reply_addr and from_addr[0] != reply_addr[0]:
                anomalies.append("Header anomaly: Sender From address does not match Reply-To address")
                
        # SPF, DKIM, DMARC failures
        auth_results = headers.get("Authentication-Results", "").lower()
        received_spf = headers.get("Received-SPF", "").lower()
        
        if "spf=fail" in auth_results or "spf=fail" in received_spf:
            anomalies.append("Header anomaly: SPF verification failed (sender spoofing attempt)")
        if "dkim=fail" in auth_results:
            anomalies.append("Header anomaly: DKIM signature verification failed")
            
        return anomalies

    def analyze_text(self, text: str) -> dict:
        """Analyzes text body for social engineering triggers, urgency, grammar, and categories."""
        indicators = []
        scam_types = []
        highlight_words = set()
        
        # Urgency detection
        urgency_matches = self.urgency_pattern.findall(text)
        if urgency_matches:
            indicators.append("Creates a strong sense of urgency or immediate penalty")
            for match in urgency_matches:
                # Add word itself or list
                highlight_words.add(match[0] if isinstance(match, tuple) else match)
                
        # Credential harvesting patterns
        cred_matches = self.credential_pattern.findall(text)
        if cred_matches:
            indicators.append("Asks for sensitive login credentials or account updates")
            for match in cred_matches:
                highlight_words.add(match[0] if isinstance(match, tuple) else match)
                
        # Financial scams
        fin_matches = self.financial_pattern.findall(text)
        if fin_matches:
            indicators.append("Contains keywords related to urgent wire transfers or outstanding payments")
            for match in fin_matches:
                highlight_words.add(match[0] if isinstance(match, tuple) else match)

        # Grammar analysis
        # Excessive exclamation points
        if text.count("!") > 3:
            indicators.append("Uses unusual/excessive exclamation marks to coerce user")
            highlight_words.add("!")
            
        # ALL CAPS words
        caps_words = re.findall(r'\b[A-Z]{4,}\b', text)
        if len(caps_words) > 2:
            indicators.append("Contains excessive ALL-CAPS words to simulate emergency")
            for w in caps_words[:5]:
                highlight_words.add(w)

        # Detect specific scam category
        for label, pattern in self.scam_patterns.items():
            if pattern.search(text):
                scam_types.append(label)
                
        return {
            "indicators": indicators,
            "scam_types": scam_types,
            "highlight_words": list(highlight_words)
        }

    def evaluate_threat(self, parse_results: dict) -> dict:
        """Combines all heuristic checks to output risk score and threat level."""
        body = parse_results.get("body", "")
        links = parse_results.get("links", [])
        headers = parse_results.get("headers", {})
        
        url_analysis = self.analyze_urls(links)
        header_anomalies = self.analyze_headers(headers)
        text_analysis = self.analyze_text(body)
        
        # Compile all indicators
        all_indicators = []
        all_indicators.extend(url_analysis["indicators"])
        all_indicators.extend(header_anomalies)
        all_indicators.extend(text_analysis["indicators"])
        
        # Threat scoring logic
        score = 10  # Base safe score
        
        # Add weights
        if url_analysis["has_suspicious_url"]:
            score += 35
        if header_anomalies:
            score += 20
        if "Creates a strong sense of urgency or immediate penalty" in text_analysis["indicators"]:
            score += 15
        if "Asks for sensitive login credentials or account updates" in text_analysis["indicators"]:
            score += 20
        if "Contains keywords related to urgent wire transfers or outstanding payments" in text_analysis["indicators"]:
            score += 15
            
        # Add smaller weights for grammar anomalies
        if "Uses unusual/excessive exclamation marks to coerce user" in text_analysis["indicators"]:
            score += 5
        if "Contains excessive ALL-CAPS words to simulate emergency" in text_analysis["indicators"]:
            score += 5
            
        # Check attachments (any attachments in EML files score up if keywords are phishing-related)
        has_attachments = len(parse_results.get("attachments", [])) > 0
        if has_attachments and score > 25:
            # High correlation of attachments in phishing emails
            score += 10
            all_indicators.append("Contains file attachments linked with other suspicious triggers")
            
        score = min(score, 100)
        
        # Map score to level
        if score <= 20:
            level = "SAFE"
            color = "green"
        elif score <= 50:
            level = "MEDIUM"
            color = "yellow"
        elif score <= 80:
            level = "HIGH"
            color = "orange"
        else:
            level = "CRITICAL"
            color = "red"
            
        return {
            "threat_score": score,
            "threat_level": level,
            "threat_color": color,
            "indicators": all_indicators,
            "scam_types": text_analysis["scam_types"],
            "highlight_words": text_analysis["highlight_words"],
            "suspicious_links": url_analysis["suspicious_links"]
        }
