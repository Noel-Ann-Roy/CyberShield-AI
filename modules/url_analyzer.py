import re
from urllib.parse import urlparse

def analyze_url_risk(url_string):
    """
    Parses structural threat markers inside target URL strings
    using zero-trust lexical analysis blocks.
    """
    if not url_string:
        return None
        
    # Standardize input structure
    target = url_string.strip()
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
        
    try:
        parsed = urlparse(target)
        domain = parsed.netloc
        path = parsed.path.lower()
    except Exception:
        domain = target
        path = ""

    # 1. Flag Identifiers
    is_https = url_string.strip().startswith('https://')
    url_length = len(url_string)
    dot_count = domain.count('.')
    
    # Suspicious structural vectors
    has_ip = bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain))
    has_at_symbol = "@" in url_string
    
    # High-risk phish keywords targeting identity assets
    suspicious_keywords = ['login', 'verify', 'secure', 'update', 'account', 'banking', 'signin']
    found_keywords = [kw for kw in suspicious_keywords if kw in path or kw in domain.lower()]

    # 2. Risk Calculation Formula Matrix
    risk_score = 0
    reasons = []

    if not is_https:
        risk_score += 35
        reasons.append("⚠️ UNENCRYPTED CHANNEL: Transmission exposes systemic plain-text interception vulnerabilities (No HTTPS).")
    
    if url_length > 75:
        risk_score += 15
        reasons.append(f"⚠️ LENGTH OVERFLOW: Defends against visual spoofing via extreme length footprint ({url_length} chars).")
        
    if dot_count > 3:
        risk_score += 20
        reasons.append(f"⚠️ SUBDOMAIN FLOODING: High count of sub-level zones ({dot_count} dots) patterns standard DNS hijacking evasion.")
        
    if has_ip:
        risk_score += 40
        reasons.append("🚨 DIRECT IP TARGET: Routing uses standard raw numerical IP addresses bypassing reputation filters.")
        
    if has_at_symbol:
        risk_score += 25
        reasons.append("🚨 USER AUTH IN URL: Internal '@' character structure tricks standard parsing engines into masking malicious domains.")
        
    if found_keywords:
        risk_score += (20 * len(found_keywords))
        reasons.append(f"🚨 CREDENTIAL HARVESTING SIGNATURES: Matches critical targeted phishing indicators: {found_keywords}")

    # Cap raw penalty array max bound
    risk_score = min(risk_score, 100)

    # 3. Threat Classification Boundaries
    if risk_score <= 25:
        classification = "Safe"
        color = "#10B981"
    elif risk_score <= 60:
        classification = "Suspicious"
        color = "#F59E0B"
    else:
        classification = "Dangerous"
        color = "#EF4444"

    return {
        "url": url_string,
        "is_https": is_https,
        "length": url_length,
        "dots": dot_count,
        "has_ip": has_ip,
        "found_keywords": found_keywords,
        "risk_score": risk_score,
        "classification": classification,
        "color": color,
        "reasons": reasons if reasons else ["🟢 Zero immediate threat signatures caught by lexical analysis modules."]
    }