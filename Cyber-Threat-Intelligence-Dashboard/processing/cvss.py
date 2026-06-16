"""
processing/cvss.py
==================
CVSS-style score calculation for threat intelligence.

Inspired by CVSS v3.1 but simplified for open-source feed data.
Full CVSS v3.1 spec: https://www.first.org/cvss/v3.1/specification-document

Calculation Steps:
------------------
Step 1 — Base score from severity label
Step 2 — Confidence adjustment (AbuseIPDB score)
Step 3 — Category booster (threat type weight)
Step 4 — Clamp to valid range 0.0–10.0
"""


# ================================================================
# CATEGORY BOOSTERS
# Adds extra weight to more dangerous threat categories
# ================================================================
CATEGORY_BOOSTERS = {
    # ── Critical boosters (+0.5) ─────────────────────────────
    "C2 Server":            0.5,   # Direct attacker control
    "Ransomware":           0.5,   # Catastrophic data loss

    # ── High boosters (+0.3) ─────────────────────────────────
    "DDoS Attack":          0.3,   # High availability impact
    "SQL Injection":        0.3,   # Data breach risk
    "Hacking":              0.3,   # Active intrusion
    "DNS Compromise":       0.3,   # Infrastructure attack

    # ── Medium-high boosters (+0.2) ──────────────────────────
    "Web App Attack":       0.2,   # Application exploitation
    "Malware Distribution": 0.2,   # Active malware delivery
    "FTP Brute Force":      0.2,   # Service compromise

    # ── Medium boosters (+0.1) ───────────────────────────────
    "Phishing":             0.1,   # Credential theft
    "Brute Force":          0.1,   # Credential attack
    "SSH Brute Force":      0.1,   # Remote access attack
    "Fraud Orders":         0.1,   # Financial crime

    # ── Low boosters (+0.05) ─────────────────────────────────
    "Port Scan":            0.05,  # Reconnaissance only
    "Open Proxy":           0.05,  # Anonymisation tool
    "Email Spam":           0.05,  # Nuisance level
    "Web Spam":             0.05,  # Nuisance level

    # ── No booster (0.0) ─────────────────────────────────────
    "Suspicious Activity":  0.0,   # Unconfirmed — no boost
}


def calculate_cvss(severity: str,
                   confidence: float = None,
                   category: str = None) -> float:
    """
    Calculate a CVSS-style score (0.0–10.0).

    Args:
        severity   : 'Critical', 'High', 'Medium', or 'Low'
        confidence : AbuseIPDB confidence score (0–100), optional
        category   : Normalised threat category, optional

    Returns:
        float: CVSS score between 0.0 and 10.0

    Calculation:
    ─────────────────────────────────────────────
    Step 1: Base score from severity
            Critical = 9.0
            High     = 7.5
            Medium   = 5.0
            Low      = 2.5

    Step 2: Confidence adjustment (AbuseIPDB only)
            adj = (confidence / 100) × 2.0 − 1.0
            Range: −1.0 to +1.0
            Example: 85% → (85/100)×2.0−1.0 = +0.7

    Step 3: Category booster (see CATEGORY_BOOSTERS above)
            C2 Server  → +0.5
            Ransomware → +0.5
            Phishing   → +0.1
            Port Scan  → +0.05

    Step 4: Clamp to 0.0–10.0

    Example:
    ─────────────────────────────────────────────
    SSH Brute Force, AbuseIPDB confidence = 85%
    Base  = 7.5   (High)
    Adj   = +0.7  (85% confidence)
    Boost = +0.1  (SSH Brute Force)
    Final = 8.3   → High
    """
    # Step 1: Base score
    base = {
        "Critical": 9.0,
        "High":     7.5,
        "Medium":   5.0,
        "Low":      2.5,
    }.get(severity, 5.0)

    # Step 2: Confidence adjustment
    if confidence is not None:
        adjustment = (confidence / 100.0) * 2.0 - 1.0
        base = base + adjustment

    # Step 3: Category booster
    if category:
        base += CATEGORY_BOOSTERS.get(category, 0.0)

    # Step 4: Clamp to valid range
    return round(min(10.0, max(0.0, base)), 1)


def cvss_to_severity(score: float) -> str:
    """
    Convert CVSS score to severity label.

    Based on CVSS v3.1 standard ratings:
      9.0 – 10.0 = Critical
      7.0 –  8.9 = High
      4.0 –  6.9 = Medium
      0.0 –  3.9 = Low
    """
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    return "Low"


def calculate_risk_rating(cvss: float,
                          total_reports: int = 0,
                          status: str = "unknown") -> str:
    """
    Calculate overall risk rating.

    Combines CVSS score with real-world activity indicators:
      - High report volume = widely known threat (+0.5 or +0.2)
      - Currently active/online status (+0.3)

    Returns: 'Critical', 'High', 'Medium', or 'Low'
    """
    risk = cvss

    # Report volume bonus
    if total_reports > 100:
        risk += 0.5
    elif total_reports > 10:
        risk += 0.2

    # Active status bonus
    if status.lower() in ["active", "online"]:
        risk += 0.3

    return cvss_to_severity(min(10.0, risk))