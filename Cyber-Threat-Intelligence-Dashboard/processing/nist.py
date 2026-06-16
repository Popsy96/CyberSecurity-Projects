"""
processing/nist.py
===================
NIST Cybersecurity Framework (CSF), ASD Essential Eight,
and ISO 27001 mapping for each normalised threat category.

Sources:
  NIST CSF : https://www.nist.gov/cyberframework
  ASD E8   : https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight
  ISO 27001 : https://www.iso.org/standard/27001

WHY 3 FRAMEWORKS:
------------------
  NIST CSF  → International standard (Identify/Protect/Detect/Respond/Recover)
  ASD E8    → Australian-specific controls (required for AU context)
  ISO 27001 → Global security management standard
"""


# ================================================================
# NIST CSF MAPPING
# 5 Functions: Identify / Protect / Detect / Respond / Recover
# ================================================================
NIST_MAP = {
    # ── Identify ─────────────────────────────────────────────
    # Understand assets and risks
    "DNS Compromise":          "Identify",
    "CVE":                     "Identify",   # CVE = known vulnerability → Identify
    "cve":                     "Identify",   # lowercase fallback

    # ── Protect ──────────────────────────────────────────────
    # Implement safeguards to limit impact
    "Phishing":                "Protect",
    "Brute Force":             "Protect",
    "SSH Brute Force":         "Protect",
    "FTP Brute Force":         "Protect",   # added
    "SQL Injection":           "Protect",
    "Web App Attack":          "Protect",
    "Email Spam":              "Protect",
    "Web Spam":                "Protect",   # added
    "Credential Harvesting":   "Protect",   # added

    # ── Detect ───────────────────────────────────────────────
    # Find cybersecurity events
    "C2 Server":               "Detect",
    "Port Scan":               "Detect",
    "Malware Distribution":    "Detect",
    "Open Proxy":              "Detect",
    "Exit Node":               "Detect",    # added
    "Botnet":                  "Detect",    # added
    "Suspicious Activity":     "Detect",

    # ── Respond ──────────────────────────────────────────────
    # Take action on detected incidents
    "DDoS Attack":             "Respond",
    "Ransomware":              "Respond",
    "Hacking":                 "Respond",
    "Fraud Orders":            "Respond",

    # ── Recover ──────────────────────────────────────────────
    # Restore normal operations
    # (post-incident threats map here in extended use)
}

DEFAULT_NIST = "Detect"


# ================================================================
# ASD ESSENTIAL EIGHT MAPPING
# Australia-specific mitigation strategies
# ================================================================
ASD_E8_MAP = {
    # Phishing-related
    "Phishing":                "Restrict Microsoft Office Macros",
    "Web Spam":                "Restrict Microsoft Office Macros",  # added
    "Email Spam":              "Restrict Microsoft Office Macros",

    # Credential attacks
    "Brute Force":             "Multi-Factor Authentication",
    "SSH Brute Force":         "Multi-Factor Authentication",
    "FTP Brute Force":         "Multi-Factor Authentication",       # added
    "Credential Harvesting":   "Multi-Factor Authentication",       # added

    # Application exploits
    "SQL Injection":           "Patch Applications",
    "Web App Attack":          "Patch Applications",
    "Hacking":                 "Patch Applications",                # added
    "CVE":                     "Patch Operating Systems",

    # Malware & C2
    "C2 Server":               "Application Control",
    "Malware Distribution":    "Application Control",
    "Botnet":                  "Application Control",               # added
    "Exit Node":               "Application Control",               # added
    "Open Proxy":              "Application Control",

    # Ransomware
    "Ransomware":              "Regular Backups",

    # Network threats
    "DDoS Attack":             "Application Control",
    "Port Scan":               "Application Control",

    # DNS
    "DNS Compromise":          "Patch Applications",

    # Fraud
    "Fraud Orders":            "Application Control",               # added

    # Generic
    "Suspicious Activity":     "Application Control",
}

DEFAULT_ASD = "Application Control"


# ================================================================
# ISO 27001 CONTROL MAPPING
# Maps threats to relevant ISO 27001:2022 Annex A controls
# ================================================================
ISO_MAP = {
    # Web & Email filtering
    "Phishing":                "A.8.23 Web Filtering",
    "Web Spam":                "A.8.23 Web Filtering",              # added
    "Email Spam":              "A.8.23 Web Filtering",

    # Authentication
    "Brute Force":             "A.8.5 Secure Authentication",
    "SSH Brute Force":         "A.8.5 Secure Authentication",
    "FTP Brute Force":         "A.8.5 Secure Authentication",       # added
    "Credential Harvesting":   "A.8.5 Secure Authentication",       # added

    # Network security
    "C2 Server":               "A.8.20 Network Security",
    "DDoS Attack":             "A.8.20 Network Security",
    "Port Scan":               "A.8.20 Network Security",           # added
    "Open Proxy":              "A.8.20 Network Security",           # added
    "Exit Node":               "A.8.20 Network Security",           # added
    "Botnet":                  "A.8.20 Network Security",           # added

    # Secure coding
    "SQL Injection":           "A.8.28 Secure Coding",
    "Web App Attack":          "A.8.28 Secure Coding",
    "Hacking":                 "A.8.28 Secure Coding",              # added

    # Malware protection
    "Malware Distribution":    "A.8.7 Malware Protection",

    # Backup
    "Ransomware":              "A.8.13 Information Backup",

    # Infrastructure
    "DNS Compromise":          "A.8.20 Network Security",

    # Monitoring
    "Suspicious Activity":     "A.8.16 Monitoring Activities",

    # Transactions / fraud
    "Fraud Orders":            "A.8.32 Transaction Security",       # added

    # Vulnerability management
    "CVE":                     "A.8.8 Management of Vulnerabilities",
}

DEFAULT_ISO = "A.8.16 Monitoring Activities"


# ================================================================
# FUNCTIONS
# ================================================================

def get_nist(category: str) -> str:
    """
    Get NIST CSF function for a normalised threat category.

    Returns one of: Identify / Protect / Detect / Respond / Recover

    Example:
        get_nist('Phishing')   → 'Protect'
        get_nist('C2 Server')  → 'Detect'
        get_nist('Ransomware') → 'Respond'
    """
    return NIST_MAP.get(category, DEFAULT_NIST)


def get_asd_e8(category: str) -> str:
    """
    Get ASD Essential Eight strategy for a normalised threat category.

    Example:
        get_asd_e8('Phishing')    → 'Restrict Microsoft Office Macros'
        get_asd_e8('Brute Force') → 'Multi-Factor Authentication'
        get_asd_e8('Ransomware')  → 'Regular Backups'
    """
    return ASD_E8_MAP.get(category, DEFAULT_ASD)


def get_iso(category: str) -> str:
    """
    Get ISO 27001:2022 control for a normalised threat category.

    Example:
        get_iso('Phishing')   → 'A.8.23 Web Filtering'
        get_iso('C2 Server')  → 'A.8.20 Network Security'
        get_iso('Ransomware') → 'A.8.13 Information Backup'
    """
    return ISO_MAP.get(category, DEFAULT_ISO)