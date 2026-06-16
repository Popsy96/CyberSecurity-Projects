"""
processing/mitre.py
====================
MITRE ATT&CK framework mapping.

MITRE ATT&CK is a globally recognised knowledge base of
adversary tactics and techniques based on real-world observations.
Source: https://attack.mitre.org/

We map each normalised threat category to the most relevant
technique ID and name so analysts understand HOW the attack works.

DEFAULT FALLBACK:
-----------------
T1071 (Application Layer Protocol) is the safe fallback for
unmapped categories. It represents general network communication
used by most threats. However we explicitly map as many categories
as possible to reduce T1071 dominance in the dashboard.
"""


# ================================================================
# MITRE ATT&CK MAPPING
# category → (technique_id, technique_name)
# ================================================================
MITRE_MAP = {

    # ── Phishing & Credential Attacks ────────────────────────
    "Phishing":                ("T1566",     "Phishing"),
    "Web Spam":                ("T1566",     "Phishing"),           # web-based lure
    "Email Spam":              ("T1566.001", "Spearphishing Attachment"),

    # ── Credential Harvesting ────────────────────────────────
    "Credential Harvesting":   ("T1056",     "Input Capture"),      # keylogging/form grab

    # ── C2 & Botnet Infrastructure ───────────────────────────
    "C2 Server":               ("T1071",     "Application Layer Protocol"),
    "Botnet":                  ("T1090",     "Proxy"),              # botnet proxies traffic

    # ── Ransomware ───────────────────────────────────────────
    "Ransomware":              ("T1486",     "Data Encrypted for Impact"),

    # ── Brute Force Variants ─────────────────────────────────
    "Brute Force":             ("T1110",     "Brute Force"),
    "SSH Brute Force":         ("T1110.004", "Credential Stuffing"),
    "FTP Brute Force":         ("T1110.001", "Password Guessing"),

    # ── Exploitation ─────────────────────────────────────────
    "SQL Injection":           ("T1190",     "Exploit Public-Facing Application"),
    "Web App Attack":          ("T1190",     "Exploit Public-Facing Application"),
    "Hacking":                 ("T1059",     "Command and Scripting Interpreter"),
    "CVE":                     ("T1190",     "Exploit Public-Facing Application"),

    # ── Network Attacks ──────────────────────────────────────
    "DDoS Attack":             ("T1498",     "Network Denial of Service"),
    "Port Scan":               ("T1046",     "Network Service Discovery"),

    # ── Malware ──────────────────────────────────────────────
    "Malware Distribution":    ("T1204",     "User Execution"),

    # ── Proxy & Anonymisation ────────────────────────────────
    "Open Proxy":              ("T1090",     "Proxy"),
    "Exit Node":               ("T1090",     "Proxy"),              # Tor exit node

    # ── DNS & Infrastructure ─────────────────────────────────
    "DNS Compromise":          ("T1584",     "Compromise Infrastructure"),

    # ── Fraud ────────────────────────────────────────────────
    "Fraud Orders":            ("T1657",     "Financial Theft"),

    # ── Suspicious / Unknown ─────────────────────────────────
    # T1598 = Phishing for Information (neutral, non-dominant)
    "Suspicious Activity":     ("T1598",     "Phishing for Information"),

    # ── Explicit fallbacks ───────────────────────────────────
    # Keep T1071 as default for truly unknown categories
    "Unknown":                 ("T1071",     "Application Layer Protocol"),
    "Other":                   ("T1071",     "Application Layer Protocol"),
}

# Default fallback — T1071 for anything not in the map
DEFAULT_MITRE = ("T1071", "Application Layer Protocol")


def get_mitre(category: str) -> tuple:
    """
    Get MITRE technique ID and name for a normalised threat category.

    Returns:
        tuple: (technique_id, technique_name)

    Example:
        get_mitre("Phishing")     → ("T1566", "Phishing")
        get_mitre("C2 Server")    → ("T1071", "Application Layer Protocol")
        get_mitre("Port Scan")    → ("T1046", "Network Service Discovery")
        get_mitre("Suspicious Activity") → ("T1598", "Phishing for Information")
    """
    return MITRE_MAP.get(category, DEFAULT_MITRE)