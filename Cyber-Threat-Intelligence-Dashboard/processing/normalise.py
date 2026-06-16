"""
processing/normalise.py
========================
Normalisation Layer — maps raw feed data into unified schema.

KEY FIX:
--------
OTX sends pulse NAMES not categories.
We use smart_category() to scan full text + tags
for keywords to detect the real category.

AbuseIPDB sends numeric category codes.
We map those codes directly to clean categories.
"""

# ================================================================
# CATEGORY NORMALISATION MAP
# Maps raw labels → clean dashboard category
# ================================================================
CATEGORY_MAP = {
    # ── Phishing ─────────────────────────────────────────────
    "phishing":                    "Phishing",
    "phishing_kit":                "Phishing",
    "phish":                       "Phishing",
    "phishing site":               "Phishing",
    "phishing url":                "Phishing",
    "phishing page":               "Phishing",
    "spear phishing":              "Phishing",
    "spearphishing":               "Phishing",
    "credential harvesting":       "Phishing",
    "credential harvest":          "Phishing",
    "credential theft":            "Phishing",
    "credential stealing":         "Phishing",
    "fake login":                  "Phishing",
    "fake login page":             "Phishing",
    "brand impersonation":         "Phishing",
    "fake update":                 "Phishing",
    "clickfix":                    "Phishing",
    "typosquat":                   "Phishing",
    "typosquatting":               "Phishing",
    "typosquatted":                "Phishing",
    "webex spoofing":              "Phishing",
    "spoofing":                    "Phishing",

    # ── Malware Distribution ─────────────────────────────────
    "malware":                     "Malware Distribution",
    "malware_download":            "Malware Distribution",
    "malware download":            "Malware Distribution",
    "malware_url":                 "Malware Distribution",
    "malware url":                 "Malware Distribution",
    "payload":                     "Malware Distribution",
    "dropper":                     "Malware Distribution",
    "downloader":                  "Malware Distribution",
    "malware distribution":        "Malware Distribution",
    "malicious download":          "Malware Distribution",
    "malicious file":              "Malware Distribution",
    "malicious attachment":        "Malware Distribution",
    "trojan":                      "Malware Distribution",
    "infostealer":                 "Malware Distribution",
    "stealer":                     "Malware Distribution",
    "info stealer":                "Malware Distribution",
    "cryptojacking":               "Malware Distribution",
    "cryptominer":                 "Malware Distribution",
    "miner":                       "Malware Distribution",
    "worm":                        "Malware Distribution",
    "spyware":                     "Malware Distribution",
    "adware":                      "Malware Distribution",
    "backdoor":                    "Malware Distribution",
    "keylogger":                   "Malware Distribution",
    "rat":                         "Malware Distribution",
    "remote access trojan":        "Malware Distribution",
    "virus":                       "Malware Distribution",
    "npm":                         "Malware Distribution",
    "supply chain":                "Malware Distribution",
    "poisoned":                    "Malware Distribution",
    "drive-by":                    "Malware Distribution",
    "drive by":                    "Malware Distribution",
    "opendir":                     "Malware Distribution",

    # ── Compromised Host ─────────────────────────────────────
    "compromised host":            "Malware Distribution",
    "compromised system":          "Malware Distribution",
    "compromised server":          "Malware Distribution",
    "infected host":               "Malware Distribution",
    "infected system":             "Malware Distribution",

    # ── C2 Server ────────────────────────────────────────────
    "c2":                          "C2 Server",
    "c2 server":                   "C2 Server",
    "c&c":                         "C2 Server",
    "c&c server":                  "C2 Server",
    "cnc":                         "C2 Server",
    "command and control":         "C2 Server",
    "command & control":           "C2 Server",
    "command-and-control":         "C2 Server",
    "botnet":                      "C2 Server",
    "botnet c2":                   "C2 Server",
    "c2_server":                   "C2 Server",
    "c2server":                    "C2 Server",
    "cobalt strike":               "C2 Server",
    "cobaltstrike":                "C2 Server",
    "metasploit":                  "C2 Server",
    "empire":                      "C2 Server",
    "sliver":                      "C2 Server",
    "reverse shell":               "C2 Server",
    "reverse_shell":               "C2 Server",
    "active c2":                   "C2 Server",
    "c2 infrastructure":           "C2 Server",
    "caddy proxy":                 "C2 Server",
    "tsundere botnet":             "C2 Server",
    "castleloader":                "C2 Server",
    "deno runtime":                "C2 Server",
    "intrusion":                   "C2 Server",
    "enterprise compromise":       "C2 Server",
    "edge appliance":              "C2 Server",

    # ── Ransomware ───────────────────────────────────────────
    "ransomware":                  "Ransomware",
    "ransom":                      "Ransomware",
    "cryptolocker":                "Ransomware",
    "crypto ransomware":           "Ransomware",
    "data extortion":              "Ransomware",
    "double extortion":            "Ransomware",
    "lockbit":                     "Ransomware",
    "blackcat":                    "Ransomware",
    "cl0p":                        "Ransomware",
    "revil":                       "Ransomware",
    "conti":                       "Ransomware",
    "hive ransomware":             "Ransomware",

    # ── Brute Force ──────────────────────────────────────────
    "brute force":                 "Brute Force",
    "brute-force":                 "Brute Force",
    "bruteforce":                  "Brute Force",
    "brute_force":                 "Brute Force",
    "credential stuffing":         "Brute Force",
    "password spraying":           "Brute Force",
    "password spray":              "Brute Force",
    "rdp brute force":             "Brute Force",
    "rdp attack":                  "Brute Force",
    "smb brute force":             "Brute Force",

    # ── SSH Brute Force ──────────────────────────────────────
    "ssh brute force":             "SSH Brute Force",
    "ssh brute-force":             "SSH Brute Force",
    "ssh_brute_force":             "SSH Brute Force",
    "ssh bruteforce":              "SSH Brute Force",
    "ssh attack":                  "SSH Brute Force",

    # ── FTP Brute Force ──────────────────────────────────────
    "ftp brute force":             "FTP Brute Force",
    "ftp bruteforce":              "FTP Brute Force",
    "ftp_brute_force":             "FTP Brute Force",

    # ── DDoS ─────────────────────────────────────────────────
    "ddos":                        "DDoS Attack",
    "ddos attack":                 "DDoS Attack",
    "ddos-for-hire":               "DDoS Attack",
    "dos":                         "DDoS Attack",
    "denial of service":           "DDoS Attack",
    "network flood":               "DDoS Attack",
    "game-server botnet":          "DDoS Attack",
    "game server botnet":          "DDoS Attack",
    "booter":                      "DDoS Attack",
    "stresser":                    "DDoS Attack",

    # ── Port Scan ────────────────────────────────────────────
    "port scan":                   "Port Scan",
    "port scanner":                "Port Scan",
    "port_scan":                   "Port Scan",
    "scanning":                    "Port Scan",
    "network scan":                "Port Scan",
    "recon":                       "Port Scan",
    "reconnaissance":              "Port Scan",
    "masscan":                     "Port Scan",
    "nmap":                        "Port Scan",
    "shodan":                      "Port Scan",

    # ── SQL Injection ────────────────────────────────────────
    "sql injection":               "SQL Injection",
    "sqli":                        "SQL Injection",
    "sql_injection":               "SQL Injection",
    "database attack":             "SQL Injection",

    # ── Web App Attack ───────────────────────────────────────
    "web app attack":              "Web App Attack",
    "web application attack":      "Web App Attack",
    "web attack":                  "Web App Attack",
    "web exploit":                 "Web App Attack",
    "xss":                         "Web App Attack",
    "cross site scripting":        "Web App Attack",
    "rfi":                         "Web App Attack",
    "lfi":                         "Web App Attack",
    "ssrf":                        "Web App Attack",
    "exploit":                     "Web App Attack",
    "cve-":                        "Web App Attack",
    "forticlient":                 "Web App Attack",
    "confluence":                  "Web App Attack",
    "f5":                          "Web App Attack",

    # ── Hacking ──────────────────────────────────────────────
    "hacking":                     "Hacking",
    "hack":                        "Hacking",
    "exploitation":                "Hacking",
    "unauthorized access":         "Hacking",
    "cyberespionage":              "Hacking",
    "cyber espionage":             "Hacking",
    "apt":                         "Hacking",
    "advanced persistent":         "Hacking",
    "nation state":                "Hacking",
    "threat actor":                "Hacking",
    "china-aligned":               "Hacking",
    "lazarus":                     "Hacking",
    "kimsuky":                     "Hacking",
    "shadow":                      "Hacking",
    "espionage":                   "Hacking",
    "attack technique":            "Hacking",
    "attack campaign":             "Hacking",

    # ── Spam ─────────────────────────────────────────────────
    "spam":                        "Email Spam",
    "email spam":                  "Email Spam",
    "spam campaign":               "Email Spam",
    "web spam":                    "Web Spam",

    # ── Open Proxy ───────────────────────────────────────────
    "open proxy":                  "Open Proxy",
    "proxy":                       "Open Proxy",
    "exit node":                   "Open Proxy",
    "tor exit node":               "Open Proxy",
    "tor":                         "Open Proxy",
    "vpn":                         "Open Proxy",

    # ── DNS ──────────────────────────────────────────────────
    "dns compromise":              "DNS Compromise",
    "dns poisoning":               "DNS Compromise",
    "dns hijacking":               "DNS Compromise",
    "dns spoofing":                "DNS Compromise",
    "dns tunneling":               "DNS Compromise",

    # ── Fraud ────────────────────────────────────────────────
    "fraud":                       "Fraud Orders",
    "financial theft":             "Fraud Orders",
    "scam":                        "Fraud Orders",
    "carding":                     "Fraud Orders",
    "cryptocurrency":              "Fraud Orders",
    "token":                       "Fraud Orders",
    "crypto":                      "Fraud Orders",
    "mining":                      "Fraud Orders",

    # ── Generic catch-all ────────────────────────────────────
    "malicious ip":                "Suspicious Activity",
    "malicious host":              "Suspicious Activity",
    "malicious activity":          "Suspicious Activity",
    "suspicious activity":         "Suspicious Activity",
    "suspicious":                  "Suspicious Activity",
    "abuse":                       "Suspicious Activity",
    "unknown":                     "Suspicious Activity",
    "other":                       "Suspicious Activity",
    "":                            "Suspicious Activity",
}

# ================================================================
# SEVERITY MAP
# ================================================================
SEVERITY_MAP = {
    "critical":      "Critical",
    "very high":     "Critical",
    "very_high":     "Critical",
    "highest":       "Critical",
    "extreme":       "Critical",
    "severe":        "Critical",
    "high":          "High",
    "significant":   "High",
    "major":         "High",
    "medium":        "Medium",
    "moderate":      "Medium",
    "med":           "Medium",
    "warning":       "Medium",
    "low":           "Low",
    "minor":         "Low",
    "informational": "Low",
    "info":          "Low",
}

# ================================================================
# SMART CATEGORY DETECTION
# Scans full text for keywords — used for OTX pulse names
# ================================================================
KEYWORD_CATEGORY = [
    # Order matters — more specific first
    ("ransomware",            "Ransomware"),
    ("lockbit",               "Ransomware"),
    ("blackcat",              "Ransomware"),
    ("cl0p",                  "Ransomware"),

    ("ddos-for-hire",         "DDoS Attack"),
    ("ddos",                  "DDoS Attack"),
    ("denial of service",     "DDoS Attack"),
    ("game-server botnet",    "DDoS Attack"),
    ("booter",                "DDoS Attack"),

    ("sql injection",         "SQL Injection"),
    ("sqli",                  "SQL Injection"),

    ("phishing",              "Phishing"),
    ("clickfix",              "Phishing"),
    ("fake update",           "Phishing"),
    ("typosquat",             "Phishing"),
    ("spoofing",              "Phishing"),
    ("credential",            "Phishing"),

    ("c2 server",             "C2 Server"),
    ("active c2",             "C2 Server"),
    ("c2 infrastructure",     "C2 Server"),
    ("command and control",   "C2 Server"),
    ("command-and-control",   "C2 Server"),
    ("reverse shell",         "C2 Server"),
    ("botnet",                "C2 Server"),
    ("cobalt strike",         "C2 Server"),
    ("enterprise compromise", "C2 Server"),
    ("intrusion",             "C2 Server"),
    ("edge appliance",        "C2 Server"),
    ("caddy proxy",           "C2 Server"),
    ("tsundere",              "C2 Server"),
    ("castleloader",          "C2 Server"),
    ("deno runtime",          "C2 Server"),

    ("stealer",               "Malware Distribution"),
    ("infostealer",           "Malware Distribution"),
    ("info stealer",          "Malware Distribution"),
    ("backdoor",              "Malware Distribution"),
    ("rat ",                  "Malware Distribution"),
    ("remote access",         "Malware Distribution"),
    ("cryptojack",            "Malware Distribution"),
    ("cryptomin",             "Malware Distribution"),
    ("gpu mining",            "Malware Distribution"),
    ("malware",               "Malware Distribution"),
    ("dropper",               "Malware Distribution"),
    ("downloader",            "Malware Distribution"),
    ("npm",                   "Malware Distribution"),
    ("supply chain",          "Malware Distribution"),
    ("poisoned",              "Malware Distribution"),
    ("drive-by",              "Malware Distribution"),
    ("opendir",               "Malware Distribution"),
    ("android",               "Malware Distribution"),
    ("loader",                "Malware Distribution"),

    ("apt",                   "Hacking"),
    ("lazarus",               "Hacking"),
    ("kimsuky",               "Hacking"),
    ("espionage",             "Hacking"),
    ("cyberespionage",        "Hacking"),
    ("china-aligned",         "Hacking"),
    ("nation state",          "Hacking"),
    ("threat actor",          "Hacking"),
    ("attack technique",      "Hacking"),
    ("attack campaign",       "Hacking"),
    ("shadow-earth",          "Hacking"),

    ("exploit",               "Web App Attack"),
    ("cve-",                  "Web App Attack"),
    ("forticlient",           "Web App Attack"),
    ("confluence",            "Web App Attack"),

    ("cryptocurrency",        "Fraud Orders"),
    ("token bingo",           "Fraud Orders"),
    ("crypto",                "Fraud Orders"),
    ("mining",                "Fraud Orders"),

    ("ssh",                   "SSH Brute Force"),
    ("brute force",           "Brute Force"),
    ("bruteforce",            "Brute Force"),
    ("port scan",             "Port Scan"),
    ("scanning",              "Port Scan"),
]


def smart_category(text: str, tags: list = None) -> str:
    """
    Detect category by scanning full text + tags for keywords.
    Used for OTX pulse names which are long descriptive strings.

    Priority:
    1. Scan tags first (most reliable)
    2. Scan full text (pulse name + description)
    3. Fall back to exact CATEGORY_MAP match
    4. Return "Suspicious Activity" if nothing matches
    """
    if not text and not tags:
        return "Suspicious Activity"

    # Step 1: Scan tags
    if tags:
        for tag in tags:
            tag_lower = str(tag).lower().strip()
            # Direct map check
            if tag_lower in CATEGORY_MAP:
                result = CATEGORY_MAP[tag_lower]
                if result != "Suspicious Activity":
                    return result
            # Keyword scan on tag
            for keyword, category in KEYWORD_CATEGORY:
                if keyword in tag_lower:
                    return category

    # Step 2: Scan full text
    text_lower = str(text).lower().strip()
    for keyword, category in KEYWORD_CATEGORY:
        if keyword in text_lower:
            return category

    # Step 3: Try exact map
    result = CATEGORY_MAP.get(text_lower, "Suspicious Activity")
    return result


def normalize_category(raw: str) -> str:
    """
    Normalise a simple raw category string.
    For OTX pulse names use smart_category() instead.
    """
    if not raw:
        return "Suspicious Activity"
    cleaned = str(raw).lower().strip().replace("_", " ").replace("-", " ")
    return CATEGORY_MAP.get(cleaned, "Suspicious Activity")


def normalize_severity(raw: str) -> str:
    """Normalise severity string."""
    if not raw:
        return "Medium"
    return SEVERITY_MAP.get(str(raw).lower().strip(), "Medium")


def normalize_severity_from_confidence(confidence: float) -> str:
    """Derive severity from AbuseIPDB confidence score."""
    if confidence is None:
        return "Medium"
    if confidence >= 90: return "Critical"
    if confidence >= 70: return "High"
    if confidence >= 50: return "Medium"
    return "Low"


def normalize_threat(ioc: str, raw_category: str,
                     raw_severity: str = None,
                     confidence: float = None,
                     tags: list = None) -> dict:
    """
    Full normalisation pass.
    Uses smart_category() to handle OTX pulse names.
    """
    # Use smart detection for long text (OTX pulse names)
    if raw_category and len(raw_category) > 30:
        category = smart_category(raw_category, tags)
    else:
        category = smart_category(raw_category, tags)

    # Severity priority: confidence > raw label > category default
    if confidence is not None:
        severity = normalize_severity_from_confidence(confidence)
    elif raw_severity:
        severity = normalize_severity(raw_severity)
    else:
        severity = _severity_from_category(category)

    return {"category": category, "severity": severity}


def _severity_from_category(category: str) -> str:
    """Infer severity from category."""
    defaults = {
        "C2 Server":            "Critical",
        "Ransomware":           "Critical",
        "DDoS Attack":          "High",
        "SQL Injection":        "High",
        "Phishing":             "High",
        "Malware Distribution": "High",
        "SSH Brute Force":      "High",
        "FTP Brute Force":      "High",
        "Brute Force":          "High",
        "Web App Attack":       "High",
        "Hacking":              "High",
        "DNS Compromise":       "Medium",
        "Email Spam":           "Medium",
        "Web Spam":             "Medium",
        "Open Proxy":           "Medium",
        "Fraud Orders":         "Medium",
        "Port Scan":            "Medium",
        "Suspicious Activity":  "Medium",
    }
    return defaults.get(category, "Medium")


def normalize_tags(raw_tags) -> list:
    """Normalise tags to clean list."""
    if not raw_tags:
        return []
    if isinstance(raw_tags, list):
        return [str(t).strip().lower() for t in raw_tags if t][:4]
    if isinstance(raw_tags, str):
        return [t.strip().lower() for t in raw_tags.split(",") if t.strip()][:4]
    return []


def normalize_status(raw_status: str) -> str:
    """Normalise status string."""
    if not raw_status:
        return "unknown"
    s = str(raw_status).lower().strip()
    if s in ["active", "online", "live", "up", "confirmed"]:
        return "active"
    if s in ["offline", "down", "inactive", "expired", "dead"]:
        return "offline"
    return "unknown"


def normalize_ioc_type(raw_type: str) -> str:
    """Normalise IOC type."""
    if not raw_type:
        return "Unknown"
    type_map = {
        "ipv4": "IP", "ipv6": "IP", "ip": "IP",
        "url": "URL", "uri": "URL",
        "domain": "Domain", "hostname": "Domain",
        "host": "Domain", "fqdn": "Domain",
        "filehash-md5": "Hash", "filehash-sha1": "Hash",
        "filehash-sha256": "Hash", "hash": "Hash",
        "md5": "Hash", "sha1": "Hash", "sha256": "Hash",
        "cve": "CVE",
    }
    return type_map.get(str(raw_type).lower().strip(), "Unknown")