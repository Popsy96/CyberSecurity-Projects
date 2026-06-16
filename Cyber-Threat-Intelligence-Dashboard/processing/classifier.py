"""
processing/classifier.py
=========================
Malware family and industry classification.

KEY FIXES:
----------
1. Tags scanned for malware type BEFORE family name
2. DDoS/game-related families not misclassified
3. More tag-based detection added
4. Industry detection improved
"""

import re

# ── Malware family → type ────────────────────────────────────
MALWARE_FAMILIES = {
    # Ransomware
    "lockbit":          "Ransomware",
    "blackcat":         "Ransomware",
    "alphv":            "Ransomware",
    "revil":            "Ransomware",
    "conti":            "Ransomware",
    "hive":             "Ransomware",
    "cl0p":             "Ransomware",
    "medusa":           "Ransomware",
    "play":             "Ransomware",
    "darkside":         "Ransomware",
    "ryuk":             "Ransomware",
    "maze":             "Ransomware",
    "ransomware":       "Ransomware",
    "ekz":              "Ransomware",

    # Banking Trojans
    "emotet":           "Banking Trojan",
    "qakbot":           "Banking Trojan",
    "qbot":             "Banking Trojan",
    "trickbot":         "Banking Trojan",
    "dridex":           "Banking Trojan",
    "ursnif":           "Banking Trojan",
    "icedid":           "Banking Trojan",
    "gootloader":       "Banking Trojan",

    # C2 Frameworks
    "cobalt strike":    "C2 Framework",
    "cobaltstrike":     "C2 Framework",
    "metasploit":       "C2 Framework",
    "sliver":           "C2 Framework",
    "empire":           "C2 Framework",
    "castleloader":     "C2 Framework",
    "dindoor":          "C2 Framework",
    "gopherwhisper":    "C2 Framework",
    "komari":           "C2 Framework",

    # RATs
    "remcos":           "RAT",
    "njrat":            "RAT",
    "asyncrat":         "RAT",
    "nanocore":         "RAT",
    "purehvnc":         "RAT",
    "httpspy":          "RAT",
    "remotemanipu":     "RAT",

    # Infostealers
    "redline":          "Infostealer",
    "raccoon":          "Infostealer",
    "vidar":            "Infostealer",
    "azorult":          "Infostealer",
    "formbook":         "Infostealer",
    "amos":             "Infostealer",
    "santastealer":     "Infostealer",
    "lofystealer":      "Infostealer",
    "snappyclient":     "Infostealer",
    "weedhack":         "Infostealer",
    "clearfake":        "Infostealer",
    "venomLNK":         "Infostealer",

    # Botnets
    "mirai":            "Botnet",
    "mirai-derived":    "Botnet",
    "mozi":             "Botnet",
    "ddostf":           "Botnet",
    "tsundere":         "Botnet",
    "ddos-for-hire":    "Botnet",
    "booter":           "Botnet",
    "stresser":         "Botnet",
    "game server":      "Botnet",
    "game-server":      "Botnet",

    # Keyloggers
    "agent tesla":      "Keylogger",
    "hawkeye":          "Keylogger",
}

# ── Tags that indicate malware type directly ──────────────────
TAG_TYPE_MAP = {
    "ransomware":       "Ransomware",
    "lockbit":          "Ransomware",
    "blackcat":         "Ransomware",
    "revil":            "Ransomware",
    "conti":            "Ransomware",
    "mirai":            "Botnet",
    "mirai-derived":    "Botnet",
    "botnet":           "Botnet",
    "ddos-for-hire":    "Botnet",
    "booter":           "Botnet",
    "stresser":         "Botnet",
    "game-server":      "Botnet",
    "emotet":           "Banking Trojan",
    "qakbot":           "Banking Trojan",
    "trickbot":         "Banking Trojan",
    "cobalt strike":    "C2 Framework",
    "cobaltstrike":     "C2 Framework",
    "castleloader":     "C2 Framework",
    "rat":              "RAT",
    "asyncrat":         "RAT",
    "remcos":           "RAT",
    "stealer":          "Infostealer",
    "infostealer":      "Infostealer",
    "redline":          "Infostealer",
    "amos":             "Infostealer",
    "keylogger":        "Keylogger",
    "agent tesla":      "Keylogger",
}

# ── Words that are NOT malware families ───────────────────────
# These are targets, platforms, or generic words
NOT_A_FAMILY = {
    "minecraft", "game", "gaming", "server", "android", "ios",
    "windows", "linux", "macos", "australia", "australian",
    "energy", "government", "bank", "finance", "healthcare",
    "sector", "industry", "campaign", "operation", "threat",
    "actor", "group", "apt", "attack", "targeting", "target",
    "new", "old", "unknown", "other", "none", "null",
}

# ── AU Industry Keywords ─────────────────────────────────────
INDUSTRY_MAP = [
    (["anz","nab","commbank","commonwealth","westpac","macquarie",
      "bendigo","suncorp","bankwest","bank","financial","finance",
      "payment","credit card","carding","bitcoin","crypto exchange"],
      "Banking & Finance"),
    (["mygov","mygovid","ato","centrelink","medicare",
      "services australia","gov.au","afp","abs","asd","acsc",
      "government","defence","defense","military","parliament",
      "shadow-earth","china-aligned","espionage","geopolitical"],
      "Government"),
    (["telstra","optus","tpg","iinet","vodafone","nbn",
      "telecommunications","telecom","internet provider","isp"],
      "Telecommunications"),
    (["hospital","health","medicare","medical","clinic","pharmacy",
      "healthcare","surgery","patient","aged care"],
      "Healthcare"),
    (["woolworths","coles","bunnings","officeworks","amazon",
      "ebay","retail","shop","store","ecommerce"],
      "Retail"),
    (["qantas","virgin australia","jetstar","airline","aviation",
      "airport","flight","transport","logistics","auspost"],
      "Aviation & Transport"),
    (["uni","university","edu.au","school","tafe","college",
      "student","academic","research","education"],
      "Education"),
    (["agl","origin energy","energyaustralia","energy","power",
      "utilities","electricity","gas","water","infrastructure",
      "energy sector"],
      "Energy & Utilities"),
    (["software","developer","ci/cd","cicd","github","npm","pypi",
      "supply chain","cryptocurrency","blockchain","web3","token",
      "cursor","screenconnect","fortinet","forticlient","confluence"],
      "Technology & Crypto"),
]


def classify_malware_type(text: str, tags: list = None) -> str:
    """
    Classify malware type.
    Checks TAGS first (most reliable), then text.
    """
    # Step 1: Check tags first
    if tags:
        for tag in tags:
            tag_lower = str(tag).strip().lower()
            if tag_lower in TAG_TYPE_MAP:
                return TAG_TYPE_MAP[tag_lower]
            # Partial match on tags
            for key, mtype in TAG_TYPE_MAP.items():
                if key in tag_lower:
                    return mtype

    # Step 2: Check text
    if not text:
        return "Unknown"
    t = text.lower()
    for name, mtype in MALWARE_FAMILIES.items():
        if name.lower() in t:
            return mtype

    return "Unknown"


def extract_malware_family_from_tags(tags: list) -> str:
    """
    Extract short malware family name from tags.
    Skips generic words that aren't real family names.
    """
    if not tags:
        return ""

    # Known good family names to extract
    known_families = list(MALWARE_FAMILIES.keys()) + list(TAG_TYPE_MAP.keys())

    for tag in tags:
        tag_clean = str(tag).strip().lower()

        # Skip if it's not a real family name
        if tag_clean in NOT_A_FAMILY:
            continue
        if len(tag_clean) < 3:
            continue

        # Check if tag matches a known family
        for family in known_families:
            if family in tag_clean or tag_clean in family:
                return tag.strip().title()

    return ""


def get_industry(text: str) -> str:
    """Detect AU industry from IOC text."""
    if not text:
        return "Other"
    t = text.lower()
    for keywords, industry in INDUSTRY_MAP:
        if any(kw in t for kw in keywords):
            return industry
    return "Other"


CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)


def extract_cve(text: str) -> str:
    """Extract CVE ID from text."""
    if not text:
        return ""
    match = CVE_PATTERN.search(text)
    return match.group(0).upper() if match else ""


def is_cve(text: str) -> bool:
    """Check if string is a CVE identifier."""
    return bool(CVE_PATTERN.match(str(text).strip()))