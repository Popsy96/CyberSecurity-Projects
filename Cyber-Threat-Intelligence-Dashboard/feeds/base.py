"""
feeds/base.py
=============
Shared utilities — AU filter + threat builder.

KEY FIXES:
----------
1. Tags passed to classify_malware_type()
2. CVE detection overrides category to "CVE"
   so NIST maps correctly to "Identify"
3. Malware family extracted from tags only
   (not from long pulse names)
"""

from processing.normalise  import normalize_threat, normalize_tags, normalize_status, normalize_ioc_type
from processing.cvss       import calculate_cvss, cvss_to_severity, calculate_risk_rating
from processing.mitre      import get_mitre
from processing.nist       import get_nist, get_asd_e8, get_iso
from processing.classifier import (get_industry, classify_malware_type,
                                   extract_cve, extract_malware_family_from_tags)
from processing.location   import assign_au_city, to_au_time, now_utc_date

# ── Australian Keywords ──────────────────────────────────────
AU_KEYWORDS = [
    # Country
    "australia", "australian", "aus ",
    # Domains
    ".com.au", ".gov.au", ".edu.au", ".net.au", ".org.au", ".id.au",
    # Banking
    "anz", "nab", "commbank", "commonwealth bank", "westpac", "macquarie",
    "bendigo", "suncorp", "bankwest", "ing australia", "boq", "bank of queensland",
    "st george", "bank of melbourne", "banksa",
    # Government
    "mygov", "mygovid", "ato", "centrelink", "medicare",
    "services australia", "auspost", "australia post",
    "acsc", "asd", "afp", "abs", "asio", "asis",
    "service nsw", "vic gov", "qld gov",
    # Telecom
    "telstra", "optus", "tpg", "iinet", "vodafone australia",
    "aussie broadband", "superloop",
    # Energy
    "agl", "origin energy", "energyaustralia", "ausgrid", "endeavour energy",
    # Retail
    "woolworths", "coles", "bunnings", "officeworks", "jb hi-fi",
    "harvey norman", "kmart australia", "target australia",
    # Transport
    "qantas", "virgin australia", "jetstar", "tigerair",
    "australia post", "toll group", "linfox",
    # Healthcare
    "medibank", "bupa australia", "hcf", "nib health",
    "st vincents", "royal melbourne", "royal sydney",
    # Education
    "unimelb", "usyd", "unsw", "uq", "monash",
    "anu", "rmit", "deakin", "curtin",
    # Cyber specific
    "australian government", "au government",
    "critical infrastructure australia",
]

# ── Australian IP Ranges ─────────────────────────────────────
AU_IP_PREFIXES = [
    "1.120.", "1.121.", "1.128.", "1.129.",
    "27.32.", "27.33.", "36.255.",
    "43.228.", "43.229.", "43.240.", "43.241.",
    "49.176.", "49.177.", "49.178.", "49.179.",
    "58.96.", "58.160.", "58.161.", "58.162.", "58.163.",
    "101.160.", "101.161.", "103.1.", "103.2.", "103.3.",
    "110.140.", "110.141.", "110.142.", "110.143.",
    "121.200.", "121.201.", "121.216.", "121.217.",
    "124.168.", "124.169.", "124.170.", "124.171.",
    "139.130.", "144.48.", "150.101.",
    "203.0.", "203.2.", "203.4.", "203.6.", "203.8.", "203.10.",
    "210.10.", "210.11.", "210.12.", "210.13.",
    "220.240.", "220.241.", "221.133.",
]


def is_au_related(text: str) -> bool:
    return any(kw in text.lower() for kw in AU_KEYWORDS)


def is_au_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in AU_IP_PREFIXES)


def build_threat(ioc, raw_type, raw_category,
                 raw_severity=None, source="",
                 raw_status="", raw_tags=None,
                 timestamp_utc="", confidence=None,
                 total_reports=0, malware_family="",
                 isp="", reference="", target="") -> dict:
    """
    Build standardised threat dictionary.

    Processing order:
    Step 1 → Normalise (category, severity, type, tags, status)
    Step 2 → CVE detection (overrides category if CVE found)
    Step 3 → CVSS score
    Step 4 → Framework mappings
    Step 5 → Malware classification (tags-first)
    Step 6 → Industry detection
    Step 7 → Location + timestamp
    """

    # ── STEP 1: NORMALISE ────────────────────────────────────
    clean_tags = normalize_tags(raw_tags)
    norm       = normalize_threat(ioc, raw_category,
                                  raw_severity, confidence,
                                  clean_tags)
    category   = norm["category"]
    severity   = norm["severity"]
    ioc_type   = normalize_ioc_type(raw_type)
    status     = normalize_status(raw_status)

    # ── STEP 2: CVE DETECTION ────────────────────────────────
    # Check IOC itself, target text, and raw_category
    cve_id = (extract_cve(ioc) or
              extract_cve(target) or
              extract_cve(raw_category))

    # If CVE found → override category and type
    if cve_id:
        category = "CVE"           # → NIST: Identify ✅
        if ioc_type not in ["IP", "URL", "Domain", "Hash"]:
            ioc_type = "CVE"

    # ── STEP 3: CVSS ─────────────────────────────────────────
    cvss      = calculate_cvss(severity, confidence, category)
    sev_final = cvss_to_severity(cvss)
    risk      = calculate_risk_rating(cvss, total_reports, status)

    # ── STEP 4: FRAMEWORK MAPPING ────────────────────────────
    mitre_id, mitre_name = get_mitre(category)
    nist_fn              = get_nist(category)
    asd_e8               = get_asd_e8(category)
    iso_ctrl             = get_iso(category)

    # ── STEP 5: MALWARE CLASSIFICATION ───────────────────────
    # Pass TAGS to classifier — tags are most reliable signal
    mal_type = classify_malware_type(
        malware_family or category,
        tags=clean_tags
    )

    # Extract short family name from tags only
    # (avoids long pulse names like "DinDoor Backdoor: Deno...")
    mal_fam = extract_malware_family_from_tags(clean_tags)
    if not mal_fam and malware_family:
        # Only use malware_family if it's short and meaningful
        mf_clean = malware_family.strip()
        if len(mf_clean) < 25 and mf_clean.lower() not in ["unknown", "none", ""]:
            mal_fam = mf_clean

    # ── STEP 6: INDUSTRY ─────────────────────────────────────
    # Scan IOC + target + tags for industry keywords
    tags_text = " ".join(clean_tags)
    industry  = get_industry(ioc + " " + target + " " + tags_text)

    # ── STEP 7: LOCATION + TIME ──────────────────────────────
    city, city_data = assign_au_city(ioc, target)

    return {
        "ioc":             ioc,
        "type":            ioc_type,
        "category":        category,
        "severity":        sev_final,
        "cvss_score":      cvss,
        "risk_rating":     risk,
        "mitre_technique": mitre_id,
        "mitre_name":      mitre_name,
        "nist_function":   nist_fn,
        "asd_e8":          asd_e8,
        "iso_control":     iso_ctrl,
        "source":          source,
        "status":          status,
        "tags":            clean_tags,
        "industry":        industry,
        "malware_family":  mal_fam,
        "malware_type":    mal_type,
        "cve_id":          cve_id,
        "city":            city,
        "state":           city_data["state"],
        "lat":             city_data["lat"],
        "lng":             city_data["lng"],
        "confidence_score":confidence,
        "total_reports":   total_reports,
        "isp":             isp,
        "reference":       reference,
        "timestamp_au":    to_au_time(timestamp_utc),
        "timestamp_utc":   timestamp_utc[:16] if timestamp_utc else "",
        "date_only":       timestamp_utc[:10] if timestamp_utc else now_utc_date(),
    }