"""
main.py
========
AU Cyber Threat Intelligence Dashboard
CYB815 Cybersecurity Capstone — Group 14
Supervisor: Dr. Haafizah Rameeza Shaukat

Project Brief:
  Developing a CTI Dashboard that aggregates multiple
  open-source threat feeds to provide real-time insights
  into emerging cyber threats including malware outbreaks,
  phishing campaigns, and suspicious network activities.

Run:
  python main.py
"""

import json
from processing.cvss     import cvss_to_severity
from processing.location import now_au, now_utc, get_au_tz
from processing.response import export_for_dashboard
from feeds.otx_feed      import fetch_otx
from feeds.abuseipdb_feed import fetch_abuseipdb
from feeds.urlhaus_feed  import fetch_urlhaus
from feeds.feodo_feed    import fetch_feodo
from database.db         import (
    setup_database, save_threats, save_run,
    load_all_threats, load_fetch_runs, load_timeline
)

try:
    from config import OTX_API_KEY, ABUSEIPDB_KEY, MAX_RESULTS_PER_FEED
except ImportError:
    print("ERROR: config.py not found!")
    exit(1)

JSON_PATH = "data.json"


def count_by(lst: list, key: str) -> dict:
    d = {}
    for t in lst:
        v = t.get(key, "Unknown") or "Unknown"
        d[v] = d.get(v, 0) + 1
    return d


def build_stats(historical, this_run, new_count, runs, timeline):
    cvss_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for t in historical:
        cvss_dist[cvss_to_severity(t.get("cvss_score") or 5.0)] += 1

    nist_dist = {"Identify": 0, "Protect": 0, "Detect": 0,
                 "Respond": 0, "Recover": 0}
    for t in historical:
        fn = t.get("nist_function", "Detect")
        if fn in nist_dist:
            nist_dist[fn] += 1

    mitre_d = {}
    for t in historical:
        tid  = t.get("mitre_technique", "")
        name = t.get("mitre_name", "")
        if tid:
            if tid not in mitre_d:
                mitre_d[tid] = {"technique": tid, "name": name, "count": 0}
            mitre_d[tid]["count"] += 1
    mitre_top = sorted(mitre_d.values(), key=lambda x: -x["count"])[:8]

    # Category counts
    cat_counts = count_by(historical, "category")

    return {
        # ── Core counts ──────────────────────────────────────
        "total":               len(historical),
        "this_run":            len(this_run),
        "new_this_run":        new_count,

        # ── Severity (from project brief: identify risks) ────
        "critical":            sum(1 for t in historical if t.get("severity") == "Critical"),
        "high":                sum(1 for t in historical if t.get("severity") == "High"),
        "medium":              sum(1 for t in historical if t.get("severity") == "Medium"),
        "low":                 sum(1 for t in historical if t.get("severity") == "Low"),

        # ── Threat types (from project brief) ────────────────
        # "malware outbreaks" — includes all malware categories
        "malware":             (cat_counts.get("Malware Distribution", 0) +
                                cat_counts.get("Malware Outbreaks", 0)),
        # "phishing campaigns"
        "phishing":            cat_counts.get("Phishing", 0),
        # "suspicious network activities" — brute force, port scan, SSH attacks
        "suspicious":          (cat_counts.get("Suspicious Activity", 0) +
                                cat_counts.get("Brute Force", 0) +
                                cat_counts.get("SSH Brute Force", 0) +
                                cat_counts.get("FTP Brute Force", 0) +
                                cat_counts.get("Port Scan", 0)),
        # C2 infrastructure
        "c2":                  cat_counts.get("C2 Server", 0),
        # Web attacks
        "web_app":             (cat_counts.get("Web App Attack", 0) +
                                cat_counts.get("SQL Injection", 0)),
        # DDoS
        "ddos":                cat_counts.get("DDoS Attack", 0),
        # CVEs
        "cve_count":           cat_counts.get("CVE", 0),
        # Fraud
        "fraud":               cat_counts.get("Fraud Orders", 0),

        # ── Malware classification ────────────────────────────
        "ransomware_count":    sum(1 for t in historical if t.get("malware_type") == "Ransomware"),
        "trojan_count":        sum(1 for t in historical if t.get("malware_type") == "Banking Trojan"),
        "rat_count":           sum(1 for t in historical if t.get("malware_type") == "RAT"),
        "infostealer_count":   sum(1 for t in historical if t.get("malware_type") == "Infostealer"),
        "botnet_count":        sum(1 for t in historical if t.get("malware_type") == "Botnet"),
        "c2fw_count":          sum(1 for t in historical if t.get("malware_type") == "C2 Framework"),

        # ── Risk scoring ─────────────────────────────────────
        "avg_cvss":            round(sum(t.get("cvss_score") or 0
                               for t in historical) / max(len(historical), 1), 1),
        "cvss_dist":           cvss_dist,

        # ── Framework distributions ───────────────────────────
        "nist_dist":           nist_dist,
        "mitre_top":           mitre_top,

        # ── Breakdown counts ─────────────────────────────────
        "industry_counts":     count_by(historical, "industry"),
        "category_counts":     cat_counts,
        "source_counts":       count_by(historical, "source"),
        "city_counts":         count_by(historical, "city"),
        "malware_type_counts": count_by(historical, "malware_type"),
        "malware_family_counts": count_by(historical, "malware_family"),
        "asd_e8_counts":       count_by(historical, "asd_e8"),

        # ── Meta ─────────────────────────────────────────────
        "last_updated":        now_au(),
        "last_updated_utc":    now_utc(),
        "timezone":            get_au_tz()[1],
        "feeds":               ["AlienVault OTX", "AbuseIPDB",
                                 "URLhaus", "Feodo Tracker"],
        "frameworks":          ["MITRE ATT&CK", "NIST CSF", "CVSS v3.1",
                                 "ASD Essential 8", "ISO 27001"],
        "fetch_runs":          runs,
        "timeline":            timeline,
    }


def print_results(stats, unique):
    """Print results aligned to project brief."""
    _, tz = get_au_tz()
    sep = "=" * 55

    print(f"\n{sep}")
    print(f"  COLLECTION SUMMARY")
    print(f"{sep}")
    print(f"  This run    : {len(unique)} threats collected")
    print(f"  New to DB   : {stats['new_this_run']}")
    print(f"  Total in DB : {stats['total']}")

    print(f"\n  SEVERITY BREAKDOWN")
    print(f"  {'Critical':<12}: {stats['critical']}")
    print(f"  {'High':<12}: {stats['high']}")
    print(f"  {'Medium':<12}: {stats['medium']}")
    print(f"  {'Low':<12}: {stats['low']}")

    print(f"\n  THREAT CATEGORIES (Project Brief)")
    print(f"  {'Malware Outbreaks':<22}: {stats['malware']}")
    print(f"  {'Phishing Campaigns':<22}: {stats['phishing']}")
    print(f"  {'Suspicious Activity':<22}: {stats['suspicious']}")
    print(f"  {'Web App Attacks':<22}: {stats['web_app']}")
    print(f"  {'C2 Infrastructure':<22}: {stats['c2']}")
    print(f"  {'DDoS Attacks':<22}: {stats['ddos']}")
    print(f"  {'CVE References':<22}: {stats['cve_count']}")
    print(f"  {'Fraud Orders':<22}: {stats['fraud']}")

    print(f"\n  MALWARE CLASSIFICATION")
    print(f"  {'RAT':<16}: {stats['rat_count']}")
    print(f"  {'Infostealer':<16}: {stats['infostealer_count']}")
    print(f"  {'Botnet':<16}: {stats['botnet_count']}")
    print(f"  {'C2 Framework':<16}: {stats['c2fw_count']}")

    print(f"\n  NIST CSF DISTRIBUTION")
    nd = stats['nist_dist']
    print(f"  {'Identify':<12}: {nd.get('Identify', 0)}")
    print(f"  {'Protect':<12}: {nd.get('Protect', 0)}")
    print(f"  {'Detect':<12}: {nd.get('Detect', 0)}")
    print(f"  {'Respond':<12}: {nd.get('Respond', 0)}")
    print(f"  {'Recover':<12}: {nd.get('Recover', 0)}")

    print(f"\n  RISK SCORING")
    print(f"  {'Avg CVSS':<12}: {stats['avg_cvss']} / 10.0")

    print(f"\n  FRAMEWORKS APPLIED")
    for fw in stats['frameworks']:
        print(f"  ✓ {fw}")

    print(f"\n  Updated     : {stats['last_updated']}")
    print(f"{sep}")
    print(f"\n  Done! Open dashboard/index.html in browser.")
    print(f"{sep}\n")


def main():
    _, tz = get_au_tz()
    sep = "=" * 55
    print(f"\n{sep}")
    print(f"  AU CTI DASHBOARD - THREAT FEED COLLECTOR v3.0")
    print(f"  CYB815 Cybersecurity Capstone — Group 14")
    print(f"{sep}")
    print(f"  Timezone   : {tz}")
    print(f"  Frameworks : MITRE ATT&CK | NIST CSF | CVSS v3.1 | ASD E8 | ISO 27001")
    print(f"  Feeds      : OTX | AbuseIPDB | URLhaus | Feodo Tracker")
    print(f"{sep}")

    # Setup
    setup_database()

    # Show AbuseIPDB cache status upfront
    import os, json
    from datetime import datetime, timezone, timedelta
    cache_file = "abuseipdb_cache.json"
    aest = timezone(timedelta(hours=10))
    if os.path.exists(cache_file):
        try:
            with open(cache_file) as f:
                c = json.load(f)
            cached_date = c.get("date","")
            today_aest  = datetime.now(aest).strftime("%Y-%m-%d")
            au_ips      = len([d for d in c.get("data",[]) if d.get("countryCode","")=="AU"])
            calls       = c.get("calls_today", 0)
            status      = "VALID" if cached_date == today_aest else "EXPIRED"
            print(f"   AbuseIPDB Cache : {status} ({cached_date}) — {au_ips} AU IPs — {calls}/5 calls used")
        except:
            print("   AbuseIPDB Cache : corrupted — will fetch fresh")
    else:
        print("   AbuseIPDB Cache : not found — will fetch fresh today")
    print(sep)

    # Collect from all feeds
    all_threats  = []
    all_threats += fetch_otx(OTX_API_KEY, MAX_RESULTS_PER_FEED)
    all_threats += fetch_abuseipdb(ABUSEIPDB_KEY, MAX_RESULTS_PER_FEED)
    all_threats += fetch_urlhaus()
    all_threats += fetch_feodo()

    # Deduplicate
    seen, unique = set(), []
    for t in all_threats:
        if t["ioc"] not in seen:
            seen.add(t["ioc"])
            unique.append(t)
    print(f"\n   This run: {len(unique)} unique threats")

    # Save and load
    new_count  = save_threats(unique)
    historical = load_all_threats()
    runs       = load_fetch_runs()
    timeline   = load_timeline()

    # Build stats
    stats = build_stats(historical, unique, new_count, runs, timeline)

    # Save data.json — compact and optimised for fast browser loading
    ir_data = export_for_dashboard()

    # Keep only fields the dashboard actually uses
    KEEP = {'severity','cvss_score','type','ioc','category',
            'mitre_technique','mitre_name','nist_function','asd_e8',
            'malware_type','malware_family','industry','source',
            'city','lat','lng','timestamp_au','timestamp_utc',
            'confidence','status'}

    # Sort by CVSS desc — all threats included
    sorted_threats = sorted(historical, key=lambda x: x.get('cvss_score',0), reverse=True)
    slim_threats   = [{k:v for k,v in t.items() if k in KEEP} for t in sorted_threats]

    # Store real total in stats
    stats['total_in_db'] = len(historical)

    with open(JSON_PATH, "w", encoding="utf-8") as f:
        json.dump({
            "stats":   stats,
            "threats": slim_threats,
            "ir_data": ir_data,
        }, f, separators=(',',':'))  # compact JSON = 3x smaller

    # Save run history
    save_run(stats, new_count)

    # Print results
    print_results(stats, unique)


if __name__ == "__main__":
    main()