"""
show_feeds.py — Raw feed sample data
CYB815 Capstone — Group 14
Run: python show_feeds.py
"""

import requests, json, os
from config import OTX_API_KEY, ABUSEIPDB_KEY

SEP = "=" * 60

print(f"\n{SEP}")
print("  RAW FEED DATA SAMPLES — Before Normalisation")
print("  CYB815 Cybersecurity Capstone — Group 14")
print(f"{SEP}")

# ── FEED 1: OTX ──────────────────────────────────────────────
print("\n  FEED 1 — AlienVault OTX (Raw Pulse)\n")
try:
    r = requests.get(
        "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=1",
        headers={"X-OTX-API-KEY": OTX_API_KEY}, timeout=30
    )
    p   = r.json().get("results", [{}])[0]
    ind = p.get("indicators", [{}])[0]
    print(json.dumps({
        "pulse_name": p.get("name","—"),
        "tags":       p.get("tags",[])[:4],
        "indicator":  ind.get("indicator","—"),
        "type":       ind.get("type","—"),
        "created":    ind.get("created","—")[:10],
    }, indent=4))
except Exception as e:
    print(f"  Error: {e}")

# ── FEED 2: AbuseIPDB ─────────────────────────────────────────
print("\n  FEED 2 — AbuseIPDB (Raw IP Record)\n")
try:
    if os.path.exists("abuseipdb_cache.json"):
        with open("abuseipdb_cache.json") as f:
            entry = json.load(f).get("data",[{}])[0]
        print(json.dumps({
            "ipAddress":            entry.get("ipAddress","—"),
            "countryCode":          entry.get("countryCode","—"),
            "abuseConfidenceScore": entry.get("abuseConfidenceScore","—"),
            "categories":           entry.get("categories",[]),
            "lastReportedAt":       entry.get("lastReportedAt","—"),
        }, indent=4))
    else:
        print("  No cache — run main.py first")
except Exception as e:
    print(f"  Error: {e}")

# ── FEED 3: URLhaus ───────────────────────────────────────────
print("\n  FEED 3 — URLhaus (Raw URL Record)\n")
try:
    r   = requests.get("https://urlhaus-api.abuse.ch/v1/urls/recent/", timeout=30)
    url = r.json().get("urls",[{}])[0]
    print(json.dumps({
        "url":        url.get("url","—")[:60],
        "url_status": url.get("url_status","—"),
        "threat":     url.get("threat","—"),
        "tags":       url.get("tags","—"),
        "date_added": url.get("date_added","—"),
    }, indent=4))
except Exception as e:
    print(f"  Error: {e}")

# ── FEED 4: Feodo ─────────────────────────────────────────────
print("\n  FEED 4 — Feodo Tracker (Raw CSV Line)\n")
try:
    r     = requests.get(
        "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        timeout=30
    )
    lines = [l for l in r.text.split("\n") if l and not l.startswith("#")]
    if lines:
        cols = ["first_seen","dst_port","last_online","malware","host"]
        vals = lines[0].split(",")
        print(json.dumps(dict(zip(cols, vals)), indent=4))
    else:
        print("  Feodo dataset currently empty")
except Exception as e:
    print(f"  Error: {e}")

print(f"\n{SEP}")
print("  Note: Above shows RAW format from each feed")
print("  Our normalisation layer converts all to unified schema")
print(f"{SEP}\n")