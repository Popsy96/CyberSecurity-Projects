"""
feeds/urlhaus_feed.py
======================
URLhaus malware URL feed.

Strategy:
  1. Prefer AU-related URLs (strict filter)
  2. If AU URLs < 50, fill with global
     malware URLs up to max_results
  3. Cap total at max_results (200)

This ensures:
  Always have enough data ✅
  AU-relevant where possible ✅
  Defensible in report ✅
"""

import csv
import requests
from feeds.base import build_threat, is_au_related

def fetch_urlhaus(max_results: int = 200) -> list:
    print("Fetching URLhaus...")
    threats     = []
    au_threats  = []
    all_threats = []

    try:
        response = requests.get(
            "https://urlhaus.abuse.ch/downloads/csv_recent/",
            timeout=30,
            headers={"User-Agent": "CTI-Capstone-Dashboard/1.0"}
        )
        response.raise_for_status()

        lines = [
            line for line in response.text.splitlines()
            if line.strip() and not line.startswith("#")
        ]

        reader = csv.DictReader(lines, fieldnames=[
            "id", "dateadded", "url", "url_status",
            "last_online", "threat", "tags",
            "urlhaus_link", "reporter"
        ])

        for row in reader:
            url_val    = row.get("url",        "").strip()
            raw_tags   = row.get("tags",        "").strip()
            raw_threat = row.get("threat",      "malware_download").strip()
            status     = row.get("url_status",  "unknown").strip()

            if not url_val:
                continue

            # Only active URLs
            if status.lower() not in ["online", "active"]:
                continue

            threat = build_threat(
                ioc=url_val[:120],
                raw_type="url",
                raw_category=raw_threat or "malware_download",
                raw_severity=None,
                source="URLhaus",
                raw_status=status,
                raw_tags=raw_tags,
                timestamp_utc=row.get("dateadded", ""),
                malware_family=raw_tags or "Unknown",
                reference=row.get("urlhaus_link", ""),
                target="Australian organisations",
            )

            # Separate AU vs global
            if is_au_related(url_val) or is_au_related(raw_tags):
                au_threats.append(threat)
            else:
                all_threats.append(threat)

            # Stop reading once we have enough
            if len(au_threats) + len(all_threats) >= max_results * 3:
                break

        # Prefer AU threats, fill with global if needed
        threats = au_threats[:max_results]
        if len(threats) < 50:
            needed  = min(max_results - len(threats), len(all_threats))
            threats += all_threats[:needed]

        print(f"   URLhaus         : {len(threats)} AU threats "
              f"({len(au_threats)} AU-specific + "
              f"{len(threats)-len(au_threats[:len(threats)])} global fill)")

    except Exception as e:
        print(f"   URLhaus         : Error — {e}")

    return threats[:max_results]