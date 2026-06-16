"""
feeds/feodo_feed.py
====================
Feodo Tracker — Active C2 botnet servers
Global C2 infrastructure targeting AU systems

Improvements applied:
  1. User-Agent header (avoids blocks)
  2. IP format validation (no bad rows)
  3. Timestamp fallback (first_seen or last_online)
"""

import csv
import ipaddress
import requests
from feeds.base import build_threat


def fetch_feodo() -> list:
    print("Fetching Feodo Tracker (global C2 targeting AU)...")
    threats = []

    try:
        response = requests.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
            timeout=30,
            headers={"User-Agent": "CTI-Capstone-Dashboard/1.0"}
        )
        response.raise_for_status()

        lines = [
            line for line in response.text.splitlines()
            if line.strip() and not line.startswith("#")
        ]

        reader = csv.DictReader(lines, fieldnames=[
            "first_seen", "dst_ip", "dst_port",
            "c2_status", "last_online", "malware"
        ])

        count = 0

        for row in reader:
            ip      = row.get("dst_ip",     "").strip()
            malware = row.get("malware",     "Unknown").strip()
            status  = row.get("c2_status",   "unknown").strip()

            if not ip:
                continue

            # Validate IP format
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue

            # Only active C2 servers
            if status.lower() not in ["online", "active"]:
                continue

            # Timestamp fallback
            timestamp = row.get("first_seen") or row.get("last_online", "")

            threats.append(build_threat(
                ioc=ip,
                raw_type="ipv4",
                raw_category="c2",
                raw_severity="critical",
                source="Feodo Tracker",
                raw_status=status,
                raw_tags=["botnet", "c2", malware.lower()],
                timestamp_utc=timestamp,
                malware_family=malware,
                reference=f"https://feodotracker.abuse.ch/browse/host/{ip}/",
            ))

            count += 1
            if count >= 100:
                break

        print(f"   Feodo Tracker   : {len(threats)} active global C2 IPs")

    except Exception as e:
        print(f"   Feodo Tracker   : Error — {e}")

    return threats