"""
feeds/abuseipdb_feed.py
========================
AbuseIPDB feed fetcher.

RATE LIMIT AWARE:
-----------------
Free tier blacklist = 5 requests/day ONLY.
This script tracks daily usage in the cache file.
When limit is reached it uses last successful data.
Cache auto-deletes and refreshes each new day.
"""

import json
import os
import requests
from datetime import datetime, timezone
from feeds.base import build_threat

CACHE_FILE    = "abuseipdb_cache.json"
DAILY_LIMIT   = 5

ABUSE_CAT_LABELS = {
    1:  "dns compromise",
    3:  "fraud orders",
    4:  "ddos attack",
    5:  "ftp brute force",
    7:  "phishing",
    9:  "open proxy",
    10: "web spam",
    11: "email spam",
    14: "port scan",
    15: "hacking",
    16: "sql injection",
    18: "brute force",
    21: "web app attack",
    22: "ssh brute force",
}


def _today() -> str:
    """Return today's date in AEST timezone."""
    from datetime import timezone, timedelta
    aest = timezone(timedelta(hours=10))
    return datetime.now(aest).strftime("%Y-%m-%d")


def _load_cache() -> dict:
    """
    Load cache. Auto-deletes and resets if from a previous day.
    Returns cache dict with keys: date, calls_today, data
    """
    today = _today()

    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                cache = json.load(f)

            # New day → delete old cache and start fresh
            if cache.get("date", "") != today:
                os.remove(CACHE_FILE)
                print(f"   AbuseIPDB       : new day — old cache deleted, starting fresh")
                return {"date": today, "calls_today": 0, "data": []}

            # Same day → return existing cache
            calls = cache.get("calls_today", 0)
            au    = len([d for d in cache.get("data",[]) if d.get("countryCode","")=="AU"])
            print(f"   AbuseIPDB       : cache valid ({today}) — {au} AU IPs — {calls}/{DAILY_LIMIT} calls used today")
            return cache

        except Exception:
            os.remove(CACHE_FILE)
            return {"date": today, "calls_today": 0, "data": []}

    # No cache file at all
    return {"date": today, "calls_today": 0, "data": []}


def _save_cache(cache: dict):
    """Save cache to file."""
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        print(f"   AbuseIPDB       : cache save error: {e}")


def fetch_abuseipdb(api_key: str, max_results: int = 100) -> list:
    """
    Fetch Australian IPs from AbuseIPDB.
    Tracks daily API usage and respects 5/day limit.
    Auto-refreshes cache each new day.
    """
    print("Fetching AbuseIPDB...")
    cache = _load_cache()
    today = _today()

    # Check if limit reached
    calls_today = cache.get("calls_today", 0)
    if calls_today >= DAILY_LIMIT:
        au_data = [d for d in cache.get("data",[]) if d.get("countryCode","")=="AU"]
        print(f"   AbuseIPDB       : daily limit reached ({DAILY_LIMIT}/{DAILY_LIMIT}) — using last cached data ({len(au_data)} AU IPs)")
    else:
        # Fetch fresh from API
        try:
            headers = {"Key": api_key, "Accept": "application/json"}
            params  = {
                "countryCode":       "AU",
                "maxAgeInDays":      30,
                "limit":             max_results,
                "confidenceMinimum": 50,
            }
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/blacklist",
                headers=headers, params=params, timeout=30
            )
            response.raise_for_status()

            raw_data = response.json().get("data", [])

            # Filter to AU only (free tier doesn't reliably filter)
            au_data = [d for d in raw_data if d.get("countryCode","") == "AU"]

            # Update cache
            cache["date"]        = today
            cache["calls_today"] = calls_today + 1
            cache["data"]        = raw_data   # save all, filter on load
            _save_cache(cache)

            remaining = DAILY_LIMIT - (calls_today + 1)
            print(f"   AbuseIPDB       : fetched {len(au_data)} fresh AU IPs — {calls_today+1}/{DAILY_LIMIT} calls used ({remaining} remaining today)")

        except requests.exceptions.HTTPError as e:
            code = e.response.status_code
            au_data = [d for d in cache.get("data",[]) if d.get("countryCode","")=="AU"]
            if code == 401:
                print("   AbuseIPDB       : invalid API key — check config.py")
            elif code == 429:
                print(f"   AbuseIPDB       : rate limit hit — using cached data ({len(au_data)} AU IPs)")
                cache["calls_today"] = DAILY_LIMIT
                _save_cache(cache)
            else:
                print(f"   AbuseIPDB       : HTTP error {code} — using cached data")
            return _build_threats(au_data)

        except Exception as e:
            print(f"   AbuseIPDB       : error — {e}")
            au_data = [d for d in cache.get("data",[]) if d.get("countryCode","")=="AU"]

    threats = _build_threats(au_data)
    print(f"   AbuseIPDB       : {len(threats)} AU IP threats processed")
    return threats


def _build_threats(raw_data: list) -> list:
    """Build threat objects from raw AbuseIPDB data."""
    threats = []
    for entry in raw_data:
        ip         = entry.get("ipAddress", "")
        confidence = entry.get("abuseConfidenceScore", 0)
        last_rep   = entry.get("lastReportedAt", "")
        categories = entry.get("categories", [])
        isp        = entry.get("isp", "")
        domain     = entry.get("domain", "")
        reports    = entry.get("totalReports", 0)

        if not ip:
            continue

        raw_labels   = [ABUSE_CAT_LABELS.get(c, "suspicious activity")
                        for c in categories if c in ABUSE_CAT_LABELS]
        raw_category = raw_labels[0] if raw_labels else "suspicious activity"

        threats.append(build_threat(
            ioc=ip,
            raw_type="ipv4",
            raw_category=raw_category,
            raw_severity=None,
            source="AbuseIPDB",
            raw_status="active",
            raw_tags=raw_labels,
            timestamp_utc=last_rep,
            confidence=confidence,
            total_reports=reports,
            isp=isp,
            reference=f"https://www.abuseipdb.com/check/{ip}",
            target=domain or "",
        ))
    return threats