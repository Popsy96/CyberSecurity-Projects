"""
feeds/otx_feed.py
==================
AlienVault OTX feed fetcher.
Retry logic with 90 second timeout.
Falls back to cached DB data on persistent timeout.
"""

import time
import requests
from feeds.base import is_au_related, is_au_ip, build_threat
from processing.normalise import normalize_ioc_type, smart_category
from processing.classifier import extract_malware_family_from_tags


def fetch_otx(api_key: str, max_results: int = 100) -> list:
    print("Fetching AlienVault OTX...")
    threats  = []
    headers  = {"X-OTX-API-KEY": api_key}
    url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50&page=1"

    # ── RETRY LOGIC ──────────────────────────────────────────
    # Try 3 times with increasing wait between attempts
    response = None
    for attempt in range(1, 4):
        try:
            print(f"   OTX: Attempt {attempt}/3 ...")
            response = requests.get(url, headers=headers, timeout=90)
            response.raise_for_status()
            print(f"   OTX: Connected successfully")
            break
        except requests.exceptions.Timeout:
            if attempt < 3:
                wait = attempt * 5   # 5s, 10s between retries
                print(f"   OTX: Timeout — waiting {wait}s before retry...")
                time.sleep(wait)
            else:
                print("   OTX: Timed out after 3 attempts")
                print("   OTX: Dashboard will use existing DB data")
                return []
        except requests.exceptions.HTTPError as e:
            code = e.response.status_code
            if code == 401:
                print("   OTX: Invalid API key — check config.py")
            elif code == 429:
                print("   OTX: Rate limit hit — try again later")
            else:
                print(f"   OTX: HTTP Error {code}")
            return []
        except requests.exceptions.ConnectionError:
            if attempt < 3:
                print(f"   OTX: Connection error — retrying...")
                time.sleep(5)
            else:
                print("   OTX: Cannot connect — check internet connection")
                return []
        except Exception as e:
            print(f"   OTX Error: {e}")
            return []

    if not response:
        return []

    # ── PROCESS PULSES ────────────────────────────────────────
    try:
        for pulse in response.json().get("results", []):
            pname = pulse.get("name", "")
            ptags = pulse.get("tags", [])
            pdesc = pulse.get("description", "")

            # Smart category from pulse name + tags
            category = smart_category(pname + " " + pdesc, ptags)

            # Malware family from tags
            mal_family = extract_malware_family_from_tags(ptags)
            if not mal_family:
                words = pname.split()
                if len(words) >= 2:
                    mal_family = " ".join(words[:2])

            for ind in pulse.get("indicators", []):
                ioc      = ind.get("indicator", "")
                raw_type = ind.get("type", "")
                created  = ind.get("created", "")

                if not ioc:
                    continue

                ioc_type = normalize_ioc_type(raw_type)

                # AU filter
                au = (
                    is_au_related(ioc) or
                    is_au_related(pname) or
                    is_au_related(pdesc) or
                    any(is_au_related(t) for t in ptags) or
                    (ioc_type == "IP" and is_au_ip(ioc))
                )
                if not au:
                    continue

                threats.append(build_threat(
                    ioc=ioc,
                    raw_type=raw_type,
                    raw_category=category,
                    raw_severity=None,
                    source="AlienVault OTX",
                    raw_status="active",
                    raw_tags=ptags,
                    timestamp_utc=created,
                    confidence=None,
                    malware_family=mal_family,
                    reference=f"https://otx.alienvault.com/pulse/{pulse.get('id','')}",
                    target=pname,
                ))

        print(f"   AlienVault OTX  : {len(threats)} AU threats")

    except Exception as e:
        print(f"   OTX processing error: {e}")

    return threats