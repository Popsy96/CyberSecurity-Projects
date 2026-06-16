"""
processing/location.py
=======================
Australian city and timezone assignment.
"""

import random
from datetime import datetime, timezone, timedelta

AU_CITIES = {
    "Sydney":     {"lat": -33.8688, "lng": 151.2093, "state": "NSW"},
    "Melbourne":  {"lat": -37.8136, "lng": 144.9631, "state": "VIC"},
    "Brisbane":   {"lat": -27.4698, "lng": 153.0251, "state": "QLD"},
    "Perth":      {"lat": -31.9505, "lng": 115.8605, "state": "WA"},
    "Adelaide":   {"lat": -34.9285, "lng": 138.6007, "state": "SA"},
    "Canberra":   {"lat": -35.2809, "lng": 149.1300, "state": "ACT"},
    "Hobart":     {"lat": -42.8821, "lng": 147.3272, "state": "TAS"},
    "Darwin":     {"lat": -12.4634, "lng": 130.8456, "state": "NT"},
    "Gold Coast": {"lat": -28.0167, "lng": 153.4000, "state": "QLD"},
    "Newcastle":  {"lat": -32.9283, "lng": 151.7817, "state": "NSW"},
}

CITY_HINTS = {
    "sydney": "Sydney",    "nsw": "Sydney",
    "melbourne":"Melbourne","vic": "Melbourne",
    "brisbane":"Brisbane",  "qld": "Brisbane",
    "perth":  "Perth",      "wa":  "Perth",
    "adelaide":"Adelaide",  "sa":  "Adelaide",
    "canberra":"Canberra",  "act": "Canberra",
    "hobart": "Hobart",     "tas": "Hobart",
    "darwin": "Darwin",     "nt":  "Darwin",
    "gold coast":"Gold Coast",
    "newcastle":"Newcastle",
}

CITY_WEIGHTS = [30, 25, 15, 10, 8, 4, 2, 2, 2, 2]


def assign_au_city(ioc: str, target: str = "") -> tuple:
    """
    Assign an Australian city to a threat.

    Step 1: Check IOC text for city/state hints.
    Step 2: If no hint, use population-weighted random selection.

    Returns: (city_name, city_data_dict)
    """
    text = (ioc + " " + target).lower()
    for hint, city in CITY_HINTS.items():
        if hint in text:
            return city, AU_CITIES[city]
    cities = list(AU_CITIES.keys())
    city   = random.choices(cities, weights=CITY_WEIGHTS)[0]
    return city, AU_CITIES[city]


def get_au_tz() -> tuple:
    """
    Return current Australian Eastern timezone offset and label.
    AEDT = UTC+11 (October–April, Daylight Saving)
    AEST = UTC+10 (April–October, Standard Time)
    """
    month = datetime.now(timezone.utc).month
    if month in [10, 11, 12, 1, 2, 3]:
        return timedelta(hours=11), "AEDT"
    return timedelta(hours=10), "AEST"


def to_au_time(utc_str: str) -> str:
    """Convert a UTC timestamp string to Australian Eastern Time."""
    if not utc_str:
        return ""
    try:
        offset, label = get_au_tz()
        dt    = datetime.strptime(utc_str[:16].replace("T", " "), "%Y-%m-%d %H:%M")
        dt_au = dt.replace(tzinfo=timezone.utc) + offset
        return dt_au.strftime(f"%d/%m/%Y %H:%M {label}")
    except Exception:
        return utc_str[:16]


def now_au() -> str:
    """Current time in Australian Eastern Time."""
    offset, label = get_au_tz()
    return (datetime.now(timezone.utc) + offset).strftime(f"%d/%m/%Y %H:%M:%S {label}")


def now_utc() -> str:
    """Current UTC time as string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def now_utc_date() -> str:
    """Current UTC date as string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")