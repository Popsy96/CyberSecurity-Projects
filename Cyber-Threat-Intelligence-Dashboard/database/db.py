"""
database/db.py
===============
SQLite database setup and queries.

Two tables:
  threats    — every IOC ever collected (full history)
  fetch_runs — summary of each data collection run
"""

import sqlite3
from processing.location import now_utc, now_utc_date

DB_PATH = "threats.db"


def setup_database():
    """Create tables and indexes if they don't exist."""
    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc              TEXT NOT NULL UNIQUE,
            type             TEXT,
            category         TEXT,
            severity         TEXT,
            cvss_score       REAL,
            risk_rating      TEXT,
            mitre_technique  TEXT,
            mitre_name       TEXT,
            nist_function    TEXT,
            asd_e8           TEXT,
            iso_control      TEXT,
            source           TEXT,
            status           TEXT,
            tags             TEXT,
            industry         TEXT,
            city             TEXT,
            state            TEXT,
            lat              REAL,
            lng              REAL,
            country          TEXT DEFAULT 'AU',
            confidence_score REAL,
            total_reports    INTEGER DEFAULT 0,
            malware_family   TEXT,
            malware_type     TEXT,
            cve_id           TEXT,
            isp              TEXT,
            reference        TEXT,
            timestamp_au     TEXT,
            timestamp_utc    TEXT,
            date_only        TEXT,
            first_seen       TEXT,
            last_seen        TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS fetch_runs (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            run_time_au  TEXT,
            run_time_utc TEXT,
            total        INTEGER,
            critical     INTEGER,
            high         INTEGER,
            medium       INTEGER,
            low          INTEGER,
            phishing     INTEGER,
            malware      INTEGER,
            c2           INTEGER,
            avg_cvss     REAL,
            new_threats  INTEGER,
            feeds_used   TEXT
        )
    """)

    for idx in [
        "CREATE INDEX IF NOT EXISTS idx_severity  ON threats(severity)",
        "CREATE INDEX IF NOT EXISTS idx_source    ON threats(source)",
        "CREATE INDEX IF NOT EXISTS idx_type      ON threats(type)",
        "CREATE INDEX IF NOT EXISTS idx_city      ON threats(city)",
        "CREATE INDEX IF NOT EXISTS idx_industry  ON threats(industry)",
        "CREATE INDEX IF NOT EXISTS idx_date      ON threats(date_only)",
        "CREATE INDEX IF NOT EXISTS idx_timestamp ON threats(timestamp_utc)",
        "CREATE INDEX IF NOT EXISTS idx_mitre     ON threats(mitre_technique)",
        "CREATE INDEX IF NOT EXISTS idx_nist      ON threats(nist_function)",
        "CREATE INDEX IF NOT EXISTS idx_cvss      ON threats(cvss_score)",
        "CREATE INDEX IF NOT EXISTS idx_malware   ON threats(malware_type)",
    ]:
        cur.execute(idx)

    conn.commit()
    conn.close()
    print("   Database ready:", DB_PATH)


def save_threats(threats: list) -> int:
    """
    Save threats to SQLite.
    New IOCs are inserted; existing ones are updated.
    first_seen is preserved for historical tracking.

    Returns: number of new threats inserted
    """
    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()
    n    = now_utc()
    new  = updated = 0

    for t in threats:
        cur.execute("SELECT id, first_seen FROM threats WHERE ioc=?", (t["ioc"],))
        existing   = cur.fetchone()
        first_seen = existing[1] if existing else t.get("timestamp_utc", n)

        try:
            cur.execute("""
                INSERT OR REPLACE INTO threats (
                    ioc, type, category, severity, cvss_score, risk_rating,
                    mitre_technique, mitre_name, nist_function, asd_e8, iso_control,
                    source, status, tags, industry, city, state, lat, lng, country,
                    confidence_score, total_reports, malware_family, malware_type,
                    cve_id, isp, reference,
                    timestamp_au, timestamp_utc, date_only, first_seen, last_seen
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                t["ioc"], t["type"], t["category"], t["severity"],
                t["cvss_score"], t["risk_rating"],
                t["mitre_technique"], t["mitre_name"], t["nist_function"],
                t.get("asd_e8",""), t.get("iso_control",""),
                t["source"], t["status"], ",".join(t.get("tags",[])),
                t["industry"], t["city"], t.get("state",""),
                t["lat"], t["lng"], "AU",
                t.get("confidence_score"), t.get("total_reports",0),
                t.get("malware_family",""), t.get("malware_type","Unknown"),
                t.get("cve_id",""), t.get("isp",""), t.get("reference",""),
                t["timestamp_au"], t["timestamp_utc"],
                t.get("date_only", now_utc_date()),
                first_seen, n,
            ))
            if existing: updated += 1
            else: new += 1
        except Exception as e:
            print(f"   DB warning: {e}")

    conn.commit()
    conn.close()
    print(f"   DB: {new} new | {updated} updated")
    return new


def save_run(stats: dict, new_count: int):
    """Save a summary of this fetch run."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO fetch_runs (
            run_time_au, run_time_utc, total, critical, high, medium, low,
            phishing, malware, c2, avg_cvss, new_threats, feeds_used
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        stats["last_updated"], stats["last_updated_utc"],
        stats["total"], stats["critical"], stats["high"],
        stats["medium"], stats["low"],
        stats["phishing"], stats["malware"], stats["c2"],
        stats["avg_cvss"], new_count, ",".join(stats["feeds"]),
    ))
    conn.commit()
    conn.close()


def load_all_threats() -> list:
    """Load all threats from DB (full history)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur  = conn.cursor()
    cur.execute("SELECT * FROM threats ORDER BY cvss_score DESC, last_seen DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    for r in rows:
        r["tags"] = [t.strip() for t in (r.get("tags") or "").split(",") if t.strip()]
    return rows


def load_fetch_runs() -> list:
    """Load last 10 fetch run summaries."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur  = conn.cursor()
    cur.execute("SELECT * FROM fetch_runs ORDER BY id DESC LIMIT 10")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def load_timeline() -> list:
    """
    Load daily IOC counts for timeline chart.
    Uses date_only (pulse creation date) so May/June
    subscribed pulses show their original threat dates.
    Pads project period March 14 - June 7 with zeros.
    """
    from datetime import date, timedelta

    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()
    cur.execute("""
        SELECT date_only, COUNT(*) as count
        FROM threats
        WHERE date_only IS NOT NULL
          AND date_only != ''
          AND date_only >= '2026-03-14'
          AND date_only <= '2026-06-07'
        GROUP BY date_only
        ORDER BY date_only ASC
    """)
    data = {r[0]: r[1] for r in cur.fetchall()}
    conn.close()

    # Pad all dates in project period with 0 for missing days
    start = date(2026, 3, 14)
    end   = date(2026, 6, 7)
    rows  = []
    d = start
    while d <= end:
        ds = d.strftime("%Y-%m-%d")
        rows.append({"date": ds, "count": data.get(ds, 0)})
        d += timedelta(days=1)
    return rows