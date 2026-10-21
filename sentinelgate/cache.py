import json
import sqlite3
import time
from pathlib import Path
from typing import Optional
from sentinelgate.provenance import PackageProvenance

CACHE_DIR = Path.home() / ".cache" / "sentinelgate"
CACHE_FILE = CACHE_DIR / "provenance.db"

class ProvenanceCache:
    def __init__(self, ttl_seconds: int = 86400):
        self.ttl = ttl_seconds
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(CACHE_FILE) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS provenance_cache (
                    name TEXT PRIMARY KEY,
                    pkg_exists INTEGER,
                    age_days REAL,
                    version_count INTEGER,
                    has_project_urls INTEGER,
                    has_source_repo INTEGER,
                    latest_release_age_days REAL,
                    risk_score REAL,
                    flags TEXT,
                    cached_at REAL
                )
            """)

    def get(self, name: str) -> Optional[PackageProvenance]:
        with sqlite3.connect(CACHE_FILE) as conn:
            row = conn.execute(
                "SELECT pkg_exists, age_days, version_count, has_project_urls, has_source_repo, "
                "latest_release_age_days, risk_score, flags, cached_at "
                "FROM provenance_cache WHERE name = ?",
                (name.lower(),)
            ).fetchone()

        if not row:
            return None

        if time.time() - row[8] > self.ttl:
            return None

        return PackageProvenance(
            name=name.lower(),
            exists=bool(row[0]),
            age_days=row[1],
            version_count=row[2],
            has_project_urls=bool(row[3]),
            has_source_repo=bool(row[4]),
            latest_release_age_days=row[5],
            risk_score=row[6],
            flags=json.loads(row[7])
        )

    def set(self, prov: PackageProvenance):
        with sqlite3.connect(CACHE_FILE) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO provenance_cache
                (name, pkg_exists, age_days, version_count, has_project_urls, has_source_repo,
                 latest_release_age_days, risk_score, flags, cached_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                prov.name.lower(),
                1 if prov.exists else 0,
                prov.age_days,
                prov.version_count,
                1 if prov.has_project_urls else 0,
                1 if prov.has_source_repo else 0,
                prov.latest_release_age_days,
                prov.risk_score,
                json.dumps(prov.flags),
                time.time()
            ))
