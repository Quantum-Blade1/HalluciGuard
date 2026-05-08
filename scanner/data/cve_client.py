"""
CVE Client — OSV.dev API + SQLite Cache.

Queries OSV.dev POST /v1/query with package name and ecosystem (PyPI/npm).
Caches results in SQLite at data/cve_cache/cve_cache.db with 24h TTL.
Returns (cve_count, [cve_ids]).
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from pathlib import Path

import httpx
from scanner.config import CVE_CACHE_DIR

logger = logging.getLogger(__name__)

OSV_API_URL = "https://api.osv.dev/v1/query"
CACHE_TTL_SECONDS = 86400  # 24 hours
REQUEST_TIMEOUT = 3.0


class CVEClient:
    """Client for OSV.dev vulnerability lookups with SQLite caching."""

    def __init__(self, cache_dir: Path | None = None) -> None:
        self._cache_dir = cache_dir or CVE_CACHE_DIR
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = self._cache_dir / "cve_cache.db"
        self._init_cache()
        self._client: httpx.AsyncClient | None = None

    def _init_cache(self) -> None:
        conn = sqlite3.connect(str(self._db_path))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                package_name TEXT NOT NULL, 
                ecosystem TEXT NOT NULL,
                cve_count INTEGER NOT NULL,
                cve_ids TEXT NOT NULL, 
                cached_at REAL NOT NULL,
                PRIMARY KEY (package_name, ecosystem)
            )
        """)
        conn.commit()
        conn.close()

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(REQUEST_TIMEOUT),
                headers={"Content-Type": "application/json"},
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    def _check_cache(self, package_name: str, ecosystem: str) -> tuple[int, list[str]] | None:
        try:
            conn = sqlite3.connect(str(self._db_path))
            cursor = conn.execute(
                "SELECT cve_count, cve_ids, cached_at "
                "FROM cve_cache WHERE package_name = ? AND ecosystem = ?",
                (package_name, ecosystem),
            )
            row = cursor.fetchone()
            conn.close()
            if row and time.time() - row[2] < CACHE_TTL_SECONDS:
                return (row[0], json.loads(row[1]))
        except sqlite3.Error as e:
            logger.warning("Cache read error: %s", e)
        return None

    def _update_cache(self, package_name: str, ecosystem: str, cve_count: int, cve_ids: list[str]) -> None:
        try:
            conn = sqlite3.connect(str(self._db_path))
            conn.execute(
                "INSERT OR REPLACE INTO cve_cache VALUES (?, ?, ?, ?, ?)",
                (package_name, ecosystem, cve_count, json.dumps(cve_ids), time.time()),
            )
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logger.warning("Cache write error: %s", e)

    async def check_cve(self, package_name: str, ecosystem: str) -> tuple[int, list[str]]:
        """Query OSV.dev for CVEs.
        
        Args:
            package_name: Name of the package.
            ecosystem: 'PyPI' or 'npm'.
            
        Returns:
            Tuple of (cve_count, [cve_ids]).
        """
        cached = self._check_cache(package_name, ecosystem)
        if cached is not None:
            return cached

        client = await self._get_client()
        payload = {"package": {"name": package_name, "ecosystem": ecosystem}}
        try:
            response = await client.post(OSV_API_URL, json=payload)
            if response.status_code == 200:
                data = response.json()
                vulns = data.get("vulns", [])
                cve_ids = [v.get("id", "") for v in vulns if v.get("id")]
                cve_count = len(vulns)
                
                self._update_cache(package_name, ecosystem, cve_count, cve_ids[:20])
                return (cve_count, cve_ids[:20])
        except Exception as e:
            logger.warning("OSV.dev lookup failed for %s: %s", package_name, e)

        return (0, [])
