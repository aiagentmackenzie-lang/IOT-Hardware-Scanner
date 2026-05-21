"""NVD API Client with local SQLite caching.

SDR §11.1 — NVD API v2 Integration

Queries the NVD API for CVEs by CPE string and keyword.
Caches results locally in SQLite with configurable TTL.
Rate-limits requests per NVD guidelines.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from iot_hardware_scanner.config import ScannerConfig

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_CACHE_DB = Path.home() / ".iot_hardware_scanner" / "nvd_cache.db"
CACHE_TTL_DAYS = 7


class NVDClient:
    """NVD API v2 client with rate limiting and local caching.

    Rate limits:
    - Without API key: 6-second delay between requests
    - With API key: 0.6-second delay between requests

    Cache:
    - SQLite database at ~/.iot_hardware_scanner/nvd_cache.db
    - Results cached for 7 days by default
    """

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config
        self._cache_db = DEFAULT_CACHE_DB
        self._last_request_time: float = 0.0
        self._init_cache()

    def _init_cache(self) -> None:
        """Initialize the SQLite cache database."""
        self._cache_db.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(self._cache_db)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS nvd_cache (
                    query_key TEXT PRIMARY KEY,
                    response_json TEXT NOT NULL,
                    cached_at REAL NOT NULL
                )
            """)
            conn.commit()

    def _rate_limit(self) -> None:
        """Enforce NVD rate limits between requests."""
        min_interval = 0.6 if self.config.nvd_api_key else 6.0
        elapsed = time.time() - self._last_request_time
        if elapsed < min_interval:
            wait = min_interval - elapsed
            logger.debug("NVD rate limit: sleeping %.1fs", wait)
            time.sleep(wait)
        self._last_request_time = time.time()

    def _get_cached(self, query_key: str) -> list[dict] | None:
        """Retrieve cached results if still within TTL."""
        ttl_seconds = self.config.nvd_cache_days * 86400
        try:
            with sqlite3.connect(str(self._cache_db)) as conn:
                row = conn.execute(
                    "SELECT response_json, cached_at FROM nvd_cache WHERE query_key = ?",
                    (query_key,),
                ).fetchone()
                if row:
                    cached_at = row[1]
                    if time.time() - cached_at < ttl_seconds:
                        return json.loads(row[0])  # type: ignore[no-any-return]
                    # Expired — delete
                    conn.execute("DELETE FROM nvd_cache WHERE query_key = ?", (query_key,))
                    conn.commit()
        except (sqlite3.Error, json.JSONDecodeError) as exc:
            logger.warning("Cache read error: %s", exc)
        return None

    def _set_cached(self, query_key: str, results: list[dict]) -> None:
        """Store results in cache."""
        try:
            with sqlite3.connect(str(self._cache_db)) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO nvd_cache (query_key, response_json, cached_at) "
                    "VALUES (?, ?, ?)",
                    (query_key, json.dumps(results), time.time()),
                )
                conn.commit()
        except sqlite3.Error as exc:
            logger.warning("Cache write error: %s", exc)

    def _make_request(self, url: str) -> dict | None:
        """Make an HTTP GET request to the NVD API.

        Returns:
            Response dict on success, None on failure.

        May raise NVDClientError on persistent failures to allow
        upstream callers to distinguish "API down" from "no results".
        """
        if self.config.offline_mode:
            logger.info("NVD query skipped (offline mode): %s", url)
            return None

        headers = {"Accept": "application/json"}
        if self.config.nvd_api_key:
            headers["apiKey"] = self.config.nvd_api_key

        last_error: str | None = None
        for attempt in range(self.config.nvd_max_retries + 1):
            if attempt > 0:
                delay = min(2 ** attempt, 30)  # Exponential backoff: 2, 4, 8, ... max 30s
                logger.info("NVD retry attempt %d/%d in %.1fs", attempt, self.config.nvd_max_retries, delay)
                time.sleep(delay)

            req = Request(url, headers=headers)
            try:
                self._rate_limit()
                with urlopen(req, timeout=30) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        return data  # type: ignore[no-any-return]
                    else:
                        logger.warning("NVD API returned status %d", resp.status)
                        return None
            except HTTPError as exc:
                status_code = getattr(exc, 'code', None)
                last_error = f"HTTP {status_code}: {exc.reason}"
                logger.warning("NVD API HTTP error: %s", last_error)
                if status_code in (429, 503):
                    continue  # Retryable
                return None
            except URLError as exc:
                last_error = f"URL error: {exc}"
                logger.warning("NVD API URL error: %s", exc)
                continue  # Retryable (network)
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("NVD API request error: %s", exc)
                return None

        logger.warning("NVD API request failed after %d retries: %s", self.config.nvd_max_retries, last_error)
        return None

    def _parse_cve_results(self, data: dict) -> list[dict]:
        """Parse NVD API response into simplified CVE records."""
        results = []
        vulnerabilities = data.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Extract CVSS v3
            metrics = cve.get("metrics", {})
            cvss_v3 = None
            cvss_v3_vector = None
            for key in ("cvssMetricV31", "cvssMetricV30"):
                if metrics.get(key):
                    cvss_data = metrics[key][0].get("cvssData", {})
                    cvss_v3 = cvss_data.get("baseScore")
                    cvss_v3_vector = cvss_data.get("vectorString")
                    break

            # Extract references
            references = []
            for ref in cve.get("references", []):
                url = ref.get("url", "")
                if url:
                    references.append(url)

            # Published date
            published = cve.get("published", "")

            results.append(
                {
                    "cve_id": cve_id,
                    "description": description,
                    "cvss_v3_score": cvss_v3,
                    "cvss_v3_vector": cvss_v3_vector,
                    "published_date": published,
                    "references": references,
                }
            )

        return results

    def query_cpe(self, cpe_string: str) -> list[dict]:
        """Query NVD for CVEs matching a CPE string.

        Uses cpeName parameter for precise matching.
        """
        # Check cache first
        cache_key = f"cpe:{cpe_string}"
        cached = self._get_cached(cache_key)
        if cached is not None:
            logger.debug("NVD cache hit for CPE: %s", cpe_string)
            return cached

        # Build URL
        from urllib.parse import quote

        url = f"{NVD_API_BASE}?cpeName={quote(cpe_string, safe=':')}"
        logger.info("NVD CPE query: %s", cpe_string)

        data = self._make_request(url)
        if data is None:
            return []

        results = self._parse_cve_results(data)
        self._set_cached(cache_key, results)
        logger.info("NVD CPE query returned %d CVEs for %s", len(results), cpe_string)
        return results

    def query_keyword(self, keyword: str) -> list[dict]:
        """Query NVD for CVEs matching a keyword.

        Uses keywordSearch parameter for broad matching.
        """
        cache_key = f"kw:{keyword}"
        cached = self._get_cached(cache_key)
        if cached is not None:
            logger.debug("NVD cache hit for keyword: %s", keyword)
            return cached

        from urllib.parse import quote

        url = f"{NVD_API_BASE}?keywordSearch={quote(keyword)}"
        logger.info("NVD keyword query: %s", keyword)

        data = self._make_request(url)
        if data is None:
            return []

        results = self._parse_cve_results(data)
        # Limit results to most recent 20
        results = results[:20]
        self._set_cached(cache_key, results)
        logger.info("NVD keyword query returned %d CVEs for %s", len(results), keyword)
        return results
