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
from dataclasses import dataclass, field
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from iot_hardware_scanner.config import ScannerConfig

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_CACHE_DB = Path.home() / ".iot_hardware_scanner" / "nvd_cache.db"
CACHE_TTL_DAYS = 7

#: NVD's own maximum page size. Larger values are rejected by the service.
MAX_RESULTS_PER_PAGE = 2000

#: Lookup states a caller can act on. They are deliberately distinct: "no
#: results" and "could not ask" mean opposite things to a CI gate.
STATE_MATCHED = "MATCHED"
STATE_KNOWN_EMPTY = "KNOWN_EMPTY"
STATE_UNAVAILABLE = "UNAVAILABLE"
STATE_STALE = "STALE"
STATE_PARTIAL = "PARTIAL"


@dataclass
class LookupResult:
    """One advisory query's answer, with its state and pagination record.

    ``pages`` and ``total_results`` come from the provider's own ``totalResults``
    field. When the page bound is reached before every result was read, the
    state is ``PARTIAL`` and the caller must not treat the empty remainder as a
    clean answer.
    """

    records: list[dict] = field(default_factory=list)
    state: str = STATE_KNOWN_EMPTY
    pages: int = 0
    total_results: int = 0
    reason: str = ""

    @property
    def complete(self) -> bool:
        """Whether the provider's whole result set was read."""
        return self.state in (STATE_MATCHED, STATE_KNOWN_EMPTY)


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

    def _request_page(self, url: str) -> tuple[dict | None, str]:
        """One page, with the reason it failed when it did.

        Offline is not a failure to hide: it returns ``UNAVAILABLE`` with the
        reason, so a caller can tell "we did not ask" from "the answer was none".
        """
        if self.config.offline_mode:
            logger.info("NVD query skipped (offline mode): %s", url)
            return None, "offline mode: no request was issued"

        headers = {"Accept": "application/json"}
        if self.config.nvd_api_key:
            headers["apiKey"] = self.config.nvd_api_key

        last_error = ""
        for attempt in range(self.config.nvd_max_retries + 1):
            if attempt > 0:
                delay = min(2**attempt, 30)
                logger.info(
                    "NVD retry attempt %d/%d in %.1fs",
                    attempt,
                    self.config.nvd_max_retries,
                    delay,
                )
                time.sleep(delay)

            request = Request(url, headers=headers)
            try:
                self._rate_limit()
                with urlopen(request, timeout=30) as response:
                    if response.status == 200:
                        return json.loads(response.read().decode("utf-8")), ""
                    last_error = f"HTTP {response.status}"
                    return None, last_error
            except HTTPError as exc:
                status_code = getattr(exc, "code", None)
                last_error = f"HTTP {status_code}: {exc.reason}"
                logger.warning("NVD API HTTP error: %s", last_error)
                if status_code in (429, 503):
                    continue  # rate limited: retry, bounded by nvd_max_retries
                return None, last_error
            except URLError as exc:
                last_error = f"URL error: {exc}"
                logger.warning("NVD API URL error: %s", exc)
                continue
            except (OSError, json.JSONDecodeError) as exc:
                last_error = f"request error: {exc}"
                logger.warning("NVD API request error: %s", exc)
                return None, last_error

        return None, f"failed after {self.config.nvd_max_retries} retr(ies): {last_error}"

    def _paginate(self, base_url: str) -> LookupResult:
        """Read a query's pages, bounded, and report how far it got."""
        per_page = min(MAX_RESULTS_PER_PAGE, max(1, self.config.nvd_max_results_per_page))
        records: list[dict] = []
        total = 0
        pages = 0
        for page in range(self.config.nvd_max_pages):
            url = f"{base_url}&startIndex={page * per_page}&resultsPerPage={per_page}"
            payload, error = self._request_page(url)
            if payload is None:
                if pages == 0:
                    return LookupResult(state=STATE_UNAVAILABLE, reason=error)
                return LookupResult(
                    records=records,
                    state=STATE_PARTIAL,
                    pages=pages,
                    total_results=total,
                    reason=f"page {pages + 1} failed: {error}",
                )
            pages += 1
            total = int(payload.get("totalResults", 0) or 0)
            records.extend(self._parse_cve_results(payload))
            if len(records) >= total or not payload.get("vulnerabilities"):
                return LookupResult(
                    records=records,
                    state=STATE_MATCHED if records else STATE_KNOWN_EMPTY,
                    pages=pages,
                    total_results=total,
                )
        return LookupResult(
            records=records,
            state=STATE_PARTIAL,
            pages=pages,
            total_results=total,
            reason=(
                f"stopped at the {self.config.nvd_max_pages}-page bound with "
                f"{len(records)} of {total} result(s) read"
            ),
        )

    def _parse_cve_results(self, data: dict) -> list[dict]:
        """Parse NVD API response into simplified CVE records.

        Applicability is preserved, not flattened: the version bounds and the
        CPE names of every vulnerable match are carried through so a later
        matcher can decide applicability from the provider's own statement.
        """
        results = []
        for vulnerability in data.get("vulnerabilities", []):
            cve = vulnerability.get("cve", {})
            cve_id = cve.get("id", "")
            description = ""
            for item in cve.get("descriptions", []):
                if item.get("lang") == "en":
                    description = item.get("value", "")
                    break

            metrics = cve.get("metrics", {})
            score = None
            vector = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
                if metrics.get(key):
                    data_block = metrics[key][0].get("cvssData", {})
                    score = data_block.get("baseScore")
                    vector = data_block.get("vectorString")
                    break

            matches: list[dict] = []
            for configuration in cve.get("configurations", []) or []:
                for node in configuration.get("nodes", []) or []:
                    for cpe_match in node.get("cpeMatch", []) or []:
                        matches.append(
                            {
                                "cpe": cpe_match.get("criteria", ""),
                                "vulnerable": bool(cpe_match.get("vulnerable", True)),
                                "version_start_including": cpe_match.get("versionStartIncluding"),
                                "version_start_excluding": cpe_match.get("versionStartExcluding"),
                                "version_end_including": cpe_match.get("versionEndIncluding"),
                                "version_end_excluding": cpe_match.get("versionEndExcluding"),
                            }
                        )

            results.append(
                {
                    "cve_id": cve_id,
                    "description": description,
                    "cvss_v3_score": score,
                    "cvss_v3_vector": vector,
                    "published_date": cve.get("published", ""),
                    "last_modified": cve.get("lastModified", ""),
                    "references": [
                        ref.get("url", "")
                        for ref in cve.get("references", []) or []
                        if ref.get("url")
                    ],
                    "matches": matches,
                }
            )
        return results

    def query_cpe_result(self, cpe_string: str) -> LookupResult:
        """Query NVD by CPE name, with pagination and an explicit state."""
        cache_key = f"cpe:{cpe_string}"
        cached = self._get_cached_result(cache_key)
        if cached is not None:
            return cached

        url = f"{NVD_API_BASE}?cpeName={quote(cpe_string, safe=':')}"
        logger.info("NVD CPE query: %s", cpe_string)
        result = self._paginate(url)
        if result.state in (STATE_MATCHED, STATE_KNOWN_EMPTY, STATE_PARTIAL):
            self._set_cached_result(cache_key, result)
        return result

    def query_keyword_result(self, keyword: str) -> LookupResult:
        """Query NVD by keyword, with pagination and an explicit state."""
        cache_key = f"kw:{keyword}"
        cached = self._get_cached_result(cache_key)
        if cached is not None:
            return cached

        url = f"{NVD_API_BASE}?keywordSearch={quote(keyword)}"
        logger.info("NVD keyword query: %s", keyword)
        result = self._paginate(url)
        if result.state in (STATE_MATCHED, STATE_KNOWN_EMPTY, STATE_PARTIAL):
            self._set_cached_result(cache_key, result)
        return result

    # ── Cache ──

    def _get_cached_result(self, query_key: str) -> LookupResult | None:
        """A cached answer, marked stale when it is past its TTL.

        An expired entry is still returned — with ``STALE`` — because "we asked
        this last month and it answered" is more useful than silence, as long as
        the caller can see it is not current.
        """
        ttl_seconds = self.config.nvd_cache_days * 86400
        try:
            with sqlite3.connect(str(self._cache_db)) as conn:
                row = conn.execute(
                    "SELECT response_json, cached_at FROM nvd_cache WHERE query_key = ?",
                    (query_key,),
                ).fetchone()
        except sqlite3.Error as exc:
            logger.warning("Cache read error: %s", exc)
            return None
        if not row:
            return None
        try:
            payload = json.loads(row[0])
        except json.JSONDecodeError as exc:
            logger.warning("Cache entry is not JSON: %s", exc)
            return None
        result = LookupResult(
            records=list(payload.get("records") or []),
            state=str(payload.get("state", STATE_KNOWN_EMPTY)),
            pages=int(payload.get("pages", 0) or 0),
            total_results=int(payload.get("total_results", 0) or 0),
            reason=str(payload.get("reason", "")),
        )
        age = time.time() - float(row[1])
        if age >= ttl_seconds:
            result.state = STATE_STALE
            result.reason = (
                f"cached {age / 86400:.1f} day(s) ago, beyond the "
                f"{self.config.nvd_cache_days}-day TTL"
            )
        return result

    def _set_cached_result(self, query_key: str, result: LookupResult) -> None:
        """Store one answer with its state and pagination record."""
        try:
            with sqlite3.connect(str(self._cache_db)) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO nvd_cache (query_key, response_json, cached_at) "
                    "VALUES (?, ?, ?)",
                    (
                        query_key,
                        json.dumps(
                            {
                                "records": result.records,
                                "state": result.state,
                                "pages": result.pages,
                                "total_results": result.total_results,
                                "reason": result.reason,
                            }
                        ),
                        time.time(),
                    ),
                )
                conn.commit()
        except sqlite3.Error as exc:
            logger.warning("Cache write error: %s", exc)

    # ── Compatibility shims ──
    #
    # Callers that only want the records keep working; the state is available
    # from the *_result forms and from the cache, and a partial answer is now
    # never presented as a complete one.

    def query_cpe(self, cpe_string: str) -> list[dict]:
        """The records for a CPE query (see :meth:`query_cpe_result` for the state)."""
        return self.query_cpe_result(cpe_string).records

    def query_keyword(self, keyword: str) -> list[dict]:
        """The records for a keyword query (see :meth:`query_keyword_result`)."""
        return self.query_keyword_result(keyword).records[:20]
