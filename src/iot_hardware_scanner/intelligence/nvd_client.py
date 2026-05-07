"""NVD API Client with local SQLite caching.

SDR §11.1 — NVD API v2 Integration

Stub — full implementation in Phase 5.
"""

from __future__ import annotations

import logging

from iot_hardware_scanner.config import ScannerConfig

logger = logging.getLogger(__name__)


class NVDClient:
    """NVD API v2 client with rate limiting and local caching."""

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config

    def query_cpe(self, cpe_string: str) -> list[dict]:
        """Query NVD for CVEs matching a CPE string."""
        logger.info("NVD query for CPE: %s — stub", cpe_string)
        return []

    def query_keyword(self, keyword: str) -> list[dict]:
        """Query NVD for CVEs matching a keyword."""
        logger.info("NVD keyword query: %s — stub", keyword)
        return []
