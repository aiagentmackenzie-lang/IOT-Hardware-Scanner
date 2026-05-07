"""CVE Scanner — Phase 5.

Looks up known CVEs for detected software components via NVD API.

SDR §11 — CVE Matching & Vulnerability Correlation

Stub implementation — full build in Phase 5 delivery.
"""

from __future__ import annotations

import logging

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import CVEFinding, SoftwareComponent

logger = logging.getLogger(__name__)


class CVEScanner:
    """Look up known CVEs for software components via NVD API."""

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config

    def scan_component(self, component: SoftwareComponent) -> list[CVEFinding]:
        """Look up known CVEs for a specific software component.

        Stub — will integrate NVD API v2 with local SQLite cache.
        """
        logger.info(
            "CVE scan for %s %s (CPE: %s)",
            component.product,
            component.version,
            component.cpe_string,
        )
        return []

    def scan_all(self, components: list[SoftwareComponent]) -> list[CVEFinding]:
        """Scan all detected software components for known CVEs."""
        findings: list[CVEFinding] = []
        for component in components:
            findings.extend(self.scan_component(component))
        logger.info(
            "CVE scan complete: %d findings across %d components", len(findings), len(components)
        )
        return findings
