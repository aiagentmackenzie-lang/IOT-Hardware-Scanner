"""CVE Scanner — Phase 5.

Looks up known CVEs for detected software components via NVD API.
Cross-references against CISA KEV catalog. Escalates KEV entries to CRITICAL.

SDR §11 — CVE Matching & Vulnerability Correlation
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.intelligence.cpe_builder import CPEBuilder
from iot_hardware_scanner.intelligence.nvd_client import NVDClient
from iot_hardware_scanner.models import CVEFinding, Severity, SoftwareComponent

logger = logging.getLogger(__name__)

# KEV catalog URL (CISA Known Exploited Vulnerabilities)
KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"

# Local KEV data path
_KEV_DATA_PATH = Path(__file__).parent.parent.parent.parent / "data" / "kev_catalog.json"


class CVEScanner:
    """Look up known CVEs for software components via NVD API.

    Query strategy (per SDR §11):
    1. Try CPE-based query (most precise)
    2. Fallback to keyword-based query
    3. Results cached in SQLite (7-day TTL)
    4. Cross-reference against CISA KEV catalog
    5. KEV entries escalated to CRITICAL severity
    """

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config
        self._nvd = NVDClient(config)
        self._cpe_builder = CPEBuilder()
        self._kev_ids: set[str] | None = None

    def _load_kev_catalog(self) -> set[str]:
        """Load CISA KEV catalog for cross-referencing.

        Tries local data file first, then downloads from CISA.
        """
        if self._kev_ids is not None:
            return self._kev_ids

        kev_ids: set[str] = set()

        # Try local JSON file
        if _KEV_DATA_PATH.exists():
            try:
                data = json.loads(_KEV_DATA_PATH.read_text(encoding="utf-8"))
                for entry in data.get("vulnerabilities", []):
                    cve_id = entry.get("cveID", "")
                    if cve_id:
                        kev_ids.add(cve_id)
                logger.info("KEV catalog loaded: %d entries from local file", len(kev_ids))
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Cannot load local KEV catalog: %s", exc)

        self._kev_ids = kev_ids
        return kev_ids

    def scan_component(self, component: SoftwareComponent) -> list[CVEFinding]:
        """Look up known CVEs for a specific software component.

        Strategy:
        1. Try CPE-based NVD query
        2. If no results, try keyword-based query
        3. Cross-reference KEV catalog
        4. Map CVSS scores to severity levels
        """
        findings: list[CVEFinding] = []

        # Strategy 1: CPE-based query
        cpe: str | None = component.cpe_string
        if not cpe:
            # Try to build CPE from product name
            cpe = self._cpe_builder.build(component.product, component.version)

        raw_results: list[dict] = []
        if cpe:
            raw_results = self._nvd.query_cpe(cpe)

        # Strategy 2: Keyword fallback
        if not raw_results:
            keyword = f"{component.product} {component.version}"
            raw_results = self._nvd.query_keyword(keyword)

        # Convert raw results to CVEFinding
        kev_ids = self._load_kev_catalog()
        for raw in raw_results:
            cve_id: str = str(raw.get("cve_id", ""))
            if not cve_id:
                continue

            cvss_score: float | None = raw.get("cvss_v3_score")  # type: ignore[assignment]
            severity = self._cvss_to_severity(cvss_score)

            # KEV check
            is_in_kev = cve_id in kev_ids
            if is_in_kev:
                severity = Severity.CRITICAL

            findings.append(
                CVEFinding(
                    cve_id=cve_id,
                    severity=severity,
                    cvss_v3_score=cvss_score,
                    cvss_v3_vector=str(raw.get("cvss_v3_vector", "")),
                    description=str(raw.get("description", "")),
                    affected_product=component.product,
                    affected_version=component.version,
                    published_date=str(raw.get("published_date", "")),
                    references=list(raw.get("references", [])),  # type: ignore[arg-type]
                    is_in_kev=is_in_kev,
                    exploit_available=is_in_kev,  # KEV implies known exploitation
                )
            )

        logger.info(
            "CVE scan: %s %s → %d findings",
            component.product,
            component.version,
            len(findings),
        )
        return findings

    def scan_all(self, components: list[SoftwareComponent]) -> list[CVEFinding]:
        """Scan all detected software components for known CVEs."""
        findings: list[CVEFinding] = []
        seen_ids: set[str] = set()

        for component in components:
            component_findings = self.scan_component(component)
            for f in component_findings:
                # Deduplicate by CVE ID
                if f.cve_id in seen_ids:
                    continue
                seen_ids.add(f.cve_id)
                findings.append(f)

        logger.info(
            "CVE scan complete: %d unique findings across %d components",
            len(findings),
            len(components),
        )
        return findings

    @staticmethod
    def _cvss_to_severity(score: float | None) -> Severity:
        """Map CVSS v3 score to Severity enum.

        NVD CVSS v3 severity ranges:
        - 0.0: NONE (INFO)
        - 0.1-3.9: LOW
        - 4.0-6.9: MEDIUM
        - 7.0-8.9: HIGH
        - 9.0-10.0: CRITICAL
        """
        if score is None:
            return Severity.MEDIUM  # Unknown score = assume medium
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        if score > 0.0:
            return Severity.LOW
        return Severity.INFO
