"""CVE Scanner — Phase 5.

Looks up known CVEs for detected software components via NVD API.
Cross-references against CISA KEV catalog. Escalates KEV entries to CRITICAL.

SDR §11 — CVE Matching & Vulnerability Correlation
"""

from __future__ import annotations

import json
import logging

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.intelligence.cpe_builder import CPEBuilder
from iot_hardware_scanner.intelligence.nvd_client import NVDClient
from iot_hardware_scanner.models import CVEFinding, Severity, SoftwareComponent

logger = logging.getLogger(__name__)

# KEV catalog URL (CISA Known Exploited Vulnerabilities)
KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"


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
        #: Keyword search results that were not promoted because the advisory
        #: did not name the shipped product. Counted, never silently dropped.
        self.last_keyword_candidates: int = 0

    def _load_kev_catalog(self) -> set[str]:
        """Load CISA KEV catalog for cross-referencing.

        Tries local data file first, then downloads from CISA.
        """
        if self._kev_ids is not None:
            return self._kev_ids

        kev_ids: set[str] = set()

        # Bundled catalog. It is a sample; the report says so.
        try:
            from iot_hardware_scanner import resources

            kev_path = resources.data_file("kev_catalog.json")
            try:
                data = json.loads(kev_path.read_text(encoding="utf-8"))
                for entry in data.get("vulnerabilities", []):
                    cve_id = entry.get("cveID", "")
                    if cve_id:
                        kev_ids.add(cve_id)
                logger.info("KEV catalog loaded: %d entries from bundled sample", len(kev_ids))
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Cannot load bundled KEV catalog: %s", exc)
        except Exception as exc:  # bundled resource missing entirely
            logger.warning("KEV catalog unavailable: %s", exc)

        self._kev_ids = kev_ids
        return kev_ids

    def scan_component(self, component: SoftwareComponent) -> list[CVEFinding]:
        """Look up known CVEs for one component, keeping applicability explicit.

        1. A CPE query returns advisories the provider matched to this CPE.
        2. A keyword query is a *candidate*: its results are promoted only when
           the advisory's own CPE match names the same product, and the
           candidate count is recorded either way.
        3. KEV membership is recorded as its own fact; it does not rewrite the
           provider's severity, because "known exploited somewhere" and "this
           image is affected here" are different statements.
        """
        findings: list[CVEFinding] = []
        self.last_keyword_candidates = 0

        cpe: str | None = component.cpe_string
        if not cpe:
            cpe = self._cpe_builder.build(component.product, component.version)

        raw_results: list[dict] = []
        applicability = "UNKNOWN"
        if cpe:
            raw_results = self._nvd.query_cpe(cpe)
            applicability = "cpe-exact"

        if not raw_results:
            keyword = f"{component.product} {component.version}"
            candidates = self._nvd.query_keyword(keyword)
            raw_results = [entry for entry in candidates if self._names_product(entry, component)]
            self.last_keyword_candidates = len(candidates)
            applicability = "keyword-validated"

        kev_ids = self._load_kev_catalog()
        for raw in raw_results:
            cve_id = str(raw.get("cve_id", ""))
            if not cve_id:
                continue

            score = raw.get("cvss_v3_score")
            provider_score = float(score) if score is not None else None
            is_in_kev = cve_id in kev_ids
            findings.append(
                CVEFinding(
                    cve_id=cve_id,
                    severity=self._cvss_to_severity(provider_score),
                    cvss_v3_score=provider_score,
                    cvss_v3_vector=str(raw.get("cvss_v3_vector") or ""),
                    description=str(raw.get("description", "")),
                    affected_product=component.product,
                    affected_version=component.version,
                    published_date=str(raw.get("published_date", "")),
                    references=[str(url) for url in raw.get("references", [])],
                    is_in_kev=is_in_kev,
                    exploit_available=bool(raw.get("exploit_available_public", False)),
                    applicability=applicability,
                    provider_score=provider_score,
                    provider=str(raw.get("provider", "nvd")),
                    last_modified=str(raw.get("last_modified", "")),
                    occurrences=[f"{component.product} {component.version}"],
                )
            )

        logger.info(
            "CVE scan: %s %s → %d finding(s) (%s); %d keyword candidate(s)",
            component.product,
            component.version,
            len(findings),
            applicability,
            self.last_keyword_candidates,
        )
        return findings

    @staticmethod
    def _names_product(entry: dict, component: SoftwareComponent) -> bool:
        """Whether a keyword candidate's own CPE data names this product."""
        for match in entry.get("matches") or []:
            cpe = str(match.get("cpe", "")).lower()
            parts = cpe.split(":")
            if component.product.lower() in parts or component.vendor.lower() in parts:
                return True
        return False

    def scan_all(self, components: list[SoftwareComponent]) -> list[CVEFinding]:
        """Scan every component, keeping one finding per CVE with every location."""
        findings: dict[str, CVEFinding] = {}
        order: list[str] = []
        for component in components:
            for finding in self.scan_component(component):
                existing = findings.get(finding.cve_id)
                if existing is None:
                    findings[finding.cve_id] = finding
                    order.append(finding.cve_id)
                    continue
                for location in finding.occurrences:
                    if location not in existing.occurrences:
                        existing.occurrences.append(location)
                existing.is_in_kev = existing.is_in_kev or finding.is_in_kev
                existing.exploit_available = existing.exploit_available or finding.exploit_available
                if finding.severity is Severity.CRITICAL:
                    existing.severity = Severity.CRITICAL

        logger.info(
            "CVE scan complete: %d unique finding(s) across %d component(s)",
            len(findings),
            len(components),
        )
        return [findings[cve_id] for cve_id in order]

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
