"""Intelligence subpackage — NVD client, threat intel, domain scoring, CPE builder."""

from iot_hardware_scanner.intelligence.cpe_builder import CPEBuilder
from iot_hardware_scanner.intelligence.domain_scorer import DomainScorer
from iot_hardware_scanner.intelligence.nvd_client import NVDClient
from iot_hardware_scanner.intelligence.threat_intel import ThreatIntelManager

__all__ = ["CPEBuilder", "DomainScorer", "NVDClient", "ThreatIntelManager"]
