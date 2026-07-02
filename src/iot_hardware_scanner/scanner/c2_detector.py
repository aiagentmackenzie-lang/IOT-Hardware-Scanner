"""C2 Detector — Phase 6.

Detects hardcoded C2 domains, suspicious IPs, backdoor services,
and known IoT malware signatures in firmware.

SDR §12 — C2 & Malicious Indicator Detection
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
from pathlib import Path

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.intelligence.domain_scorer import DomainScorer
from iot_hardware_scanner.intelligence.threat_intel import ThreatIntelManager
from iot_hardware_scanner.models import (
    C2Finding,
    FileCategory,
    FilesystemInventory,
)
from iot_hardware_scanner.yara.yara_engine import YaraEngine

logger = logging.getLogger(__name__)

# ── Binary magic bytes ──
_ELF_MAGIC = b"\x7fELF"
_PE_MAGIC = b"MZ"
_MACHO_MAGIC = b"\xfe\xed\xfa\xce"
_MACHO_MAGIC_64 = b"\xfe\xed\xfa\xcf"

# ── Regex patterns ──
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

# ── Known-benign file path prefixes ──
_BENIGN_PATH_PREFIXES = ("docs/", "tests/", "test/", "documentation/")

# ── MITRE ATT&CK mapping for malware families ──
_MITRE_MALWARE_MAP: dict[str, list[str]] = {
    "mirai": ["T0839", "T1133"],
    "gafgyt": ["T0886", "T1133"],
    "hajime": ["T0867", "T1200"],
}
_MITRE_BACKDOOR = ["T1133", "T0866"]

# ── Score constants (must match DomainScorer signals) ──
_SCORE_THREAT_INTEL = 50.0
_SCORE_SUSPICIOUS_TLD = 15.0
_SCORE_IN_FIRMWARE_BINARY = 20.0
_SCORE_DGA = 25.0
_SCORE_BOTNET_NAMING = 30.0
_SCORE_IN_HOSTS_CONFIG = 5.0
_SCORE_BENIGN = -50.0

# ── IP scoring ──
_IP_THREAT_INTEL_SCORE = 50.0
_IP_SUSPICIOUS_RANGE_SCORE = 30.0


class C2Detector:
    """Detect C2 indicators and malicious patterns in firmware.

    Three detection methods:
    1. detect_domains — Extract & score domains for C2 indicators
    2. detect_ips — Extract & score public IPs against threat intel
    3. detect_malware_signatures — YARA-based malware family detection
    """

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config
        self._threat_intel = ThreatIntelManager(config)
        self._domain_scorer = DomainScorer(config, self._threat_intel)
        self._yara_engine: YaraEngine | None = None

    def _init_yara(self) -> YaraEngine:
        """Lazy-init YARA engine."""
        if self._yara_engine is None:
            self._yara_engine = YaraEngine(self.config)
            self._yara_engine.load_rules()
        return self._yara_engine

    # ──────────────────────────────────────────
    # Domain detection
    # ──────────────────────────────────────────

    def detect_domains(self, inventory: FilesystemInventory) -> list[C2Finding]:
        """Extract and score domains from firmware for C2 indicators.

        Scans text-readable files, extracts domains via regex,
        scores each with DomainScorer, cross-references threat intel.
        """
        findings: list[C2Finding] = []
        seen_hashes: set[str] = set()

        for ff in inventory.findings:
            if self._is_benign_path(ff.path):
                continue
            if self._is_binary_file(ff.absolute_path):
                # Still check binary files — domains can be embedded
                # But mark context as in_binary=True
                domains = self._extract_domains_from_file(ff.absolute_path)
                context = {"in_binary": True, "file_path": str(ff.path)}
            else:
                # Check if file is a config/hosts file
                is_hosts = self._is_hosts_or_config(ff.path)
                domains = self._extract_domains_from_file(ff.absolute_path)
                context = {
                    "in_binary": False,
                    "in_hosts": is_hosts,
                    "file_path": str(ff.path),
                }

            for domain in domains:
                # Skip email local parts
                if self._is_email_domain(domain, ff.absolute_path):
                    continue

                raw_hash = hashlib.sha256(domain.encode()).hexdigest()
                if raw_hash in seen_hashes:
                    continue
                seen_hashes.add(raw_hash)

                score = self._domain_scorer.score(domain, context)
                classification = self._domain_scorer.classify(score)

                if classification == "INFORMATIONAL":
                    continue

                # Build score breakdown
                breakdown = self._domain_score_breakdown(domain, context)

                # Get threat intel match description
                intel = self._threat_intel.check_domain(domain)
                threat_desc = None
                if intel:
                    tags = intel.get("tags", [])
                    if tags:
                        threat_desc = f"Threat intel: {', '.join(tags)}"
                    else:
                        threat_desc = "Threat intel match"

                findings.append(
                    C2Finding(
                        severity=classification,
                        indicator_type="domain",
                        value=domain,
                        file_path=ff.path,
                        suspicion_score=score,
                        score_breakdown=breakdown,
                        threat_intel_match=threat_desc,
                        description=(f"Domain scored {score:.0f}: {classification}"),
                    )
                )

        logger.info("C2 domain detection: %d findings", len(findings))
        return findings

    # ──────────────────────────────────────────
    # IP detection
    # ──────────────────────────────────────────

    def detect_ips(self, inventory: FilesystemInventory) -> list[C2Finding]:
        """Extract and score IP addresses for malicious indicators.

        Filters private/local ranges, cross-references threat intel.
        """
        findings: list[C2Finding] = []
        seen_hashes: set[str] = set()

        for ff in inventory.findings:
            if self._is_benign_path(ff.path):
                continue

            ips = self._extract_ips_from_file(ff.absolute_path)
            for ip_str in ips:
                if self._is_private_or_reserved(ip_str):
                    continue

                raw_hash = hashlib.sha256(ip_str.encode()).hexdigest()
                if raw_hash in seen_hashes:
                    continue
                seen_hashes.add(raw_hash)

                score = 0.0
                breakdown: dict[str, float] = {}
                threat_desc = None

                # Check threat intel
                intel = self._threat_intel.check_ip(ip_str)
                if intel:
                    score += _IP_THREAT_INTEL_SCORE
                    breakdown["threat_intel"] = _IP_THREAT_INTEL_SCORE
                    tags = intel.get("tags", [])
                    if tags:
                        threat_desc = f"Threat intel: {', '.join(tags)}"
                    else:
                        threat_desc = "Threat intel match"

                # Check if IP is in suspicious ranges (Tor exits, known bad ranges)
                if self._is_suspicious_ip_range(ip_str):
                    score += _IP_SUSPICIOUS_RANGE_SCORE
                    breakdown["suspicious_range"] = _IP_SUSPICIOUS_RANGE_SCORE

                # Classify
                if score >= self.config.c2_likely_threshold:
                    classification = "LIKELY_C2"
                elif score >= self.config.c2_suspicion_threshold:
                    classification = "SUSPICIOUS"
                else:
                    continue  # Skip informational IPs

                findings.append(
                    C2Finding(
                        severity=classification,
                        indicator_type="ip",
                        value=ip_str,
                        file_path=ff.path,
                        suspicion_score=score,
                        score_breakdown=breakdown,
                        threat_intel_match=threat_desc,
                        description=f"IP scored {score:.0f}: {classification}",
                    )
                )

        logger.info("C2 IP detection: %d findings", len(findings))
        return findings

    # ──────────────────────────────────────────
    # Malware signature detection
    # ──────────────────────────────────────────

    def detect_malware_signatures(self, inventory: FilesystemInventory) -> list[C2Finding]:
        """Run YARA rules for known IoT malware family detection.

        Scans CRITICAL_BINARY and CRITICAL_SERVICE files.
        Filters for YARA matches with category=malware_signature or backdoor_service.
        """
        findings: list[C2Finding] = []
        seen_hashes: set[str] = set()

        scan_categories = [FileCategory.CRITICAL_BINARY, FileCategory.CRITICAL_SERVICE]
        yara_engine = self._init_yara()

        if not yara_engine.is_available:
            logger.warning("YARA engine not available — malware signature detection skipped")
            return findings

        for category in scan_categories:
            files = inventory.categories.get(category, [])
            for ff in files:
                yara_matches = yara_engine.scan_file(ff.absolute_path)
                for ym in yara_matches:
                    meta = ym.meta
                    yara_category = meta.get("category", "")

                    if yara_category not in ("malware_signature", "backdoor_service"):
                        continue

                    # Deduplicate
                    rule_key = f"{ym.rule_name}:{ff.path}"
                    raw_hash = hashlib.sha256(rule_key.encode()).hexdigest()
                    if raw_hash in seen_hashes:
                        continue
                    seen_hashes.add(raw_hash)

                    # Determine indicator type
                    indicator_type = (
                        "backdoor_service"
                        if yara_category == "backdoor_service"
                        else "malware_signature"
                    )

                    # Map MITRE ATT&CK techniques
                    family = meta.get("family", "").lower()
                    mitre = self._get_mitre_techniques(family, indicator_type)

                    # Severity from YARA meta
                    severity_str = meta.get("severity", "HIGH").upper()
                    if severity_str in ("CRITICAL", "HIGH"):
                        classification = "LIKELY_C2"
                    else:
                        classification = "SUSPICIOUS"

                    # Extract matched data for description
                    matched_data = ""
                    if ym.strings:
                        _, _ident, sdata = ym.strings[0]
                        matched_data = sdata.decode(errors="ignore")[:64]

                    description = meta.get("description", ym.rule_name)
                    if matched_data:
                        description += f" (matched: {matched_data!r})"

                    findings.append(
                        C2Finding(
                            severity=classification,
                            indicator_type=indicator_type,
                            value=f"{ym.rule_name}:{ff.path}",
                            file_path=ff.path,
                            suspicion_score=80.0 if classification == "LIKELY_C2" else 50.0,
                            score_breakdown={
                                "yara_match": (80.0 if classification == "LIKELY_C2" else 50.0)
                            },
                            threat_intel_match=None,
                            mitre_attack=mitre,
                            description=description,
                        )
                    )

        logger.info("Malware signature detection: %d findings", len(findings))
        return findings

    # ──────────────────────────────────────────
    # Helper methods
    # ──────────────────────────────────────────

    @staticmethod
    def _is_binary_file(path: Path) -> bool:
        """Check if a file is binary (ELF/PE/Mach-O) using magic bytes."""
        try:
            with path.open("rb") as f:
                magic = f.read(4)
        except (OSError, PermissionError):
            return False

        if magic[:4] == _ELF_MAGIC:
            return True
        if magic[:2] == _PE_MAGIC:
            return True
        return magic[:4] in (_MACHO_MAGIC, _MACHO_MAGIC_64)

    @staticmethod
    def _is_benign_path(path: Path) -> bool:
        """Check if file path is in known-benign location."""
        path_str = str(path)
        for prefix in _BENIGN_PATH_PREFIXES:
            if path_str.startswith(prefix) or f"/{prefix}" in path_str:
                return True
        return False

    @staticmethod
    def _is_hosts_or_config(path: Path) -> bool:
        """Check if a file is /etc/hosts or a config file."""
        name = path.name.lower()
        if name == "hosts":
            return True
        if name.endswith((".conf", ".cfg", ".ini", ".config")):
            return True
        return "etc" in str(path).lower()

    def _extract_domains_from_file(self, path: Path) -> set[str]:
        """Extract domain names from a file, with OOM protection."""
        max_size = self.config.max_scan_file_size_mb * 1024 * 1024
        try:
            if path.stat().st_size > max_size:
                logger.debug(
                    "Skipping large file for domain extraction: %s (%s)",
                    path,
                    _fmt_size(path.stat().st_size),
                )
                return set()
        except OSError:
            return set()
        return _extract_domains_text(path)

    def _is_email_domain(self, domain: str, path: Path) -> bool:
        """Check if a domain appears only as part of an email address."""
        return _is_email_domain_text(domain, path)

    def _extract_ips_from_file(self, path: Path) -> set[str]:
        """Extract IPv4 addresses from a file, with OOM protection."""
        max_size = self.config.max_scan_file_size_mb * 1024 * 1024
        try:
            if path.stat().st_size > max_size:
                logger.debug(
                    "Skipping large file for IP extraction: %s (%s)",
                    path,
                    _fmt_size(path.stat().st_size),
                )
                return set()
        except OSError:
            return set()
        return _extract_ips_text(path)

    @staticmethod
    def _is_private_or_reserved(ip_str: str) -> bool:
        """Check if an IP is in private, loopback, or reserved ranges.

        Filters RFC 1918 private ranges, loopback, link-local,
        multicast, reserved, CGN, and RFC 5737 documentation ranges
        (TEST-NET-1/2/3) since firmware should not connect to these.
        """
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return True

        if ip.is_loopback or ip.is_link_local or ip.is_multicast:
            return True

        # Private ranges (RFC 1918)
        private_networks = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("169.254.0.0/16"),
            ipaddress.ip_network("224.0.0.0/4"),  # Multicast
            ipaddress.ip_network("240.0.0.0/4"),  # Reserved
            ipaddress.ip_network("0.0.0.0/8"),  # Current network
            ipaddress.ip_network("100.64.0.0/10"),  # CGN
            ipaddress.ip_network("192.0.0.0/24"),  # IETF Protocol Assignments
            ipaddress.ip_network("192.0.2.0/24"),  # RFC 5737 TEST-NET-1
            ipaddress.ip_network("198.51.100.0/24"),  # RFC 5737 TEST-NET-2
            ipaddress.ip_network("203.0.113.0/24"),  # RFC 5737 TEST-NET-3
        ]
        return any(ip in network for network in private_networks)

    @staticmethod
    def _is_suspicious_ip_range(ip_str: str) -> bool:
        """Check if IP falls in known suspicious ranges.

        Known suspicious ranges include Tor exit nodes, bulletproof hosting, etc.
        This is a heuristic — the threat intel feed provides precise data.
        """
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        # Known bulletproof hosting / suspicious ranges
        suspicious_networks = [
            ipaddress.ip_network("5.187.35.0/24"),  # Known botnet infra
            ipaddress.ip_network("185.220.101.0/24"),  # Tor exit range
            ipaddress.ip_network("91.234.99.0/24"),  # Known C2 hosting
            ipaddress.ip_network("23.106.122.0/24"),  # Bulletproof hosting
        ]

        return any(ip in network for network in suspicious_networks)

    @staticmethod
    def _get_mitre_techniques(family: str, indicator_type: str) -> str:
        """Get MITRE ATT&CK ICS technique IDs for a malware family."""
        if indicator_type == "backdoor_service":
            return ", ".join(_MITRE_BACKDOOR)
        techniques = _MITRE_MALWARE_MAP.get(family, [])
        if techniques:
            return ", ".join(techniques)
        return ""

    def _domain_score_breakdown(self, domain: str, context: dict) -> dict[str, float]:
        """Build a detailed score breakdown for a domain finding."""
        breakdown: dict[str, float] = {}

        # Threat intel
        intel = self._threat_intel.check_domain(domain)
        if intel:
            breakdown["threat_intel"] = _SCORE_THREAT_INTEL

        # Suspicious TLD
        suspicious_tlds = self._domain_scorer._load_suspicious_tlds()
        tld = self._domain_scorer._extract_tld(domain)
        if tld and (f".{tld}" in suspicious_tlds or tld in suspicious_tlds):
            breakdown["suspicious_tld"] = _SCORE_SUSPICIOUS_TLD

        # DGA
        if self._domain_scorer._is_dga(domain):
            breakdown["dga"] = _SCORE_DGA

        # Botnet naming
        if self._domain_scorer._is_botnet_name(domain):
            breakdown["botnet_naming"] = _SCORE_BOTNET_NAMING

        # In firmware binary
        if context.get("in_binary", False):
            breakdown["in_binary"] = _SCORE_IN_FIRMWARE_BINARY

        # In hosts/config
        if context.get("in_hosts", False):
            breakdown["in_hosts"] = _SCORE_IN_HOSTS_CONFIG

        # Benign
        benign = self._domain_scorer._load_benign_domains()
        if self._domain_scorer._domain_in_benign(domain, benign):
            breakdown["benign"] = _SCORE_BENIGN

        return breakdown


# ── Module-level text extractors (usable without OOM gating) ──
def _extract_domains_text(path: Path) -> set[str]:
    """Extract domain names from file text (no size gating)."""
    domains: set[str] = set()
    try:
        content = path.read_text(errors="ignore")
    except (OSError, PermissionError):
        return domains

    urls = _URL_RE.findall(content)
    url_domains: set[str] = set()
    for url in urls:
        try:
            host_part = url.split("://", 1)[-1].split("/")[0].split(":")[0]
            if _DOMAIN_RE.match(host_part):
                url_domains.add(host_part.lower())
        except (IndexError, ValueError):
            continue

    bare_domains = set(m.lower() for m in _DOMAIN_RE.findall(content))
    all_domains = url_domains | bare_domains
    for d in all_domains:
        parts = d.split(".")
        if all(p.isdigit() for p in parts):
            continue
        if len(parts) >= 2 and len(parts[-1]) < 2:
            continue
        domains.add(d)
    return domains


def _extract_ips_text(path: Path) -> set[str]:
    """Extract IPv4 addresses from file text (no size gating)."""
    ips: set[str] = set()
    try:
        content = path.read_text(errors="ignore")
    except (OSError, PermissionError):
        return ips

    for match in _IP_RE.findall(content):
        parts = match.split(".")
        if all(0 <= int(o) <= 255 for o in parts):
            ips.add(match)
    return ips


def _is_email_domain_text(domain: str, path: Path) -> bool:
    """Check if a domain appears only as part of an email address.

    Quick heuristic: if the file contains the domain with an @ prefix,
    it's likely just an email, not a C2 domain.
    """
    try:
        content = path.read_text(errors="ignore")
    except (OSError, PermissionError):
        return False

    email_count = len(_EMAIL_RE.findall(content))
    if email_count == 0:
        return False

    standalone = content.lower().count(domain)
    in_email = sum(1 for e in _EMAIL_RE.findall(content) if domain in e.lower())
    return standalone == in_email and standalone > 0


# ── Module-level helper ──
def _fmt_size(n: int) -> str:
    """Format byte count as human-readable size."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n //= 1024
    return f"{n:.1f} TB"
