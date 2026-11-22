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
from collections import Counter
from pathlib import Path

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.intelligence.domain_scorer import DomainScorer
from iot_hardware_scanner.intelligence.threat_intel import ThreatIntelManager
from iot_hardware_scanner.models import (
    C2Finding,
    CryptoFinding,
    FileCategory,
    FilesystemInventory,
)
from iot_hardware_scanner.scanner.analysis_cache import AnalysisCache, sha256_file
from iot_hardware_scanner.scanner.bounded_reader import open_bounded
from iot_hardware_scanner.yara.yara_engine import YaraEngine, YaraMatch

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

#: Identity of the text-fact extractor. Bump when the regexes or the
#: derivation change: a cache entry made by an older extractor is then ignored.
TEXT_FACTS_VERSION = "2"
#: The bounded text budget the extractor uses; part of the cache key.
TEXT_FACTS_MAX_BYTES = 8 * 1024 * 1024

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

    def __init__(
        self,
        config: ScannerConfig,
        rule_engine: YaraEngine | None = None,
        *,
        cache: AnalysisCache | None = None,
    ) -> None:
        self.config = config
        #: Optional content-addressed cache of per-file text facts (slice 5C).
        self._cache = cache
        self._threat_intel = ThreatIntelManager(config)
        self._domain_scorer = DomainScorer(config, self._threat_intel)
        #: The run's single compiled rule set. One compile per run: the caller
        #: builds it and every detector uses it.
        self._yara_engine = rule_engine
        #: Tokens rejected by the reachability/semantics rules, with the reason.
        #: Reported as stage coverage so a suppression is never invisible.
        self.suppressed: dict[str, dict[str, str]] = {}
        #: Cryptographic algorithms observed in the artifact (destination crypto).
        self.crypto_findings: list[CryptoFinding] = []

    def _init_yara(self) -> YaraEngine:
        """The shared rule set, compiled once by the orchestrator."""
        if self._yara_engine is None:
            self._yara_engine = YaraEngine(self.config)
            self._yara_engine.load_rules()
        return self._yara_engine

    # ──────────────────────────────────────────
    # Domain detection
    # ──────────────────────────────────────────

    def detect_domains(
        self,
        inventory: FilesystemInventory,
        known_names: set[str] | None = None,
    ) -> list[C2Finding]:
        """Extract domains from the inventory and derive one decision per indicator.

        Occurrences are collected **first**, then each occurrence is scored in
        its own context, and a single documented aggregate is applied. The
        previous implementation deduplicated by domain before scoring, so the
        first file seen decided the verdict and reversing enumeration order
        flipped a domain between SUSPICIOUS and LIKELY_C2.

        A token is only a candidate when it is plausible as a hostname (see
        :meth:`DomainScorer.plausible_domain`): a dot in a string table is not a
        domain, and a dependency name is not infrastructure. Rejected tokens are
        counted by reason and reported as coverage, never silently dropped.

        Aggregate rule: an indicator takes the **highest** score of any of its
        occurrences. One occurrence inside a binary is not made safer by the
        same string also appearing in a config file. The reported location is
        the highest-scoring occurrence, ties broken by path, so the finding is
        byte-for-byte stable for a given inventory.
        """
        occurrences: dict[str, list[tuple[Path, dict]]] = {}
        names = known_names or self._image_names(inventory)

        for ff in sorted(inventory.findings, key=lambda f: str(f.path)):
            if self._is_benign_path(ff.path):
                continue
            facts = self._file_text_facts(ff.absolute_path)
            if facts is None:
                continue
            email_only = set(facts.get("email_only_domains", []))
            if self._is_binary_file(ff.absolute_path):
                context: dict = {"in_binary": True, "in_hosts": False}
            else:
                context = {
                    "in_binary": False,
                    "in_hosts": self._is_hosts_or_config(ff.path),
                }
            for domain in sorted(facts.get("domains", [])):
                if domain in email_only:
                    continue
                plausible, reason = self._domain_scorer.plausible_domain(domain, names)
                if not plausible:
                    self._record_suppressed(domain, reason, ff.path)
                    continue
                occurrences.setdefault(domain.lower(), []).append((ff.path, context))

        findings = self._aggregate_domains(occurrences)
        logger.info(
            "C2 domain detection: %d indicators from %d occurrence(s), %d token(s) rejected",
            len(findings),
            sum(len(v) for v in occurrences.values()),
            len(self.suppressed),
        )
        return findings

    @staticmethod
    def _image_names(inventory: FilesystemInventory) -> set[str]:
        """File basenames in the image: these are names, not hostnames."""
        names: set[str] = set()
        for finding in inventory.findings:
            names.add(finding.path.name.lower())
        return names

    def _record_suppressed(self, token: str, reason: str, path: Path) -> None:
        entry = self.suppressed.setdefault(token.lower(), {"reason": reason, "example": str(path)})
        entry["example"] = min(entry["example"], str(path))

    @property
    def suppression_summary(self) -> list[str]:
        """One line per rejected token class, for stage coverage."""
        if not self.suppressed:
            return []
        by_reason: dict[str, list[str]] = {}
        for token, entry in self.suppressed.items():
            by_reason.setdefault(entry["reason"], []).append(token)
        return [
            f"{len(tokens)} domain-shaped token(s) rejected for indicator use: "
            f"{reason} (e.g. {', '.join(sorted(tokens)[:3])})"
            for reason, tokens in sorted(by_reason.items())
        ]

    def _aggregate_domains(
        self, occurrences: dict[str, list[tuple[Path, dict]]]
    ) -> list[C2Finding]:
        """Apply the documented aggregate once, deterministically."""
        findings: list[C2Finding] = []

        for domain in sorted(occurrences):
            scored = [
                (self._domain_scorer.score(domain, context), path, context)
                for path, context in occurrences[domain]
            ]
            best_score = max(score for score, _path, _ctx in scored)
            classification = self._domain_scorer.classify(best_score)
            if classification == "INFORMATIONAL":
                continue

            _score, best_path, best_context = sorted(
                scored, key=lambda item: (-item[0], str(item[1]))
            )[0]
            intel = self._threat_intel.check_domain(domain)
            threat_desc = None
            if intel:
                tags = intel.get("tags", [])
                threat_desc = f"Threat intel: {', '.join(tags)}" if tags else "Threat intel match"

            locations = sorted({str(path) for path, _ctx in occurrences[domain]})
            findings.append(
                C2Finding(
                    severity=classification,
                    indicator_type="domain",
                    value=domain,
                    file_path=best_path,
                    suspicion_score=best_score,
                    score_breakdown=self._domain_score_breakdown(domain, best_context),
                    threat_intel_match=threat_desc,
                    description=(
                        f"Domain scored {best_score:.0f}: {classification} "
                        f"across {len(locations)} occurrence(s)"
                    ),
                    occurrences=locations,
                )
            )

        return findings

    # ──────────────────────────────────────────
    # IP detection
    # ──────────────────────────────────────────

    def detect_ips(self, inventory: FilesystemInventory) -> list[C2Finding]:
        """Extract public IP addresses and decide once per indicator."""
        occurrences: dict[str, list[Path]] = {}

        for ff in sorted(inventory.findings, key=lambda f: str(f.path)):
            if self._is_benign_path(ff.path):
                continue
            facts = self._file_text_facts(ff.absolute_path)
            if facts is None:
                continue
            for ip_str in sorted(facts.get("ips", [])):
                if self._is_private_or_reserved(ip_str):
                    continue
                occurrences.setdefault(ip_str, []).append(ff.path)

        findings: list[C2Finding] = []
        for ip_str in sorted(occurrences):
            score = 0.0
            breakdown: dict[str, float] = {}
            threat_desc = None

            intel = self._threat_intel.check_ip(ip_str)
            if intel:
                score += _IP_THREAT_INTEL_SCORE
                breakdown["threat_intel"] = _IP_THREAT_INTEL_SCORE
                tags = intel.get("tags", [])
                threat_desc = f"Threat intel: {', '.join(tags)}" if tags else "Threat intel match"

            if self._is_suspicious_ip_range(ip_str):
                score += _IP_SUSPICIOUS_RANGE_SCORE
                breakdown["suspicious_range"] = _IP_SUSPICIOUS_RANGE_SCORE

            if score >= self.config.c2_likely_threshold:
                classification = "LIKELY_C2"
            elif score >= self.config.c2_suspicion_threshold:
                classification = "SUSPICIOUS"
            else:
                continue

            locations = sorted({str(p) for p in occurrences[ip_str]})
            findings.append(
                C2Finding(
                    severity=classification,
                    indicator_type="ip",
                    value=ip_str,
                    file_path=sorted(occurrences[ip_str], key=str)[0],
                    suspicion_score=score,
                    score_breakdown=breakdown,
                    threat_intel_match=threat_desc,
                    description=(
                        f"IP scored {score:.0f}: {classification} "
                        f"across {len(locations)} occurrence(s)"
                    ),
                    occurrences=locations,
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

        # A backdoor *directive* lives in a config or init file; a malware
        # *implementation* lives in a binary. Both are scanned, and the rule
        # destinations decide which is which.
        scan_categories = [
            FileCategory.CRITICAL_BINARY,
            FileCategory.CRITICAL_SERVICE,
            FileCategory.CRITICAL_CONFIG,
        ]
        yara_engine = self._init_yara()

        if not yara_engine.is_available:
            logger.warning("YARA engine not available — malware signature detection skipped")
            return findings

        for category in scan_categories:
            files = inventory.categories.get(category, [])
            for ff in files:
                yara_matches = yara_engine.scan_file(ff.absolute_path)
                for ym in yara_matches:
                    # Route by the destination the rule's own category earned.
                    # A credential or crypto match belongs to its own detector.
                    if ym.destination not in ("indicator", "service"):
                        continue

                    # Deduplicate
                    rule_key = f"{ym.rule_name}:{ff.path}"
                    raw_hash = hashlib.sha256(rule_key.encode()).hexdigest()
                    if raw_hash in seen_hashes:
                        continue
                    seen_hashes.add(raw_hash)

                    findings.append(self._yara_indicator(ym, ff.path))

        logger.info("Malware signature detection: %d findings", len(findings))
        return findings

    def _yara_indicator(self, ym: YaraMatch, path: Path) -> C2Finding:
        """One YARA match as an indicator, with its rule identity and offsets."""
        meta = ym.meta
        indicator_type = "backdoor_service" if ym.destination == "service" else "malware_signature"

        # A configured backdoor entry is not a listening socket. The finding
        # keeps the configuration as evidence and the description says so.
        if indicator_type == "backdoor_service":
            classification = "SUSPICIOUS"
            score = 50.0
        else:
            classification = "LIKELY_C2" if ym.severity in ("CRITICAL", "HIGH") else "SUSPICIOUS"
            score = 80.0 if classification == "LIKELY_C2" else 50.0

        matched_data = ""
        if ym.strings:
            _offset, _ident, sdata = ym.strings[0]
            matched_data = sdata.decode(errors="ignore")[:64]

        description = str(meta.get("description", ym.rule_name))
        if matched_data:
            description += f" (matched: {matched_data!r})"
        if indicator_type == "backdoor_service":
            description += (
                " — a startup directive or implementation string configures this "
                "service; whether it listens requires device evidence."
            )

        return C2Finding(
            severity=classification,
            indicator_type=indicator_type,
            value=f"{ym.rule_name}:{path}",
            file_path=path,
            suspicion_score=score,
            score_breakdown={"yara_match": score},
            threat_intel_match=None,
            mitre_attack=self._get_mitre_techniques(
                str(meta.get("family", "")).lower(), indicator_type
            ),
            description=description,
            rule_id=f"c2.yara.{ym.rule_name}",
            occurrences=[f"{path}@{offset}" for offset in ym.offsets] or [str(path)],
        )

    def detect_crypto(self, inventory: FilesystemInventory) -> list[CryptoFinding]:
        """Observe cryptographic algorithms in the image's binaries.

        This is *algorithm evidence*, deliberately separate from binary
        hardening (NX/PIE/canary) and from account hash algorithms. A match
        means the implementation is present; it does not mean the device uses
        it, and the crypto check says so.
        """
        findings: list[CryptoFinding] = []
        engine = self._init_yara()
        if not engine.is_available:
            return findings

        seen: set[tuple[str, str]] = set()
        for finding in sorted(inventory.findings, key=lambda f: str(f.path)):
            if finding.format != "elf":
                continue
            for match in engine.scan_file(finding.absolute_path):
                if match.destination != "crypto":
                    continue
                algorithm = str(match.meta.get("algorithm", "unknown"))
                key = (match.rule_name, str(finding.path))
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    CryptoFinding(
                        rule_id=f"crypto.yara.{match.rule_name}",
                        algorithm=algorithm,
                        strength=str(match.meta.get("strength", "unknown")),
                        file_path=finding.path,
                        offset=match.offsets[0] if match.offsets else None,
                        matched_pattern=match.rule_name,
                        namespace=match.namespace,
                        ruleset_digest=match.ruleset_digest,
                        description=str(match.meta.get("description", match.rule_name)),
                        evidence=(
                            f"{finding.path}@{match.offsets[0]}"
                            if match.offsets
                            else str(finding.path)
                        ),
                    )
                )

        self.crypto_findings = findings
        logger.info("Crypto algorithm evidence: %d finding(s)", len(findings))
        return findings

    def detect_artifact(self, artifact: Path) -> list[C2Finding]:
        """Sweep a whole artifact in bounded windows that keep their offsets.

        No window is joined to the next: an indicator is recorded with the offset
        of the first window it appeared in, and the scan stops at the configured
        byte budget. When the artifact is larger than the budget the truncation
        is stated on every finding rather than silently analysed in full.
        """
        findings: list[C2Finding] = []
        if artifact.is_dir() or not artifact.is_file():
            return findings

        limit = self.config.max_scan_file_size_mb * 1024 * 1024
        window_size = self.config.bounded_window_kb * 1024
        reader = open_bounded(artifact)
        sweep = reader.scan_windows(window_size, budget=limit)

        domains: dict[str, int] = {}
        addresses: dict[str, int] = {}
        yara_matches: list[YaraMatch] = []
        yara_engine = self._init_yara()

        for window in sweep.windows:
            text = window.data.decode("latin-1", errors="ignore")
            for url in _URL_RE.findall(text):
                host = url.split("://", 1)[-1].split("/")[0].split(":")[0]
                if _DOMAIN_RE.match(host):
                    domains.setdefault(host.lower(), window.offset)
            for domain in _DOMAIN_RE.findall(text):
                if not all(part.isdigit() for part in domain.split(".")):
                    domains.setdefault(domain.lower(), window.offset)
            for address in _IP_RE.findall(text):
                if all(0 <= int(octet) <= 255 for octet in address.split(".")):
                    addresses.setdefault(address, window.offset)
            if yara_engine.is_available:
                yara_matches.extend(yara_engine.scan_data(window.data, module_name=artifact.name))

        # The same reachability rule as the inventory path: a token in an opaque
        # artifact is only an indicator when it is plausible as a hostname.
        for domain in sorted(domains):
            plausible, reason = self._domain_scorer.plausible_domain(domain)
            if not plausible:
                self._record_suppressed(domain, reason, Path(artifact.name))
                del domains[domain]

        context = {"in_binary": True, "in_hosts": False}
        occurrences: dict[str, list[tuple[Path, dict]]] = {
            domain: [(Path(artifact.name), context)] for domain in sorted(domains)
        }
        findings.extend(self._aggregate_domains(occurrences))
        for finding in findings:
            if finding.indicator_type == "domain":
                finding.description += f" (first window at offset {domains[finding.value]:,})"

        for ip_str in sorted(addresses):
            if self._is_private_or_reserved(ip_str):
                continue
            score = 0.0
            breakdown: dict[str, float] = {}
            intel = self._threat_intel.check_ip(ip_str)
            if intel:
                score += _IP_THREAT_INTEL_SCORE
                breakdown["threat_intel"] = _IP_THREAT_INTEL_SCORE
            if self._is_suspicious_ip_range(ip_str):
                score += _IP_SUSPICIOUS_RANGE_SCORE
                breakdown["suspicious_range"] = _IP_SUSPICIOUS_RANGE_SCORE
            if score >= self.config.c2_likely_threshold:
                classification = "LIKELY_C2"
            elif score >= self.config.c2_suspicion_threshold:
                classification = "SUSPICIOUS"
            else:
                continue
            findings.append(
                C2Finding(
                    severity=classification,
                    indicator_type="ip",
                    value=ip_str,
                    file_path=Path(artifact.name),
                    suspicion_score=score,
                    score_breakdown=breakdown,
                    description=(
                        f"IP scored {score:.0f}: {classification} in artifact "
                        f"(first window at offset {addresses[ip_str]:,})"
                    ),
                )
            )

        for match in yara_matches:
            # Only indicator and service destinations belong here; a credential
            # or crypto match is another detector's business.
            if match.destination not in ("indicator", "service"):
                continue
            findings.append(self._yara_indicator(match, Path(artifact.name)))

        if sweep.sampled:
            for finding in findings:
                finding.description += (
                    f" (artifact sampled: {sweep.bytes_read:,} of {reader.size:,} bytes read; "
                    f"{sweep.omissions[0] if sweep.omissions else 'regions unread'})"
                )
            logger.warning(
                "Indicator sweep read %s of %s",
                _fmt_size(sweep.bytes_read),
                _fmt_size(reader.size),
            )

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
        facts = self._file_text_facts(path)
        if facts is None:
            return set()
        return set(facts.get("domains", []))

    def _file_text_facts(self, path: Path) -> dict[str, list[str]] | None:
        """The extractor's facts for one file, through the cache when enabled.

        A fact set is a pure function of the file's bytes and the extractor
        version: the domains, the public-looking IPv4 strings, and the subset of
        domains that occur only inside an email address. Scoring, feeds and
        suffix lists are applied afterwards by the detector, so a feed update
        is never hidden behind a cached verdict.
        """
        max_size = self.config.max_scan_file_size_mb * 1024 * 1024
        try:
            if path.stat().st_size > max_size:
                logger.debug(
                    "Skipping large file for text extraction: %s (%s)",
                    path,
                    _fmt_size(path.stat().st_size),
                )
                return None
        except OSError:
            return None

        cache = getattr(self, "_cache", None)
        if cache is None:
            return _text_facts_from_content(_read_text_bounded(path))

        digest = sha256_file(path)
        if digest is None:
            return None
        dependencies = {
            "extractor_version": TEXT_FACTS_VERSION,
            "max_bytes": TEXT_FACTS_MAX_BYTES,
        }
        cached = cache.get("text-facts", digest, dependencies)
        if isinstance(cached, dict):
            return cached
        facts = _text_facts_from_content(_read_text_bounded(path))
        cache.put("text-facts", digest, dependencies, facts)
        return facts

    def _is_email_domain(self, domain: str, path: Path) -> bool:
        """Check if a domain appears only as part of an email address."""
        return _is_email_domain_text(domain, path)

    def _extract_ips_from_file(self, path: Path) -> set[str]:
        """Extract IPv4 addresses from a file, with OOM protection."""
        facts = self._file_text_facts(path)
        if facts is None:
            return set()
        return set(facts.get("ips", []))

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
def _read_text_bounded(path: Path, budget: int = 8 * 1024 * 1024) -> str:
    """Read a text file through the bounded reader, or return ``""``."""
    try:
        reader = open_bounded(path)
        text, _truncated = reader.read_text_bounded(budget, encoding="latin-1")
        return text
    except (OSError, ValueError):
        return ""


def _text_facts_from_content(content: str) -> dict[str, list[str]]:
    """Derive the deterministic per-file text facts from its decoded content."""
    domains: set[str] = set()
    ips: set[str] = set()
    email_only: set[str] = set()
    if not content:
        return {"domains": [], "ips": [], "email_only_domains": []}

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
    for domain in url_domains | bare_domains:
        parts = domain.split(".")
        if all(p.isdigit() for p in parts):
            continue
        if len(parts) >= 2 and len(parts[-1]) < 2:
            continue
        domains.add(domain)

    for match in _IP_RE.findall(content):
        parts = match.split(".")
        if all(0 <= int(octet) <= 255 for octet in parts):
            ips.add(match)

    emails = _EMAIL_RE.findall(content)
    if emails:
        # One pass over the content, then one subtraction. The previous version
        # ran ``content.lower().count(domain)`` once per unique domain, so its
        # cost was ``domains x bytes`` with both factors under the attacker's
        # control (slice 2.6): 1,028 domains over 4 MiB was 4.3 GB of scanning
        # for one file. Counting domain *tokens* also stops a domain that only
        # appears inside a longer domain (``foo.com`` in ``foo.com.br``) from
        # being counted as a standalone occurrence.
        token_totals = Counter(match.lower() for match in _DOMAIN_RE.findall(content))
        email_totals = Counter(email.rsplit("@", 1)[-1].lower() for email in emails if "@" in email)
        for domain in domains:
            total = token_totals.get(domain, 0)
            if total and total == email_totals.get(domain, 0):
                email_only.add(domain)

    return {
        "domains": sorted(domains),
        "ips": sorted(ips),
        "email_only_domains": sorted(email_only),
    }


def _extract_domains_text(path: Path) -> set[str]:
    """Extract domain names from file text, bounded."""
    return set(_text_facts_from_content(_read_text_bounded(path))["domains"])


def _extract_ips_text(path: Path) -> set[str]:
    """Extract IPv4 addresses from file text, bounded."""
    return set(_text_facts_from_content(_read_text_bounded(path))["ips"])


def _is_email_domain_text(domain: str, path: Path) -> bool:
    """Check if a domain appears only as part of an email address.

    Uses the same pass as the per-file facts rather than re-scanning the content
    once per domain; the two answers cannot disagree.
    """
    content = _read_text_bounded(path)
    if not content:
        return False
    if not _EMAIL_RE.search(content):
        return False
    return domain.lower() in set(_text_facts_from_content(content)["email_only_domains"])


# ── Module-level helper ──
def _fmt_size(n: int) -> str:
    """Format byte count as human-readable size."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n //= 1024
    return f"{n:.1f} TB"
