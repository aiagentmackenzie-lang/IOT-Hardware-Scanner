"""Domain Suspicion Scorer.

SDR §12.1 — Domain Heuristic Scoring

Scores domains for C2 suspicion based on heuristic signals:
- Threat intel feed match
- Suspicious TLD
- DGA (domain generation algorithm) detection
- Botnet naming patterns
- Firmware binary context
- Benign domain whitelisting
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.intelligence.threat_intel import ThreatIntelManager

logger = logging.getLogger(__name__)

# ── Data file paths ──
_DATA_DIR = Path(__file__).parent.parent.parent.parent / "data"

# ── Scoring signals (SDR §12.1) ──
_SCORE_THREAT_INTEL = 50.0
_SCORE_MALICIOUS_IP = 40.0
_SCORE_SUSPICIOUS_TLD = 15.0
_SCORE_IN_FIRMWARE_BINARY = 20.0
_SCORE_DGA = 25.0
_SCORE_BOTNET_NAMING = 30.0
_SCORE_IN_HOSTS_CONFIG = 5.0
_SCORE_BENIGN = -50.0
_SCORE_SSL_ORG = -20.0  # Stub: not implemented, always 0

# ── DGA detection constants ──
_DGA_MIN_SUBDOMAIN_LEN = 8
_DGA_MAX_VOWEL_RATIO = 0.3

# ── Botnet naming patterns ──
_BOTNET_PATTERNS: list[re.Pattern] = [
    re.compile(r"\.mirai\b", re.IGNORECASE),
    re.compile(r"\.mozi\b", re.IGNORECASE),
    re.compile(r"\.hajime\b", re.IGNORECASE),
    re.compile(r"\.gafgyt\b", re.IGNORECASE),
    re.compile(r"\.bashlite\b", re.IGNORECASE),
    re.compile(r"\.vpnfilter\b", re.IGNORECASE),
    re.compile(r"\.jackskid\b", re.IGNORECASE),
    re.compile(r"\.kimwolf\b", re.IGNORECASE),
    re.compile(r"\.aisuru\b", re.IGNORECASE),
    re.compile(r"c2[-_]", re.IGNORECASE),
    re.compile(r"bot[-_]net", re.IGNORECASE),
    re.compile(r"command[-_]and[-_]control", re.IGNORECASE),
]

# ── DGA hex/random patterns ──
_HEX_SUBDOMAIN = re.compile(r"^[0-9a-f]{" + str(_DGA_MIN_SUBDOMAIN_LEN) + r",}$")
_CONSONANT_CLUSTER = re.compile(r"[bcdfghjklmnpqrstvwxz]{4,}", re.IGNORECASE)


class DomainScorer:
    """Score domains for C2 suspicion based on heuristic signals.

    Thresholds (configurable via ScannerConfig):
      Score >= c2_suspicion_threshold (default 40) → SUSPICIOUS
      Score >= c2_likely_threshold (default 60) → LIKELY_C2
    """

    def __init__(
        self,
        config: ScannerConfig,
        threat_intel: ThreatIntelManager | None = None,
    ) -> None:
        self.config = config
        self.threat_intel = threat_intel or ThreatIntelManager(config)
        self._benign_domains: set[str] | None = None
        self._suspicious_tlds: set[str] | None = None

    def _load_benign_domains(self) -> set[str]:
        """Load benign domain whitelist from data file."""
        if self._benign_domains is not None:
            return self._benign_domains

        self._benign_domains = set()
        path = _DATA_DIR / "benign_domains.txt"
        if path.exists():
            try:
                for line in path.read_text(encoding="utf-8").splitlines():
                    domain = line.strip().lower()
                    if domain and not domain.startswith("#"):
                        self._benign_domains.add(domain)
            except OSError as exc:
                logger.warning("Cannot load benign domains: %s", exc)

        return self._benign_domains

    def _load_suspicious_tlds(self) -> set[str]:
        """Load suspicious TLD list from data file."""
        if self._suspicious_tlds is not None:
            return self._suspicious_tlds

        self._suspicious_tlds = set()
        path = _DATA_DIR / "suspicious_tlds.txt"
        if path.exists():
            try:
                for line in path.read_text(encoding="utf-8").splitlines():
                    tld = line.strip().lower()
                    if tld and not tld.startswith("#"):
                        # Store with and without leading dot
                        if tld.startswith("."):
                            self._suspicious_tlds.add(tld)
                            self._suspicious_tlds.add(tld[1:])
                        else:
                            self._suspicious_tlds.add(tld)
                            self._suspicious_tlds.add(f".{tld}")
            except OSError as exc:
                logger.warning("Cannot load suspicious TLDs: %s", exc)

        return self._suspicious_tlds

    def score(self, domain: str, context: dict | None = None) -> float:
        """Score a domain for C2 suspicion (0.0 - 100.0+).

        Args:
            domain: Domain name to score.
            context: Optional context dict with keys:
                - in_binary: bool — domain found in firmware binary (not config)
                - in_hosts: bool — domain in /etc/hosts or config file
                - file_path: str — where the domain was found

        Returns:
            Suspicion score. Higher = more suspicious.
        """
        if not domain or not domain.strip():
            return 0.0

        domain = domain.strip().lower()
        context = context or {}
        total = 0.0

        # ── Signal: Benign domain whitelist ──
        benign = self._load_benign_domains()
        if domain in benign or self._domain_in_benign(domain, benign):
            # Known-benign domain: immediately cap at 0 and return INFORMATIONAL.
            # A false-positive threat intel match should never override a
            # verified benign domain.
            return 0.0

        # ── Positive signals ──
        total += self._score_positive_signals(domain, context, check_threat_intel=True)

        return max(total, 0.0)

    def _score_positive_signals(
        self,
        domain: str,
        context: dict,
        check_threat_intel: bool = True,
    ) -> float:
        """Calculate positive (suspicion-increasing) signal scores."""
        total = 0.0

        # ── Signal: Threat intel feed match ──
        if check_threat_intel:
            intel = self.threat_intel.check_domain(domain)
            if intel is not None:
                total += _SCORE_THREAT_INTEL

        # ── Signal: Suspicious TLD ──
        suspicious_tlds = self._load_suspicious_tlds()
        tld = self._extract_tld(domain)
        if tld and (f".{tld}" in suspicious_tlds or tld in suspicious_tlds):
            total += _SCORE_SUSPICIOUS_TLD

        # ── Signal: Domain in firmware binary (not config) ──
        if context.get("in_binary", False):
            total += _SCORE_IN_FIRMWARE_BINARY

        # ── Signal: DGA detection ──
        if self._is_dga(domain):
            total += _SCORE_DGA

        # ── Signal: Botnet naming pattern ──
        if self._is_botnet_name(domain):
            total += _SCORE_BOTNET_NAMING

        # ── Signal: Domain in /etc/hosts or config ──
        if context.get("in_hosts", False):
            total += _SCORE_IN_HOSTS_CONFIG

        # ── Signal: SSL/Org (stub — always 0) ──
        # Per SDR: "valid SSL cert + established org" → -20, stub: not implemented

        return total

    def classify(self, score: float) -> str:
        """Classify a domain based on its suspicion score.

        Returns:
            "LIKELY_C2", "SUSPICIOUS", or "INFORMATIONAL"
        """
        if score >= self.config.c2_likely_threshold:
            return "LIKELY_C2"
        if score >= self.config.c2_suspicion_threshold:
            return "SUSPICIOUS"
        return "INFORMATIONAL"

    # ──────────────────────────────────────────
    # Detection helpers
    # ──────────────────────────────────────────

    @staticmethod
    def _extract_tld(domain: str) -> str | None:
        """Extract the top-level domain from a domain name."""
        parts = domain.rsplit(".", 1)
        if len(parts) < 2:
            return None
        return parts[-1].lower()

    @staticmethod
    def _domain_in_benign(domain: str, benign_set: set[str]) -> bool:
        """Check if domain or its parent zone is in the benign set."""
        # Check exact match first
        if domain in benign_set:
            return True
        # Check parent domains (e.g., updates.google.com → google.com)
        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in benign_set:
                return True
        return False

    @staticmethod
    def _is_dga(domain: str) -> bool:
        """Detect DGA-like domains using subdomain analysis.

        Heuristics:
        - 8+ char subdomain with low vowel ratio (< 0.3)
        - Pure hex subdomain (8+ chars)
        - Excessive consonant clusters (4+ consecutive consonants)
        - Excludes legitimate CDN subdomains by checking for common
          CDN patterns (e.g., CloudFront has very long subdomains)
        """
        parts = domain.split(".")
        if len(parts) < 2:
            return False

        subdomain = parts[0]

        # Skip very short subdomains
        if len(subdomain) < _DGA_MIN_SUBDOMAIN_LEN:
            return False

        # Skip legitimate CDN subdomains (very long but well-structured)
        # CloudFront: dXXXXXXXXXXXX.cloudfront.net
        # Fastly/other CDNs use long subdomains too
        if len(parts) > 2 and any(
            tld in domain.lower()
            for tld in (
                ".cloudfront.net",
                ".akamaihd.net",
                ".fastly.net",
                ".cdn77.org",
                ".edgekey.net",
                ".akamaiedge.net",
            )
        ):
            return False

        # Check pure hex pattern
        if _HEX_SUBDOMAIN.match(subdomain):
            return True

        # Check vowel ratio
        vowels = sum(1 for c in subdomain.lower() if c in "aeiou")
        if len(subdomain) > 0:
            vowel_ratio = vowels / len(subdomain)
            if vowel_ratio < _DGA_MAX_VOWEL_RATIO:
                # Also check for consonant clusters
                if _CONSONANT_CLUSTER.search(subdomain):
                    return True
                # Low vowel ratio alone can indicate DGA if very low
                if vowel_ratio < 0.15:
                    return True

        return False

    @staticmethod
    def _is_botnet_name(domain: str) -> bool:
        """Check if domain matches known botnet naming patterns."""
        return any(pattern.search(domain) for pattern in _BOTNET_PATTERNS)
