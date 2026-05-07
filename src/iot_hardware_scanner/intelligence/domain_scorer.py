"""Domain Suspicion Scorer.

SDR §12.1 — Domain Heuristic Scoring

Stub — full implementation in Phase 6.
"""

from __future__ import annotations

import logging

from iot_hardware_scanner.config import ScannerConfig

logger = logging.getLogger(__name__)


class DomainScorer:
    """Score domains for C2 suspicion based on heuristic signals."""

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config

    def score(self, domain: str, context: dict | None = None) -> float:
        """Score a domain for C2 suspicion (0.0 - 100.0).

        SDR §12.1 scoring signals applied.
        """
        return 0.0
