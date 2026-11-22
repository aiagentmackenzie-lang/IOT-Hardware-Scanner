"""Record every test outcome for the duration of one pytest process.

Two consumers share this record, and they are the reason it exists:

``tests/conftest.py --fail-on-skips``
    A skip in a run started with the flag fails the *process*, naming the node
    id and the reason. That replaces the ``grep -qE "[0-9]+ skipped"`` blocks
    the CI workflow used to carry: the enforcement is the flag, the log stays
    for humans.

``tests/test_claim_matrix.py``
    A support-matrix row is a claim, so a claimed test that ran in this session
    must have passed. A claimed test that did not run here is reported rather
    than silently counted as evidence.

One process-level recorder is enough: ``python -m pytest`` runs once per
process. Precedence is failed > skipped > passed, so a teardown error cannot be
hidden by a call that passed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

FAILED = "failed"
SKIPPED = "skipped"
PASSED = "passed"

_RANK = {PASSED: 0, SKIPPED: 1, FAILED: 2}


@dataclass(frozen=True)
class Outcome:
    """What happened to one collected node id."""

    nodeid: str
    status: str
    reason: str | None = None


def skip_reason(report: Any) -> str:
    """The reason pytest recorded for a skip, without the traceback noise.

    A setup-phase skip carries ``longrepr`` as ``(path, lineno, reason)``; a skip
    raised from inside a test carries a ``longrepr`` with ``reprcrash``. Both are
    attacker-neutral here -- this is test reporting, not analysis input -- but
    neither may be lost, because the reason is the qualification gap.
    """
    longrepr = getattr(report, "longrepr", None)
    if isinstance(longrepr, tuple) and len(longrepr) >= 3:
        return str(longrepr[2])
    crash = getattr(longrepr, "reprcrash", None)
    if crash is not None:
        return str(getattr(crash, "message", crash))
    return str(longrepr) if longrepr is not None else "skipped without a recorded reason"


def failure_reason(report: Any) -> str | None:
    """The first line of the failure, for a one-line claim report."""
    longrepr = getattr(report, "longrepr", None)
    crash = getattr(longrepr, "reprcrash", None)
    if crash is not None:
        return str(getattr(crash, "message", crash))
    text = str(longrepr) if longrepr is not None else ""
    return text.splitlines()[0] if text else None


@dataclass
class RunRecorder:
    """Every outcome this process saw, keyed by node id."""

    outcomes: dict[str, Outcome] = field(default_factory=dict)
    skips: dict[str, Outcome] = field(default_factory=dict)

    def record(self, report: Any) -> None:
        nodeid = str(report.nodeid)
        status: str
        reason: str | None
        if getattr(report, "failed", False):
            status = FAILED
            reason = failure_reason(report)
        elif getattr(report, "skipped", False):
            status = SKIPPED
            reason = skip_reason(report)
            self.skips.setdefault(nodeid, Outcome(nodeid, status, reason))
        elif getattr(report, "when", None) == "call" and getattr(report, "passed", False):
            status = PASSED
            reason = None
        else:
            return

        existing = self.outcomes.get(nodeid)
        if existing is not None and _RANK[existing.status] >= _RANK[status]:
            return
        self.outcomes[nodeid] = Outcome(nodeid, status, reason)

    def outcome(self, nodeid: str) -> Outcome | None:
        return self.outcomes.get(nodeid)

    @property
    def skipped(self) -> list[Outcome]:
        return list(self.skips.values())


#: The one recorder for this process. ``conftest`` writes to it; the claim check
#: reads from it.
RECORDER = RunRecorder()
