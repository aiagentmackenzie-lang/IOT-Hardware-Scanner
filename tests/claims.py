"""The support matrix read as claims.

Shared by ``tests/test_claim_matrix.py`` (existence, coverage, the visible
reports) and ``tests/conftest.py`` (the session-end verdict on what actually
ran). The split matters: a per-test check cannot see a failure in a module that
pytest has not reached yet, so "a claimed test passed" is decided when the
session ends, not when the claim module happens to execute.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from run_recorder import FAILED, SKIPPED, Outcome

MATRIX = Path(__file__).resolve().parents[1] / "docs" / "SUPPORT-MATRIX.md"

_BACKTICKED = re.compile(r"`([^`]+)`")
#: ``tests/x.py``, ``tests/x.py::Class``, ``tests/x.py::test_name``. The symbol
#: charset stops at whitespace and a backtick, so a parametrised id is allowed.
_TEST_REFERENCE = re.compile(r"^(?P<module>tests/[\w./-]+\.py)(?:::(?P<symbol>[^`\s]+))?$")


@dataclass(frozen=True)
class Claim:
    """One backticked test reference from the matrix.

    ``parent`` is the previous reference's full prefix, set only for a
    ``::name`` continuation. The matrix uses continuations for both "another
    method of the same class" (``TestBootManifestProfile`` then
    ``::test_a_supplied_key...``) and "another class of the same module"
    (``TestReferenceImageInventory`` then ``::TestReleasedDetectionSemantics``),
    so a continuation resolves against both and must match exactly one.
    """

    text: str
    module: str
    symbol: str | None
    line: int
    parent: str | None = None

    @property
    def is_fixture(self) -> bool:
        return Path(self.module).name == "conftest.py"

    @property
    def candidates(self) -> tuple[str, ...]:
        """Prefixes this reference may mean, most specific first."""
        if self.symbol is None:
            return (self.module,)
        prefixes: list[str] = []
        if self.parent is not None:
            prefixes.append(f"{self.parent}::{self.symbol}")
        prefixes.append(f"{self.module}::{self.symbol}")
        return tuple(dict.fromkeys(prefixes))

    def matches(self, nodeid: str) -> bool:
        """Whether a collected/executed node id is covered by this claim."""
        return any(
            nodeid == prefix or nodeid.startswith(prefix + "::") or nodeid.startswith(prefix + "[")
            for prefix in self.candidates
        )


def parse_claims(text: str) -> list[Claim]:
    """Extract test references, resolving ``::name`` continuations.

    The matrix uses the table convention ``tests/x.py::A``, ``::B``: a
    continuation is resolved against the most recently named reference and, if
    that does not contain it, against that reference's module. That covers both
    the "another method of the same class" cell and the "another class of the
    same module" cell. Two meanings that both resolve are an error, not a guess.
    """
    claims: list[Claim] = []
    module: str | None = None
    for number, line in enumerate(text.splitlines(), start=1):
        for token in _BACKTICKED.findall(line):
            if token.startswith("::"):
                if module is None or not claims:
                    raise ValueError(
                        f"line {number}: `{token}` continues a test reference "
                        "but no module was named before it"
                    )
                previous = claims[-1]
                # A continuation after another continuation (a run of sibling
                # classes, ``::A``, ``::B``) is module-relative: there is no
                # enclosing class to inherit.
                parent = (
                    f"{previous.module}::{previous.symbol}"
                    if previous.symbol is not None and previous.parent is None
                    else previous.module
                )
                claims.append(Claim(token, module, token[2:], number, parent=parent))
                continue
            match = _TEST_REFERENCE.match(token)
            if match is None:
                continue
            module = match.group("module")
            claims.append(Claim(token, module, match.group("symbol"), number))
    return claims


def matrix_claims() -> list[Claim]:
    """The claims of the live support matrix."""
    return parse_claims(MATRIX.read_text())


def claimed_outcomes(
    outcomes: Mapping[str, Outcome],
) -> tuple[list[tuple[Claim, Outcome]], list[tuple[Claim, Outcome]]]:
    """Claimed nodes that failed and claimed nodes that skipped, in matrix order.

    Only nodes this process actually saw are returned; a run that selects some
    files cannot say anything about the rest.
    """
    failed: list[tuple[Claim, Outcome]] = []
    skipped: list[tuple[Claim, Outcome]] = []
    seen: set[str] = set()
    for claim in matrix_claims():
        if claim.is_fixture:
            continue
        for nodeid, outcome in outcomes.items():
            if nodeid in seen or not claim.matches(nodeid):
                continue
            seen.add(nodeid)
            if outcome.status == FAILED:
                failed.append((claim, outcome))
            elif outcome.status == SKIPPED:
                skipped.append((claim, outcome))
    return failed, skipped
