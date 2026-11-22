"""P1 — a row in the support matrix is executable, or it is not a claim.

The support matrix is the public answer to "what has actually been
demonstrated, on what, and by which code". Before this module it was a
hand-maintained table: a renamed acceptance test, or a deleted row, changed the
claim without changing anything a run could notice.

What is enforced here
---------------------
1. Every backticked test reference in ``docs/SUPPORT-MATRIX.md`` resolves to a
   collected test node (or, for ``tests/conftest.py::fixture``, to a fixture the
   file defines). A bare module reference names every test in that module.
2. Every acceptance class in the two installed-entrypoint modules is named by at
   least one matrix row. An acceptance row that no claim points at is invisible
   evidence.
3. Tests that back no claim are **reported**, never failed: most of the suite is
   unit-level work and does not carry a public claim. The list stays visible so
   the claim surface can grow deliberately.

The verdict on what actually ran is a session-end hook in ``tests/conftest.py``,
not a test in this module: pytest executes modules in file order, so a test here
cannot see a failure in a module it has not reached yet. ``tests/claims.py``
holds the parsing both sides share.

What is deliberately not enforced
----------------------------------
Historical slice records (``docs/MILESTONE-*.md``) are records, not live claims;
they are not edited to match a later rename. The live claim surface is the
support matrix. A "not supported" row names no test because there is nothing to
run -- inventing a test reference for it would be the drift this module exists
to stop.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from claims import Claim, matrix_claims
from harness import REPO_ROOT

#: The two modules whose tests are the release acceptance surface. Every class
#: here must be named by a matrix row.
ACCEPTANCE_MODULES = (
    "tests/test_installed_cli.py",
    "tests/test_installed_image_cli.py",
)

#: How many unclaimed modules to print. The full list is long and stable; the
#: point is that a reader can see the size of the gap without a wall of text.
_REPORT_LIMIT = 60


@lru_cache(maxsize=1)
def collected_nodeids() -> frozenset[str]:
    """Every node id the suite collects, from a collection-only subprocess.

    It has to be a subprocess rather than ``request.session.items``: this module
    also runs inside CI jobs that select a handful of files, and a claim that
    names a test outside the selection must still be seen to exist. ``addopts``
    is overridden because the repository's ``-q`` plus ``--collect-only`` would
    otherwise print per-module counts instead of node ids.
    """
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "--no-header",
            "-p",
            "no:cacheprovider",
            "--override-ini",
            "addopts=",
        ],
        cwd=str(REPO_ROOT),
        env={**os.environ, "PYTHONNOUSERSITE": "1"},
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    if completed.returncode != 0:
        # A failed collection prints every node id it reached before the error.
        # The cause is the part that does not look like a node id.
        detail = [
            line
            for line in (completed.stdout + completed.stderr).splitlines()
            if not line.startswith("tests/")
        ]
        raise AssertionError(
            "test collection failed while checking the claims; the venv must be "
            "able to import every test module (install the wheel with its dev "
            "extra):\n" + "\n".join(detail)[-4000:]
        )
    nodes = {line.strip() for line in completed.stdout.splitlines() if "::" in line}
    if not nodes:
        raise AssertionError(f"collection produced no node ids:\n{completed.stdout}")
    return frozenset(nodes)


def _source_defines(module: str, symbol: str) -> bool:
    """Whether ``module`` defines a function or class called ``symbol``."""
    path = REPO_ROOT / module
    if not path.is_file():
        return False
    tree = ast.parse(path.read_text())
    return any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and node.name == symbol
        for node in tree.body
    )


def _match(prefix: str) -> list[str]:
    """Collected node ids under one prefix: a module, class or test."""
    return sorted(
        nodeid
        for nodeid in collected_nodeids()
        if nodeid == prefix or nodeid.startswith(prefix + "::") or nodeid.startswith(prefix + "[")
    )


def _resolve(claim: Claim) -> tuple[list[str], str | None]:
    """The nodes a claim covers, and why it covers none."""
    if claim.is_fixture:
        if claim.symbol is None:
            return [], "a conftest reference must name the fixture it points at"
        if not _source_defines(claim.module, claim.symbol):
            return [], "no such fixture"
        return [], None
    if not (REPO_ROOT / claim.module).is_file():
        return [], "the module does not exist"

    found = [(prefix, _match(prefix)) for prefix in claim.candidates]
    found = [(prefix, nodes) for prefix, nodes in found if nodes]
    if len(found) > 1:
        return [], "ambiguous continuation: it matches " + ", ".join(prefix for prefix, _ in found)
    if not found:
        return [], "no collected test node matches"
    return found[0][1], None


def _nodes_for(claim: Claim) -> list[str]:
    """Collected node ids a claim covers."""
    return _resolve(claim)[0]


def _unresolved(claim: Claim) -> str | None:
    """Why a claim is not backed by a collected test, or ``None`` if it is."""
    return _resolve(claim)[1]


def _has_test_method(node: ast.ClassDef) -> bool:
    return any(
        isinstance(body, (ast.FunctionDef, ast.AsyncFunctionDef)) and body.name.startswith("test_")
        for body in node.body
    )


def _classes_with_tests() -> dict[str, tuple[str, ...]]:
    """Every acceptance class that actually holds a test, by module."""
    found: dict[str, tuple[str, ...]] = {}
    for module in ACCEPTANCE_MODULES:
        tree = ast.parse((REPO_ROOT / module).read_text())
        found[module] = tuple(
            node.name
            for node in tree.body
            if isinstance(node, ast.ClassDef) and _has_test_method(node)
        )
    return found


def _write(config: pytest.Config, line: str) -> None:
    """Print a report line where a CI log will keep it."""
    reporter = config.pluginmanager.get_plugin("terminalreporter")
    if reporter is None:
        print(line)
    else:
        reporter.write_line(line)


# ──────────────────────────────────────────────
# The checks
# ──────────────────────────────────────────────


def test_every_matrix_reference_resolves() -> None:
    """A claim that names a test must name one that exists.

    This is the check that fails when an acceptance test is renamed: the matrix
    keeps the old id and CI goes red instead of quietly publishing evidence that
    no longer runs.
    """
    claims = matrix_claims()
    assert claims, "the support matrix names no test at all: it is not a claim surface"

    unresolved = []
    for claim in claims:
        why = _unresolved(claim)
        if why is not None:
            unresolved.append(f"line {claim.line}: `{claim.text}` -- {why}")
    assert not unresolved, (
        "docs/SUPPORT-MATRIX.md names tests that do not resolve. A claim without"
        " a passing case is unqualified, not a claim:\n  " + "\n  ".join(unresolved)
    )


def test_every_acceptance_class_is_named_by_a_row() -> None:
    """The acceptance surface must be visible in the matrix."""
    claims = matrix_claims()
    missing: list[str] = []
    for module, classes in _classes_with_tests().items():
        for name in classes:
            covered = any(
                claim.module == module
                and claim.symbol is not None
                and (claim.symbol == name or claim.symbol.startswith(name + "::"))
                for claim in claims
            )
            if not covered:
                missing.append(f"{module}::{name}")
    assert not missing, (
        "these acceptance classes back no row in docs/SUPPORT-MATRIX.md, so their"
        " evidence is invisible to a reader:\n  " + "\n  ".join(missing)
    )


def test_unclaimed_tests_are_reported(pytestconfig: pytest.Config) -> None:
    """Show which tests back no claim. Report only: this test never fails."""
    claims = [claim for claim in matrix_claims() if not claim.is_fixture]
    claimed_modules = {claim.module for claim in claims}
    nodes = sorted(collected_nodeids())
    claimed_nodes = {nodeid for nodeid in nodes if any(claim.matches(nodeid) for claim in claims)}
    modules = sorted({nodeid.split("::", 1)[0] for nodeid in nodes})
    unclaimed_modules = [
        module
        for module in modules
        if not any(nodeid.split("::", 1)[0] == module for nodeid in claimed_nodes)
    ]

    _write(
        pytestconfig,
        f"claim matrix: {len(claimed_nodes)} of {len(nodes)} collected tests back a "
        f"support-matrix row; {len(unclaimed_modules)} of {len(modules)} test modules "
        "back none",
    )
    if unclaimed_modules:
        _write(
            pytestconfig,
            "  modules with no claim: " + ", ".join(unclaimed_modules[:_REPORT_LIMIT]),
        )
    _write(
        pytestconfig,
        f"  matrix references: {len(claims)} ({len(claimed_modules)} modules); "
        f"collected: {len(nodes)}",
    )
