"""Session fixtures for the performance cases.

Every fixture here is prepared before a measured round starts. Generation,
cache population and the sparse 2 GiB file are setup cost, not scan cost, and a
benchmark that folded them into the number would report the disk.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cases


@pytest.fixture(scope="session")
def perf_root() -> Path:
    """Build every fixture and populate the warm cache once per session."""
    cases.prepare_all()
    return cases.workdir()


@pytest.fixture(scope="session")
def tree(perf_root: Path) -> Path:
    return perf_root / "tree"


@pytest.fixture(scope="session")
def cache_dir(perf_root: Path) -> Path:
    return perf_root / "cache"


@pytest.fixture(scope="session")
def dtb(perf_root: Path) -> Path:
    return perf_root / "perf.dtb"


@pytest.fixture(scope="session")
def entropy_file(perf_root: Path) -> Path:
    return perf_root / "entropy-2gib.bin"
