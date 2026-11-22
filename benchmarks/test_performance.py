"""The four measured paths as pytest-benchmark cases (slice P2).

Run explicitly -- a bare ``pytest`` never collects this directory, because
``pyproject.toml`` sets ``testpaths = ["tests"]``::

    pytest benchmarks/ --benchmark-json=bench.json
    python benchmarks/measure.py --out measure.json
    python benchmarks/perf_contract.py measure.json

Each case asserts a semantic result as well as timing. A benchmark that
measures the wrong thing quickly is worse than no benchmark: if the scan stops
producing findings, the timing must not be allowed to stand as a pass.

``rounds`` is set per case rather than left to calibration. A 7 s scan calibrated
for statistical confidence would spend minutes per run and would not make the
number more honest -- the release record is a min over a handful of rounds on a
named machine, and the contract's envelope is +25 %.
"""

from __future__ import annotations

from pathlib import Path

import cases
import pytest

pytestmark = pytest.mark.slow


def test_cold_scan_tree(benchmark, tree: Path) -> None:
    """A full ``firmware-tree`` scan with no cache: the release baseline path."""
    result = benchmark.pedantic(cases.scan_tree, args=(tree,), rounds=3, iterations=1)
    assert result["files"] > 300, result
    assert result["elf"] > 0, result
    assert result["findings"] > 0, result
    assert result["assessment"] == "COMPLETE", result


def test_warm_scan_tree(benchmark, tree: Path, cache_dir: Path) -> None:
    """The same tree with the content cache populated by the session fixture."""
    result = benchmark.pedantic(cases.scan_tree, args=(tree, cache_dir), rounds=3, iterations=1)
    assert result["files"] > 300, result
    assert result["cache"] is not None, result
    assert result["cache"]["hits"] > 0, result
    assert result["assessment"] == "COMPLETE", result


def test_parse_dtb(benchmark, dtb: Path) -> None:
    """One ~1 MiB flattened device tree through the 3D parser."""
    result = benchmark.pedantic(cases.parse_dtb, args=(dtb,), rounds=10, iterations=1)
    assert result["nodes"] > 1000, result
    assert result["compatible"] >= 2, result


def test_entropy_2gib(benchmark, entropy_file: Path) -> None:
    """The whole 2 GiB file through the windowed reader, at a fixed block size."""
    result = benchmark.pedantic(cases.entropy_2gib, args=(entropy_file,), rounds=2, iterations=1)
    assert result["sampled"] is False, result
    assert result["blocks"] > 100, result
