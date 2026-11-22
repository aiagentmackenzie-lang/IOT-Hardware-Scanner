"""The performance contract's own tests: a gate without them is a hope.

The contract decides two different things -- a machine-relative envelope and
machine-independent invariants -- and the dangerous failure is the quiet one:
reporting a pass when the baseline never applied. These tests pin the exit
codes and the wording for both, using synthetic documents only (no scan, no
fixtures, no timing), so they belong in the qualified suite and run in
milliseconds.

The module under test lives in ``benchmarks/``; it is loaded by path because the
benchmark directory is deliberately outside ``testpaths``.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

BENCHMARKS = Path(__file__).resolve().parent.parent / "benchmarks"


def _load(name: str) -> Any:
    if str(BENCHMARKS) not in sys.path:
        sys.path.insert(0, str(BENCHMARKS))
    spec = importlib.util.spec_from_file_location(f"_contract_{name}", BENCHMARKS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


contract = _load("perf_contract")

FINGERPRINT = {
    "system": "Darwin",
    "machine": "arm64",
    "python": "3.12",
    "cpu_count": 8,
    "yara": "4.5.1",
    "engine": "2.5.1",
    "fixtures": "plan-digest",
}

WALLS = {"cold-scan": 14.0, "warm-scan": 1.6, "fit-parse": 0.012, "entropy-2gib": 32.0}

RSS = {
    "cold-scan": 410 * 1024 * 1024,
    "warm-scan": 422 * 1024 * 1024,
    "fit-parse": 45 * 1024 * 1024,
    "entropy-2gib": 78 * 1024 * 1024,
}


def measure_document(
    *,
    fingerprint: dict[str, Any] | None = None,
    rss: dict[str, int] | None = None,
    walls: dict[str, float] | None = None,
    drop: str | None = None,
) -> dict[str, Any]:
    values = dict(RSS if rss is None else rss)
    times = dict(WALLS if walls is None else walls)
    cases = {
        name: {
            "case": name,
            "wall_seconds": times[name],
            "peak_rss_bytes": value,
            "result": {},
        }
        for name, value in values.items()
    }
    if drop is not None:
        cases.pop(drop)
    return {
        "format": "ihs-perf-measure/1",
        "fingerprint": dict(FINGERPRINT if fingerprint is None else fingerprint),
        "fixtures": {"plan": "plan-digest"},
        "cases": cases,
    }


def baseline_document() -> dict[str, Any]:
    return {
        "format": "ihs-perf-baseline/1",
        "recorded_at": "2026-11-22T00:00:00+00:00",
        "fingerprint": dict(FINGERPRINT),
        "fixtures": {"plan": "plan-digest"},
        "envelope": {"wall": contract.WALL_TOLERANCE, "rss": contract.RSS_TOLERANCE},
        "cases": {
            name: {"wall_seconds": WALLS[name], "peak_rss_bytes": RSS[name]} for name in WALLS
        },
    }


def test_a_matching_run_inside_the_envelope_is_judged() -> None:
    ok, applicable, lines = contract.verdict(
        measure_document(), baseline_document(), walls=dict(WALLS)
    )
    assert ok is True
    assert applicable is True
    assert any("envelope applied" not in line and "cold-scan: wall" in line for line in lines)


def test_a_slower_case_breaks_the_wall_envelope_and_is_named() -> None:
    walls = dict(WALLS)
    walls["cold-scan"] = WALLS["cold-scan"] * (1 + contract.WALL_TOLERANCE + 0.05)
    ok, applicable, lines = contract.verdict(measure_document(), baseline_document(), walls=walls)
    assert ok is False
    assert applicable is True
    assert any(line.startswith("FAIL") and "cold-scan" in line for line in lines)


def test_a_case_just_inside_the_wall_envelope_passes() -> None:
    walls = dict(WALLS)
    walls["fit-parse"] = WALLS["fit-parse"] * (1 + contract.WALL_TOLERANCE) * 0.99
    ok, _applicable, _lines = contract.verdict(measure_document(), baseline_document(), walls=walls)
    assert ok is True


def test_a_memory_regression_breaks_the_rss_envelope() -> None:
    rss = dict(RSS)
    rss["cold-scan"] = int(RSS["cold-scan"] * (1 + contract.RSS_TOLERANCE + 0.01))
    ok, _applicable, lines = contract.verdict(
        measure_document(rss=rss), baseline_document(), walls=dict(WALLS)
    )
    assert ok is False
    assert any("peak RSS" in line and "cold-scan" in line for line in lines)


def test_a_new_engine_version_is_still_judged() -> None:
    """A release must not quietly turn the gate into a recorder."""
    upgraded = dict(FINGERPRINT, engine="9.9.9")
    ok, applicable, _lines = contract.verdict(
        measure_document(fingerprint=upgraded), baseline_document(), walls=dict(WALLS)
    )
    assert ok is True
    assert applicable is True


def test_a_different_machine_is_recorded_not_passed() -> None:
    other = dict(FINGERPRINT, machine="x86_64", system="Linux")
    ok, applicable, lines = contract.verdict(
        measure_document(fingerprint=other), baseline_document(), walls=dict(WALLS)
    )
    assert ok is True
    assert applicable is False
    assert any("NOT APPLICABLE" in line and "machine" in line for line in lines)
    assert not any(line.startswith("ok       cold-scan: wall") for line in lines)


def test_the_cache_invariant_is_enforced_without_an_applicable_baseline() -> None:
    other = dict(FINGERPRINT, machine="x86_64")
    walls = dict(WALLS)
    walls["warm-scan"] = walls["cold-scan"]
    ok, applicable, lines = contract.verdict(
        measure_document(fingerprint=other), baseline_document(), walls=walls
    )
    assert ok is False
    assert applicable is False
    assert any("cache is not earning its place" in line for line in lines)


def test_the_window_invariant_is_enforced_without_an_applicable_baseline() -> None:
    other = dict(FINGERPRINT, machine="x86_64")
    rss = dict(RSS)
    rss["entropy-2gib"] = contract.ENTROPY_RSS_CEILING + 1
    ok, applicable, _lines = contract.verdict(
        measure_document(fingerprint=other, rss=rss), baseline_document(), walls=dict(WALLS)
    )
    assert ok is False
    assert applicable is False


def test_a_case_that_did_not_run_is_never_a_pass() -> None:
    ok, _applicable, lines = contract.verdict(
        measure_document(drop="entropy-2gib"), baseline_document(), walls=dict(WALLS)
    )
    assert ok is False
    assert any("MISSING  entropy-2gib" in line for line in lines)


def test_the_command_line_exit_codes(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(baseline_document()))

    good = tmp_path / "good.json"
    good.write_text(json.dumps(measure_document()))

    bad = tmp_path / "bad.json"
    rss = dict(RSS)
    rss["cold-scan"] = int(RSS["cold-scan"] * 2)
    bad.write_text(json.dumps(measure_document(rss=rss)))

    other = tmp_path / "other.json"
    other.write_text(json.dumps(measure_document(fingerprint=dict(FINGERPRINT, machine="x86_64"))))

    assert contract.main(["--measure", str(good), "--baseline", str(baseline)]) == 0
    assert contract.main(["--measure", str(bad), "--baseline", str(baseline)]) == 1
    assert contract.main(["--measure", str(other), "--baseline", str(baseline)]) == 0
    assert (
        contract.main(
            ["--measure", str(other), "--baseline", str(baseline), "--require-applicable"]
        )
        == 1
    )


def test_a_missing_measurement_is_an_input_error(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(baseline_document()))
    assert (
        contract.main(["--measure", str(tmp_path / "absent.json"), "--baseline", str(baseline)])
        == 2
    )


@pytest.mark.parametrize("tolerance", ["WALL_TOLERANCE", "RSS_TOLERANCE"])
def test_the_envelopes_are_the_numbers_the_record_states(tolerance: str) -> None:
    import json as _json

    recorded = _json.loads((BENCHMARKS / "baseline.json").read_text())
    assert recorded["envelope"]["wall" if tolerance == "WALL_TOLERANCE" else "rss"] == getattr(
        contract, tolerance
    )
