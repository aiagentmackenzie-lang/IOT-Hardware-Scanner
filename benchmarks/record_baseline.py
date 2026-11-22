"""Merge a benchmark run and a measurement run into the baseline.

A baseline is two numbers per case from two harnesses: wall time is the minimum
of ``pytest-benchmark`` rounds (statistics done by a tool that exists for it),
peak RSS is the child-process ``ru_maxrss`` from ``measure.py`` (the only place
it is attributable to one case). One file records both, with the fingerprint
that decides whether the envelope may be applied at all.

Record a new baseline only on the machine that will be judged, and only from a
clean tree::

    pytest benchmarks/ --benchmark-json=bench.json
    python benchmarks/measure.py --out measure.json
    python benchmarks/record_baseline.py --bench bench.json --measure measure.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cases

BASELINE = Path(__file__).resolve().parent / "baseline.json"


def wall_from_bench(bench: dict[str, Any]) -> dict[str, float]:
    """Minimum wall time per case, in seconds."""
    walls: dict[str, float] = {}
    for entry in bench.get("benchmarks", []):
        name = entry.get("name", "")
        case = cases.TEST_TO_CASE.get(name)
        if case is None:
            continue
        walls[case] = entry["stats"]["min"]
    return walls


def build(bench: dict[str, Any], measure: dict[str, Any]) -> dict[str, Any]:
    walls = wall_from_bench(bench)
    recorded: dict[str, Any] = {}
    for name, record in measure.get("cases", {}).items():
        recorded[name] = {
            "wall_seconds": round(walls.get(name, record["wall_seconds"]), 6),
            "wall_source": "pytest-benchmark min" if name in walls else "measure single run",
            "peak_rss_bytes": record["peak_rss_bytes"],
            "result": record.get("result"),
        }
    return {
        "format": "ihs-perf-baseline/1",
        "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "fingerprint": measure.get("fingerprint") or cases.environment_fingerprint(),
        "fixtures": measure.get("fixtures") or cases.fixture_summary(),
        "envelope": {"wall": 0.25, "rss": 0.15},
        "cases": recorded,
        "note": (
            "Wall is the minimum of the pytest-benchmark rounds; RSS is the child-process "
            "peak. The envelope applies only when the fingerprint matches."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bench", type=Path, required=True)
    parser.add_argument("--measure", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=BASELINE)
    args = parser.parse_args(argv)

    bench = json.loads(args.bench.read_text())
    measure = json.loads(args.measure.read_text())
    document = build(bench, measure)

    missing = [name for name in cases.CASE_NAMES if name not in document["cases"]]
    if missing:
        print(f"record-baseline: no record for {', '.join(missing)}")
        return 1

    args.out.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(f"record-baseline: wrote {args.out}")
    for name in cases.CASE_NAMES:
        record = document["cases"][name]
        print(
            f"  {name:<14} wall {record['wall_seconds']:8.3f} s   "
            f"peak RSS {record['peak_rss_bytes'] / (1024 * 1024):7.1f} MiB"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
