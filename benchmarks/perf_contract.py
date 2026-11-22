"""The performance contract: an envelope against a recorded baseline.

Two rules, and the difference between them is the whole point of this file.

**The envelope is machine-relative.** A wall-time budget recorded on a Mac mini
is not evidence about a shared GitHub runner, and pretending otherwise is how a
performance gate becomes a flaky test that someone eventually deletes. The
baseline carries a fingerprint (system, machine, Python, CPU count, YARA,
engine version, fixture plan). When the fingerprint does not match, the run is
**recorded, not judged**: the exit is 0 and the report says
``applicable: false``. It never prints a pass.

**The invariants are machine-independent.** Three claims do not depend on the
host:

* the warm-cache run is faster than the cold run (a cache that does not help is
  a defect, not a slow machine);
* the 2 GiB windowed entropy pass stays far below one flat allocation, which is
  the bounded reader's contract;
* every case completes (a benchmark that raises is a failure, not a number).

Those are enforced everywhere, including on a host with no applicable baseline.

Usage::

    python benchmarks/perf_contract.py --measure measure.json \
        --bench bench.json [--baseline benchmarks/baseline.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cases

DEFAULT_BASELINE = Path(__file__).resolve().parent / "baseline.json"

#: Wall time may grow by this fraction before the contract fails. The number is
#: deliberately loose: a release gate that trips on scheduler noise teaches the
#: wrong lesson. Anything above a quarter is a change in the algorithm, not the
#: machine.
WALL_TOLERANCE = 0.25

#: Peak RSS may grow by this fraction. Tighter than wall time on purpose: a
#: memory regression is monotonic and does not wash out with repetition.
RSS_TOLERANCE = 0.15

#: Machine-independent ceiling for the 2 GiB windowed pass. The bounded
#: resources job asserts 512 MiB for the CLI; the in-process reader should be
#: far below it, because the window is 16 MiB. A flat allocation would be 2 GiB.
ENTROPY_RSS_CEILING = 256 * 1024 * 1024

#: Keys that decide whether the envelope may be applied. ``fixtures`` matters as
#: much as the CPU: a rebuilt tree is a different measurement. ``engine`` is
#: deliberately **not** here -- a new engine version is the change the gate is
#: meant to judge, and a baseline that expires on every release would silently
#: degrade to "recorded only" exactly when it is needed. It stays in the
#: document as metadata.
FINGERPRINT_KEYS = ("system", "machine", "python", "cpu_count", "yara", "fixtures")


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def compare_fingerprint(baseline: dict[str, Any], current: dict[str, Any]) -> list[str]:
    left = baseline.get("fingerprint", {})
    right = current.get("fingerprint", {})
    return [key for key in FINGERPRINT_KEYS if left.get(key) != right.get(key)]


def walls_from_bench(bench: dict[str, Any]) -> dict[str, float]:
    """Minimum wall time per case, in seconds, from a pytest-benchmark document."""
    walls: dict[str, float] = {}
    for entry in bench.get("benchmarks", []):
        case = cases.TEST_TO_CASE.get(entry.get("name", ""))
        if case is not None:
            walls[case] = entry["stats"]["min"]
    return walls


def verdict(
    measure: dict[str, Any],
    baseline: dict[str, Any],
    *,
    walls: dict[str, float] | None = None,
) -> tuple[bool, bool, list[str]]:
    """Return (ok, applicable, lines)."""
    lines: list[str] = []
    ok = True
    current_cases = measure.get("cases", {})
    baseline_cases = baseline.get("cases", {})
    measured_walls = walls or {}
    if not measured_walls:
        lines.append(
            "NOTE     no --bench given: wall times come from the single measure run, "
            "which is noisier than a benchmark minimum"
        )

    # ── machine-independent invariants ──
    for name in cases.CASE_NAMES:
        if name not in current_cases:
            lines.append(f"MISSING  {name}: the case did not run")
            ok = False

    def wall_of(name: str) -> float | None:
        if name in measured_walls:
            return measured_walls[name]
        return current_cases.get(name, {}).get("wall_seconds")

    cold = wall_of("cold-scan")
    warm = wall_of("warm-scan")
    if cold and warm is not None:
        if warm >= cold:
            lines.append(
                f"FAIL     warm-scan is not faster than cold-scan "
                f"({warm:.3f} s vs {cold:.3f} s): the cache is not earning its place"
            )
            ok = False
        else:
            lines.append(
                f"ok       warm-scan {warm:.3f} s vs cold-scan {cold:.3f} s "
                f"({(1 - warm / cold) * 100:.0f} % saved)"
            )

    entropy = current_cases.get("entropy-2gib", {}).get("peak_rss_bytes")
    if entropy is not None:
        if entropy > ENTROPY_RSS_CEILING:
            lines.append(
                f"FAIL     entropy-2gib peak RSS {entropy / (1024 * 1024):.0f} MiB over the "
                f"{ENTROPY_RSS_CEILING // (1024 * 1024)} MiB windowed ceiling"
            )
            ok = False
        else:
            lines.append(
                f"ok       entropy-2gib peak RSS {entropy / (1024 * 1024):.1f} MiB "
                f"< {ENTROPY_RSS_CEILING // (1024 * 1024)} MiB ceiling"
            )

    mismatched = compare_fingerprint(baseline, measure)
    if mismatched:
        lines.append("NOT APPLICABLE  baseline fingerprint differs in: " + ", ".join(mismatched))
        lines.append("                this run is recorded, not judged; no envelope was applied")
        return ok, False, lines

    if not baseline_cases:
        lines.append("NO BASELINE  the baseline has no case records")
        return False, False, lines

    for name, record in baseline_cases.items():
        now = current_cases.get(name)
        if now is None:
            continue
        base_wall = record.get("wall_seconds")
        wall = wall_of(name)
        if base_wall and wall is not None:
            limit = base_wall * (1 + WALL_TOLERANCE)
            share = (wall - base_wall) / base_wall * 100
            if wall > limit:
                lines.append(
                    f"FAIL     {name}: wall {wall:.3f} s vs {base_wall:.3f} s baseline "
                    f"({share:+.1f} %, envelope +{WALL_TOLERANCE * 100:.0f} %)"
                )
                ok = False
            else:
                lines.append(
                    f"ok       {name}: wall {wall:.3f} s vs {base_wall:.3f} s ({share:+.1f} %)"
                )
        base_rss = record.get("peak_rss_bytes")
        if base_rss:
            limit = base_rss * (1 + RSS_TOLERANCE)
            rss = now["peak_rss_bytes"]
            share = (rss - base_rss) / base_rss * 100
            if rss > limit:
                lines.append(
                    f"FAIL     {name}: peak RSS {rss / (1024 * 1024):.1f} MiB vs "
                    f"{base_rss / (1024 * 1024):.1f} MiB baseline "
                    f"({share:+.1f} %, envelope +{RSS_TOLERANCE * 100:.0f} %)"
                )
                ok = False
            else:
                lines.append(
                    f"ok       {name}: peak RSS {rss / (1024 * 1024):.1f} MiB vs "
                    f"{base_rss / (1024 * 1024):.1f} MiB ({share:+.1f} %)"
                )

    return ok, True, lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check a measurement against the baseline")
    parser.add_argument("--measure", type=Path, required=True, help="the measure.json to judge")
    parser.add_argument(
        "--bench",
        type=Path,
        default=None,
        help="the pytest-benchmark JSON; its per-case minimum is the wall-time value",
    )
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument(
        "--require-applicable",
        action="store_true",
        help="fail instead of recording when the baseline does not apply to this host",
    )
    args = parser.parse_args(argv)

    if not args.measure.exists():
        print(f"perf-contract: no measurement at {args.measure}")
        return 2
    if not args.baseline.exists():
        print(f"perf-contract: no baseline at {args.baseline}")
        return 2

    measure = load(args.measure)
    baseline = load(args.baseline)
    walls = walls_from_bench(load(args.bench)) if args.bench else {}
    ok, applicable, lines = verdict(measure, baseline, walls=walls)

    print("PERFORMANCE CONTRACT")
    print(f"  baseline  {args.baseline}  recorded {baseline.get('recorded_at', 'unknown')}")
    print(f"  measured  {args.measure}" + (f" + {args.bench}" if args.bench else ""))
    for line in lines:
        print(f"  {line}")

    if not applicable and args.require_applicable:
        print("perf-contract: the baseline does not apply here and --require-applicable was set")
        return 1
    if not ok:
        return 1
    print("  RESULT    " + ("envelope applied and met" if applicable else "recorded only"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
