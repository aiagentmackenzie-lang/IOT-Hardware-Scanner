"""Record wall time and peak RSS per case, one subprocess per case.

``pytest-benchmark`` measures wall time well and memory not at all. Peak RSS is
also not resettable inside a process, so a shared pytest run would charge the
largest case's high-water mark to every case after it. Each case therefore runs
in its own child, which reports its own ``ru_maxrss`` and its own elapsed time.

Usage::

    python benchmarks/measure.py --out measure.json      # all four cases
    python benchmarks/measure.py --case fit-parse         # one case, in this process
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cases


def peak_rss_bytes() -> int:
    """Peak RSS of this process, normalised to bytes.

    ``ru_maxrss`` is bytes on macOS and kibibytes on Linux; the baseline is
    only ever compared on a matching fingerprint, but the number is stored in
    one unit so a human can read two records side by side.
    """
    import resource

    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return int(value)
    return int(value) * 1024


def run_one(name: str) -> dict[str, Any]:
    started = time.perf_counter()
    result = cases.run_case(name)
    elapsed = time.perf_counter() - started
    return {
        "case": name,
        "wall_seconds": round(elapsed, 6),
        "peak_rss_bytes": peak_rss_bytes(),
        "result": result,
    }


def child(name: str) -> int:
    # A child may be invoked on its own (an operator reproducing one number);
    # building the fixtures first keeps the measured region identical either way.
    cases.prepare_all()
    record = run_one(name)
    print(json.dumps(record))
    return 0


def parent(names: list[str], out: Path) -> int:
    cases.prepare_all()
    records = []
    for name in names:
        completed = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--case", name],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            sys.stderr.write(completed.stdout)
            sys.stderr.write(completed.stderr)
            print(f"measure: case {name!r} failed with exit {completed.returncode}")
            return 1
        lines = [line for line in completed.stdout.splitlines() if line.strip()]
        try:
            record = json.loads(lines[-1])
        except (IndexError, ValueError):
            print(f"measure: case {name!r} produced no record\n{completed.stdout}")
            return 1
        record["stderr"] = completed.stderr.strip()[-2000:]
        records.append(record)
        print(
            f"{name:<14} wall {record['wall_seconds']:.3f} s   "
            f"peak RSS {record['peak_rss_bytes'] / (1024 * 1024):.1f} MiB"
        )

    document = {
        "format": "ihs-perf-measure/1",
        "fingerprint": cases.environment_fingerprint(),
        "fixtures": cases.fixture_summary(),
        "cases": {record["case"]: record for record in records},
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(f"measure: wrote {out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=cases.CASE_NAMES, help="run one case in this process")
    parser.add_argument("--out", type=Path, default=None, help="write the full record here")
    parser.add_argument(
        "--cases",
        nargs="+",
        choices=cases.CASE_NAMES,
        default=list(cases.CASE_NAMES),
        help="which cases to run (default: all four)",
    )
    args = parser.parse_args(argv)

    if args.case:
        return child(args.case)
    out = args.out or (cases.workdir() / "measure.json")
    return parent(list(args.cases), out)


if __name__ == "__main__":
    raise SystemExit(main())
