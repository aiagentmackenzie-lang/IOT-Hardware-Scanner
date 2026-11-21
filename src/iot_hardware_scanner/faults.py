"""Fault injection for the acceptance harness (never enabled in production).

Three release-gate rows cannot be produced from a benign artifact on demand:

* a build output replaced between ingest and analysis (2D);
* an extraction worker that exceeds its deadline (2A);
* a helper that exits non-zero after decoding begins (2A).

Each of those paths must be exercised *through the installed CLI*, not only at
the decision-function level, so the harness needs a way to reach them
deterministically. This module is that way, and it is deliberately small and
obvious: it does nothing at all unless ``IHS_TEST_FAULTS`` names a fault, and
every use is recorded in the scan's limitations so a report cannot pretend it
was produced without one.

Accepted values (comma separated)
---------------------------------
``replace-input-after-ingest``
    Rewrite the input with different bytes after it has been hashed and before
    it is bound to the snapshot. The scan must refuse to attribute the new bytes
    to the recorded digest.
``replace-input-after-bind``
    Rewrite the input after the verified snapshot exists. The snapshot stays in
    use and the report records that the source changed -- the other documented
    outcome of the same situation.
``extraction-timeout``
    Run a worker command that never finishes, so the wall-clock deadline fires.
``extraction-nonzero``
    Make the helper exit non-zero without producing a tree.
"""

from __future__ import annotations

import os
from pathlib import Path

ENV_VAR = "IHS_TEST_FAULTS"

FAULT_REPLACE_INPUT = "replace-input-after-ingest"
FAULT_REPLACE_AFTER_BIND = "replace-input-after-bind"
FAULT_EXTRACTION_TIMEOUT = "extraction-timeout"
FAULT_EXTRACTION_NONZERO = "extraction-nonzero"

KNOWN_FAULTS = frozenset(
    {
        FAULT_REPLACE_INPUT,
        FAULT_REPLACE_AFTER_BIND,
        FAULT_EXTRACTION_TIMEOUT,
        FAULT_EXTRACTION_NONZERO,
    }
)


def active(environ: dict[str, str] | None = None) -> set[str]:
    """Faults requested for this process, ignoring anything unrecognised."""
    environ = dict(os.environ) if environ is None else environ
    raw = environ.get(ENV_VAR, "")
    return {item.strip() for item in raw.split(",") if item.strip() in KNOWN_FAULTS}


def enabled(fault: str, environ: dict[str, str] | None = None) -> bool:
    """Whether one fault is active."""
    return fault in active(environ)


def replace_input(path: Path, message: str) -> None:
    """Overwrite ``path`` with different bytes, keeping its recorded digest.

    The replacement is deliberately *not* the same length as a normal edit so a
    stale cached digest cannot accidentally match.
    """
    path = Path(path)
    path.write_bytes(message.encode("utf-8") + b"\x00" * 64)
