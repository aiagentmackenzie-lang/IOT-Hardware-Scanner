"""Content-addressed cache for deterministic analysis outputs (slice 5C).

The entry condition was measured, not assumed: on the pinned OpenWrt image a
full scan spent about 83 % of its wall time re-deriving facts that are a pure
function of the file bytes, the rule set and the extractor version (per-file
YARA matches and per-file text facts). This module stores exactly those
outputs, nothing else.

The contract
------------
* **Key.** A cache entry is addressed by ``sha256(canonical_json(key))`` where
  the key names the *content* digest and every identity the result depends on:
  the compiled rule-set digest plus the YARA engine version for rule matches,
  the extractor version plus the text budget for text facts. Change the rule
  set, the engine or the extractor and the key changes; the old entry is simply
  never read again.
* **No artifact locations.** An entry stores rule names, match offsets and
  token sets — never a path. The caller rebinds the current locator when it
  reads the entry, so a moved file is still reported where it was observed.
* **Atomic.** Entries are written to a temporary file in the same directory and
  ``os.replace``d into place. A reader never sees a partial file; an interrupted
  writer leaves only a temporary file, which a later sweep removes.
* **Validated.** A read checks the format marker, the entry kind, the key echo
  and the value type. Anything else is discarded (and counted), then treated as
  a miss. A cache entry is never authoritative for a fact this run did not key.
* **Bounded.** The store is capped by entry count and by bytes; the oldest
  entries are evicted when a write pushes it over. A single value larger than
  the per-entry ceiling is not stored at all (and counted as skipped).
* **Offline.** This module performs only local filesystem operations.

The cache is opt-in: ``--cache-dir`` (or ``analysis_cache_dir``) points at it.
Without that setting a scan behaves exactly as before.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: Bumped when the on-disk entry shape changes; old entries are ignored.
CACHE_FORMAT = "ihs-analysis-cache/1"
#: Default ceiling on stored entries.
DEFAULT_MAX_ENTRIES = 20_000
#: Default ceiling on stored bytes.
DEFAULT_MAX_BYTES = 256 * 1024 * 1024
#: A single value larger than this is not worth storing.
MAX_VALUE_BYTES = 4 * 1024 * 1024


def canonical_key(kind: str, content_sha256: str, dependencies: dict[str, Any]) -> str:
    """The stable digest that names one cache entry."""
    payload = {
        "format": CACHE_FORMAT,
        "kind": kind,
        "content_sha256": content_sha256,
        "dependencies": dependencies,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class AnalysisCache:
    """A bounded, atomic, content-addressed store of parser outputs."""

    def __init__(
        self,
        root: Path,
        *,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> None:
        self.root = Path(root)
        self.max_entries = max(1, int(max_entries))
        self.max_bytes = max(1, int(max_bytes))
        self.stats: dict[str, int] = {
            "hits": 0,
            "misses": 0,
            "writes": 0,
            "invalid": 0,
            "evicted": 0,
            "skipped": 0,
        }
        self._sweep_temporaries()
        self._entries = 0
        self._bytes = 0
        self._scan_store()

    # ──────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────

    def get(self, kind: str, content_sha256: str, dependencies: dict[str, Any]) -> Any | None:
        """Return a stored value, or ``None`` for a miss or an invalid entry."""
        digest = canonical_key(kind, content_sha256, dependencies)
        path = self._path_for(digest)
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            self.stats["misses"] += 1
            return None
        except OSError as exc:
            logger.debug("cache read failed for %s: %s", path, exc)
            self.stats["invalid"] += 1
            self._discard(path)
            return None

        value = self._decode(
            raw,
            kind=kind,
            content_sha256=content_sha256,
            dependencies=dependencies,
            digest=digest,
        )
        if value is _INVALID:
            self.stats["invalid"] += 1
            self._discard(path)
            return None
        self.stats["hits"] += 1
        return value

    def put(
        self,
        kind: str,
        content_sha256: str,
        dependencies: dict[str, Any],
        value: Any,
    ) -> bool:
        """Store one value atomically. Returns whether it was stored."""
        try:
            encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError) as exc:  # pragma: no cover - programming error
            logger.debug("cache value for %s is not serialisable: %s", kind, exc)
            self.stats["skipped"] += 1
            return False
        if len(encoded.encode("utf-8")) > MAX_VALUE_BYTES:
            self.stats["skipped"] += 1
            return False

        digest = canonical_key(kind, content_sha256, dependencies)
        entry = {
            "format": CACHE_FORMAT,
            "kind": kind,
            "content_sha256": content_sha256,
            "dependencies": dependencies,
            "value": value,
        }
        path = self._path_for(digest)
        try:
            previous = path.stat().st_size
        except OSError:
            previous = 0
        payload = json.dumps(entry, sort_keys=True).encode("utf-8")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._write_atomic(path, payload)
        except OSError as exc:
            logger.debug("cache write failed for %s: %s", path, exc)
            self.stats["skipped"] += 1
            return False
        self.stats["writes"] += 1
        if previous == 0:
            self._entries += 1
        self._bytes = max(0, self._bytes - previous) + len(payload)
        self._evict_if_needed()
        return True

    def summary(self) -> dict[str, Any]:
        """A serialisable description of this cache for the report."""
        return {
            "enabled": True,
            "format": CACHE_FORMAT,
            "path": str(self.root),
            "entries": self._entries,
            "bytes": self._bytes,
            "max_entries": self.max_entries,
            "max_bytes": self.max_bytes,
            **self.stats,
            "note": (
                "Cache entries hold deterministic parser outputs keyed by content digest "
                "and the rule-set/extractor identity; artifact paths are never stored. "
                "A hit is still an observation of the same bytes and the same parser."
            ),
        }

    # ──────────────────────────────────────────
    # Internals
    # ──────────────────────────────────────────

    def _path_for(self, digest: str) -> Path:
        return self.root / digest[:2] / digest[2:4] / f"{digest}.json"

    @staticmethod
    def _write_atomic(path: Path, payload: bytes) -> None:
        descriptor, name = tempfile.mkstemp(prefix=".tmp-", dir=str(path.parent))
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        except BaseException:
            with contextlib.suppress(OSError):
                temporary.unlink(missing_ok=True)
            raise

    def _decode(
        self,
        raw: bytes,
        *,
        kind: str,
        content_sha256: str,
        dependencies: dict[str, Any],
        digest: str,
    ) -> Any:
        try:
            entry = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _INVALID
        if not isinstance(entry, dict):
            return _INVALID
        if entry.get("format") != CACHE_FORMAT or entry.get("kind") != kind:
            return _INVALID
        if entry.get("content_sha256") != content_sha256:
            return _INVALID
        if entry.get("dependencies") != dependencies:
            return _INVALID
        if canonical_key(kind, content_sha256, dependencies) != digest:
            return _INVALID
        if "value" not in entry:
            return _INVALID
        return entry["value"]

    def _discard(self, path: Path) -> None:
        with contextlib.suppress(OSError):
            path.unlink(missing_ok=True)

    def _sweep_temporaries(self) -> None:
        """Remove abandoned temporary files from an interrupted writer."""
        if not self.root.exists():
            return
        for temporary in self.root.rglob(".tmp-*"):
            if temporary.is_file():
                with contextlib.suppress(OSError):
                    temporary.unlink()

    def _entry_paths(self) -> list[Path]:
        if not self.root.exists():
            return []
        return [p for p in self.root.rglob("*.json") if p.is_file()]

    def _scan_store(self) -> None:
        """Measure the existing store once, then track deltas on write/evict."""
        for path in self._entry_paths():
            self._entries += 1
            try:
                self._bytes += path.stat().st_size
            except OSError:  # pragma: no cover - raced with eviction
                continue

    def _evict_if_needed(self) -> None:
        """Evict oldest entries until both ceilings hold again."""
        if self._entries <= self.max_entries and self._bytes <= self.max_bytes:
            return
        paths = self._entry_paths()
        try:
            paths.sort(key=lambda p: (p.stat().st_mtime, str(p)))
        except OSError:  # pragma: no cover - best effort
            return
        for path in paths:
            if self._entries <= self.max_entries and self._bytes <= self.max_bytes:
                break
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            self._discard(path)
            self._entries = max(0, self._entries - 1)
            self._bytes = max(0, self._bytes - size)
            self.stats["evicted"] += 1


class _Invalid:
    """Sentinel distinguishing "stored null" from "invalid entry"."""


_INVALID = _Invalid()


def sha256_file(path: Path, *, chunk_size: int = 64 * 1024) -> str | None:
    """Digest a file through bounded windows; ``None`` when it cannot be read."""
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while True:
                window = handle.read(chunk_size)
                if not window:
                    break
                digest.update(window)
    except OSError:
        return None
    return digest.hexdigest()


def default_cache_root() -> Path:
    """The conventional cache location when an operator enables caching."""
    return Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "ihs-analysis"
