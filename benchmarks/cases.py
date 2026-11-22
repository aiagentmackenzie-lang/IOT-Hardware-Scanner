"""Deterministic inputs and the four measured paths (slice P2).

These benchmarks live outside ``tests/`` on purpose: ``pyproject.toml`` sets
``testpaths = ["tests"]``, so a bare ``pytest`` never collects them and the
qualified suite keeps its runtime. Two entry points use this module:

``pytest benchmarks/``
    Wall time, through ``pytest-benchmark`` (rounds, min, mean, stddev).
    Produces ``--benchmark-json`` for the release record.

``python benchmarks/measure.py --out measure.json``
    Peak RSS, one subprocess per case so the number is attributable to that
    case, plus an independent wall-time cross-check.

Both feed ``benchmarks/perf_contract.py``, which owns the envelope.

Nothing here is product code. The fixtures are generated, not shipped: a
benchmark that depends on a downloaded corpus cannot run in CI, and a fixture
that is checked in ages into a different measurement.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import platform
import struct
import sys
from pathlib import Path
from typing import Any

import iot_hardware_scanner
from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.orchestrator import Orchestrator
from iot_hardware_scanner.scanner.bounded_reader import open_bounded
from iot_hardware_scanner.scanner.entropy_analyzer import EntropyAnalyzer
from iot_hardware_scanner.scanner.fit_dtb import board_description, parse_fdt

REPO_ROOT = Path(__file__).resolve().parent.parent

#: The four cases named in the P2 queue. Order matters: the cold run populates
#: nothing, the warm run reuses the cache the cold run wrote.
CASE_NAMES = ("cold-scan", "warm-scan", "fit-parse", "entropy-2gib")

#: pytest-benchmark groups its statistics by test function, so the mapping from
#: a recorded timing back to a case has to be explicit.
TEST_TO_CASE = {
    "test_cold_scan_tree": "cold-scan",
    "test_warm_scan_tree": "warm-scan",
    "test_parse_dtb": "fit-parse",
    "test_entropy_2gib": "entropy-2gib",
}

#: Size of the generated root tree. The 2.4 profile was measured on a 109 MB
#: gzip-expanded OpenWrt rootfs; 100 MiB keeps the same order of magnitude
#: without shipping the image.
TREE_TARGET_BYTES = 100 * 1024 * 1024

#: The queue asked for a ~1 MiB device tree: big enough that the parse, not the
#: process start, is what is being timed.
DTB_MIN_BYTES = 1 * 1024 * 1024

#: The bounded-resources job already measures this file size for a ceiling. The
#: same size is measured here against a baseline, so a regression in the
#: windowed reader is visible as a slope, not just as a pass.
ENTROPY_BYTES = 2 * 1024 * 1024 * 1024

ENTROPY_BLOCK = 16 * 1024 * 1024

ELF_FIXTURES = REPO_ROOT / "tests" / "elf_fixtures.py"
FDT_FIXTURES = REPO_ROOT / "tests" / "fdt_fixtures.py"


# ──────────────────────────────────────────────
# Work directory and fixtures
# ──────────────────────────────────────────────


def workdir() -> Path:
    """Where generated inputs live. Override with ``IHS_PERF_WORKDIR``."""
    return Path(os.environ.get("IHS_PERF_WORKDIR", Path.home() / ".cache" / "ihs-perf"))


def _load_module(name: str, path: Path) -> Any:
    """Load a reviewed fixture generator from ``tests/`` by path.

    The FDT and ELF builders already exist as reviewed, byte-level fixtures.
    Copying them here would let two generators drift, and the benchmark would
    then be measuring a different artifact than the acceptance rows.
    """
    spec = importlib.util.spec_from_file_location(f"_perf_{name}", path)
    if spec is None or spec.loader is None:  # pragma: no cover - import guard
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _pseudo_bytes(seed: str, length: int) -> bytes:
    """Deterministic, incompressible-ish bytes without touching ``random``."""
    out = bytearray()
    block_seed = seed.encode()
    while len(out) < length:
        block_seed = hashlib.blake2b(block_seed, digest_size=64).digest()
        out += block_seed
    return bytes(out[:length])


def _stream_to(path: Path, seed: str, length: int, *, chunk: int = 1 << 20) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        written = 0
        index = 0
        while written < length:
            want = min(chunk, length - written)
            handle.write(_pseudo_bytes(f"{seed}:{index}", want))
            written += want
            index += 1


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _opkg_status(packages: int) -> str:
    stanzas = []
    for index in range(packages):
        stanzas.append(
            f"Package: perf-pkg-{index:04d}\n"
            f"Version: 1.{index % 17}.{index % 251}\n"
            "Depends: libc, libpthread\n"
            f"Status: install user installed\n"
            f"Architecture: aarch64_generic\n"
            f"Installed-Size: {1024 + index * 7}\n"
            f"Description: Generated package {index} for the performance fixture\n"
        )
    return "\n".join(stanzas) + "\n"


def _passwd(users: int) -> str:
    lines = ["root:x:0:0:root:/root:/bin/ash"]
    for index in range(users):
        lines.append(
            f"svc{index:03d}:x:{1000 + index}:{1000 + index}:"
            f"service {index}:/var/run/svc{index:03d}:/bin/false"
        )
    return "\n".join(lines) + "\n"


def _shadow(users: int) -> str:
    lines = ["root:$1$perf$0123456789abcdefghijkl:19000:0:99999:7:::"]
    for index in range(users):
        lines.append(
            f"svc{index:03d}:$6$perf{index:03d}$abcdefghijklmnopqrstuvwxyz0123456789"
            ":19000:0:99999:7:::"
        )
    return "\n".join(lines) + "\n"


def _plan() -> list[tuple[str, int, str]]:
    """The tree's file plan: (relative path, bytes, kind).

    Deterministic and content-free, so its digest identifies the fixture
    without hashing 100 MiB every run.
    """
    plan: list[tuple[str, int, str]] = []

    # 200 valid ELFs: the scan's most expensive per-file parser after YARA.
    for index in range(200):
        plan.append((f"usr/bin/perf-tool-{index:03d}", 0, "elf"))

    plan.append(("usr/lib/opkg/status", 0, "opkg"))
    plan.append(("etc/passwd", 0, "passwd"))
    plan.append(("etc/shadow", 0, "shadow"))

    for index in range(40):
        plan.append((f"etc/config/perf-{index:02d}.conf", 4096, "text"))
    for index in range(30):
        plan.append((f"etc/init.d/service-{index:02d}", 2048, "script"))
    for index in range(60):
        plan.append((f"www/assets/bundle-{index:02d}.js", 32 * 1024, "text"))

    # The bulk. Strings are embedded in every blob so the text extractor and the
    # domain detector do real work rather than seeing pure noise. The count is
    # derived from TREE_TARGET_BYTES so the declared size and the built size
    # cannot drift apart.
    blob_size = 4 * 1024 * 1024
    fixed = (
        sum(size for _rel, size, kind in plan if kind in ("text", "script"))
        + len([1 for _rel, _size, kind in plan if kind == "elf"]) * 2500
    )
    blobs = max(1, round((TREE_TARGET_BYTES - fixed) / blob_size))
    for index in range(blobs):
        plan.append((f"usr/share/firmware/blob-{index:02d}.bin", blob_size, "blob"))

    return plan


def plan_fingerprint() -> str:
    canonical = json.dumps([list(item) for item in _plan()], separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _blob(seed: str, length: int) -> bytes:
    """High-entropy bulk with periodic URLs and credential-shaped strings."""
    body = bytearray(_pseudo_bytes(seed, length))
    marker = (
        b"\nhttp://update{0}.cdn.example{0}.com/api/v1/check"
        b"?device=perf&build={0:04d}\n"
        b'password = "perfsecret{0:04d}"\n'
        b"192.168.{1}.{2} telnet://admin:admin@10.0.0.{2}:23\n"
    )
    stride = 4096
    for offset in range(0, len(body) - 256, stride):
        stamp = (offset // stride) % 10000
        line = marker.replace(b"{0}", str(stamp).encode())
        line = line.replace(b"{1}", str(stamp % 254).encode())
        line = line.replace(b"{2}", str((stamp * 7) % 254).encode())
        body[offset : offset + len(line)] = line
    return bytes(body)


def ensure_tree(root: Path | None = None) -> Path:
    """Materialise the 100 MiB tree once, keyed by the plan digest."""
    base = root or (workdir() / "tree")
    marker = base.with_suffix(".plan.json")
    fingerprint = plan_fingerprint()
    if marker.exists() and base.is_dir():
        try:
            if json.loads(marker.read_text())["plan"] == fingerprint:
                return base
        except (ValueError, KeyError):
            pass

    if base.exists():
        import shutil

        shutil.rmtree(base)
    base.mkdir(parents=True)

    elf_fixtures = _load_module("elf_fixtures", ELF_FIXTURES)
    pie = elf_fixtures.build_elf(elf_fixtures.ElfSpec())
    static = elf_fixtures.build_elf(
        elf_fixtures.ElfSpec(
            elf_class=32,
            little_endian=False,
            machine=8,
            elf_type=2,
            interpreter=None,
            needed=[],
            bind_now=False,
            gnu_relro=False,
            dynamic=False,
            symbols=[],
            build_id=None,
        )
    )

    written = 0
    for index, (rel, size, kind) in enumerate(_plan()):
        path = base / rel
        if kind == "elf":
            data = pie if index % 2 == 0 else static
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            written += len(data)
        elif kind == "opkg":
            text = _opkg_status(400)
            _write_text(path, text)
            written += len(text)
        elif kind == "passwd":
            text = _passwd(40)
            _write_text(path, text)
            written += len(text)
        elif kind == "shadow":
            text = _shadow(40)
            _write_text(path, text)
            written += len(text)
        elif kind == "text":
            text = (
                f"# generated perf fixture {rel}\n"
                + "\n".join(
                    f"option_{line}=value_{line}_{rel}" for line in range(max(1, size // 40))
                )
                + "\n"
            )
            _write_text(path, text)
            written += len(text)
        elif kind == "script":
            text = (
                "#!/bin/sh\n# generated perf fixture\n"
                + "\n".join(
                    f'echo "service {line} starting" && /usr/sbin/perf-tool-{line:03d}'
                    for line in range(max(1, size // 50))
                )
                + "\n"
            )
            _write_text(path, text)
            written += len(text)
        else:
            blob = _blob(f"{rel}", size)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(blob)
            written += len(blob)

    marker.write_text(json.dumps({"plan": fingerprint, "bytes": written}, sort_keys=True))
    return base


def build_dtb(path: Path) -> Path:
    """A ~1 MiB device tree with a wide, shallow node set.

    The parser caps a device tree at 4096 nodes and 16384 properties, so the
    size is reached with a realistic number of nodes and a fat ``description``
    property rather than with an artificial node count. That keeps the case an
    honest parse of a legal artifact instead of a fixture that the bounds check
    rejects.
    """
    fdt = _load_module("fdt_fixtures", FDT_FIXTURES)

    def serialise(padding: int) -> bytes:
        root = fdt.Node("")
        root.add_strings("compatible", ["perf,board", "perf,soc"])
        root.add_str("model", "IHS Performance Board")
        root.add_u32("#address-cells", 2)
        root.add_u32("#size-cells", 1)
        for index in range(3000):
            node = fdt.Node(f"peripheral@{index:08x}")
            node.add_str("compatible", f"perf,peripheral-{index % 32}")
            node.add("reg", struct.pack(">III", 0, 0x40000000 + index * 0x1000, 0x1000))
            node.add_str(
                "description",
                (f"peripheral {index}: " + "generated performance fixture " * 16)[:padding],
            )
            root.child(node)
        return fdt.build_fdt(root)

    padding = 240
    data = serialise(padding)
    for _ in range(8):
        if len(data) >= DTB_MIN_BYTES:
            break
        padding += max(8, (DTB_MIN_BYTES - len(data)) // 3000 + 8)
        data = serialise(padding)
    else:  # pragma: no cover - the loop converges on every observed platform
        raise RuntimeError(f"device-tree fixture stalled at {len(data)} bytes")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def cache_identity() -> str:
    """What a populated cache depends on, so a stale one cannot be measured warm.

    The fixture plan alone is not enough: the per-file facts carry an extractor
    version and the match sets carry a rule-set digest. When either moves, every
    entry misses, and a "warm" benchmark would silently time a cold run (2.6
    changed the facts extractor and did exactly that until this was keyed).
    """
    from iot_hardware_scanner.scanner.c2_detector import TEXT_FACTS_VERSION
    from iot_hardware_scanner.yara.yara_engine import YaraEngine

    engine = YaraEngine(ScannerConfig())
    engine.load_rules()
    payload = f"{iot_hardware_scanner.__version__}:{TEXT_FACTS_VERSION}:{engine.digest}"
    return hashlib.sha256(payload.encode()).hexdigest()


def ensure_entropy_file(path: Path) -> Path:
    """A sparse 2 GiB file: the size the resource ceiling is stated in."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() or path.stat().st_size != ENTROPY_BYTES:
        with path.open("wb") as handle:
            handle.truncate(ENTROPY_BYTES)
    return path


def fixture_summary() -> dict[str, Any]:
    base = workdir()
    tree = base / "tree"
    dtb = base / "perf.dtb"
    summary: dict[str, Any] = {"plan": plan_fingerprint()}
    if tree.is_dir():
        files = [p for p in tree.rglob("*") if p.is_file()]
        summary["tree_files"] = len(files)
        summary["tree_bytes"] = sum(p.stat().st_size for p in files)
    if dtb.exists():
        summary["dtb_bytes"] = dtb.stat().st_size
    summary["entropy_bytes"] = ENTROPY_BYTES
    return summary


# ──────────────────────────────────────────────
# The four measured paths
# ──────────────────────────────────────────────


def _config(cache_dir: Path | None, *, entropy: bool = False) -> ScannerConfig:
    config = ScannerConfig()
    config.offline_mode = True
    config.output_dir = workdir() / "out"
    config.analysis_cache_dir = cache_dir
    if entropy:
        # The default samples above 256 MiB. The point of this case is the
        # windowed pass over the whole file, so the ceiling is lifted the same
        # way the bounded-resources job lifts it, and the block size is fixed so
        # two releases measure the same windows.
        config.max_entropy_scan_size_mb = 4096
    return config


def scan_tree(tree: Path, cache_dir: Path | None = None) -> dict[str, Any]:
    """One full ``firmware-tree`` scan: the product's hot path, no worker."""
    orchestrator = Orchestrator(_config(cache_dir), input_tree=True)
    context = orchestrator.run(tree)
    inventory = context.filesystem_inventory
    return {
        "files": len(context.tree_manifest),
        "findings": len(inventory.findings) if inventory is not None else 0,
        "elf": len(context.elf_metadata),
        "packages": context.opkg_inventory.installed_count
        if context.opkg_inventory is not None
        else 0,
        "assessment": context.assessment.completion.value if context.assessment else None,
        "cache": context.cache_summary,
    }


def parse_dtb(path: Path) -> dict[str, Any]:
    """Parse one device tree through the shipped 3D parser."""
    parsed = parse_fdt(open_bounded(path))
    board = board_description(parsed)
    return {"nodes": len(parsed.root.walk()), "compatible": len(board["compatible"])}


def entropy_2gib(path: Path) -> dict[str, Any]:
    """The whole-file windowed entropy pass, at the resource ceiling's size."""
    analyzer = EntropyAnalyzer(_config(None, entropy=True))
    profile = analyzer.analyze_file(path, block_size=ENTROPY_BLOCK)
    return {
        "blocks": len(profile.blocks),
        "sampled": profile.bytes_sampled,
        "bytes": profile.bytes_analyzed,
    }


def run_case(name: str) -> dict[str, Any]:
    """Dispatch one case by name on already-prepared fixtures."""
    base = workdir()
    if name == "cold-scan":
        return scan_tree(base / "tree")
    if name == "warm-scan":
        return scan_tree(base / "tree", base / "cache")
    if name == "fit-parse":
        return parse_dtb(base / "perf.dtb")
    if name == "entropy-2gib":
        return entropy_2gib(base / "entropy-2gib.bin")
    raise SystemExit(f"unknown case {name!r}; expected one of {', '.join(CASE_NAMES)}")


def prepare_all() -> None:
    """Build every fixture and populate the cache used by the warm case."""
    base = workdir()
    base.mkdir(parents=True, exist_ok=True)
    tree = ensure_tree()
    build_dtb(base / "perf.dtb")
    ensure_entropy_file(base / "entropy-2gib.bin")
    # The warm case needs a populated cache. Populate it once, outside any
    # measured round, and key the marker to the fixture plan so a rebuilt tree
    # cannot be measured against entries for the old one.
    marker = base / "cache-populated.json"
    cache = base / "cache"
    identity = {"plan": plan_fingerprint(), "cache": cache_identity()}
    stale = True
    if marker.exists():
        try:
            stale = json.loads(marker.read_text()) != identity
        except ValueError:
            stale = True
    if stale:
        scan_tree(tree, cache)
        marker.write_text(json.dumps(identity, sort_keys=True))


def environment_fingerprint() -> dict[str, Any]:
    """What makes a baseline applicable. A mismatch is not a pass."""
    try:
        import yara

        yara_version = getattr(yara, "__version__", "unknown")
    except Exception:  # pragma: no cover - import guard
        yara_version = "unavailable"
    return {
        "system": platform.system(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "yara": str(yara_version),
        "engine": iot_hardware_scanner.__version__,
        "fixtures": plan_fingerprint(),
    }
