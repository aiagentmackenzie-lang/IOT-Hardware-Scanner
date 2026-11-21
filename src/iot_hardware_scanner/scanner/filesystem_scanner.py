"""Filesystem Scanner — Phase 2b.

Walks one filesystem root and indexes every regular file by security relevance.
This is the index every later stage reads: credential scanning, the Unix account
join, C2 indicators and the ELF/opkg inventory all address files through it.

Identity (slice 2B)
-------------------
* **Root identity.** Two roots may both contain ``etc/shadow``; each file's
  locator is therefore qualified by its root (``slot_b/etc/shadow``), following
  the convention the Unix account reader already used. A locator never
  collides with the same path in another root.
* **Metadata provenance.** ``metadata`` may carry mode/uid/gid from the image's
  own tar record or from a build manifest the operator supplied. When it does
  not, values are read from this host and marked ``host``. A permission-based
  conclusion may only rest on image or declared metadata.
* **Hardlinks.** Entries sharing a device/inode — or a manifest hardlink
  target — are reconciled into one group, so one file is not counted twice and
  a link does not become a second, independent copy of the same bytes.

Every read here is bounded. A file's format is decided from its first four
bytes, never from its extension or its service category.
"""

from __future__ import annotations

import hashlib
import logging
import stat
from pathlib import Path

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import (
    BootEvidence,
    FileCategory,
    FilesystemFinding,
    FilesystemInventory,
    RootIdentity,
)
from iot_hardware_scanner.scanner.bounded_reader import (
    DEFAULT_TEXT_BUDGET,
    open_bounded,
)

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# File categorization patterns (SDR §8.2 Table)
# ──────────────────────────────────────────────

CATEGORY_PATTERNS: dict[FileCategory, list[str]] = {
    FileCategory.CRITICAL_CREDENTIAL: [
        "etc/passwd",
        "etc/shadow",
        "etc/gshadow",
    ],
    FileCategory.CRITICAL_CONFIG: [
        "etc/inittab",
        "etc/fstab",
        "etc/hosts",
        ".conf",
        ".cfg",
        ".ini",
        ".config",
    ],
    FileCategory.CRITICAL_SERVICE: [
        "sshd",
        "telnetd",
        "dropbear",
        "httpd",
        "nginx",
        "lighttpd",
        "vsftpd",
        "tftpd",
        "snmpd",
    ],
    FileCategory.CRITICAL_SCRIPT: [
        "etc/init.d/",
        "etc/rc.d/",
        "etc/rc.local",
        "etc/rcS.d/",
    ],
    FileCategory.HIGH_API_KEY: [
        ".env",
        "credentials",
        "secrets",
    ],
    FileCategory.HIGH_CRYPTO: [
        ".pem",
        ".crt",
        ".p12",
        ".jks",
        ".pfx",
        ".cer",
    ],
    FileCategory.HIGH_DATABASE: [
        ".db",
        ".sqlite",
        ".sql",
    ],
    FileCategory.MEDIUM_LOG: [
        ".log",
        "var/log/",
    ],
    FileCategory.MEDIUM_WEB: [
        "www/",
        "htdocs/",
        ".cgi",
        ".php",
        ".asp",
    ],
}

EXTENSION_CATEGORIES: dict[str, FileCategory] = {
    ".key": FileCategory.CRITICAL_CREDENTIAL,
    ".pem": FileCategory.HIGH_CRYPTO,
    ".crt": FileCategory.HIGH_CRYPTO,
    ".p12": FileCategory.HIGH_CRYPTO,
    ".jks": FileCategory.HIGH_CRYPTO,
    ".pfx": FileCategory.HIGH_CRYPTO,
    ".cer": FileCategory.HIGH_CRYPTO,
    ".db": FileCategory.HIGH_DATABASE,
    ".sqlite": FileCategory.HIGH_DATABASE,
    ".conf": FileCategory.CRITICAL_CONFIG,
    ".cfg": FileCategory.CRITICAL_CONFIG,
    ".ini": FileCategory.CRITICAL_CONFIG,
    ".sh": FileCategory.CRITICAL_SCRIPT,
    ".log": FileCategory.MEDIUM_LOG,
    ".cgi": FileCategory.MEDIUM_WEB,
    ".php": FileCategory.MEDIUM_WEB,
    ".asp": FileCategory.MEDIUM_WEB,
}

SERVICE_BINARIES: set[str] = {
    "sshd",
    "telnetd",
    "dropbear",
    "httpd",
    "nginx",
    "lighttpd",
    "vsftpd",
    "tftpd",
    "snmpd",
}

HASH_SIZE_LIMIT = 10 * 1024 * 1024  # Hash files below this size in-line

#: Header signatures, read from the file itself. Extension plays no part.
FORMAT_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
    (b"\xfe\xed\xfa\xce", "macho"),
    (b"\xce\xfa\xed\xfe", "macho"),
    (b"\xcf\xfa\xed\xfe", "macho"),
)


def _fmt_size(n: int) -> str:
    """Format byte count as human-readable size."""
    value = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def detect_format(path: Path) -> str:
    """The file's format, from its first bytes only."""
    try:
        header = open_bounded(Path(path)).read_head(4)
    except (OSError, ValueError):
        return "other"
    for signature, name in FORMAT_SIGNATURES:
        if header.startswith(signature):
            return name
    return "other"


class FilesystemScanner:
    """Walk one filesystem root and categorize every regular file."""

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config

    # ──────────────────────────────────────────
    # The walk
    # ──────────────────────────────────────────

    def scan(
        self,
        rootfs_path: Path,
        *,
        root_id: str | None = None,
        artifact_id: str | None = None,
        metadata: dict[str, dict] | None = None,
        metadata_source: str | None = None,
    ) -> FilesystemInventory:
        """Walk ``rootfs_path`` and categorize every regular file.

        ``metadata`` maps a root-relative path to the mode/uid/gid/sha256 the
        image or a declaration recorded for it. ``metadata_source`` defaults to
        ``image`` when metadata is supplied, ``host`` otherwise.
        """
        rootfs_path = Path(rootfs_path).resolve()
        label = root_id or rootfs_path.name or "rootfs"
        source = metadata_source or ("image" if metadata else "host")

        if not rootfs_path.exists() or not rootfs_path.is_dir():
            logger.warning("Root filesystem path invalid: %s", rootfs_path)
            return FilesystemInventory(
                rootfs_path=rootfs_path,
                metadata_source="host",
                roots=[
                    RootIdentity(
                        root_id=label,
                        locator=str(rootfs_path),
                        metadata_source="host",
                        omissions=["the root path does not exist or is not a directory"],
                    )
                ],
            )

        findings: list[FilesystemFinding] = []
        categories: dict[FileCategory, list[FilesystemFinding]] = {cat: [] for cat in FileCategory}
        total_dirs = 0
        total_size = 0
        permission_unknown = 0
        inodes: dict[tuple[int, int], str] = {}
        skipped = 0

        for entry in sorted(rootfs_path.rglob("*")):
            if entry.is_symlink():
                skipped += 1
                continue
            if entry.is_dir():
                total_dirs += 1
                continue
            if not entry.is_file():
                skipped += 1
                continue
            try:
                finding = self._categorize_file(
                    entry,
                    rootfs_path,
                    root_id=label,
                    metadata=(metadata or {}).get(str(entry.relative_to(rootfs_path).as_posix())),
                    metadata_source=source,
                    artifact_id=artifact_id,
                )
            except (OSError, PermissionError) as exc:
                logger.debug("Skipping file (access error): %s — %s", entry, exc)
                skipped += 1
                continue

            # Hardlink reconciliation: the same inode is one file, however many
            # names point at it.
            stat_key = self._inode_key(entry)
            if stat_key is not None and stat_key in inodes:
                group = inodes[stat_key]
                finding.hardlink_group = group
                finding.hardlink_count = 0
                for existing in findings:
                    if existing.path and str(existing.path).endswith(group):
                        existing.hardlink_count += 1
                        break
                continue
            if stat_key is not None:
                inodes[stat_key] = str(finding.path)

            if finding.mode is None:
                permission_unknown += 1
            findings.append(finding)
            categories[finding.category].append(finding)
            total_size += finding.file_size

        inventory = FilesystemInventory(
            rootfs_path=rootfs_path,
            total_files=len(findings),
            total_directories=total_dirs,
            total_size=total_size,
            findings=findings,
            categories=categories,
            metadata_source=source,
            permission_unknown_count=permission_unknown,
            roots=[
                RootIdentity(
                    root_id=label,
                    locator=str(rootfs_path),
                    files=len(findings),
                    directories=total_dirs,
                    bytes=total_size,
                    metadata_source=source,
                    artifact_id=artifact_id,
                    omissions=(
                        [f"{skipped} non-regular entr(ies) indexed as metadata only"]
                        if skipped
                        else []
                    ),
                )
            ],
        )

        inventory.suid_binaries = [f for f in findings if f.is_suid]
        inventory.world_writable_files = [f for f in findings if f.is_world_writable]
        inventory.shadow_files = categories.get(FileCategory.CRITICAL_CREDENTIAL, [])
        inventory.ssl_cert_files = categories.get(FileCategory.HIGH_CRYPTO, [])
        inventory.init_scripts = categories.get(FileCategory.CRITICAL_SCRIPT, [])
        inventory.network_services = categories.get(FileCategory.CRITICAL_SERVICE, [])

        logger.info(
            "Filesystem scan complete (%s): %d files, %d dirs, %d SUID, %d world-writable, "
            "metadata from %s",
            label,
            inventory.total_files,
            inventory.total_directories,
            len(inventory.suid_binaries),
            len(inventory.world_writable_files),
            source,
        )
        return inventory

    @staticmethod
    def _inode_key(entry: Path) -> tuple[int, int] | None:
        try:
            result = entry.lstat()
        except OSError:  # pragma: no cover - race with the writer
            return None
        if result.st_nlink <= 1:
            return None
        return (result.st_dev, result.st_ino)

    def get_files_by_category(
        self, inventory: FilesystemInventory, category: FileCategory
    ) -> list[FilesystemFinding]:
        """Return all files matching a security category."""
        return inventory.categories.get(category, [])

    # ──────────────────────────────────────────
    # Boot evidence
    # ──────────────────────────────────────────

    def collect_boot_evidence(
        self, rootfs_path: Path, *, root_id: str | None = None
    ) -> list[BootEvidence]:
        """Read configured startup directives from one root filesystem.

        Only genuinely configured directives are returned as ``configured``. A
        commented-out example is recorded with ``configured=False`` so the report
        can show it was seen and deliberately not counted.

        Directives understood: SysV-style ``inittab`` actions (``sysinit``,
        ``respawn``, ``wait``, ``once``, ``boot``) and ``start``/``restart``
        invocations in init scripts and ``rc.local``. Every read is bounded.
        """
        rootfs_path = Path(rootfs_path)
        label = root_id or rootfs_path.name or "rootfs"
        evidence: list[BootEvidence] = []

        inittab = rootfs_path / "etc" / "inittab"
        if inittab.is_file() and not inittab.is_symlink():
            evidence.extend(self._inittab_evidence(inittab, rootfs_path, label))

        script_paths: list[Path] = []
        init_d = rootfs_path / "etc" / "init.d"
        if init_d.is_dir():
            script_paths.extend(sorted(p for p in init_d.iterdir() if p.is_file()))
        for extra in (rootfs_path / "etc" / "rc.local", rootfs_path / "etc" / "rcS.local"):
            if extra.is_file() and not extra.is_symlink():
                script_paths.append(extra)

        for script in script_paths:
            evidence.extend(self._script_evidence(script, rootfs_path, label))

        return evidence

    def _bounded_lines(self, path: Path) -> list[tuple[int, int, str]] | None:
        """``(line number, byte offset, text)`` for a small text file, or ``None``."""
        budget = min(
            DEFAULT_TEXT_BUDGET,
            self.config.max_scan_file_size_mb * 1024 * 1024,
        )
        try:
            reader = open_bounded(path)
            if reader.size > budget:
                logger.debug("Skipping oversized text read: %s (%s)", path, _fmt_size(reader.size))
                return None
            return [
                (line.number, line.offset, line.text) for line in reader.iter_lines(budget=budget)
            ]
        except (OSError, ValueError) as exc:
            logger.debug("Cannot read %s: %s", path, exc)
            return None

    def _inittab_evidence(self, path: Path, rootfs: Path, root_id: str) -> list[BootEvidence]:
        actions = {"sysinit", "respawn", "wait", "once", "boot", "bootwait"}
        out: list[BootEvidence] = []
        lines = self._bounded_lines(path)
        if lines is None:
            return out
        for line_no, _offset, raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue
            configured = not stripped.startswith("#")
            body = stripped.lstrip("#").strip()
            fields = body.split(":", 3)
            if len(fields) < 4:
                continue
            _ident, _runlevels, action, program = fields
            if action.strip() not in actions:
                continue
            out.append(
                BootEvidence(
                    root_id=root_id,
                    source=f"{root_id}/{path.relative_to(rootfs).as_posix()}",
                    line_number=line_no,
                    directive=stripped,
                    action=action.strip(),
                    program=program.strip(),
                    configured=configured,
                )
            )
        return out

    def _script_evidence(self, path: Path, rootfs: Path, root_id: str) -> list[BootEvidence]:
        out: list[BootEvidence] = []
        lines = self._bounded_lines(path)
        if lines is None:
            return out
        for line_no, _offset, raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue
            configured = not stripped.startswith("#")
            body = stripped.lstrip("#").strip()
            tokens = body.split()
            for index, token in enumerate(tokens):
                if token not in ("start", "restart") or index == 0:
                    continue
                target = tokens[index - 1]
                if target in {"if", "then", "&&", ";", "do"}:
                    continue
                out.append(
                    BootEvidence(
                        root_id=root_id,
                        source=f"{root_id}/{path.relative_to(rootfs).as_posix()}",
                        line_number=line_no,
                        directive=stripped,
                        action=token,
                        program=target,
                        configured=configured,
                    )
                )
                break
        return out

    def analyze_boot_process(self, inventory: FilesystemInventory) -> dict[str, list[str]]:
        """Analyze the boot process for security-relevant observations."""
        result: dict[str, list[str]] = {
            "init_system": [],
            "inittab_entries": [],
            "init_scripts": [],
            "services": [],
            "findings": [],
        }
        rootfs = inventory.rootfs_path

        init_paths = (
            rootfs / "sbin" / "init",
            rootfs / "bin" / "init",
            rootfs / "sbin" / "busybox",
        )
        for path in init_paths:
            if path.exists():
                result["init_system"].append(path.name)
                if path.name == "busybox":
                    result["findings"].append(
                        "BusyBox init detected — common in embedded, check for default credentials"
                    )

        inittab = rootfs / "etc" / "inittab"
        if inittab.is_file():
            for line_no, _offset, line in self._bounded_lines(inittab) or []:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if ":respawn:" in stripped or ":sysinit:" in stripped:
                    result["inittab_entries"].append(f"{line_no}: {stripped}")
                    for service in SERVICE_BINARIES:
                        if service in stripped:
                            result["findings"].append(
                                f"Service '{service}' configured in inittab: {stripped}"
                            )

        init_d = rootfs / "etc" / "init.d"
        if init_d.is_dir():
            for script in sorted(init_d.iterdir()):
                if script.is_file() and not script.is_symlink():
                    result["init_scripts"].append(script.name)
                    self._check_script_for_services(script, result["services"], result["findings"])

        for rc_path in (rootfs / "etc" / "rc.local", rootfs / "etc" / "rcS.d"):
            if rc_path.is_file():
                self._check_script_for_services(rc_path, result["services"], result["findings"])

        result["services"] = sorted(set(result["services"]))
        result["findings"] = sorted(set(result["findings"]))
        return result

    def _check_script_for_services(
        self, script_path: Path, services: list[str], findings: list[str]
    ) -> None:
        """Record service binaries an init script references, bounded."""
        lines = self._bounded_lines(script_path)
        if lines is None:
            return
        content = "\n".join(text for _number, _offset, text in lines).lower()
        for service in SERVICE_BINARIES:
            if service in content:
                services.append(service)
                findings.append(f"Service '{service}' referenced in {script_path.name}")

    # ──────────────────────────────────────────
    # One file
    # ──────────────────────────────────────────

    def _categorize_file(
        self,
        file_path: Path,
        rootfs_path: Path,
        *,
        root_id: str,
        metadata: dict | None,
        metadata_source: str,
        artifact_id: str | None,
    ) -> FilesystemFinding:
        """Categorize a single file, preferring image/declared metadata."""
        relative = file_path.relative_to(rootfs_path)
        locator = Path(root_id) / relative
        file_stat = file_path.stat()
        host_mode = file_stat.st_mode

        declared = metadata or {}
        raw_mode = declared.get("mode")
        mode: int | None
        if isinstance(raw_mode, int):
            mode = raw_mode
        elif metadata_source == "host":
            mode = host_mode
        else:
            mode = None
        uid = declared.get("uid") if isinstance(declared.get("uid"), int) else None
        gid = declared.get("gid") if isinstance(declared.get("gid"), int) else None
        if metadata_source == "host":
            uid = file_stat.st_uid
            gid = file_stat.st_gid

        file_format = detect_format(file_path)
        raw_hash = declared.get("sha256")
        file_hash = raw_hash if isinstance(raw_hash, str) else ""
        if not file_hash and file_stat.st_size < HASH_SIZE_LIMIT:
            file_hash = self._hash_file(file_path)

        category = self._determine_category(relative, file_path, file_format)

        return FilesystemFinding(
            path=locator,
            absolute_path=file_path,
            category=category,
            file_type=file_format,
            file_size=file_stat.st_size,
            permissions=self._format_permissions(mode) if mode is not None else "unknown",
            owner_uid=uid if uid is not None else -1,
            owner_gid=gid if gid is not None else -1,
            is_suid=bool(mode & stat.S_ISUID) if mode is not None else False,
            is_world_writable=bool(mode & stat.S_IWOTH) if mode is not None else False,
            hash_sha256=file_hash,
            format=file_format,
            artifact_id=artifact_id,
            root_id=root_id,
            mode=mode,
            metadata_source=metadata_source,
            hardlink_group=(
                str(declared.get("link_target")) if declared.get("link_target") else None
            ),
        )

    def _determine_category(
        self, rel_path: Path, file_path: Path, file_format: str
    ) -> FileCategory:
        """Determine the security category for a file."""
        rel_str = rel_path.as_posix()
        rel_lower = rel_str.lower()
        ext = rel_path.suffix.lower()

        for category, patterns in CATEGORY_PATTERNS.items():
            for pattern in patterns:
                if rel_lower.startswith(pattern) or pattern == ext:
                    return category

        # A binary is a binary because its header says so, not because of a
        # suffix or the name of the service it might implement.
        if file_format in ("elf", "pe", "macho"):
            return FileCategory.CRITICAL_BINARY

        if ext in EXTENSION_CATEGORIES:
            return EXTENSION_CATEGORIES[ext]

        name = file_path.name.lower()
        if name in SERVICE_BINARIES:
            return FileCategory.CRITICAL_SERVICE

        return FileCategory.LOW_MISC

    def _format_permissions(self, mode: int) -> str:
        """Format a mode as ``rwxr-xr-x``."""
        bits = [
            (stat.S_IRUSR, "r"),
            (stat.S_IWUSR, "w"),
            (stat.S_IXUSR, "x"),
            (stat.S_IRGRP, "r"),
            (stat.S_IWGRP, "w"),
            (stat.S_IXGRP, "x"),
            (stat.S_IROTH, "r"),
            (stat.S_IWOTH, "w"),
            (stat.S_IXOTH, "x"),
        ]
        rwx = "".join(char if mode & bit else "-" for bit, char in bits)
        if mode & stat.S_ISUID:
            rwx = rwx[:2] + "s" + rwx[3:]
        if mode & stat.S_ISGID:
            rwx = rwx[:5] + "s" + rwx[6:]
        return rwx

    def _hash_file(self, path: Path) -> str:
        """SHA-256 of a file, streamed."""
        hasher = hashlib.sha256()
        try:
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (OSError, PermissionError):
            return ""
