"""Filesystem Scanner — Phase 2b.

Walks extracted firmware filesystem and categorizes every file by
security relevance. This is the backbone for all subsequent scanning.

SDR §8.2 — Filesystem Analysis
"""

from __future__ import annotations

import hashlib
import logging
import stat
from pathlib import Path

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import (
    FileCategory,
    FilesystemFinding,
    FilesystemInventory,
)

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# File categorization patterns
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
        ".key",
        ".cer",
        ".pfx",
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

# Extension-based quick categorization
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


class FilesystemScanner:
    """Walk extracted filesystem and categorize files by security relevance.

    Produces a FilesystemInventory that serves as the index for
    all subsequent scanner modules (credentials, CVE, C2).
    """

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config

    def scan(self, rootfs_path: Path) -> FilesystemInventory:
        """Walk the extracted rootfs and categorize every file.

        Args:
            rootfs_path: Path to extracted root filesystem.

        Returns:
            FilesystemInventory with all files categorized.
        """
        rootfs_path = Path(rootfs_path).resolve()

        if not rootfs_path.exists() or not rootfs_path.is_dir():
            logger.warning("Root filesystem path invalid: %s", rootfs_path)
            return FilesystemInventory(rootfs_path=rootfs_path)

        findings: list[FilesystemFinding] = []
        categories: dict[FileCategory, list[FilesystemFinding]] = {cat: [] for cat in FileCategory}
        total_dirs = 0
        total_size = 0

        for entry in rootfs_path.rglob("*"):
            if not entry.is_file():
                if entry.is_dir():
                    total_dirs += 1
                continue

            try:
                finding = self._categorize_file(entry, rootfs_path)
                findings.append(finding)
                categories[finding.category].append(finding)
                total_size += finding.file_size
            except (OSError, PermissionError) as exc:
                logger.debug("Skipping file (access error): %s — %s", entry, exc)
                continue

        inventory = FilesystemInventory(
            rootfs_path=rootfs_path,
            total_files=len(findings),
            total_directories=total_dirs,
            total_size=total_size,
            findings=findings,
            categories=categories,
        )

        # Build quick-access indices
        inventory.suid_binaries = [f for f in findings if f.is_suid]
        inventory.world_writable_files = [f for f in findings if f.is_world_writable]
        inventory.shadow_files = categories.get(FileCategory.CRITICAL_CREDENTIAL, [])
        inventory.ssl_cert_files = categories.get(FileCategory.HIGH_CRYPTO, [])
        inventory.init_scripts = categories.get(FileCategory.CRITICAL_SCRIPT, [])
        inventory.network_services = categories.get(FileCategory.CRITICAL_SERVICE, [])

        logger.info(
            "Filesystem scan complete: %d files, %d dirs, %d SUID, %d world-writable",
            inventory.total_files,
            inventory.total_directories,
            len(inventory.suid_binaries),
            len(inventory.world_writable_files),
        )
        return inventory

    def get_files_by_category(
        self, inventory: FilesystemInventory, category: FileCategory
    ) -> list[FilesystemFinding]:
        """Return all files matching a security category."""
        return inventory.categories.get(category, [])

    def _categorize_file(self, file_path: Path, rootfs_path: Path) -> FilesystemFinding:
        """Categorize a single file by security relevance."""
        rel_path = file_path.relative_to(rootfs_path)
        file_stat = file_path.stat()
        mode = file_stat.st_mode

        # Determine file type
        file_type = self._get_file_type(file_path)

        # Compute hash (small files only for speed; large files skip)
        file_hash = ""
        if file_stat.st_size < 10 * 1024 * 1024:  # < 10 MB
            file_hash = self._hash_file(file_path)

        # Determine category
        category = self._determine_category(rel_path, file_path, file_type)

        return FilesystemFinding(
            path=rel_path,
            absolute_path=file_path,
            category=category,
            file_type=file_type,
            file_size=file_stat.st_size,
            permissions=self._format_permissions(mode),
            owner_uid=file_stat.st_uid,
            owner_gid=file_stat.st_gid,
            is_suid=bool(mode & stat.S_ISUID),
            is_world_writable=bool(mode & stat.S_IWOTH),
            hash_sha256=file_hash,
        )

    def _determine_category(self, rel_path: Path, file_path: Path, file_type: str) -> FileCategory:
        """Determine security category for a file."""
        rel_str = str(rel_path)
        rel_lower = rel_str.lower()
        ext = rel_path.suffix.lower()

        # Check path-based patterns first (more specific)
        for category, patterns in CATEGORY_PATTERNS.items():
            for pattern in patterns:
                if pattern in rel_lower or pattern == ext:
                    return category

        # Check ELF binaries
        if "elf" in file_type.lower() or "executable" in file_type.lower():
            return FileCategory.CRITICAL_BINARY

        # Check extension-based categories
        if ext in EXTENSION_CATEGORIES:
            return EXTENSION_CATEGORIES[ext]

        # Check for service binaries by name
        name = file_path.name.lower()
        service_names = {
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
        if name in service_names:
            return FileCategory.CRITICAL_SERVICE

        return FileCategory.LOW_MISC

    def _get_file_type(self, path: Path) -> str:
        """Get file type description."""
        try:
            import magic

            return magic.from_file(str(path))
        except (ImportError, Exception):
            ext = path.suffix.lower()
            return ext if ext else "unknown"

    def _format_permissions(self, mode: int) -> str:
        """Format file mode as rwxr-xr-x string."""
        parts = []
        for who in (
            stat.S_IRUSR,
            stat.S_IWUSR,
            stat.S_IXUSR,
            stat.S_IRGRP,
            stat.S_IWGRP,
            stat.S_IXGRP,
            stat.S_IROTH,
            stat.S_IWOTH,
            stat.S_IXOTH,
        ):
            parts.append(bool(mode & who))
        rwx = ""
        for _i, (r, w, x) in enumerate(
            [
                (parts[0], parts[1], parts[2]),
                (parts[3], parts[4], parts[5]),
                (parts[6], parts[7], parts[8]),
            ]
        ):
            rwx += ("r" if r else "-") + ("w" if w else "-") + ("x" if x else "-")
        # SUID
        if mode & stat.S_ISUID:
            rwx = rwx[:2] + "s" + rwx[3:]
        return rwx

    def _hash_file(self, path: Path) -> str:
        """Compute SHA-256 of a file."""
        hasher = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (OSError, PermissionError):
            return ""
