"""Custom exceptions for IoT Hardware Scanner.

All scanner-specific errors inherit from ScannerError.
Exit codes map to specific exception types for CLI use.
"""


class ScannerError(Exception):
    """Base exception for all scanner errors."""

    exit_code: int = 6  # Internal error (default)


class FirmwareNotFoundError(ScannerError):
    """Firmware file does not exist at the specified path."""

    exit_code = 3


class FirmwareEmptyError(ScannerError):
    """Firmware file is 0 bytes."""

    exit_code = 3


class FirmwareTooLargeError(ScannerError):
    """Firmware file exceeds the configured maximum size."""

    exit_code = 3


class FirmwareUnreadableError(ScannerError):
    """Current user cannot read the firmware file."""

    exit_code = 3


class FirmwarePathTraversalError(ScannerError):
    """Firmware path contains traversal sequences (..) or null bytes."""

    exit_code = 2


class ExtractionFailedError(ScannerError):
    """Binwalk extraction failed."""

    exit_code = 4


class BinwalkNotFoundError(ScannerError):
    """Binwalk binary or pybinwalk not found on system."""

    exit_code = 5


class YaraRuleError(ScannerError):
    """YARA rule compilation or loading error."""

    exit_code = 5


class NVDApiError(ScannerError):
    """NVD API request failed."""

    exit_code = 6


class ConfigError(ScannerError):
    """Configuration validation error."""

    exit_code = 2


class DiskSpaceError(ScannerError):
    """Insufficient disk space for extraction."""

    exit_code = 6
