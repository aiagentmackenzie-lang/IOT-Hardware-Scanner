"""Tests for Exception classes — Phase 1.

Covers:
- Exception hierarchy
- Exit code mapping
- Error message formatting
"""

from iot_hardware_scanner.exceptions import (
    BinwalkNotFoundError,
    ConfigError,
    DiskSpaceError,
    ExtractionFailedError,
    FirmwareEmptyError,
    FirmwareNotFoundError,
    FirmwarePathTraversalError,
    FirmwareTooLargeError,
    FirmwareUnreadableError,
    NVDApiError,
    ScannerError,
    YaraRuleError,
)


class TestExceptionHierarchy:
    """All scanner exceptions inherit from ScannerError."""

    def test_all_inherit_from_scanner_error(self) -> None:
        exceptions = [
            FirmwareNotFoundError,
            FirmwareEmptyError,
            FirmwareTooLargeError,
            FirmwareUnreadableError,
            FirmwarePathTraversalError,
            ExtractionFailedError,
            BinwalkNotFoundError,
            YaraRuleError,
            NVDApiError,
            ConfigError,
            DiskSpaceError,
        ]
        for exc_class in exceptions:
            assert issubclass(exc_class, ScannerError), (
                f"{exc_class.__name__} must inherit from ScannerError"
            )

    def test_scanner_error_inherits_from_exception(self) -> None:
        assert issubclass(ScannerError, Exception)


class TestExitCodes:
    """Exit codes match SDR §15 specification."""

    def test_not_found_code_3(self) -> None:
        exc = FirmwareNotFoundError("test")
        assert exc.exit_code == 3

    def test_empty_code_3(self) -> None:
        exc = FirmwareEmptyError("test")
        assert exc.exit_code == 3

    def test_too_large_code_3(self) -> None:
        exc = FirmwareTooLargeError("test")
        assert exc.exit_code == 3

    def test_unreadable_code_3(self) -> None:
        exc = FirmwareUnreadableError("test")
        assert exc.exit_code == 3

    def test_path_traversal_code_2(self) -> None:
        exc = FirmwarePathTraversalError("test")
        assert exc.exit_code == 2

    def test_extraction_failed_code_4(self) -> None:
        exc = ExtractionFailedError("test")
        assert exc.exit_code == 4

    def test_binwalk_not_found_code_5(self) -> None:
        exc = BinwalkNotFoundError("test")
        assert exc.exit_code == 5

    def test_yara_error_code_5(self) -> None:
        exc = YaraRuleError("test")
        assert exc.exit_code == 5

    def test_nvd_api_code_6(self) -> None:
        exc = NVDApiError("test")
        assert exc.exit_code == 6

    def test_config_error_code_2(self) -> None:
        exc = ConfigError("test")
        assert exc.exit_code == 2

    def test_default_code_6(self) -> None:
        exc = ScannerError("test")
        assert exc.exit_code == 6


class TestErrorMessages:
    """Exception messages are informative."""

    def test_not_found_message(self) -> None:
        exc = FirmwareNotFoundError("/missing/firmware.bin")
        assert "/missing/firmware.bin" in str(exc)

    def test_too_large_message_includes_size(self) -> None:
        exc = FirmwareTooLargeError("File too large: 5000000 bytes (limit: 2048 MB)")
        assert "5000000" in str(exc)
        assert "2048" in str(exc)
