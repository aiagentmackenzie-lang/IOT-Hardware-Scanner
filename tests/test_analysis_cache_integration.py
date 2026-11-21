"""In-process cache integration for the two consumers (YARA and text facts).

The installed-CLI cases prove cold/warm equivalence at the product boundary.
These exercise the cache branches inside the engine and the detector, which a
subprocess cannot report to the parent's coverage.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import FileCategory, FilesystemFinding, FilesystemInventory
from iot_hardware_scanner.scanner.analysis_cache import AnalysisCache
from iot_hardware_scanner.scanner.c2_detector import C2Detector, _text_facts_from_content
from iot_hardware_scanner.yara.yara_engine import YaraEngine


def _cache(tmp_path: Path) -> AnalysisCache:
    return AnalysisCache(tmp_path / "cache")


class TestYaraCache:
    def test_a_second_engine_reads_the_stored_match_set(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        secret = tmp_path / "config.txt"
        secret.write_text('password = "Sup3rS3cretV4lue123!"\n')
        config = ScannerConfig()

        first = YaraEngine(config, cache=cache)
        first.load_rules()
        matches = first.scan_file(secret)
        assert cache.stats["writes"] >= 1

        second = YaraEngine(config, cache=cache)
        second.load_rules()
        cached = second.scan_file(secret)

        assert [(m.rule_name, m.namespace) for m in cached] == [
            (m.rule_name, m.namespace) for m in matches
        ]
        assert second.info.digest == first.info.digest
        assert cache.stats["hits"] >= 1

    def test_scan_data_round_trips_through_the_cache(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        config = ScannerConfig()
        engine = YaraEngine(config, cache=cache)
        engine.load_rules()
        payload = b'password = "Sup3rS3cretV4lue123!"\n'

        first = engine.scan_data(payload, module_name="mem")
        second = engine.scan_data(payload, module_name="mem")

        assert [m.rule_name for m in second] == [m.rule_name for m in first]
        assert cache.stats["hits"] >= 1

    def test_a_corrupt_value_shape_is_recomputed(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        config = ScannerConfig()
        engine = YaraEngine(config, cache=cache)
        engine.load_rules()
        path = tmp_path / "plain.txt"
        path.write_text("nothing to see")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        cache.put("yara-file", digest, engine._cache_dependencies(), {"not": "a list"})

        matches = engine.scan_file(path)

        assert isinstance(matches, list)

    def test_an_invalid_entry_is_converted_to_a_placeholder(self) -> None:
        engine = YaraEngine(ScannerConfig())
        engine.load_rules()

        placeholder = engine._match_from_entry("not a dict", None)
        assert placeholder.rule_name == "invalid-cache-entry"

        partial = engine._match_from_entry({"strings": [["bad"]]}, None)
        assert partial.strings == []


class TestTextFactCache:
    @staticmethod
    def _inventory(path: Path) -> FilesystemInventory:
        finding = FilesystemFinding(
            path=Path("rootfs/etc/app.conf"),
            absolute_path=path,
            category=FileCategory.CRITICAL_CONFIG,
            file_type="ASCII text",
            file_size=path.stat().st_size,
            permissions="644",
            owner_uid=0,
            owner_gid=0,
            is_suid=False,
            is_world_writable=False,
            hash_sha256="",
        )
        return FilesystemInventory(
            rootfs_path=path.parent,
            total_files=1,
            findings=[finding],
        )

    def test_a_second_detector_reuses_the_text_facts(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        path = tmp_path / "app.conf"
        path.write_text("server = evil.example.com\nadmin@mail.test\n")
        inventory = self._inventory(path)

        first = C2Detector(ScannerConfig(), cache=cache)
        found = first.detect_domains(inventory)
        writes = cache.stats["writes"]
        assert writes >= 1

        second = C2Detector(ScannerConfig(), cache=cache)
        again = second.detect_domains(inventory)

        assert [(f.value, f.severity) for f in again] == [(f.value, f.severity) for f in found]
        assert cache.stats["hits"] >= 1
        assert cache.stats["writes"] == writes

    def test_ip_extraction_and_a_large_file_are_handled(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        path = tmp_path / "app.conf"
        path.write_text("c2 = 45.9.148.37\n")
        detector = C2Detector(ScannerConfig(), cache=cache)
        inventory = self._inventory(path)

        detector.detect_ips(inventory)
        facts = detector._file_text_facts(path)
        assert facts is not None and facts["ips"] == ["45.9.148.37"]

        config = ScannerConfig(max_scan_file_size_mb=1)
        big = tmp_path / "big.conf"
        big.write_bytes(b"x" * (1024 * 1024 + 1))
        assert C2Detector(config, cache=cache)._file_text_facts(big) is None

    def test_a_missing_file_is_a_miss_not_a_crash(self, tmp_path: Path) -> None:
        detector = C2Detector(ScannerConfig(), cache=_cache(tmp_path))
        assert detector._file_text_facts(tmp_path / "missing.conf") is None

    def test_text_facts_are_deterministic(self) -> None:
        content = "a@mail.test and evil.example.com and 8.8.8.8"

        assert _text_facts_from_content(content) == _text_facts_from_content(content)
        facts = _text_facts_from_content(content)
        assert "evil.example.com" in facts["domains"]
        assert "mail.test" in facts["email_only_domains"]
        assert facts["ips"] == ["8.8.8.8"]
