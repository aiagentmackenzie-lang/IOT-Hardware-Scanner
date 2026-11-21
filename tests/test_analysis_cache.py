"""Slice 5C — the repeated-work cache contract.

Measured before it was written: on the pinned OpenWrt image, per-file YARA
matches and per-file text facts were about 83 % of a scan's wall time and are a
pure function of content + parser identity. These tests pin the properties the
plan requires: equivalence, invalidation, atomic writes, bounded size and
usability after an interrupted writer.
"""

from __future__ import annotations

import json
from pathlib import Path

from iot_hardware_scanner.scanner.analysis_cache import (
    CACHE_FORMAT,
    AnalysisCache,
    canonical_key,
    sha256_file,
)


def _cache(tmp_path: Path, **kwargs) -> AnalysisCache:
    return AnalysisCache(tmp_path / "cache", **kwargs)


class TestKeyIdentity:
    def test_the_key_names_content_and_every_dependency(self) -> None:
        base = canonical_key("yara-file", "a" * 64, {"ruleset_digest": "r1"})
        assert base == canonical_key("yara-file", "a" * 64, {"ruleset_digest": "r1"})
        assert base != canonical_key("yara-file", "b" * 64, {"ruleset_digest": "r1"})
        assert base != canonical_key("yara-file", "a" * 64, {"ruleset_digest": "r2"})
        assert base != canonical_key("yara-data", "a" * 64, {"ruleset_digest": "r1"})


class TestRoundTrip:
    def test_a_value_survives_and_no_artifact_path_is_stored(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        value = [{"rule_name": "r", "strings": [[0, "$a", "41"]]}]

        assert cache.put("yara-file", "a" * 64, {"ruleset_digest": "r1"}, value) is True
        assert cache.get("yara-file", "a" * 64, {"ruleset_digest": "r1"}) == value

        entries = list((tmp_path / "cache").rglob("*.json"))
        assert len(entries) == 1
        text = entries[0].read_text()
        assert CACHE_FORMAT in text
        assert "/tmp/" not in text and "rootfs" not in text
        assert cache.summary()["hits"] == 1
        assert cache.summary()["writes"] == 1

    def test_a_dependency_change_is_a_miss(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put("text-facts", "a" * 64, {"extractor_version": "1"}, {"domains": []})

        assert cache.get("text-facts", "a" * 64, {"extractor_version": "2"}) is None
        assert cache.summary()["misses"] == 1


class TestInvalidEntries:
    def test_corrupt_json_is_discarded_and_counted(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put("k", "a" * 64, {"d": "1"}, {"ok": True})
        path = next((tmp_path / "cache").rglob("*.json"))
        path.write_text("{not json")

        assert cache.get("k", "a" * 64, {"d": "1"}) is None
        assert cache.summary()["invalid"] == 1
        assert not path.exists()

    def test_a_key_echo_mismatch_is_discarded(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put("k", "a" * 64, {"d": "1"}, {"ok": True})
        path = next((tmp_path / "cache").rglob("*.json"))
        entry = json.loads(path.read_text())
        entry["content_sha256"] = "b" * 64
        path.write_text(json.dumps(entry))

        assert cache.get("k", "a" * 64, {"d": "1"}) is None
        assert cache.summary()["invalid"] == 1

    def test_a_value_over_the_entry_ceiling_is_not_stored(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        huge = {"blob": "x" * (5 * 1024 * 1024)}

        assert cache.put("k", "a" * 64, {"d": "1"}, huge) is False
        assert cache.summary()["skipped"] == 1


class TestAtomicityAndBounds:
    def test_a_reader_never_sees_a_temporary_file(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put("k", "a" * 64, {"d": "1"}, {"ok": True})

        assert list((tmp_path / "cache").rglob(".tmp-*")) == []

    def test_an_interrupted_writers_temporary_is_swept(self, tmp_path: Path) -> None:
        root = tmp_path / "cache"
        root.mkdir()
        (root / ".tmp-abandoned").write_text("partial")
        cache = AnalysisCache(root)

        assert list(root.rglob(".tmp-*")) == []
        cache.put("k", "a" * 64, {"d": "1"}, {"ok": True})
        assert cache.get("k", "a" * 64, {"d": "1"}) == {"ok": True}

    def test_the_store_is_bounded_by_entry_count(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path, max_entries=2)
        for index, digest in enumerate(("a", "b", "c")):
            cache.put("k", digest * 64, {"d": "1"}, {"index": index})

        assert len(list((tmp_path / "cache").rglob("*.json"))) == 2
        assert cache.summary()["evicted"] >= 1
        assert cache.get("k", "a" * 64, {"d": "1"}) is None

    def test_parallel_writers_leave_a_readable_entry(self, tmp_path: Path) -> None:
        import threading

        cache = _cache(tmp_path)
        errors: list[BaseException] = []

        def write(index: int) -> None:
            try:
                cache.put("k", "a" * 64, {"d": "1"}, {"writer": index})
            except BaseException as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=write, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert errors == []
        value = cache.get("k", "a" * 64, {"d": "1"})
        assert isinstance(value, dict) and "writer" in value


class TestFileDigest:
    def test_sha256_file_streams_and_returns_none_when_unreadable(self, tmp_path: Path) -> None:
        path = tmp_path / "f.bin"
        path.write_bytes(b"abc")
        assert sha256_file(path) == (
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        assert sha256_file(tmp_path / "missing.bin") is None


class TestOperationalEdges:
    def test_the_default_root_honours_xdg(self, tmp_path: Path, monkeypatch) -> None:
        from iot_hardware_scanner.scanner.analysis_cache import default_cache_root

        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
        assert default_cache_root() == tmp_path / "ihs-analysis"

    def test_a_missing_value_field_is_invalid(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put("k", "a" * 64, {"d": "1"}, {"ok": True})
        path = next((tmp_path / "cache").rglob("*.json"))
        entry = json.loads(path.read_text())
        entry.pop("value")
        path.write_text(json.dumps(entry))

        assert cache.get("k", "a" * 64, {"d": "1"}) is None
        assert cache.summary()["invalid"] == 1

    def test_a_non_object_entry_is_invalid(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put("k", "a" * 64, {"d": "1"}, {"ok": True})
        path = next((tmp_path / "cache").rglob("*.json"))
        path.write_text("[]")

        assert cache.get("k", "a" * 64, {"d": "1"}) is None
        assert cache.summary()["invalid"] == 1

    def test_a_wrong_format_marker_is_invalid(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put("k", "a" * 64, {"d": "1"}, {"ok": True})
        path = next((tmp_path / "cache").rglob("*.json"))
        entry = json.loads(path.read_text())
        entry["format"] = "other/1"
        path.write_text(json.dumps(entry))

        assert cache.get("k", "a" * 64, {"d": "1"}) is None

    def test_an_unwritable_location_is_reported_not_raised(self, tmp_path: Path) -> None:
        blocker = tmp_path / "not-a-directory"
        blocker.write_text("x")
        cache = AnalysisCache(blocker)

        assert cache.put("k", "a" * 64, {"d": "1"}, {"ok": True}) is False
        assert cache.summary()["skipped"] == 1

    def test_the_byte_ceiling_also_evicts(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path, max_bytes=16)
        cache.put("k", "a" * 64, {"d": "1"}, {"payload": "x" * 100})

        assert cache.summary()["evicted"] >= 1
        assert cache.get("k", "a" * 64, {"d": "1"}) is None
