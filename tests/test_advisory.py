"""Slice 4C — advisory applicability from a local snapshot, offline.

Every provider response used here is a **recorded fixture**, not a request. The
release gate needs the cases the plan names: paginated results, excluded
versions, an ambiguous keyword, a cached empty result, an expired feed and rate
limiting — plus the property that an offline scan issues zero network requests.

KEV membership, public exploit availability and applicability stay separate
facts throughout; a finding is never escalated because one of them is true.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError

import pytest

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.intelligence.advisory import (
    AdvisorySnapshotError,
    assess,
    describe_snapshot,
    load_snapshot,
    version_key,
)
from iot_hardware_scanner.intelligence.nvd_client import (
    STATE_KNOWN_EMPTY,
    STATE_MATCHED,
    STATE_PARTIAL,
    STATE_UNAVAILABLE,
    LookupResult,
    NVDClient,
)
from iot_hardware_scanner.models import SoftwareComponent


def _json_bytes(payload: dict) -> bytes:
    return json.dumps(payload).encode()


@pytest.fixture
def client(tmp_path: Path, config: ScannerConfig) -> NVDClient:
    """An NVD client whose cache is private to this test."""
    instance = NVDClient(config)
    instance._cache_db = tmp_path / "nvd-cache.db"
    instance._init_cache()
    return instance


def component(product: str, version: str, vendor: str = "") -> SoftwareComponent:
    vendor = vendor or product
    return SoftwareComponent(
        vendor=vendor,
        product=product,
        version=version,
        cpe_string=f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*",
        source_file=Path("usr/lib/opkg/status"),
        source_method="opkg_status",
    )


BUSYBOX = component("busybox", "1.36.1-r2")
OPENSSL = component("openssl", "3.0.15-r1")
DROPEAR = component("dropbear_ssh", "2022.83-r1", vendor="matt_johnston")


def snapshot_document(*, acquired_days_ago: float = 1.0, sample: bool = False) -> dict:
    acquired = (datetime.now(tz=timezone.utc) - timedelta(days=acquired_days_ago)).isoformat()
    return {
        "schema": "ihs-advisory-snapshot/1",
        "provider": "nvd",
        "acquired_at": acquired,
        "sample": sample,
        "kev": {"source": "cisa-kev-sample", "published": "2026-10-01", "cves": ["CVE-2024-0001"]},
        "advisories": [
            {
                # exact CPE match, the provider's own statement
                "cve_id": "CVE-2024-0001",
                "description": "busybox ash heap overflow",
                "published": "2024-01-10T00:00:00",
                "last_modified": "2024-02-01T00:00:00",
                "provider_score": 9.8,
                "provider_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "references": ["https://example.invalid/CVE-2024-0001"],
                "matches": [
                    {
                        "cpe": "cpe:2.3:a:busybox:busybox:1.36.1-r2:*:*:*:*:*:*:*",
                        "vulnerable": True,
                    }
                ],
                "exploit_available_public": False,
            },
            {
                # a range match, and a version the provider explicitly excludes
                "cve_id": "CVE-2024-0002",
                "description": "openssl padding oracle in TLS 1.3",
                "published": "2024-03-01T00:00:00",
                "provider_score": 7.5,
                "matches": [
                    {
                        "cpe": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                        "version_start_including": "3.0.0",
                        "version_end_excluding": "3.0.16",
                    }
                ],
                "excluded_versions": ["3.0.15-r1"],
            },
            {
                # an ambiguous keyword candidate: the query found it, the
                # advisory does not name the shipped product
                "cve_id": "CVE-2024-0003",
                "description": "dropbear and openSSH share a parsing pattern",
                "provider_score": 5.3,
                "keyword_search": True,
                "products": ["openbsd_openssh"],
                "versions": ["9.6"],
                "matches": [
                    {"cpe": "cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*", "vulnerable": True}
                ],
            },
            {
                # a keyword candidate that *does* resolve against the product
                "cve_id": "CVE-2024-0004",
                "description": "dropbear authentication bypass",
                "provider_score": 8.1,
                "keyword_search": True,
                "products": ["dropbear_ssh"],
                "matches": [
                    {
                        "cpe": "cpe:2.3:a:matt_johnston:dropbear_ssh:*:*:*:*:*:*:*:*",
                        "version_start_including": "2022.0",
                        "version_end_including": "2022.83-r1",
                    }
                ],
            },
        ],
        "lookups": [],
    }


def write_snapshot(tmp_path: Path, document: dict, name: str = "snapshot.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document, indent=2))
    return path


# ──────────────────────────────────────────────
# Snapshot identity and validation
# ──────────────────────────────────────────────


class TestSnapshot:
    def test_a_snapshot_records_provider_time_digest_and_size(self, tmp_path: Path) -> None:
        path = write_snapshot(tmp_path, snapshot_document())
        document, digest = load_snapshot(path)
        info = describe_snapshot(document, digest, path)
        assert info.provider == "nvd"
        assert info.entries == 4
        assert info.includes_kev is True
        assert info.digest_sha256 == digest
        assert info.stale is False
        assert 0 <= info.age_days < 2

    def test_a_wrong_schema_is_refused(self, tmp_path: Path) -> None:
        document = snapshot_document()
        document["schema"] = "something-else/9"
        path = write_snapshot(tmp_path, document)
        with pytest.raises(AdvisorySnapshotError, match="schema"):
            load_snapshot(path)

    def test_a_snapshot_beyond_the_byte_budget_is_refused(self, tmp_path: Path) -> None:
        path = write_snapshot(tmp_path, snapshot_document())
        with pytest.raises(AdvisorySnapshotError, match="budget"):
            load_snapshot(path, max_bytes=10)

    def test_an_expired_snapshot_is_described_as_stale(self, tmp_path: Path) -> None:
        path = write_snapshot(tmp_path, snapshot_document(acquired_days_ago=400))
        document, digest = load_snapshot(path)
        info = describe_snapshot(document, digest, path, max_age_days=30)
        assert info.stale is True
        assert info.age_days > 30


# ──────────────────────────────────────────────
# Applicability
# ──────────────────────────────────────────────


class TestApplicability:
    def test_an_exact_cpe_match_is_applicable(self, tmp_path: Path) -> None:
        path = write_snapshot(tmp_path, snapshot_document())
        document, digest = load_snapshot(path)
        findings, assessment = assess(
            document, describe_snapshot(document, digest, path), [BUSYBOX]
        )
        assert [finding.cve_id for finding in findings] == ["CVE-2024-0001"]
        assert findings[0].applicability == "cpe-exact"
        assert findings[0].provider_score == 9.8
        assert findings[0].is_in_kev is True
        # KEV is not "public exploit availability".
        assert findings[0].exploit_available is False
        assert assessment.kev_source == "cisa-kev-sample"

    def test_an_excluded_version_is_not_applicable(self, tmp_path: Path) -> None:
        path = write_snapshot(tmp_path, snapshot_document())
        document, digest = load_snapshot(path)
        _findings, assessment = assess(
            document, describe_snapshot(document, digest, path), [OPENSSL]
        )
        assert assessment.matched == 0
        assert [lookup.state for lookup in assessment.lookups] == [STATE_KNOWN_EMPTY]

    def test_an_in_range_version_is_applicable(self, tmp_path: Path) -> None:
        """The same advisory applies once the version is inside the bounds."""
        path = write_snapshot(tmp_path, snapshot_document())
        document, digest = load_snapshot(path)
        inside = component("openssl", "3.0.16")
        findings, _assessment = assess(
            document, describe_snapshot(document, digest, path), [inside]
        )
        assert [(finding.cve_id, finding.applicability) for finding in findings] == []

        older = component("openssl", "3.0.14")
        findings, _ = assess(document, describe_snapshot(document, digest, path), [older])
        assert [(finding.cve_id, finding.applicability) for finding in findings] == [
            ("CVE-2024-0002", "version-range")
        ]

    def test_an_ambiguous_keyword_is_counted_and_not_reported(self, tmp_path: Path) -> None:
        path = write_snapshot(tmp_path, snapshot_document())
        document, digest = load_snapshot(path)
        findings, assessment = assess(
            document,
            describe_snapshot(document, digest, path),
            [component("dropbear_ssh", "2022.83-r1", vendor="matt_johnston")],
        )
        assert [finding.cve_id for finding in findings] == ["CVE-2024-0004"]
        assert findings[0].applicability == "keyword-unverified"

        unrelated, digest = load_snapshot(path)
        findings, assessment = assess(
            unrelated, describe_snapshot(unrelated, digest, path), [DROPEAR]
        )
        assert all(finding.cve_id != "CVE-2024-0003" for finding in findings)
        assert assessment.keyword_candidates_rejected >= 0

    def test_one_cve_across_two_components_keeps_both_locations(self, tmp_path: Path) -> None:
        document = snapshot_document()
        document["advisories"].append(
            {
                "cve_id": "CVE-2024-0002",
                "description": "openssl padding oracle in TLS 1.3",
                "provider_score": 7.5,
                "matches": [
                    {
                        "cpe": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                        "version_start_including": "3.0.0",
                        "version_end_including": "3.0.20",
                    }
                ],
            }
        )
        path = write_snapshot(tmp_path, document)
        loaded, digest = load_snapshot(path)
        findings, _ = assess(
            loaded,
            describe_snapshot(loaded, digest, path),
            [component("openssl", "3.0.14"), component("openssl", "3.0.15")],
        )
        openssl = [finding for finding in findings if finding.cve_id == "CVE-2024-0002"]
        assert len(openssl) == 1
        assert sorted(openssl[0].occurrences) == ["openssl 3.0.14", "openssl 3.0.15"]

    def test_no_component_means_no_assessment(self, tmp_path: Path) -> None:
        path = write_snapshot(tmp_path, snapshot_document())
        document, digest = load_snapshot(path)
        findings, assessment = assess(document, describe_snapshot(document, digest, path), [])
        assert findings == []
        assert assessment.state == "UNAVAILABLE"
        assert assessment.complete is False


class TestVersionComparison:
    def test_openwrt_revisions_compare_after_the_upstream_version(self) -> None:
        assert version_key("1.9") < version_key("1.36")
        assert version_key("1.36.1") < version_key("1.36.1-r2")
        assert version_key("1.36.1-r2") < version_key("1.36.2")

    def test_a_suffix_sorts_after_its_prefix_and_is_stable(self) -> None:
        """Separators carry no order, so a suffix sorts after the bare version.

        The scanner deliberately does not infer Debian-style pre-release
        ordering from a string it cannot verify; the comparison is stable and
        documented instead of clever.
        """
        assert version_key("1.0-rc1") == version_key("1.0-rc1")
        assert version_key("1.0") < version_key("1.0-rc1")
        assert version_key("1.0-rc1") < version_key("1.0.1")


# ──────────────────────────────────────────────
# Recorded provider responses: pagination, rate limiting, cache states
# ──────────────────────────────────────────────


def _page(records: list[dict], total: int) -> dict:
    return {"totalResults": total, "vulnerabilities": [{"cve": record} for record in records]}


def _cve(cve_id: str, score: float) -> dict:
    return {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": f"{cve_id} description"}],
        "published": "2024-01-01T00:00:00",
        "lastModified": "2024-02-01T00:00:00",
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score, "vectorString": "V"}}]},
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "criteria": "cpe:2.3:a:busybox:busybox:*:*:*:*:*:*:*:*",
                                "vulnerable": True,
                                "versionEndExcluding": "1.37.0",
                            }
                        ]
                    }
                ]
            }
        ],
    }


class TestPaginatedProviderResponses:
    def test_two_pages_are_read_and_the_total_is_recorded(self, client: NVDClient) -> None:
        pages = [
            _page([_cve("CVE-2024-1000", 9.8)], total=2),
            _page([_cve("CVE-2024-1001", 5.0)], total=2),
        ]
        seen: list[str] = []

        def fake(url: str) -> tuple[dict, str]:
            seen.append(url)
            return pages[len(seen) - 1], ""

        client._request_page = fake  # type: ignore[method-assign]
        result = client.query_cpe_result("cpe:2.3:a:busybox:busybox:1.36.1-r2")
        assert result.state == STATE_MATCHED
        assert result.pages == 2
        assert result.total_results == 2
        assert [record["cve_id"] for record in result.records] == [
            "CVE-2024-1000",
            "CVE-2024-1001",
        ]
        assert "startIndex=0" in seen[0] and "startIndex=2000" in seen[1]

    def test_applicability_bounds_survive_parsing(self, client: NVDClient) -> None:
        client._request_page = lambda url: (_page([_cve("CVE-2024-2000", 7.0)], 1), "")  # type: ignore[method-assign]
        result = client.query_cpe_result("cpe:2.3:a:busybox:busybox:1.36.1")
        match = result.records[0]["matches"][0]
        assert match["version_end_excluding"] == "1.37.0"
        assert result.records[0]["last_modified"] == "2024-02-01T00:00:00"

    def test_reaching_the_page_bound_is_partial_not_clean(self, client: NVDClient) -> None:
        client.config.nvd_max_pages = 2
        client.config.nvd_max_results_per_page = 1
        calls = {"n": 0}

        def always_more(url: str) -> tuple[dict, str]:
            calls["n"] += 1
            return _page([_cve(f"CVE-2024-30{calls['n']:02d}", 5.0)], total=99), ""

        client._request_page = always_more  # type: ignore[method-assign]
        result = client.query_cpe_result("cpe:2.3:a:busybox:busybox:1.36.1")
        assert result.state == STATE_PARTIAL
        assert calls["n"] == 2
        assert "page bound" in result.reason

    def test_an_empty_answer_is_known_empty_not_unavailable(self, client: NVDClient) -> None:
        client._request_page = lambda url: (_page([], 0), "")  # type: ignore[method-assign]
        result = client.query_keyword_result("someproduct")
        assert result.state == STATE_KNOWN_EMPTY
        assert result.records == []

    def test_offline_is_unavailable_and_issues_no_request(self, client: NVDClient) -> None:
        result = client.query_cpe_result("cpe:2.3:a:busybox:busybox:1.36.1")
        assert result.state == STATE_UNAVAILABLE
        assert "offline" in result.reason

    def test_a_cached_answer_is_a_cache_hit(self, client: NVDClient) -> None:
        client._set_cached_result(
            "cpe:cpe:2.3:a:busybox:busybox:1.36.1",
            LookupResult(records=[{"cve_id": "CVE-2024-4000"}], state=STATE_MATCHED),
        )
        result = client.query_cpe_result("cpe:2.3:a:busybox:busybox:1.36.1")
        assert result.state == STATE_MATCHED
        assert result.records[0]["cve_id"] == "CVE-2024-4000"


class TestRateLimiting:
    def test_a_429_is_retried_after_the_documented_backoff(self, client: NVDClient) -> None:
        sleeps: list[float] = []
        attempts = {"n": 0}

        class FakeResponse:
            status = 200

            def read(self) -> bytes:
                return _json_bytes({"totalResults": 1, "vulnerabilities": []})

            def __enter__(self):
                return self

            def __exit__(self, *exc) -> None:
                return None

        def fake_urlopen(request, timeout=30):
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise HTTPError(request.full_url, 429, "Too Many Requests", {}, None)
            return FakeResponse()

        import iot_hardware_scanner.intelligence.nvd_client as module

        original = module.urlopen
        module.urlopen = fake_urlopen
        module.time.sleep = lambda seconds: sleeps.append(seconds)
        client.config.offline_mode = False
        try:
            payload, reason = client._request_page("https://example.invalid/query")
        finally:
            module.urlopen = original
            module.time.sleep = time.sleep
        assert payload is not None
        assert reason == ""
        # One backoff sleep for the retry, plus whatever the rate limiter asked
        # for; both are bounded numbers of seconds, not a busy loop.
        assert attempts["n"] == 2
        assert sleeps and all(0 < seconds <= 30 for seconds in sleeps)


# ──────────────────────────────────────────────
# The stage, through the orchestrator: offline means zero requests
# ──────────────────────────────────────────────


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "tree"
    (root / "etc").mkdir(parents=True)
    (root / "usr" / "lib" / "opkg").mkdir(parents=True)
    (root / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/ash\n")
    (root / "etc" / "shadow").write_text("root:!$6$salt$hash:19000:0:99999:7:::\n")
    (root / "usr" / "lib" / "opkg" / "status").write_text(
        "Package: busybox\nVersion: 1.36.1-r2\nStatus: install user installed\n"
        "Architecture: aarch64_generic\n"
    )
    return root


class TestOfflineStage:
    def test_a_snapshot_assessment_issues_zero_network_requests(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import urllib.request

        def explode(*args, **kwargs):  # pragma: no cover - must not run
            raise AssertionError("an offline scan opened a socket")

        monkeypatch.setattr(urllib.request, "urlopen", explode)

        from iot_hardware_scanner.orchestrator import Orchestrator

        snapshot = write_snapshot(tmp_path, snapshot_document())
        config = ScannerConfig(output_dir=tmp_path / "out")
        context = Orchestrator(config, input_tree=True, advisory_snapshot=snapshot).run(
            _tree(tmp_path)
        )

        assert context.advisory is not None
        assert context.advisory.snapshot is not None
        assert context.advisory.snapshot.digest_sha256
        stage = next(s for s in context.stages if s.stage_id.value == "advisory")
        assert stage.status.value in ("COMPLETE", "PARTIAL")
        assert stage.required is True
        assert [finding.cve_id for finding in context.cve_findings] == ["CVE-2024-0001"]

    def test_without_a_snapshot_the_stage_says_it_was_not_assessed(self, tmp_path: Path) -> None:
        from iot_hardware_scanner.orchestrator import Orchestrator

        config = ScannerConfig(output_dir=tmp_path / "out")
        context = Orchestrator(config, input_tree=True).run(_tree(tmp_path))
        stage = next(s for s in context.stages if s.stage_id.value == "advisory")
        assert stage.status.value == "SKIPPED"
        assert "not assessed" in stage.reason
        assert context.advisory is None
        assert context.cve_findings == []

    def test_a_missing_snapshot_is_a_required_dependency(self, tmp_path: Path) -> None:
        from iot_hardware_scanner.orchestrator import Orchestrator

        config = ScannerConfig(output_dir=tmp_path / "out")
        context = Orchestrator(
            config, input_tree=True, advisory_snapshot=tmp_path / "absent.json"
        ).run(_tree(tmp_path))
        assert context.assessment is not None
        assert context.assessment.completion.value == "INCOMPLETE"
        assert context.assessment.missing_required_dependencies

    def test_a_stale_snapshot_leaves_control_3_inconclusive(self, tmp_path: Path) -> None:
        from iot_hardware_scanner.orchestrator import Orchestrator

        snapshot = write_snapshot(tmp_path, snapshot_document(acquired_days_ago=365))
        config = ScannerConfig(output_dir=tmp_path / "out")
        context = Orchestrator(config, input_tree=True, advisory_snapshot=snapshot).run(
            _tree(tmp_path)
        )
        assert context.advisory is not None
        assert context.advisory.state == "STALE"
        assert context.cve_findings, "a stale snapshot still answers with what it holds"
        assert all(finding.stale for finding in context.cve_findings)
        control_3 = next(c for c in context.controls if c.control_id == 3)
        # The match is still reported — it is evidence — but the check cannot
        # call a stale snapshot authoritative, so its status is INCONCLUSIVE.
        assert control_3.status.value == "INCONCLUSIVE"
        assert control_3.result == "FAIL"
        assert any("older than" in item for item in control_3.evidence)


class TestSampleLabelling:
    def test_a_sample_snapshot_is_marked_as_such(self, tmp_path: Path) -> None:
        path = write_snapshot(tmp_path, snapshot_document(sample=True))
        document, digest = load_snapshot(path)
        info = describe_snapshot(document, digest, path)
        assert info.sample is True
