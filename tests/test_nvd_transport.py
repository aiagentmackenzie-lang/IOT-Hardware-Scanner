"""The advisory transport, executed end to end against a loopback server (D §2.3).

Everything else in the suite stubs the client. This module does not: it stands
up a stdlib HTTP server on 127.0.0.1 with an ephemeral port, hands
:class:`NVDClient` its base URL, and drives the real ``urllib`` path —
pagination, a rate-limited retry, an empty answer, a page-bound breach and a
cache hit from SQLite — through it.

Guard rails, asserted rather than assumed:

* the server binds loopback only, and every request ``urllib`` makes is checked
  against a loopback host before it is sent, so nothing can leave the machine;
* no test here is reachable from ``scan``: the scan's advisory stage reads a
  local snapshot and issues zero requests (``tests/test_advisory.py``);
* sleeps are recorded, not slept: backoff values are asserted, and rate
  limiting itself is covered by ``tests/test_advisory.py``.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.intelligence import nvd_client as nvd_module
from iot_hardware_scanner.intelligence.nvd_client import (
    STATE_KNOWN_EMPTY,
    STATE_MATCHED,
    STATE_PARTIAL,
    LookupResult,
    NVDClient,
)


def _page(cve_ids: list[str], total: int) -> dict:
    """One NVD-shaped page whose ids are distinguishable in the assertion."""
    return {
        "totalResults": total,
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "published": "2024-01-01T00:00:00",
                    "lastModified": "2024-02-01T00:00:00",
                    "descriptions": [{"lang": "en", "value": f"detail for {cve_id}"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 7.5,
                                    "vectorString": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                }
                            }
                        ]
                    },
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
            }
            for cve_id in cve_ids
        ],
    }


class _Recorder:
    """What the server saw, and the answers to give back."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.responses: dict[str, list[tuple[int, dict]]] = {}
        self.failures: list[str] = []

    def route(self, cpe_name: str, responses: list[tuple[int, dict]]) -> str:
        self.responses[cpe_name] = list(responses)
        return cpe_name


@pytest.fixture
def server():
    """A loopback-only HTTP server whose answers a test scripts per query."""
    recorder = _Recorder()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            params = {key: values[0] for key, values in parse_qs(parts.query).items()}
            recorder.requests.append(
                {
                    "path": parts.path,
                    "host": self.headers.get("Host", ""),
                    "client": self.client_address[0],
                    "params": params,
                }
            )
            if parts.path != "/rest/json/cves/2.0":
                recorder.failures.append(f"unexpected path {parts.path}")
                self._send(404, {"error": "no such endpoint"})
                return
            key = params.get("cpeName") or params.get("keywordSearch") or ""
            scripted = recorder.responses.get(key)
            if not scripted:
                recorder.failures.append(f"unscripted query for {key!r}")
                self._send(400, {"error": "unscripted"})
                return
            status, body = scripted.pop(0) if len(scripted) > 1 else scripted[0]
            self._send(status, body)

        def _send(self, status: int, body: dict) -> None:
            payload = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: object) -> None:  # keep pytest output clean
            return

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[0], httpd.server_address[1]
    assert host == "127.0.0.1"
    try:
        yield f"http://{host}:{port}/rest/json/cves/2.0", recorder
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


@pytest.fixture
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record every sleep the client asks for instead of waiting."""
    recorded: list[float] = []
    monkeypatch.setattr(nvd_module.time, "sleep", lambda seconds: recorded.append(seconds))
    return recorded


@pytest.fixture(autouse=True)
def loopback_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test if the client tries to reach any non-loopback host."""
    real_urlopen = nvd_module.urlopen

    def guarded(request, *args, **kwargs):  # type: ignore[no-untyped-def]
        url = getattr(request, "full_url", str(request))
        host = urlsplit(url).hostname
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise AssertionError(f"the transport test tried to reach {host!r}: {url}")
        return real_urlopen(request, *args, **kwargs)

    monkeypatch.setattr(nvd_module, "urlopen", guarded)


def _isolated(config: ScannerConfig, directory: Path) -> None:
    """Keep every case's cache in its own SQLite file."""
    config.nvd_cache_path = directory / "nvd-cache.db"


class TestPagination:
    def test_two_pages_are_read_and_both_urls_carry_the_page_parameters(
        self, server, sleeps, tmp_path: Path
    ) -> None:
        base, recorder = server
        cpe = "cpe:2.3:a:busybox:busybox:1.36.1-r2:*:*:*:*:*:*:*"
        # The provider says there are two results; one page carries one.
        recorder.route(
            cpe,
            [(200, _page(["CVE-2024-0001"], 2)), (200, _page(["CVE-2024-0002"], 2))],
        )
        config = ScannerConfig(
            offline_mode=False,
            nvd_api_base=base,
            nvd_api_key="loopback-test-key",
            nvd_max_results_per_page=1,
            nvd_max_pages=3,
        )
        _isolated(config, tmp_path)
        client = NVDClient(config)

        result = client.query_cpe_result(cpe)

        assert result.state == STATE_MATCHED
        assert result.pages == 2
        assert result.total_results == 2
        assert [record["cve_id"] for record in result.records] == [
            "CVE-2024-0001",
            "CVE-2024-0002",
        ]
        assert [request["params"]["startIndex"] for request in recorder.requests] == ["0", "1"]
        assert [request["params"]["resultsPerPage"] for request in recorder.requests] == ["1", "1"]
        assert all(request["client"] == "127.0.0.1" for request in recorder.requests)
        assert not recorder.failures
        # The only sleeps are the client's rate-limit intervals: pagination
        # itself requests the next page immediately.
        assert all(0 < seconds <= 0.6 for seconds in sleeps)


class TestRateLimiting:
    def test_a_429_is_retried_and_the_second_answer_is_used(
        self, server, sleeps, tmp_path: Path
    ) -> None:
        base, recorder = server
        cpe = "cpe:2.3:a:dnsmasq:dnsmasq:2.90-r1:*:*:*:*:*:*:*"
        recorder.route(cpe, [(429, {"error": "rate limited"}), (200, _page(["CVE-2024-0100"], 1))])
        config = ScannerConfig(
            offline_mode=False,
            nvd_api_base=base,
            nvd_api_key="loopback-test-key",
            nvd_max_results_per_page=1,
            nvd_max_pages=2,
            nvd_max_retries=1,
        )
        _isolated(config, tmp_path)
        client = NVDClient(config)

        result = client.query_cpe_result(cpe)

        assert result.state == STATE_MATCHED
        assert result.pages == 1
        assert [record["cve_id"] for record in result.records] == ["CVE-2024-0100"]
        assert len(recorder.requests) == 2
        # Exactly one bounded backoff between the two attempts (the others are
        # rate-limit intervals), and it is within the documented ceiling.
        backoffs = [seconds for seconds in sleeps if seconds > 1]
        assert backoffs == [2]
        assert max(sleeps) <= 30


class TestEmptyAndPartial:
    def test_an_empty_result_is_known_empty_not_unavailable(
        self, server, sleeps, tmp_path: Path
    ) -> None:
        base, recorder = server
        cpe = "cpe:2.3:a:openwrt:nonexistent-package:1.0-r1:*:*:*:*:*:*:*"
        recorder.route(cpe, [(200, _page([], 0))])
        config = ScannerConfig(offline_mode=False, nvd_api_base=base, nvd_max_results_per_page=1)
        _isolated(config, tmp_path)
        client = NVDClient(config)

        result = client.query_cpe_result(cpe)

        assert result.state == STATE_KNOWN_EMPTY
        assert result.records == []
        assert result.pages == 1
        assert result.total_results == 0

    def test_the_page_bound_is_a_partial_answer_with_a_reason(
        self, server, sleeps, tmp_path: Path
    ) -> None:
        base, recorder = server
        cpe = "cpe:2.3:a:openssl:openssl:3.0.15-r1:*:*:*:*:*:*:*"
        recorder.route(
            cpe,
            [
                (200, _page(["CVE-2024-0200"], 10)),
                (200, _page(["CVE-2024-0201"], 10)),
                (200, _page(["CVE-2024-0202"], 10)),
            ],
        )
        config = ScannerConfig(
            offline_mode=False,
            nvd_api_base=base,
            nvd_max_results_per_page=1,
            nvd_max_pages=2,
        )
        _isolated(config, tmp_path)
        client = NVDClient(config)

        result = client.query_cpe_result(cpe)

        assert result.state == STATE_PARTIAL
        assert result.pages == 2
        assert result.total_results == 10
        assert len(result.records) == 2
        assert "2-page bound" in result.reason
        assert [request["params"]["startIndex"] for request in recorder.requests] == ["0", "1"]


class TestCache:
    def test_a_second_lookup_is_answered_from_sqlite_without_a_request(
        self, server, sleeps, tmp_path: Path
    ) -> None:
        base, recorder = server
        cpe = "cpe:2.3:a:busybox:busybox:1.36.1-r2:*:*:*:*:*:*:*"
        recorder.route(cpe, [(200, _page(["CVE-2024-0300"], 1))])
        config = ScannerConfig(offline_mode=False, nvd_api_base=base, nvd_max_results_per_page=1)
        _isolated(config, tmp_path)

        first = NVDClient(config).query_cpe_result(cpe)
        requests_after_first = len(recorder.requests)
        assert first.records

        # A second client over the same cache, pointed at a port nothing listens
        # on: any request would fail, so a good answer can only come from SQLite.
        second_config = ScannerConfig(
            offline_mode=False,
            nvd_api_base="http://127.0.0.1:1/rest/json/cves/2.0",
            nvd_max_results_per_page=1,
        )
        _isolated(second_config, tmp_path)
        second = NVDClient(second_config).query_cpe_result(cpe)

        assert len(recorder.requests) == requests_after_first
        assert second.state == STATE_MATCHED
        assert [record["cve_id"] for record in second.records] == ["CVE-2024-0300"]
        assert second.pages == first.pages

    def test_the_cached_row_records_the_state_and_page_count(
        self, server, sleeps, tmp_path: Path
    ) -> None:
        base, recorder = server
        cpe = "cpe:2.3:a:dropbear:mbed_tls:3.6.2-r0:*:*:*:*:*:*:*"
        recorder.route(cpe, [(200, _page(["CVE-2024-0400"], 1))])
        config = ScannerConfig(offline_mode=False, nvd_api_base=base, nvd_max_results_per_page=1)
        _isolated(config, tmp_path)
        NVDClient(config).query_cpe_result(cpe)

        with sqlite3.connect(str(config.nvd_cache_path)) as conn:
            row = conn.execute(
                "SELECT response_json FROM nvd_cache WHERE query_key = ?", (f"cpe:{cpe}",)
            ).fetchone()
        assert row is not None
        stored = json.loads(row[0])
        assert stored["state"] == STATE_MATCHED
        assert stored["pages"] == 1
        assert stored["total_results"] == 1


class TestScanIsUnchanged:
    def test_the_scan_never_uses_the_transport(self) -> None:
        """A scan opens no socket: the client is offline unless asked not to be."""
        config = ScannerConfig()
        assert config.offline_mode is True
        client = NVDClient(config)
        started = time.monotonic()
        result: LookupResult = client.query_cpe_result(
            "cpe:2.3:a:busybox:busybox:1.36.1-r2:*:*:*:*:*:*:*"
        )
        assert result.state == "UNAVAILABLE"
        assert "offline" in result.reason
        assert time.monotonic() - started < 1.0
