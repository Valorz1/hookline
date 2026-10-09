"""VirusTotal lookups, with the network replaced by fake answers: no real API calls."""

import pytest
import requests

from analyser import virustotal as vt


class FakeResponse:
    def __init__(self, status_code, body=None):
        self.status_code = status_code
        self._body = body or {}

    def json(self):
        return self._body


@pytest.fixture
def offline(monkeypatch, tmp_path):
    """No waiting, an empty cache in a temporary folder, and a pretend API key."""
    monkeypatch.setattr(vt, "API_KEY", "test-key")
    monkeypatch.setattr(vt, "SECONDS_BETWEEN_REQUESTS", 0)
    monkeypatch.setattr(vt, "_pause_everyone", lambda seconds: None)
    monkeypatch.setattr(vt, "_limit_reached_until", 0.0)
    monkeypatch.setattr(vt, "_cache", {})
    monkeypatch.setattr(vt, "CACHE_FILE", tmp_path / "vt_cache.json")

    def answer_with(*responses):
        calls = []
        queue = list(responses)

        def fake_get(address, headers, timeout):
            calls.append(address)
            response = queue.pop(0)
            if isinstance(response, Exception):
                raise response
            return response

        monkeypatch.setattr(vt.requests, "get", fake_get)
        return calls

    return answer_with


def found(malicious):
    stats = {"malicious": malicious, "suspicious": 0, "undetected": 60, "harmless": 30}
    return FakeResponse(200, {"data": {"id": "abc123", "attributes": {"last_analysis_stats": stats}}})


def test_found_is_cached(offline):
    calls = offline(found(2))
    first = vt.lookup("domain", "evil.example")
    second = vt.lookup("domain", "evil.example")
    assert first == second
    assert first["malicious"] == 2 and first["engines"] == 92
    assert len(calls) == 1          # the second answer came from the cache
    assert vt.CACHE_FILE.exists()


def test_too_many_requests_then_success(offline):
    calls = offline(FakeResponse(429), found(0))
    assert vt.lookup("domain", "a.example")["status"] == "found"
    assert len(calls) == 2


def test_daily_limit_stops_further_lookups(offline):
    calls = offline(FakeResponse(429), FakeResponse(429))
    result = vt.lookup("domain", "a.example")
    assert result["status"] == "error" and result["reason"] == "Daily limit reached"
    # The next lookup doesn't even ask: it fails at once instead of waiting a minute
    assert vt.lookup("domain", "b.example")["reason"] == "Daily limit reached"
    assert len(calls) == 2


@pytest.mark.parametrize("response, reason", [
    (FakeResponse(401), "Key rejected"),
    (FakeResponse(503), "VirusTotal error"),
    (requests.ConnectionError(), "No connection"),
    (requests.Timeout(), "Timed out"),
])
def test_failures_say_why(offline, response, reason):
    offline(response)
    result = vt.lookup("domain", "a.example")
    assert result["status"] == "error" and result["reason"] == reason
    assert "domain:a.example" not in vt._cache   # errors are tried again next time


def test_choose_targets_skips_noise():
    found_items = {
        "ips": ["192.168.1.1", "33.162.119.19"],
        "domains": ["fonts.googleapis.com", "evil.example"],
        "urls": ["https://evil.example/a", "https://evil.example/b",
                 "https://evil.example/logo.png", "https://www.facebook.com/brand"],
    }
    assert vt.choose_targets(found_items, []) == [
        ("ip", "33.162.119.19"),            # private 192.168.x.x skipped
        ("domain", "evil.example"),         # Google Fonts skipped
        ("url", "https://evil.example/a"),  # one link per website, no images
    ]


def test_report_links():
    assert vt.report_link({"kind": "domain", "value": "a.example", "status": "found"}) == \
        "https://www.virustotal.com/gui/domain/a.example"
    assert vt.report_link({"kind": "url", "value": "https://a.example/", "status": "found", "id": "f00"}) == \
        "https://www.virustotal.com/gui/url/f00"
    assert vt.report_link({"kind": "url", "value": "https://a.example/", "status": "not_found"}) is None
