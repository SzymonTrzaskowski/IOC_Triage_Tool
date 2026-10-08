"""Unit tests for VirusTotal client and JSON cache (no real HTTP)."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from core.cache import IocCache
from core.classifier import IocType
from core.virustotal import VirusTotalClient


def _vt_stats_response(malicious: int = 5, suspicious: int = 1, harmless: int = 64) -> dict:
    """Build a minimal VirusTotal v3 JSON body."""
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": 0,
                    "timeout": 0,
                },
                "country": "US",
                "names": ["dropper.bin"],
            }
        }
    }


def test_lookup_skipped_without_api_key() -> None:
    """Missing key disables the client instead of crashing."""
    client = VirusTotalClient(api_key="")
    assert client.enabled is False
    assert client.lookup(IocType.IP, "8.8.8.8") is None


def test_ip_lookup_parses_stats(monkeypatch: pytest.MonkeyPatch) -> None:
    """IP lookup uses MockTransport and extracts engine counts."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("x-apikey") == "test-key"
        assert str(request.url).endswith("/ip_addresses/8.8.8.8")
        return httpx.Response(200, json=_vt_stats_response())

    transport = httpx.MockTransport(handler)
    http_client = httpx.Client(transport=transport)
    client = VirusTotalClient(api_key="test-key", client=http_client)
    result = client.lookup(IocType.IP, "8.8.8.8")
    assert result is not None
    assert result["vt_malicious"] == 5
    assert result["vt_suspicious"] == 1
    assert result["vt_total"] == 70
    assert result["country"] == "US"
    assert "dropper.bin" in result["related"]
    assert result["vt_link"] == "https://www.virustotal.com/gui/ip-address/8.8.8.8"


def test_url_lookup_uses_sha256_id() -> None:
    """URL objects are requested by SHA256 of the URL string."""
    url = "https://evil.example/payload.exe"
    expected_id = hashlib.sha256(url.encode("utf-8")).hexdigest()

    def handler(request: httpx.Request) -> httpx.Response:
        assert expected_id in str(request.url)
        return httpx.Response(200, json=_vt_stats_response(malicious=0, suspicious=0))

    transport = httpx.MockTransport(handler)
    http_client = httpx.Client(transport=transport)
    client = VirusTotalClient(api_key="test-key", client=http_client)
    result = client.lookup(IocType.URL, url)
    assert result is not None
    assert result["vt_malicious"] == 0
    assert expected_id in result["vt_link"]


def test_network_timeout_does_not_raise() -> None:
    """Timeouts become an error payload instead of crashing."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("slow")

    transport = httpx.MockTransport(handler)
    http_client = httpx.Client(transport=transport)
    client = VirusTotalClient(api_key="test-key", client=http_client)
    result = client.lookup(IocType.DOMAIN, "example.com")
    assert result is not None
    assert "timed out" in result["error"]


def test_cache_ttl(tmp_path: Path) -> None:
    """Entries older than 24h are treated as a miss."""
    cache = IocCache(path=tmp_path / "cache.json")
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    payload = {"vt_malicious": 1, "vt_total": 70}
    cache.set(IocType.IP, "1.2.3.4", payload, now=now)
    hit = cache.get(IocType.IP, "1.2.3.4", now=now + timedelta(hours=1))
    assert hit is not None
    assert hit["vt_malicious"] == 1
    miss = cache.get(IocType.IP, "1.2.3.4", now=now + timedelta(hours=25))
    assert miss is None
