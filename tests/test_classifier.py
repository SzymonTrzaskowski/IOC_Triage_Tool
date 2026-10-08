"""Unit tests for IOC type detection and verdict classification."""

from __future__ import annotations

import pytest

from core.classifier import (
    IocType,
    Verdict,
    classify,
    detect_type,
    detection_count_from_sources,
    normalize_ioc,
    normalize_url,
    verdict_from_sources,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://evil.example/payload.exe", IocType.URL),
        ("http://192.0.2.1/path", IocType.URL),
        ("8.8.8.8", IocType.IP),
        ("2001:db8::1", IocType.IP),
        ("d41d8cd98f00b204e9800998ecf8427e", IocType.HASH),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", IocType.HASH),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IocType.HASH),
        ("example.com", IocType.DOMAIN),
        ("sub.mail.example.co.uk", IocType.DOMAIN),
        ("not an ioc", IocType.UNKNOWN),
        ("", IocType.UNKNOWN),
    ],
)
def test_detect_type(raw: str, expected: IocType) -> None:
    """Detect IOC type from representative samples."""
    assert detect_type(raw) == expected


def test_normalize_hash_lowercase() -> None:
    """Hashes are lowercased for cache keys and API paths."""
    digest = "D41D8CD98F00B204E9800998ECF8427E"
    assert normalize_ioc(digest, IocType.HASH) == digest.lower()


def test_normalize_domain() -> None:
    """Domains are lowercased and trailing dots stripped."""
    assert normalize_ioc("Example.COM.", IocType.DOMAIN) == "example.com"


def test_normalize_url_canonicalizes_slash_case_port_fragment() -> None:
    """Host case, trailing slash, default port and fragment collapse to one URL."""
    canonical = "https://x.pl/"
    variants = (
        "https://X.pl",
        "https://x.pl/",
        "https://x.pl:443/",
        "https://x.pl/#a",
    )
    results = [normalize_url(item) for item in variants]
    assert results == [canonical] * len(variants)
    assert normalize_ioc("https://X.pl", IocType.URL) == canonical
    assert normalize_ioc("https://x.pl/", IocType.URL) == canonical


@pytest.mark.parametrize(
    ("count", "verdict"),
    [
        (0, Verdict.CLEAN),
        (1, Verdict.SUSPICIOUS),
        (3, Verdict.SUSPICIOUS),
        (4, Verdict.MALICIOUS),
        (70, Verdict.MALICIOUS),
    ],
)
def test_classify_thresholds(count: int, verdict: Verdict) -> None:
    """Map detection counts onto Clean / Suspicious / Malicious."""
    assert classify(count) == verdict


def test_vt_404_is_unknown_not_clean() -> None:
    """Missing VT analysis is Unknown; Clean requires an actual report."""
    assert verdict_from_sources(0, has_report=False) == Verdict.UNKNOWN
    assert verdict_from_sources(0, has_report=True) == Verdict.CLEAN


def test_payload_404_maps