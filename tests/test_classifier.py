"""Unit tests for IOC type detection and verdict classification."""

from __future__ import annotations

import pytest

from core.classifier import (
    IocType,
    Verdict,
    classify,
    classify_abuseipdb,
    classify_virustotal,
    combine_verdicts,
    detect_type,
    normalize_ioc,
    normalize_url,
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
    assert classify_virustotal(0, 0, has_report=False) == Verdict.UNKNOWN
    assert classify_virustotal(0, 0, has_report=True) == Verdict.CLEAN


def test_payload_404_maps_to_unknown() -> None:
    """Merged VT 404 payload becomes Unknown with the analyst-facing note."""
    from core.classifier import VT_NOT_FOUND_NOTE
    from triage import merge_lookups, payload_to_result

    merged = merge_lookups({"error": "VirusTotal: indicator not found"}, None)
    result = payload_to_result("https://x.pl/", IocType.URL, merged)
    assert result.verdict == Verdict.UNKNOWN
    assert result.vt_verdict == Verdict.UNKNOWN
    assert result.error == VT_NOT_FOUND_NOTE


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, Verdict.CLEAN),
        (24, Verdict.CLEAN),
        (25, Verdict.SUSPICIOUS),
        (74, Verdict.SUSPICIOUS),
        (75, Verdict.MALICIOUS),
        (100, Verdict.MALICIOUS),
        (None, None),
    ],
)
def test_classify_abuseipdb(score: int | None, expected: Verdict | None) -> None:
    """AbuseIPDB uses score bands, not a fake extra VT engine."""
    assert classify_abuseipdb(score) == expected


def test_combined_verdict_is_worse_of_sources() -> None:
    """Final verdict is max severity; scores are not summed into VT engines."""
    assert combine_verdicts(Verdict.CLEAN, Verdict.MALICIOUS) == Verdict.MALICIOUS
    assert combine_verdicts(Verdict.CLEAN, Verdict.SUSPICIOUS) == Verdict.SUSPICIOUS
    assert combine_verdicts(Verdict.UNKNOWN, None) == Verdict.UNKNOWN
    assert combine_verdicts(Verdict.CLEAN, None) == Verdict.CLEAN
    assert combine_verdicts(None, None) == Verdict.UNKNOWN


def test_vt_clean_plus_high_abuse_is_malicious() -> None:
    """A clean VT report does not hide a high AbuseIPDB score."""
    from triage import merge_lookups, payload_to_result

    vt = {
        "vt_malicious": 0,
        "vt_suspicious": 0,
        "vt_total": 70,
        "vt_link": "https://www.virustotal.com/gui/ip-address/203.0.113.10",
    }
    abuse = {"abuse_score": 88, "country": "NL"}
    result = payload_to_result("203.0.113.10", IocType.IP, merge_lookups(vt, abuse))
    assert result.vt_verdict == Verdict.CLEAN
    assert result.abuse_verdict == Verdict.MALICIOUS
    assert result.verdict == Verdict.MALICIOUS
    assert result.detection_count == 0
