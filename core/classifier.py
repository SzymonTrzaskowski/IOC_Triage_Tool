"""IOC type detection (regex) and verdict classification."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urlsplit, urlunsplit


class IocType(str, Enum):
    """Supported indicator-of-compromise kinds."""

    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    URL = "url"
    UNKNOWN = "unknown"


class Verdict(str, Enum):
    """Triage verdict derived from engine detection counts."""

    CLEAN = "Clean"
    SUSPICIOUS = "Suspicious"
    MALICIOUS = "Malicious"
    UNKNOWN = "Unknown"


VT_NOT_FOUND_NOTE = (
    "No VirusTotal analysis — this IOC has not been scanned before"
)
_DEFAULT_PORTS = {"http": 80, "https": 443}
_VERDICT_RANK = {
    Verdict.CLEAN: 0,
    Verdict.UNKNOWN: 1,
    Verdict.SUSPICIOUS: 2,
    Verdict.MALICIOUS: 3,
}


_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


@dataclass
class TriageResult:
    """Aggregated triage outcome for a single IOC."""

    ioc: str
    ioc_type: IocType
    verdict: Verdict = Verdict.CLEAN
    vt_verdict: Optional[Verdict] = None
    abuse_verdict: Optional[Verdict] = None
    detection_count: int = 0
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_total: int = 0
    abuse_score: Optional[int] = None
    country: Optional[str] = None
    related: list[str] = field(default_factory=list)
    vt_link: Optional[str] = None
    error: Optional[str] = None
    from_cache: bool = False


def normalize_ioc(raw: str, ioc_type: IocType) -> str:
    """Strip whitespace and apply type-specific normalization.

    Args:
        raw: Raw IOC string from CLI or file.
        ioc_type: Detected IOC type.

    Returns:
        Normalized IOC string used as cache key and API identifier.
    """
    value = raw.strip()
    if ioc_type == IocType.HASH:
        return value.lower()
    if ioc_type == IocType.DOMAIN:
        host = value.lower().rstrip(".")
        return host
    if ioc_type == IocType.URL:
        return normalize_url(value)
    if ioc_type == IocType.IP:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return value
    return value


def detect_type(raw: str) -> IocType:
    """Detect IOC type using regex and IP parsing.

    Order: URL, IP, hash (MD5/SHA1/SHA256), domain.

    Args:
        raw: Candidate IOC string.

    Returns:
        Detected ``IocType``, or ``UNKNOWN`` if nothing matches.
    """
    value = raw.strip()
    if not value:
        return IocType.UNKNOWN
    if _URL_RE.match(value) and _looks_like_url(value):
        return IocType.URL
    if _is_ip_address(value):
        return IocType.IP
    if _HASH_RE.fullmatch(value):
        return IocType.HASH
    if _DOMAIN_RE.fullmatch(value.rstrip(".")):
        return IocType.DOMAIN
    return IocType.UNKNOWN


def normalize_url(raw: str) -> str:
    """Canonicalize a URL so slash, case, default port and fragment variants match.

    Used as the VirusTotal URL identifier input and as the cache key.

    Args:
        raw: URL as typed by the analyst.

    Returns:
        Canonical URL (lowercase scheme/host, path at least ``/``, no fragment,
        no default :80/:443 port).
    """
    parts = urlsplit(raw.strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = parts.port
    default_port = _DEFAULT_PORTS.get(scheme)
    if port is not None and port != default_port:
        netloc = f"{host}:{port}"
    else:
        netloc = host
    if parts.username:
        userinfo = quote_userinfo(parts.username, parts.password)
        netloc = f"{userinfo}@{netloc}"
    path = parts.path if parts.path else "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def quote_userinfo(username: str, password: Optional[str]) -> str:
    """Rebuild userinfo for a URL netloc.

    Args:
        username: URL username.
        password: Optional URL password.

    Returns:
        ``user`` or ``user:pass`` fragment.
    """
    if password is None:
        return username
    return f"{username}:{password}"


def classify(detection_count: int) -> Verdict:
    """Map VirusTotal engine hits to a per-source verdict.

    Args:
        detection_count: ``malicious + suspicious`` engine hits.

    Returns:
        Clean (0), Suspicious (1-3), or Malicious (4+).
    """
    if detection_count <= 0:
        return Verdict.CLEAN
    if detection_count <= 3:
        return Verdict.SUSPICIOUS
    return Verdict.MALICIOUS


def classify_virustotal(
    vt_malicious: int,
    vt_suspicious: int,
    *,
    has_report: bool,
) -> Optional[Verdict]:
    """Classify a VirusTotal lookup.

    Args:
        vt_malicious: Malicious engine count.
        vt_suspicious: Suspicious engine count.
        has_report: True when VT returned analysis stats.

    Returns:
        Per-source verdict, or ``Unknown`` when VT has no report.
        ``None`` if VirusTotal was not queried.
    """
    if not has_report:
        return Verdict.UNKNOWN
    count = max(0, vt_malicious) + max(0, vt_suspicious)
    return classify(count)


def classify_abuseipdb(abuse_score: Optional[int]) -> Optional[Verdict]:
    """Classify an AbuseIPDB confidence score.

    0-24 Clean, 25-74 Suspicious, 75-100 Malicious.

    Args:
        abuse_score: abuseConfidenceScore, or None if unused/unavailable.

    Returns:
        Per-source verdict, or ``None`` when there is no score.
    """
    if abuse_score is None:
        return None
    if abuse_score >= 75:
        return Verdict.MALICIOUS
    if abuse_score >= 25:
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN


def combine_verdicts(*verdicts: Optional[Verdict]) -> Verdict:
    """Return the worse verdict among sources that produced a result.

    Severity order: Malicious > Suspicious > Unknown > Clean.

    Args:
        verdicts: Per-source verdicts; ``None`` is ignored.

    Returns:
        Combined verdict. ``Unknown`` if no source produced a result.
    """
    present = [item for item in verdicts if item is not None]
    if not present:
        return Verdict.UNKNOWN
    return max(present, key=lambda item: _VERDICT_RANK[item])


def format_vt_cell(row: TriageResult) -> str:
    """Human-readable VirusTotal column text.

    Args:
        row: Triage result.

    Returns:
        Verdict plus engine ratio, or an em dash.
    """
    if row.vt_verdict is None:
        return "—"
    if row.vt_total:
        hits = row.vt_malicious + row.vt_suspicious
        return f"{row.vt_verdict.value} {hits}/{row.vt_total}"
    return row.vt_verdict.value


def format_abuse_cell(row: TriageResult) -> str:
    """Human-readable AbuseIPDB column text.

    Args:
        row: Triage result.

    Returns:
        Verdict plus confidence, or an em dash.
    """
    if row.abuse_verdict is None or row.abuse_score is None:
        return "—"
    return f"{row.abuse_verdict.value} {row.abuse_score}%"


def _is_ip_address(value: str) -> bool:
    """Return True if value is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _looks_like_url(value: str) -> bool:
    """Return True if value parses as an http(s) URL with a netloc."""
    parsed = urlsplit(value)
    return parsed.scheme.lower() in {"http", "https"} and bool(parsed.netloc)
