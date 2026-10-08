"""VirusTotal API v3 client for reputation lookups."""

from __future__ import annotations

import hashlib
from typing import Any, Optional
from urllib.parse import quote

import httpx

from core.classifier import IocType

VT_BASE = "https://www.virustotal.com/api/v3"
VT_GUI = "https://www.virustotal.com/gui"
DEFAULT_TIMEOUT = 15.0


class VirusTotalClient:
    """Thin VirusTotal v3 wrapper. Skips requests when no API key is set."""

    def __init__(
        self,
        api_key: Optional[str],
        timeout: float = DEFAULT_TIMEOUT,
        client: Optional[httpx.Client] = None,
    ) -> None:
        """Create a client.

        Args:
            api_key: VirusTotal API key, or empty/None to disable the integration.
            timeout: HTTP timeout in seconds.
            client: Optional injected ``httpx.Client`` (tests).
        """
        self.api_key = (api_key or "").strip()
        self.timeout = timeout
        self._client = client
        self.enabled = bool(self.api_key)

    def lookup(self, ioc_type: IocType, ioc: str) -> Optional[dict[str, Any]]:
        """Look up an IOC on VirusTotal.

        Args:
            ioc_type: Detected type (ip, domain, hash, url).
            ioc: Normalized indicator.

        Returns:
            Parsed payload dict, a dict with ``error``, or ``None`` if disabled
            or the type is unsupported.
        """
        if not self.enabled:
            return None
        if ioc_type == IocType.UNKNOWN:
            return None
        path, gui_id, gui_kind = self._endpoint(ioc_type, ioc)
        if path is None:
            return None
        data = self._get(path)
        if "error" in data:
            return data
        return self._parse(ioc_type, ioc, data, gui_id, gui_kind)

    def _endpoint(
        self,
        ioc_type: IocType,
        ioc: str,
    ) -> tuple[Optional[str], str, str]:
        """Map IOC type to API path and GUI identifiers.

        Args:
            ioc_type: Detected type.
            ioc: Normalized indicator.

        Returns:
            Tuple of API path, GUI id, GUI resource kind.
        """
        if ioc_type == IocType.IP:
            return f"/ip_addresses/{quote(ioc, safe='')}", ioc, "ip-address"
        if ioc_type == IocType.DOMAIN:
            return f"/domains/{quote(ioc, safe='')}", ioc, "domain"
        if ioc_type == IocType.HASH:
            return f"/files/{quote(ioc, safe='')}", ioc, "file"
        if ioc_type == IocType.URL:
            url_id = hashlib.sha256(ioc.encode("utf-8")).hexdigest()
            return f"/urls/{url_id}", url_id, "url"
        return None, "", ""

    def _get(self, path: str) -> dict[str, Any]:
        """Perform a GET request and return JSON or an error payload.

        Args:
            path: API path beginning with ``/``.

        Returns:
            Response JSON or ``{"error": ...}``.
        """
        url = f"{VT_BASE}{path}"
        headers = {"x-apikey": self.api_key, "Accept": "application/json"}
        try:
            if self._client is not None:
                response = self._client.get(url, headers=headers, timeout=self.timeout)
            else:
                response = httpx.get(url, headers=headers, timeout=self.timeout)
        except httpx.TimeoutException:
            return {"error": "VirusTotal request timed out"}
        except httpx.RequestError as exc:
            return {"error": f"VirusTotal network error: {exc}"}
        if response.status_code == 404:
            return {"error": "VirusTotal: indicator not found"}
        if response.status_code == 429:
            return {"error": "VirusTotal rate limit exceeded"}
        if response.status_code >= 400:
            return {"error": f"VirusTotal HTTP {response.status_code}"}
        try:
            payload = response.json()
        except ValueError:
            return {"error": "VirusTotal returned invalid JSON"}
        if not isinstance(payload, dict):
            return {"error": "VirusTotal returned unexpected payload"}
        return payload

    def _parse(
        self,
        ioc_type: IocType,
        ioc: str,
        payload: dict[str, Any],
        gui_id: str,
        gui_kind: str,
    ) -> dict[str, Any]:
        """Extract stats, country, related entities, and GUI link.

        Args:
            ioc_type: Detected type.
            ioc: Normalized indicator.
            payload: Raw VT JSON.
            gui_id: Identifier used in the GUI URL.
            gui_kind: GUI resource kind.

        Returns:
            Normalized lookup dict.
        """
        data = payload.get("data") or {}
        attributes = data.get("attributes") or {}
        stats = attributes.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        total = sum(int(v or 0) for v in stats.values()) if stats else 0
        country = attributes.get("country") or attributes.get("country_code")
        related = _extract_related(attributes)
        return {
            "vt_malicious": malicious,
            "vt_suspicious": suspicious,
            "vt_total": total,
            "country": country,
            "related": related,
            "vt_link": f"{VT_GUI}/{gui_kind}/{gui_id}",
            "raw_ioc": ioc,
            "ioc_type": ioc_type.value,
        }


def _extract_related(attributes: dict[str, Any]) -> list[str]:
    """Collect related domains or hashes from VT attributes.

    Args:
        attributes: VirusTotal object attributes.

    Returns:
        Short list of related indicators (max 8).
    """
    related: list[str] = []
    names = attributes.get("last_dns_records") or []
    if isinstance(names, list):
        for record in names:
            if isinstance(record, dict) and record.get("type") == "A":
                value = record.get("value")
                if value:
                    related.append(str(value))
    resolutions = attributes.get("resolutions") or []
    if isinstance(resolutions, list):
        for item in resolutions:
            if isinstance(item, dict):
                host = item.get("hostname") or item.get("ip_address")
                if host:
                    related.append(str(host))
    for key in ("contacted_domains", "contacted_ips"):
        values = attributes.get(key) or []
        if isinstance(values, list):
            related.extend(str(v) for v in values if v)
    names_list = attributes.get("names") or []
    if isinstance(names_list, list):
        related.extend(str(n) for n in names_list if n)
    # de-duplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for item in related:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique[:8]
