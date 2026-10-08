"""AbuseIPDB API client for IP reputation checks."""

from __future__ import annotations

from typing import Any, Optional

import httpx

CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
DEFAULT_TIMEOUT = 15.0


class AbuseIPDBClient:
    """AbuseIPDB v2 check wrapper. Disabled when no API key is present."""

    def __init__(
        self,
        api_key: Optional[str],
        timeout: float = DEFAULT_TIMEOUT,
        client: Optional[httpx.Client] = None,
    ) -> None:
        """Create a client.

        Args:
            api_key: AbuseIPDB API key, or empty/None to disable.
            timeout: HTTP timeout in seconds.
            client: Optional injected ``httpx.Client`` (tests).
        """
        self.api_key = (api_key or "").strip()
        self.timeout = timeout
        self._client = client
        self.enabled = bool(self.api_key)

    def lookup(self, ip: str) -> Optional[dict[str, Any]]:
        """Check an IP address against AbuseIPDB.

        Args:
            ip: Normalized IPv4 or IPv6 address.

        Returns:
            Parsed payload, error dict, or ``None`` if the client is disabled.
        """
        if not self.enabled:
            return None
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        try:
            if self._client is not None:
                response = self._client.get(
                    CHECK_URL,
                    headers=headers,
                    params=params,
                    timeout=self.timeout,
                )
            else:
                response = httpx.get(
                    CHECK_URL,
                    headers=headers,
                    params=params,
                    timeout=self.timeout,
                )
        except httpx.TimeoutException:
            return {"error": "AbuseIPDB request timed out"}
        except httpx.RequestError as exc:
            return {"error": f"AbuseIPDB network error: {exc}"}
        if response.status_code == 429:
            return {"error": "AbuseIPDB rate limit exceeded"}
        if response.status_code >= 400:
            return {"error": f"AbuseIPDB HTTP {response.status_code}"}
        try:
            payload = response.json()
        except ValueError:
            return {"error": "AbuseIPDB returned invalid JSON"}
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict):
            return {"error": "AbuseIPDB returned unexpected payload"}
        related: list[str] = []
        domain = data.get("domain")
        if domain:
            related.append(str(domain))
        return {
            "abuse_score": int(data.get("abuseConfidenceScore") or 0),
            "country": data.get("countryCode"),
            "related": related,
        }
