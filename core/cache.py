"""Local JSON cache for IOC lookup results with a 24-hour TTL."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from core.classifier import IocType

TTL = timedelta(hours=24)
DEFAULT_CACHE_PATH = Path(".cache") / "ioc_cache.json"


class IocCache:
    """File-backed cache mapping (type, IOC) to API payloads."""

    def __init__(self, path: Path = DEFAULT_CACHE_PATH) -> None:
        """Initialize the cache and load existing entries from disk.

        Args:
            path: JSON file used to persist cache entries.
        """
        self.path = path
        self._entries: dict[str, dict[str, Any]] = {}
        self._load()

    def cache_key(self, ioc_type: IocType, ioc: str) -> str:
        """Build a stable cache key.

        Args:
            ioc_type: Detected IOC type.
            ioc: Normalized IOC value.

        Returns:
            String key unique for type and value.
        """
        return f"{ioc_type.value}:{ioc}"

    def get(
        self,
        ioc_type: IocType,
        ioc: str,
        now: Optional[datetime] = None,
    ) -> Optional[dict[str, Any]]:
        """Return a cached payload if it exists and is younger than 24h.

        Args:
            ioc_type: Detected IOC type.
            ioc: Normalized IOC value.
            now: Clock override for tests.

        Returns:
            Stored payload dict, or ``None`` on miss / expiry.
        """
        key = self.cache_key(ioc_type, ioc)
        entry = self._entries.get(key)
        if not entry:
            return None
        stored_at = datetime.fromisoformat(entry["stored_at"])
        current = now or datetime.now(timezone.utc)
        if current - stored_at >= TTL:
            del self._entries[key]
            self._save()
            return None
        payload = dict(entry["payload"])
        return payload

    def set(
        self,
        ioc_type: IocType,
        ioc: str,
        payload: dict[str, Any],
        now: Optional[datetime] = None,
    ) -> None:
        """Store a payload and persist the cache file.

        Args:
            ioc_type: Detected IOC type.
            ioc: Normalized IOC value.
            payload: Serializable lookup data.
            now: Clock override for tests.
        """
        current = now or datetime.now(timezone.utc)
        key = self.cache_key(ioc_type, ioc)
        self._entries[key] = {
            "stored_at": current.isoformat(),
            "payload": payload,
        }
        self._save()

    def _load(self) -> None:
        """Load cache entries from disk; ignore missing or corrupt files."""
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self._entries = {}
            return
        if isinstance(raw, dict):
            self._entries = raw
        else:
            self._entries = {}

    def _save(self) -> None:
        """Write the in-memory cache to disk."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(self._entries, indent=2),
            encoding="utf-8",
        )
