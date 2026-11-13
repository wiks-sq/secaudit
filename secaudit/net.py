"""Shared HTTP helpers and a tiny on-disk JSON cache."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

import httpx

from secaudit import USER_AGENT

BROWSER_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"


def client(timeout: float, follow_redirects: bool = True, verify: bool = True) -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(timeout, connect=min(timeout, 10)),
        follow_redirects=follow_redirects,
        verify=verify,
        headers={"User-Agent": USER_AGENT, "Accept": BROWSER_ACCEPT},
        max_redirects=10,
    )


class JsonCache:
    def __init__(self, root: Path, namespace: str, ttl_seconds: int):
        self.dir = root / namespace
        self.ttl = ttl_seconds

    def _path(self, key: str) -> Path:
        return self.dir / (hashlib.sha256(key.encode()).hexdigest()[:32] + ".json")

    def get(self, key: str) -> Any | None:
        p = self._path(key)
        try:
            if time.time() - p.stat().st_mtime > self.ttl:
                return None
            return json.loads(p.read_text())
        except (OSError, ValueError):
            return None

    def set(self, key: str, value: Any) -> None:
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            self._path(key).write_text(json.dumps(value))
        except OSError:
            pass
