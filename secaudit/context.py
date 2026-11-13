"""Audit target and shared state passed between collectors."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

from secaudit.config import Config
from secaudit.models import CVE, Technology


@dataclass
class Target:
    input: str
    host: str
    port: int | None
    path: str
    scheme_hint: str  # scheme the user typed, or "https"

    @property
    def is_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
            return True
        except ValueError:
            return False

    def url(self, scheme: str | None = None, path: str | None = None) -> str:
        scheme = scheme or self.scheme_hint
        netloc = self.host if not self.port else f"{self.host}:{self.port}"
        if ":" in self.host and not self.host.startswith("["):
            netloc = f"[{self.host}]" + (f":{self.port}" if self.port else "")
        return f"{scheme}://{netloc}{path if path is not None else self.path}"

    @classmethod
    def parse(cls, raw: str) -> "Target":
        raw = raw.strip()
        if "://" not in raw:
            raw_url = "https://" + raw
            scheme = "https"
        else:
            raw_url = raw
            scheme = raw.split("://", 1)[0].lower()
        parts = urlsplit(raw_url)
        if scheme not in ("http", "https"):
            raise ValueError(f"unsupported scheme: {scheme}")
        if not parts.hostname:
            raise ValueError(f"could not parse a host from {raw!r}")
        host = parts.hostname.lower().rstrip(".")
        try:
            host = host.encode("idna").decode() if not _is_ip(host) else host
        except UnicodeError:
            pass
        return cls(input=raw, host=host, port=parts.port, path=parts.path or "/", scheme_hint=scheme)


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


@dataclass
class Options:
    verbose: int = 0
    exposure_checks: bool = False
    ct_logs: bool = True
    cve_lookup: bool = True
    fetch_assets: bool = True
    verify_tls: bool = True


@dataclass
class AuditContext:
    target: Target
    config: Config
    options: Options
    apex: str | None = None
    ips: list[str] = field(default_factory=list)
    # populated by the HTTP collector
    response: httpx.Response | None = None
    html: str = ""
    final_url: str = ""
    https_ok: bool = False
    error_page_body: str = ""
    error_page_headers: dict[str, str] = field(default_factory=dict)
    # set when a CDN/WAF served a challenge or block page instead of the site
    blocked: dict | None = None
    # populated by content / tech collectors
    script_srcs: list[str] = field(default_factory=list)
    technologies: list[Technology] = field(default_factory=list)
    cves: list[CVE] = field(default_factory=list)
    tls_cert_sans: list[str] = field(default_factory=list)
