"""Core data structures shared by collectors, reporting and history."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @property
    def style(self) -> str:
        return {
            Severity.INFO: "cyan",
            Severity.LOW: "green",
            Severity.MEDIUM: "yellow",
            Severity.HIGH: "bold red",
            Severity.CRITICAL: "bold white on red",
        }[self]

    @classmethod
    def parse(cls, value: str | int | "Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).upper()]

    @classmethod
    def from_cvss(cls, score: float | None) -> "Severity":
        if score is None:
            return cls.MEDIUM
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0:
            return cls.LOW
        return cls.INFO


@dataclass
class Finding:
    id: str  # stable identifier, used to diff audits over time
    title: str
    severity: Severity
    category: str
    detail: str = ""
    recommendation: str = ""
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        d = dict(d)
        d["severity"] = Severity.parse(d["severity"])
        return cls(**d)


@dataclass
class Technology:
    name: str
    version: str | None = None
    category: str = "Other"
    source: str = ""  # how it was detected
    confidence: str = "high"

    def key(self) -> str:
        return self.name.lower()


@dataclass
class CVE:
    id: str
    product: str
    product_version: str | None
    score: float | None = None
    severity: str = "UNKNOWN"
    vector: str = ""
    published: str = ""
    summary: str = ""
    kev: bool = False  # in CISA Known Exploited Vulnerabilities catalog
    epss: float | None = None  # probability of exploitation in next 30 days
    epss_percentile: float | None = None
    source: str = ""  # NVD / OSV
    url: str = ""
    aliases: list[str] = field(default_factory=list)


@dataclass
class SectionResult:
    """Output of one collector."""

    name: str
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add(self, *args: Any, **kwargs: Any) -> Finding:
        f = Finding(*args, **kwargs)
        self.findings.append(f)
        return f
