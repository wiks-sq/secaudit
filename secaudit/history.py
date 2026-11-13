"""Per-domain audit history: one JSON file per audit under <history_dir>/<domain>/."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from secaudit.models import Finding


def _safe(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9.\-_]", "_", name.lower())


class History:
    def __init__(self, root: Path):
        self.root = root

    def domain_dir(self, domain: str) -> Path:
        return self.root / _safe(domain)

    def save(self, domain: str, report: dict[str, Any]) -> Path:
        d = self.domain_dir(domain)
        d.mkdir(parents=True, exist_ok=True)
        stamp = report["started_at"].replace(":", "").replace("-", "")[:15]
        path = d / f"{stamp}.json"
        n = 1
        while path.exists():
            path = d / f"{stamp}-{n}.json"
            n += 1
        path.write_text(json.dumps(report, indent=2, default=str))
        return path

    def list(self, domain: str) -> list[Path]:
        d = self.domain_dir(domain)
        return sorted(d.glob("*.json")) if d.exists() else []

    def domains(self) -> list[str]:
        if not self.root.exists():
            return []
        return sorted(p.name for p in self.root.iterdir() if p.is_dir() and any(p.glob("*.json")))

    def load(self, path: Path) -> dict[str, Any]:
        return json.loads(path.read_text())

    def previous(self, domain: str, exclude: Path | None = None) -> dict[str, Any] | None:
        files = [p for p in self.list(domain) if p != exclude]
        return self.load(files[-1]) if files else None

    def resolve(self, domain: str, ref: str | None) -> Path | None:
        """ref: None/'latest', 'previous', an index (1 = oldest, -1 = latest) or a filename prefix."""
        files = self.list(domain)
        if not files:
            return None
        if ref in (None, "latest"):
            return files[-1]
        if ref == "previous":
            return files[-2] if len(files) > 1 else None
        if re.fullmatch(r"-?\d+", ref):
            i = int(ref)
            try:
                return files[i - 1] if i > 0 else files[i]
            except IndexError:
                return None
        for f in files:
            if f.name.startswith(ref):
                return f
        return None


@dataclass
class Diff:
    new: list[Finding]
    resolved: list[Finding]
    severity_changed: list[tuple[Finding, Finding]]
    tech_added: list[str]
    tech_removed: list[str]
    tech_changed: list[tuple[str, str | None, str | None]]
    cves_new: list[str]
    cves_resolved: list[str]
    score_before: float | None
    score_after: float | None
    grade_before: str | None
    grade_after: str | None
    previous_at: str | None
    coverage_note: str | None = None
    old_blocked: bool = False
    new_blocked: bool = False


def diff_reports(old: dict[str, Any], new: dict[str, Any]) -> Diff:
    of = {f["id"] + "|" + f["title"]: Finding.from_dict(f) for f in old.get("findings", [])}
    nf = {f["id"] + "|" + f["title"]: Finding.from_dict(f) for f in new.get("findings", [])}
    # match by id first, fallback to id+title for multi-instance ids
    o_by_id = {f.id: f for f in of.values()}
    n_by_id = {f.id: f for f in nf.values()}
    new_f = [f for i, f in n_by_id.items() if i not in o_by_id]
    resolved = [f for i, f in o_by_id.items() if i not in n_by_id]
    changed = [(o_by_id[i], n_by_id[i]) for i in n_by_id if i in o_by_id and o_by_id[i].severity != n_by_id[i].severity]

    ot = {t["name"]: t.get("version") for t in old.get("technologies", [])}
    nt = {t["name"]: t.get("version") for t in new.get("technologies", [])}
    oc = {f"{c['product']}:{c['id']}" for c in old.get("cves", [])}
    nc = {f"{c['product']}:{c['id']}" for c in new.get("cves", [])}
    return Diff(
        new=sorted(new_f, key=lambda f: -f.severity),
        resolved=sorted(resolved, key=lambda f: -f.severity),
        severity_changed=changed,
        tech_added=sorted(set(nt) - set(ot)),
        tech_removed=sorted(set(ot) - set(nt)),
        tech_changed=[(n, ot[n], nt[n]) for n in sorted(set(ot) & set(nt)) if ot[n] != nt[n]],
        cves_new=sorted(c.split(":", 1)[1] for c in nc - oc),
        cves_resolved=sorted(c.split(":", 1)[1] for c in oc - nc),
        score_before=old.get("score"),
        score_after=new.get("score"),
        grade_before=old.get("grade"),
        grade_after=new.get("grade"),
        previous_at=old.get("started_at"),
        coverage_note=_coverage_note(old, new),
        old_blocked=bool((old.get("coverage") or {}).get("blocked")),
        new_blocked=bool((new.get("coverage") or {}).get("blocked")),
    )


def _coverage_note(old: dict[str, Any], new: dict[str, Any]) -> str | None:
    """Findings appear/disappear en masse when one audit was blocked by a bot challenge."""
    ob = (old.get("coverage") or {}).get("blocked")
    nb = (new.get("coverage") or {}).get("blocked")
    if nb and not ob:
        return f"This audit was blocked by {nb['vendor']} - 'fixed' page-level findings were simply not checked."
    if ob and not nb:
        return f"The previous audit was blocked by {ob['vendor']} - 'new' page-level findings may have existed before."
    return None
