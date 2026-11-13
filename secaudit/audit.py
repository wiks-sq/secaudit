"""Orchestrates collectors and assembles the final report dictionary."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable

from secaudit import __version__, cve
from secaudit.collectors import content_probe, dns_probe, domain_probe, http_probe, tech, tls_probe
from secaudit.context import AuditContext
from secaudit.models import Finding, SectionResult, Severity

Progress = Callable[[str, str], None]  # (step, status) status: start|done|error|info

WEIGHTS = {Severity.CRITICAL: 25, Severity.HIGH: 10, Severity.MEDIUM: 4, Severity.LOW: 1, Severity.INFO: 0}


def score_findings(findings: list[Finding]) -> tuple[float, str]:
    penalty = 0.0
    per_cat: dict[tuple[str, Severity], int] = {}
    for f in findings:
        # diminishing returns for many findings of the same kind in one category
        n = per_cat.get((f.category, f.severity), 0)
        per_cat[(f.category, f.severity)] = n + 1
        penalty += WEIGHTS[f.severity] * (0.6 ** n)
    score = max(0.0, round(100 - penalty, 1))
    worst = max((f.severity for f in findings), default=Severity.INFO)
    if score >= 95 and worst <= Severity.LOW:
        grade = "A+"
    elif score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"
    if worst == Severity.CRITICAL and grade in ("A+", "A", "B"):
        grade = "C"
    return score, grade


def _safe(name: str, fn: Callable[[], SectionResult], progress: Progress) -> SectionResult:
    progress(name, "start")
    try:
        r = fn()
        progress(name, "error" if r.errors and not r.data else "done")
        return r
    except Exception as e:  # a failing collector must never abort the whole audit
        progress(name, "error")
        r = SectionResult(name)
        r.errors.append(f"{type(e).__name__}: {e}")
        return r


def run_audit(ctx: AuditContext, progress: Progress) -> dict[str, Any]:
    started = datetime.now(timezone.utc)
    t0 = time.perf_counter()
    t = ctx.target

    progress("resolve", "start")
    if not t.is_ip:
        ctx.apex = dns_probe.find_apex(t.host, ctx.config.timeout)
        ctx.ips = dns_probe.resolve_ips(t.host, ctx.config.timeout)
    else:
        ctx.ips = [t.host]
    progress("resolve", "done" if ctx.ips else "error")

    sections: dict[str, SectionResult] = {}
    with ThreadPoolExecutor(max_workers=4) as pool:
        fut_http = pool.submit(_safe, "http", lambda: http_probe.run(ctx), progress)
        fut_tls = pool.submit(_safe, "tls", lambda: tls_probe.run(ctx), progress)
        fut_dns = pool.submit(_safe, "dns", lambda: dns_probe.run(ctx), progress)
        sections["tls"] = fut_tls.result()
        # domain needs TLS SANs to seed subdomain list
        fut_domain = pool.submit(_safe, "domain", lambda: domain_probe.run(ctx), progress)
        sections["http"] = fut_http.result()
        sections["content"] = _safe("content", lambda: content_probe.run(ctx), progress)
        sections["tech"] = _safe("tech", lambda: tech.run(ctx), progress)
        sections["dns"] = fut_dns.result()
        if ctx.options.cve_lookup:
            sections["cve"] = _safe("cve", lambda: cve.run(ctx, lambda m: progress(m, "info")), progress)
        sections["domain"] = fut_domain.result()

    findings: list[Finding] = []
    seen = set()
    for s in sections.values():
        for f in s.findings:
            key = (f.id, f.title)
            if key not in seen:
                seen.add(key)
                findings.append(f)
    findings.sort(key=lambda f: (-f.severity, f.category, f.title))
    score, grade = score_findings(findings)
    if any(f.id == "http.unreachable" for f in findings):
        grade = "N/A"  # nothing web-facing could be assessed; a letter grade would mislead
    if ctx.blocked:
        grade = "N/A"  # page-level checks were skipped, so the score only covers part of the audit

    finished = datetime.now(timezone.utc)
    report = {
        "tool": "secaudit",
        "tool_version": __version__,
        "target": {"input": t.input, "host": t.host, "apex": ctx.apex, "final_url": ctx.final_url, "ips": ctx.ips},
        "options": {k: v for k, v in ctx.options.__dict__.items()},
        "started_at": started.isoformat(timespec="seconds"),
        "finished_at": finished.isoformat(timespec="seconds"),
        "duration_s": round(time.perf_counter() - t0, 1),
        "score": score,
        "grade": grade,
        "coverage": {"complete": ctx.blocked is None, "blocked": ctx.blocked},
        "summary": {s.name: sum(1 for f in findings if f.severity == s) for s in Severity},
        "findings": [f.to_dict() for f in findings],
        "technologies": [x.__dict__ for x in ctx.technologies],
        "cves": [c.__dict__ for c in ctx.cves],
        "sections": {name: s.data for name, s in sections.items()},
        "errors": {name: s.errors for name, s in sections.items() if s.errors},
    }
    report["summary"] = {k.lower(): v for k, v in report["summary"].items()}
    # page body samples are large and only useful during the run
    report["sections"].get("content", {}).pop("inline_script_sample", None)
    return report
