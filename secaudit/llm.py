"""Optional Ollama integration: turns the audit report into an analyst-style summary."""

from __future__ import annotations

import json
import re
from typing import Any, Iterator

import httpx

SYSTEM_PROMPT = """You are a senior web application security analyst writing for the site owner.
You receive the JSON output of a passive, non-intrusive security audit (no exploitation was attempted).
Write a concise report in Markdown with these sections:

## Executive summary
2-4 sentences: overall posture, the grade, and the single most important risk.

## Top priorities
A numbered list (max 7) of the most important fixes, ordered by real-world risk. For each: what is wrong,
why it matters in practice, and the concrete fix (config snippet when helpful). Prioritise actively
exploited CVEs (kev=true) and high EPSS scores, then transport/TLS/cookie/header issues.

## Known vulnerabilities
Summarise CVE exposure per component. Mention that distro packages may backport fixes when the server
banner shows a distribution (e.g. Ubuntu/Debian). Do not invent CVE IDs - only use ones in the input.

## Quick wins
Bullet list of low-effort hardening steps.

If coverage.complete is false, a bot challenge/WAF hid the site: say so up front, do not draw conclusions
about headers, cookies or the tech stack, and recommend re-running the audit from an allow-listed IP.

Rules: be factual, use only the provided data, do not speculate beyond it, no exploitation instructions."""


class OllamaError(RuntimeError):
    pass


class Ollama:
    def __init__(self, base_url: str, timeout: float = 600):
        self.base = base_url.rstrip("/")
        self.timeout = timeout

    def models(self) -> list[dict[str, Any]]:
        try:
            r = httpx.get(f"{self.base}/api/tags", timeout=5)
            r.raise_for_status()
            return r.json().get("models", [])
        except (httpx.HTTPError, ValueError) as e:
            raise OllamaError(f"cannot reach Ollama at {self.base}: {e}") from e

    def pick_model(self, preferred: str | None) -> str:
        names = [m["name"] for m in self.models()]
        if not names:
            raise OllamaError("Ollama has no models installed (try: ollama pull qwen2.5:7b)")
        if preferred:
            for n in names:
                if n == preferred or n.split(":")[0] == preferred or n == f"{preferred}:latest":
                    return n
            raise OllamaError(f"model {preferred!r} not found. Installed: {', '.join(names)}")
        # prefer general instruction models of reasonable size
        for pref in ("qwen2.5:7b", "qwen3:8b", "llama3.1", "llama3", "mistral", "gemma", "qwen"):
            for n in names:
                if n.startswith(pref) and "embed" not in n and "ocr" not in n:
                    return n
        return names[0]

    def stream_chat(self, model: str, system: str, user: str) -> Iterator[str]:
        payload = {
            "model": model,
            "stream": True,
            "think": False,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "options": {"temperature": 0.2, "num_ctx": 16384},
        }
        for attempt in range(2):
            try:
                with httpx.stream("POST", f"{self.base}/api/chat", json=payload, timeout=self.timeout) as r:
                    if r.status_code == 400 and attempt == 0:
                        r.read()
                        if "think" in r.text.lower():
                            payload.pop("think")  # model does not support the think flag
                            continue
                    if r.status_code != 200:
                        r.read()
                        raise OllamaError(f"Ollama returned {r.status_code}: {r.text[:300]}")
                    for line in r.iter_lines():
                        if not line:
                            continue
                        msg = json.loads(line)
                        if msg.get("error"):
                            raise OllamaError(msg["error"])
                        chunk = (msg.get("message") or {}).get("content", "")
                        if chunk:
                            yield chunk
                        if msg.get("done"):
                            return
                return
            except httpx.HTTPError as e:
                raise OllamaError(f"Ollama request failed: {e}") from e


def strip_thinking(text: str) -> str:
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
    if "<think>" in text:  # unterminated block while streaming
        text = text.split("<think>", 1)[0]
    return text.strip()


def build_prompt(report: dict[str, Any], max_cves: int = 40) -> str:
    """Condense the report to what matters, keeping the prompt small enough for local models."""
    s = report.get("sections", {})
    tls = s.get("tls", {})
    cert = tls.get("certificate", {})
    http = s.get("http", {})
    dom = s.get("domain", {})
    dns = s.get("dns", {})
    compact = {
        "target": report["target"],
        "grade": report.get("grade"),
        "coverage": report.get("coverage") or {"complete": True},
        "score": report.get("score"),
        "finding_counts": report.get("summary"),
        "findings": [{k: f[k] for k in ("severity", "category", "title", "evidence", "recommendation") if f.get(k)}
                     for f in report.get("findings", []) if f["severity"] != "INFO"][:60],
        "technologies": [f"{t['name']} {t.get('version') or ''}".strip() for t in report.get("technologies", [])],
        "os_hint": s.get("tech", {}).get("os_hint"),
        "cves": [{"id": c["id"], "product": f"{c['product']} {c.get('product_version')}", "cvss": c.get("score"),
                  "severity": c.get("severity"), "kev": c.get("kev"), "epss": c.get("epss"),
                  "summary": (c.get("summary") or "")[:180]} for c in report.get("cves", [])[:max_cves]],
        "total_cves": len(report.get("cves", [])),
        "tls": {"protocol": tls.get("negotiated_protocol"), "cipher": tls.get("negotiated_cipher"),
                "protocols": tls.get("protocols"), "issuer": cert.get("issuer_org"), "days_left": cert.get("days_left")},
        "security_headers_present": sorted(k for k in (http.get("headers") or {}) if k in {
            "strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options",
            "referrer-policy", "permissions-policy", "cross-origin-opener-policy"}),
        "domain": {k: (dom.get("registration") or {}).get(k) for k in ("registrar", "expires", "expires_in_days", "status")},
        "email": {k: (dns.get("email") or {}).get(k) for k in ("spf", "dmarc", "dmarc_policy")},
    }
    return "Audit result JSON:\n```json\n" + json.dumps(compact, indent=1, default=str) + "\n```"
