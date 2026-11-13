"""Recognise bot-challenge and WAF block pages served instead of the real site.

When a CDN/WAF answers with an interstitial ("Just a moment...", "Access denied"),
everything page-level (headers, cookies, HTML, tech stack) describes the WAF,
not the website, so the audit must treat those results as unavailable.
"""

from __future__ import annotations

import re
from typing import Callable

import httpx

# (vendor, kind, header predicate or None, body regex or None)
# Body regexes only apply to error statuses, so normal pages that merely embed
# e.g. Cloudflare Turnstile are not mistaken for a challenge.
SIGNATURES: list[tuple[str, str, Callable[[dict[str, str]], bool] | None, str | None]] = [
    ("Cloudflare", "bot challenge", lambda h: h.get("cf-mitigated", "").lower() == "challenge", None),
    ("Cloudflare", "bot challenge", None,
     r"<title>Just a moment\.\.\.</title>|/cdn-cgi/challenge-platform/|window\._cf_chl_opt|cf-browser-verification"),
    ("Cloudflare", "block page", None,
     r"Attention Required! \| Cloudflare|id=\"cf-error-details\"|Sorry, you have been blocked|error code: 10(06|07|08|10|12|20)\b"),
    ("AWS WAF", "bot challenge", lambda h: "x-amzn-waf-action" in h, None),
    ("Akamai", "block page", None, r"<TITLE>Access Denied</TITLE>[\s\S]{0,600}Reference&#32;&#35;|errors\.edgesuite\.net"),
    ("Imperva", "block page", None, r"Incapsula incident ID|_Incapsula_Resource"),
    ("Sucuri", "block page", None, r"Sucuri WebSite Firewall - Access Denied|Access Denied - Sucuri Website Firewall"),
    ("DataDome", "bot challenge", None, r"captcha-delivery\.com"),
    ("HUMAN (PerimeterX)", "bot challenge", None, r"_pxCaptcha|px-captcha|/_px/captcha"),
]

BLOCK_STATUSES = {401, 403, 405, 406, 409, 429, 503}


def detect(status: int, headers: dict[str, str], body: str) -> dict | None:
    h = {k.lower(): v for k, v in headers.items()}
    sample = body[:60_000]
    for vendor, kind, header_check, body_rx in SIGNATURES:
        if header_check and header_check(h):
            return {"vendor": vendor, "kind": kind, "status": status, "signal": "response header"}
        if body_rx and status in BLOCK_STATUSES and re.search(body_rx, sample, re.I):
            return {"vendor": vendor, "kind": kind, "status": status, "signal": "page content"}
    return None


def detect_response(r: httpx.Response) -> dict | None:
    try:
        text = r.text
    except Exception:
        text = ""
    return detect(r.status_code, dict(r.headers), text)
