"""HTTP layer: redirects, security headers, cookies, CORS, methods, error pages.

Every request here is an ordinary GET/OPTIONS that any browser or crawler
would make; nothing is fuzzed or exploited.
"""

from __future__ import annotations

import re
import secrets
import time
from urllib.parse import urlsplit

import httpx

from secaudit.collectors import waf
from secaudit.context import AuditContext
from secaudit.models import SectionResult, Severity
from secaudit.net import client

MAX_BODY = 5 * 1024 * 1024
SESSIONISH = re.compile(r"sess|sid|auth|token|login|jwt|remember|csrf|xsrf", re.I)


def _fetch(c: httpx.Client, method: str, url: str, **kw) -> httpx.Response:
    return c.request(method, url, **kw)


def _headers_dict(h: httpx.Headers) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in h.multi_items():
        k = k.lower()
        if k == "set-cookie":
            continue
        out[k] = f"{out[k]}, {v}" if k in out else v
    return out


def _chain(resp: httpx.Response) -> list[dict]:
    hops = []
    for r in [*resp.history, resp]:
        hops.append({"url": str(r.url), "status": r.status_code, "location": r.headers.get("location", "")})
    return hops


def run(ctx: AuditContext) -> SectionResult:
    res = SectionResult("http")
    t = ctx.target
    timeout = ctx.config.timeout

    with client(timeout, verify=ctx.options.verify_tls) as c:
        # 1. Plain HTTP: does it upgrade to HTTPS?
        http_resp = None
        if not t.port or t.scheme_hint == "http":
            try:
                http_resp = _fetch(c, "GET", t.url("http"))
                res.data["http_redirect_chain"] = _chain(http_resp)
            except httpx.HTTPError as e:
                res.data["http_redirect_chain"] = []
                res.data["http_error"] = f"{type(e).__name__}: {e}"

        # 2. HTTPS main page
        resp = None
        start = time.perf_counter()
        try:
            resp = _fetch(c, "GET", t.url("https") if t.scheme_hint == "https" or not t.port else t.url())
            ctx.https_ok = str(resp.url).startswith("https://")
        except httpx.HTTPError as e:
            res.errors.append(f"HTTPS request failed: {type(e).__name__}: {e}")
            res.data["https_error"] = f"{type(e).__name__}: {e}"
        elapsed = (time.perf_counter() - start) * 1000

        if resp is None and http_resp is not None:
            resp = http_resp
        if resp is None:
            res.add("http.unreachable", "Site is unreachable over HTTP and HTTPS", Severity.HIGH, "HTTP",
                    detail="; ".join(res.errors) or res.data.get("http_error", ""))
            return res

        ctx.response = resp
        ctx.final_url = str(resp.url)
        body = resp.content[:MAX_BODY]
        ctx.html = body.decode(resp.encoding or "utf-8", errors="replace")
        headers = _headers_dict(resp.headers)
        set_cookies = resp.headers.get_list("set-cookie")
        for r in resp.history:
            set_cookies += r.headers.get_list("set-cookie")

        res.data["main"] = {
            "url": ctx.final_url,
            "status": resp.status_code,
            "reason": resp.reason_phrase,
            "http_version": resp.http_version,
            "elapsed_ms": round(elapsed),
            "size_bytes": len(resp.content),
            "content_type": headers.get("content-type", ""),
            "redirect_chain": _chain(resp),
        }
        res.data["headers"] = headers
        res.data["set_cookie_raw"] = set_cookies

        blocked = waf.detect(resp.status_code, headers, ctx.html)
        if blocked:
            # Headers, cookies and HTML now describe the WAF's interstitial, not the site:
            # keep only checks that hold at the edge (HTTPS + redirect) and stop here.
            ctx.blocked = blocked
            res.data["blocked"] = blocked
            res.add("coverage.blocked",
                    f"{blocked['vendor']} served a {blocked['kind']} instead of the site (HTTP {blocked['status']})",
                    Severity.INFO, "Audit coverage",
                    detail="Header, cookie, content and tech-stack checks were skipped because they would describe "
                           "the challenge page. TLS, DNS, domain and email results are unaffected.",
                    evidence=f"detected via {blocked['signal']}",
                    recommendation="Audit from an allow-listed IP, or temporarily exempt the auditing host from bot protection.")
            _check_transport(ctx, res, http_resp)
            return res

        _check_transport(ctx, res, http_resp)
        if ctx.https_ok:
            _check_hsts(ctx, res, headers, c)
        _check_csp_and_framing(res, headers)
        _check_misc_headers(res, headers, ctx.https_ok)
        _check_cookies(res, set_cookies, ctx.https_ok)
        _check_cors(c, ctx, res)
        _check_methods(c, ctx, res)
        _check_error_page(c, ctx, res)
    return res


# --------------------------------------------------------------------------- transport


def _check_transport(ctx: AuditContext, res: SectionResult, http_resp: httpx.Response | None) -> None:
    if not ctx.https_ok:
        res.add("http.no-https", "Site is not served over HTTPS", Severity.CRITICAL, "Transport",
                detail="All traffic, including cookies and form data, travels in clear text.",
                recommendation="Obtain a certificate (e.g. Let's Encrypt) and serve the site exclusively over HTTPS.")
        return
    if http_resp is None:
        return
    chain = [str(r.url) for r in [*http_resp.history, http_resp]]
    if not str(http_resp.url).startswith("https://"):
        res.add("http.no-redirect", "HTTP does not redirect to HTTPS", Severity.HIGH, "Transport",
                detail=f"http:// request ended at {http_resp.url} (status {http_resp.status_code}).",
                recommendation="Return a 301 redirect from every http:// URL to its https:// equivalent.")
        return
    first = http_resp.history[0] if http_resp.history else None
    if first is not None:
        loc = first.headers.get("location", "")
        if loc.startswith("http://"):
            res.add("http.redirect-via-http", "HTTP→HTTPS redirect passes through another plain-HTTP hop",
                    Severity.LOW, "Transport", evidence=" → ".join(chain),
                    recommendation="Redirect straight to the canonical https:// URL on the same host first.")
        if first.status_code in (302, 303, 307):
            res.add("http.temp-redirect", f"HTTP→HTTPS redirect uses temporary status {first.status_code}",
                    Severity.INFO, "Transport", recommendation="Use 301/308 so clients and caches remember the upgrade.")


# --------------------------------------------------------------------------- HSTS


def _check_hsts(ctx: AuditContext, res: SectionResult, headers: dict[str, str], c: httpx.Client) -> None:
    hsts = headers.get("strict-transport-security")
    info: dict = {"header": hsts}
    if not hsts:
        res.add("hsts.missing", "Missing Strict-Transport-Security (HSTS) header", Severity.MEDIUM, "Headers",
                detail="Without HSTS, users can be downgraded to HTTP by an on-path attacker (SSL stripping).",
                recommendation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains")
    else:
        m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
        max_age = int(m.group(1)) if m else 0
        info.update(max_age=max_age, include_subdomains="includesubdomains" in hsts.lower(),
                    preload_directive="preload" in hsts.lower())
        if max_age < 15552000:
            res.add("hsts.short", f"HSTS max-age is short ({max_age}s, {max_age // 86400} days)", Severity.LOW,
                    "Headers", evidence=hsts, recommendation="Use max-age of at least 15552000 (180 days), ideally 31536000.")
        if not info["include_subdomains"]:
            res.add("hsts.no-subdomains", "HSTS does not include subdomains", Severity.INFO, "Headers", evidence=hsts,
                    recommendation="Add includeSubDomains once all subdomains support HTTPS.")
    # preload list status (public API; only queried for the registrable domain)
    domain = ctx.apex or ctx.target.host
    if not ctx.target.is_ip:
        try:
            r = c.get(f"https://hstspreload.org/api/v2/status?domain={domain}", timeout=8)
            if r.status_code == 200:
                info["preload_status"] = r.json().get("status")
        except (httpx.HTTPError, ValueError):
            pass
    res.data["hsts"] = info


# --------------------------------------------------------------------------- CSP & framing


def parse_csp(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t for t in tokens[1:]])
    return directives


def _check_csp_and_framing(res: SectionResult, headers: dict[str, str]) -> None:
    csp = headers.get("content-security-policy")
    csp_ro = headers.get("content-security-policy-report-only")
    xfo = headers.get("x-frame-options")
    analysis: dict = {"header": csp, "report_only": csp_ro, "issues": []}
    directives = parse_csp(csp) if csp else {}
    analysis["directives"] = directives

    if not csp:
        if csp_ro:
            res.add("csp.report-only", "Content-Security-Policy is only in report-only mode", Severity.LOW, "Headers",
                    evidence=csp_ro[:300], recommendation="Enforce the policy once violation reports are clean.")
        else:
            res.add("csp.missing", "Missing Content-Security-Policy header", Severity.MEDIUM, "Headers",
                    detail="A CSP is the main defence-in-depth control against XSS and data injection.",
                    recommendation="Start with: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
    else:
        script = directives.get("script-src", directives.get("default-src"))
        if script is None:
            analysis["issues"].append("no script-src/default-src")
            res.add("csp.no-script-src", "CSP has no script-src or default-src directive", Severity.MEDIUM, "Headers",
                    evidence=csp[:300], recommendation="Define default-src or script-src so scripts are restricted.")
        else:
            lowered = [s.lower() for s in script]
            has_nonce_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in lowered)
            strict_dynamic = "'strict-dynamic'" in lowered
            if "'unsafe-inline'" in lowered and not has_nonce_hash:
                res.add("csp.unsafe-inline", "CSP allows 'unsafe-inline' scripts", Severity.MEDIUM, "Headers",
                        detail="Inline script injection (the most common XSS) is not blocked by this policy.",
                        evidence=" ".join(script)[:300],
                        recommendation="Replace 'unsafe-inline' with nonces or hashes (optionally 'strict-dynamic').")
            if "'unsafe-eval'" in lowered:
                res.add("csp.unsafe-eval", "CSP allows 'unsafe-eval'", Severity.LOW, "Headers",
                        evidence=" ".join(script)[:300], recommendation="Remove 'unsafe-eval' and avoid eval()/new Function().")
            wild = [s for s in lowered if s in ("*", "http:", "https:", "data:") or s.startswith("http://")]
            if wild and not strict_dynamic:
                res.add("csp.wildcard", f"CSP script sources are overly broad ({', '.join(wild)})", Severity.MEDIUM,
                        "Headers", evidence=" ".join(script)[:300],
                        recommendation="List explicit trusted origins or use nonces with 'strict-dynamic'.")
        default = [s.lower() for s in directives.get("default-src", [])]
        if "object-src" not in directives and "'none'" not in default:
            res.add("csp.object-src", "CSP lacks object-src 'none'", Severity.LOW, "Headers",
                    recommendation="Add object-src 'none' to block plugin-based injection.")
        if "base-uri" not in directives:
            res.add("csp.base-uri", "CSP lacks base-uri", Severity.LOW, "Headers",
                    recommendation="Add base-uri 'self' (or 'none') to prevent <base> tag hijacking.")

    has_frame_ancestors = "frame-ancestors" in directives
    if not xfo and not has_frame_ancestors:
        res.add("framing.missing", "No clickjacking protection (X-Frame-Options / frame-ancestors)", Severity.MEDIUM,
                "Headers", detail="The page can be embedded in a hostile site's iframe.",
                recommendation="Add CSP frame-ancestors 'self' (and X-Frame-Options: SAMEORIGIN for old browsers).")
    elif xfo and xfo.strip().upper().startswith("ALLOW-FROM"):
        res.add("framing.allow-from", "X-Frame-Options ALLOW-FROM is obsolete and ignored", Severity.LOW, "Headers",
                evidence=xfo, recommendation="Use CSP frame-ancestors instead.")
    res.data["csp"] = analysis


# --------------------------------------------------------------------------- other headers


def _check_misc_headers(res: SectionResult, h: dict[str, str], https: bool) -> None:
    if h.get("x-content-type-options", "").lower().strip() != "nosniff":
        res.add("hdr.nosniff", "Missing X-Content-Type-Options: nosniff", Severity.LOW, "Headers",
                recommendation="Add X-Content-Type-Options: nosniff to stop MIME-type sniffing.")
    rp = h.get("referrer-policy", "").lower()
    if not rp:
        res.add("hdr.referrer", "Missing Referrer-Policy header", Severity.LOW, "Headers",
                recommendation="Add Referrer-Policy: strict-origin-when-cross-origin (or stricter).")
    elif "unsafe-url" in rp or rp.strip() == "no-referrer-when-downgrade":
        res.add("hdr.referrer-weak", f"Weak Referrer-Policy ({rp})", Severity.LOW, "Headers",
                recommendation="Use strict-origin-when-cross-origin or no-referrer.")
    if "permissions-policy" not in h:
        res.add("hdr.permissions", "Missing Permissions-Policy header", Severity.LOW, "Headers",
                recommendation="Restrict powerful features, e.g. Permissions-Policy: camera=(), microphone=(), geolocation=()")
    for name, label in (("cross-origin-opener-policy", "COOP"), ("cross-origin-resource-policy", "CORP")):
        if name not in h:
            res.add(f"hdr.{label.lower()}", f"Missing {name} ({label})", Severity.INFO, "Headers",
                    recommendation=f"Consider {name}: same-origin for cross-origin isolation.")
    xxss = h.get("x-xss-protection")
    if xxss and xxss.strip().startswith("1"):
        res.add("hdr.xxss", "Deprecated X-XSS-Protection filter is enabled", Severity.INFO, "Headers", evidence=xxss,
                recommendation="Set X-XSS-Protection: 0 (or remove it) and rely on CSP; the legacy filter can introduce leaks.")

    # information disclosure
    server = h.get("server", "")
    if re.search(r"\d+\.\d+", server):
        res.add("disclosure.server", "Server header discloses software version", Severity.LOW, "Information disclosure",
                evidence=f"Server: {server}", recommendation="Suppress version details (e.g. nginx server_tokens off; Apache ServerTokens Prod).")
    for hdr in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-runtime", "x-version"):
        if hdr in h:
            res.add(f"disclosure.{hdr}", f"{hdr} header discloses technology details", Severity.LOW,
                    "Information disclosure", evidence=f"{hdr}: {h[hdr]}", recommendation=f"Remove the {hdr} header.")
    for hdr in ("x-debug-token", "x-debug-token-link", "x-backend-server", "x-upstream", "x-served-by-host"):
        if hdr in h:
            res.add(f"disclosure.{hdr}", f"Internal/debug header exposed: {hdr}", Severity.LOW, "Information disclosure",
                    evidence=f"{hdr}: {h[hdr]}", recommendation="Strip internal headers at the edge.")


# --------------------------------------------------------------------------- cookies


def _parse_set_cookie(raw: str) -> dict:
    parts = [p.strip() for p in raw.split(";")]
    name, _, value = parts[0].partition("=")
    attrs: dict[str, str | bool] = {}
    for p in parts[1:]:
        k, eq, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip() if eq else True
    return {"name": name.strip(), "value_len": len(value), "attrs": attrs, "raw": raw}


def _check_cookies(res: SectionResult, raw_cookies: list[str], https: bool) -> None:
    cookies = []
    issues: dict[str, list[str]] = {"secure": [], "httponly": [], "samesite": [], "none_insecure": [], "prefix": []}
    seen = set()
    for raw in raw_cookies:
        ck = _parse_set_cookie(raw)
        if ck["name"] in seen:
            continue
        seen.add(ck["name"])
        a = ck["attrs"]
        ck.update(secure="secure" in a, httponly="httponly" in a, samesite=str(a.get("samesite", "")) or None,
                  domain=a.get("domain"), path=a.get("path"), expires=a.get("expires") or a.get("max-age"))
        cookies.append(ck)
        name = ck["name"]
        if https and not ck["secure"]:
            issues["secure"].append(name)
        if not ck["httponly"] and SESSIONISH.search(name):
            issues["httponly"].append(name)
        if not ck["samesite"]:
            issues["samesite"].append(name)
        elif str(ck["samesite"]).lower() == "none" and not ck["secure"]:
            issues["none_insecure"].append(name)
        if name.startswith(("__Host-", "__Secure-")) and not ck["secure"]:
            issues["prefix"].append(name)
        if name.startswith("BIGipServer"):
            ip = _decode_bigip(raw.split(";")[0].split("=", 1)[1])
            if ip:
                res.add("cookie.bigip", "F5 BIG-IP persistence cookie leaks an internal IP address", Severity.LOW,
                        "Information disclosure", evidence=f"{name} → {ip}",
                        recommendation="Enable cookie encryption for the BIG-IP persistence profile.")
    for c in cookies:
        c.pop("raw", None)
    res.data["cookies"] = cookies

    sess_insecure = [n for n in issues["secure"] if SESSIONISH.search(n)]
    if issues["secure"]:
        res.add("cookie.no-secure", f"{len(issues['secure'])} cookie(s) set without the Secure flag",
                Severity.MEDIUM if sess_insecure else Severity.LOW, "Cookies", evidence=", ".join(issues["secure"]),
                recommendation="Set Secure on every cookie served over HTTPS.")
    if issues["httponly"]:
        res.add("cookie.no-httponly", "Session-like cookie(s) readable by JavaScript (no HttpOnly)", Severity.MEDIUM,
                "Cookies", evidence=", ".join(issues["httponly"]),
                recommendation="Set HttpOnly on session/auth cookies so XSS cannot steal them.")
    if issues["samesite"]:
        res.add("cookie.no-samesite", f"{len(issues['samesite'])} cookie(s) without an explicit SameSite attribute",
                Severity.LOW, "Cookies", evidence=", ".join(issues["samesite"]),
                recommendation="Set SameSite=Lax (or Strict) explicitly.")
    if issues["none_insecure"]:
        res.add("cookie.samesite-none", "SameSite=None cookie without Secure (rejected by browsers)", Severity.MEDIUM,
                "Cookies", evidence=", ".join(issues["none_insecure"]))
    if issues["prefix"]:
        res.add("cookie.prefix", "__Host-/__Secure- prefixed cookie missing Secure", Severity.LOW, "Cookies",
                evidence=", ".join(issues["prefix"]))


def _decode_bigip(value: str) -> str | None:
    m = re.match(r"^(\d+)\.(\d+)\.\d+$", value)
    if not m:
        return None
    n = int(m.group(1))
    ip = ".".join(str((n >> (8 * i)) & 0xFF) for i in range(4))
    port = int(m.group(2))
    port = ((port & 0xFF) << 8) | (port >> 8)
    return f"{ip}:{port}"


# --------------------------------------------------------------------------- CORS / methods


def _check_cors(c: httpx.Client, ctx: AuditContext, res: SectionResult) -> None:
    probe_origin = "https://secaudit-cors-check.example"
    try:
        r = c.get(ctx.final_url, headers={"Origin": probe_origin}, follow_redirects=False)
    except httpx.HTTPError:
        return
    acao = r.headers.get("access-control-allow-origin")
    acac = (r.headers.get("access-control-allow-credentials") or "").lower() == "true"
    res.data["cors"] = {"allow_origin": acao, "allow_credentials": acac,
                        "allow_methods": r.headers.get("access-control-allow-methods")}
    if not acao:
        return
    if acao == probe_origin:
        res.add("cors.reflect", "CORS reflects arbitrary Origin" + (" with credentials" if acac else ""),
                Severity.HIGH if acac else Severity.LOW, "CORS",
                detail="Any website can read responses from this origin" + (" using the visitor's cookies." if acac else "."),
                evidence=f"Origin: {probe_origin} → Access-Control-Allow-Origin: {acao}",
                recommendation="Validate Origin against an explicit allow-list.")
    elif acao == "null":
        res.add("cors.null", "CORS allows the 'null' origin", Severity.MEDIUM, "CORS",
                detail="Sandboxed iframes and local files use origin 'null' and can read responses.",
                recommendation="Never allow-list the null origin.")
    elif acao == "*":
        res.add("cors.wildcard", "CORS allows any origin (*)", Severity.INFO, "CORS",
                detail="Fine for public, unauthenticated resources; dangerous for anything user-specific.")


def _check_methods(c: httpx.Client, ctx: AuditContext, res: SectionResult) -> None:
    try:
        r = c.request("OPTIONS", ctx.final_url, follow_redirects=False)
    except httpx.HTTPError:
        return
    allow = r.headers.get("allow") or r.headers.get("access-control-allow-methods") or ""
    methods = sorted({m.strip().upper() for m in allow.split(",") if m.strip()})
    res.data["options"] = {"status": r.status_code, "allow": methods}
    if "TRACE" in methods or "TRACK" in methods:
        res.add("methods.trace", "TRACE/TRACK method advertised", Severity.LOW, "HTTP",
                evidence=f"Allow: {allow}", recommendation="Disable TRACE (Apache: TraceEnable off).")
    risky = [m for m in methods if m in ("PUT", "DELETE", "PROPFIND", "MKCOL", "COPY", "MOVE", "CONNECT")]
    if risky:
        res.add("methods.risky", f"Potentially risky methods advertised: {', '.join(risky)}", Severity.INFO, "HTTP",
                evidence=f"Allow: {allow}", detail="Advertised only - not tested. Verify they require authentication.")


# --------------------------------------------------------------------------- error page

ERROR_LEAKS = [
    (r"You're seeing this error because you have <code>DEBUG = True</code>", "Django debug mode enabled", Severity.HIGH),
    (r"Whoops! There was an error|ignition-|laravel\.log|Illuminate\\", "Laravel debug/error page exposed", Severity.HIGH),
    (r"Action Controller: Exception caught|Rails\.root:", "Ruby on Rails debug page exposed", Severity.HIGH),
    (r"Traceback \(most recent call last\)", "Python stack trace in error page", Severity.MEDIUM),
    (r"at [a-z]+(\.[a-zA-Z_$][\w$]*)+\([\w]+\.java:\d+\)", "Java stack trace in error page", Severity.MEDIUM),
    (r"<b>(Fatal error|Warning|Notice)</b>:.* in <b>/", "PHP error with file path in error page", Severity.MEDIUM),
    (r"Server Error in '/' Application|ASP\.NET is configured to show verbose error", "ASP.NET verbose error page", Severity.MEDIUM),
    (r"Werkzeug Debugger|__debugger__", "Werkzeug interactive debugger exposed", Severity.CRITICAL),
]


def _check_error_page(c: httpx.Client, ctx: AuditContext, res: SectionResult) -> None:
    """Request one random non-existent path to see how errors are rendered."""
    base = urlsplit(ctx.final_url)
    url = f"{base.scheme}://{base.netloc}/secaudit-{secrets.token_hex(6)}"
    try:
        r = c.get(url, follow_redirects=False)
    except httpx.HTTPError:
        return
    body = r.text[:200_000]
    ctx.error_page_body = body
    ctx.error_page_headers = _headers_dict(r.headers)
    res.data["not_found"] = {"status": r.status_code, "size": len(r.content)}
    if r.status_code == 200:
        res.add("http.soft-404", "Non-existent paths return HTTP 200 (soft 404)", Severity.INFO, "HTTP",
                detail="Can confuse scanners and caches; usually a SPA catch-all route.")
    for pattern, title, sev in ERROR_LEAKS:
        if re.search(pattern, body, re.I):
            res.add("error." + re.sub(r"\W+", "-", title.lower())[:40], title, sev, "Information disclosure",
                    evidence=f"GET {url} → {r.status_code}",
                    recommendation="Disable debug output in production and use generic error pages.")
    m = re.search(r"<address>([^<]*Server at[^<]*)</address>|<center>((?:nginx|openresty)/[\d.]+)</center>|"
                  r"<h3>(Apache Tomcat/[\d.]+)</h3>", body)
    if m:
        res.add("disclosure.error-banner", "Default error page reveals server version", Severity.LOW,
                "Information disclosure", evidence=next(g for g in m.groups() if g).strip(),
                recommendation="Use custom error pages and hide version banners.")
