"""Page content: mixed content, forms, SRI, third parties, comments, robots.txt,
security.txt, sitemap, and (opt-in) well-known exposure checks.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import httpx

from secaudit.collectors import waf
from secaudit.context import AuditContext
from secaudit.models import SectionResult, Severity
from secaudit.net import client

COMMENT_KEYWORDS = re.compile(r"todo|fixme|hack|password|passwd|secret|api[_-]?key|token|debug|admin|internal|"
                              r"staging|localhost|127\.0\.0\.1|192\.168\.|10\.\d+\.\d+\.\d+|bug|remove", re.I)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
SECRET_PATTERNS = [
    ("AWS access key ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Stripe live secret key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("Private key block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----")),
]
SENSITIVE_ROBOTS = re.compile(r"admin|backup|private|secret|config|\.git|\.env|internal|api|staging|test|"
                              r"wp-admin|phpmyadmin|cgi-bin|login|dashboard|db|sql|dump|old|tmp", re.I)

# (path, signature regex, title, severity) - each verified by content to avoid soft-404 false positives
EXPOSURE_CHECKS = [
    ("/.git/HEAD", r"^ref: refs/", "Git repository metadata exposed (/.git/)", Severity.HIGH),
    ("/.git/config", r"\[core\]", "Git config exposed (/.git/config)", Severity.HIGH),
    ("/.svn/entries", r"^\d+\s*$|svn:", "Subversion metadata exposed (/.svn/)", Severity.HIGH),
    ("/.hg/requires", r"revlogv1|store|fncache", "Mercurial metadata exposed (/.hg/)", Severity.HIGH),
    ("/.env", r"^(APP_|DB_|DATABASE_|SECRET|AWS_|MAIL_|REDIS_)[A-Z_]*=", "Environment file exposed (/.env)", Severity.CRITICAL),
    ("/.DS_Store", None, "macOS .DS_Store directory listing exposed", Severity.LOW),
    ("/server-status", r"Apache Server Status", "Apache mod_status page is public", Severity.MEDIUM),
    ("/server-info", r"Apache Server Information", "Apache mod_info page is public", Severity.MEDIUM),
    ("/phpinfo.php", r"<title>phpinfo\(\)|PHP Version \d", "phpinfo() page exposed", Severity.MEDIUM),
    ("/info.php", r"<title>phpinfo\(\)|PHP Version \d", "phpinfo() page exposed (/info.php)", Severity.MEDIUM),
    ("/.well-known/openid-configuration", r'"issuer"', "OpenID Connect discovery document", Severity.INFO),
    ("/crossdomain.xml", r'allow-access-from domain="\*"', "Permissive Flash crossdomain.xml policy", Severity.LOW),
    ("/wp-json/wp/v2/users", r'"slug"\s*:', "WordPress REST API exposes user list (username enumeration)", Severity.LOW),
    ("/actuator", r'"_links"', "Spring Boot Actuator endpoints exposed", Severity.MEDIUM),
    ("/elmah.axd", r"Error Log for", "ELMAH error log exposed", Severity.HIGH),
    ("/composer.json", r'"require"', "composer.json exposed (dependency versions)", Severity.LOW),
    ("/package.json", r'"dependencies"', "package.json exposed (dependency versions)", Severity.LOW),
]


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[dict] = []
        self.inline_scripts = 0
        self.inline_script_text: list[str] = []
        self.styles: list[dict] = []
        self.iframes: list[str] = []
        self.images: list[str] = []
        self.forms: list[dict] = []
        self.links: list[str] = []
        self.blank_no_opener = 0
        self.meta: dict[str, str] = {}
        self.comments: list[str] = []
        self.title = ""
        self._in_title = False
        self._title_done = False
        self._in_svg = False
        self._in_script = False
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs_list) -> None:
        a = {k.lower(): (v or "") for k, v in attrs_list}
        if tag == "script":
            if a.get("src"):
                self.scripts.append({"src": a["src"], "integrity": a.get("integrity"), "crossorigin": a.get("crossorigin")})
            else:
                self.inline_scripts += 1
                self._in_script = True
        elif tag == "link" and "stylesheet" in a.get("rel", "").lower() and a.get("href"):
            self.styles.append({"href": a["href"], "integrity": a.get("integrity")})
        elif tag == "iframe" and a.get("src"):
            self.iframes.append(a["src"])
        elif tag == "img" and a.get("src"):
            self.images.append(a["src"])
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])
            if a.get("target", "").lower() == "_blank" and not re.search(r"noopener|noreferrer", a.get("rel", ""), re.I):
                self.blank_no_opener += 1
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": a.get("method", "get").lower(), "password": False,
                          "csrf_token": False, "autocomplete": a.get("autocomplete")}
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None:
            if a.get("type", "").lower() == "password":
                self._form["password"] = True
            if a.get("type", "").lower() == "hidden" and re.search(r"csrf|xsrf|token|nonce|authenticity", a.get("name", ""), re.I):
                self._form["csrf_token"] = True
        elif tag == "meta":
            key = (a.get("name") or a.get("property") or a.get("http-equiv") or "").lower()
            if key:
                self.meta[key] = a.get("content", "")
        elif tag == "title" and not self._title_done and not self._in_svg:
            self._in_title = True
        elif tag == "svg":
            self._in_svg = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None
        elif tag == "title" and self._in_title:
            self._in_title = False
            self._title_done = True
        elif tag == "svg":
            self._in_svg = False
        elif tag == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
        if self._in_script and len(self.inline_script_text) < 200:
            self.inline_script_text.append(data[:20000])

    def handle_comment(self, data: str) -> None:
        d = data.strip()
        if d and not d.startswith(("[if", "<![endif", "[endif")):
            self.comments.append(d)


def run(ctx: AuditContext) -> SectionResult:
    res = SectionResult("content")
    if not ctx.response:
        return res
    if ctx.blocked:
        res.data["skipped"] = f"page content not analysed ({ctx.blocked['vendor']} {ctx.blocked['kind']})"
        _well_known(ctx, res, ctx.final_url)
        return res
    page_url = ctx.final_url
    page_host = urlsplit(page_url).hostname or ""
    https = page_url.startswith("https://")
    p = PageParser()
    try:
        p.feed(ctx.html)
    except Exception as e:  # malformed HTML should never kill the audit
        res.errors.append(f"HTML parse error: {e}")

    abs_scripts = [urljoin(page_url, s["src"]) for s in p.scripts]
    ctx.script_srcs = abs_scripts
    res.data["page"] = {
        "title": p.title.strip()[:200],
        "meta_generator": p.meta.get("generator"),
        "meta_robots": p.meta.get("robots"),
        "external_scripts": len(p.scripts),
        "inline_scripts": p.inline_scripts,
        "stylesheets": len(p.styles),
        "iframes": len(p.iframes),
        "forms": len(p.forms),
        "links": len(p.links),
    }
    res.data["meta"] = p.meta
    res.data["scripts"] = abs_scripts
    res.data["inline_script_sample"] = "\n".join(p.inline_script_text)[:300_000]

    # third-party origins
    third = {}
    for kind, urls in (("script", abs_scripts), ("style", [urljoin(page_url, s["href"]) for s in p.styles]),
                       ("iframe", [urljoin(page_url, u) for u in p.iframes]),
                       ("image", [urljoin(page_url, u) for u in p.images])):
        for u in urls:
            h = urlsplit(u).hostname
            if h and h != page_host and not h.endswith("." + (ctx.apex or page_host)):
                third.setdefault(h, set()).add(kind)
    res.data["third_party"] = {h: sorted(k) for h, k in sorted(third.items())}

    # mixed content
    if https:
        active = [u for u in abs_scripts + [urljoin(page_url, s["href"]) for s in p.styles] +
                  [urljoin(page_url, u) for u in p.iframes] if u.startswith("http://")]
        passive = [urljoin(page_url, u) for u in p.images if urljoin(page_url, u).startswith("http://")]
        if active:
            res.add("content.mixed-active", f"Active mixed content: {len(active)} script/style/iframe over HTTP",
                    Severity.MEDIUM, "Content", evidence=", ".join(active[:5]),
                    recommendation="Load every subresource over HTTPS (or add CSP upgrade-insecure-requests).")
        if passive:
            res.add("content.mixed-passive", f"Passive mixed content: {len(passive)} image(s) over HTTP", Severity.LOW,
                    "Content", evidence=", ".join(passive[:5]))

    # SRI on cross-origin scripts / styles
    no_sri = [urljoin(page_url, s["src"]) for s in p.scripts
              if not s["integrity"] and (urlsplit(urljoin(page_url, s["src"])).hostname or page_host) != page_host]
    no_sri += [urljoin(page_url, s["href"]) for s in p.styles
               if not s["integrity"] and (urlsplit(urljoin(page_url, s["href"])).hostname or page_host) != page_host]
    res.data["no_sri"] = no_sri
    if no_sri:
        hosts = sorted({urlsplit(u).hostname for u in no_sri})
        res.add("content.no-sri", f"{len(no_sri)} third-party script/style(s) loaded without Subresource Integrity",
                Severity.LOW, "Content", evidence=", ".join(hosts[:8]),
                detail="If the third party is compromised, its code runs with full access to your page.",
                recommendation="Add integrity= and crossorigin= attributes for static third-party assets.")

    # forms
    form_info = []
    for f in p.forms:
        action = urljoin(page_url, f["action"]) if f["action"] else page_url
        f["action_abs"] = action
        form_info.append(f)
        if f["password"] and not page_url.startswith("https://"):
            res.add("content.password-http", "Password field on a page served over HTTP", Severity.HIGH, "Content",
                    recommendation="Serve login pages exclusively over HTTPS.")
        if action.startswith("http://") and https:
            res.add("content.form-http", "Form submits to an http:// URL", Severity.HIGH if f["password"] else Severity.MEDIUM,
                    "Content", evidence=action, recommendation="Submit forms to https:// endpoints only.")
        if f["password"] and f["method"] == "get":
            res.add("content.password-get", "Password form uses GET (credentials end up in URLs/logs)", Severity.MEDIUM,
                    "Content", evidence=action)
        if f["method"] == "post" and not f["csrf_token"] and urlsplit(action).hostname == page_host:
            res.add("content.no-csrf-token", "POST form without a visible anti-CSRF token", Severity.INFO, "Content",
                    evidence=action, detail="May rely on SameSite cookies or headers instead - verify manually.")
    res.data["forms"] = form_info

    if p.blank_no_opener:
        res.add("content.blank-noopener", f"{p.blank_no_opener} target=_blank link(s) without rel=noopener", Severity.INFO,
                "Content", detail="Modern browsers imply noopener; only legacy browsers are affected.")

    # comments, emails, secrets
    interesting = [c[:200] for c in p.comments if COMMENT_KEYWORDS.search(c)]
    res.data["comments"] = {"total": len(p.comments), "interesting": interesting[:20]}
    if interesting:
        res.add("content.comments", f"{len(interesting)} HTML comment(s) with potentially sensitive keywords",
                Severity.INFO, "Information disclosure", evidence=" | ".join(interesting[:3])[:400],
                recommendation="Strip developer comments from production HTML.")
    emails = sorted({e.lower() for e in EMAIL_RE.findall(ctx.html) if not e.lower().endswith((".png", ".jpg", ".svg", ".webp", ".gif"))})
    res.data["emails"] = emails[:50]
    if emails:
        res.add("content.emails", f"{len(emails)} email address(es) published in page source", Severity.INFO,
                "Information disclosure", evidence=", ".join(emails[:5]),
                detail="Harvestable for phishing/spam; consider contact forms or obfuscation.")
    for label, rx in SECRET_PATTERNS:
        m = rx.search(ctx.html)
        if m:
            token = m.group(0)
            res.add("content.secret." + label.split()[0].lower(), f"Possible {label} in page source", Severity.HIGH,
                    "Information disclosure", evidence=token[:8] + "…" + token[-4:],
                    recommendation="Revoke the credential and remove it from client-side code.")

    _well_known(ctx, res, page_url)
    return res


def _well_known(ctx: AuditContext, res: SectionResult, page_url: str) -> None:
    with client(ctx.config.timeout, verify=ctx.options.verify_tls) as c:
        base = f"{urlsplit(page_url).scheme}://{urlsplit(page_url).netloc}"
        _robots(c, base, res)
        _security_txt(c, base, res)
        _sitemap(c, base, res)
        if ctx.blocked:
            res.data["exposure_checks"] = "skipped (site is behind a bot challenge)"
        elif ctx.options.exposure_checks:
            _exposure(c, base, res)
        else:
            res.data["exposure_checks"] = "skipped (enable with --exposure-checks)"


def _get_text(c: httpx.Client, url: str, limit: int = 500_000) -> httpx.Response | None:
    try:
        r = c.get(url)
    except httpx.HTTPError:
        return None
    return r


def _looks_html(r: httpx.Response) -> bool:
    return "html" in r.headers.get("content-type", "").lower() or r.text.lstrip()[:15].lower().startswith(("<!doctype", "<html"))


def _body_is_html(r: httpx.Response) -> bool:
    return r.text.lstrip()[:200].lower().startswith(("<!doctype", "<html", "<head", "<body"))


def _robots(c, base: str, res: SectionResult) -> None:
    r = _get_text(c, base + "/robots.txt")
    if r is not None and waf.detect_response(r):
        res.data["robots"] = {"blocked": True}
        return
    if not r or r.status_code != 200 or _looks_html(r):
        res.data["robots"] = None
        return
    disallow, sitemaps = [], []
    for line in r.text.splitlines():
        line = line.split("#", 1)[0].strip()
        k, _, v = line.partition(":")
        if k.lower() == "disallow" and v.strip():
            disallow.append(v.strip())
        elif k.lower() == "sitemap":
            sitemaps.append(v.strip())
    sensitive = sorted({d for d in disallow if SENSITIVE_ROBOTS.search(d)})
    res.data["robots"] = {"disallow": disallow[:200], "sitemaps": sitemaps, "sensitive": sensitive}
    if sensitive:
        res.add("robots.sensitive", f"robots.txt reveals {len(sensitive)} potentially sensitive path(s)", Severity.INFO,
                "Information disclosure", evidence=", ".join(sensitive[:10]),
                detail="robots.txt is public and is a roadmap for attackers; it is not access control.")


def _security_txt(c, base: str, res: SectionResult) -> None:
    r = None
    challenged = False
    for path in ("/.well-known/security.txt", "/security.txt"):
        r = _get_text(c, base + path)
        if r is not None and waf.detect_response(r):
            challenged = True
        elif r and r.status_code == 200 and "contact:" in r.text.lower() and not _looks_html(r):
            break
        r = None
    if not r and challenged:
        res.data["security_txt"] = {"blocked": True}
        return
    if not r:
        res.data["security_txt"] = None
        res.add("sectxt.missing", "No security.txt (RFC 9116) vulnerability disclosure contact", Severity.LOW,
                "Disclosure policy", recommendation="Publish /.well-known/security.txt with Contact: and Expires: fields.")
        return
    fields: dict[str, list[str]] = {}
    for line in r.text.splitlines():
        k, _, v = line.partition(":")
        if v and not line.startswith("#"):
            fields.setdefault(k.strip().lower(), []).append(v.strip())
    res.data["security_txt"] = {"url": str(r.url), "fields": fields}
    exp = (fields.get("expires") or [None])[0]
    if not exp:
        res.add("sectxt.no-expires", "security.txt lacks the required Expires field", Severity.INFO, "Disclosure policy")
    else:
        try:
            dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            if dt < datetime.now(timezone.utc):
                res.add("sectxt.expired", "security.txt has expired", Severity.LOW, "Disclosure policy", evidence=exp)
        except ValueError:
            pass


def _sitemap(c, base: str, res: SectionResult) -> None:
    r = _get_text(c, base + "/sitemap.xml")
    if r is not None and waf.detect_response(r):
        res.data["sitemap"] = {"blocked": True}
        return
    head = r.text[:3000] if r is not None and r.status_code == 200 else ""
    if "<urlset" in head or "<sitemapindex" in head:
        res.data["sitemap"] = {"url": str(r.url), "entries": r.text.count("<loc>"),
                               "index": "<sitemapindex" in head}
    else:
        res.data["sitemap"] = None


def _exposure(c, base: str, res: SectionResult) -> None:
    hits = []
    for path, sig, title, sev in EXPOSURE_CHECKS:
        try:
            r = c.get(base + path, follow_redirects=False)
        except httpx.HTTPError:
            continue
        if r.status_code != 200:
            continue
        ok = False
        if path == "/.DS_Store":
            ok = r.content[:8] == b"\x00\x00\x00\x01Bud1"
        elif sig and not (_body_is_html(r) and path not in ("/server-status", "/server-info", "/phpinfo.php", "/info.php", "/elmah.axd")):
            ok = bool(re.search(sig, r.text[:100_000], re.M))
        if ok:
            hits.append(path)
            res.add("exposure." + path.strip("/").replace("/", "-"), title, sev, "Exposure", evidence=f"GET {base}{path} → 200",
                    recommendation="Block access to this path at the web server / remove the file from the web root.")
    res.data["exposure_checks"] = {"checked": [p for p, *_ in EXPOSURE_CHECKS], "found": hits}
