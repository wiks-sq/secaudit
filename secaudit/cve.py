"""CVE lookup for detected technologies.

Sources:
  * NVD CVE API 2.0 (CPE virtual match on product+version) for servers/CMS/languages
  * OSV.dev for npm / PyPI packages (exact affected-range matching)
  * CISA KEV catalog - flags vulnerabilities known to be exploited in the wild
  * FIRST EPSS - probability of exploitation in the next 30 days
Results are cached on disk (24h) to stay friendly with public APIs.
"""

from __future__ import annotations

import re
import threading
import time
from typing import Callable

import httpx

from secaudit.config import Config
from secaudit.context import AuditContext
from secaudit.models import CVE, SectionResult, Severity, Technology
from secaudit.net import JsonCache, client

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_URL = "https://api.osv.dev/v1/query"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

# canonical tech name (lowercase) -> CPE prefix "part:vendor:product" ('*' vendor = any)
NVD_CPE = {
    "nginx": "a:*:nginx",
    "apache http server": "a:apache:http_server",
    "apache tomcat": "a:apache:tomcat",
    "php": "a:php:php",
    "openssl": "a:openssl:openssl",
    "microsoft iis": "a:microsoft:internet_information_services",
    "openresty": "a:openresty:openresty",
    "litespeed": "a:litespeedtech:litespeed_web_server",
    "lighttpd": "a:lighttpd:lighttpd",
    "caddy": "a:caddyserver:caddy",
    "jetty": "a:eclipse:jetty",
    "envoy": "a:envoyproxy:envoy",
    "haproxy": "a:haproxy:haproxy",
    "squid": "a:squid-cache:squid",
    "varnish": "a:varnish-software:varnish_cache",
    "tengine": "a:alibaba:tengine",
    "wordpress": "a:wordpress:wordpress",
    "drupal": "a:drupal:drupal",
    "joomla": "a:joomla:joomla\\!",
    "typo3": "a:typo3:typo3",
    "magento": "a:magento:magento",
    "prestashop": "a:prestashop:prestashop",
    "mediawiki": "a:mediawiki:mediawiki",
    "concrete cms": "a:concretecms:concrete_cms",
    "craft cms": "a:craftcms:craft_cms",
    "discourse": "a:discourse:discourse",
    "python": "a:python:python",
    "node.js": "a:nodejs:node.js",
    "perl": "a:perl:perl",
    "mod_ssl": "a:apache:mod_ssl",
    "phusion passenger": "a:phusion:passenger",
    "kong": "a:konghq:kong_gateway",
    "traefik": "a:traefik:traefik",
    "atlassian confluence": "a:atlassian:confluence_server",
    "atlassian jira": "a:atlassian:jira_server",
    "gitlab": "a:gitlab:gitlab",
    "jenkins": "a:jenkins:jenkins",
}

# canonical tech name (lowercase) -> (OSV ecosystem, package)
OSV_PKG = {
    "jquery": ("npm", "jquery"),
    "jquery ui": ("npm", "jquery-ui"),
    "jquery migrate": ("npm", "jquery-migrate"),
    "bootstrap": ("npm", "bootstrap"),
    "angularjs": ("npm", "angular"),
    "angular": ("npm", "@angular/core"),
    "lodash": ("npm", "lodash"),
    "underscore.js": ("npm", "underscore"),
    "moment.js": ("npm", "moment"),
    "vue.js": ("npm", "vue"),
    "react": ("npm", "react-dom"),
    "handlebars": ("npm", "handlebars"),
    "dompurify": ("npm", "dompurify"),
    "select2": ("npm", "select2"),
    "popper.js": ("npm", "@popperjs/core"),
    "swiper": ("npm", "swiper"),
    "axios": ("npm", "axios"),
    "chart.js": ("npm", "chart.js"),
    "prototype": ("npm", "prototype"),
    "tinymce": ("npm", "tinymce"),
    "ckeditor": ("npm", "ckeditor4"),
    "next.js": ("npm", "next"),
    "nuxt": ("npm", "nuxt"),
    "express": ("npm", "express"),
    "ghost": ("npm", "ghost"),
    "gatsby": ("npm", "gatsby"),
    "astro": ("npm", "astro"),
    "werkzeug": ("PyPI", "werkzeug"),
    "gunicorn": ("PyPI", "gunicorn"),
    "uvicorn": ("PyPI", "uvicorn"),
    "django": ("PyPI", "django"),
    "hugo": ("Go", "github.com/gohugoio/hugo"),
}


class _RateLimiter:
    def __init__(self, interval: float):
        self.interval = interval
        self.last = 0.0
        self.lock = threading.Lock()

    def wait(self) -> None:
        with self.lock:
            delta = time.monotonic() - self.last
            if delta < self.interval:
                time.sleep(self.interval - delta)
            self.last = time.monotonic()


# ----------------------------------------------------------------------------- CVSS


def cvss3_base_score(vector: str) -> float | None:
    """Compute a CVSS v3.x base score from its vector string."""
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
        ac = {"L": 0.77, "H": 0.44}[m["AC"]]
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        ui = {"N": 0.85, "R": 0.62}[m["UI"]]
        c, i, a = ({"H": 0.56, "L": 0.22, "N": 0.0}[m[k]] for k in ("C", "I", "A"))
    except (KeyError, ValueError):
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    exploit = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    raw = min(1.08 * (impact + exploit), 10) if scope_changed else min(impact + exploit, 10)
    return _roundup(raw)


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (int(i / 10000) + 1) / 10.0


def _severity_label(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    return Severity.from_cvss(score).name if score > 0 else "NONE"


# ----------------------------------------------------------------------------- lookups


class CveLookup:
    def __init__(self, config: Config, log: Callable[[str], None] | None = None):
        self.config = config
        self.cache_nvd = JsonCache(config.cache_dir, "nvd", 24 * 3600)
        self.cache_osv = JsonCache(config.cache_dir, "osv", 24 * 3600)
        self.cache_misc = JsonCache(config.cache_dir, "misc", 24 * 3600)
        self.nvd_rate = _RateLimiter(0.7 if config.nvd_api_key else 6.2)
        self.log = log or (lambda _m: None)
        self.http = client(30)

    def close(self) -> None:
        self.http.close()

    # NVD -------------------------------------------------------------------
    def nvd(self, tech: Technology) -> list[CVE]:
        prefix = NVD_CPE[tech.key()]
        version = tech.version
        cpe = f"cpe:2.3:{prefix}:{version}"
        cached = self.cache_nvd.get(cpe)
        if cached is None:
            items: list[dict] = []
            start = 0
            headers = {"apiKey": self.config.nvd_api_key} if self.config.nvd_api_key else {}
            while True:
                self.nvd_rate.wait()
                for attempt in range(3):
                    r = self.http.get(NVD_URL, params={"virtualMatchString": cpe, "resultsPerPage": 2000,
                                                       "startIndex": start}, headers=headers)
                    if r.status_code in (403, 429, 503):
                        self.log(f"NVD rate-limited, retrying in {6 * (attempt + 1)}s")
                        time.sleep(6 * (attempt + 1))
                        continue
                    break
                r.raise_for_status()
                d = r.json()
                items += d.get("vulnerabilities", [])
                start += d.get("resultsPerPage", 0)
                if start >= d.get("totalResults", 0) or not d.get("resultsPerPage"):
                    break
            cached = [self._slim_nvd(v["cve"]) for v in items]
            self.cache_nvd.set(cpe, cached)
        out = []
        for c in cached:
            if c.get("rejected"):
                continue
            out.append(CVE(id=c["id"], product=tech.name, product_version=version, score=c["score"],
                           severity=c["severity"], vector=c["vector"], published=c["published"],
                           summary=c["summary"], kev=c["kev"], source="NVD",
                           url=f"https://nvd.nist.gov/vuln/detail/{c['id']}"))
        return out

    @staticmethod
    def _slim_nvd(cve: dict) -> dict:
        metrics = cve.get("metrics", {})
        score, sev, vector = None, "UNKNOWN", ""
        for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                entry = next((m for m in metrics[key] if m.get("type") == "Primary"), metrics[key][0])
                data = entry.get("cvssData", {})
                score = data.get("baseScore")
                sev = data.get("baseSeverity") or entry.get("baseSeverity") or _severity_label(score)
                vector = data.get("vectorString", "")
                break
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        return {"id": cve["id"], "score": score, "severity": sev, "vector": vector,
                "published": (cve.get("published") or "")[:10], "summary": desc,
                "kev": bool(cve.get("cisaExploitAdd")), "rejected": cve.get("vulnStatus") == "Rejected"}

    # OSV -------------------------------------------------------------------
    def osv(self, tech: Technology) -> list[CVE]:
        eco, pkg = OSV_PKG[tech.key()]
        key = f"{eco}:{pkg}:{tech.version}"
        vulns = self.cache_osv.get(key)
        if vulns is None:
            r = self.http.post(OSV_URL, json={"package": {"name": pkg, "ecosystem": eco}, "version": tech.version})
            r.raise_for_status()
            vulns = r.json().get("vulns", [])
            # page_token pagination is rare for a single version; ignore
            vulns = [{k: v.get(k) for k in ("id", "aliases", "summary", "details", "severity", "database_specific", "published")}
                     for v in vulns]
            self.cache_osv.set(key, vulns)
        out = []
        for v in vulns:
            aliases = v.get("aliases") or []
            cve_ids = [a for a in aliases if a.startswith("CVE-")]
            vid = cve_ids[0] if cve_ids else v["id"]
            vector, score = "", None
            for s in v.get("severity") or []:
                if s.get("type") == "CVSS_V3":
                    vector = s["score"]
                    score = cvss3_base_score(vector)
                    break
                if s.get("type") == "CVSS_V4" and not vector:
                    vector = s["score"]
            label = (v.get("database_specific") or {}).get("severity") or _severity_label(score)
            label = {"MODERATE": "MEDIUM"}.get(str(label).upper(), str(label).upper())
            out.append(CVE(id=vid, product=tech.name, product_version=tech.version, score=score, severity=label,
                           vector=vector, published=(v.get("published") or "")[:10],
                           summary=v.get("summary") or (v.get("details") or "")[:300], source="OSV",
                           url=f"https://osv.dev/vulnerability/{v['id']}", aliases=[v["id"], *aliases]))
        return out

    # enrichment ------------------------------------------------------------
    def kev_set(self) -> set[str]:
        cached = self.cache_misc.get("kev")
        if cached is None:
            try:
                r = self.http.get(KEV_URL)
                r.raise_for_status()
                cached = [v["cveID"] for v in r.json().get("vulnerabilities", [])]
                self.cache_misc.set("kev", cached)
            except (httpx.HTTPError, ValueError, KeyError):
                cached = []
        return set(cached)

    def epss(self, ids: list[str]) -> dict[str, tuple[float, float]]:
        out: dict[str, tuple[float, float]] = {}
        need = []
        for i in ids:
            c = self.cache_misc.get("epss:" + i)
            if c is not None:
                out[i] = tuple(c)  # type: ignore[assignment]
            else:
                need.append(i)
        for chunk in (need[i:i + 100] for i in range(0, len(need), 100)):
            try:
                r = self.http.get(EPSS_URL, params={"cve": ",".join(chunk)})
                r.raise_for_status()
                for row in r.json().get("data", []):
                    val = (float(row["epss"]), float(row["percentile"]))
                    out[row["cve"]] = val
                    self.cache_misc.set("epss:" + row["cve"], list(val))
            except (httpx.HTTPError, ValueError, KeyError):
                pass
        return out


def run(ctx: AuditContext, log: Callable[[str], None] | None = None) -> SectionResult:
    res = SectionResult("cve")
    lookup = CveLookup(ctx.config, log)
    checked, skipped, unsupported = [], [], []
    all_cves: list[CVE] = []
    try:
        for tech in ctx.technologies:
            k = tech.key()
            if k not in NVD_CPE and k not in OSV_PKG:
                continue
            if not tech.version:
                skipped.append(tech.name)
                continue
            try:
                if k in OSV_PKG:
                    if log:
                        log(f"OSV: {tech.name} {tech.version}")
                    found = lookup.osv(tech)
                else:
                    if log:
                        log(f"NVD: {tech.name} {tech.version}")
                    found = lookup.nvd(tech)
                checked.append({"product": tech.name, "version": tech.version, "source": "OSV" if k in OSV_PKG else "NVD",
                                "count": len(found)})
                all_cves += found
            except (httpx.HTTPError, ValueError) as e:
                res.errors.append(f"CVE lookup for {tech.name} {tech.version} failed: {type(e).__name__}: {e}")
                unsupported.append(tech.name)

        # de-duplicate per product
        uniq: dict[tuple[str, str], CVE] = {}
        for c in all_cves:
            uniq.setdefault((c.product, c.id), c)
        all_cves = list(uniq.values())

        if all_cves:
            if log:
                log("Enriching with CISA KEV + EPSS")
            kev = lookup.kev_set()
            epss = lookup.epss([c.id for c in all_cves if c.id.startswith("CVE-")])
            for c in all_cves:
                c.kev = c.kev or c.id in kev
                if c.id in epss:
                    c.epss, c.epss_percentile = epss[c.id]
    finally:
        lookup.close()

    all_cves.sort(key=lambda c: (not c.kev, -(c.score or 0), -(c.epss or 0)))
    ctx.cves = all_cves
    res.data["checked"] = checked
    res.data["version_unknown"] = skipped
    res.data["cves"] = [c.__dict__ for c in all_cves]

    # one finding per affected product
    by_product: dict[str, list[CVE]] = {}
    for c in all_cves:
        by_product.setdefault(c.product, []).append(c)
    for product, items in by_product.items():
        version = items[0].product_version
        kev_n = sum(c.kev for c in items)
        top = max((c.score or 0) for c in items)
        sev = Severity.from_cvss(top) if top else Severity.MEDIUM
        if kev_n:
            sev = max(sev, Severity.HIGH)
        counts = {}
        for c in items:
            counts[c.severity] = counts.get(c.severity, 0) + 1
        breakdown = ", ".join(f"{n} {s.lower()}" for s, n in sorted(counts.items(), key=lambda kv: -_rank(kv[0])))
        res.add(f"cve.{re.sub(r'[^a-z0-9]+', '-', product.lower())}",
                f"{product} {version}: {len(items)} known vulnerabilit{'y' if len(items) == 1 else 'ies'}"
                + (f" ({kev_n} actively exploited)" if kev_n else ""),
                sev, "Known vulnerabilities", detail=breakdown,
                evidence=", ".join(c.id for c in items[:6]) + (" ..." if len(items) > 6 else ""),
                recommendation=f"Upgrade {product} to the latest supported release."
                + (" Note: distro packages may carry backported fixes - verify with your OS vendor." if items[0].source == "NVD" else ""))
    if skipped:
        res.add("cve.version-unknown", f"Versions hidden for {len(skipped)} component(s); CVEs cannot be matched",
                Severity.INFO, "Known vulnerabilities", evidence=", ".join(skipped),
                detail="Hiding versions is good practice - but make sure these are patched.")
    return res


def _rank(label: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(label.upper(), 0)
