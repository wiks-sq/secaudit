"""DNS records and email/DNS security posture (SPF, DMARC, DKIM, CAA, DNSSEC, MTA-STS)."""

from __future__ import annotations

import re

import dns.exception
import dns.flags
import dns.name
import dns.resolver

from secaudit.context import AuditContext
from secaudit.models import SectionResult, Severity

DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim", "s1", "s2",
                  "smtp", "mxvault", "zoho", "protonmail", "fm1", "everlytickey1", "mandrill", "amazonses"]
TAKEOVER_SUFFIXES = (
    "github.io", "herokuapp.com", "herokudns.com", "azurewebsites.net", "cloudapp.net", "trafficmanager.net",
    "blob.core.windows.net", "s3.amazonaws.com", "elasticbeanstalk.com", "pantheonsite.io", "ghost.io",
    "myshopify.com", "surge.sh", "bitbucket.io", "netlify.app", "wordpress.com", "readthedocs.io", "zendesk.com",
    "fastly.net", "unbouncepages.com", "helpscoutdocs.com", "cargocollective.com", "webflow.io",
)


def resolver(timeout: float) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.lifetime = timeout
    r.timeout = min(timeout, 5)
    return r


def query(r: dns.resolver.Resolver, name: str, rtype: str) -> list[str]:
    try:
        ans = r.resolve(name, rtype, raise_on_no_answer=False)
        return [rr.to_text() for rr in ans] if ans.rrset else []
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout, dns.resolver.NoAnswer,
            dns.name.EmptyLabel, dns.resolver.LifetimeTimeout):
        return []


def txt(r: dns.resolver.Resolver, name: str) -> list[str]:
    out = []
    for rec in query(r, name, "TXT"):
        out.append("".join(p for p in re.findall(r'"((?:[^"\\]|\\.)*)"', rec)) or rec.strip('"'))
    return out


def find_apex(host: str, timeout: float) -> str:
    try:
        return dns.resolver.zone_for_name(host, resolver=resolver(timeout)).to_text().rstrip(".")
    except Exception:
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host


def resolve_ips(host: str, timeout: float) -> list[str]:
    r = resolver(timeout)
    return query(r, host, "A") + query(r, host, "AAAA")


def _spf_lookups(r, domain: str, depth: int = 0, seen: set | None = None) -> int:
    """Count DNS-querying SPF mechanisms recursively (RFC 7208 limit: 10)."""
    seen = seen if seen is not None else set()
    if depth > 10 or domain in seen:
        return 0
    seen.add(domain)
    rec = next((t for t in txt(r, domain) if t.lower().startswith("v=spf1")), None)
    if not rec:
        return 0
    count = 0
    for term in rec.split()[1:]:
        term = term.lstrip("+-~?").lower()
        if term.startswith(("include:", "redirect=")):
            count += 1
            count += _spf_lookups(r, term.split(":", 1)[-1].split("=", 1)[-1], depth + 1, seen)
        elif term.startswith(("a", "mx", "ptr", "exists:")) and not term.startswith("all"):
            count += 1
    return count


def run(ctx: AuditContext) -> SectionResult:
    res = SectionResult("dns")
    if ctx.target.is_ip:
        res.data["skipped"] = "target is an IP address"
        return res
    r = resolver(min(ctx.config.timeout, 8))
    host, apex = ctx.target.host, ctx.apex or ctx.target.host

    records = {
        "host": {t: query(r, host, t) for t in ("A", "AAAA", "CNAME")},
        "apex": {t: query(r, apex, t) for t in ("A", "AAAA", "NS", "MX", "SOA", "CAA", "TXT")},
    }
    records["apex"]["TXT"] = txt(r, apex)
    res.data["records"] = records

    _dangling_cname(r, res, host, records["host"]["CNAME"])
    _nameservers(res, records["apex"]["NS"])
    _dnssec(r, res, apex)
    _caa(r, res, host, apex, records["apex"]["CAA"])
    _email(r, res, apex, records["apex"]["MX"], records["apex"]["TXT"])
    return res


def _dangling_cname(r, res: SectionResult, host: str, cnames: list[str]) -> None:
    if not cnames:
        return
    target = cnames[0].rstrip(".")
    try:
        r.resolve(target, "A")
        return
    except dns.resolver.NXDOMAIN:
        sev = Severity.HIGH if target.endswith(TAKEOVER_SUFFIXES) else Severity.MEDIUM
        res.add("dns.dangling-cname", "CNAME points to a non-existent name (possible subdomain takeover)", sev, "DNS",
                evidence=f"{host} CNAME {target} → NXDOMAIN",
                recommendation="Remove the stale CNAME or reclaim the target resource.")
    except Exception:
        return


def _nameservers(res: SectionResult, ns: list[str]) -> None:
    if len(ns) == 1:
        res.add("dns.single-ns", "Only one authoritative nameserver", Severity.MEDIUM, "DNS",
                evidence=ns[0], recommendation="Use at least two nameservers on separate networks.")


def _dnssec(r, res: SectionResult, apex: str) -> None:
    dnskey = query(r, apex, "DNSKEY")
    ds = query(r, apex, "DS")
    res.data["dnssec"] = {"dnskey": bool(dnskey), "ds": bool(ds)}
    if not dnskey and not ds:
        res.add("dns.no-dnssec", "DNSSEC is not enabled", Severity.LOW, "DNS",
                detail="DNS answers for this zone can be spoofed by on-path resolvers.",
                recommendation="Enable DNSSEC signing at your DNS provider and publish the DS record at the registrar.")
    elif dnskey and not ds:
        res.add("dns.dnssec-no-ds", "Zone has DNSKEY but no DS record at the parent", Severity.MEDIUM, "DNS",
                detail="DNSSEC chain of trust is broken - signatures are never validated.",
                recommendation="Publish the DS record at your registrar.")


def _caa(r, res: SectionResult, host: str, apex: str, caa: list[str]) -> None:
    if not caa and host != apex:
        caa = query(r, host, "CAA")
    res.data["caa"] = caa
    if not caa:
        res.add("dns.no-caa", "No CAA record restricting certificate issuance", Severity.LOW, "DNS",
                recommendation='Add a CAA record, e.g. 0 issue "letsencrypt.org" (and an iodef contact).')


def _email(r, res: SectionResult, apex: str, mx: list[str], apex_txt: list[str]) -> None:
    email: dict = {"mx": mx}
    has_mail = bool(mx) and not any(m.strip().rstrip(".").endswith(" .") or m.strip() == "0 ." for m in mx)

    # SPF
    spf = [t for t in apex_txt if t.lower().startswith("v=spf1")]
    email["spf"] = spf
    if not spf:
        res.add("email.no-spf", "No SPF record", Severity.MEDIUM if has_mail else Severity.LOW, "Email security",
                detail="Anyone can send mail claiming to be from this domain." if has_mail else
                "Domain has no MX; spoofers can still use it as a sender.",
                recommendation='Publish SPF, e.g. "v=spf1 include:<provider> -all" (or "v=spf1 -all" if the domain sends no mail).')
    elif len(spf) > 1:
        res.add("email.multi-spf", "Multiple SPF records (SPF permerror)", Severity.MEDIUM, "Email security",
                evidence=" | ".join(spf), recommendation="Merge into a single v=spf1 record.")
    else:
        rec = spf[0].lower()
        if re.search(r"(^|\s)\+?all\b", rec) and "-all" not in rec and "~all" not in rec and "?all" not in rec:
            res.add("email.spf-pass-all", "SPF ends in +all (allows every sender)", Severity.HIGH, "Email security",
                    evidence=spf[0], recommendation="End the record with -all or ~all.")
        elif "?all" in rec:
            res.add("email.spf-neutral", "SPF uses neutral ?all", Severity.MEDIUM, "Email security", evidence=spf[0],
                    recommendation="Use -all (hard fail) or ~all (soft fail).")
        elif "~all" in rec:
            res.add("email.spf-softfail", "SPF uses soft-fail ~all", Severity.INFO, "Email security", evidence=spf[0],
                    detail="Acceptable when DMARC is enforced; -all is stricter.")
        lookups = _spf_lookups(r, apex)
        email["spf_lookups"] = lookups
        if lookups > 10:
            res.add("email.spf-lookups", f"SPF needs {lookups} DNS lookups (limit is 10)", Severity.MEDIUM,
                    "Email security", detail="Receivers will return permerror, effectively disabling SPF.",
                    recommendation="Flatten includes or remove unused senders.")

    # DMARC
    dmarc = [t for t in txt(r, f"_dmarc.{apex}") if t.lower().startswith("v=dmarc1")]
    email["dmarc"] = dmarc
    if not dmarc:
        res.add("email.no-dmarc", "No DMARC record", Severity.MEDIUM, "Email security",
                detail="Receivers get no policy for spoofed mail and you get no reports.",
                recommendation='Publish _dmarc TXT: "v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>" and move to p=reject.')
    else:
        tags = dict((k.strip().lower(), v.strip()) for k, _, v in (p.partition("=") for p in dmarc[0].split(";")) if k.strip())
        email["dmarc_policy"] = tags.get("p")
        if tags.get("p", "").lower() == "none":
            res.add("email.dmarc-none", "DMARC policy is p=none (monitor only)", Severity.LOW, "Email security",
                    evidence=dmarc[0], recommendation="Move to p=quarantine, then p=reject once reports are clean.")
        if tags.get("pct") and tags["pct"] != "100":
            res.add("email.dmarc-pct", f"DMARC only applies to {tags['pct']}% of mail", Severity.LOW, "Email security",
                    evidence=dmarc[0])
        if "rua" not in tags:
            res.add("email.dmarc-no-rua", "DMARC has no aggregate report address (rua)", Severity.INFO, "Email security",
                    evidence=dmarc[0])

    # DKIM (common selectors only - absence is not conclusive)
    found = []
    if has_mail:
        for sel in DKIM_SELECTORS:
            recs = txt(r, f"{sel}._domainkey.{apex}") or query(r, f"{sel}._domainkey.{apex}", "CNAME")
            if recs:
                found.append(sel)
    email["dkim_selectors_found"] = found

    # MTA-STS / TLS-RPT / BIMI
    email["mta_sts"] = [t for t in txt(r, f"_mta-sts.{apex}") if "sts" in t.lower()]
    email["tls_rpt"] = [t for t in txt(r, f"_smtp._tls.{apex}") if "tlsrpt" in t.lower()]
    email["bimi"] = [t for t in txt(r, f"default._bimi.{apex}") if "bimi" in t.lower()]
    if has_mail and not email["mta_sts"]:
        res.add("email.no-mta-sts", "No MTA-STS policy for inbound mail", Severity.INFO, "Email security",
                recommendation="Publish MTA-STS to force TLS for mail delivered to you.")
    res.data["email"] = email

    # interesting TXT verification tokens reveal SaaS in use
    vendors = []
    for t in apex_txt:
        m = re.match(r"([a-z0-9\-]+)-(?:site-)?verification[=:]", t, re.I) or re.match(r"(MS)=ms\d+", t)
        if m:
            vendors.append(m.group(1).lower())
    res.data["txt_verifications"] = sorted(set(vendors))
