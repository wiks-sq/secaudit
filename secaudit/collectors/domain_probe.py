"""Domain registration (RDAP/WHOIS), IP ownership and Certificate Transparency subdomains."""

from __future__ import annotations

import re
import socket
from datetime import datetime, timezone

import httpx

from secaudit.context import AuditContext
from secaudit.models import SectionResult, Severity
from secaudit.net import client

INTERESTING_SUB = re.compile(
    r"(^|[.-])(dev|develop|staging|stage|stg|test|testing|qa|uat|preprod|sandbox|demo|beta|admin|internal|intranet|"
    r"vpn|jenkins|gitlab|git|jira|confluence|grafana|kibana|prometheus|phpmyadmin|db|database|backup|old|legacy|"
    r"api-dev|debug|mail|webmail|remote|rdp|citrix|portal|sso|auth)([.-]|$)", re.I)


def _event(data: dict, action: str) -> str | None:
    for ev in data.get("events", []) or []:
        if ev.get("eventAction") == action:
            return ev.get("eventDate")
    return None


def _vcard_name(entity: dict) -> str | None:
    try:
        for item in entity["vcardArray"][1]:
            if item[0] in ("fn", "org") and item[3]:
                return item[3] if isinstance(item[3], str) else " ".join(item[3])
    except (KeyError, IndexError, TypeError):
        pass
    return entity.get("handle")


def _days_until(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (dt - datetime.now(timezone.utc)).days
    except ValueError:
        return None


def rdap_domain(c: httpx.Client, domain: str) -> dict:
    r = c.get(f"https://rdap.org/domain/{domain}", headers={"Accept": "application/rdap+json"})
    r.raise_for_status()
    d = r.json()
    registrar = None
    abuse = None
    for ent in d.get("entities", []) or []:
        if "registrar" in (ent.get("roles") or []):
            registrar = _vcard_name(ent)
            for sub in ent.get("entities", []) or []:
                if "abuse" in (sub.get("roles") or []):
                    try:
                        abuse = next(i[3] for i in sub["vcardArray"][1] if i[0] == "email")
                    except (StopIteration, KeyError, IndexError):
                        pass
    return {
        "source": "RDAP",
        "rdap_url": str(r.url),
        "ldh_name": d.get("ldhName"),
        "registrar": registrar,
        "registrar_abuse": abuse,
        "created": _event(d, "registration"),
        "updated": _event(d, "last changed"),
        "expires": _event(d, "expiration"),
        "status": d.get("status", []),
        "nameservers": sorted(ns.get("ldhName", "").lower() for ns in d.get("nameservers", []) or []),
        "dnssec_delegation": (d.get("secureDNS") or {}).get("delegationSigned"),
    }


def whois_fallback(domain: str, timeout: float) -> dict:
    """Classic port-43 WHOIS via IANA referral, used when RDAP is not available for the TLD."""
    def ask(server: str, q: str) -> str:
        with socket.create_connection((server, 43), timeout=timeout) as s:
            s.sendall((q + "\r\n").encode())
            chunks = []
            while True:
                b = s.recv(4096)
                if not b:
                    break
                chunks.append(b)
        return b"".join(chunks).decode(errors="replace")

    tld = domain.rsplit(".", 1)[-1]
    iana = ask("whois.iana.org", tld)
    m = re.search(r"^whois:\s*(\S+)", iana, re.M)
    if not m:
        raise RuntimeError("no WHOIS server for TLD")
    text = ask(m.group(1), domain)

    def grab(*keys):
        for k in keys:
            mm = re.search(rf"^\s*{k}\s*:\s*(.+)$", text, re.I | re.M)
            if mm:
                return mm.group(1).strip()
        return None

    return {
        "source": f"WHOIS ({m.group(1)})",
        "registrar": grab("Registrar", "registrar name", "Sponsoring Registrar"),
        "created": grab("Creation Date", "created", "Registered on", "Registration Time"),
        "updated": grab("Updated Date", "changed", "last-update", "Last updated"),
        "expires": grab("Registry Expiry Date", "Expiry Date", "expires", "Expiration Date", "paid-till"),
        "status": re.findall(r"^\s*(?:Domain )?Status:\s*(\S+)", text, re.I | re.M),
        "nameservers": sorted({n.lower().rstrip(".") for n in re.findall(r"^\s*(?:Name Server|nserver):\s*(\S+)", text, re.I | re.M)}),
        "dnssec_delegation": (grab("DNSSEC") or "").lower().startswith("signed") or None,
    }


def rdap_ip(c: httpx.Client, ip: str) -> dict:
    r = c.get(f"https://rdap.org/ip/{ip}", headers={"Accept": "application/rdap+json"})
    r.raise_for_status()
    d = r.json()
    org = None
    for ent in d.get("entities", []) or []:
        roles = ent.get("roles") or []
        if "registrant" in roles or "administrative" in roles:
            org = _vcard_name(ent)
            break
    rng = f"{d.get('startAddress')} - {d.get('endAddress')}" if d.get("startAddress") else None
    cidr = None
    if d.get("cidr0_cidrs"):
        cc = d["cidr0_cidrs"][0]
        cidr = f"{cc.get('v4prefix') or cc.get('v6prefix')}/{cc.get('length')}"
    return {"network": d.get("name"), "handle": d.get("handle"), "org": org, "country": d.get("country"),
            "range": cidr or rng}


def certspotter_subdomains(c: httpx.Client, apex: str, pages: int = 3) -> set[str]:
    names: set[str] = set()
    after = None
    for _ in range(pages):
        params = {"domain": apex, "include_subdomains": "true", "expand": "dns_names"}
        if after:
            params["after"] = after
        r = c.get("https://api.certspotter.com/v1/issuances", params=params, timeout=20)
        if r.status_code != 200:
            break
        items = r.json()
        if not items:
            break
        for it in items:
            names.update(n.lower() for n in it.get("dns_names", []))
        after = items[-1].get("id")
        if len(items) < 100:
            break
    return names


def crtsh_subdomains(c: httpx.Client, apex: str) -> set[str]:
    r = c.get("https://crt.sh/", params={"q": f"%.{apex}", "output": "json"}, timeout=25)
    r.raise_for_status()
    names: set[str] = set()
    for row in r.json():
        for n in str(row.get("name_value", "")).splitlines():
            names.add(n.strip().lower())
    return names


def run(ctx: AuditContext) -> SectionResult:
    res = SectionResult("domain")
    timeout = ctx.config.timeout
    with client(timeout) as c:
        # IP ownership + reverse DNS
        ip_info = []
        for ip in ctx.ips[:6]:
            entry = {"ip": ip}
            try:
                entry["ptr"] = socket.gethostbyaddr(ip)[0]
            except OSError:
                entry["ptr"] = None
            try:
                entry.update(rdap_ip(c, ip))
            except (httpx.HTTPError, ValueError) as e:
                entry["error"] = str(e)
            ip_info.append(entry)
        res.data["ips"] = ip_info

        if ctx.target.is_ip:
            return res
        apex = ctx.apex or ctx.target.host
        res.data["apex"] = apex

        # Registration data
        reg = None
        try:
            reg = rdap_domain(c, apex)
        except (httpx.HTTPError, ValueError) as e:
            try:
                reg = whois_fallback(apex, min(timeout, 10))
            except Exception as e2:
                res.errors.append(f"RDAP and WHOIS lookups failed: {e}; {e2}")
        if reg:
            res.data["registration"] = reg
            _registration_findings(res, reg)

        # Certificate Transparency
        if ctx.options.ct_logs:
            subs: set[str] = set()
            source = None
            try:
                subs = certspotter_subdomains(c, apex)
                source = "certspotter"
            except (httpx.HTTPError, ValueError):
                pass
            if not subs:
                try:
                    subs = crtsh_subdomains(c, apex)
                    source = "crt.sh"
                except (httpx.HTTPError, ValueError) as e:
                    res.errors.append(f"CT log lookup failed: {type(e).__name__}")
            subs |= {n.lower() for n in ctx.tls_cert_sans if n.lower().endswith(apex)}
            subs = {s for s in subs if s.endswith(apex)}
            res.data["ct"] = {"source": source, "count": len(subs), "subdomains": sorted(subs)}
            interesting = sorted(s for s in subs if INTERESTING_SUB.search(s[: -len(apex)]))
            res.data["ct"]["interesting"] = interesting
            if subs:
                res.add("ct.subdomains", f"{len(subs)} hostnames found in Certificate Transparency logs", Severity.INFO,
                        "Attack surface", detail="Every publicly trusted certificate is logged; these names are public.")
            if interesting:
                res.add("ct.interesting", f"{len(interesting)} potentially sensitive hostnames publicly logged",
                        Severity.LOW, "Attack surface", evidence=", ".join(interesting[:15]) + (" ..." if len(interesting) > 15 else ""),
                        recommendation="Make sure dev/staging/admin hosts are not publicly reachable or are access-controlled.")
    return res


def _registration_findings(res: SectionResult, reg: dict) -> None:
    days = _days_until(reg.get("expires"))
    reg["expires_in_days"] = days
    if days is not None:
        if days < 0:
            res.add("domain.expired", "Domain registration has expired", Severity.CRITICAL, "Domain",
                    evidence=reg["expires"], recommendation="Renew immediately - expired domains get hijacked.")
        elif days < 30:
            res.add("domain.expiring", f"Domain expires in {days} days", Severity.HIGH, "Domain",
                    evidence=reg["expires"], recommendation="Renew and enable auto-renew.")
        elif days < 90:
            res.add("domain.expiring", f"Domain expires in {days} days", Severity.LOW, "Domain",
                    evidence=reg["expires"], recommendation="Ensure auto-renew is enabled.")
    created_age = _days_until(reg.get("created"))
    if created_age is not None and -created_age < 60:
        res.add("domain.new", f"Domain was registered only {-created_age} days ago", Severity.INFO, "Domain",
                detail="Newly registered domains are often treated as suspicious by mail and web filters.")
    status = " ".join(reg.get("status") or []).lower().replace(" ", "")
    if status and "transferprohibited" not in status:
        res.add("domain.no-lock", "Registrar transfer lock is not set", Severity.LOW, "Domain",
                evidence=", ".join(reg.get("status") or []),
                recommendation="Enable clientTransferProhibited (registrar lock) to prevent hijacking via transfer.")
    if reg.get("nameservers") and len(reg["nameservers"]) == 1:
        res.add("domain.single-ns", "Only one nameserver delegated at the registry", Severity.MEDIUM, "Domain")
