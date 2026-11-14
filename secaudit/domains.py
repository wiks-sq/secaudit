"""Domain discovery: find every hostname and related domain for a domain, and check which ones resolve.

Passive sources only (Certificate Transparency, passive-DNS style APIs, the domain's own DNS records and
the certificates its hosts present). An optional small wordlist check (`bruteforce=True`) only sends
ordinary DNS queries.
"""

from __future__ import annotations

import ipaddress
import re
import secrets
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urlsplit

import dns.exception
import dns.name
import dns.resolver
import dns.reversename
import httpx
from cryptography import x509
from rich import box
from rich.console import Console
from rich.style import Style
from rich.table import Table
from rich.text import Text

from secaudit.collectors.dns_probe import TAKEOVER_SUFFIXES, query, txt
from secaudit.collectors.domain_probe import (INTERESTING_SUB, certspotter_subdomains, crtsh_subdomains, rdap_domain,
                                              whois_fallback)
from secaudit.config import Config
from secaudit.net import JsonCache, client

HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
SOURCE_CACHE_TTL = 6 * 3600

# Public suffixes with more than one label, so foo.co.uk is treated as the registrable domain rather than co.uk.
_SECOND_LEVEL = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "mil", "nom", "gob", "ltd", "plc"}
_MULTI_SUFFIX = {"github.io", "herokuapp.com", "azurewebsites.net", "cloudfront.net", "amazonaws.com", "netlify.app",
                 "vercel.app", "pages.dev", "workers.dev", "web.app", "firebaseapp.com", "blogspot.com",
                 "appspot.com", "myshopify.com", "wordpress.com"}

WORDLIST = """www mail webmail smtp imap pop pop3 mx mx1 mx2 ns ns1 ns2 ns3 dns ftp sftp ssh vpn remote gateway gw
proxy cdn static assets img images media files download downloads upload api api2 app apps pwd mobile web portal
intranet extranet internal admin administrator login auth sso id account accounts my secure pay payment payments
billing shop store cart checkout blog news forum community help support docs doc wiki kb status monitor
monitoring grafana kibana prometheus jenkins ci git gitlab jira confluence dev develop staging stage stg test
testing qa uat preprod sandbox demo beta alpha old legacy new v2 backup db database mysql sql redis search
analytics stats tracking crm erp cms cpanel whm webdisk autodiscover autoconfig calendar chat meet video cloud
office owa exchange lists newsletter email go link click events jobs careers partners partner""".split()


def registrable(name: str) -> str:
    """Best-effort registrable domain (no public suffix list dependency)."""
    parts = name.lower().rstrip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    for suffix in _MULTI_SUFFIX:
        if name.endswith("." + suffix):
            return ".".join(parts[-(suffix.count(".") + 2):])
    if len(parts[-1]) == 2 and parts[-2] in _SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def normalise_domain(raw: str) -> str:
    raw = raw.strip().lower()
    host = urlsplit(raw if "://" in raw else "//" + raw).hostname or ""
    host = host.rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    try:
        host = host.encode("idna").decode()
    except UnicodeError:
        pass
    if not HOSTNAME_RE.match(host):
        raise ValueError(f"{raw!r} is not a domain name")
    return host


# ----------------------------------------------------------------------------- discovery sources


def _hackertarget(c: httpx.Client, d: str) -> set[str]:
    r = c.get("https://api.hackertarget.com/hostsearch/", params={"q": d}, timeout=20)
    r.raise_for_status()
    lines = r.text.strip().splitlines()
    if lines and "," not in lines[0]:
        if "no records" in lines[0].lower():
            return set()
        raise RuntimeError(lines[0][:80])
    return {ln.split(",")[0] for ln in lines}


def _urlscan(c: httpx.Client, d: str) -> set[str]:
    r = c.get("https://urlscan.io/api/v1/search/", params={"q": f"domain:{d}", "size": 1000}, timeout=25)
    r.raise_for_status()
    names: set[str] = set()
    for row in r.json().get("results", []):
        for part in ("page", "task"):
            names.add(str((row.get(part) or {}).get("domain", "")))
    return names


def _wayback(c: httpx.Client, d: str) -> set[str]:
    # The CDX index streams slowly for big domains: read for at most 12 s and keep what arrived.
    names: set[str] = set()
    deadline = time.monotonic() + 12
    try:
        with c.stream("GET", "https://web.archive.org/cdx/search/cdx", timeout=12,
                      params={"url": d, "matchType": "domain", "fl": "original", "collapse": "urlkey",
                              "limit": 20000}) as r:
            r.raise_for_status()
            for ln in r.iter_lines():
                names.add(urlsplit(ln if "://" in ln else "//" + ln).hostname or "")
                if time.monotonic() > deadline:
                    break
    except httpx.TimeoutException:
        if not names:
            raise
    return names


def _crtsh(c: httpx.Client, d: str) -> set[str]:
    try:
        return crtsh_subdomains(c, d)
    except httpx.HTTPStatusError:  # crt.sh often answers 502/503 on the first try
        time.sleep(2)
        return crtsh_subdomains(c, d)


SOURCES: dict[str, Callable[[httpx.Client, str], set[str]]] = {
    "crt.sh": _crtsh,
    "certspotter": lambda c, d: certspotter_subdomains(c, d, pages=10),
    "hackertarget": _hackertarget,
    "urlscan": _urlscan,
    "wayback": _wayback,
}


def _clean(names: set[str], domain: str) -> tuple[set[str], set[str]]:
    """Split raw names into (hostnames in scope, wildcard entries in scope)."""
    hosts: set[str] = set()
    wild: set[str] = set()
    for n in names:
        n = n.strip().lower().rstrip(".")
        is_wild = n.startswith("*.")
        n = n.lstrip("*.")
        if not (n == domain or n.endswith("." + domain)) or not HOSTNAME_RE.match(n):
            continue
        hosts.add(n)
        if is_wild:
            wild.add("*." + n)
    return hosts, wild


# ----------------------------------------------------------------------------- DNS

_tls = threading.local()


def _resolver(timeout: float, nameservers: list[str] | None) -> dns.resolver.Resolver:
    key = (timeout, tuple(nameservers or ()))
    if getattr(_tls, "key", None) != key:
        r = dns.resolver.Resolver(configure=not nameservers)
        if nameservers:
            r.nameservers = nameservers
        r.lifetime = timeout
        r.timeout = min(timeout, 3)
        _tls.key, _tls.resolver = key, r
    return _tls.resolver


def resolve_name(name: str, timeout: float = 5.0, nameservers: list[str] | None = None) -> dict:
    """Resolve A/AAAA for one name. status: resolved | NXDOMAIN | NODATA | SERVFAIL | TIMEOUT | INVALID."""
    r = _resolver(timeout, nameservers)
    out: dict = {"name": name, "a": [], "aaaa": [], "cname": None}
    seen: list[str] = []
    for rtype, key in (("A", "a"), ("AAAA", "aaaa")):
        for attempt in (1, 2):
            try:
                ans = r.resolve(name, rtype, raise_on_no_answer=False)
                canon = ans.canonical_name.to_text().rstrip(".").lower()
                if canon != name:
                    out["cname"] = canon
                if ans.rrset:
                    out[key] = sorted(rr.to_text() for rr in ans)
                else:
                    seen.append("NODATA")
            except dns.resolver.NXDOMAIN as e:
                seen.append("NXDOMAIN")
                try:
                    canon = e.canonical_name.to_text().rstrip(".").lower()
                    if canon != name:
                        out["cname"] = canon
                except Exception:
                    pass
            except dns.resolver.NoNameservers:
                seen.append("SERVFAIL")
            except dns.exception.Timeout:
                if attempt == 1:
                    continue
                seen.append("TIMEOUT")
            except (dns.name.NameTooLong, dns.name.EmptyLabel, dns.name.LabelTooLong, UnicodeError):
                seen.append("INVALID")
            break
        if "NXDOMAIN" in seen or "INVALID" in seen:
            break
    if out["a"] or out["aaaa"]:
        out["status"] = "resolved"
    else:
        out["status"] = next(s for s in ("NXDOMAIN", "INVALID", "SERVFAIL", "TIMEOUT", "NODATA") if s in seen)
    out["resolves"] = out["status"] == "resolved"
    return out


def asn_lookup(ip: str, timeout: float, nameservers: list[str] | None, names: dict[str, str]) -> dict | None:
    """Origin AS and network owner for an IP via Team Cymru's DNS interface."""
    r = _resolver(timeout, nameservers)
    rev = dns.reversename.from_address(ip).to_text()
    if rev.endswith(".in-addr.arpa."):
        q = rev[: -len(".in-addr.arpa.")] + ".origin.asn.cymru.com"
    else:
        q = rev[: -len(".ip6.arpa.")] + ".origin6.asn.cymru.com"
    rec = txt(r, q)
    if not rec:
        return None
    f = [x.strip() for x in rec[0].split("|")]
    asn = f[0].split()[0] if f[0] else ""
    if asn and asn not in names:
        owner = txt(r, f"AS{asn}.asn.cymru.com")
        names[asn] = owner[0].split("|")[-1].strip() if owner else ""
    return {"asn": asn, "prefix": f[1] if len(f) > 1 else None, "country": f[2] if len(f) > 2 else None,
            "owner": names.get(asn, "")}


# ----------------------------------------------------------------------------- per-host probes


def cert_names(host: str, timeout: float) -> list[str]:
    """DNS names in the certificate the host presents on 443 (not validated: we only read it)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(True)
        cert = x509.load_der_x509_certificate(der)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        return [n.lower() for n in san.get_values_for_type(x509.DNSName)]
    except Exception:
        return []


_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


def http_probe(c: httpx.Client, host: str) -> dict:
    err = ""
    for scheme in ("https", "http"):
        try:
            with c.stream("GET", f"{scheme}://{host}/") as r:
                body = b""
                for chunk in r.iter_bytes():
                    body += chunk
                    if len(body) > 65536:
                        break
            m = _TITLE_RE.search(body)
            title = re.sub(r"\s+", " ", m.group(1).decode(r.encoding or "utf-8", "replace")).strip() if m else ""
            final = str(r.url)
            return {"scheme": scheme, "status": r.status_code, "title": title[:120],
                    "server": r.headers.get("server", ""),
                    "final_url": final if urlsplit(final).hostname != host else None}
        except (httpx.HTTPError, OSError, ValueError) as e:
            err = type(e).__name__
    return {"error": err}


# ----------------------------------------------------------------------------- orchestration


def discover(domain: str, cfg: Config, *, probe: bool = True, bruteforce: bool = False, refresh: bool = False,
             nameservers: list[str] | None = None, workers: int = 30, dns_timeout: float = 5.0,
             progress: Callable[[str], None] = lambda _msg: None) -> dict:
    cache = JsonCache(cfg.cache_dir, "domains", SOURCE_CACHE_TTL)
    found: dict[str, set[str]] = {domain: {"input"}}  # hostname -> where it was seen
    wildcards: set[str] = set()
    related: dict[str, set[str]] = {}  # other registrable domain -> how it is related
    sources: list[dict] = []
    reg_domain = registrable(domain)

    def add(names, source: str) -> int:
        hosts, wild = _clean(set(names), domain)
        wildcards.update(wild)
        for h in hosts:
            found.setdefault(h, set()).add(source)
        return len(hosts)

    def relate(name: str, how: str) -> None:
        name = name.strip().lower().rstrip(".").lstrip("*.")
        if not HOSTNAME_RE.match(name) or name == domain or name.endswith("." + domain):
            return
        reg = registrable(name)
        if reg != domain:
            related.setdefault(reg, set()).add(how)

    # 1. passive sources, in parallel
    progress("Querying certificate transparency and passive DNS sources")

    def run_source(item):
        name, fn = item
        cached = None if refresh else cache.get(f"{name}:{domain}")
        if cached is not None:
            return name, set(cached), None, True
        try:
            with client(cfg.timeout) as c:
                names = {str(n) for n in fn(c, domain)}
            cache.set(f"{name}:{domain}", sorted(names))
            return name, names, None, False
        except Exception as e:  # each source is optional
            msg = f"HTTP {e.response.status_code}" if isinstance(e, httpx.HTTPStatusError) else (str(e) or type(e).__name__)
            return name, set(), msg[:80], False

    with ThreadPoolExecutor(len(SOURCES)) as ex:
        for name, names, error, cached in ex.map(run_source, SOURCES.items()):
            sources.append({"source": name, "names": add(names, name), "error": error, "cached": cached})

    # 2. the domain's own records
    progress("Reading DNS records and registration data")
    r = _resolver(dns_timeout, nameservers)
    records = {t: query(r, domain, t) for t in ("NS", "MX", "SOA", "CAA")}
    records["TXT"] = txt(r, domain)
    for ns in records["NS"]:
        add([ns], "NS record")
        relate(ns, "name server")
    for mx in records["MX"]:
        target = mx.split()[-1]
        add([target], "MX record")
        relate(target, "mail server (MX)")
    for t in records["TXT"]:
        if t.lower().startswith("v=spf1"):
            for inc in re.findall(r"(?:include:|redirect=)(\S+)", t, re.I):
                add([inc], "SPF")
                relate(inc, "SPF include")
    sources.append({"source": "DNS records (NS/MX/SPF)", "error": None, "cached": False,
                    "names": sum(1 for s in found.values() if s & {"NS record", "MX record", "SPF"})})

    registration: dict = {}
    try:
        with client(cfg.timeout) as c:
            registration = rdap_domain(c, reg_domain)
    except Exception:
        try:
            registration = whois_fallback(reg_domain, cfg.timeout)
        except Exception as e:
            registration = {"error": str(e) or type(e).__name__}

    # 3. wildcard DNS detection (a wildcard makes every name "resolve")
    wild_bases = [domain] + sorted(w[2:] for w in wildcards if w[2:] != domain)[:25]
    wildcard_dns: dict[str, dict] = {}
    with ThreadPoolExecutor(workers) as ex:
        probes = ex.map(lambda b: resolve_name(f"{secrets.token_hex(6)}.{b}", dns_timeout, nameservers), wild_bases)
        for base, res in zip(wild_bases, probes):
            if res["resolves"]:
                wildcard_dns[base] = {"ips": res["a"] + res["aaaa"], "cname": res["cname"]}

    def wildcard_match(h: dict) -> str | None:
        for base, w in wildcard_dns.items():
            if h["name"].endswith("." + base) and (
                    (h["cname"] and h["cname"] == w["cname"]) or set(h["a"] + h["aaaa"]) <= set(w["ips"])):
                return base
        return None

    if bruteforce:
        if domain in wildcard_dns:
            sources.append({"source": "wordlist", "names": 0, "cached": False,
                            "error": "skipped: wildcard DNS answers for every name"})
        else:
            progress(f"Trying {len(WORDLIST)} common names")
            cands = [f"{w}.{domain}" for w in WORDLIST if f"{w}.{domain}" not in found]
            with ThreadPoolExecutor(workers) as ex:
                hits = [h["name"] for h in ex.map(lambda n: resolve_name(n, dns_timeout, nameservers), cands)
                        if h["resolves"]]
            sources.append({"source": "wordlist", "names": add(hits, "wordlist"), "error": None, "cached": False})

    # 4. resolve everything; read certificates of live hosts, which can reveal more names (two rounds)
    hosts: dict[str, dict] = {}
    for rnd in (1, 2, 3):
        todo = sorted(n for n in found if n not in hosts)
        if not todo:
            break
        progress(f"Resolving {len(todo)} names" + (" found in certificates" if rnd > 1 else ""))
        with ThreadPoolExecutor(workers) as ex:
            for h in ex.map(lambda n: resolve_name(n, dns_timeout, nameservers), todo):
                hosts[h["name"]] = h
                if h["cname"]:
                    relate(h["cname"], f"CNAME target of {h['name']}")
        live = [n for n in todo if hosts[n]["resolves"]]
        if not probe or rnd == 3 or not live:
            continue
        progress(f"Reading TLS certificates of {len(live)} hosts")
        with ThreadPoolExecutor(workers) as ex:
            for n, sans in zip(live, ex.map(lambda n: cert_names(n, min(cfg.timeout, 4)), live)):
                hosts[n]["cert_names"] = len(sans)
                add(sans, "live certificate")
                if len({registrable(s.lstrip("*.")) for s in sans}) <= 40:  # skip shared-hosting mega certificates
                    for s in sans:
                        relate(s, f"same certificate as {n}")
    sources.append({"source": "live certificates", "error": None, "cached": False,
                    "names": sum(1 for s in found.values() if "live certificate" in s)})

    resolved = [h for h in hosts.values() if h["resolves"]]

    # 5. network owner per IP
    progress("Looking up network owners")
    ips = sorted({(h["a"] or h["aaaa"])[0] for h in resolved})
    as_names: dict[str, str] = {}
    with ThreadPoolExecutor(workers) as ex:
        nets = dict(zip(ips, ex.map(lambda ip: asn_lookup(ip, dns_timeout, nameservers, as_names), ips)))
    for h in resolved:
        h["network"] = nets.get((h["a"] or h["aaaa"])[0])

    # 6. HTTP status and page title
    if probe and resolved:
        progress(f"Requesting the front page of {len(resolved)} hosts")
        with client(min(cfg.timeout, 5), verify=False) as c, ThreadPoolExecutor(workers) as ex:
            for h, web in zip(resolved, ex.map(lambda h: http_probe(c, h["name"]), resolved)):
                h["http"] = web
                if web.get("final_url"):
                    relate(urlsplit(web["final_url"]).hostname or "", f"redirect from {h['name']}")

    for h in hosts.values():
        h["sources"] = sorted(found[h["name"]])
        h["interesting"] = bool(INTERESTING_SUB.search(h["name"][: -len(domain)])) if h["name"] != domain else False
        h["wildcard"] = wildcard_match(h) if h["resolves"] else None
        h["private"] = any(not ipaddress.ip_address(ip).is_global for ip in h["a"] + h["aaaa"])
        h["takeover_risk"] = bool(not h["resolves"] and h["cname"] and h["cname"].endswith(TAKEOVER_SUFFIXES))

    # 7. do the related domains resolve?
    rel_names = sorted(related)
    progress(f"Checking {len(rel_names)} related domains")
    with ThreadPoolExecutor(workers) as ex:
        rel = [{"domain": n, "resolves": res["resolves"], "status": res["status"], "relation": sorted(related[n])}
               for n, res in zip(rel_names, ex.map(lambda n: resolve_name(n, dns_timeout, nameservers), rel_names))]

    ordered = sorted(hosts.values(), key=lambda h: h["name"].split(".")[::-1])
    return {
        "domain": domain,
        "registrable_domain": reg_domain,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "registration": registration,
        "dns": records,
        "sources": sources,
        "wildcard_dns": wildcard_dns,
        "wildcard_certificates": sorted(wildcards),
        "hosts": ordered,
        "related_domains": rel,
        "summary": {"total": len(ordered), "resolving": len(resolved), "not_resolving": len(ordered) - len(resolved),
                    "related_domains": len(rel)},
    }


# ----------------------------------------------------------------------------- rendering

STATUS_TEXT = {
    "NXDOMAIN": "does not exist (NXDOMAIN)",
    "NODATA": "name exists, no A/AAAA record",
    "SERVFAIL": "name servers failed (SERVFAIL)",
    "TIMEOUT": "DNS timeout (unknown)",
    "INVALID": "not a valid DNS name",
}


def _link(label: str, url: str, style: str = "") -> Text:
    """Text carrying an OSC 8 hyperlink, so it is clickable whatever the label looks like."""
    return Text(label, style=Style.parse(style) + Style(link=url))


def _url(name: str, scheme: str = "https", style: str = "") -> Text:
    url = f"{scheme}://{name}"
    return _link(url, url, style)


def _section(console: Console, title: str) -> None:
    console.print()
    console.rule(f"[bold]{title}[/]", align="left", style="blue")


def render(rep: dict, console: Console, only: str = "all", verbose: int = 0) -> None:
    dom = rep["domain"]
    s = rep["summary"]
    console.print()
    console.print(Text.assemble(("Domains related to ", "bold"), _url(dom, style="bold cyan")))
    console.print(f"[bold]{s['total']}[/] names found · [bold green]{s['resolving']} resolve[/] · "
                  f"[bold red]{s['not_resolving']} do not resolve[/] · {s['related_domains']} related domains")

    # registration + DNS
    reg = rep["registration"]
    t = Table(box=None, show_header=False, padding=(0, 2, 0, 0))
    t.add_column(style="bold cyan", no_wrap=True)
    t.add_column(overflow="fold")
    if reg.get("error"):
        t.add_row("Registration", f"[dim]lookup failed: {reg['error']}[/]")
    elif not (reg.get("registrar") or reg.get("created") or reg.get("nameservers")):
        t.add_row("Registration", "[yellow]no registration record found[/]")
    else:
        t.add_row("Registered domain", _url(rep["registrable_domain"]))
        t.add_row("Registrar", reg.get("registrar") or "-")
        t.add_row("Created", (reg.get("created") or "-")[:10])
        t.add_row("Expires", (reg.get("expires") or "-")[:10])
        if verbose:
            t.add_row("Status", ", ".join(reg.get("status") or []) or "-")
        if reg.get("rdap_url"):
            t.add_row("Record", _link(reg["rdap_url"], reg["rdap_url"], "dim"))
    d = rep["dns"]
    t.add_row("Name servers", ", ".join(n.rstrip(".") for n in d["NS"]) or "-")
    t.add_row("Mail servers", ", ".join(m.split()[-1].rstrip(".") for m in d["MX"]) or "-")
    if verbose:
        for rec in d["TXT"]:
            t.add_row("TXT", rec)
    if rep["wildcard_dns"]:
        t.add_row("Wildcard DNS", "[yellow]" + ", ".join(f"*.{b}" for b in rep["wildcard_dns"])
                  + "[/] [dim](any name under these resolves)[/]")
    _section(console, "Domain")
    console.print(t)

    _section(console, "Sources")
    t = Table(box=box.SIMPLE, pad_edge=False)
    t.add_column("Source")
    t.add_column("Names", justify="right")
    t.add_column("Note", style="dim")
    for src in rep["sources"]:
        note = f"[red]failed: {src['error']}[/]" if src["error"] else ("cached" if src["cached"] else "")
        t.add_row(src["source"], str(src["names"]), note)
    console.print(t)

    live = [h for h in rep["hosts"] if h["resolves"]]
    dead = [h for h in rep["hosts"] if not h["resolves"]]

    if only in ("all", "resolved"):
        _section(console, f"Resolving ({len(live)})")
        if live:
            t = Table(box=box.SIMPLE, pad_edge=False)
            t.add_column("URL", no_wrap=True, min_width=min(60, max(len(h["name"]) for h in live) + 8))
            t.add_column("IP address", no_wrap=True)
            t.add_column("Network", no_wrap=True, max_width=22, overflow="ellipsis")
            t.add_column("HTTP", no_wrap=True)
            t.add_column("Title / redirect / CNAME", overflow="fold" if verbose else "ellipsis", no_wrap=not verbose,
                         max_width=None if verbose else 56)
            if verbose:
                t.add_column("Found via", style="dim")
            for h in live:
                web = h.get("http") or {}
                ips = h["a"] + h["aaaa"]
                ip = _link(ips[0], f"https://ipinfo.io/{ips[0]}")
                if len(ips) > 1:
                    ip.append(f" +{len(ips) - 1}", style="dim")
                net = h.get("network") or {}
                status = web.get("status")
                http = Text(str(status), style="green" if status < 400 else "yellow" if status < 500 else "red") \
                    if status else Text("-" if "http" not in h else "no web", style="dim")
                info = Text(web.get("title") or "")
                if web.get("final_url"):
                    shown = web["final_url"] if verbose or len(web["final_url"]) <= 54 else web["final_url"][:53] + "…"
                    info = Text.assemble(("→ ", "dim"), _link(shown, web["final_url"]))
                elif h["cname"]:
                    info = Text.assemble(info, " " if info else "", (f"→ {h['cname']}", "dim"))
                if h["wildcard"]:
                    info = Text.assemble(("wildcard ", "yellow"), info)
                row = [_url(h["name"], web.get("scheme", "https"), "yellow" if h["interesting"] else ""), ip,
                       net.get("owner") or (f"AS{net['asn']}" if net.get("asn") else
                                            Text("private address", style="yellow") if h["private"] else "-"), http, info]
                if verbose:
                    row.append(", ".join(h["sources"]))
                t.add_row(*row)
            console.print(t)
        else:
            console.print("[dim]none[/]")

    if only in ("all", "unresolved"):
        _section(console, f"Not resolving ({len(dead)})")
        if dead:
            t = Table(box=box.SIMPLE, pad_edge=False)
            t.add_column("URL", no_wrap=True)
            t.add_column("Why")
            t.add_column("Found via", style="dim")
            for h in dead:
                why = Text(STATUS_TEXT.get(h["status"], h["status"]))
                if h["cname"]:
                    why = Text("CNAME target has no address" if h["status"] == "NODATA" else "CNAME target does not exist"
                               if h["status"] == "NXDOMAIN" else STATUS_TEXT.get(h["status"], h["status"]))
                    why.append(f" · dangling CNAME → {h['cname']}", style="bold red" if h["takeover_risk"] else "yellow")
                    if h["takeover_risk"]:
                        why.append(" (takeover risk)", style="bold red")
                t.add_row(_url(h["name"], style="dim"), why, ", ".join(h["sources"]))
            console.print(t)
        else:
            console.print("[dim]none[/]")

    if only == "all":
        if rep["wildcard_certificates"]:
            _section(console, f"Wildcard certificates ({len(rep['wildcard_certificates'])})")
            console.print(", ".join(rep["wildcard_certificates"]), soft_wrap=False)
        if rep["related_domains"]:
            _section(console, f"Related domains ({len(rep['related_domains'])})")
            t = Table(box=box.SIMPLE, pad_edge=False)
            t.add_column("URL", no_wrap=True)
            t.add_column("Resolves")
            t.add_column("Relation")
            for rd in rep["related_domains"]:
                rel = rd["relation"] if verbose else rd["relation"][:2] + (
                    [f"+{len(rd['relation']) - 2} more"] if len(rd["relation"]) > 2 else [])
                t.add_row(_url(rd["domain"]), "[green]yes[/]" if rd["resolves"] else f"[red]no[/] [dim]{STATUS_TEXT.get(rd['status'], rd['status'])}[/]",
                          "; ".join(rel))
            console.print(t)
    console.print()
