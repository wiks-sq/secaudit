"""Terminal (rich) and Markdown rendering of an audit report dict."""

from __future__ import annotations

from typing import Any

from rich import box
from rich.columns import Columns
from rich.console import Console, Group
from rich.markdown import Markdown
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from secaudit.history import Diff
from secaudit.models import Severity

GRADE_STYLE = {"A+": "bold green", "A": "bold green", "B": "bold yellow", "C": "bold dark_orange",
               "D": "bold red", "F": "bold white on red"}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
CVE_SEV_STYLE = {"CRITICAL": "bold white on red", "HIGH": "bold red", "MEDIUM": "yellow", "LOW": "green",
                 "NONE": "dim", "UNKNOWN": "dim"}

OK = Text("✔", style="bold green")
BAD = Text("✘", style="bold red")
WARN = Text("!", style="bold yellow")


def sev_badge(name: str) -> Text:
    s = Severity.parse(name)
    return Text(f" {s.label.upper():<8}", style=s.style)


def _kv_table(title: str | None = None) -> Table:
    t = Table(box=box.SIMPLE_HEAD, show_header=False, title=title, title_justify="left", title_style="bold",
              pad_edge=False, expand=False)
    t.add_column(style="bold cyan", no_wrap=True)
    t.add_column(overflow="fold")
    return t


def _section(console: Console, title: str) -> None:
    console.print()
    console.print(Rule(Text(title, style="bold magenta"), style="magenta", align="left"))


def _trunc(s: str | None, n: int) -> str:
    s = (s or "").replace("\n", " ").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


# ----------------------------------------------------------------------------- main render


def render(report: dict[str, Any], console: Console, verbose: int = 0, diff: Diff | None = None,
           history_path: str | None = None) -> None:
    s = report.get("sections", {})
    _header(report, console)
    _key_findings(report, console)
    _overview(report, console)
    _tech(report, console)
    _cves(report, console, verbose)
    _http(s.get("http", {}), console, verbose)
    _tls(s.get("tls", {}), console, verbose)
    _domain(s.get("domain", {}), s.get("dns", {}), console, verbose)
    _content(s.get("content", {}), s.get("domain", {}), s.get("tech", {}), console, verbose)
    _all_findings(report, console, verbose)
    if diff:
        render_diff(diff, console)
    if report.get("ai_analysis"):
        _section(console, "AI analysis (" + report["ai_analysis"].get("model", "ollama") + ")")
        console.print(Markdown(report["ai_analysis"]["text"]))
    errs = report.get("errors") or {}
    if errs:
        _section(console, "Collector warnings")
        for name, items in errs.items():
            for e in items:
                console.print(f"  [yellow]•[/] [bold]{name}[/]: {_trunc(e, 220)}")
    console.print()
    if history_path:
        console.print(f"[dim]History saved →[/] [bold]{history_path}[/]")


def _header(report: dict, console: Console) -> None:
    t = report["target"]
    grade = report.get("grade", "?")
    summary = report.get("summary", {})
    badges = Text()
    for name in SEV_ORDER:
        n = summary.get(name.lower(), 0)
        style = Severity.parse(name).style if n else "dim"
        badges.append(f" {n} {name.capitalize()} ", style=style)
        badges.append("  ")
    info = _kv_table()
    info.add_row("Target", t.get("final_url") or t["host"])
    if t.get("apex") and t.get("apex") != t["host"]:
        info.add_row("Domain", t["apex"])
    info.add_row("IP(s)", ", ".join(t.get("ips") or []) or "-")
    info.add_row("Audited", f"{report['started_at']}  ({report.get('duration_s')}s)")
    blocked = (report.get("coverage") or {}).get("blocked")
    info.add_row("Score", f"{report.get('score')}/100" + ("  [yellow](partial — see warning)[/]" if blocked else ""))
    grade_panel = Panel(Group(Text("GRADE", style="dim", justify="center"),
                              Text(grade, style=GRADE_STYLE.get(grade, "bold"), justify="center")),
                        width=13, box=box.HEAVY, border_style=GRADE_STYLE.get(grade, "white").split()[-1])
    console.print(Panel(Group(Columns([grade_panel, info], padding=(0, 2)), badges),
                        title=f"[bold]secaudit[/] · [bold cyan]{t['host']}[/]", border_style="blue",
                        subtitle="passive, non-intrusive audit", subtitle_align="right"))
    if blocked:
        console.print(Panel(
            Text.assemble(
                (f"{blocked['vendor']} served a {blocked['kind']} (HTTP {blocked['status']}) instead of the website.\n", "bold"),
                "Security headers, cookies, CORS, page content, tech stack and the CVEs that depend on it were NOT checked —\n"
                "they would describe the challenge page, not the site. No grade is given.\n",
                ("Still valid: ", "bold"), "TLS/certificate, HTTPS redirect, DNS, email security, domain registration, CT subdomains.\n",
                ("To get a full audit: ", "bold"), "run it from an allow-listed IP or exempt this host from bot protection for the audit.",
            ),
            title="[bold]⚠ Incomplete audit — blocked by bot protection[/]", border_style="yellow"))


def _key_findings(report: dict, console: Console) -> None:
    key = [f for f in report.get("findings", []) if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM")]
    if not key:
        if (report.get("coverage") or {}).get("blocked"):
            console.print(Panel("[yellow]No critical, high or medium findings in the parts that could be checked.[/]",
                                title="Key findings", border_style="yellow"))
        else:
            console.print(Panel("[bold green]No critical, high or medium findings.[/]", title="Key findings",
                                border_style="green"))
        return
    t = Table(box=None, show_header=False, pad_edge=False, expand=True)
    t.add_column(no_wrap=True, width=10)
    t.add_column(ratio=1)
    for f in key[:15]:
        body = Text(f["title"], style="bold")
        if f.get("evidence"):
            body.append("\n" + _trunc(f["evidence"], 160), style="dim")
        t.add_row(sev_badge(f["severity"]), body)
    if len(key) > 15:
        t.add_row("", Text(f"… and {len(key) - 15} more (see All findings)", style="dim"))
    worst = Severity.parse(key[0]["severity"])
    console.print(Panel(t, title="[bold]⚠ Key findings[/]", border_style=worst.style.split()[-1]))


def _overview(report: dict, console: Console) -> None:
    s = report["sections"]
    http = s.get("http", {})
    main = http.get("main", {})
    tls = s.get("tls", {})
    cert = tls.get("certificate", {})
    dom = s.get("domain", {})
    reg = dom.get("registration") or {}
    hdr = http.get("headers") or {}
    _section(console, "Overview")
    t = _kv_table()
    if main:
        t.add_row("Response", f"HTTP {main.get('status')} {main.get('reason', '')} · {main.get('http_version')} · "
                              f"{main.get('elapsed_ms')} ms · {main.get('size_bytes', 0) / 1024:.1f} KiB")
        chain = main.get("redirect_chain") or []
        if len(chain) > 1:
            t.add_row("Redirects", " → ".join(f"{h['url']} [{h['status']}]" for h in chain))
        http_chain = http.get("http_redirect_chain") or []
        if http_chain:
            t.add_row("http:// →", " → ".join(f"{h['url']} [{h['status']}]" for h in http_chain))
    if hdr.get("server"):
        t.add_row("Server", hdr["server"])
    if s.get("content", {}).get("page", {}).get("title"):
        t.add_row("Page title", s["content"]["page"]["title"])
    for ip in dom.get("ips", []):
        parts = [ip["ip"]]
        if ip.get("ptr"):
            parts.append(f"({ip['ptr']})")
        owner = " / ".join(x for x in (ip.get("network"), ip.get("org"), ip.get("country")) if x)
        if owner:
            parts.append(f"— {owner}")
        t.add_row("Host IP", " ".join(parts))
    if tls.get("available"):
        trust = "[green]trusted[/]" if tls.get("trusted") else "[red]NOT trusted[/]"
        t.add_row("TLS", f"{tls.get('negotiated_protocol')} · {tls.get('negotiated_cipher')} · ALPN {tls.get('alpn') or '-'} · {trust}")
        if cert:
            days = cert.get("days_left", 0)
            col = "green" if days > 30 else "yellow" if days > 14 else "red"
            t.add_row("Certificate", f"{cert.get('subject_cn')} · issued by {cert.get('issuer_org') or cert.get('issuer_cn')} · "
                                     f"[{col}]expires in {days} days[/]")
    if reg:
        exp = reg.get("expires_in_days")
        col = "green" if exp is None or exp > 90 else "yellow" if exp > 30 else "red"
        t.add_row("Registrar", f"{reg.get('registrar') or '-'}  ({reg.get('source')})")
        t.add_row("Domain dates", f"created {(reg.get('created') or '-')[:10]} · expires {(reg.get('expires') or '-')[:10]}"
                                  + (f" [{col}]({exp} days)[/]" if exp is not None else ""))
    console.print(t)


def _tech(report: dict, console: Console) -> None:
    techs = report.get("technologies", [])
    _section(console, f"Technology stack ({len(techs)})")
    if not techs:
        console.print("  [dim]No technologies fingerprinted.[/]")
        return
    cve_counts: dict[str, int] = {}
    for c in report.get("cves", []):
        cve_counts[c["product"]] = cve_counts.get(c["product"], 0) + 1
    t = Table(box=box.SIMPLE_HEAD, header_style="bold")
    t.add_column("Category", style="dim")
    t.add_column("Technology", style="bold")
    t.add_column("Version")
    t.add_column("CVEs", justify="right")
    t.add_column("Detected via", style="dim", overflow="fold")
    for x in sorted(techs, key=lambda x: (x["category"], x["name"])):
        n = cve_counts.get(x["name"], 0)
        t.add_row(x["category"], x["name"], x.get("version") or "[dim]-[/]",
                  f"[bold red]{n}[/]" if n else ("[dim]-[/]"), _trunc(x.get("source"), 60))
    console.print(t)
    os_hint = report["sections"].get("tech", {}).get("os_hint")
    if os_hint:
        console.print(f"  [dim]OS hint from banner:[/] {os_hint}")
    plugins = report["sections"].get("tech", {}).get("wordpress_plugins") or {}
    if plugins:
        console.print("  [bold]WordPress plugins:[/] " + ", ".join(f"{k}{' ' + v if v else ''}" for k, v in sorted(plugins.items())))


def _cves(report: dict, console: Console, verbose: int) -> None:
    sec = report["sections"].get("cve")
    if sec is None:
        return
    cves = report.get("cves", [])
    kev = sum(1 for c in cves if c.get("kev"))
    _section(console, f"Known vulnerabilities — {len(cves)} CVE(s)" + (f", {kev} actively exploited (CISA KEV)" if kev else ""))
    checked = sec.get("checked", [])
    if checked:
        console.print("  [dim]Checked:[/] " + ", ".join(f"{c['product']} {c['version']} ({c['source']}: {c['count']})" for c in checked))
    if sec.get("version_unknown"):
        console.print("  [dim]Version unknown (not matchable):[/] " + ", ".join(sec["version_unknown"]))
    if not cves:
        if checked:
            console.print("  [green]No known CVEs for the detected versions.[/]")
        elif not sec.get("version_unknown"):
            console.print("  [dim]No version-identifiable components with CVE data sources.[/]")
        return
    by_product: dict[str, list[dict]] = {}
    for c in cves:
        by_product.setdefault(f"{c['product']} {c.get('product_version') or ''}".strip(), []).append(c)
    for product, items in by_product.items():
        t = Table(box=box.SIMPLE_HEAD, header_style="bold", title=f"{product}  ({len(items)})", title_justify="left",
                  title_style="bold red", expand=True)
        t.add_column("ID", no_wrap=True, style="bold")
        t.add_column("CVSS", justify="right", no_wrap=True)
        t.add_column("Severity", no_wrap=True)
        t.add_column("KEV", justify="center", no_wrap=True)
        t.add_column("EPSS", justify="right", no_wrap=True)
        t.add_column("Published", no_wrap=True, style="dim")
        t.add_column("Summary", ratio=1, overflow="fold" if verbose else "ellipsis", no_wrap=not verbose)
        for c in items:
            epss = c.get("epss")
            epss_txt = f"{epss * 100:.1f}%" if epss is not None else "-"
            if epss is not None and epss >= 0.1:
                epss_txt = f"[bold red]{epss_txt}[/]"
            t.add_row(c["id"], f"{c['score']:.1f}" if c.get("score") is not None else "-",
                      Text(c.get("severity", "?"), style=CVE_SEV_STYLE.get(str(c.get("severity")).upper(), "")),
                      "[bold white on red] YES [/]" if c.get("kev") else "",
                      epss_txt, c.get("published", ""), (c.get("summary") or "").replace("\n", " ") if verbose else _trunc(c.get("summary"), 200))
        console.print(t)
    if any(c.get("source") == "NVD" for c in cves):
        console.print("  [dim]NVD matches are by upstream version; Linux distributions often backport fixes "
                      "without changing the version string.[/]")


SEC_HEADERS = [
    ("strict-transport-security", "HSTS"),
    ("content-security-policy", "CSP"),
    ("x-frame-options", "X-Frame-Options"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("referrer-policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy"),
    ("cross-origin-opener-policy", "COOP"),
    ("cross-origin-resource-policy", "CORP"),
    ("cross-origin-embedder-policy", "COEP"),
]


def _http(http: dict, console: Console, verbose: int) -> None:
    if not http.get("headers"):
        return
    h = http["headers"]
    _section(console, "HTTP security headers")
    if http.get("blocked"):
        b = http["blocked"]
        console.print(f"  [yellow]Not checked — {b['vendor']} answered with a {b['kind']} (HTTP {b['status']}), "
                      "so these headers and cookies belong to the challenge page, not the site.[/]")
        if verbose:
            console.print("  [dim]Challenge response headers: " + ", ".join(f"{k}: {v}" for k, v in sorted(h.items())) + "[/]")
        return
    t = Table(box=box.SIMPLE_HEAD, header_style="bold", expand=True)
    t.add_column("", width=2)
    t.add_column("Header", style="bold", no_wrap=True)
    t.add_column("Value", ratio=1, overflow="fold")
    for key, label in SEC_HEADERS:
        v = h.get(key)
        mark = OK if v else (WARN if key.startswith("cross-origin") else BAD)
        t.add_row(mark, label, (v if verbose else _trunc(v, 140)) if v else Text("missing", style="dim"))
    if h.get("content-security-policy-report-only"):
        t.add_row(WARN, "CSP (report-only)", _trunc(h["content-security-policy-report-only"], 140))
    hsts = http.get("hsts") or {}
    if hsts.get("preload_status"):
        st = hsts["preload_status"]
        t.add_row(OK if st == "preloaded" else WARN, "HSTS preload list",
                  {"unknown": "not on the preload list"}.get(st, st))
    cors = http.get("cors") or {}
    if cors.get("allow_origin"):
        t.add_row(WARN, "CORS", f"ACAO: {cors['allow_origin']}  credentials: {cors['allow_credentials']}")
    opts = http.get("options") or {}
    if opts.get("allow"):
        t.add_row(Text("·"), "Allowed methods", ", ".join(opts["allow"]))
    for leak in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        if h.get(leak):
            t.add_row(WARN, leak, h[leak])
    console.print(t)

    cookies = http.get("cookies") or []
    if cookies:
        ct = Table(box=box.SIMPLE_HEAD, header_style="bold", title=f"Cookies ({len(cookies)})", title_justify="left",
                   title_style="bold")
        ct.add_column("Name", style="bold", overflow="fold")
        ct.add_column("Secure", justify="center")
        ct.add_column("HttpOnly", justify="center")
        ct.add_column("SameSite", justify="center")
        ct.add_column("Domain / Path", style="dim", overflow="fold")
        ct.add_column("Expires", style="dim", overflow="fold")
        for c in cookies:
            ct.add_row(c["name"], OK if c["secure"] else BAD, OK if c["httponly"] else BAD,
                       c.get("samesite") or Text("-", style="red"),
                       f"{c.get('domain') or '(host)'} {c.get('path') or ''}", _trunc(str(c.get("expires") or "session"), 32))
        console.print(ct)

    if verbose:
        rt = Table(box=box.SIMPLE, title="All response headers", title_justify="left", title_style="bold", show_header=False)
        rt.add_column(style="cyan", no_wrap=True)
        rt.add_column(overflow="fold")
        for k, v in sorted(h.items()):
            rt.add_row(k, v)
        console.print(rt)


def _tls(tls: dict, console: Console, verbose: int) -> None:
    if not tls.get("available"):
        return
    _section(console, "TLS / certificate")
    cert = tls.get("certificate", {})
    t = _kv_table()
    t.add_row("Subject", f"{cert.get('subject_cn')}" + (f"  ({cert['subject_org']})" if cert.get("subject_org") else ""))
    t.add_row("Issuer", f"{cert.get('issuer_cn')}  ({cert.get('issuer_org') or '-'})")
    t.add_row("Validity", f"{cert.get('not_before', '')[:10]} → {cert.get('not_after', '')[:10]}  "
                          f"({cert.get('days_left')} days left, {cert.get('lifetime_days')}-day lifetime)")
    t.add_row("Key / signature", f"{cert.get('key_type')} {cert.get('key_bits') or ''} bits · {cert.get('signature_hash')}")
    sans = cert.get("san_dns", [])
    t.add_row("SANs", (", ".join(sans) if verbose else _trunc(", ".join(sans), 200)) + f"  [dim]({len(sans)})[/]")
    t.add_row("CT SCTs", str(cert.get("sct_count")))
    t.add_row("Trust", "[green]valid chain[/]" if tls.get("trusted") else f"[red]{tls.get('verify_error')}[/]")
    if tls.get("chain"):
        t.add_row("Chain", " ← ".join(c.get("subject_cn") or "?" for c in tls["chain"]))
    if verbose:
        t.add_row("Serial", cert.get("serial", ""))
        t.add_row("SHA-256", cert.get("sha256_fingerprint", ""))
        t.add_row("OCSP", ", ".join(cert.get("ocsp_urls", [])) or "-")
    console.print(t)

    pt = Table(box=box.SIMPLE_HEAD, header_style="bold", title="Protocols & cipher classes", title_justify="left",
               title_style="bold")
    pt.add_column("Test", style="bold")
    pt.add_column("Result")
    for proto, state in (tls.get("protocols") or {}).items():
        legacy = proto in ("TLSv1.0", "TLSv1.1")
        if state == "yes":
            pt.add_row(proto, Text("enabled", style="bold red" if legacy else "green"))
        elif state == "no":
            pt.add_row(proto, Text("disabled", style="green" if legacy else "yellow"))
        else:
            pt.add_row(proto, Text("not testable with local OpenSSL", style="dim"))
    for label, state in (tls.get("weak_ciphers") or {}).items():
        if state.startswith("yes"):
            pt.add_row(label, Text(f"ACCEPTED ({state.split(':', 1)[1]})", style="bold red"))
        elif state == "no":
            pt.add_row(label, Text("rejected", style="green"))
        else:
            pt.add_row(label, Text("not testable locally", style="dim"))
    console.print(pt)


def _domain(dom: dict, dns: dict, console: Console, verbose: int) -> None:
    if not dom and not dns:
        return
    _section(console, "Domain & DNS")
    reg = dom.get("registration") or {}
    if reg:
        t = _kv_table("Registration")
        t.add_row("Domain", dom.get("apex", ""))
        t.add_row("Registrar", reg.get("registrar") or "-")
        if reg.get("registrar_abuse"):
            t.add_row("Abuse contact", reg["registrar_abuse"])
        t.add_row("Created", reg.get("created") or "-")
        t.add_row("Updated", reg.get("updated") or "-")
        t.add_row("Expires", (reg.get("expires") or "-") + (f"  ({reg['expires_in_days']} days)" if reg.get("expires_in_days") is not None else ""))
        t.add_row("Status", ", ".join(reg.get("status") or []) or "-")
        t.add_row("Nameservers", ", ".join(reg.get("nameservers") or []) or "-")
        t.add_row("DNSSEC (registry)", {True: "[green]signed[/]", False: "[yellow]unsigned[/]"}.get(reg.get("dnssec_delegation"), "-"))
        console.print(t)

    recs = dns.get("records") or {}
    if recs:
        t = Table(box=box.SIMPLE_HEAD, header_style="bold", title="DNS records", title_justify="left", title_style="bold",
                  expand=True)
        t.add_column("Name", style="dim", no_wrap=True)
        t.add_column("Type", style="bold cyan", no_wrap=True)
        t.add_column("Value", ratio=1, overflow="fold")
        for scope in ("host", "apex"):
            for rtype, vals in (recs.get(scope) or {}).items():
                if not vals:
                    continue
                if rtype == "TXT" and not verbose:
                    vals = [_trunc(v, 100) for v in vals[:6]] + ([f"… {len(vals) - 6} more (-v)"] if len(vals) > 6 else [])
                t.add_row(scope, rtype, "\n".join(vals))
        console.print(t)

    email = dns.get("email") or {}
    if email or dns.get("dnssec"):
        t = Table(box=box.SIMPLE_HEAD, header_style="bold", title="Email & DNS security", title_justify="left",
                  title_style="bold", expand=True)
        t.add_column("", width=2)
        t.add_column("Control", style="bold", no_wrap=True)
        t.add_column("Value", ratio=1, overflow="fold")
        spf = email.get("spf") or []
        t.add_row(OK if spf else BAD, "SPF", (spf[0] if spf else "missing") +
                  (f"  [dim]({email['spf_lookups']} DNS lookups)[/]" if email.get("spf_lookups") is not None else ""))
        dmarc = email.get("dmarc") or []
        pol = (email.get("dmarc_policy") or "").lower()
        t.add_row(OK if pol in ("reject", "quarantine") else WARN if dmarc else BAD, "DMARC", dmarc[0] if dmarc else "missing")
        if email.get("mx"):
            sel = email.get("dkim_selectors_found") or []
            t.add_row(OK if sel else WARN, "DKIM", ("selectors: " + ", ".join(sel)) if sel else "no common selector found (not conclusive)")
            t.add_row(OK if email.get("mta_sts") else WARN, "MTA-STS", email["mta_sts"][0] if email.get("mta_sts") else "missing")
            t.add_row(OK if email.get("tls_rpt") else WARN, "TLS-RPT", email["tls_rpt"][0] if email.get("tls_rpt") else "missing")
        dnssec = dns.get("dnssec") or {}
        t.add_row(OK if dnssec.get("ds") and dnssec.get("dnskey") else BAD, "DNSSEC",
                  "signed (DNSKEY + DS)" if dnssec.get("ds") and dnssec.get("dnskey") else
                  "DNSKEY without DS" if dnssec.get("dnskey") else "not signed")
        caa = dns.get("caa") or []
        t.add_row(OK if caa else BAD, "CAA", "\n".join(caa) if caa else "missing")
        if dns.get("txt_verifications"):
            t.add_row(Text("·"), "SaaS verifications", ", ".join(dns["txt_verifications"]))
        console.print(t)


def _content(content: dict, dom: dict, tech: dict, console: Console, verbose: int) -> None:
    if not content and not dom.get("ct"):
        return
    _section(console, "Content & attack surface")
    t = _kv_table()
    page = content.get("page") or {}
    if page:
        t.add_row("Page", f"{page.get('external_scripts')} external scripts · {page.get('inline_scripts')} inline · "
                          f"{page.get('stylesheets')} stylesheets · {page.get('iframes')} iframes · {page.get('forms')} forms")
    tp = content.get("third_party") or {}
    if tp:
        items = [f"{h} [dim]({'/'.join(k)})[/]" for h, k in tp.items()]
        t.add_row(f"Third parties ({len(tp)})", ", ".join(items if verbose else items[:15]) + ("" if verbose or len(items) <= 15 else f" … +{len(items) - 15}"))
    if content.get("no_sri"):
        t.add_row("Missing SRI", ", ".join(_trunc(u, 70) for u in content["no_sri"][: (50 if verbose else 5)]))
    forms = content.get("forms") or []
    for f in forms[:5]:
        flags = []
        if f.get("password"):
            flags.append("[yellow]password[/]")
        if f.get("csrf_token"):
            flags.append("csrf-token")
        t.add_row("Form", f"{f.get('method', 'get').upper()} {f.get('action_abs')} {' '.join(flags)}")
    if content.get("emails"):
        t.add_row("Emails in source", ", ".join(content["emails"][:10]))
    if content.get("skipped"):
        t.add_row("Page content", f"[yellow]{content['skipped']}[/]")
    rob = content.get("robots")
    if rob and rob.get("blocked"):
        t.add_row("robots.txt", "[yellow]blocked by bot challenge[/]")
    elif rob is not None:
        t.add_row("robots.txt", f"{len(rob.get('disallow', []))} disallow rules" +
                  (f"; notable: {', '.join(rob['sensitive'][:10])}" if rob.get("sensitive") else ""))
    else:
        t.add_row("robots.txt", "[dim]not present[/]")
    st = content.get("security_txt")
    if st and st.get("blocked"):
        t.add_row("security.txt", "[yellow]blocked by bot challenge[/]")
    elif st:
        f = st.get("fields", {})
        t.add_row("security.txt", f"[green]present[/] · contact: {', '.join(f.get('contact', []))} · expires: {', '.join(f.get('expires', [])) or '-'}")
    else:
        t.add_row("security.txt", "[yellow]missing[/]")
    sm = content.get("sitemap")
    if sm and sm.get("blocked"):
        sm = None
        t.add_row("sitemap.xml", "[yellow]blocked by bot challenge[/]")
    else:
        t.add_row("sitemap.xml", f"{sm['entries']} entries" + (" (index)" if sm.get("index") else "") if sm else "[dim]not present[/]")
    exp = content.get("exposure_checks")
    if isinstance(exp, dict):
        t.add_row("Exposure checks", f"{len(exp['checked'])} paths checked · " +
                  (f"[bold red]{len(exp['found'])} exposed: {', '.join(exp['found'])}[/]" if exp["found"] else "[green]none exposed[/]"))
    elif exp:
        t.add_row("Exposure checks", f"[dim]{exp}[/]")
    comments = content.get("comments") or {}
    if comments.get("interesting") and verbose:
        t.add_row("Notable comments", "\n".join(_trunc(c, 150) for c in comments["interesting"][:10]))
    console.print(t)

    ct = dom.get("ct")
    if ct:
        subs = ct.get("subdomains", [])
        interesting = set(ct.get("interesting", []))
        limit = None if verbose else 40
        shown = subs if limit is None else subs[:limit]
        txt = Text()
        for i, name in enumerate(shown):
            txt.append(name, style="bold yellow" if name in interesting else "")
            if i < len(shown) - 1:
                txt.append(", ", style="dim")
        if limit and len(subs) > limit:
            txt.append(f"  … +{len(subs) - limit} more (use -v)", style="dim")
        console.print(Panel(txt, title=f"Subdomains from Certificate Transparency ({ct.get('count')} via {ct.get('source')})",
                            title_align="left", border_style="dim", subtitle="[yellow]yellow[/] = potentially sensitive",
                            subtitle_align="right"))


def _all_findings(report: dict, console: Console, verbose: int) -> None:
    findings = report.get("findings", [])
    _section(console, f"All findings ({len(findings)})")
    if not findings:
        console.print("  [green]Nothing to report.[/]")
        return
    t = Table(box=box.SIMPLE_HEAD, header_style="bold", expand=True)
    t.add_column("Severity", no_wrap=True, width=10)
    t.add_column("Category", style="dim", no_wrap=True)
    t.add_column("Finding", ratio=3, overflow="fold")
    t.add_column("Recommendation", ratio=2, overflow="fold", style="green")
    for f in findings:
        if not verbose and f["severity"] == "INFO" and len(findings) > 40:
            continue
        body = Text(f["title"], style="bold" if f["severity"] in ("CRITICAL", "HIGH") else "")
        if f.get("detail") and (verbose or f["severity"] in ("CRITICAL", "HIGH", "MEDIUM")):
            body.append("\n" + f["detail"], style="dim")
        if f.get("evidence") and verbose:
            body.append("\n↳ " + f["evidence"], style="italic dim")
        t.add_row(sev_badge(f["severity"]), f["category"], body, f.get("recommendation") or "")
    console.print(t)


# finding categories that are still assessed when a bot challenge hides the page
EDGE_CATEGORIES = {"Transport", "TLS", "DNS", "Domain", "Email security", "Attack surface", "Audit coverage"}


def render_diff(d: Diff, console: Console) -> None:
    _section(console, f"Changes since previous audit ({(d.previous_at or '')[:19]})")
    if d.grade_before:
        arrow = "→"
        delta = (d.score_after or 0) - (d.score_before or 0)
        col = "green" if delta > 0 else "red" if delta < 0 else "dim"
        console.print(f"  Grade [bold]{d.grade_before}[/] {arrow} [bold]{d.grade_after}[/]   "
                      f"score {d.score_before} {arrow} {d.score_after} [{col}]({delta:+.1f})[/]")
    if d.coverage_note:
        console.print(f"  [bold yellow]⚠ {d.coverage_note}[/]")
    if not any([d.new, d.resolved, d.severity_changed, d.tech_added, d.tech_removed, d.tech_changed, d.cves_new, d.cves_resolved]):
        console.print("  [dim]No changes.[/]")
        return
    for f in d.new:
        unseen = d.old_blocked and f.category not in EDGE_CATEGORIES
        label = Text("  + UNSEEN   ", style="bold yellow") if unseen else Text("  + NEW      ", style="bold red")
        console.print(label + sev_badge(f.severity.name) + Text(" " + f.title))
    for f in d.resolved:
        unchecked = d.new_blocked and f.category not in EDGE_CATEGORIES
        label = Text("  ? UNCHECKED", style="bold yellow") if unchecked else Text("  - FIXED    ", style="bold green")
        console.print(label + sev_badge(f.severity.name) + Text(" " + f.title))
    for o, n in d.severity_changed:
        console.print(Text("  ~ CHANGED  ", style="bold yellow") + Text(f"{o.title}: {o.severity.label} → {n.severity.label}"))
    for name, a, b in d.tech_changed:
        console.print(f"  [cyan]~ TECH[/]     {name}: {a or '?'} → {b or '?'}")
    if d.tech_added:
        console.print(f"  [cyan]+ TECH[/]     {', '.join(d.tech_added)}")
    if d.tech_removed:
        console.print(f"  [cyan]- TECH[/]     {', '.join(d.tech_removed)}")
    if d.cves_new:
        console.print(f"  [red]+ CVEs[/]     {len(d.cves_new)} new: {', '.join(d.cves_new[:10])}{' …' if len(d.cves_new) > 10 else ''}")
    if d.cves_resolved:
        console.print(f"  [green]- CVEs[/]     {len(d.cves_resolved)} no longer apply")


# ----------------------------------------------------------------------------- markdown export


def to_markdown(report: dict[str, Any]) -> str:
    t = report["target"]
    s = report["sections"]
    out = [f"# Security audit: {t['host']}", "",
           f"- **Grade:** {report['grade']} ({report['score']}/100)",
           f"- **URL:** {t.get('final_url')}",
           f"- **IPs:** {', '.join(t.get('ips') or [])}",
           f"- **Audited:** {report['started_at']} ({report['duration_s']}s, secaudit {report['tool_version']})",
           *([f"> **Incomplete audit:** {report['coverage']['blocked']['vendor']} served a "
               f"{report['coverage']['blocked']['kind']}; headers, cookies, content and tech stack were not checked.", ""]
             if (report.get("coverage") or {}).get("blocked") else []),
           "- **Findings:** " + ", ".join(f"{report['summary'].get(k.lower(), 0)} {k.lower()}" for k in SEV_ORDER), ""]
    out += ["## Findings", "", "| Severity | Category | Finding | Evidence | Recommendation |", "|---|---|---|---|---|"]
    esc = lambda x: (x or "").replace("|", "\\|").replace("\n", " ")  # noqa: E731
    for f in report["findings"]:
        out.append(f"| {f['severity']} | {f['category']} | {esc(f['title'])} | {esc(_trunc(f.get('evidence'), 120))} | {esc(f.get('recommendation'))} |")
    out += ["", "## Technology stack", "", "| Technology | Version | Category |", "|---|---|---|"]
    for x in report["technologies"]:
        out.append(f"| {x['name']} | {x.get('version') or '-'} | {x['category']} |")
    if report.get("cves"):
        out += ["", f"## Known vulnerabilities ({len(report['cves'])})", "",
                "| CVE | Product | CVSS | Severity | KEV | EPSS | Summary |", "|---|---|---|---|---|---|---|"]
        for c in report["cves"]:
            epss = f"{c['epss'] * 100:.1f}%" if c.get("epss") is not None else "-"
            out.append(f"| [{c['id']}]({c['url']}) | {c['product']} {c.get('product_version') or ''} | {c.get('score') or '-'} | "
                       f"{c.get('severity')} | {'YES' if c.get('kev') else ''} | {epss} | {esc(_trunc(c.get('summary'), 160))} |")
    hdr = (s.get("http") or {}).get("headers") or {}
    if hdr:
        out += ["", "## Security headers", ""]
        for key, label in SEC_HEADERS:
            out.append(f"- {'✅' if hdr.get(key) else '❌'} **{label}**: `{_trunc(hdr.get(key), 200) or 'missing'}`")
    tls = s.get("tls") or {}
    if tls.get("available"):
        cert = tls.get("certificate", {})
        out += ["", "## TLS", "", f"- Negotiated: {tls.get('negotiated_protocol')} / {tls.get('negotiated_cipher')}",
                f"- Certificate: {cert.get('subject_cn')} issued by {cert.get('issuer_org')}, expires {cert.get('not_after', '')[:10]} ({cert.get('days_left')} days)",
                "- Protocols: " + ", ".join(f"{k}={v}" for k, v in (tls.get("protocols") or {}).items())]
    reg = (s.get("domain") or {}).get("registration") or {}
    if reg:
        out += ["", "## Domain", "", f"- Registrar: {reg.get('registrar')}", f"- Created: {reg.get('created')}",
                f"- Expires: {reg.get('expires')}", f"- Status: {', '.join(reg.get('status') or [])}",
                f"- Nameservers: {', '.join(reg.get('nameservers') or [])}"]
    ct = (s.get("domain") or {}).get("ct")
    if ct and ct.get("subdomains"):
        out += ["", f"## Subdomains from CT logs ({ct['count']})", "", ", ".join(ct["subdomains"][:500])]
    if report.get("ai_analysis"):
        out += ["", f"## AI analysis ({report['ai_analysis'].get('model')})", "", report["ai_analysis"]["text"]]
    return "\n".join(out) + "\n"
