"""Command-line interface."""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

import click
from rich.console import Console
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich import box

from secaudit import __version__
from secaudit.audit import run_audit
from secaudit.config import CONFIG_PATH, Config
from secaudit.context import AuditContext, Options, Target
from secaudit.history import History, diff_reports
from secaudit.llm import SYSTEM_PROMPT, Ollama, OllamaError, build_prompt, strip_thinking
from secaudit.models import Severity
from secaudit.report import render, render_diff, to_markdown

console = Console()
err_console = Console(stderr=True)

STEP_LABELS = {
    "resolve": "Resolving host",
    "http": "HTTP, redirects, headers & cookies",
    "tls": "TLS handshake, certificate & protocols",
    "dns": "DNS records & email security",
    "domain": "Registration (RDAP/WHOIS), IP owner & CT logs",
    "content": "Page content, robots.txt, security.txt",
    "tech": "Technology fingerprinting",
    "cve": "CVE lookup (NVD / OSV / KEV / EPSS)",
}


class DefaultGroup(click.Group):
    """Lets `secaudit example.com` work as shorthand for `secaudit audit example.com`."""

    def parse_args(self, ctx, args):
        if args and args[0] not in self.commands and not args[0].startswith("-"):
            args = ["audit", *args]
        return super().parse_args(ctx, args)


@click.group(cls=DefaultGroup, context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="secaudit")
def main() -> None:
    """secaudit - passive, non-intrusive website & domain security auditor.

    \b
    Examples:
      secaudit example.com
      secaudit audit https://example.com -v --ollama
      secaudit history example.com
      secaudit diff example.com
      secaudit domains example.com
    """


# ----------------------------------------------------------------------------- audit


@main.command()
@click.argument("target")
@click.option("-v", "--verbose", count=True, help="More detail (-v: full values, all CVE text, raw headers; -vv: also collector log).")
@click.option("-q", "--quiet", is_flag=True, help="Only show the header, key findings and all-findings table.")
@click.option("--ollama", "use_ollama", is_flag=True, help="Ask a local Ollama model for an analyst summary.")
@click.option("--model", "-m", help="Ollama model to use (implies --ollama).")
@click.option("--ollama-url", help="Ollama base URL (default: $OLLAMA_HOST or http://localhost:11434).")
@click.option("--exposure-checks", is_flag=True,
              help="Also GET a short list of well-known sensitive paths (/.git/HEAD, /.env, server-status...). Read-only, signature-verified.")
@click.option("--no-ct", is_flag=True, help="Skip Certificate Transparency subdomain lookup.")
@click.option("--no-cve", is_flag=True, help="Skip CVE lookup.")
@click.option("--no-assets", is_flag=True, help="Don't download referenced JS files to read library version banners.")
@click.option("--insecure", is_flag=True, help="Don't verify TLS certificates for HTTP requests (TLS is still analysed).")
@click.option("--timeout", type=float, help="Per-request timeout in seconds (default 15).")
@click.option("--json", "as_json", is_flag=True, help="Print the full JSON report to stdout instead of the rich report.")
@click.option("--markdown", "md_path", type=click.Path(dir_okay=False, path_type=Path), help="Also write a Markdown report to this file.")
@click.option("--no-history", is_flag=True, help="Don't write a history file for this audit.")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
              help="Exit with code 2 if any finding is at or above this severity (for CI).")
def audit(target, verbose, quiet, use_ollama, model, ollama_url, exposure_checks, no_ct, no_cve, no_assets, insecure,
          timeout, as_json, md_path, no_history, fail_on):
    """Audit TARGET (a hostname or URL)."""
    cfg = Config.load()
    if timeout:
        cfg.timeout = timeout
    if ollama_url:
        cfg.ollama_url = ollama_url
    try:
        tgt = Target.parse(target)
    except ValueError as e:
        raise click.BadParameter(str(e), param_hint="TARGET")
    opts = Options(verbose=verbose, exposure_checks=exposure_checks, ct_logs=not no_ct, cve_lookup=not no_cve,
                   fetch_assets=not no_assets, verify_tls=not insecure)
    ctx = AuditContext(target=tgt, config=cfg, options=opts)
    out = err_console if as_json else console

    # pre-flight Ollama check so we fail fast, before the audit runs
    llm = None
    llm_model = None
    if use_ollama or model:
        llm = Ollama(cfg.ollama_url)
        try:
            llm_model = llm.pick_model(model or cfg.ollama_model)
        except OllamaError as e:
            out.print(f"[bold red]Ollama:[/] {e}")
            sys.exit(1)

    out.print(f"[bold blue]secaudit[/] {__version__} · auditing [bold cyan]{tgt.host}[/]"
              + (f" · AI: [magenta]{llm_model}[/]" if llm_model else ""))
    report = _run_with_progress(ctx, out, verbose)

    history = History(cfg.history_dir)
    domain = tgt.host
    previous = history.previous(domain)

    if llm and llm_model:
        text = _stream_ollama(llm, llm_model, report, out, live=not as_json)
        if text:
            report["ai_analysis"] = {"model": llm_model, "text": text}

    hist_path = None
    if not no_history:
        hist_path = history.save(domain, report)
    diff = diff_reports(previous, report) if previous else None

    if as_json:
        click.echo(json.dumps(report, indent=2, default=str))
    elif quiet:
        from secaudit.report import _all_findings, _header, _key_findings  # noqa: PLC0415
        _header(report, console)
        _key_findings(report, console)
        _all_findings(report, console, verbose)
        if diff:
            render_diff(diff, console)
        if hist_path:
            console.print(f"\n[dim]History saved →[/] [bold]{hist_path}[/]")
    else:
        # AI text was already streamed live; don't print it twice
        ai = report.pop("ai_analysis", None)
        render(report, console, verbose=verbose, diff=diff, history_path=str(hist_path) if hist_path else None)
        if ai:
            report["ai_analysis"] = ai

    if md_path:
        md_path.write_text(to_markdown(report))
        out.print(f"[dim]Markdown report →[/] [bold]{md_path}[/]")

    if fail_on:
        threshold = Severity.parse(fail_on)
        if any(Severity.parse(f["severity"]) >= threshold for f in report["findings"]):
            sys.exit(2)


def _run_with_progress(ctx: AuditContext, out: Console, verbose: int) -> dict:
    lock = threading.Lock()
    running: dict[str, None] = {}
    status = out.status("Starting…", spinner="dots")

    def progress(step: str, state: str) -> None:
        with lock:
            label = STEP_LABELS.get(step, step)
            if state == "start":
                running[step] = None
            elif state in ("done", "error"):
                running.pop(step, None)
                mark = "[green]✔[/]" if state == "done" else "[yellow]![/]"
                out.print(f"  {mark} {label}")
            elif state == "info" and verbose >= 2:
                out.print(f"    [dim]{step}[/]")
            elif state == "info":
                status.update(f"[bold]CVE lookup:[/] {step}")
                return
            if running:
                status.update("[bold]" + " · ".join(STEP_LABELS.get(s, s) for s in running) + "[/]")

    with status:
        report = run_audit(ctx, progress)
    out.print(f"  [dim]done in {report['duration_s']}s[/]")
    return report


def _stream_ollama(llm: Ollama, model: str, report: dict, out: Console, live: bool = True) -> str | None:
    prompt = build_prompt(report)
    buf = ""
    try:
        if live:
            out.print()
            with Live(Panel("[dim]thinking…[/]", title=f"AI analysis · {model}", border_style="magenta"),
                      console=out, refresh_per_second=8, vertical_overflow="visible") as lv:
                for chunk in llm.stream_chat(model, SYSTEM_PROMPT, prompt):
                    buf += chunk
                    shown = strip_thinking(buf)
                    lv.update(Panel(Markdown(shown) if shown else "[dim]thinking…[/]",
                                    title=f"AI analysis · {model}", border_style="magenta"))
        else:
            with out.status(f"Asking {model}…"):
                for chunk in llm.stream_chat(model, SYSTEM_PROMPT, prompt):
                    buf += chunk
    except OllamaError as e:
        out.print(f"[bold red]Ollama failed:[/] {e}")
        return None
    except KeyboardInterrupt:
        out.print("[yellow]AI analysis interrupted.[/]")
    return strip_thinking(buf) or None


# ----------------------------------------------------------------------------- history


@main.command("history")
@click.argument("domain", required=False)
@click.option("--show", "show_ref", help="Re-render a stored audit: 'latest', 'previous', an index (1 = oldest, -1 = newest) or filename prefix.")
@click.option("-v", "--verbose", count=True)
@click.option("--json", "as_json", is_flag=True, help="Print the stored JSON (with --show).")
def history_cmd(domain, show_ref, verbose, as_json):
    """List audited domains, or the audit history of DOMAIN."""
    cfg = Config.load()
    h = History(cfg.history_dir)
    if not domain:
        domains = h.domains()
        if not domains:
            console.print(f"[dim]No history yet in {cfg.history_dir}[/]")
            return
        t = Table(box=box.SIMPLE_HEAD, header_style="bold", title=f"Audited domains  [dim]({cfg.history_dir})[/]", title_justify="left")
        t.add_column("Domain", style="bold cyan", no_wrap=True)
        t.add_column("Audits", justify="right")
        t.add_column("Last audit (UTC)", no_wrap=True)
        t.add_column("Grade", justify="center")
        t.add_column("Findings (C/H/M/L)")
        for d in domains:
            files = h.list(d)
            last = h.load(files[-1])
            s = last.get("summary", {})
            t.add_row(d, str(len(files)), last["started_at"][:16].replace("T", " "), last.get("grade", "?"),
                      f"{s.get('critical', 0)}/{s.get('high', 0)}/{s.get('medium', 0)}/{s.get('low', 0)}")
        console.print(t)
        return

    domain = Target.parse(domain).host
    if show_ref:
        path = h.resolve(domain, show_ref)
        if not path:
            raise click.ClickException(f"no audit {show_ref!r} for {domain}")
        rep = h.load(path)
        if as_json:
            click.echo(json.dumps(rep, indent=2))
        else:
            render(rep, console, verbose=verbose, history_path=str(path))
        return

    files = h.list(domain)
    if not files:
        raise click.ClickException(f"no history for {domain} in {cfg.history_dir}")
    t = Table(box=box.SIMPLE_HEAD, header_style="bold", title=f"History for {domain}", title_justify="left")
    t.add_column("#", justify="right", style="dim")
    t.add_column("Date (UTC)", no_wrap=True)
    t.add_column("Grade", justify="center")
    t.add_column("Score", justify="right")
    t.add_column("Crit", justify="right", style="bold red")
    t.add_column("High", justify="right", style="red")
    t.add_column("Med", justify="right", style="yellow")
    t.add_column("Low", justify="right", style="green")
    t.add_column("CVEs", justify="right")
    t.add_column("File", style="dim", overflow="fold")
    prev_score = None
    for i, f in enumerate(files, 1):
        r = h.load(f)
        s = r.get("summary", {})
        score = r.get("score")
        trend = ""
        if prev_score is not None and score is not None:
            trend = " [green]▲[/]" if score > prev_score else " [red]▼[/]" if score < prev_score else ""
        prev_score = score
        t.add_row(str(i), r["started_at"][:16].replace("T", " "), r.get("grade", "?"), f"{score}{trend}", str(s.get("critical", 0)),
                  str(s.get("high", 0)), str(s.get("medium", 0)), str(s.get("low", 0)), str(len(r.get("cves", []))), f.name)
    console.print(t)
    console.print("[dim]Show one with:[/] secaudit history " + domain + " --show -1    [dim]Compare:[/] secaudit diff " + domain)


@main.command("diff")
@click.argument("domain")
@click.argument("old", required=False, default="previous")
@click.argument("new", required=False, default="latest")
def diff_cmd(domain, old, new):
    """Compare two stored audits of DOMAIN (default: previous vs latest)."""
    cfg = Config.load()
    h = History(cfg.history_dir)
    domain = Target.parse(domain).host
    po, pn = h.resolve(domain, old), h.resolve(domain, new)
    if not po or not pn:
        raise click.ClickException("need at least two stored audits (see: secaudit history " + domain + ")")
    render_diff(diff_reports(h.load(po), h.load(pn)), console)


@main.command("analyze")
@click.argument("domain")
@click.argument("ref", required=False, default="latest")
@click.option("--model", "-m", help="Ollama model.")
@click.option("--ollama-url", help="Ollama base URL.")
@click.option("--save/--no-save", default=True, help="Store the AI analysis back into the history file.")
def analyze_cmd(domain, ref, model, ollama_url, save):
    """Run (or re-run) Ollama analysis on a stored audit."""
    cfg = Config.load()
    if ollama_url:
        cfg.ollama_url = ollama_url
    h = History(cfg.history_dir)
    domain = Target.parse(domain).host
    path = h.resolve(domain, ref)
    if not path:
        raise click.ClickException(f"no audit {ref!r} for {domain}")
    rep = h.load(path)
    llm = Ollama(cfg.ollama_url)
    try:
        name = llm.pick_model(model or cfg.ollama_model)
    except OllamaError as e:
        raise click.ClickException(str(e))
    console.print(f"Analysing [bold]{path.name}[/] with [magenta]{name}[/]")
    text = _stream_ollama(llm, name, rep, console)
    if text and save:
        rep["ai_analysis"] = {"model": name, "text": text}
        path.write_text(json.dumps(rep, indent=2, default=str))
        console.print(f"[dim]Saved into {path}[/]")


@main.command("models")
@click.option("--ollama-url", help="Ollama base URL.")
def models_cmd(ollama_url):
    """List models available in Ollama."""
    cfg = Config.load()
    llm = Ollama(ollama_url or cfg.ollama_url)
    try:
        models = llm.models()
    except OllamaError as e:
        raise click.ClickException(str(e))
    t = Table(box=box.SIMPLE_HEAD, header_style="bold", title=f"Ollama models at {llm.base}", title_justify="left")
    t.add_column("Model", style="bold")
    t.add_column("Size", justify="right")
    t.add_column("Params")
    t.add_column("Quant")
    default = None
    try:
        default = llm.pick_model(cfg.ollama_model)
    except OllamaError:
        pass
    for m in models:
        d = m.get("details", {})
        t.add_row(m["name"] + ("  [green](default)[/]" if m["name"] == default else ""), f"{m.get('size', 0) / 1e9:.1f} GB",
                  d.get("parameter_size", ""), d.get("quantization_level", ""))
    console.print(t)
    console.print(f"[dim]Set a default with ollama_model = \"...\" in {CONFIG_PATH} or $SECAUDIT_OLLAMA_MODEL[/]")


@main.command("domains", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("domain")
@click.option("--only", type=click.Choice(["all", "resolved", "unresolved"]), default="all",
              help="Show only the names that resolve, or only those that do not.")
@click.option("--no-probe", is_flag=True, help="DNS only: don't read TLS certificates or request the front page of found hosts.")
@click.option("--bruteforce", is_flag=True, help="Also try ~150 common subdomain names (DNS queries only).")
@click.option("--resolver", "resolvers", multiple=True, help="DNS server to use instead of the system one (repeatable), e.g. 1.1.1.1.")
@click.option("--refresh", is_flag=True, help="Ignore cached source results (cached for 6 h).")
@click.option("--workers", type=click.IntRange(1, 200), default=30, show_default=True, help="Parallel lookups.")
@click.option("--timeout", type=float, help="Per-request timeout in seconds (default 15).")
@click.option("-v", "--verbose", count=True, help="Show where each name was found, TXT records and all relations.")
@click.option("--json", "as_json", is_flag=True, help="Print the result as JSON to stdout.")
@click.option("--links/--no-links", default=None, help="Force clickable terminal hyperlinks on or off (default: on in a terminal).")
@click.option("--no-files", is_flag=True, help="Don't write <domain>_resolved.txt and <domain>_unresolved.txt to the current directory.")
def domains_cmd(domain, only, no_probe, bruteforce, resolvers, refresh, workers, timeout, verbose, as_json, links,
                no_files):
    """Find every hostname and related domain for DOMAIN and check which ones resolve."""
    from secaudit import domains as dm

    cfg = Config.load()
    if timeout:
        cfg.timeout = timeout
    try:
        name = dm.normalise_domain(domain)
    except ValueError as e:
        raise click.BadParameter(str(e), param_hint="DOMAIN")
    with err_console.status(f"[bold]{name}[/]", spinner="dots") as status:
        rep = dm.discover(name, cfg, probe=not no_probe, bruteforce=bruteforce, refresh=refresh,
                          nameservers=list(resolvers) or None, workers=workers,
                          progress=lambda msg: status.update(f"[bold]{name}[/] · {msg}"))
    saved = [] if no_files else _save_domain_lists(rep)
    if as_json:
        click.echo(json.dumps(rep, indent=2))
    else:
        dm.render(rep, console if links is None else Console(force_terminal=links), only=only, verbose=verbose)
    for path, count in saved:
        err_console.print(f"[dim]Saved {count} names to[/] ./{path.name}", highlight=False)


def _save_domain_lists(rep: dict) -> list[tuple[Path, int]]:
    """Write <domain>_resolved.txt and <domain>_unresolved.txt (one hostname per line) to the current directory."""
    saved = []
    for suffix, want in (("resolved", True), ("unresolved", False)):
        names = [h["name"] for h in rep["hosts"] if h["resolves"] is want]
        path = Path.cwd() / f"{rep['domain']}_{suffix}.txt"
        try:
            path.write_text("".join(n + "\n" for n in names))
            saved.append((path, len(names)))
        except OSError as e:
            err_console.print(f"[bold red]Could not write {path}:[/] {e}")
    return saved




@main.command("config")
def config_cmd():
    """Show effective configuration and file locations."""
    cfg = Config.load()
    t = Table(box=box.SIMPLE, show_header=False)
    t.add_column(style="bold cyan")
    t.add_column()
    t.add_row("config file", f"{CONFIG_PATH} {'(exists)' if CONFIG_PATH.exists() else '(not created)'}")
    t.add_row("history_dir", str(cfg.history_dir))
    t.add_row("cache_dir", str(cfg.cache_dir))
    t.add_row("timeout", str(cfg.timeout))
    t.add_row("ollama_url", cfg.ollama_url)
    t.add_row("ollama_model", cfg.ollama_model or "(auto)")
    t.add_row("nvd_api_key", "set" if cfg.nvd_api_key else "not set (slower CVE lookups: 5 req / 30 s)")
    console.print(t)


if __name__ == "__main__":
    main()
