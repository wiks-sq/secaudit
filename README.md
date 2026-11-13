# secaudit

A passive, **non-intrusive** security audit CLI for websites and their domains.
It collects everything a careful visitor (or attacker doing reconnaissance) can
see, grades it, highlights key findings, lists every known CVE for the detected
tech stack, keeps a per-domain history, and can ask a local **Ollama** model for
an analyst-style write-up.

It never fuzzes, brute-forces, injects payloads or attempts exploitation.

## Install

```bash
git clone https://github.com/wiks-sq/secaudit.git
cd secaudit
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/secaudit --help
```

Requires Python ≥ 3.10. Dependencies: `click`, `rich`, `httpx`, `dnspython`, `cryptography`.

## Running the commands

The install creates two launchers inside the virtual environment: `.venv/bin/secaudit` and
`.venv/bin/secdomains` (a shorthand for `secaudit domains`). They are not on your `PATH` yet, so pick one of
these. The examples in the rest of this README use the plain names and assume option 2 or 3.

1. **Call them by path**, from the project folder:

   ```bash
   .venv/bin/secaudit example.com
   .venv/bin/secdomains example.com
   ```

2. **Activate the virtual environment**, which makes the plain names work in that terminal until you close it
   or run `deactivate`:

   ```bash
   source .venv/bin/activate
   secaudit example.com
   ```

3. **Symlink them into a folder on your `PATH`** (once, from the project folder), so they work from anywhere
   without activating anything:

   ```bash
   mkdir -p ~/.local/bin
   ln -s "$PWD/.venv/bin/secaudit" ~/.local/bin/secaudit
   ln -s "$PWD/.venv/bin/secdomains" ~/.local/bin/secdomains
   ```

   If `secaudit` is still not found afterwards, `~/.local/bin` is not on your `PATH`: add
   `export PATH="$HOME/.local/bin:$PATH"` to your shell profile.

`python -m secaudit …` also works with the virtual environment's Python, e.g.
`.venv/bin/python -m secaudit domains example.com`.

## Usage

```bash
secaudit example.com                      # shorthand for: secaudit audit example.com
secaudit audit https://example.com -v     # full values, full CVE descriptions, raw headers
secaudit audit example.com -vv            # also show collector / CVE lookup log
secaudit audit example.com -q             # header, key findings, findings table only
secaudit audit example.com --ollama       # + AI summary (auto-picks a model)
secaudit audit example.com -m qwen3:8b    # + AI summary with a specific model
secaudit audit example.com --markdown report.md
secaudit audit example.com --json > report.json
secaudit audit example.com --fail-on high # exit code 2 if any HIGH+ finding (CI use)

secaudit history                          # all audited domains, last grade
secaudit history example.com              # every audit of the domain, with score trend
secaudit history example.com --show -1    # re-render a stored audit (1 = oldest, -1 = newest)
secaudit diff example.com                 # previous vs latest: new / fixed findings, tech & CVE changes
secaudit analyze example.com              # run Ollama on a stored audit and save it into the history file
secaudit domains example.com              # every hostname & related domain, and which ones resolve
secdomains example.com                    # the same, as a standalone command
secaudit models                           # list Ollama models
secaudit config                           # effective config & paths
```

Useful audit flags: `--exposure-checks`, `--no-ct`, `--no-cve`, `--no-assets`,
`--insecure`, `--timeout N`, `--no-history`, `--ollama-url URL`.

## Domain discovery

`secaudit domains example.com`, or the shorthand `secdomains example.com`, lists every hostname it can find
under a domain, checks each one in DNS and splits the result into **Resolving** and **Not resolving**.

- **Where names come from:** Certificate Transparency (crt.sh, certspotter), hackertarget, urlscan.io, the Wayback
  Machine index, the domain's own NS/MX/SPF records, and the certificates that live hosts present. Source results
  are cached for 6 h (`--refresh` to ignore the cache). `--bruteforce` adds ~150 common names (DNS queries only).
- **Per resolving host:** IP addresses, network owner (origin AS), HTTP status, page title, redirect target and CNAME.
  Hosts on private addresses and hosts that only match a wildcard DNS record are marked.
- **Per non-resolving host:** the reason (NXDOMAIN, no A/AAAA record, SERVFAIL, timeout) and any dangling CNAME,
  flagged as a takeover risk when it points at a known claimable service.
- **Related domains:** other registrable domains seen as name server, mail server, SPF include, CNAME target,
  redirect target or on the same certificate, each with a resolve check.
- **Clickable everywhere:** every host is printed as a full `https://…` URL and wrapped in a terminal hyperlink
  (OSC 8), so Ctrl+click (or click, depending on the terminal) opens any of them, not only `www.` names. IP
  addresses link to their ipinfo.io page. Use `--links` to force hyperlinks when piping (e.g. into `less -R`).

Options: `--only resolved|unresolved`, `--no-probe` (DNS only, no TLS/HTTP requests to found hosts),
`--bruteforce`, `--resolver 1.1.1.1`, `--refresh`, `--workers N`, `--json`, `-v` (where each name was found).

## What it checks

| Area | Details |
|---|---|
| **Transport** | HTTPS availability, HTTP→HTTPS redirect (status, extra plain-HTTP hops), redirect chain |
| **Security headers** | HSTS (max-age, includeSubDomains, preload-list status), CSP analysis (`unsafe-inline`/`unsafe-eval`, wildcards, missing `object-src`/`base-uri`), clickjacking (XFO / `frame-ancestors`), nosniff, Referrer-Policy, Permissions-Policy, COOP/CORP/COEP, legacy X-XSS-Protection |
| **Cookies** | Secure, HttpOnly (session-like names), SameSite, `__Host-`/`__Secure-` prefixes, F5 BIG-IP cookie internal-IP decoding |
| **CORS / methods** | Origin reflection (+credentials), `null` origin, wildcard; `OPTIONS` allowed methods (TRACE, PUT, WebDAV) |
| **Error handling** | One request to a random 404 path: soft-404s, debug pages (Django, Laravel, Rails, Werkzeug), stack traces, version banners |
| **TLS** | Negotiated protocol/cipher, ALPN/HTTP2, chain trust, hostname match, expiry, key type/size, signature hash, SCTs, wildcard; TLS 1.0–1.3 support; NULL/EXPORT/RC4/3DES/static-RSA/CBC-SHA1 acceptance (one handshake per class) |
| **Domain** | RDAP (WHOIS fallback): registrar, created/expiry with warnings, transfer lock, nameservers, DNSSEC delegation |
| **DNS** | A/AAAA/CNAME/NS/MX/SOA/CAA/TXT, dangling CNAME (takeover risk), single NS, DNSSEC (DNSKEY+DS), CAA |
| **Email security** | SPF (qualifier, multiple records, recursive 10-lookup limit), DMARC (policy, pct, rua), DKIM common selectors, MTA-STS, TLS-RPT, BIMI |
| **Hosting** | Reverse DNS + IP RDAP (network owner, country) |
| **Attack surface** | Subdomains from Certificate Transparency (certspotter, crt.sh fallback) with sensitive names (dev/staging/admin/vpn…) highlighted |
| **Content** | Mixed content, forms posting to HTTP, password over HTTP/GET, missing CSRF token (info), SRI on third-party assets, third-party origins, notable HTML comments, published emails, leaked API keys (AWS/Google/Stripe/GitHub/Slack/private keys) |
| **Well-known files** | robots.txt (sensitive Disallow entries), security.txt (RFC 9116, expiry), sitemap.xml |
| **Tech stack** | Server/X-Powered-By tokens, 40+ header signatures, cookies, meta generator, HTML markers, WordPress core + plugins, JS libraries by URL and by version banner in fetched scripts, 404-page banners |
| **CVEs** | Every detected *versioned* component: NVD CVE API (CPE match) for servers/CMS/languages, OSV.dev for npm/PyPI packages; enriched with **CISA KEV** (actively exploited) and **FIRST EPSS** (exploit probability). All CVEs are listed, KEV first, then by CVSS |

`--exposure-checks` (off by default) additionally performs plain GETs for ~17
well-known paths (`/.git/HEAD`, `/.env`, `/server-status`, `/phpinfo.php`,
`/actuator`, `/wp-json/wp/v2/users`, …). Each hit is confirmed by a content
signature to avoid soft-404 false positives. Only enable it for sites you are
authorised to test.

## Grading

Each finding has a severity (Critical / High / Medium / Low / Info) and a stable
id. The score starts at 100 and subtracts 25 / 10 / 4 / 1 / 0 per finding, with
diminishing weight for repeated findings in the same category. Grades:
A+ (≥95, nothing above Low) · A ≥85 · B ≥70 · C ≥55 · D ≥40 · F. Any Critical caps the
grade at C. Unreachable sites get `N/A`.

## History

Every audit writes `~/.local/share/secaudit/history/<host>/<timestamp>.json`
(override with `history_dir` or `$SECAUDIT_HISTORY_DIR`). The next audit of the
same host automatically prints what changed: new and fixed findings, severity
changes, technology/version changes, and new or resolved CVEs.

## Ollama

`--ollama` (or `-m MODEL`) sends a condensed version of the report (findings,
tech stack, top 40 CVEs, TLS/domain/email summary) to your local Ollama
(`$OLLAMA_HOST` or `http://localhost:11434`) and streams back an executive
summary, prioritised fixes, CVE overview and quick wins. Thinking blocks from
reasoning models are stripped. The text is stored in the history file and in
Markdown exports. Nothing leaves your machine for this step.

## Notes & limitations

- **Bot protection:** if Cloudflare, AWS WAF, Akamai, Imperva, Sucuri, DataDome or HUMAN answers with a challenge or
  block page instead of the site, the audit says so in a warning panel, skips header/cookie/content/tech checks
  (they would describe the challenge page), and gives grade `N/A`. TLS, DNS, email and domain results still apply.
  History diffs mark the affected findings as `UNCHECKED`/`UNSEEN` instead of fixed/new.
- Behind a CDN such as Cloudflare, the `Server` header and TLS settings belong to the CDN, so origin server
  software (nginx/Apache/OpenSSL) and its CVEs are usually not visible. Application-level detection still works.
- CVEs can only be matched when a version is visible. Hidden versions are listed as "version unknown".
- NVD matching uses upstream versions. Distros (Ubuntu/Debian/RHEL) backport fixes without bumping the
  version, so a banner like `Apache/2.4.41 (Ubuntu)` may be patched. Verify with your OS vendor.
- Without an NVD API key, NVD allows 5 requests per 30 s. Lookups are rate-limited and cached for 24 h.
  A free key (`NVD_API_KEY`) makes them much faster.
- Weak-cipher and legacy-protocol tests depend on what the local OpenSSL build can still negotiate.
  Anything it can't test is shown as "not testable locally" instead of a false "disabled".
- Third-party services used: NVD, OSV.dev, CISA KEV feed, FIRST EPSS, rdap.org, hstspreload.org,
  certspotter / crt.sh. Use `--no-cve` / `--no-ct` to skip them.
