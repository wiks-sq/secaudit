# secaudit cheatsheet

The plain command names below work once the virtual environment is activated or the launchers are symlinked
into your `PATH`; see "Running the commands" in [README.md](README.md). Otherwise prefix them with `.venv/bin/`.
Add `-h` to any command for its full help.

## Domain discovery: `secdomains`

`secdomains <domain>` is the same as `secaudit domains <domain>`.

| Command | What it does |
|---|---|
| `secdomains example.com` | Find all hostnames and related domains, check which resolve |
| `secdomains example.com --only resolved` | Show only the names that resolve |
| `secdomains example.com --only unresolved` | Show only the names that do not resolve |
| `secdomains example.com --no-probe` | DNS only: no TLS or HTTP requests to the found hosts (faster) |
| `secdomains example.com --bruteforce` | Also try ~150 common subdomain names |
| `secdomains example.com --refresh` | Ignore the 6-hour cache and query the sources again |
| `secdomains example.com --resolver 1.1.1.1` | Use a specific DNS server (repeatable) |
| `secdomains example.com -v` | Also show where each name was found, TXT records, all relations |
| `secdomains example.com --workers 60` | More parallel lookups (default 30) |
| `secdomains example.com --timeout 8` | Per-request timeout in seconds (default 15) |
| `secdomains example.com --json` | Print the result as JSON |
| `secdomains example.com --links` | Force clickable links when piping |
| `secdomains example.com --no-links` | Turn clickable links off |

### Recipes

```bash
# Page through a long result, keeping colours and clickable links
secdomains example.com --links | less -R
```

```bash
# Save the full result
secdomains example.com --json > example.com.domains.json
```

```bash
# Plain list of hosts that resolve
secdomains example.com --json | jq -r '.hosts[] | select(.resolves) | .name'
```

```bash
# Plain list of hosts that do not resolve, with the reason
secdomains example.com --json | jq -r '.hosts[] | select(.resolves | not) | "\(.name)\t\(.status)"'
```

```bash
# Dangling CNAMEs flagged as takeover risk
secdomains example.com --json | jq -r '.hosts[] | select(.takeover_risk) | "\(.name) -> \(.cname)"'
```

```bash
# Hosts that answer on the web, with status code and title
secdomains example.com --json | jq -r '.hosts[] | select(.http.status) | "\(.http.status)\t\(.name)\t\(.http.title)"'
```

```bash
# Related domains only
secdomains example.com --json | jq -r '.related_domains[] | "\(.domain)\t\(.resolves)"'
```

### Reading the output

| Marker | Meaning |
|---|---|
| Yellow URL | Sensitive-looking name (dev, staging, admin, vpn, auth, ...) |
| `wildcard` | Host only matches a wildcard DNS record, so it may not be a real host |
| `private address` | Resolves to an internal IP (10.x, 192.168.x, ...) |
| `no web` | Resolves, but nothing answered on HTTPS or HTTP |
| `→ https://...` | The front page redirects to another host |
| `→ name` (dim) | CNAME target |
| `does not exist (NXDOMAIN)` | No such name in DNS |
| `name exists, no A/AAAA record` | The name is in DNS but has no address |
| `dangling CNAME` | Points at a target that no longer resolves; red means takeover risk |
| `DNS timeout (unknown)` | Could not be checked; rerun or try `--resolver` |

Links: Ctrl+click (or plain click, depending on the terminal) opens any URL. IP addresses link to ipinfo.io.

## Security audit: `secaudit`

| Command | What it does |
|---|---|
| `secaudit example.com` | Audit a site (shorthand for `secaudit audit example.com`) |
| `secaudit audit https://example.com -v` | Full values, full CVE descriptions, raw headers |
| `secaudit audit example.com -vv` | Also show the collector and CVE lookup log |
| `secaudit audit example.com -q` | Only header, key findings and findings table |
| `secaudit audit example.com --exposure-checks` | Also check ~17 commonly exposed paths (authorised targets only) |
| `secaudit audit example.com --no-ct` | Skip the certificate-log subdomain lookup |
| `secaudit audit example.com --no-cve` | Skip the CVE lookup |
| `secaudit audit example.com --no-assets` | Don't download JS files to read library versions |
| `secaudit audit example.com --insecure` | Don't verify TLS certificates on HTTP requests |
| `secaudit audit example.com --timeout 30` | Per-request timeout in seconds (default 15) |
| `secaudit audit example.com --no-history` | Don't save this audit |
| `secaudit audit example.com --json > report.json` | Full report as JSON |
| `secaudit audit example.com --markdown report.md` | Also write a Markdown report |
| `secaudit audit example.com --fail-on high` | Exit code 2 if any finding is High or worse (CI) |

### AI summary (local Ollama)

| Command | What it does |
|---|---|
| `secaudit audit example.com --ollama` | Add an AI summary, model picked automatically |
| `secaudit audit example.com -m qwen3:8b` | Add an AI summary with a specific model |
| `secaudit audit example.com --ollama-url http://host:11434` | Use another Ollama server |
| `secaudit analyze example.com` | Run the AI on the latest saved audit and store the result |
| `secaudit analyze example.com previous --no-save` | Analyse the previous audit without storing |
| `secaudit models` | List installed Ollama models |

### History

| Command | What it does |
|---|---|
| `secaudit history` | All audited domains with their last grade |
| `secaudit history example.com` | Every audit of a domain, with score trend |
| `secaudit history example.com --show -1` | Re-render a saved audit (1 = oldest, -1 = newest) |
| `secaudit history example.com --show latest --json` | Print a saved audit as JSON |
| `secaudit diff example.com` | Previous vs latest: new and fixed findings, tech and CVE changes |
| `secaudit diff example.com 1 latest` | Compare two specific audits (here: oldest vs latest) |

### Misc

| Command | What it does |
|---|---|
| `secaudit config` | Show active settings and file locations |
| `secaudit --version` | Show the version |

## Typical workflow

```bash
secdomains example.com
```

```bash
secaudit example.com
```

```bash
secaudit diff example.com
```

## Files and settings

| Path | Purpose |
|---|---|
| `~/.config/secaudit/config.toml` | Settings (see `config.example.toml`) |
| `~/.local/share/secaudit/history/` | Saved audits, one JSON file per run |
| `~/.cache/secaudit/` | Cached lookups (CVE data 24 h, domain sources 6 h) |

| Environment variable | Purpose |
|---|---|
| `NVD_API_KEY` | Faster CVE lookups |
| `OLLAMA_HOST` | Ollama server address |
| `SECAUDIT_OLLAMA_MODEL` | Default AI model |
| `SECAUDIT_HISTORY_DIR` | Where audits are saved |
