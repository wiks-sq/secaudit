Run these from the project folder as .venv/bin/secaudit …, or as plain secaudit once you’ve run source .venv/bin/activate.

Commands
Command	What it does
secaudit <target>	Shorthand for secaudit audit <target>
secaudit audit <target>	Runs an audit. The target can be a hostname or a URL.
secaudit history	Lists every domain you’ve audited, with its last date and grade
secaudit history <domain>	Lists every audit of that domain, with a score trend
secaudit diff <domain> [old] [new]	Compares two saved audits (by default the previous one against the latest)
secaudit analyze <domain> [ref]	Runs an Ollama analysis on a saved audit and stores the result in its history file
secaudit models	Lists your installed Ollama models and shows which one is the default
secaudit config	Shows the active settings and file locations
secaudit --version	Shows the version
secaudit -h / <command> -h	Shows help
audit options
Option	Effect
-v	Verbose: full values, full CVE descriptions, every response header, all subdomains
-vv	Also shows each step’s log, including every CVE lookup
-q, --quiet	Shows only the header, key findings and findings table
--ollama	Adds an AI summary, picking a model automatically
-m, --model <name>	Adds an AI summary using that model (turns on --ollama)
--ollama-url <url>	Uses a different Ollama server
--exposure-checks	Also checks for ~17 commonly exposed paths (/.git/HEAD, /.env, /server-status, …). Use only on sites you’re allowed to test.
--no-ct	Skips the subdomain lookup in public certificate logs
--no-cve	Skips the CVE lookup
--no-assets	Doesn’t download the site’s JavaScript files to read library versions
--insecure	Doesn’t check TLS certificates on HTTP requests (TLS is still analysed)
--timeout <sec>	Timeout per request (default 15)
--json	Prints the full report as JSON instead of the formatted view
--markdown <file>	Also writes a Markdown report to that file
--no-history	Doesn’t save a history file
--fail-on <critical|high|medium|low>	Exits with code 2 if any finding is at or above that severity (useful in CI)
Options for the other commands
history <domain>:
--show <ref> re-displays a saved audit.
--json prints it as raw JSON.
-v makes it verbose.
analyze:
-m <model> picks the model.
--ollama-url <url> uses a different Ollama server.
--no-save skips writing the result into the history file.
models: --ollama-url <url> uses a different Ollama server.
Picking a saved audit: wherever a command takes a ref (--show, diff, analyze), you can use:

latest
previous
a number: 1 is the oldest audit and -1 the newest
the start of a history filename, such as 20261112T13
Examples
secaudit example.com
secaudit audit https://example.com -v --ollama -m qwen3:8b --markdown report.md
secaudit history example.com --show -1
secaudit diff example.com 1 latest
secaudit analyze example.com previous -m qwen2.5:7b
