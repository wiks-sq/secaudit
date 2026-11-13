"""Technology fingerprinting from headers, cookies, HTML markers and JS library banners."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

import httpx

from secaudit.context import AuditContext
from secaudit.models import SectionResult, Severity, Technology
from secaudit.net import client

V = r"v?(\d+(?:\.\d+){1,3}[a-z]?)"

# Server / X-Powered-By product tokens: token (lowercase) -> (canonical name, category)
SERVER_TOKENS = {
    "nginx": ("nginx", "Web server"),
    "apache": ("Apache HTTP Server", "Web server"),
    "microsoft-iis": ("Microsoft IIS", "Web server"),
    "openresty": ("OpenResty", "Web server"),
    "litespeed": ("LiteSpeed", "Web server"),
    "lighttpd": ("lighttpd", "Web server"),
    "caddy": ("Caddy", "Web server"),
    "jetty": ("Jetty", "Web server"),
    "apache-coyote": ("Apache Tomcat", "Web server"),
    "tomcat": ("Apache Tomcat", "Web server"),
    "gunicorn": ("Gunicorn", "Web server"),
    "uvicorn": ("Uvicorn", "Web server"),
    "werkzeug": ("Werkzeug", "Web framework"),
    "kestrel": ("Kestrel", "Web server"),
    "envoy": ("Envoy", "Reverse proxy"),
    "haproxy": ("HAProxy", "Reverse proxy"),
    "squid": ("Squid", "Reverse proxy"),
    "varnish": ("Varnish", "Cache"),
    "cloudflare": ("Cloudflare", "CDN"),
    "amazons3": ("Amazon S3", "Hosting"),
    "awselb": ("AWS Elastic Load Balancer", "Load balancer"),
    "gws": ("Google Web Server", "Web server"),
    "gse": ("Google Servlet Engine", "Web server"),
    "esf": ("Google ESF", "Web server"),
    "vercel": ("Vercel", "Hosting"),
    "netlify": ("Netlify", "Hosting"),
    "github.com": ("GitHub Pages", "Hosting"),
    "akamaighost": ("Akamai", "CDN"),
    "akamainetstorage": ("Akamai NetStorage", "CDN"),
    "cowboy": ("Cowboy", "Web server"),
    "tengine": ("Tengine", "Web server"),
    "phusion_passenger": ("Phusion Passenger", "Web server"),
    "php": ("PHP", "Language"),
    "openssl": ("OpenSSL", "Library"),
    "mod_ssl": ("mod_ssl", "Library"),
    "mod_perl": ("mod_perl", "Library"),
    "perl": ("Perl", "Language"),
    "python": ("Python", "Language"),
    "node.js": ("Node.js", "Language"),
    "express": ("Express", "Web framework"),
    "next.js": ("Next.js", "Web framework"),
    "asp.net": ("ASP.NET", "Web framework"),
    "plesklin": ("Plesk", "Control panel"),
    "plesk": ("Plesk", "Control panel"),
    "wp engine": ("WP Engine", "Hosting"),
    "ddos-guard": ("DDoS-Guard", "CDN"),
    "sucuri/cloudproxy": ("Sucuri", "WAF"),
    "imperva": ("Imperva", "WAF"),
    "bigip": ("F5 BIG-IP", "Load balancer"),
    "istio-envoy": ("Istio (Envoy)", "Reverse proxy"),
    "kong": ("Kong", "API gateway"),
    "traefik": ("Traefik", "Reverse proxy"),
}

HEADER_SIGNS = [
    # (header, regex on value or None for presence, name, category, version group?)
    ("cf-ray", None, "Cloudflare", "CDN"),
    ("x-amz-cf-id", None, "Amazon CloudFront", "CDN"),
    ("x-amz-cf-pop", None, "Amazon CloudFront", "CDN"),
    ("x-amz-request-id", None, "Amazon S3", "Hosting"),
    ("x-azure-ref", None, "Azure Front Door", "CDN"),
    ("x-msedge-ref", None, "Azure CDN", "CDN"),
    ("x-served-by", r"cache-", "Fastly", "CDN"),
    ("x-fastly-request-id", None, "Fastly", "CDN"),
    ("x-vercel-id", None, "Vercel", "Hosting"),
    ("x-nf-request-id", None, "Netlify", "Hosting"),
    ("x-github-request-id", None, "GitHub Pages", "Hosting"),
    ("x-akamai-transformed", None, "Akamai", "CDN"),
    ("akamai-grn", None, "Akamai", "CDN"),
    ("x-varnish", None, "Varnish", "Cache"),
    ("via", r"varnish", "Varnish", "Cache"),
    ("x-drupal-cache", None, "Drupal", "CMS"),
    ("x-drupal-dynamic-cache", None, "Drupal", "CMS"),
    ("x-shopify-stage", None, "Shopify", "E-commerce"),
    ("x-shopid", None, "Shopify", "E-commerce"),
    ("x-wix-request-id", None, "Wix", "Website builder"),
    ("x-litespeed-cache", None, "LiteSpeed Cache", "Cache"),
    ("x-turbo-charged-by", r"litespeed", "LiteSpeed", "Web server"),
    ("x-envoy-upstream-service-time", None, "Envoy", "Reverse proxy"),
    ("x-kong-proxy-latency", None, "Kong", "API gateway"),
    ("x-pantheon-styx-hostname", None, "Pantheon", "Hosting"),
    ("x-kinsta-cache", None, "Kinsta", "Hosting"),
    ("x-sucuri-id", None, "Sucuri", "WAF"),
    ("x-cdn", r"imperva|incapsula", "Imperva", "WAF"),
    ("x-iinfo", None, "Imperva", "WAF"),
    ("x-hudson", None, "Jenkins", "CI"),
    ("x-jenkins", None, "Jenkins", "CI"),
    ("x-magento-cache-debug", None, "Magento", "E-commerce"),
    ("x-pingback", r"xmlrpc\.php", "WordPress", "CMS"),
    ("link", r"rel=\"?https://api\.w\.org", "WordPress", "CMS"),
    ("x-redirect-by", r"wordpress", "WordPress", "CMS"),
    ("x-nextjs-cache", None, "Next.js", "Web framework"),
    ("x-nextjs-prerender", None, "Next.js", "Web framework"),
    ("x-middleware-rewrite", None, "Next.js", "Web framework"),
    ("x-gitlab-meta", None, "GitLab", "DevOps"),
    ("x-confluence-request-time", None, "Atlassian Confluence", "Wiki"),
    ("x-arequestid", None, "Atlassian Jira", "Issue tracker"),
    ("x-ghost-cache-status", None, "Ghost", "CMS"),
    ("x-squarespace-frontend", None, "Squarespace", "Website builder"),
]

COOKIE_SIGNS = [
    (r"^PHPSESSID$", "PHP", "Language"),
    (r"^JSESSIONID$", "Java (Servlet)", "Language"),
    (r"^ASP\.NET_SessionId$|^\.ASPXAUTH$|^\.AspNetCore\.", "ASP.NET", "Web framework"),
    (r"^laravel_session$", "Laravel", "Web framework"),
    (r"^ci_session$", "CodeIgniter", "Web framework"),
    (r"^csrftoken$", "Django", "Web framework"),
    (r"^wordpress_|^wp-settings-|^wordpress_test_cookie$", "WordPress", "CMS"),
    (r"^_shopify_|^cart_sig$", "Shopify", "E-commerce"),
    (r"^connect\.sid$", "Express", "Web framework"),
    (r"^rack\.session$", "Ruby Rack", "Web framework"),
    (r"^_[a-z0-9]+_session$", "Ruby on Rails", "Web framework"),
    (r"^__cf_bm$|^__cflb$|^cf_clearance$", "Cloudflare", "CDN"),
    (r"^AWSALB(CORS)?$", "AWS Application Load Balancer", "Load balancer"),
    (r"^AWSELB$", "AWS Elastic Load Balancer", "Load balancer"),
    (r"^BIGipServer", "F5 BIG-IP", "Load balancer"),
    (r"^incap_ses_|^visid_incap_", "Imperva", "WAF"),
    (r"^Drupal\.visitor|^SSESS[0-9a-f]{32}$", "Drupal", "CMS"),
    (r"^frontend$|^mage-cache", "Magento", "E-commerce"),
    (r"^PrestaShop-", "PrestaShop", "E-commerce"),
    (r"^_ga$|^_gid$", "Google Analytics", "Analytics"),
    (r"^_hj", "Hotjar", "Analytics"),
    (r"^XSRF-TOKEN$", "XSRF-TOKEN (Laravel/Angular)", "Web framework"),
]

HTML_SIGNS = [
    (r"/wp-content/|/wp-includes/", "WordPress", "CMS"),
    (r"/sites/(default|all)/(files|themes|modules)/|Drupal\.settings|data-drupal-", "Drupal", "CMS"),
    (r"/media/jui/|/components/com_|Joomla!", "Joomla", "CMS"),
    (r"Mage\.Cookies|/static/version\d+/frontend/|text/x-magento-init", "Magento", "E-commerce"),
    (r"cdn\.shopify\.com|Shopify\.theme", "Shopify", "E-commerce"),
    (r"static\.wixstatic\.com|wix-bolt", "Wix", "Website builder"),
    (r"static1\.squarespace\.com|squarespace-cdn", "Squarespace", "Website builder"),
    (r"/typo3conf/|/typo3temp/", "TYPO3", "CMS"),
    (r"prestashop", "PrestaShop", "E-commerce"),
    (r"id=\"__NEXT_DATA__\"|/_next/static/", "Next.js", "Web framework"),
    (r"window\.__NUXT__|/_nuxt/", "Nuxt", "Web framework"),
    (r"__sveltekit|data-sveltekit", "SvelteKit", "Web framework"),
    (r"<astro-island|/_astro/", "Astro", "Web framework"),
    (r"___gatsby|/page-data/app-data\.json", "Gatsby", "Web framework"),
    (r"data-reactroot|data-reactid|react-dom", "React", "JavaScript framework"),
    (r"\bng-version=|<app-root", "Angular", "JavaScript framework"),
    (r"\bng-app\b|ng-controller", "AngularJS", "JavaScript framework"),
    (r"data-v-[0-9a-f]{8}|__vue__|vue(\.min|\.global|\.runtime)", "Vue.js", "JavaScript framework"),
    (r"googletagmanager\.com/gtm\.js|GTM-[A-Z0-9]{4,}", "Google Tag Manager", "Tag manager"),
    (r"google-analytics\.com/(analytics|ga)\.js|gtag\('config'", "Google Analytics", "Analytics"),
    (r"static\.hotjar\.com", "Hotjar", "Analytics"),
    (r"matomo\.js|piwik\.js", "Matomo", "Analytics"),
    (r"plausible\.io/js", "Plausible", "Analytics"),
    (r"www\.google\.com/recaptcha|grecaptcha", "Google reCAPTCHA", "Security"),
    (r"challenges\.cloudflare\.com/turnstile", "Cloudflare Turnstile", "Security"),
    (r"js\.stripe\.com", "Stripe", "Payments"),
    (r"connect\.facebook\.net", "Facebook Pixel", "Analytics"),
    (r"cdn\.jsdelivr\.net", "jsDelivr", "CDN"),
    (r"cdnjs\.cloudflare\.com", "cdnjs", "CDN"),
    (r"fonts\.googleapis\.com", "Google Fonts", "Fonts"),
    (r"use\.fontawesome\.com|font-awesome|fontawesome", "Font Awesome", "Fonts"),
    (r"js\.hs-scripts\.com|hubspot", "HubSpot", "Marketing"),
    (r"cookiebot|cookie-script\.com|onetrust", "Cookie consent manager", "Privacy"),
    (r"intercomcdn|widget\.intercom\.io", "Intercom", "Live chat"),
    (r"alpine(\.min)?\.js|x-data=\"", "Alpine.js", "JavaScript framework"),
    (r"htmx(\.min)?\.js|hx-get=", "htmx", "JavaScript framework"),
    (r"csrfmiddlewaretoken", "Django", "Web framework"),
    (r"__VIEWSTATE", "ASP.NET Web Forms", "Web framework"),
    (r"<meta name=\"csrf-token\"[^>]+>.*laravel|laravel", "Laravel", "Web framework"),
]

# JS library: (canonical name, filename regex, banner regex)
JS_LIBS = [
    ("jQuery", r"jquery[.-]?(\d+\.\d+\.\d+)(?:\.min|\.slim)*\.js|/jquery/(\d+\.\d+\.\d+)/|jquery@(\d+\.\d+\.\d+)|jquery(?:\.min)?\.js\?ver=(\d+\.\d+\.\d+)",
     r"jQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+)|jquery:\s*\"(\d+\.\d+\.\d+)\""),
    ("jQuery UI", r"jquery-ui[.-]?(\d+\.\d+\.\d+)|/jqueryui/(\d+\.\d+\.\d+)/|jquery-ui@(\d+\.\d+\.\d+)", r"jQuery UI - v(\d+\.\d+\.\d+)"),
    ("jQuery Migrate", r"jquery-migrate[.-](\d+\.\d+\.\d+)|jquery-migrate(?:\.min)?\.js\?ver=(\d+\.\d+\.\d+)", r"jQuery Migrate (?:- )?v(\d+\.\d+\.\d+)"),
    ("Bootstrap", r"bootstrap[.-](\d+\.\d+\.\d+)|/bootstrap/(\d+\.\d+\.\d+)/|bootstrap@(\d+\.\d+\.\d+)", r"Bootstrap v(\d+\.\d+\.\d+)"),
    ("AngularJS", r"angular[.-](1\.\d+\.\d+)|/angular\.js/(1\.\d+\.\d+)/|angular@(1\.\d+\.\d+)", r"AngularJS v(1\.\d+\.\d+)"),
    ("Lodash", r"lodash[.-](\d+\.\d+\.\d+)|/lodash\.js/(\d+\.\d+\.\d+)/|lodash@(\d+\.\d+\.\d+)", r"(?:Lodash|lodash\.com)[^\n]{0,200}?VERSION\s*=\s*'(\d+\.\d+\.\d+)'|@license Lodash (\d+\.\d+\.\d+)|lodash\.js v?(\d+\.\d+\.\d+)"),
    ("Underscore.js", r"underscore[.-](\d+\.\d+\.\d+)|/underscore\.js/(\d+\.\d+\.\d+)/|underscore@(\d+\.\d+\.\d+)", r"Underscore\.js (\d+\.\d+\.\d+)"),
    ("Moment.js", r"moment[.-](\d+\.\d+\.\d+)|/moment\.js/(\d+\.\d+\.\d+)/|moment@(\d+\.\d+\.\d+)", r"//! version : (\d+\.\d+\.\d+)"),
    ("Vue.js", r"vue[.-](\d+\.\d+\.\d+)|/vue/(\d+\.\d+\.\d+)/|vue@(\d+\.\d+\.\d+)", r"Vue\.js v(\d+\.\d+\.\d+)"),
    ("React", r"react[.-](\d+\.\d+\.\d+)|/react/(\d+\.\d+\.\d+)/|react@(\d+\.\d+\.\d+)", r"@license React v(\d+\.\d+\.\d+)|React v(\d+\.\d+\.\d+)"),
    ("Handlebars", r"handlebars[.-]v?(\d+\.\d+\.\d+)|/handlebars\.js/(\d+\.\d+\.\d+)/|handlebars@(\d+\.\d+\.\d+)", r"Handlebars v(\d+\.\d+\.\d+)|handlebars v(\d+\.\d+\.\d+)"),
    ("DOMPurify", r"purify[.-](\d+\.\d+\.\d+)|/dompurify/(\d+\.\d+\.\d+)/|dompurify@(\d+\.\d+\.\d+)", r"DOMPurify (\d+\.\d+\.\d+)"),
    ("Select2", r"select2[.-](\d+\.\d+\.\d+)|/select2/(\d+\.\d+\.\d+)/|select2@(\d+\.\d+\.\d+)", r"Select2 (\d+\.\d+\.\d+)"),
    ("Popper.js", r"popper[.-](\d+\.\d+\.\d+)|/popper\.js/(\d+\.\d+\.\d+)/|@popperjs/core@(\d+\.\d+\.\d+)", r"@popperjs/core v(\d+\.\d+\.\d+)|Popper\.js v?(\d+\.\d+\.\d+)"),
    ("Swiper", r"swiper[.-](\d+\.\d+\.\d+)|swiper@(\d+\.\d+\.\d+)", r"Swiper (\d+\.\d+\.\d+)"),
    ("Axios", r"axios[.-](\d+\.\d+\.\d+)|axios@(\d+\.\d+\.\d+)", r"axios v(\d+\.\d+\.\d+)"),
    ("Chart.js", r"chart\.js@(\d+\.\d+\.\d+)|/Chart\.js/(\d+\.\d+\.\d+)/", r"Chart\.js v(\d+\.\d+\.\d+)"),
    ("Prototype", r"prototype[.-](\d+\.\d+\.\d+)|/prototype/(\d+\.\d+\.\d+)/", r"Prototype JavaScript framework, version (\d+\.\d+\.\d+)"),
    ("TinyMCE", r"tinymce/(\d+\.\d+\.\d+)/|tinymce@(\d+\.\d+\.\d+)", r"TinyMCE version (\d+\.\d+\.\d+)"),
    ("CKEditor", r"ckeditor[^/]*/(\d+\.\d+\.\d+)/", r"CKEDITOR\.version\s*=\s*['\"](\d+\.\d+\.\d+)"),
]

GENERATOR_RE = [
    (r"WordPress\s*" + V, "WordPress", "CMS"),
    (r"Drupal\s*(\d+(?:\.\d+)*)", "Drupal", "CMS"),
    (r"Joomla!?\s*(\d+(?:\.\d+)*)?", "Joomla", "CMS"),
    (r"TYPO3\s*(?:CMS\s*)?(\d+(?:\.\d+)*)?", "TYPO3", "CMS"),
    (r"Ghost\s*" + V, "Ghost", "CMS"),
    (r"Hugo\s*" + V, "Hugo", "Static site generator"),
    (r"Jekyll\s*" + V, "Jekyll", "Static site generator"),
    (r"Gatsby\s*" + V, "Gatsby", "Web framework"),
    (r"Docusaurus\s*" + V, "Docusaurus", "Static site generator"),
    (r"MkDocs-?" + V, "MkDocs", "Static site generator"),
    (r"Hexo\s*" + V, "Hexo", "Static site generator"),
    (r"Wix\.com", "Wix", "Website builder"),
    (r"Squarespace", "Squarespace", "Website builder"),
    (r"Webflow", "Webflow", "Website builder"),
    (r"PrestaShop", "PrestaShop", "E-commerce"),
    (r"Magento\s*(\d+(?:\.\d+)*)?", "Magento", "E-commerce"),
    (r"MediaWiki\s*" + V, "MediaWiki", "Wiki"),
    (r"Discourse\s*" + V, "Discourse", "Forum"),
    (r"Concrete\s?CMS\s*" + V + "?", "Concrete CMS", "CMS"),
    (r"Craft CMS\s*" + V + "?", "Craft CMS", "CMS"),
    (r"Elementor\s*" + V, "Elementor", "CMS plugin"),
    (r"WooCommerce\s*" + V, "WooCommerce", "E-commerce"),
    (r"Site Kit by Google\s*" + V, "Site Kit by Google", "CMS plugin"),
    (r"Yoast SEO", "Yoast SEO", "CMS plugin"),
    (r"Astro\s*" + V, "Astro", "Web framework"),
    (r"Nuxt", "Nuxt", "Web framework"),
    (r"Next\.js", "Next.js", "Web framework"),
]

WP_PLUGIN_RE = re.compile(r"/wp-content/plugins/([a-z0-9_\-]+)/[^\"'\s>]*?(?:\?ver=(\d+(?:\.\d+){1,3}))?[\"'\s>]", re.I)
DISTRO_RE = re.compile(r"\((Ubuntu|Debian|CentOS|Red Hat|RHEL|Fedora|Amazon Linux|AlmaLinux|Rocky|Win64|Win32|Unix)\)", re.I)


class Detector:
    def __init__(self) -> None:
        self.found: dict[str, Technology] = {}
        self.notes: dict[str, str] = {}

    def add(self, name: str, category: str, version: str | None, source: str, confidence: str = "high") -> None:
        key = name.lower()
        version = version.strip(" .") if version else None
        cur = self.found.get(key)
        if cur is None:
            self.found[key] = Technology(name, version, category, source, confidence)
        elif version and not cur.version:
            cur.version, cur.source = version, f"{cur.source}; {source}"
        elif source not in cur.source:
            cur.source = f"{cur.source}; {source}"


def _first_group(m: re.Match | None) -> str | None:
    if not m:
        return None
    return next((g for g in m.groups() if g), None) if m.groups() else None


def _clean_version(v: str | None) -> str | None:
    """'7.4.3-4ubuntu2.20' -> '7.4.3'; keeps OpenSSL-style letter suffixes ('1.1.1f')."""
    if not v:
        return None
    m = re.match(r"(\d+(?:\.\d+){0,3}[a-z]?)(?![a-z])", v)
    return m.group(1) if m else None


def parse_product_tokens(value: str, d: Detector, source: str) -> None:
    for name, ver in re.findall(r"([A-Za-z][\w.\- ]*?)(?:/|\s+v?)(\d[\w.\-]*)", value):
        token = name.strip().lower()
        mapped = SERVER_TOKENS.get(token)
        if mapped:
            d.add(mapped[0], mapped[1], _clean_version(ver), source)
    # tokens without versions
    for tok in re.split(r"[\s,;()]+", value):
        base = tok.split("/")[0].lower()
        if base in SERVER_TOKENS and SERVER_TOKENS[base][0].lower() not in d.found:
            d.add(*SERVER_TOKENS[base], None, source)
    m = DISTRO_RE.search(value)
    if m and m.group(1).lower() != "unix":
        d.notes["os"] = {"win64": "Windows", "win32": "Windows"}.get(m.group(1).lower(), m.group(1))


def run(ctx: AuditContext) -> SectionResult:
    res = SectionResult("tech")
    d = Detector()
    resp = ctx.response
    if resp is None:
        return res

    headers = {k.lower(): v for k, v in resp.headers.items()}
    # Server-type headers (main + error page, which sometimes leaks more)
    for src_name, hs in (("main", headers), ("404 page", ctx.error_page_headers)):
        for h in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-runtime",
                  "x-server-powered-by", "x-backend"):
            if h in hs:
                val = hs[h]
                if h == "x-aspnet-version":
                    d.add("ASP.NET", "Web framework", _clean_version(val), f"header {h}")
                elif h == "x-aspnetmvc-version":
                    d.add("ASP.NET MVC", "Web framework", _clean_version(val), f"header {h}")
                elif h == "x-generator":
                    _generator(val, d, f"header {h}")
                else:
                    parse_product_tokens(val, d, f"header {h} ({src_name})")
                    if h == "x-powered-by" and val.lower().startswith("next.js"):
                        d.add("Next.js", "Web framework", _clean_version(val.split()[-1]), "header x-powered-by")

    for h, rx, name, cat in HEADER_SIGNS:
        if h in headers and (rx is None or re.search(rx, headers[h], re.I)):
            d.add(name, cat, None, f"header {h}")

    # Cookies
    for raw in resp.headers.get_list("set-cookie") + [c for r in resp.history for c in r.headers.get_list("set-cookie")]:
        name = raw.split("=", 1)[0].strip()
        for rx, tech_name, cat in COOKIE_SIGNS:
            if re.search(rx, name):
                d.add(tech_name, cat, None, f"cookie {name}")

    # A challenge page's HTML belongs to the WAF, not the site; only headers stay meaningful.
    html = "" if ctx.blocked else ctx.html
    res.data["html_analysed"] = not ctx.blocked
    # Meta generator(s)
    for gen in re.findall(r"<meta[^>]+name=[\"']generator[\"'][^>]*content=[\"']([^\"']+)", html, re.I) + \
               re.findall(r"<meta[^>]+content=[\"']([^\"']+)[\"'][^>]*name=[\"']generator", html, re.I):
        _generator(gen, d, "meta generator")

    for rx, name, cat in HTML_SIGNS:
        if re.search(rx, html, re.I):
            d.add(name, cat, None, "HTML marker", confidence="medium")

    m = re.search(r'ng-version="(\d+\.\d+\.\d+)"', html)
    if m:
        d.add("Angular", "JavaScript framework", m.group(1), "ng-version attribute")
    # WordPress core version from ?ver= on core assets, when generator is hidden
    if "wordpress" in d.found and not d.found["wordpress"].version:
        vers = re.findall(r"/wp-includes/[^\"'?]+\?ver=(\d+\.\d+(?:\.\d+)?)", html)
        if vers:
            d.add("WordPress", "CMS", max(set(vers), key=vers.count), "wp-includes ?ver=", confidence="medium")
    # WordPress plugins
    plugins = {}
    for slug, ver in WP_PLUGIN_RE.findall(html):
        if slug not in plugins or (ver and not plugins[slug]):
            plugins[slug] = ver or None
    res.data["wordpress_plugins"] = plugins

    # Error page banners (e.g. Apache "Server at", Tomcat)
    eb = "" if ctx.blocked else ctx.error_page_body
    for rx, name, cat in ((r"Apache/(\d+\.\d+\.\d+)", "Apache HTTP Server", "Web server"),
                          (r"nginx/(\d+\.\d+\.\d+)", "nginx", "Web server"),
                          (r"Apache Tomcat/(\d+\.\d+\.\d+)", "Apache Tomcat", "Web server"),
                          (r"Jetty://|Powered by Jetty:// (\d+\.\d+\.\d+)", "Jetty", "Web server"),
                          (r"OpenResty|openresty/(\d+\.\d+\.\d+(?:\.\d+)?)", "OpenResty", "Web server"),
                          (r"Microsoft-IIS/(\d+\.\d+)", "Microsoft IIS", "Web server")):
        m = re.search(rx, eb)
        if m:
            d.add(name, cat, _first_group(m), "404 page banner")

    # JS libraries from script URLs, then banners in fetched script bodies
    script_urls = ctx.script_srcs
    for url in script_urls:
        for lib, file_rx, _ in JS_LIBS:
            m = re.search(file_rx, url, re.I)
            if m:
                d.add(lib, "JavaScript library", _first_group(m), "script URL")
    inline = html
    for lib, _, banner_rx in JS_LIBS:
        m = re.search(banner_rx, inline)
        if m and _first_group(m):
            d.add(lib, "JavaScript library", _first_group(m), "inline script banner")
    if ctx.options.fetch_assets and script_urls:
        bodies = _fetch_scripts(ctx, script_urls)
        for url, body in bodies:
            for lib, file_rx, banner_rx in JS_LIBS:
                if lib.lower() in d.found and d.found[lib.lower()].version:
                    continue
                m = re.search(banner_rx, body[:400_000])
                if m and _first_group(m):
                    d.add(lib, "JavaScript library", _first_group(m), f"banner in {urlsplit(url).path.rsplit('/', 1)[-1][:40]}")
        res.data["scripts_fetched"] = len(bodies)

    techs = sorted(d.found.values(), key=lambda t: (t.category, t.name))
    ctx.technologies = techs
    res.data["technologies"] = [t.__dict__ for t in techs]
    res.data["os_hint"] = d.notes.get("os")

    versioned = [t for t in techs if t.version]
    if versioned:
        res.add("tech.versions", f"{len(versioned)} component version(s) disclosed to visitors", Severity.INFO,
                "Information disclosure", evidence=", ".join(f"{t.name} {t.version}" for t in versioned[:10]),
                detail="Exact versions let attackers match known CVEs instantly.")
    if d.notes.get("os"):
        res.add("tech.os", f"Operating system disclosed ({d.notes['os']})", Severity.INFO, "Information disclosure")
    return res


def _generator(value: str, d: Detector, source: str) -> None:
    for rx, name, cat in GENERATOR_RE:
        m = re.search(rx, value, re.I)
        if m:
            d.add(name, cat, _first_group(m), source)
            return
    d.add(value.split(" ")[0][:40], "Generator", _clean_version(value.split(" ")[-1]) if re.search(r"\d", value) else None, source,
          confidence="medium")


def _fetch_scripts(ctx: AuditContext, urls: list[str], limit: int = 20) -> list[tuple[str, str]]:
    """Download (like a browser would) up to `limit` referenced scripts to read version banners."""
    candidates = [u for u in urls if u.startswith(("http://", "https://"))][:limit]
    out: list[tuple[str, str]] = []

    def get(u: str):
        try:
            with client(min(ctx.config.timeout, 10), verify=ctx.options.verify_tls) as c:
                with c.stream("GET", u) as r:
                    if r.status_code != 200:
                        return None
                    buf = b""
                    for chunk in r.iter_bytes():
                        buf += chunk
                        if len(buf) > 1_500_000:
                            break
                    return u, buf.decode("utf-8", errors="replace")
        except httpx.HTTPError:
            return None

    with ThreadPoolExecutor(max_workers=6) as pool:
        for item in pool.map(get, candidates):
            if item:
                out.append(item)
    return out
