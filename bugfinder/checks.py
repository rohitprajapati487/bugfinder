import difflib
import hashlib
import random
import re
import socket
import ssl
import string
import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from bs4 import BeautifulSoup

from .crawler import fetch
from .models import Finding
from .utils import origin_of, same_site, truncate


SECURITY_HEADERS = {
    "content-security-policy": ("high", "Content-Security-Policy header is missing", "Add a strict Content-Security-Policy to reduce XSS and injection risk."),
    "strict-transport-security": ("medium", "Strict-Transport-Security header is missing", "Add HSTS (max-age=31536000; includeSubDomains) and serve only over HTTPS."),
    "x-frame-options": ("medium", "X-Frame-Options / frame-ancestors protection is missing", "Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors to prevent clickjacking."),
    "x-content-type-options": ("low", "X-Content-Type-Options header is missing", "Set X-Content-Type-Options: nosniff."),
    "referrer-policy": ("low", "Referrer-Policy header is missing", "Set Referrer-Policy: strict-origin-when-cross-origin or stricter."),
    "permissions-policy": ("info", "Permissions-Policy header is missing", "Restrict powerful browser features with Permissions-Policy."),
}

SENSITIVE_PATHS = {
    ".git/config": ("critical", "Exposed Git repository metadata"),
    ".git/HEAD": ("critical", "Exposed Git repository metadata"),
    ".env": ("critical", "Exposed environment file"),
    ".env.bak": ("critical", "Exposed environment backup"),
    "backup.zip": ("critical", "Exposed backup archive"),
    "backup.sql": ("critical", "Exposed database backup"),
    "db.sql": ("critical", "Exposed database backup"),
    "debug.log": ("high", "Exposed debug log"),
    "config.php.bak": ("high", "Exposed configuration backup"),
    "wp-config.php.bak": ("high", "Exposed WordPress configuration backup"),
    ".DS_Store": ("low", "Exposed macOS metadata file"),
    ".svn/entries": ("high", "Exposed Subversion metadata"),
    "phpinfo.php": ("high", "Exposed phpinfo() output"),
    "server-status": ("high", "Exposed server status page"),
    "actuator/env": ("critical", "Exposed Spring Boot actuator environment"),
    "actuator/health": ("low", "Exposed Spring Boot actuator health endpoint"),
    "admin/": ("low", "Admin area is publicly reachable"),
    "administrator/": ("low", "Admin area is publicly reachable"),
    "wp-admin/": ("low", "WordPress admin area is reachable"),
    "swagger.json": ("medium", "Exposed API specification"),
    "openapi.json": ("medium", "Exposed API specification"),
    "api/swagger.json": ("medium", "Exposed API specification"),
    "package.json": ("low", "Exposed package manifest"),
    "composer.json": ("low", "Exposed composer manifest"),
    "Dockerfile": ("medium", "Exposed Dockerfile"),
    "docker-compose.yml": ("high", "Exposed docker-compose configuration"),
    "web.config": ("medium", "Exposed IIS configuration"),
    "sitemap.xml": ("info", "Sitemap found"),
    "robots.txt": ("info", "Robots file found"),
}

SQL_ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "mysqli", "you have an error in your sql",
    "unclosed quotation mark", "quoted string not properly terminated",
    "pg_query", "postgresql", "psql:", "ora-0", "oracle error", "pls-",
    "sqlite error", "sqlite3", "odbc sql server driver", "microsoft ole db",
    "syntax error at or near", "unterminated string", "jdbc",
    "warning: mysql", "valid mysql result", "mysql server version",
    "invalid input syntax for", "unterminated quoted string",
    "microsoft sql server", "native client", "sqlstate",
    "unrecognized token", "no such table", "no such column",
    "division by zero", "conversion failed when converting",
]

SQL_DBMS = [
    ("MySQL / MariaDB", ("mysql", "mysqli", "mariadb", "you have an error in your sql")),
    ("PostgreSQL", ("postgresql", "pg_query", "psql:", "invalid input syntax for", "unterminated quoted string")),
    ("Microsoft SQL Server", ("microsoft sql server", "odbc sql server", "native client", "unclosed quotation mark")),
    ("Oracle", ("ora-0", "oracle error", "pls-")),
    ("SQLite", ("sqlite", "unrecognized token", "no such table", "no such column")),
]

SQL_PAYLOADS = ["'", '"', "''", "')", "';"]

SQL_TIME_PAYLOADS = [
    ("' OR SLEEP(3)-- -", "MySQL"),
    ("'; SELECT pg_sleep(3)-- -", "PostgreSQL"),
    ("'; WAITFOR DELAY '0:0:3'-- -", "Microsoft SQL Server"),
]

STACK_TRACE_SIGNATURES = [
    "traceback (most recent call last)", "stack trace:", "stacktrace",
    "fatal error:", "uncaught exception", "at java.", "at org.springframework",
    "notice: undefined", "warning: include(", "warning: require(",
    "parse error:", "call to undefined function", "system.nullreferenceexception",
]

SOFT_404_MARKERS = [
    "page not found", "404 not found", "not found", "does not exist",
    "no longer available", "cannot be found",
]


def _add(findings, category, title, severity, url="", evidence="", remediation=""):
    findings.append(Finding(
        category=category,
        title=title,
        severity=severity,
        url=url,
        evidence=truncate(evidence, 1500),
        remediation=remediation,
    ))


def _unique(values):
    seen = set()
    result = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _normalize_body(text):
    text = re.sub(r"<[^>]+>", " ", text or "")
    text = re.sub(r"\d+", "0", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip().lower()[:4000]


def _is_soft_404(body, baseline_body):
    lowered = (body or "").lower()
    if any(marker in lowered for marker in SOFT_404_MARKERS):
        return True
    if not baseline_body:
        return False
    ratio = difflib.SequenceMatcher(None, _normalize_body(body), _normalize_body(baseline_body)).quick_ratio()
    return ratio > 0.92


def check_page_availability(crawl):
    findings = []
    for page in crawl.pages:
        if page.status == 0:
            _add(findings, "Availability", "Page could not be loaded", "high", page.url,
                 page.error, "Fix the server/network error and make the page reachable.")
        elif page.status >= 500:
            _add(findings, "Availability", f"Server error (HTTP {page.status})", "high", page.url,
                 f"HTTP {page.status} returned for {page.url}", "Investigate server logs and fix the 5xx error.")
        elif page.status in (401, 403):
            _add(findings, "Access Control", f"Access restricted (HTTP {page.status})", "info", page.url,
                 f"HTTP {page.status} returned for {page.url}",
                 "Verify the restriction is intentional; authenticated areas can be out of program scope.")
        elif page.status >= 400:
            _add(findings, "Availability", f"Client error (HTTP {page.status})", "medium", page.url,
                 f"HTTP {page.status} returned for {page.url}", "Fix the broken page or update links pointing to it.")
    return findings


def check_broken_links(crawl, session, timeout=15, check_external=True, max_external=15, max_internal=40):
    findings = []
    cache = {}

    def status_of(url):
        if url in cache:
            return cache[url]
        result = fetch(session, url, timeout=timeout, read_body=False)
        cache[url] = result
        return result

    internal = [u for u in crawl.links if same_site(u, crawl.start_url)]
    external = [u for u in crawl.external_links if not same_site(u, crawl.start_url)]
    resources = [u for u in crawl.resources if same_site(u, crawl.start_url)]

    for url in _unique(internal)[:max_internal]:
        if url in {p.url for p in crawl.pages}:
            continue
        result = status_of(url)
        if result.status in (401, 403, 429, 405):
            if result.status in (401, 403):
                sev = "low"
            else:
                sev = "info"
            _add(findings, "Access Control", f"Access-restricted link (HTTP {result.status})", sev, url,
                 result.error or f"HTTP {result.status} for {url}",
                 "Confirm the restriction is intentional; direct access may bypass the UI flow.")
        elif result.status == 0 or result.status >= 400:
            _add(findings, "Broken Links", "Broken internal link", "medium", url,
                 result.error or f"HTTP {result.status} for {url}",
                 "Fix or remove the broken internal link.")

    for url in _unique(resources)[:max_internal]:
        result = status_of(url)
        if result.status in (401, 403, 429, 405):
            _add(findings, "Access Control", f"Access-restricted resource (HTTP {result.status})", "info", url,
                 result.error or f"HTTP {result.status} for {url}",
                 "Confirm the resource does not expose sensitive content without authentication.")
        elif result.status == 0 or result.status >= 400:
            _add(findings, "Broken Links", "Broken internal resource", "medium", url,
                 result.error or f"HTTP {result.status} for {url}",
                 "Fix the missing resource (image/script/style) or update its reference.")

    if check_external:
        seen_hosts = set()
        for url in _unique(external):
            host = urlparse(url).hostname or url
            if host in seen_hosts:
                continue
            seen_hosts.add(host)
            if len(seen_hosts) > max_external:
                break
            result = status_of(url)
            if result.status in (401, 403, 429):
                _add(findings, "Access Control", f"External link blocked (HTTP {result.status})", "info", url,
                     result.error or f"HTTP {result.status} for external URL {url}",
                     "Likely bot protection; verify manually before treating this as a broken link.")
            elif result.status == 0 or result.status >= 400:
                _add(findings, "Broken Links", "Broken external link", "low", url,
                     result.error or f"HTTP {result.status} for external URL {url}",
                     "Update or remove the external link, or verify bot blocking is not the cause.")

    return findings


def check_security_headers(crawl):
    findings = []
    origins = {}
    for page in crawl.pages:
        if not page.status or not page.headers:
            continue
        origin = origin_of(page.url)
        if origin in origins:
            continue
        origins[origin] = page

    for origin, page in origins.items():
        headers = page.headers
        csp = headers.get("content-security-policy", "")
        for header, (severity, title, remediation) in SECURITY_HEADERS.items():
            if header in headers and headers[header].strip():
                continue
            if header == "strict-transport-security" and not origin.startswith("https://"):
                continue
            if header == "x-frame-options" and "frame-ancestors" in csp:
                continue
            _add(findings, "Security Headers", title, severity, origin,
                 f"Response headers for {origin}: {', '.join(sorted(headers.keys()))}",
                 remediation)

        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        if powered:
            _add(findings, "Information Disclosure", "Technology stack disclosed via X-Powered-By", "low", origin,
                 f"X-Powered-By: {powered}", "Remove the X-Powered-By header.")
        if server and re.search(r"[\d.]+", server):
            _add(findings, "Information Disclosure", "Server version disclosed", "low", origin,
                 f"Server: {server}", "Remove version details from the Server header.")

    return findings


def check_cookies(session, crawl):
    findings = []
    if not session.cookies:
        return findings
    seen = set()
    for cookie in session.cookies:
        key = (cookie.domain, cookie.name)
        if key in seen:
            continue
        seen.add(key)
        issues = []
        if not cookie.secure:
            issues.append("missing Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append("missing HttpOnly flag")
        samesite = cookie._rest.get("SameSite") if hasattr(cookie, "_rest") else None
        if not samesite:
            issues.append("missing SameSite attribute")
        if not issues:
            continue
        severity = "medium" if "missing Secure flag" in issues else "low"
        _add(findings, "Cookies", f"Cookie '{cookie.name}' has weak attributes", severity,
             f"https://{cookie.domain.lstrip('.')}",
             f"Cookie {cookie.name} on {cookie.domain}: {', '.join(issues)}",
             "Set Secure, HttpOnly and SameSite attributes on all cookies.")
    return findings


def check_forms(crawl):
    findings = []
    for form in crawl.forms:
        origin = origin_of(form.page_url)
        if form.has_password:
            if form.action.startswith("http://"):
                _add(findings, "Forms", "Password form submits over plain HTTP", "critical", form.page_url,
                     f"Form action: {form.action}", "Serve the form and submit credentials only over HTTPS.")
            if form.method == "get":
                _add(findings, "Forms", "Password form uses GET method", "high", form.page_url,
                     f"Form action: {form.action}, method=GET", "Use POST for authentication forms.")
            if form.method == "post" and not form.csrf_names:
                _add(findings, "Forms", "Login form has no visible CSRF token", "medium", form.page_url,
                     f"Form action: {form.action}, fields: {', '.join(i['name'] for i in form.inputs)}",
                     "Add and validate an anti-CSRF token for state-changing and authentication forms.")
        if not same_site(form.action, form.page_url):
            _add(findings, "Forms", "Form submits to a different domain", "medium", form.page_url,
                 f"Form action points to {form.action}", "Verify the external form target is intentional and trusted.")
        if any(i["type"] == "file" for i in form.inputs) and "multipart/form-data" not in form.enctype:
            _add(findings, "Forms", "File upload form is missing multipart encoding", "low", form.page_url,
                 f"Form action: {form.action}, enctype='{form.enctype}'",
                 "Set enctype='multipart/form-data' on file upload forms.")

    seen = set()
    for form in crawl.forms:
        if not form.has_password:
            continue
        key = (form.page_url, form.action)
        if key in seen:
            continue
        seen.add(key)
        password_inputs = [i for i in form.inputs if i["type"] == "password"]
        if password_inputs:
            _add(findings, "Forms", "Password field may allow autocomplete", "info", form.page_url,
                 f"Password field(s): {', '.join(i['name'] for i in password_inputs)}",
                 "Use autocomplete='current-password' or 'new-password' as appropriate.")
    return findings


def _url_with_params(url, params):
    parsed = urlparse(url)
    query = urlencode(params, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, ""))


def _query_variants(crawl, max_pages=10, max_params=4):
    variants = []
    seen = set()
    for page in crawl.pages:
        parsed = urlparse(page.url)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        if not query:
            continue
        key = (page.url, tuple(name for name, _ in query))
        if key in seen:
            continue
        seen.add(key)
        variants.append((page.url, query[:max_params]))
        if len(variants) >= max_pages:
            return variants

    for form in crawl.forms:
        if form.method != "get" or not same_site(form.action, crawl.start_url):
            continue
        names = [
            field["name"] for field in form.inputs
            if field["name"] and field["type"] not in ("submit", "button", "reset", "image", "file", "hidden")
        ]
        if not names:
            continue
        key = (form.action, tuple(names[:max_params]))
        if key in seen:
            continue
        seen.add(key)
        params = [(name, "1") for name in names[:max_params]]
        variants.append((form.action, params))
        if len(variants) >= max_pages:
            break
    return variants


def check_reflection_xss(crawl, session, timeout=15, max_pages=10):
    findings = []
    payload = 'bfxzq9271"><svg/onload=bfxzq9271>'
    for url, params in _query_variants(crawl, max_pages=max_pages):
        for name, _ in params:
            mutated = [(key, payload if key == name else value) for key, value in params]
            target = _url_with_params(url, mutated)
            result = fetch(session, target, timeout=timeout)
            if not result.html:
                continue
            index = result.html.find(payload)
            if index == -1:
                continue
            context = result.html[max(0, index - 120):index + len(payload) + 120]
            _add(findings, "Injection", "Reflected input may allow XSS", "high", target,
                 f"Parameter '{name}' was reflected unescaped. Context: {context}",
                 "Encode/escape all reflected user input and add a strict Content-Security-Policy.")
    return findings


def _sql_dbms(matches):
    text = " ".join(matches).lower()
    for dbms, signatures in SQL_DBMS:
        if any(signature in text for signature in signatures):
            return dbms
    return "Unknown DBMS"


def check_sql_injection(crawl, session, timeout=15, max_pages=10, time_based=False, max_requests=60):
    findings = []
    requests_made = 0

    for url, params in _query_variants(crawl, max_pages=max_pages):
        baseline = fetch(session, _url_with_params(url, params), timeout=timeout)
        requests_made += 1
        if baseline.status == 0:
            continue
        baseline_ms = baseline.elapsed_ms

        for name, value in params:
            if requests_made >= max_requests:
                return findings
            found = False

            for payload in SQL_PAYLOADS:
                if requests_made >= max_requests:
                    return findings
                mutated = [(key, (item + payload) if key == name else item) for key, item in params]
                target = _url_with_params(url, mutated)
                result = fetch(session, target, timeout=timeout)
                requests_made += 1

                if result.status in (403, 406, 429):
                    continue
                body = (result.html or "").lower()
                matches = [sig for sig in SQL_ERROR_SIGNATURES if sig in body]
                if matches:
                    dbms = _sql_dbms(matches)
                    _add(findings, "Injection", f"SQL injection (error-based, {dbms})", "high", target,
                         f"Parameter '{name}' with payload {payload!r} triggered database error signatures: "
                         f"{', '.join(matches[:5])}",
                         "Use parameterized queries / prepared statements and hide database errors from users.")
                    found = True
                    break
                if baseline.status < 500 and result.status >= 500:
                    _add(findings, "Injection", "Potential SQL injection (server error after quote)", "medium", target,
                         f"Parameter '{name}' with payload {payload!r} changed HTTP {baseline.status} -> "
                         f"HTTP {result.status}",
                         "Handle invalid input gracefully and use parameterized queries; investigate the 500 error.")
                    found = True
                    break

            if found or not time_based or requests_made >= max_requests:
                continue

            for payload, dbms in SQL_TIME_PAYLOADS:
                if requests_made >= max_requests:
                    return findings
                mutated = [(key, payload if key == name else item) for key, item in params]
                target = _url_with_params(url, mutated)
                result = fetch(session, target, timeout=max(timeout, 12))
                requests_made += 1
                if result.status in (403, 406, 429):
                    continue
                if result.elapsed_ms >= baseline_ms + 2500:
                    _add(findings, "Injection", f"Time-based SQL injection ({dbms}, possible)", "high", target,
                         f"Parameter '{name}' with payload {payload!r} took {result.elapsed_ms} ms "
                         f"(baseline {baseline_ms} ms).",
                         "Use parameterized queries and avoid building SQL from user input.")
                    break

    return findings


def check_sensitive_paths(session, base_url, timeout=15):
    findings = []
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}/"
    random_path = "".join(random.choice(string.ascii_lowercase) for _ in range(14))
    baseline = fetch(session, root + random_path, timeout=timeout)
    baseline_available = baseline.status == 200

    for path, (severity, title) in SENSITIVE_PATHS.items():
        target = root + path
        result = fetch(session, target, timeout=timeout)
        if result.status != 200 or not result.html:
            continue
        requested_path = (urlparse(target).path.rstrip("/") or "/")
        final_path = (urlparse(result.final_url or target).path.rstrip("/") or "/")
        if final_path != requested_path:
            continue
        if _is_soft_404(result.html, baseline.html if baseline_available else ""):
            continue
        if "index of /" in (result.html or "").lower() and path.endswith("/"):
            _add(findings, "Exposure", f"Directory listing enabled: /{path}", "medium", target,
                 truncate(result.html, 600), "Disable directory listing on the web server.")
            continue
        if path in ("sitemap.xml", "robots.txt"):
            continue
        evidence = truncate(result.html, 700)
        if path == ".git/config" and "[core]" not in (result.html or "").lower():
            continue
        if path.endswith(".env") and "=" not in (result.html or ""):
            continue
        _add(findings, "Exposure", title, severity, target, evidence,
             "Remove the exposed file/endpoint from the public web root and block access at the server level.")
    return findings


def check_seo(crawl):
    findings = []
    for page in crawl.pages:
        if not page.is_html or not page.html:
            continue
        soup = BeautifulSoup(page.html, "html.parser")
        title = soup.title.get_text(strip=True) if soup.title else ""
        if not title:
            _add(findings, "SEO", "Missing page title", "medium", page.url,
                 "The <title> element is empty or missing.", "Add a unique, descriptive <title> to the page.")
        if not soup.find("meta", attrs={"name": "description"}):
            _add(findings, "SEO", "Missing meta description", "low", page.url,
                 "No meta description tag found.", "Add a concise meta description.")
        headings = soup.find_all("h1")
        if len(headings) == 0:
            _add(findings, "SEO", "Missing H1 heading", "low", page.url,
                 "No <h1> element found.", "Add a single descriptive H1 to the page.")
        elif len(headings) > 1:
            _add(findings, "SEO", "Multiple H1 headings", "info", page.url,
                 f"Found {len(headings)} <h1> elements.", "Use a single H1 per page for clear hierarchy.")
        if not soup.find("link", rel=lambda value: value and "canonical" in value):
            _add(findings, "SEO", "Missing canonical link", "info", page.url,
                 "No canonical link element found.", "Add rel='canonical' to avoid duplicate content issues.")
        if not soup.find("meta", attrs={"name": "viewport"}):
            _add(findings, "SEO", "Missing viewport meta tag", "low", page.url,
                 "No viewport meta tag found.", "Add <meta name='viewport' content='width=device-width, initial-scale=1'>.")
        html_tag = soup.find("html")
        if html_tag is None or not html_tag.get("lang"):
            _add(findings, "SEO", "Missing HTML lang attribute", "low", page.url,
                 "The <html> element has no lang attribute.", "Add a lang attribute to the <html> element.")
    return findings


def check_accessibility(crawl):
    findings = []
    for page in crawl.pages:
        if not page.is_html or not page.html:
            continue
        soup = BeautifulSoup(page.html, "html.parser")
        issues = []

        images = soup.find_all("img")
        no_alt = [img for img in images if not img.has_attr("alt")]
        if no_alt:
            issues.append(f"{len(no_alt)} image(s) without alt text")

        inputs = soup.find_all(["input", "select", "textarea"])
        unlabeled = 0
        label_for = {label.get("for") for label in soup.find_all("label") if label.get("for")}
        for field in inputs:
            field_type = (field.get("type") or "").lower()
            if field_type in ("hidden", "submit", "button", "reset", "image"):
                continue
            if field.get("aria-label") or field.get("aria-labelledby") or field.get("title"):
                continue
            if field.get("id") and field.get("id") in label_for:
                continue
            unlabeled += 1
        if unlabeled:
            issues.append(f"{unlabeled} form field(s) without an associated label")

        empty_links = [a for a in soup.find_all("a") if not a.get_text(strip=True) and not a.find("img", alt=True)]
        if empty_links:
            issues.append(f"{len(empty_links)} link(s) without accessible text")

        ids = [tag.get("id") for tag in soup.find_all(id=True)]
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        if duplicates:
            issues.append(f"duplicate id attribute(s): {', '.join(duplicates[:5])}")

        if soup.find(attrs={"tabindex": re.compile(r"^[1-9]")}):
            issues.append("positive tabindex values found")

        if issues:
            _add(findings, "Accessibility", "Accessibility issues found", "low", page.url,
                 "; ".join(issues), "Fix labels, alt text, accessible link names and duplicate IDs.")

    return findings


def check_mixed_content(crawl):
    findings = []
    for page in crawl.pages:
        if not page.is_html or not page.html or not page.url.startswith("https://"):
            continue
        insecure = []
        for resource, sources in crawl.resources.items():
            if resource.startswith("http://") and page.url in sources:
                insecure.append(resource)
        if insecure:
            _add(findings, "Security", "Mixed content (HTTP resources on HTTPS page)", "medium", page.url,
                 "Insecure resources: " + ", ".join(insecure[:5]),
                 "Load all subresources over HTTPS.")
    return findings


def check_performance(crawl):
    findings = []
    for page in crawl.pages:
        if not page.is_html:
            continue
        if page.elapsed_ms > 5000:
            _add(findings, "Performance", "Very slow response time", "medium", page.url,
                 f"Response took {page.elapsed_ms} ms", "Optimize server-side rendering, caching and database queries.")
        elif page.elapsed_ms > 2500:
            _add(findings, "Performance", "Slow response time", "low", page.url,
                 f"Response took {page.elapsed_ms} ms", "Optimize server-side rendering, caching and database queries.")
        if page.raw_size > 2_000_000:
            _add(findings, "Performance", "Very large HTML page", "low", page.url,
                 f"HTML size is {page.raw_size / 1024:.0f} KB", "Reduce HTML size and move inline data to separate resources.")
        if page.raw_size > 50_000 and "content-encoding" not in page.headers:
            _add(findings, "Performance", "Response is not compressed", "low", page.url,
                 f"HTML size {page.raw_size / 1024:.0f} KB with no Content-Encoding",
                 "Enable gzip or brotli compression on the server.")
        sources_count = sum(1 for sources in crawl.resources.values() if page.url in sources)
        if sources_count > 120:
            _add(findings, "Performance", "High number of subresources", "low", page.url,
                 f"{sources_count} resources referenced by this page",
                 "Bundle/minify assets and lazy-load non-critical resources.")
        if page.truncated:
            _add(findings, "Performance", "Response body exceeded scan limit", "info", page.url,
                 "Only the first 5 MB of the response was analyzed.",
                 "Check whether the page unnecessarily serves very large HTML.")
    return findings


def check_html_basics(crawl):
    findings = []
    for page in crawl.pages:
        if not page.is_html or not page.html:
            continue
        html_lower = page.html[:2000].lower()
        if "<!doctype" not in html_lower:
            _add(findings, "HTML Quality", "Missing DOCTYPE declaration", "low", page.url,
                 "The response does not start with a <!doctype> declaration.",
                 "Add a standards-mode DOCTYPE such as <!doctype html>.")
        if not re.search(r"<meta[^>]+charset", html_lower) and "charset=" not in page.content_type.lower():
            _add(findings, "HTML Quality", "Missing character encoding declaration", "low", page.url,
                 f"Content-Type: {page.content_type}",
                 "Declare UTF-8 via <meta charset='utf-8'> and the Content-Type header.")
        for signature in STACK_TRACE_SIGNATURES:
            if signature in page.html.lower():
                _add(findings, "Information Disclosure", "Error details / stack trace exposed", "high", page.url,
                     f"Response contains '{signature}'.", "Disable debug mode and return generic error pages in production.")
                break
    return findings


def check_cors(crawl):
    findings = []
    seen = set()
    for page in crawl.pages:
        origin = origin_of(page.url)
        if origin in seen or not page.headers:
            continue
        seen.add(origin)
        allow_origin = page.headers.get("access-control-allow-origin", "")
        allow_credentials = page.headers.get("access-control-allow-credentials", "").lower()
        if allow_origin == "*" and allow_credentials == "true":
            _add(findings, "CORS", "Wildcard CORS with credentials", "high", origin,
                 "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                 "Never combine wildcard origins with credentials; use an explicit allowlist.")
        elif allow_origin == "*":
            _add(findings, "CORS", "Wildcard CORS policy", "info", origin,
                 "Access-Control-Allow-Origin: *", "Restrict CORS to trusted origins if sensitive data is served.")
    return findings


def check_https_and_tls(start_url, session, timeout=15):
    findings = []
    parsed = urlparse(start_url)
    host = parsed.hostname

    if parsed.scheme == "http":
        https_url = "https://" + parsed.netloc + parsed.path
        result = fetch(session, https_url, timeout=timeout, read_body=False)
        if result.status and (result.final_url or result.url).startswith("https://"):
            _add(findings, "Transport Security", "Site is served over HTTP", "high", start_url,
                 f"HTTPS endpoint responded with HTTP {result.status}", "Redirect all HTTP traffic to HTTPS.")
        else:
            _add(findings, "Transport Security", "HTTPS is not available", "critical", start_url,
                 result.error or f"No HTTPS response ({result.status})", "Enable HTTPS with a valid certificate.")
    else:
        http_url = "http://" + parsed.netloc + parsed.path
        result = fetch(session, http_url, timeout=timeout, read_body=False)
        if result.status and not (result.final_url or result.url).startswith("https://"):
            _add(findings, "Transport Security", "HTTP does not redirect to HTTPS", "medium", http_url,
                 f"HTTP request ended at {result.url}", "Redirect HTTP to HTTPS with a permanent 301 redirect.")

    if host and parsed.scheme == "https":
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, parsed.port or 443), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
            not_after = cert.get("notAfter", "")
            if not_after:
                expiry = ssl.cert_time_to_seconds(not_after)
                days_left = (expiry - time.time()) / 86400
                if days_left < 0:
                    _add(findings, "Transport Security", "TLS certificate has expired", "critical", start_url,
                         f"Certificate expired on {not_after}", "Renew the TLS certificate immediately.")
                elif days_left < 30:
                    _add(findings, "Transport Security", "TLS certificate expires soon", "medium", start_url,
                         f"Certificate expires on {not_after} ({days_left:.0f} days left)",
                         "Renew or automate TLS certificate renewal.")
        except ssl.SSLError as exc:
            _add(findings, "Transport Security", "TLS certificate validation failed", "high", start_url,
                 str(exc), "Install a valid, trusted certificate chain.")
        except (socket.error, OSError) as exc:
            _add(findings, "Transport Security", "TLS connection failed", "high", start_url,
                 str(exc), "Verify the server is reachable on port 443 with a valid certificate.")

    return findings


def _parse_robots_groups(text):
    groups = []
    agents = []
    rules = []
    has_sitemap = False
    for raw_line in (text or "").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "sitemap":
            has_sitemap = True
            continue
        if key == "user-agent":
            if rules:
                groups.append((agents, rules))
                agents = []
                rules = []
            agents.append(value.lower())
        elif key in ("allow", "disallow"):
            if not agents:
                agents = ["*"]
            rules.append((key, value))
    if agents and rules:
        groups.append((agents, rules))
    return groups, has_sitemap


def check_robots(crawl):
    findings = []
    if crawl.robots_status == 0:
        return findings
    if crawl.robots_status >= 400:
        _add(findings, "SEO", "robots.txt is missing", "info", f"{origin_of(crawl.start_url)}/robots.txt",
             f"HTTP {crawl.robots_status}", "Add a robots.txt to guide crawlers and reference the sitemap.")
    else:
        groups, has_sitemap = _parse_robots_groups(crawl.robots_txt)
        blocks_all = any(
            "*" in agents and any(action == "disallow" and path in ("/", "/*") for action, path in rules)
            for agents, rules in groups
        )
        if blocks_all:
            _add(findings, "SEO", "robots.txt blocks all crawlers", "low", f"{origin_of(crawl.start_url)}/robots.txt",
                 truncate(crawl.robots_txt, 500), "Verify the Disallow rules are intentional.")
        if not has_sitemap:
            _add(findings, "SEO", "robots.txt does not reference a sitemap", "info", f"{origin_of(crawl.start_url)}/robots.txt",
                 truncate(crawl.robots_txt, 500), "Add a Sitemap: line to robots.txt.")
    return findings


def run_passive_checks(crawl, session, start_url, timeout=15, check_external=True, max_external=15):
    findings = []
    findings.extend(check_page_availability(crawl))
    findings.extend(check_security_headers(crawl))
    findings.extend(check_cookies(session, crawl))
    findings.extend(check_forms(crawl))
    findings.extend(check_seo(crawl))
    findings.extend(check_accessibility(crawl))
    findings.extend(check_mixed_content(crawl))
    findings.extend(check_performance(crawl))
    findings.extend(check_html_basics(crawl))
    findings.extend(check_cors(crawl))
    findings.extend(check_cors_misconfig(session, start_url, timeout=timeout))
    findings.extend(check_robots(crawl))
    findings.extend(check_https_and_tls(start_url, session, timeout=timeout))
    findings.extend(check_broken_links(crawl, session, timeout=timeout,
                                       check_external=check_external, max_external=max_external))
    return findings


def run_active_checks(crawl, session, timeout=15, max_pages=10, sql_time=False):
    findings = []
    findings.extend(check_reflection_xss(crawl, session, timeout=timeout, max_pages=max_pages))
    findings.extend(check_sql_injection(crawl, session, timeout=timeout, max_pages=max_pages, time_based=sql_time))
    findings.extend(check_sensitive_paths(session, crawl.start_url, timeout=timeout))
    return findings


# ---------------------------------------------------------------------------
# JavaScript secret scanning
# ---------------------------------------------------------------------------

JS_SECRET_PATTERNS = [
    ("Private key", "high", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("AWS access key", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", "high", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Stripe live secret key", "high", re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b")),
    ("Google API key", "low", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Firebase server key", "medium", re.compile(r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{120,}\b")),
    ("Generic API key assignment", "low", re.compile(
        r"(?i)\b(?:api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token)\b\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{16,})['\"]"
    )),
]

SECRET_PLACEHOLDERS = (
    "example", "sample", "dummy", "placeholder", "changeme", "your_", "your-",
    "xxxx", "000000", "123456", "localhost", "test-key", "test_key", "abcdef",
)


def _mask_secret(value):
    if not value:
        return ""
    if len(value) <= 8:
        return value[0] + "***"
    return value[:4] + "..." + value[-4:]


def _looks_like_placeholder(value):
    lowered = (value or "").lower()
    return any(hint in lowered for hint in SECRET_PLACEHOLDERS)


def check_js_secrets(crawl, session, timeout=15, max_files=20):
    findings = []
    seen = set()

    js_urls = []
    for resource in crawl.resources:
        if not same_site(resource, crawl.start_url):
            continue
        path = urlparse(resource).path.lower()
        if path.endswith(".js") or path.endswith(".mjs"):
            js_urls.append(resource)

    sources = [(url, None) for url in _unique(js_urls)[:max_files]]
    inline_pages = 0
    for page in crawl.pages:
        if not page.html or not page.is_html:
            continue
        if inline_pages >= max_files:
            break
        inline_pages += 1
        try:
            soup = BeautifulSoup(page.html, "html.parser")
        except Exception:
            continue
        for script in soup.find_all("script"):
            if script.get("src"):
                continue
            body = script.string or script.get_text() or ""
            if body.strip():
                sources.append((page.url + "#inline", body))

    for url, inline_body in sources:
        if inline_body is None:
            result = fetch(session, url, timeout=timeout)
            if result.status != 200 or not result.html:
                continue
            body = result.html
        else:
            body = inline_body

        hits = 0
        for name, severity, pattern in JS_SECRET_PATTERNS:
            for match in pattern.finditer(body):
                value = match.group(1) if pattern.groups and match.group(1) else match.group(0)
                if not value or _looks_like_placeholder(value):
                    continue
                key = (name, url, hashlib.sha1(value.encode("utf-8", "ignore")).hexdigest())
                if key in seen:
                    continue
                seen.add(key)
                context = body[max(0, match.start() - 40):match.end() + 40]
                context = context.replace(value, _mask_secret(value)) if value in context else context
                _add(findings, "Secrets", f"Potential {name} found in client-side JavaScript", severity, url,
                     f"Masked value: {_mask_secret(value)} | Context: {truncate(context, 240)}",
                     "Remove the secret from client-side code, rotate it, and keep it on the server side.")
                hits += 1
                if hits >= 5:
                    break
            if hits >= 5:
                break

    return findings


# ---------------------------------------------------------------------------
# .well-known / security.txt
# ---------------------------------------------------------------------------

def check_well_known(session, start_url, timeout=15):
    findings = []
    origin = origin_of(start_url)
    candidates = [
        f"{origin}/.well-known/security.txt",
        f"{origin}/security.txt",
    ]
    for url in candidates:
        result = fetch(session, url, timeout=timeout)
        if result.status == 200 and "contact:" in (result.html or "").lower():
            _add(findings, "Security Policy", "security.txt is published", "info", url,
                 truncate(result.html, 600),
                 "Keep the Contact and Expires fields current so researchers can report issues safely.")
            return findings
        if result.status in (401, 403, 429):
            return findings
    _add(findings, "Security Policy", "No security.txt published", "info", f"{origin}/.well-known/security.txt",
         "Neither /.well-known/security.txt nor /security.txt returned a valid policy.",
         "Publish a security.txt with a monitored Contact address and an Expires date.")
    return findings


# ---------------------------------------------------------------------------
# Technology fingerprinting
# ---------------------------------------------------------------------------

def check_tech_stack(crawl):
    findings = []
    if not crawl.pages:
        return findings
    headers = {}
    for page in crawl.pages:
        if page.headers:
            headers = page.headers
            break
    body = ""
    for page in crawl.pages:
        if page.is_html and page.html:
            body = page.html[:200000]
            break
    cookie_names = " ".join(sorted({
        p.headers.get("set-cookie", "") for p in crawl.pages if p.headers.get("set-cookie")
    }))
    server = headers.get("server", "").lower()
    powered = headers.get("x-powered-by", "").lower()
    detected = []

    def add(name):
        if name not in detected:
            detected.append(name)

    if "cf-ray" in headers or "cloudflare" in server:
        add("Cloudflare")
    if "x-amz-cf-id" in headers or "cloudfront" in headers.get("via", "").lower():
        add("Amazon CloudFront")
    if "x-azure-ref" in headers or "azure" in headers.get("x-ms-request-id", "").lower():
        add("Microsoft Azure")
    if "nginx" in server:
        add("nginx")
    if "apache" in server:
        add("Apache HTTP Server")
    if "iis" in server or "microsoft-iis" in server:
        add("Microsoft IIS")
    if "python" in server or "simplehttp" in server:
        add("Python HTTP server")
    if "werkzeug" in server:
        add("Flask / Werkzeug")
    if "gunicorn" in server:
        add("Gunicorn")
    if "envoy" in server:
        add("Envoy proxy")
    if "express" in powered:
        add("Express.js")
    if "php" in powered:
        add("PHP")
    if "asp.net" in powered or ".aspnet" in cookie_names.lower() or "aspnet" in cookie_names.lower():
        add("ASP.NET")
    if "next.js" in powered or "__NEXT_DATA__" in body:
        add("Next.js")
    if "react" in body.lower() and ("data-reactroot" in body or "_react" in body):
        add("React")
    if "__VUE__" in body or "data-v-" in body:
        add("Vue.js")
    if "ng-version" in body:
        add("Angular")
    if "jquery" in body.lower():
        add("jQuery")
    if "wp-content" in body or "wp-includes" in body:
        add("WordPress")
    if "drupal" in body.lower():
        add("Drupal")
    if "cdn.shopify.com" in body:
        add("Shopify")
    if "auth0" in body.lower() or "auth0" in cookie_names.lower():
        add("Auth0")
    if "sentry" in body.lower():
        add("Sentry")
    if "googletagmanager.com" in body:
        add("Google Tag Manager")
    if "cloudflareaccess" in body.lower():
        add("Cloudflare Access")
    if "cdn.redoc.ly" in body or "redoc.standalone" in body:
        add("Redoc (API docs)")

    if detected:
        _add(findings, "Fingerprint", "Technology stack detected", "info", origin_of(crawl.start_url),
             "Detected: " + ", ".join(detected),
             "Review component versions and vendor-specific defaults for known issues.")
    return findings


# ---------------------------------------------------------------------------
# HTTP OPTIONS method
# ---------------------------------------------------------------------------

RISKY_HTTP_METHODS = {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT", "PROPFIND", "MKCOL"}


def check_options_method(session, start_url, timeout=15):
    findings = []
    try:
        response = session.request("OPTIONS", origin_of(start_url) + "/", timeout=timeout, allow_redirects=True)
    except Exception:
        return findings
    allow = response.headers.get("allow", "")
    if not allow:
        return findings
    methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
    risky = sorted(methods & RISKY_HTTP_METHODS)
    if risky:
        _add(findings, "HTTP Methods", "Risky HTTP methods advertised", "info", origin_of(start_url),
             f"Allow: {allow} | Risky methods: {', '.join(risky)}",
             "Disable unused HTTP methods at the edge or application layer unless required.")
    return findings


# ---------------------------------------------------------------------------
# Active CORS origin-reflection probe (2 requests)
# ---------------------------------------------------------------------------

def check_cors_misconfig(session, start_url, timeout=15):
    findings = []
    origin = origin_of(start_url)
    probes = ["https://bugfinder-test.example", "null"]
    for probe in probes:
        try:
            response = session.get(
                origin + "/", headers={"Origin": probe}, timeout=timeout, allow_redirects=False,
            )
        except Exception:
            continue
        allow = response.headers.get("access-control-allow-origin", "")
        creds = response.headers.get("access-control-allow-credentials", "").lower()
        if allow != probe:
            continue
        if creds == "true":
            _add(findings, "CORS", "CORS reflects arbitrary origin with credentials", "high", origin,
                 f"Origin: {probe} -> Access-Control-Allow-Origin: {allow}, "
                 f"Access-Control-Allow-Credentials: {creds}",
                 "Validate the Origin against a strict allowlist and never reflect arbitrary origins with credentials.")
        else:
            _add(findings, "CORS", "CORS reflects arbitrary origin", "medium", origin,
                 f"Origin: {probe} -> Access-Control-Allow-Origin: {allow}",
                 "Use an explicit origin allowlist instead of reflecting the request Origin header.")
    return findings
