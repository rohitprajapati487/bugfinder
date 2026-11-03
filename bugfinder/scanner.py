import sys
from datetime import datetime

from . import checks
from .crawler import build_session, crawl
from .models import SEVERITY_ORDER, ScanResult
from .report import build_html, build_json, build_markdown
from .utils import origin_of, same_site


def _log(message, quiet=False):
    if not quiet:
        print(f"[bugfinder] {message}", file=sys.stderr, flush=True)


def _dedup(findings):
    seen = {}
    for finding in findings:
        key = finding.dedup_key()
        current = seen.get(key)
        if current is None or SEVERITY_ORDER.get(finding.severity, 9) < SEVERITY_ORDER.get(current.severity, 9):
            seen[key] = finding
    return list(seen.values())


def scan(
    target,
    max_pages=25,
    max_depth=2,
    timeout=15,
    delay=0.3,
    active=True,
    external=True,
    max_external=15,
    use_playwright=True,
    max_runtime_pages=10,
    quiet=False,
    cookie=None,
    headers=None,
    js_secrets=True,
    max_js_files=20,
    wellknown=True,
    tech_detect=True,
    options_check=True,
    sql_time=False,
):
    started = datetime.now()
    _log(f"Starting scan of {target}", quiet)
    session = build_session(cookie=cookie, headers=headers, min_interval=delay)

    crawl_result = crawl(
        target,
        max_pages=max_pages,
        max_depth=max_depth,
        timeout=timeout,
        delay=delay,
        session=session,
    )
    _log(
        f"Crawled {len(crawl_result.pages)} page(s), discovered {len(crawl_result.links)} link(s), "
        f"{len(crawl_result.forms)} form(s)",
        quiet,
    )

    findings = []
    findings.extend(checks.run_passive_checks(
        crawl_result, session, crawl_result.start_url,
        timeout=timeout, check_external=external, max_external=max_external,
    ))
    if js_secrets:
        findings.extend(checks.check_js_secrets(
            crawl_result, session, timeout=timeout, max_files=max_js_files,
        ))
    if wellknown:
        findings.extend(checks.check_well_known(session, crawl_result.start_url, timeout=timeout))
    if tech_detect:
        findings.extend(checks.check_tech_stack(crawl_result))
    _log(f"Passive checks finished ({len(findings)} finding(s))", quiet)

    if active:
        findings.extend(checks.run_active_checks(
            crawl_result, session, timeout=timeout, max_pages=max(1, min(max_pages, 12)),
            sql_time=sql_time,
        ))
        if options_check:
            findings.extend(checks.check_options_method(session, crawl_result.start_url, timeout=timeout))
        _log(f"Active checks finished ({len(findings)} finding(s))", quiet)

    screenshots = {}
    if use_playwright:
        try:
            from .playwright_runner import is_available, run_runtime_checks
            if is_available():
                urls = [p.url for p in crawl_result.pages if p.is_html and 0 < p.status < 400]
                if not urls:
                    urls = [crawl_result.start_url]
                _log(f"Running browser checks on {min(len(urls), max_runtime_pages)} page(s)", quiet)
                runtime_findings, screenshots, runtime_errors = run_runtime_checks(
                    urls, timeout_ms=timeout * 1000, max_pages=max_runtime_pages,
                    cookie=cookie, extra_headers=headers,
                )
                findings.extend(runtime_findings)
                for error in runtime_errors:
                    _log(f"Browser warning: {error}", quiet)
            else:
                _log("Playwright not installed; skipping browser rendering checks", quiet)
        except Exception as exc:
            _log(f"Browser checks skipped: {type(exc).__name__}: {exc}", quiet)

    findings = _dedup(findings)
    finished = datetime.now()

    result = ScanResult(
        target=crawl_result.start_url,
        started_at=started.strftime("%Y-%m-%d %H:%M:%S"),
        finished_at=finished.strftime("%Y-%m-%d %H:%M:%S"),
        duration_seconds=(finished - started).total_seconds(),
        findings=findings,
        pages_scanned=len(crawl_result.pages),
        screenshots=screenshots,
        stats={
            "links": len(crawl_result.links),
            "external_links": len([u for u in crawl_result.external_links if not same_site(u, crawl_result.start_url)]),
            "forms": len(crawl_result.forms),
            "resources": len(crawl_result.resources),
            "origin": origin_of(crawl_result.start_url),
            "active_checks": active,
            "browser_checks": bool(screenshots) or use_playwright,
            "requests": getattr(session, "request_count", 0),
        },
    )
    _log(
        f"Scan finished in {result.duration_seconds:.1f}s with {len(findings)} finding(s) "
        f"({getattr(session, 'request_count', 0)} requests)",
        quiet,
    )
    return result, crawl_result


def write_reports(result, output_path, json_path=None, md_path=None):
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(build_html(result))
    if json_path:
        with open(json_path, "w", encoding="utf-8") as handle:
            handle.write(build_json(result))
    if md_path:
        with open(md_path, "w", encoding="utf-8") as handle:
            handle.write(build_markdown(result))
