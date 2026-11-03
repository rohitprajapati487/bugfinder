import base64
import time
from urllib.parse import urlparse

from .models import Finding
from .utils import truncate


def _first_party(target, base_host):
    host = (urlparse(target).hostname or "").lower()
    if not host or not base_host:
        return False
    return host == base_host or host.endswith("." + base_host) or base_host.endswith("." + host)


def is_available():
    try:
        import playwright.sync_api  # noqa: F401
        return True
    except Exception:
        return False


def _parse_cookie_header(cookie):
    jar = []
    for part in (cookie or "").split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        if name:
            jar.append({"name": name, "value": value.strip()})
    return jar


def run_runtime_checks(urls, timeout_ms=20000, max_pages=10, screenshots=True,
                       cookie=None, extra_headers=None):
    from playwright.sync_api import sync_playwright

    findings = []
    shots = {}
    errors = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
        context = browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1366, "height": 768},
            user_agent=(
                "Mozilla/5.0 (compatible; BugFinder/1.0) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
            ),
            extra_http_headers=extra_headers or None,
        )
        if cookie and urls:
            parsed = urlparse(urls[0])
            origin = f"{parsed.scheme}://{parsed.netloc}"
            cookies = _parse_cookie_header(cookie)
            for item in cookies:
                item["url"] = origin
            if cookies:
                try:
                    context.add_cookies(cookies)
                except Exception:
                    pass

        for url in urls[:max_pages]:
            page = context.new_page()
            console_errors = []
            page_errors = []
            failed_requests = []
            bad_responses = []

            page.on("console", lambda msg, bucket=console_errors: bucket.append(msg.text) if msg.type == "error" else None)
            page.on("pageerror", lambda exc, bucket=page_errors: bucket.append(str(exc)))
            page.on("requestfailed", lambda req, bucket=failed_requests: bucket.append(f"{req.url} ({req.failure})"))
            page.on("response", lambda resp, bucket=bad_responses: bucket.append(f"{resp.status} {resp.url}") if resp.status >= 400 else None)

            started = time.monotonic()
            try:
                try:
                    page.goto(url, wait_until="load", timeout=timeout_ms)
                except Exception:
                    page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                load_ms = int((time.monotonic() - started) * 1000)
                try:
                    page.wait_for_load_state("networkidle", timeout=3000)
                except Exception:
                    pass

                try:
                    dom_nodes = page.evaluate("document.querySelectorAll('*').length")
                except Exception:
                    dom_nodes = 0
                try:
                    broken_images = page.evaluate(
                        "Array.from(document.images).filter(i => {"
                        "  const src = i.currentSrc || i.src || '';"
                        "  if (!src || src.startsWith('data:') || src === location.href) return false;"
                        "  return !i.complete || i.naturalWidth === 0 || i.naturalHeight === 0;"
                        "}).map(i => i.currentSrc || i.src).slice(0, 20)"
                    )
                except Exception:
                    broken_images = []
                try:
                    horizontal_overflow = page.evaluate(
                        "document.documentElement.scrollWidth > document.documentElement.clientWidth + 5"
                    )
                except Exception:
                    horizontal_overflow = False

                if screenshots:
                    try:
                        data = page.screenshot(type="jpeg", quality=45, full_page=False)
                        shots[url] = base64.b64encode(data).decode("ascii")
                    except Exception:
                        pass

                if load_ms > 6000:
                    findings.append(Finding("Performance", "Page takes very long to fully load", "medium", url,
                                            f"Browser load event fired after {load_ms} ms",
                                            "Reduce render-blocking resources and optimize server response."))
                elif load_ms > 3500:
                    findings.append(Finding("Performance", "Slow browser load time", "low", url,
                                            f"Browser load event fired after {load_ms} ms",
                                            "Reduce render-blocking resources and optimize server response."))
                if dom_nodes > 2500:
                    findings.append(Finding("Performance", "Very large DOM tree", "low", url,
                                            f"{dom_nodes} DOM nodes after rendering",
                                            "Simplify markup and virtualize long lists."))
                if horizontal_overflow:
                    findings.append(Finding("UI / Rendering", "Horizontal overflow on desktop viewport", "low", url,
                                            "Document scroll width exceeds viewport width at 1366x768",
                                            "Fix responsive layout so content does not overflow horizontally."))
                if broken_images:
                    findings.append(Finding("Broken Links", "Broken or unloaded images", "medium", url,
                                            "Images failed to load: " + ", ".join(broken_images[:5]),
                                            "Fix image paths or serve valid image files."))
            except Exception as exc:
                errors.append(f"{url}: {exc}")
                msg = str(exc)
                if "Timeout" in msg:
                    findings.append(Finding("Availability", "Page navigation timeout in browser", "medium", url,
                                            truncate(msg, 500),
                                            "Increase timeout or allow 'domcontentloaded' for heavy SPAs."))
                else:
                    findings.append(Finding("Availability", "Page failed in real browser", "high", url,
                                            truncate(msg, 500),
                                            "Check JavaScript errors, timeouts or blocked resources."))

            for message in dict.fromkeys(console_errors):
                findings.append(Finding("JavaScript", "Console error in browser", "low", url,
                                        truncate(message, 600),
                                        "Fix JavaScript errors reported in the browser console."))
            for message in dict.fromkeys(page_errors):
                findings.append(Finding("JavaScript", "Uncaught JavaScript exception", "medium", url,
                                        truncate(message, 800),
                                        "Fix the uncaught exception and add error handling."))
            base_host = (urlparse(url).hostname or "").lower()
            for message in dict.fromkeys(failed_requests):
                target = message.split(" (", 1)[0]
                if not _first_party(target, base_host):
                    continue
                findings.append(Finding("Network", "Network request failed", "medium", url,
                                        truncate(message, 600),
                                        "Fix the failing request or remove the reference."))
            for message in dict.fromkeys(bad_responses):
                parts = message.split(" ", 1)
                target = parts[1] if len(parts) > 1 else ""
                if target == url or not _first_party(target, base_host):
                    continue
                findings.append(Finding("Network", "Subresource returned an error status", "low", url,
                                        truncate(message, 600),
                                        "Fix the failing subresource (image/script/style/API)."))

            page.close()

        context.close()
        browser.close()

    return findings, shots, errors
