import threading
import time
from collections import deque
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from .models import CrawlResult, FormData, PageData
from .utils import (
    is_crawlable_url,
    is_probably_binary,
    normalize_url,
    same_site,
    truncate,
)


USER_AGENT = (
    "Mozilla/5.0 (compatible; BugFinder/1.0; +https://example.com/bugfinder) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)

MAX_BODY_BYTES = 5_000_000


class ThrottledSession(requests.Session):
    """Session that keeps a minimum interval between all outgoing requests."""

    def __init__(self, min_interval=0.0):
        super().__init__()
        self.min_interval = max(0.0, float(min_interval or 0.0))
        self._last_request = 0.0
        self._lock = threading.Lock()
        self.request_count = 0

    def request(self, *args, **kwargs):
        self.request_count += 1
        if self.min_interval > 0:
            with self._lock:
                wait = self.min_interval - (time.monotonic() - self._last_request)
                if wait > 0:
                    time.sleep(wait)
                self._last_request = time.monotonic()
        return super().request(*args, **kwargs)


def parse_cookie_string(cookie):
    jar = {}
    for part in (cookie or "").split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        if name:
            jar[name] = value.strip()
    return jar


def build_session(cookie=None, headers=None, min_interval=0.0):
    session = ThrottledSession(min_interval=min_interval)
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })
    if headers:
        session.headers.update(headers)
    if cookie:
        session.cookies.update(parse_cookie_string(cookie))
    return session


def fetch(session, url, timeout=15, read_body=True):
    started = time.monotonic()
    page = PageData(url=url)
    try:
        response = session.get(url, timeout=timeout, allow_redirects=True, stream=True)
        page.status = response.status_code
        page.headers = {k.lower(): v for k, v in response.headers.items()}
        page.content_type = page.headers.get("content-type", "")
        page.final_url = response.url or url
        page.is_html = "html" in page.content_type.lower() or (
            not page.content_type and url.endswith(("/", ".html", ".htm"))
        )
        if read_body and not is_probably_binary(page.content_type):
            chunks = []
            total = 0
            for chunk in response.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total >= MAX_BODY_BYTES:
                    page.truncated = True
                    break
            body = b"".join(chunks)
            page.raw_size = total
            encoding = response.encoding or "utf-8"
            try:
                page.html = body.decode(encoding, errors="replace")
            except (LookupError, UnicodeError):
                page.html = body.decode("utf-8", errors="replace")
        else:
            page.raw_size = int(page.headers.get("content-length") or 0)
        response.close()
    except requests.RequestException as exc:
        page.error = f"{type(exc).__name__}: {exc}"
    page.elapsed_ms = int((time.monotonic() - started) * 1000)
    return page


def parse_forms(soup, page_url):
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or page_url
        action = normalize_url(action, base=page_url) or page_url
        method = (form.get("method") or "get").strip().lower()
        enctype = (form.get("enctype") or "").strip().lower()
        inputs = []
        has_password = False
        csrf_names = []
        for field in form.find_all(["input", "textarea", "select", "button"]):
            name = (field.get("name") or field.get("id") or "").strip()
            field_type = (field.get("type") or field.name or "").strip().lower()
            if field_type == "password":
                has_password = True
            lowered = name.lower()
            if lowered and any(token in lowered for token in (
                "csrf", "_token", "authenticity_token", "xsrf", "requestverificationtoken",
            )):
                csrf_names.append(name)
            if name:
                inputs.append({"name": name, "type": field_type})
        submit = form.find(["button", "input"], attrs={"type": "submit"})
        submit_text = ""
        if submit is not None:
            submit_text = submit.get_text(strip=True) or (submit.get("value") or "")
        forms.append(FormData(
            page_url=page_url,
            action=action,
            method=method,
            enctype=enctype,
            inputs=inputs,
            has_password=has_password,
            csrf_names=csrf_names,
            submit_text=submit_text,
        ))
    return forms


def collect_links(soup, page_url):
    links = {}
    resources = {}
    for anchor in soup.find_all("a", href=True):
        href = anchor["href"].strip()
        if not href or href.startswith("#"):
            continue
        target = normalize_url(href, base=page_url)
        if not target:
            continue
        links[target] = anchor.get_text(" ", strip=True)[:120]
    for tag, attr in (
        ("script", "src"),
        ("link", "href"),
        ("img", "src"),
        ("img", "srcset"),
        ("iframe", "src"),
        ("source", "src"),
        ("video", "src"),
        ("audio", "src"),
    ):
        for element in soup.find_all(tag):
            value = element.get(attr)
            if not value:
                continue
            if attr == "srcset":
                candidates = [part.strip().split(" ")[0] for part in value.split(",")]
            else:
                candidates = [value]
            for candidate in candidates:
                resource = normalize_url(candidate, base=page_url)
                if resource:
                    resources.setdefault(resource, set()).add(page_url)
    return links, resources


def crawl(start_url, max_pages=25, max_depth=2, timeout=15, delay=0.3, session=None):
    start_url = normalize_url(start_url)
    if not start_url:
        raise ValueError("Invalid start URL")

    session = session or build_session()
    result = CrawlResult(start_url=start_url)

    try:
        robots = fetch(session, urljoin(start_url, "/robots.txt"), timeout=timeout)
        result.robots_status = robots.status
        result.robots_txt = truncate(robots.html, 4000)
    except Exception:
        pass

    queue = deque([(start_url, 0)])
    seen = set()

    while queue and len(result.pages) < max_pages:
        url, depth = queue.popleft()
        if url in seen:
            continue
        seen.add(url)
        if not same_site(url, start_url):
            continue
        if not is_crawlable_url(url):
            continue

        page = fetch(session, url, timeout=timeout)
        result.pages.append(page)
        result.visited_count += 1

        if not page.is_html or not page.html or page.status >= 400:
            if delay:
                time.sleep(delay)
            continue

        try:
            soup = BeautifulSoup(page.html, "html.parser")
        except Exception:
            if delay:
                time.sleep(delay)
            continue

        result.forms.extend(parse_forms(soup, url))
        links, resources = collect_links(soup, url)

        for target, text in links.items():
            result.links.setdefault(target, set()).add(url)
            if same_site(target, start_url):
                if depth < max_depth:
                    queue.append((target, depth + 1))
            else:
                result.external_links.setdefault(target, set()).add(url)

        for resource, sources in resources.items():
            result.resources.setdefault(resource, set()).update(sources)
            if not same_site(resource, start_url):
                result.external_links.setdefault(resource, set()).add(next(iter(sources)))

        if delay:
            time.sleep(delay)

    return result
