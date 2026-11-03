import re
from urllib.parse import urljoin, urlparse, urlunparse


SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp", ".tiff",
    ".css", ".js", ".mjs", ".map", ".json", ".xml", ".rss", ".atom",
    ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
    ".mp3", ".mp4", ".avi", ".mov", ".webm", ".ogg", ".wav", ".flac",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".exe", ".dmg", ".apk", ".bin", ".iso",
}

SKIP_SCHEMES = {"mailto", "tel", "javascript", "data", "ftp", "file", "sms", "whatsapp", "blob"}

DEFAULT_PORTS = {"http": 80, "https": 443}

XSS_MARKER = "bfxzq9271"


def normalize_url(url, base=None):
    if not url:
        return None
    url = url.strip()
    if base:
        url = urljoin(base, url)
    if url.startswith("//"):
        scheme = urlparse(base).scheme if base else "https"
        url = f"{scheme}:{url}"
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https"):
        return None
    if not parsed.hostname:
        return None
    netloc = parsed.hostname.lower()
    if parsed.port and parsed.port != DEFAULT_PORTS.get(parsed.scheme):
        netloc = f"{netloc}:{parsed.port}"
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, netloc, path, parsed.params, parsed.query, ""))


def origin_of(url):
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def same_site(url, base):
    a = urlparse(url)
    b = urlparse(base)
    return (a.hostname or "").lower() == (b.hostname or "").lower()


def is_crawlable_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    path = parsed.path.lower()
    for ext in SKIP_EXTENSIONS:
        if path.endswith(ext):
            return False
    return True


def is_probably_binary(content_type):
    if not content_type:
        return False
    lowered = content_type.lower()
    return not any(token in lowered for token in ("text", "html", "xml", "json", "javascript"))


def truncate(text, limit=1200):
    if not text:
        return ""
    text = str(text)
    if len(text) <= limit:
        return text
    return text[:limit] + "... [truncated]"


def safe_text(value):
    return re.sub(r"\s+", " ", str(value or "")).strip()


def strip_query(url):
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", ""))
