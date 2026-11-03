from dataclasses import dataclass, field
from typing import Any


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

SEVERITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}


@dataclass
class Finding:
    category: str
    title: str
    severity: str
    url: str = ""
    evidence: str = ""
    remediation: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER:
            self.severity = "info"

    def dedup_key(self) -> tuple:
        return (self.category, self.title, self.url, self.evidence[:300])

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "url": self.url,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "extra": self.extra,
        }


@dataclass
class PageData:
    url: str
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    html: str = ""
    raw_size: int = 0
    elapsed_ms: int = 0
    content_type: str = ""
    final_url: str = ""
    error: str = ""
    truncated: bool = False
    is_html: bool = False


@dataclass
class FormData:
    page_url: str
    action: str
    method: str
    enctype: str
    inputs: list[dict[str, str]] = field(default_factory=list)
    has_password: bool = False
    csrf_names: list[str] = field(default_factory=list)
    submit_text: str = ""


@dataclass
class LinkData:
    target: str
    source: str
    text: str = ""


@dataclass
class CrawlResult:
    start_url: str
    pages: list[PageData] = field(default_factory=list)
    links: dict[str, set[str]] = field(default_factory=dict)
    external_links: dict[str, set[str]] = field(default_factory=dict)
    forms: list[FormData] = field(default_factory=list)
    resources: dict[str, set[str]] = field(default_factory=dict)
    robots_txt: str = ""
    robots_status: int = 0
    visited_count: int = 0


@dataclass
class ScanResult:
    target: str
    started_at: str
    finished_at: str
    duration_seconds: float
    findings: list[Finding] = field(default_factory=list)
    pages_scanned: int = 0
    screenshots: dict[str, str] = field(default_factory=dict)
    stats: dict[str, Any] = field(default_factory=dict)

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.category, f.title, f.url),
        )

    def counts(self) -> dict[str, int]:
        result = {key: 0 for key in SEVERITY_ORDER}
        for finding in self.findings:
            result[finding.severity] = result.get(finding.severity, 0) + 1
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "pages_scanned": self.pages_scanned,
            "stats": self.stats,
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
