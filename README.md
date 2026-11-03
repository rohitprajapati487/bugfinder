# BugFinder

A lightweight, ethical web security scanner for authorized testing. It crawls a target, runs passive and active checks, optionally renders pages in a real browser, and produces self-contained HTML, JSON, and Markdown reports.

> **Authorized testing only.** Use BugFinder only on systems you own or have explicit written permission to test. You are responsible for complying with the target's bug bounty policy and applicable law.

## Features

- **Crawling** with configurable page/depth limits, request throttling, and same-site enforcement
- **Passive checks** for security headers, cookie flags, forms, CORS, TLS, mixed content, SEO, accessibility, performance, exposed error details, and broken links
- **Active checks** for reflected XSS, error-based and time-based SQL injection, sensitive paths, risky HTTP methods, and CORS origin reflection
- **JavaScript secret scanning** with masking, placeholder filtering, and deduplication
- **Technology fingerprinting** for common servers, frameworks, CDNs, and SaaS services
- **Browser runtime checks** with Playwright: console errors, uncaught exceptions, failed requests, broken images, slow loads, large DOM, and layout overflow
- **Reports** in HTML, JSON, and Markdown with severity filters, search, category grouping, curl reproduction commands, and screenshots
- **Safety controls** including request rate limiting, request caps, response-size limits, soft-404 filtering, first-party filtering, and finding deduplication

## Installation

```bash
git clone https://github.com/rohitprajapati487/bugfinder.git
cd bugfinder

python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

For browser rendering checks:

```bash
pip install -e ".[browser]"
playwright install chromium
```

## Usage

```bash
# Basic scan with HTML, JSON, and Markdown reports
bugfinder https://example.com \
  --json report.json \
  --md report.md

# Authenticated scan
bugfinder https://example.com \
  --cookie "session=abc123" \
  --header "Authorization: Bearer TOKEN"

# Read-only scan without active probes or a browser
bugfinder https://example.com --no-active --no-playwright

# Enable slower time-based SQL injection probes
bugfinder https://example.com --sql-time
```

You can also run it without installing the console script:

```bash
python -m bugfinder https://example.com
```

## Common options

| Option | Description |
| --- | --- |
| `--max-pages`, `--max-depth` | Crawl limits |
| `--timeout`, `--delay` | Request timeout and minimum delay |
| `--cookie`, `--header` | Authentication headers; cookies can be loaded with `@file` |
| `--json`, `--md`, `-o` | JSON, Markdown, and HTML report paths |
| `--no-active` | Disable XSS, SQLi, and sensitive-path probes |
| `--no-playwright` | Disable browser rendering checks |
| `--no-js-secrets` | Disable JavaScript secret scanning |
| `--no-wellknown`, `--no-tech-detect`, `--no-options` | Disable individual checks |
| `--sql-time` | Enable time-based blind SQL injection probes |
| `--fail-on` | Exit non-zero when a finding at or above a severity exists |
| `--quiet` | Suppress progress output |

Run `bugfinder --help` for the full list.

## Reports

A scan writes an HTML report by default. Add `--json` and `--md` to export machine-readable and human-readable versions.

The HTML report includes:

- Severity summary cards
- Severity and category filters
- Full-text search
- Grouped findings with evidence and remediation
- `curl` reproduction commands
- Browser screenshots with a lightbox

## Project structure

```text
bugfinder/
  cli.py               CLI argument parsing and entry point
  scanner.py           Scan orchestration and report writing
  crawler.py           Crawling, sessions, forms, and resources
  checks.py            Passive and active security checks
  playwright_runner.py Browser runtime checks and screenshots
  report.py            HTML, JSON, and Markdown report generation
  models.py            Data models
  utils.py             URL and text helpers
```

## Limitations

BugFinder uses automated heuristics. Findings are leads, not confirmed vulnerabilities, and may include false positives. Always verify manually before reporting. It is not a replacement for manual testing, business-logic review, or authenticated access-control testing.

## Contributing

Issues and pull requests are welcome. Please keep tests and changes focused, avoid destructive probes, and never include real credentials, tokens, or target data in commits.

## License

MIT. See [LICENSE](LICENSE).
