# BugFinder — Portfolio Notes

## One-line description

BugFinder is an ethical web-security scanner that crawls a target, runs 20+ passive and active checks, adds Playwright browser analysis, and generates HTML, JSON, and Markdown reports.

## Short project description

BugFinder is a modular Python security scanner built for authorized web assessments. It crawls a target, checks security headers, cookies, CORS, TLS, forms, exposed paths, reflected XSS, SQL injection, and client-side JavaScript secrets, then optionally renders pages in a real browser to catch runtime, network, and layout issues. Findings are deduplicated and exported as interactive HTML, structured JSON, or Markdown reports with evidence, reproduction commands, and remediation guidance.

## Resume bullets

- Built **BugFinder**, a modular Python web-security scanner with **20+ passive and active checks** covering security headers, cookies, CORS, TLS, forms, sensitive paths, reflected XSS, SQL injection, and JavaScript secrets.
- Integrated **Playwright browser automation** to detect console errors, uncaught exceptions, failed first-party requests, broken assets, slow loads, large DOM trees, and horizontal overflow, with screenshot capture in reports.
- Engineered scan safety and signal quality using **request throttling, request caps, soft-404 filtering, response-size limits, finding deduplication, and secret masking**, and packaged the tool as an installable CLI with HTML, JSON, and Markdown output.

## LinkedIn / portfolio post

> I built **BugFinder**, a Python-based web-security scanner for authorized testing.
>
> It crawls a target, runs 20+ passive and active checks, uses Playwright for browser runtime analysis, and generates interactive HTML, JSON, and Markdown reports with evidence and remediation guidance.
>
> The project includes an installable CLI, a local vulnerable demo site, and a reproducible 32-finding sample report.
>
> Repo: https://github.com/rohitprajapati487/bugfinder
>
> #cybersecurity #python #bugbounty #opensource #websecurity

## Skills demonstrated

- Python application architecture and CLI design
- Web crawling, HTTP sessions, and request throttling
- Web security fundamentals: headers, cookies, CORS, TLS, XSS, SQLi, access control
- Playwright browser automation and runtime diagnostics
- Report generation; HTML, JSON, and Markdown output
- False-positive reduction: soft-404 detection, deduplication, placeholder filtering
- Responsible testing and scope/safety controls

## Interview talking points

1. **Architecture:** CLI → throttled crawler → passive/active checks → browser runtime checks → deduplication → report generation.
2. **Signal quality:** soft-404 baselines, random-path comparisons, duplicate finding suppression, placeholder secret filtering, and first-party-only network findings.
3. **Safety:** configurable delays, request caps, response-size limits, passive-only mode, and explicit authorized-testing guidance.

## Disclaimer

BugFinder is intended only for systems you own or have explicit permission to test. Automated findings are leads, not confirmed vulnerabilities.
