# BugFinder report — http://127.0.0.1:8767/

- Started: 2026-11-03 12:59:19
- Finished: 2026-11-03 12:59:32
- Duration: 13.4s
- Pages scanned: 3
- Total findings: 32

| Severity | Count |
| --- | --- |
| Critical | 2 |
| High | 1 |
| Medium | 5 |
| Low | 15 |
| Info | 9 |

## [Critical] Password form submits over plain HTTP

- Category: Forms
- URL: http://127.0.0.1:8767/
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767/'`

```
Form action: http://127.0.0.1:8767/login
```

**Fix:** Serve the form and submit credentials only over HTTPS.

## [Critical] HTTPS is not available

- Category: Transport Security
- URL: http://127.0.0.1:8767/
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767/'`

```
SSLError: HTTPSConnectionPool(host='127.0.0.1', port=8767): Max retries exceeded with url: / (Caused by SSLError(SSLError(1, '[SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:992)')))
```

**Fix:** Enable HTTPS with a valid certificate.

## [High] Content-Security-Policy header is missing

- Category: Security Headers
- URL: http://127.0.0.1:8767
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767'`

```
Response headers for http://127.0.0.1:8767: content-length, content-type, date, last-modified, server
```

**Fix:** Add a strict Content-Security-Policy to reduce XSS and injection risk.

## [Medium] Client error (HTTP 404)

- Category: Availability
- URL: http://127.0.0.1:8767/missing-page.html
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767/missing-page.html'`

```
HTTP 404 returned for http://127.0.0.1:8767/missing-page.html
```

**Fix:** Fix the broken page or update links pointing to it.

## [Medium] Broken internal resource

- Category: Broken Links
- URL: http://127.0.0.1:8767/missing-image.png
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767/missing-image.png'`

```
HTTP 404 for http://127.0.0.1:8767/missing-image.png
```

**Fix:** Fix the missing resource (image/script/style) or update its reference.

## [Medium] Broken or unloaded images

- Category: Broken Links
- URL: http://127.0.0.1:8767/
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767/'`

```
Images failed to load: http://127.0.0.1:8767/missing-image.png
```

**Fix:** Fix image paths or serve valid image files.

## [Medium] Login form has no visible CSRF token

- Category: Forms
- URL: http://127.0.0.1:8767/
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767/'`

```
Form action: http://127.0.0.1:8767/login, fields: username, password
```

**Fix:** Add and validate an anti-CSRF token for state-changing and authentication forms.

## [Medium] X-Frame-Options / frame-ancestors protection is missing

- Category: Security Headers
- URL: http://127.0.0.1:8767
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767'`

```
Response headers for http://127.0.0.1:8767: content-length, content-type, date, last-modified, server
```

**Fix:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors to prevent clickjacking.

## [Low] Accessibility issues found

- Category: Accessibility
- URL: http://127.0.0.1:8767/
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767/'`

```
1 image(s) without alt text; 2 form field(s) without an associated label; 1 link(s) without accessible text; duplicate id attribute(s): duplicate
```

**Fix:** Fix labels, alt text, accessible link names and duplicate IDs.

## [Low] Server version disclosed

- Category: Information Disclosure
- URL: http://127.0.0.1:8767
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767'`

```
Server: SimpleHTTP/0.6 Python/3.11.2
```

**Fix:** Remove version details from the Server header.

## [Low] Console error in browser

- Category: JavaScript
- URL: http://127.0.0.1:8767/
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767/'`

```
Failed to load resource: the server responded with a status of 404 (File not found)
```

**Fix:** Fix JavaScript errors reported in the browser console.

## [Low] Console error in browser

- Category: JavaScript
- URL: http://127.0.0.1:8767/
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767/'`

```
Demo console error for BugFinder runtime checks
```

**Fix:** Fix JavaScript errors reported in the browser console.

## [Low] Subresource returned an error status

- Category: Network
- URL: http://127.0.0.1:8767/
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767/'`

```
404 http://127.0.0.1:8767/missing-image.png
```

**Fix:** Fix the failing subresource (image/script/style/API).

## [Low] Missing HTML lang attribute

- Category: SEO
- URL: http://127.0.0.1:8767/
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767/'`

```
The <html> element has no lang attribute.
```

**Fix:** Add a lang attribute to the <html> element.

## [Low] Missing HTML lang attribute

- Category: SEO
- URL: http://127.0.0.1:8767/about.html
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767/about.html'`

```
The <html> element has no lang attribute.
```

**Fix:** Add a lang attribute to the <html> element.

## [Low] Missing meta description

- Category: SEO
- URL: http://127.0.0.1:8767/
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767/'`

```
No meta description tag found.
```

**Fix:** Add a concise meta description.

## [Low] Missing meta description

- Category: SEO
- URL: http://127.0.0.1:8767/about.html
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767/about.html'`

```
No meta description tag found.
```

**Fix:** Add a concise meta description.

## [Low] Missing meta description

- Category: SEO
- URL: http://127.0.0.1:8767/missing-page.html
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767/missing-page.html'`

```
No meta description tag found.
```

**Fix:** Add a concise meta description.

## [Low] Missing viewport meta tag

- Category: SEO
- URL: http://127.0.0.1:8767/
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767/'`

```
No viewport meta tag found.
```

**Fix:** Add <meta name='viewport' content='width=device-width, initial-scale=1'>.

## [Low] Missing viewport meta tag

- Category: SEO
- URL: http://127.0.0.1:8767/about.html
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767/about.html'`

```
No viewport meta tag found.
```

**Fix:** Add <meta name='viewport' content='width=device-width, initial-scale=1'>.

## [Low] Missing viewport meta tag

- Category: SEO
- URL: http://127.0.0.1:8767/missing-page.html
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767/missing-page.html'`

```
No viewport meta tag found.
```

**Fix:** Add <meta name='viewport' content='width=device-width, initial-scale=1'>.

## [Low] Referrer-Policy header is missing

- Category: Security Headers
- URL: http://127.0.0.1:8767
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767'`

```
Response headers for http://127.0.0.1:8767: content-length, content-type, date, last-modified, server
```

**Fix:** Set Referrer-Policy: strict-origin-when-cross-origin or stricter.

## [Low] X-Content-Type-Options header is missing

- Category: Security Headers
- URL: http://127.0.0.1:8767
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767'`

```
Response headers for http://127.0.0.1:8767: content-length, content-type, date, last-modified, server
```

**Fix:** Set X-Content-Type-Options: nosniff.

## [Info] Technology stack detected

- Category: Fingerprint
- URL: http://127.0.0.1:8767
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767'`

```
Detected: Python HTTP server
```

**Fix:** Review component versions and vendor-specific defaults for known issues.

## [Info] Password field may allow autocomplete

- Category: Forms
- URL: http://127.0.0.1:8767/
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767/'`

```
Password field(s): password
```

**Fix:** Use autocomplete='current-password' or 'new-password' as appropriate.

## [Info] Missing canonical link

- Category: SEO
- URL: http://127.0.0.1:8767/
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767/'`

```
No canonical link element found.
```

**Fix:** Add rel='canonical' to avoid duplicate content issues.

## [Info] Missing canonical link

- Category: SEO
- URL: http://127.0.0.1:8767/about.html
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767/about.html'`

```
No canonical link element found.
```

**Fix:** Add rel='canonical' to avoid duplicate content issues.

## [Info] Missing canonical link

- Category: SEO
- URL: http://127.0.0.1:8767/missing-page.html
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767/missing-page.html'`

```
No canonical link element found.
```

**Fix:** Add rel='canonical' to avoid duplicate content issues.

## [Info] Multiple H1 headings

- Category: SEO
- URL: http://127.0.0.1:8767/
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767/'`

```
Found 2 <h1> elements.
```

**Fix:** Use a single H1 per page for clear hierarchy.

## [Info] robots.txt is missing

- Category: SEO
- URL: http://127.0.0.1:8767/robots.txt
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767/robots.txt'`

```
HTTP 404
```

**Fix:** Add a robots.txt to guide crawlers and reference the sitemap.

## [Info] Permissions-Policy header is missing

- Category: Security Headers
- URL: http://127.0.0.1:8767
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767'`

```
Response headers for http://127.0.0.1:8767: content-length, content-type, date, last-modified, server
```

**Fix:** Restrict powerful browser features with Permissions-Policy.

## [Info] No security.txt published

- Category: Security Policy
- URL: http://127.0.0.1:8767/.well-known/security.txt
- Reproduce: `curl -sS -i 'http://127.0.0.1:8767/.well-known/security.txt'`

```
Neither /.well-known/security.txt nor /security.txt returned a valid policy.
```

**Fix:** Publish a security.txt with a monitored Contact address and an Expires date.

---
Automated heuristics may include false positives; verify manually before reporting.
