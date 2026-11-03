import html
import json
from datetime import datetime

from .models import SEVERITY_LABELS, SEVERITY_ORDER, ScanResult


CSS = """
:root {
  --bg: #0f1220;
  --panel: #171b2e;
  --panel-2: #1e2338;
  --text: #e8ecf7;
  --muted: #9aa4bf;
  --border: #2a3150;
  --critical: #ff4d6d;
  --high: #ff8c42;
  --medium: #ffd166;
  --low: #4cc9f0;
  --info: #9aa4bf;
  --ok: #4ade80;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  background: radial-gradient(1200px 600px at 10% -10%, #232a4d 0%, var(--bg) 55%);
  color: var(--text);
  line-height: 1.5;
}
.wrap { max-width: 1180px; margin: 0 auto; padding: 32px 20px 64px; }
header.hero { margin-bottom: 24px; }
h1 { font-size: 30px; margin: 0 0 6px; letter-spacing: -0.02em; }
h1 span { color: var(--low); }
.target { color: var(--muted); font-size: 14px; word-break: break-all; }
.meta { display: flex; flex-wrap: wrap; gap: 8px 22px; margin-top: 14px; color: var(--muted); font-size: 13px; }
.meta b { color: var(--text); font-weight: 600; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 24px 0; }
.card {
  background: linear-gradient(180deg, var(--panel), var(--panel-2));
  border: 1px solid var(--border); border-radius: 14px; padding: 16px 18px;
}
.card .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }
.card .value { font-size: 30px; font-weight: 700; margin-top: 2px; }
.card.critical .value { color: var(--critical); }
.card.high .value { color: var(--high); }
.card.medium .value { color: var(--medium); }
.card.low .value { color: var(--low); }
.card.info .value { color: var(--info); }
.controls { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin: 28px 0 18px; }
.controls button, .controls select, .controls input {
  background: var(--panel); color: var(--text); border: 1px solid var(--border);
  border-radius: 10px; padding: 9px 13px; font-size: 13px; cursor: pointer;
}
.controls input { cursor: text; min-width: 240px; flex: 1; }
.controls button.active { border-color: var(--low); box-shadow: 0 0 0 1px var(--low) inset; }
.controls .spacer { flex: 1; }
#visible-count { color: var(--muted); font-size: 13px; white-space: nowrap; }
.section-title { margin: 30px 0 12px; font-size: 18px; }
.finding {
  background: var(--panel); border: 1px solid var(--border); border-left-width: 4px;
  border-radius: 12px; padding: 16px 18px; margin-bottom: 12px;
}
.finding.critical { border-left-color: var(--critical); }
.finding.high { border-left-color: var(--high); }
.finding.medium { border-left-color: var(--medium); }
.finding.low { border-left-color: var(--low); }
.finding.info { border-left-color: var(--info); }
.finding .top { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
.badge {
  font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em;
  padding: 3px 8px; border-radius: 999px; background: var(--panel-2); border: 1px solid var(--border);
}
.badge.critical { color: var(--critical); border-color: var(--critical); }
.badge.high { color: var(--high); border-color: var(--high); }
.badge.medium { color: var(--medium); border-color: var(--medium); }
.badge.low { color: var(--low); border-color: var(--low); }
.badge.info { color: var(--info); }
.finding h3 { font-size: 15px; margin: 0; flex: 1; min-width: 220px; }
.cat { color: var(--muted); font-size: 12px; }
.finding .url { color: var(--low); font-size: 12px; word-break: break-all; margin: 8px 0 0; }
.finding pre {
  background: #0b0e19; border: 1px solid var(--border); border-radius: 8px;
  padding: 10px 12px; overflow-x: auto; font-size: 12px; color: #c7d0e8; white-space: pre-wrap; word-break: break-word;
}
.finding .fix { color: var(--muted); font-size: 13px; margin: 8px 0 0; }
.finding .fix b { color: var(--ok); }
.gallery { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 14px; }
figure { margin: 0; background: var(--panel); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
figure img { width: 100%; display: block; cursor: zoom-in; }
figcaption { padding: 8px 10px; color: var(--muted); font-size: 11px; word-break: break-all; }
.empty { background: var(--panel); border: 1px dashed var(--border); border-radius: 12px; padding: 30px; text-align: center; color: var(--muted); }
footer { margin-top: 40px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--border); padding-top: 16px; }
footer code { color: var(--text); }
#lightbox {
  position: fixed; inset: 0; background: rgba(0,0,0,0.85); display: none;
  align-items: center; justify-content: center; padding: 24px; z-index: 50; cursor: zoom-out;
}
#lightbox img { max-width: 100%; max-height: 100%; border-radius: 8px; box-shadow: 0 20px 60px rgba(0,0,0,0.6); }
@media (max-width: 640px) { h1 { font-size: 23px; } .wrap { padding: 22px 14px 48px; } }
"""

JS = """
const buttons = document.querySelectorAll('[data-filter]');
const categorySelect = document.getElementById('category');
const search = document.getElementById('search');
const findings = Array.from(document.querySelectorAll('.finding'));
const countEl = document.getElementById('visible-count');
const lightbox = document.getElementById('lightbox');
const lightboxImg = document.getElementById('lightbox-img');
let severityFilter = 'all';

function apply() {
  const query = (search.value || '').toLowerCase().trim();
  const category = categorySelect.value;
  let visible = 0;
  findings.forEach((el) => {
    const matchSeverity = severityFilter === 'all' || el.dataset.severity === severityFilter;
    const matchCategory = category === 'all' || el.dataset.category === category;
    const matchQuery = !query || el.textContent.toLowerCase().includes(query);
    const show = matchSeverity && matchCategory && matchQuery;
    el.style.display = show ? '' : 'none';
    if (show) visible += 1;
  });
  countEl.textContent = visible + ' of ' + findings.length + ' findings shown';
  document.querySelectorAll('.category-block').forEach((block) => {
    const any = Array.from(block.querySelectorAll('.finding')).some((el) => el.style.display !== 'none');
    block.style.display = any ? '' : 'none';
  });
}

buttons.forEach((btn) => {
  btn.addEventListener('click', () => {
    buttons.forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    severityFilter = btn.dataset.filter;
    apply();
  });
});
categorySelect.addEventListener('change', apply);
search.addEventListener('input', apply);
document.querySelectorAll('.gallery img').forEach((img) => {
  img.addEventListener('click', () => {
    lightboxImg.src = img.src;
    lightbox.style.display = 'flex';
  });
});
lightbox.addEventListener('click', () => { lightbox.style.display = 'none'; });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') lightbox.style.display = 'none'; });
apply();
"""


def _esc(value):
    return html.escape(str(value or ""), quote=True)


def _render_finding(finding):
    evidence = ""
    if finding.evidence:
        evidence = f"<pre>{_esc(finding.evidence)}</pre>"
    url = f'<div class="url">{_esc(finding.url)}</div>' if finding.url else ""
    repro = ""
    if finding.url:
        shell_url = finding.url.replace("'", "'\\''")
        repro = f'<pre class="repro"># Reproduce\ncurl -sS -i \'{_esc(shell_url)}\'</pre>'
    remediation = f'<p class="fix"><b>Fix:</b> {_esc(finding.remediation)}</p>' if finding.remediation else ""
    return f"""
    <article class="finding {_esc(finding.severity)}" data-severity="{_esc(finding.severity)}" data-category="{_esc(finding.category)}">
      <div class="top">
        <span class="badge {_esc(finding.severity)}">{_esc(SEVERITY_LABELS.get(finding.severity, finding.severity))}</span>
        <h3>{_esc(finding.title)}</h3>
        <span class="cat">{_esc(finding.category)}</span>
      </div>
      {url}
      {evidence}
      {repro}
      {remediation}
    </article>"""


def _render_gallery(screenshots):
    if not screenshots:
        return ""
    items = []
    for url, data in screenshots.items():
        items.append(
            f'<figure><img loading="lazy" alt="Screenshot of {_esc(url)}" '
            f'src="data:image/jpeg;base64,{data}"><figcaption>{_esc(url)}</figcaption></figure>'
        )
    return (
        '<h2 class="section-title">Page screenshots</h2>'
        f'<div class="gallery">{"".join(items)}</div>'
    )


def _render_findings(result):
    findings = result.sorted_findings()
    if not findings:
        return '<div class="empty">No issues detected with the enabled checks. This is not a guarantee that the site is bug-free.</div>'

    categories = {}
    for finding in findings:
        categories.setdefault(finding.category, []).append(finding)

    blocks = []
    for category, items in categories.items():
        rendered = "".join(_render_finding(f) for f in items)
        blocks.append(
            f'<section class="category-block" data-category="{_esc(category)}">'
            f'<h2 class="section-title">{_esc(category)} <span class="cat">({len(items)})</span></h2>'
            f"{rendered}</section>"
        )
    return "".join(blocks)


def _options(categories, total):
    options = [f'<option value="all">All categories ({total})</option>']
    for category in categories:
        options.append(f'<option value="{_esc(category)}">{_esc(category)}</option>')
    return "".join(options)


def build_html(result: ScanResult) -> str:
    counts = result.counts()
    findings = result.sorted_findings()
    categories = []
    for finding in findings:
        if finding.category not in categories:
            categories.append(finding.category)
    stats = result.stats or {}
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    severity_cards = "".join(
        f'<div class="card {severity}"><div class="label">{SEVERITY_LABELS[severity]}</div>'
        f'<div class="value">{counts.get(severity, 0)}</div></div>'
        for severity in SEVERITY_ORDER
    )

    filter_buttons = "".join(
        f'<button data-filter="{severity}" class="{"active" if severity == "all" else ""}">'
        f'{severity.title()}</button>'
        for severity in ["all", *SEVERITY_ORDER]
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BugFinder report - {_esc(result.target)}</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
  <header class="hero">
    <h1>Bug<span>Finder</span> report</h1>
    <div class="target">{_esc(result.target)}</div>
    <div class="meta">
      <span>Started: <b>{_esc(result.started_at)}</b></span>
      <span>Finished: <b>{_esc(result.finished_at)}</b></span>
      <span>Duration: <b>{result.duration_seconds:.1f}s</b></span>
      <span>Pages scanned: <b>{result.pages_scanned}</b></span>
      <span>Links found: <b>{stats.get('links', 0)}</b></span>
      <span>Forms found: <b>{stats.get('forms', 0)}</b></span>
      <span>Generated: <b>{generated}</b></span>
    </div>
  </header>

  <div class="grid">
    <div class="card"><div class="label">Total findings</div><div class="value">{len(findings)}</div></div>
    {severity_cards}
  </div>

  <div class="controls">
    {filter_buttons}
    <select id="category">{_options(categories, len(findings))}</select>
    <input id="search" type="search" placeholder="Search findings...">
    <span id="visible-count"></span>
  </div>

  {_render_findings(result)}

  {_render_gallery(result.screenshots)}

  <footer>
    Generated by <code>BugFinder</code>. Findings are automated heuristics and may include false positives;
    always verify manually before reporting. Only scan sites you own or have explicit permission to test.<br>
    JSON data is available alongside this report when <code>--json</code> is used.
  </footer>
</div>
<div id="lightbox"><img id="lightbox-img" alt="Enlarged screenshot"></div>
<script>{JS}</script>
</body>
</html>
"""


def build_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)


def _md_escape(value):
    return str(value or "").replace("|", "\\|").replace("\n", " ")


def build_markdown(result: ScanResult) -> str:
    counts = result.counts()
    lines = [
        f"# BugFinder report — {result.target}",
        "",
        f"- Started: {result.started_at}",
        f"- Finished: {result.finished_at}",
        f"- Duration: {result.duration_seconds:.1f}s",
        f"- Pages scanned: {result.pages_scanned}",
        f"- Total findings: {len(result.findings)}",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for severity in SEVERITY_ORDER:
        lines.append(f"| {SEVERITY_LABELS[severity]} | {counts.get(severity, 0)} |")
    lines.append("")

    findings = result.sorted_findings()
    if not findings:
        lines.append("No issues detected with the enabled checks.")
        lines.append("")
        return "\n".join(lines)

    for finding in findings:
        lines.append(f"## [{SEVERITY_LABELS.get(finding.severity, finding.severity)}] {finding.title}")
        lines.append("")
        lines.append(f"- Category: {_md_escape(finding.category)}")
        if finding.url:
            lines.append(f"- URL: {_md_escape(finding.url)}")
            lines.append(f"- Reproduce: `curl -sS -i '{finding.url}'`")
        lines.append("")
        if finding.evidence:
            lines.append("```")
            lines.append(str(finding.evidence))
            lines.append("```")
            lines.append("")
        if finding.remediation:
            lines.append(f"**Fix:** {_md_escape(finding.remediation)}")
            lines.append("")

    lines.append("---")
    lines.append("Automated heuristics may include false positives; verify manually before reporting.")
    lines.append("")
    return "\n".join(lines)
