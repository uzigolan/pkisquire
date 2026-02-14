import argparse
import json
import time
import urllib.parse
import urllib.request
from pathlib import Path


HTML_TEMPLATE = """<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Dependency Vulnerability Report</title>
  <style>
    :root {{
      --bg: #ffffff;
      --text: #1f2933;
      --muted: #6b7280;
      --border: #e5e7eb;
      --chip: #f3f4f6;
    }}
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: var(--text); background: var(--bg); }}
    h1 {{ margin: 0 0 6px; }}
    .meta {{ color: var(--muted); margin-bottom: 16px; }}
    .controls {{ display: flex; gap: 12px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }}
    .spacer {{ flex: 1 1 auto; }}
    input[type="text"] {{ padding: 6px 10px; border: 1px solid var(--border); border-radius: 6px; min-width: 240px; }}
    select {{ padding: 6px 10px; border: 1px solid var(--border); border-radius: 6px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid var(--border); padding: 8px 10px; vertical-align: top; }}
    th {{ text-align: left; white-space: nowrap; cursor: pointer; }}
    .chip {{ display: inline-block; padding: 2px 8px; border-radius: 999px; background: var(--chip); font-size: 12px; }}
    .muted {{ color: var(--muted); }}
    .count {{ margin-left: auto; color: var(--muted); }}
  </style>
</head>
<body>
  <h1>Dependency Vulnerability Report</h1>
  <div class="meta">Known vulnerabilities in Python dependencies from requirements, with severity and fix-version guidance.</div>
  <div class="meta">Source: {source} | Generated at: {generated_at} | Version: {version}</div>
  <div class="controls">
    <label>
      Show:
      <select id="pageSizeSelect" onchange="changePageSize()">
        <option value="10" selected>10</option>
        <option value="25">25</option>
        <option value="50">50</option>
      </select>
    </label>
    <span class="count" id="pageInfo"></span>
    <input id="filterInput" type="text" placeholder="Filter by package, vuln id, or severity" onkeyup="applyFilter()" />
    <label>
      Severity:
      <select id="severitySelect" onchange="applyFilter()">
        <option value="">All</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="unreported">Unspecified</option>
      </select>
    </label>
    <span class="spacer"></span>
    <button type="button" onclick="previousPage()">Previous</button>
    <button type="button" onclick="nextPage()">Next</button>
    <span class="count" id="resultCount"></span>
  </div>
  <table id="auditTable">
    <thead>
      <tr>
        <th onclick="sortTable(0)">Package</th>
        <th onclick="sortTable(1)">Version</th>
        <th onclick="sortTable(2)">Vulnerability ID</th>
        <th onclick="sortTable(3)">Severity</th>
        <th onclick="sortTable(4)">Score</th>
        <th onclick="sortTable(5)">Fix Versions</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>

<script>
  let sortDirections = {{}};
  let currentPage = 1;
  let pageSize = 10;
  let filteredRows = [];

  function applyFilter(resetPage = true) {{
    const input = document.getElementById('filterInput').value.toLowerCase();
    const severity = document.getElementById('severitySelect').value.toLowerCase();
    const tbody = document.querySelector('#auditTable tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    filteredRows = rows.filter(row => {{
      const text = row.textContent.toLowerCase();
      const sev = row.getAttribute('data-severity') || 'unknown';
      const matchesText = text.indexOf(input) > -1;
      const matchesSev = !severity || sev === severity;
      return matchesText && matchesSev;
    }});
    document.getElementById('resultCount').textContent = 'Matched ' + filteredRows.length + ' of ' + rows.length;
    if (resetPage) currentPage = 1;
    renderPage();
  }}

  function renderPage() {{
    const tbody = document.querySelector('#auditTable tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const total = filteredRows.length;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    currentPage = Math.min(Math.max(1, currentPage), totalPages);
    const start = (currentPage - 1) * pageSize;
    const end = start + pageSize;
    rows.forEach(row => row.style.display = 'none');
    filteredRows.slice(start, end).forEach(row => row.style.display = '');
    const shownStart = total === 0 ? 0 : start + 1;
    const shownEnd = Math.min(end, total);
    document.getElementById('pageInfo').textContent = 'Page ' + currentPage + '/' + totalPages + ' | Showing ' + shownStart + '-' + shownEnd;
  }}

  function sortTable(columnIndex) {{
    const tbody = document.querySelector('#auditTable tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const isAscending = sortDirections[columnIndex] !== 'asc';
    sortDirections[columnIndex] = isAscending ? 'asc' : 'desc';
    rows.sort((a, b) => {{
      const aText = a.cells[columnIndex].textContent.trim().toLowerCase();
      const bText = b.cells[columnIndex].textContent.trim().toLowerCase();
      if (columnIndex === 4) {{
        const aNum = parseFloat(aText) || 0;
        const bNum = parseFloat(bText) || 0;
        return isAscending ? aNum - bNum : bNum - aNum;
      }}
      if (aText < bText) return isAscending ? -1 : 1;
      if (aText > bText) return isAscending ? 1 : -1;
      return 0;
    }});
    rows.forEach(row => tbody.appendChild(row));
    applyFilter(false);
  }}

  function changePageSize() {{
    pageSize = parseInt(document.getElementById('pageSizeSelect').value, 10) || 10;
    applyFilter(true);
  }}

  function nextPage() {{
    currentPage += 1;
    renderPage();
  }}

  function previousPage() {{
    currentPage -= 1;
    renderPage();
  }}

  document.addEventListener('DOMContentLoaded', () => applyFilter(true));
</script>
</body>
</html>
"""


def normalize_severity(vuln):
    sev_list = vuln.get("severity") or []
    if isinstance(sev_list, list) and sev_list:
        # Pick the highest severity if multiple are present.
        # Values are typically like "LOW", "MEDIUM", "HIGH", "CRITICAL".
        rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        normed = [str(s).lower() for s in sev_list]
        normed.sort(key=lambda s: rank.get(s, 0), reverse=True)
        return normed[0]
    return "unreported"


def fetch_nvd_severity(cve_id, cache):
    if not cve_id:
        return "unreported", ""
    if cve_id in cache:
        return cache[cve_id]
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + urllib.parse.quote(cve_id)
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        items = data.get("vulnerabilities") or []
        if not items:
            cache[cve_id] = ("unreported", "")
            return cache[cve_id]
        metrics = (items[0].get("cve") or {}).get("metrics") or {}
        # Prefer CVSS v3.1, then v3.0, then v2.
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                metric = metrics[key][0]
                cvss = metric.get("cvssData") or {}
                severity = str(cvss.get("baseSeverity", "")).lower()
                score = cvss.get("baseScore", "")
                cache[cve_id] = (severity or "unreported", str(score) if score != "" else "")
                return cache[cve_id]
        cache[cve_id] = ("unreported", "")
        return cache[cve_id]
    except Exception:
        cache[cve_id] = ("unreported", "")
        return cache[cve_id]


def fetch_ghsa_severity(cve_id, cache):
    if not cve_id:
        return "unreported", ""
    if ("ghsa", cve_id) in cache:
        return cache[("ghsa", cve_id)]
    url = "https://api.github.com/advisories?cve_id=" + urllib.parse.quote(cve_id)
    req = urllib.request.Request(url, headers={"User-Agent": "pip-audit-interactive"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        if isinstance(data, list) and data:
            adv = data[0]
            severity = str(adv.get("severity", "")).lower() or "unreported"
            score = ""
            cvss = adv.get("cvss") or {}
            if cvss.get("score") is not None:
                score = str(cvss.get("score"))
            cache[("ghsa", cve_id)] = (severity, score)
            return cache[("ghsa", cve_id)]
        cache[("ghsa", cve_id)] = ("unreported", "")
        return cache[("ghsa", cve_id)]
    except Exception:
        cache[("ghsa", cve_id)] = ("unreported", "")
        return cache[("ghsa", cve_id)]


def fetch_osv_severity(cve_id, cache):
    if not cve_id:
        return "unreported", ""
    if ("osv", cve_id) in cache:
        return cache[("osv", cve_id)]
    url = "https://api.osv.dev/v1/vulns/" + urllib.parse.quote(cve_id)
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        severity = "unreported"
        score = ""
        sev_list = data.get("severity") or []
        if sev_list:
            # Prefer CVSS_V3 if present.
            cvss_v3 = next((s for s in sev_list if s.get("type") == "CVSS_V3"), None)
            pick = cvss_v3 or sev_list[0]
            sev_score = pick.get("score", "")
            if sev_score:
                score = str(sev_score)
            # Try to map score to severity buckets.
            try:
                s = float(score)
                if s >= 9.0:
                    severity = "critical"
                elif s >= 7.0:
                    severity = "high"
                elif s >= 4.0:
                    severity = "medium"
                else:
                    severity = "low"
            except Exception:
                severity = "unreported"
        cache[("osv", cve_id)] = (severity, score)
        return cache[("osv", cve_id)]
    except Exception:
        cache[("osv", cve_id)] = ("unreported", "")
        return cache[("osv", cve_id)]

def iter_rows(data):
    rows = []
    deps = data.get("dependencies") or []
    nvd_cache = {}
    for dep in deps:
        name = dep.get("name", "")
        version = dep.get("version", "")
        vulns = dep.get("vulns") or []
        for vuln in vulns:
            vid = vuln.get("id", "")
            fix_versions = ", ".join(vuln.get("fix_versions") or [])
            # Prefer NVD severity/score; fallback to GHSA, then OSV, then pip-audit.
            severity, score = fetch_nvd_severity(vid, nvd_cache)
            if not score:
                sev_ghsa, score_ghsa = fetch_ghsa_severity(vid, nvd_cache)
                if not score and score_ghsa:
                    score = score_ghsa
                if severity == "unreported" and sev_ghsa != "unreported":
                    severity = sev_ghsa
            if not score:
                sev_osv, score_osv = fetch_osv_severity(vid, nvd_cache)
                if not score and score_osv:
                    score = score_osv
                if severity == "unreported" and sev_osv != "unreported":
                    severity = sev_osv
            if severity == "unreported":
                severity = normalize_severity(vuln)
            # Be gentle to public APIs when multiple CVEs are present.
            if vid:
                time.sleep(0.6)
            rows.append({
                "name": name,
                "version": version,
                "id": vid,
                "severity": severity,
                "score": score,
                "fix_versions": fix_versions,
            })
    return rows


def render_rows(rows):
    if not rows:
        return '<tr><td colspan="5" class="muted">No known vulnerabilities found.</td></tr>'
    out = []
    for r in rows:
        sev_label = r["severity"].capitalize() if r["severity"] != "unreported" else "Unspecified"
        out.append(
            "<tr data-severity=\"{sev}\">"
            "<td>{name}</td>"
            "<td>{version}</td>"
            "<td>{vid_link}</td>"
            "<td><span class=\"chip\">{sev_label}</span></td>"
            "<td>{score}</td>"
            "<td>{fix}</td>"
            "</tr>".format(
                sev=r["severity"],
                name=r["name"],
                version=r["version"],
                vid_link=(
                    '<a href="{0}" target="_blank" rel="noopener noreferrer">{1}</a>'.format(
                        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + r["id"],
                        r["id"]
                    )
                    if r["id"] else ""
                ),
                sev_label=sev_label,
                score=r["score"],
                fix=r["fix_versions"],
            )
        )
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", required=True)
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("-t", "--generated-at", default="")
    parser.add_argument("-v", "--version", default="")
    args = parser.parse_args()

    # pip-audit JSON can include a UTF-8 BOM on Windows; handle it safely.
    data = json.loads(Path(args.input).read_text(encoding="utf-8-sig"))
    rows = iter_rows(data)
    html = HTML_TEMPLATE.format(
        source="pip-audit.json",
        generated_at=args.generated_at or "unknown",
        version=args.version or "unknown",
        rows=render_rows(rows),
    )
    Path(args.output).write_text(html, encoding="utf-8")


if __name__ == "__main__":
    main()
