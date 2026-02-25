import argparse
import json
from html import escape
from pathlib import Path


HTML_TEMPLATE = """<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Safety Vulnerabilities Report</title>
  <style>
    :root {{
      --bg: #ffffff;
      --text: #1f2933;
      --muted: #6b7280;
      --border: #e5e7eb;
      --chip: #f3f4f6;
      --card: #f8fafc;
    }}
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: var(--text); background: var(--bg); }}
    h1 {{ margin: 0 0 6px; }}
    h2 {{ margin: 18px 0 8px; }}
    .meta {{ color: var(--muted); margin-bottom: 10px; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; margin: 12px 0 16px; }}
    .card {{ border: 1px solid var(--border); border-radius: 10px; background: var(--card); padding: 10px 12px; }}
    .card .label {{ font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }}
    .card .value {{ font-size: 20px; font-weight: 700; }}
    .controls {{ display: flex; gap: 12px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }}
    .spacer {{ flex: 1 1 auto; }}
    input[type="text"] {{ padding: 6px 10px; border: 1px solid var(--border); border-radius: 6px; min-width: 260px; }}
    select {{ padding: 6px 10px; border: 1px solid var(--border); border-radius: 6px; }}
    button {{ padding: 5px 8px; border: 1px solid var(--border); border-radius: 6px; background: #fff; cursor: pointer; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid var(--border); padding: 8px 10px; vertical-align: top; }}
    th {{ text-align: left; white-space: nowrap; cursor: pointer; }}
    .chip {{ display: inline-block; padding: 2px 8px; border-radius: 999px; background: var(--chip); font-size: 12px; }}
    .count {{ margin-left: auto; color: var(--muted); }}
    .small {{ max-width: 380px; }}
    .links a {{ margin-right: 6px; text-decoration: none; font-size: 12px; font-weight: 700; border-radius: 999px; padding: 2px 8px; border: 1px solid var(--border); display: inline-block; }}
    .links a:hover {{ filter: brightness(0.96); text-decoration: none; }}
    .col-links {{ min-width: 230px; }}
    .col-summary {{ max-width: 300px; min-width: 220px; }}
    .link-cve {{ background: #e0f2fe; color: #075985; border-color: #bae6fd; }}
    .link-ref {{ background: #eef2ff; color: #3730a3; border-color: #c7d2fe; }}
    .link-safe {{ background: #ecfdf5; color: #065f46; border-color: #a7f3d0; }}
    .link-commit {{ background: #f3e8ff; color: #6b21a8; border-color: #ddd6fe; }}
    .link-ghsa {{ background: #fee2e2; color: #991b1b; border-color: #fecaca; }}
    .link-pyup {{ background: #fff7ed; color: #9a3412; border-color: #fed7aa; }}
    .link-pypi {{ background: #ecfeff; color: #155e75; border-color: #a5f3fc; }}
    .link-mitre {{ background: #fef9c3; color: #854d0e; border-color: #fde68a; }}
    .summary-cell {{ font-size: 12px; color: var(--muted); }}
    .detail-row td {{ background: #fcfcfd; }}
    .detail-block {{ font-size: 13px; line-height: 1.45; }}
    .detail-line {{ margin: 4px 0; }}
    .legend {{ margin: 10px 0 14px; color: var(--muted); font-size: 12px; }}
    .legend .chip {{ margin-right: 6px; }}
  </style>
</head>
<body>
  <h1>Safety Vulnerabilities Report</h1>
  <div class="meta">Additional dependency vulnerability results from Safety.</div>
  <div class="meta">Source: {source} | Generated at: {generated_at} | Version: {version}</div>
  <div class="meta">{scanner_info}</div>
  <div class="meta">{scan_info}</div>

  <div class="cards">
    <div class="card"><div class="label">Packages Found</div><div class="value">{packages_found}</div></div>
    <div class="card"><div class="label">Active Vulnerabilities</div><div class="value">{active_vulns}</div></div>
    <div class="card"><div class="label">Ignored Vulnerabilities</div><div class="value">{ignored_vulns}</div></div>
    <div class="card"><div class="label">Remediations Recommended</div><div class="value">{rem_count}</div></div>
  </div>

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
    <input id="filterInput" type="text" placeholder="Filter by package, ID, CVE, severity" onkeyup="applyFilter()" />
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
    <label>
      State:
      <select id="ignoredSelect" onchange="applyFilter()">
        <option value="">All</option>
        <option value="no">Active</option>
        <option value="yes">Ignored</option>
      </select>
    </label>
    <span class="spacer"></span>
    <button type="button" onclick="previousPage()">Previous</button>
    <button type="button" onclick="nextPage()">Next</button>
    <span class="count" id="resultCount"></span>
  </div>

  <table id="vulnTable">
    <thead>
      <tr>
        <th onclick="sortTable(0)">Package</th>
        <th onclick="sortTable(1)">Version</th>
        <th onclick="sortTable(2)">Vuln ID</th>
        <th onclick="sortTable(3)">CVE</th>
        <th onclick="sortTable(4)">Severity</th>
        <th onclick="sortTable(5)">Published</th>
        <th onclick="sortTable(6)">Fix Versions</th>
        <th onclick="sortTable(7)">State</th>
        <th>Links</th>
        <th>Summary</th>
        <th>Advanced</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>
  <div class="legend">
    <strong>Links Legend:</strong>
    <span class="chip link-cve">CVE</span> Official CVE Record
    <span class="chip link-ghsa">GHSA</span> GitHub Advisory
    <span class="chip link-commit">Commit</span> Upstream commit
    <span class="chip link-pyup">PyUp</span> PyUp reference
    <span class="chip link-pypi">PyPI</span> Package page/changelog
    <span class="chip link-mitre">MITRE</span> MITRE CVE page
    <span class="chip link-ref">Ref</span> Other reference
    <span class="chip link-safe">Safe</span> Safety Advisory
  </div>

  <h2>Remediations</h2>
  <table id="remTable">
    <thead>
      <tr>
        <th>Package</th>
        <th>Current Spec</th>
        <th>Recommended</th>
        <th>Other Options</th>
        <th>More Info</th>
      </tr>
    </thead>
    <tbody>
      {remediation_rows}
    </tbody>
  </table>

<script>
  let sortDirections = {{}};
  let currentPage = 1;
  let pageSize = 10;
  let filteredMainRows = [];

  function allMainRows() {{
    return Array.from(document.querySelectorAll('#vulnTable tbody tr.main-row'));
  }}

  function allDetailRows() {{
    return Array.from(document.querySelectorAll('#vulnTable tbody tr.detail-row'));
  }}

  function applyFilter(resetPage = true) {{
    const input = document.getElementById('filterInput').value.toLowerCase();
    const sev = document.getElementById('severitySelect').value.toLowerCase();
    const ignored = document.getElementById('ignoredSelect').value.toLowerCase();
    const rows = allMainRows();
    filteredMainRows = rows.filter(row => {{
      const text = row.textContent.toLowerCase();
      const rowSev = (row.getAttribute('data-severity') || 'unreported').toLowerCase();
      const rowIgnored = (row.getAttribute('data-ignored') || 'no').toLowerCase();
      const okText = text.indexOf(input) > -1;
      const okSev = !sev || rowSev === sev;
      const okIgnored = !ignored || rowIgnored === ignored;
      return okText && okSev && okIgnored;
    }});
    document.getElementById('resultCount').textContent = 'Matched ' + filteredMainRows.length + ' rows';
    if (resetPage) currentPage = 1;
    renderPage();
  }}

  function renderPage() {{
    const total = filteredMainRows.length;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    currentPage = Math.min(Math.max(1, currentPage), totalPages);
    const start = (currentPage - 1) * pageSize;
    const end = start + pageSize;

    allMainRows().forEach(r => r.style.display = 'none');
    allDetailRows().forEach(r => r.style.display = 'none');

    filteredMainRows.slice(start, end).forEach(main => {{
      main.style.display = '';
      const rowId = main.getAttribute('data-row-id');
      if (main.getAttribute('data-expanded') === 'yes') {{
        const detail = document.querySelector('#vulnTable tbody tr.detail-row[data-parent-id=\"' + rowId + '\"]');
        if (detail) detail.style.display = '';
      }}
    }});

    const shownStart = total === 0 ? 0 : start + 1;
    const shownEnd = Math.min(end, total);
    document.getElementById('pageInfo').textContent = 'Page ' + currentPage + '/' + totalPages + ' | Showing ' + shownStart + '-' + shownEnd;
  }}

  function sortTable(i) {{
    const tbody = document.querySelector('#vulnTable tbody');
    const mains = allMainRows();
    const asc = sortDirections[i] !== 'asc';
    sortDirections[i] = asc ? 'asc' : 'desc';

    mains.sort((a, b) => {{
      const aText = a.cells[i].textContent.trim().toLowerCase();
      const bText = b.cells[i].textContent.trim().toLowerCase();
      if (i === 4) {{
        const aRank = parseInt(a.getAttribute('data-severity-rank') || '0', 10);
        const bRank = parseInt(b.getAttribute('data-severity-rank') || '0', 10);
        return asc ? aRank - bRank : bRank - aRank;
      }}
      if (aText < bText) return asc ? -1 : 1;
      if (aText > bText) return asc ? 1 : -1;
      return 0;
    }});

    mains.forEach(main => {{
      const rid = main.getAttribute('data-row-id');
      const detail = document.querySelector('#vulnTable tbody tr.detail-row[data-parent-id=\"' + rid + '\"]');
      tbody.appendChild(main);
      if (detail) tbody.appendChild(detail);
    }});
    applyFilter(false);
  }}

  function toggleAdvanced(rowId) {{
    const main = document.querySelector('#vulnTable tbody tr.main-row[data-row-id=\"' + rowId + '\"]');
    const detail = document.querySelector('#vulnTable tbody tr.detail-row[data-parent-id=\"' + rowId + '\"]');
    if (!main || !detail) return;
    const isExpanded = main.getAttribute('data-expanded') === 'yes';
    main.setAttribute('data-expanded', isExpanded ? 'no' : 'yes');
    if (main.style.display !== 'none') {{
      detail.style.display = isExpanded ? 'none' : '';
    }}
  }}

  function changePageSize() {{
    pageSize = parseInt(document.getElementById('pageSizeSelect').value, 10) || 10;
    applyFilter(true);
  }}
  function nextPage() {{ currentPage += 1; renderPage(); }}
  function previousPage() {{ currentPage -= 1; renderPage(); }}
  document.addEventListener('DOMContentLoaded', () => applyFilter(true));
</script>
</body>
</html>
"""


def _extract_embedded_json(text):
    if not text:
        return None
    decoder = json.JSONDecoder()
    for idx, ch in enumerate(text):
        if ch != "{":
            continue
        try:
            obj, _ = decoder.raw_decode(text[idx:])
        except Exception:
            continue
        if isinstance(obj, dict) and ("vulnerabilities" in obj or "report_meta" in obj):
            return obj
    return None


def _load_safety_payload(path: Path):
    raw = path.read_text(encoding="utf-8-sig", errors="replace")
    try:
        data = json.loads(raw)
    except Exception:
        return {}
    if isinstance(data, dict) and ("vulnerabilities" in data or "report_meta" in data):
        return data
    if isinstance(data, dict) and isinstance(data.get("detail"), str):
        embedded = _extract_embedded_json(data.get("detail"))
        if embedded:
            if "generated_at" in data and "generated_at" not in embedded:
                embedded["generated_at"] = data["generated_at"]
            if "version" in data and "version" not in embedded:
                embedded["version"] = data["version"]
            return embedded
    return data if isinstance(data, dict) else {}


def _severity_info(vuln):
    sev = (vuln.get("severity") or {})
    cvss3 = (sev.get("cvssv3") or {})
    base = str(cvss3.get("base_severity") or "").lower()
    if not base:
        base = "unreported"
    rank_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unreported": 0}
    return base, rank_map.get(base, 0), cvss3


def _short_text(s, limit=220):
    s = (s or "").replace("\n", " ").strip()
    if len(s) <= limit:
        return s
    return s[:limit] + "..."


def _build_links(vuln, cve):
    def classify(url):
        u = (url or "").lower()
        if "github.com/advisories/" in u:
            return ("GHSA", "link-ghsa", "GitHub Advisory")
        if "github.com/" in u and "/commit/" in u:
            return ("Commit", "link-commit", "Upstream Commit")
        if "pyup.io/" in u:
            return ("PyUp", "link-pyup", "PyUp Reference")
        if "pypi.org/" in u:
            return ("PyPI", "link-pypi", "PyPI Package Page")
        if "cve.mitre.org/" in u:
            return ("MITRE", "link-mitre", "MITRE CVE")
        return ("Ref", "link-ref", "Reference Link")

    links = []
    if cve:
        links.append(
            "<a class='link-cve' href='https://www.cve.org/CVERecord?id={id}' target='_blank' rel='noopener' title='Official CVE Record'>CVE</a>".format(
                id=escape(cve)
            )
        )
    for url in (vuln.get("resources") or [])[:3]:
        safe = escape(str(url))
        label, klass, title = classify(str(url))
        links.append(
            "<a class='{k}' href='{u}' target='_blank' rel='noopener' title='{t}'>{l}</a>".format(
                k=escape(klass),
                u=safe,
                t=escape(title),
                l=escape(label),
            )
        )
    more = vuln.get("more_info_url")
    if more:
        links.append("<a class='link-safe' href='{u}' target='_blank' rel='noopener' title='Safety Advisory'>Safe</a>".format(u=escape(str(more))))
    return " ".join(links) if links else "-"


def _advanced_block(vuln, cvss3):
    analyzed_req = vuln.get("analyzed_requirement") or {}
    specs = ", ".join(str(x) for x in (vuln.get("vulnerable_spec") or []))
    all_specs = ", ".join(str(x) for x in (vuln.get("all_vulnerable_specs") or []))
    affected = vuln.get("affected_versions") or []
    affected_preview = ", ".join(str(x) for x in affected[:12])
    if len(affected) > 12:
        affected_preview += ", ..."
    lines = [
        ("Transitive", str(bool(vuln.get("is_transitive")))),
        ("Ignored Reason", str(vuln.get("ignored_reason") or "-")),
        ("Ignored Expires", str(vuln.get("ignored_expires") or "-")),
        ("Analyzed Requirement", str(analyzed_req.get("raw") or "-")),
        ("Requirement Source", str(analyzed_req.get("found") or "-")),
        ("Vulnerable Spec", specs or "-"),
        ("All Vulnerable Specs", all_specs or "-"),
        ("CVSS Base Score", str(cvss3.get("base_score") or "-")),
        ("CVSS Vector", str(cvss3.get("vector_string") or "-")),
        ("Affected Versions", "{count} total | {preview}".format(count=len(affected), preview=affected_preview or "-")),
    ]
    return "".join(
        "<div class='detail-line'><strong>{k}:</strong> {v}</div>".format(k=escape(k), v=escape(v))
        for k, v in lines
    )


def _render_remediations(remediations):
    out = []
    if not isinstance(remediations, dict) or not remediations:
        return "<tr><td colspan='5'>No remediation data found.</td></tr>"
    for pkg, info in remediations.items():
        reqs = info.get("requirements") or {}
        if not reqs:
            continue
        for req_spec, rec in reqs.items():
            rec_ver = str(rec.get("recommended_version") or "-")
            other = ", ".join(str(x) for x in (rec.get("other_recommended_versions") or [])) or "-"
            more = str(rec.get("more_info_url") or "")
            more_html = (
                "<a href='{u}' target='_blank' rel='noopener'>Link</a>".format(u=escape(more))
                if more
                else "-"
            )
            out.append(
                "<tr><td>{pkg}</td><td>{spec}</td><td>{rec}</td><td>{other}</td><td>{more}</td></tr>".format(
                    pkg=escape(str(pkg)),
                    spec=escape(str(req_spec)),
                    rec=escape(rec_ver),
                    other=escape(other),
                    more=more_html,
                )
            )
    return "\n".join(out) if out else "<tr><td colspan='5'>No remediation rows found.</td></tr>"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--input", required=True)
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("-t", "--generated-at", default="manual")
    ap.add_argument("-v", "--version", default="unknown")
    ap.add_argument("--scanner-version", default="")
    args = ap.parse_args()

    payload = _load_safety_payload(Path(args.input))
    generated_at = str(payload.get("generated_at") or args.generated_at)
    version = str(payload.get("version") or args.version)
    report_meta = payload.get("report_meta") or {}

    scanner_ver = args.scanner_version.strip() if args.scanner_version else ""
    if not scanner_ver:
        scanner_ver = str(report_meta.get("safety_version") or "unknown")
    scanner_info = "Scanner: {scanner_ver}".format(scanner_ver=scanner_ver)
    scan_info = "Scan Timestamp: {ts} | Git: {branch}@{commit}".format(
        ts=str(report_meta.get("timestamp") or "-"),
        branch=str((report_meta.get("git") or {}).get("branch") or "-"),
        commit=str((report_meta.get("git") or {}).get("commit") or "-")[:12] or "-",
    )

    vulns = payload.get("vulnerabilities") or []
    ignored = payload.get("ignored_vulnerabilities") or []
    all_rows = [(False, v) for v in vulns] + [(True, v) for v in ignored]

    rows_html = []
    for idx, (is_ignored, vuln) in enumerate(all_rows, start=1):
        package = str(vuln.get("package_name") or "")
        ver = str(vuln.get("analyzed_version") or "")
        vid = str(vuln.get("vulnerability_id") or "")
        cve = str(vuln.get("CVE") or "")
        cve_display = cve[4:] if cve.upper().startswith("CVE-") else cve
        published = str(vuln.get("published_date") or "")
        fixes = ", ".join(str(x) for x in (vuln.get("fixed_versions") or []))
        advisory = str(vuln.get("advisory") or "")
        severity, rank, cvss3 = _severity_info(vuln)
        state = "Ignored" if is_ignored else "Active"
        row_id = "row-{i}".format(i=idx)

        rows_html.append(
            "<tr class='main-row' data-row-id='{rid}' data-expanded='no' data-severity='{sev}' data-severity-rank='{rank}' data-ignored='{ignored}'>"
            "<td>{pkg}</td><td>{ver}</td><td>{vid}</td>"
            "<td>{cve}</td><td><span class='chip'>{sev_label}</span></td><td>{pub}</td><td>{fix}</td><td>{state}</td>"
            "<td class='links col-links'>{links}</td>"
            "<td class='small summary-cell col-summary' title='{adv_title}'>{adv}</td>"
            "<td><button type='button' onclick=\"toggleAdvanced('{rid}')\">Advanced</button></td>"
            "</tr>".format(
                rid=escape(row_id),
                sev=escape(severity),
                rank=rank,
                ignored="yes" if is_ignored else "no",
                pkg=escape(package),
                ver=escape(ver),
                vid=escape(vid),
                cve=(
                    "<a href='https://www.cve.org/CVERecord?id={id}' target='_blank' rel='noopener'>{label}</a>".format(
                        id=escape(cve),
                        label=escape(cve_display),
                    )
                    if cve
                    else "-"
                ),
                sev_label=escape(severity.capitalize() if severity != "unreported" else "Unspecified"),
                pub=escape(published),
                fix=escape(fixes or "-"),
                state=escape(state),
                links=_build_links(vuln, cve),
                adv=escape(_short_text(advisory)),
                adv_title=escape(advisory),
            )
        )
        rows_html.append(
            "<tr class='detail-row' data-parent-id='{rid}' style='display:none;'><td colspan='11'><div class='detail-block'>{content}</div></td></tr>".format(
                rid=escape(row_id),
                content=_advanced_block(vuln, cvss3),
            )
        )

    html = HTML_TEMPLATE.format(
        source=escape(Path(args.input).name),
        generated_at=escape(generated_at),
        version=escape(version),
        scanner_info=escape(scanner_info),
        scan_info=escape(scan_info),
        packages_found=escape(str(report_meta.get("packages_found") or len(report_meta.get("scanned") or []))),
        active_vulns=escape(str(len(vulns))),
        ignored_vulns=escape(str(len(ignored))),
        rem_count=escape(str(report_meta.get("remediations_recommended") or 0)),
        rows="\n".join(rows_html) if rows_html else "<tr class='main-row'><td colspan='11'>No Safety vulnerability rows found.</td></tr>",
        remediation_rows=_render_remediations(payload.get("remediations") or {}),
    )
    Path(args.output).write_text(html, encoding="utf-8")


if __name__ == "__main__":
    main()
