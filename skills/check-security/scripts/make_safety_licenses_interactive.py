import argparse
import json
from html import escape
from pathlib import Path


HTML_TEMPLATE = """<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Safety License Report</title>
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
    .meta {{ color: var(--muted); margin-bottom: 16px; }}
    .controls {{ display: flex; gap: 12px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; margin: 12px 0 16px; }}
    .card {{ border: 1px solid var(--border); border-radius: 10px; background: var(--card); padding: 10px 12px; }}
    .card .label {{ font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }}
    .card .value {{ font-size: 20px; font-weight: 700; }}
    .spacer {{ flex: 1 1 auto; }}
    input[type="text"] {{ padding: 6px 10px; border: 1px solid var(--border); border-radius: 6px; min-width: 260px; }}
    select {{ padding: 6px 10px; border: 1px solid var(--border); border-radius: 6px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid var(--border); padding: 8px 10px; vertical-align: top; }}
    th {{ text-align: left; white-space: nowrap; cursor: pointer; }}
    .chip {{ display: inline-block; padding: 2px 8px; border-radius: 999px; background: var(--chip); font-size: 12px; }}
    .type-pill {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; font-weight: 700; border: 1px solid var(--border); }}
    .type-permissive {{ background: #e7f6ed; color: #166534; border-color: #bbf7d0; }}
    .type-weak-copyleft {{ background: #fff7ed; color: #9a3412; border-color: #fed7aa; }}
    .type-strong-copyleft {{ background: #fee2e2; color: #991b1b; border-color: #fecaca; }}
    .type-review {{ background: #f1f5f9; color: #334155; border-color: #cbd5e1; }}
    .legend {{ margin: 12px 0 16px; color: var(--muted); font-size: 12px; line-height: 1.45; }}
    .pill {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; font-weight: 700; border: 1px solid var(--border); }}
    .pill-good {{ background: #e7f6ed; color: #166534; border-color: #bbf7d0; }}
    .pill-warn {{ background: #fff7ed; color: #9a3412; border-color: #fed7aa; }}
    .pill-bad {{ background: #fee2e2; color: #991b1b; border-color: #fecaca; }}
    .pill-neutral {{ background: #f1f5f9; color: #334155; border-color: #cbd5e1; }}
    .count {{ margin-left: auto; color: var(--muted); }}
  </style>
</head>
<body>
  <h1>Safety License Report</h1>
  <div class="meta">Additional dependency license results from Safety.</div>
  <div class="meta">Source: {source} | Generated at: {generated_at} | Version: {version}</div>
  <div class="meta">{scanner_info}</div>
  <div class="meta">{scan_info}</div>
  <div class="cards">
    <div class="card"><div class="label">Packages Found</div><div class="value">{packages_found}</div></div>
    <div class="card"><div class="label">Licenses Found</div><div class="value">{licenses_found}</div></div>
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
    <input id="filterInput" type="text" placeholder="Filter by package or license" onkeyup="applyFilter()" />
    <span class="spacer"></span>
    <button type="button" onclick="previousPage()">Previous</button>
    <button type="button" onclick="nextPage()">Next</button>
    <span class="count" id="resultCount"></span>
  </div>
  <table id="licenseTable">
    <thead>
      <tr>
        <th onclick="sortTable(0)">Package</th>
        <th onclick="sortTable(1)">Version</th>
        <th onclick="sortTable(2)">License</th>
        <th onclick="sortTable(3)">Type</th>
        <th onclick="sortTable(4)">Overall Fit</th>
        <th onclick="sortTable(5)">SPDX</th>
        <th onclick="sortTable(6)">Risk</th>
        <th onclick="sortTable(7)">Commercial</th>
        <th onclick="sortTable(8)">Copyleft Scope</th>
        <th onclick="sortTable(9)">Patent</th>
        <th onclick="sortTable(10)">Notice</th>
        <th onclick="sortTable(11)">Attribution</th>
        <th onclick="sortTable(12)">Mod Disclosure</th>
        <th>Flags</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>
  <div class="legend">
    <strong>Column legends:</strong><br>
    <strong>Type</strong>: high-level license class (permissive vs copyleft).<br>
    <strong>SPDX</strong>: normalized identifier used for automation/policy matching.<br>
    <strong>Overall Fit</strong>: aggregate suitability for your project, derived from all shown policy attributes.<br>
    <strong>Risk</strong>: quick compliance risk signal (`Low`, `Medium`, `High`, `Review`).<br>
    <strong>Commercial</strong>: whether commercial use is generally allowed (`Yes`, `Conditional`, `Review`).<br>
    <strong>Copyleft Scope</strong>: where copyleft obligations apply (`None`, `File-level`, `Library/linking`, `Distribution-wide`, `Network-service`).<br>
    <strong>Patent</strong>: indicates explicit patent clause/grant in common interpretation.<br>
    <strong>Notice</strong>: keep license/notice text in distribution.<br>
    <strong>Attribution</strong>: credit/authorship notice expected.<br>
    <strong>Mod Disclosure</strong>: disclose modified source/files in certain conditions.<br>
    <strong>Flags</strong>: compact legal/compliance hints for quick triage.
    <br><br>
    <strong>Color key:</strong>
    <span class="pill pill-good">Good / Low Risk</span>
    <span class="pill pill-warn">Needs Attention</span>
    <span class="pill pill-bad">High Risk</span>
    <span class="pill pill-neutral">Review</span>
  </div>
<script>
  let sortDirections = {{}};
  let currentPage = 1;
  let pageSize = 10;
  let filteredRows = [];
  function applyFilter(resetPage = true) {{
    const input = document.getElementById('filterInput').value.toLowerCase();
    const rows = Array.from(document.querySelectorAll('#licenseTable tbody tr'));
    filteredRows = rows.filter(row => row.textContent.toLowerCase().indexOf(input) > -1);
    document.getElementById('resultCount').textContent = 'Matched ' + filteredRows.length + ' rows';
    if (resetPage) currentPage = 1;
    renderPage();
  }}
  function renderPage() {{
    const rows = Array.from(document.querySelectorAll('#licenseTable tbody tr'));
    const total = filteredRows.length;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    currentPage = Math.min(Math.max(1, currentPage), totalPages);
    const start = (currentPage - 1) * pageSize;
    const end = start + pageSize;
    rows.forEach(r => r.style.display = 'none');
    filteredRows.slice(start, end).forEach(r => r.style.display = '');
    const shownStart = total === 0 ? 0 : start + 1;
    const shownEnd = Math.min(end, total);
    document.getElementById('pageInfo').textContent = 'Page ' + currentPage + '/' + totalPages + ' | Showing ' + shownStart + '-' + shownEnd;
  }}
  function sortTable(i) {{
    const tbody = document.querySelector('#licenseTable tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const asc = sortDirections[i] !== 'asc';
    sortDirections[i] = asc ? 'asc' : 'desc';
    rows.sort((a, b) => {{
      const aText = a.cells[i].textContent.trim().toLowerCase();
      const bText = b.cells[i].textContent.trim().toLowerCase();
      if (aText < bText) return asc ? -1 : 1;
      if (aText > bText) return asc ? 1 : -1;
      return 0;
    }});
    rows.forEach(r => tbody.appendChild(r));
    applyFilter(false);
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
        if isinstance(obj, dict) and ("licenses" in obj or "report_meta" in obj):
            return obj
    return None


def _load_safety_payload(path: Path):
    raw = path.read_text(encoding="utf-8-sig", errors="replace")
    try:
        data = json.loads(raw)
    except Exception:
        return {}
    if isinstance(data, dict) and ("licenses" in data or "report_meta" in data):
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


def _license_details(license_name: str):
    text = (license_name or "").strip().lower()
    if "mit" in text:
        return ("Permissive", "Attribution and license notice required.")
    if "bsd" in text:
        return ("Permissive", "Attribution and disclaimer retention required.")
    if "apache-2.0" in text or "apache 2.0" in text:
        return ("Permissive", "Includes NOTICE and patent grant/termination terms.")
    if "mpl-2.0" in text or "mpl 2.0" in text:
        return ("Weak copyleft", "File-level copyleft obligations for modified files.")
    if "python-2.0" in text or "python software foundation" in text:
        return ("Permissive", "PSF-style permissive terms; keep notices.")
    if "lgpl" in text:
        return ("Weak copyleft", "Linking allowed; modified library source obligations.")
    if "gpl" in text or "agpl" in text or "sspl" in text:
        return ("Strong copyleft", "Distribution/network use may trigger source obligations.")
    return ("Review", "Unrecognized or composite license; perform legal review.")


def _license_profile(license_name: str):
    text = (license_name or "").strip().lower()

    profile = {
        "spdx": "UNKNOWN",
        "risk": "Medium",
        "commercial": "Review",
        "copyleft_scope": "None",
        "patent": "No",
        "notice": "Yes",
        "attribution": "Yes",
        "mod_disclosure": "No",
    }

    if "mit" in text:
        profile.update({"spdx": "MIT", "risk": "Low", "commercial": "Yes"})
    elif "bsd-2" in text:
        profile.update({"spdx": "BSD-2-Clause", "risk": "Low", "commercial": "Yes"})
    elif "bsd-3" in text:
        profile.update({"spdx": "BSD-3-Clause", "risk": "Low", "commercial": "Yes"})
    elif "apache-2.0" in text or "apache 2.0" in text:
        profile.update({"spdx": "Apache-2.0", "risk": "Low", "commercial": "Yes", "patent": "Yes"})
    elif "mpl-2.0" in text or "mpl 2.0" in text:
        profile.update({
            "spdx": "MPL-2.0",
            "risk": "Medium",
            "commercial": "Yes",
            "copyleft_scope": "File-level",
            "patent": "Yes",
            "mod_disclosure": "Yes",
        })
    elif "python-2.0" in text or "python software foundation" in text:
        profile.update({"spdx": "Python-2.0", "risk": "Low", "commercial": "Yes"})
    elif "lgpl" in text:
        profile.update({
            "spdx": "LGPL",
            "risk": "Medium",
            "commercial": "Conditional",
            "copyleft_scope": "Library/linking",
            "mod_disclosure": "Yes",
        })
    elif "agpl" in text:
        profile.update({
            "spdx": "AGPL",
            "risk": "High",
            "commercial": "Conditional",
            "copyleft_scope": "Network-service",
            "mod_disclosure": "Yes",
        })
    elif "gpl" in text or "sspl" in text:
        profile.update({
            "spdx": "GPL/SSPL",
            "risk": "High",
            "commercial": "Conditional",
            "copyleft_scope": "Distribution-wide",
            "mod_disclosure": "Yes",
        })
    else:
        profile.update({
            "risk": "Review",
            "commercial": "Review",
            "copyleft_scope": "Review",
            "notice": "Review",
            "attribution": "Review",
            "mod_disclosure": "Review",
        })

    return profile

def _license_flags(license_name: str):
    text = (license_name or "").strip().lower()
    flags = []
    if any(x in text for x in ["mit", "bsd", "apache", "mpl", "python"]):
        flags.append("Notice")
    if "apache-2.0" in text or "apache 2.0" in text or "mpl-2.0" in text or "mpl 2.0" in text:
        flags.append("Patent")
    if "lgpl" in text:
        flags.append("Weak-Copyleft")
    if any(x in text for x in ["gpl", "agpl", "sspl"]) and "lgpl" not in text:
        flags.append("Strong-Copyleft")
    if not flags:
        flags.append("Review")
    return flags

def _type_class(license_type: str):
    t = (license_type or "").strip().lower()
    if t == "permissive":
        return "type-permissive"
    if t == "weak copyleft":
        return "type-weak-copyleft"
    if t == "strong copyleft":
        return "type-strong-copyleft"
    return "type-review"

def _pill_class(kind: str, value: str):
    v = (value or "").strip().lower()
    if kind == "risk":
        if v == "low":
            return "pill-good"
        if v == "medium":
            return "pill-warn"
        if v == "high":
            return "pill-bad"
        return "pill-neutral"
    if kind == "commercial":
        if v == "yes":
            return "pill-good"
        if v == "conditional":
            return "pill-warn"
        return "pill-neutral"
    if kind == "scope":
        if v == "none":
            return "pill-good"
        if v in {"file-level", "library/linking"}:
            return "pill-warn"
        if v in {"distribution-wide", "network-service"}:
            return "pill-bad"
        return "pill-neutral"
    if kind in {"patent", "notice", "attribution", "mods"}:
        if v == "yes":
            return "pill-warn"
        if v == "no":
            return "pill-good"
        return "pill-neutral"
    return "pill-neutral"

def _overall_fit(profile: dict):
    risk = (profile.get("risk") or "").lower()
    commercial = (profile.get("commercial") or "").lower()
    scope = (profile.get("copyleft_scope") or "").lower()
    patent = (profile.get("patent") or "").lower()
    notice = (profile.get("notice") or "").lower()
    attribution = (profile.get("attribution") or "").lower()
    mods = (profile.get("mod_disclosure") or "").lower()

    score = 100
    score += {"low": 0, "medium": -20, "high": -45, "review": -35}.get(risk, -25)
    score += {"yes": 0, "conditional": -15, "review": -30}.get(commercial, -25)
    score += {
        "none": 0,
        "file-level": -10,
        "library/linking": -20,
        "distribution-wide": -40,
        "network-service": -45,
        "review": -25,
    }.get(scope, -20)

    # "Yes" means extra obligation for these fields, but not necessarily a blocker.
    score += {"yes": -5, "no": 0, "review": -8}.get(notice, -5)
    score += {"yes": -5, "no": 0, "review": -8}.get(attribution, -5)
    score += {"yes": -10, "no": 0, "review": -12}.get(mods, -8)

    # Explicit patent grant is usually favorable for commercial consumers.
    score += {"yes": 5, "no": 0, "review": -5}.get(patent, 0)
    score = max(0, min(100, score))

    if score >= 85:
        return ("Strong ({})".format(score), "pill-good")
    if score >= 70:
        return ("Good ({})".format(score), "pill-good")
    if score >= 55:
        return ("Conditional ({})".format(score), "pill-warn")
    if score >= 40:
        return ("Legal Review ({})".format(score), "pill-neutral")
    return ("High Impact ({})".format(score), "pill-bad")


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

    rows = payload.get("licenses") or []
    scanner_ver = args.scanner_version.strip() if args.scanner_version else ""
    if not scanner_ver:
        scanner_ver = str(report_meta.get("safety_version") or "unknown")
    scanner_info = "Scanner: {scanner_ver}".format(scanner_ver=scanner_ver)
    scan_info = "Scan Timestamp: {ts} | Git: {branch}@{commit}".format(
        ts=str(report_meta.get("timestamp") or "-"),
        branch=str((report_meta.get("git") or {}).get("branch") or "-"),
        commit=str((report_meta.get("git") or {}).get("commit") or "-")[:12] or "-",
    )
    rows_html = []
    for row in rows:
        pkg = str(row.get("package") or "")
        ver = str(row.get("version") or "")
        lic = str(row.get("license") or "")
        lic_type, lic_note = _license_details(lic)
        type_class = _type_class(lic_type)
        profile = _license_profile(lic)
        fit_label, fit_class = _overall_fit(profile)
        flags = ", ".join(_license_flags(lic))
        rows_html.append(
            "<tr><td>{pkg}</td><td>{ver}</td><td><span class='chip'>{lic}</span></td><td><span class='type-pill {cls}'>{typ}</span></td><td><span class='pill {fit_cls}'>{fit}</span></td><td>{spdx}</td><td><span class='pill {risk_cls}'>{risk}</span></td><td><span class='pill {com_cls}'>{commercial}</span></td><td><span class='pill {scope_cls}'>{scope}</span></td><td><span class='pill {pat_cls}'>{patent}</span></td><td><span class='pill {not_cls}'>{notice}</span></td><td><span class='pill {att_cls}'>{attrib}</span></td><td><span class='pill {mod_cls}'>{mods}</span></td><td>{flags}</td></tr>".format(
                pkg=escape(pkg),
                ver=escape(ver),
                lic=escape(lic),
                cls=escape(type_class),
                typ=escape(lic_type),
                fit=escape(fit_label),
                fit_cls=escape(fit_class),
                spdx=escape(profile["spdx"]),
                risk_cls=_pill_class("risk", profile["risk"]),
                risk=escape(profile["risk"]),
                com_cls=_pill_class("commercial", profile["commercial"]),
                commercial=escape(profile["commercial"]),
                scope_cls=_pill_class("scope", profile["copyleft_scope"]),
                scope=escape(profile["copyleft_scope"]),
                pat_cls=_pill_class("patent", profile["patent"]),
                patent=escape(profile["patent"]),
                not_cls=_pill_class("notice", profile["notice"]),
                notice=escape(profile["notice"]),
                att_cls=_pill_class("attribution", profile["attribution"]),
                attrib=escape(profile["attribution"]),
                mod_cls=_pill_class("mods", profile["mod_disclosure"]),
                mods=escape(profile["mod_disclosure"]),
                flags=escape(flags),
            )
        )

    html = HTML_TEMPLATE.format(
        source=escape(Path(args.input).name),
        generated_at=escape(generated_at),
        version=escape(version),
        scanner_info=escape(scanner_info),
        scan_info=escape(scan_info),
        packages_found=escape(str(report_meta.get("packages_found") or len(report_meta.get("scanned") or []))),
        licenses_found=escape(str(report_meta.get("licenses_found") or len(rows))),
        rows="\n".join(rows_html) if rows_html else "<tr><td colspan='14'>No Safety license rows found.</td></tr>",
    )
    Path(args.output).write_text(html, encoding="utf-8")


if __name__ == "__main__":
    main()
