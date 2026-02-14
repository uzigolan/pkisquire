import argparse
import json
from pathlib import Path


HTML_TEMPLATE = """<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Dependency License Compliance Report</title>
  <style>
    :root {
      --bg: #ffffff;
      --text: #1f2933;
      --muted: #6b7280;
      --border: #e5e7eb;
      --chip: #f3f4f6;
      --warn: #b45309;
    }
    body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: var(--text); background: var(--bg); }
    h1 { margin: 0 0 6px; }
    .meta { color: var(--muted); margin-bottom: 16px; }
    .controls { display: flex; gap: 12px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }
    .spacer { flex: 1 1 auto; }
    input[type="text"] { padding: 6px 10px; border: 1px solid var(--border); border-radius: 6px; min-width: 280px; }
    select { padding: 6px 10px; border: 1px solid var(--border); border-radius: 6px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { border-bottom: 1px solid var(--border); padding: 8px 10px; vertical-align: top; }
    th { text-align: left; white-space: nowrap; cursor: pointer; }
    .chip { display: inline-block; padding: 2px 8px; border-radius: 999px; background: var(--chip); font-size: 12px; }
    .warn { color: var(--warn); font-weight: 600; }
    .muted { color: var(--muted); }
    .count { margin-left: auto; color: var(--muted); }
  </style>
</head>
<body>
  <h1>Dependency License Compliance Report</h1>
  <div class="meta">Declared licenses for Python dependencies, including denylist policy matching.</div>
  <div class="meta">Source: __SOURCE__ | Generated at: __GENERATED_AT__ | Version: __VERSION__</div>
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
    <label>
      License:
      <select id="licenseState" onchange="applyFilter()">
        <option value="">All</option>
        <option value="unknown">Unknown/Unlicensed</option>
        <option value="known">Known</option>
      </select>
    </label>
    <label>
      Denied:
      <select id="deniedState" onchange="applyFilter()">
        <option value="">All</option>
        <option value="yes">Denied</option>
        <option value="no">Allowed</option>
      </select>
    </label>
    <label>
      Policy:
      <select id="policyState" onchange="applyFilter()">
        <option value="">All</option>
        <option value="allowed">Allowed</option>
        <option value="allowed-with-notice">Allowed With Notice</option>
        <option value="review-required">Review Required</option>
        <option value="restricted-copyleft-weak">Restricted (Copyleft Weak)</option>
        <option value="prohibited-strong-copyleft">Prohibited (Strong Copyleft)</option>
        <option value="unknown-unlicensed">Unknown/Unlicensed</option>
      </select>
    </label>
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
        <th onclick="sortTable(3)">Policy</th>
        <th onclick="sortTable(4)">Denied</th>
      </tr>
    </thead>
    <tbody>
      __ROWS__
    </tbody>
  </table>
  <div class="meta"><strong>Policy legend:</strong></div>
  <div class="meta">Allowed: permissive use.</div>
  <div class="meta">Allowed With Notice: use allowed with attribution/notice obligations.</div>
  <div class="meta">Review Required: manual legal review needed.</div>
  <div class="meta">Restricted (Copyleft Weak): conditional use, e.g., LGPL.</div>
  <div class="meta">Prohibited (Strong Copyleft): blocked by policy.</div>
  <div class="meta">Unknown/Unlicensed: license unclear or missing.</div>

<script>
  let sortDirections = {};
  let currentPage = 1;
  let pageSize = 10;
  let filteredRows = [];

  function applyFilter(resetPage = true) {
    const input = document.getElementById('filterInput').value.toLowerCase();
    const state = document.getElementById('licenseState').value;
    const deniedState = document.getElementById('deniedState').value;
    const policyState = document.getElementById('policyState').value;
    const tbody = document.querySelector('#licenseTable tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    filteredRows = rows.filter(row => {
      const text = row.textContent.toLowerCase();
      const isUnknown = (row.getAttribute('data-license-known') || '') === 'no';
      const isDenied = (row.getAttribute('data-denied') || '') === 'yes';
      const rowPolicy = (row.getAttribute('data-policy') || '').toLowerCase();
      const matchesText = text.indexOf(input) > -1;
      let matchesState = true;
      let matchesDenied = true;
      let matchesPolicy = true;
      if (state === 'unknown') matchesState = isUnknown;
      if (state === 'known') matchesState = !isUnknown;
      if (deniedState === 'yes') matchesDenied = isDenied;
      if (deniedState === 'no') matchesDenied = !isDenied;
      if (policyState) matchesPolicy = rowPolicy === policyState;
      return matchesText && matchesState && matchesDenied && matchesPolicy;
    });
    document.getElementById('resultCount').textContent = 'Matched ' + filteredRows.length + ' of ' + rows.length;
    if (resetPage) currentPage = 1;
    renderPage();
  }

  function renderPage() {
    const tbody = document.querySelector('#licenseTable tbody');
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
  }

  function sortTable(columnIndex) {
    const tbody = document.querySelector('#licenseTable tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const isAscending = sortDirections[columnIndex] !== 'asc';
    sortDirections[columnIndex] = isAscending ? 'asc' : 'desc';
    rows.sort((a, b) => {
      const aText = a.cells[columnIndex].textContent.trim().toLowerCase();
      const bText = b.cells[columnIndex].textContent.trim().toLowerCase();
      if (aText < bText) return isAscending ? -1 : 1;
      if (aText > bText) return isAscending ? 1 : -1;
      return 0;
    });
    rows.forEach(row => tbody.appendChild(row));
    applyFilter(false);
  }

  function changePageSize() {
    pageSize = parseInt(document.getElementById('pageSizeSelect').value, 10) || 10;
    applyFilter(true);
  }

  function nextPage() {
    currentPage += 1;
    renderPage();
  }

  function previousPage() {
    currentPage -= 1;
    renderPage();
  }

  document.addEventListener('DOMContentLoaded', () => applyFilter(true));
</script>
</body>
</html>
"""


def _is_unknown(license_text):
    text = (license_text or "").strip().lower()
    return text in {"", "unknown", "unknown license", "n/a", "none"}


def _policy_category(license_text: str):
    text = (license_text or "").strip().lower()
    if _is_unknown(text):
        return "unknown-unlicensed"
    if any(x in text for x in ["agpl", "gpl", "sspl"]) and "lgpl" not in text:
        return "prohibited-strong-copyleft"
    if "lgpl" in text:
        return "restricted-copyleft-weak"
    if " or " in text or " and " in text or ";" in text:
        return "review-required"
    if any(x in text for x in ["mpl", "psf"]):
        return "allowed-with-notice"
    if any(x in text for x in ["mit", "bsd", "apache", "isc", "unlicense", "python software foundation"]):
        return "allowed"
    return "review-required"


def _policy_label(policy_value: str):
    labels = {
        "allowed": "Allowed",
        "allowed-with-notice": "Allowed With Notice",
        "review-required": "Review Required",
        "restricted-copyleft-weak": "Restricted (Copyleft Weak)",
        "prohibited-strong-copyleft": "Prohibited (Strong Copyleft)",
        "unknown-unlicensed": "Unknown/Unlicensed",
    }
    return labels.get(policy_value, "Review Required")


def _load_deny_patterns(denylist_path: Path):
    if not denylist_path.exists():
        return []
    patterns = []
    for line in denylist_path.read_text(encoding="utf-8-sig").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        patterns.append(s)
    return patterns


def _is_denied(license_text: str, patterns):
    lic = (license_text or "").lower()
    for p in patterns:
        pattern = p.lower()
        if "*" in pattern or "?" in pattern:
            import fnmatch
            if fnmatch.fnmatch(lic, pattern):
                return True
        else:
            if pattern in lic:
                return True
    return False


def iter_rows(data, deny_patterns):
    rows = []
    if not isinstance(data, list):
        return rows
    for entry in data:
        name = str(entry.get("Name", "")).strip()
        version = str(entry.get("Version", "")).strip()
        license_name = str(entry.get("License", "")).strip()
        if not name:
            continue
        unknown = _is_unknown(license_name)
        policy = _policy_category(license_name or "UNKNOWN")
        denied = _is_denied(license_name or "UNKNOWN", deny_patterns)
        rows.append({
            "name": name,
            "version": version,
            "license": license_name or "UNKNOWN",
            "known": "no" if unknown else "yes",
            "policy": policy,
            "denied": "yes" if denied else "no",
        })
    rows.sort(key=lambda r: (r["name"].lower(), r["version"].lower()))
    return rows


def render_rows(rows):
    if not rows:
        return '<tr><td colspan="5" class="muted">No package license data found.</td></tr>'
    out = []
    for r in rows:
        lic_text = r["license"]
        if r["known"] == "no":
            lic_text = '<span class="warn">' + lic_text + "</span>"
        out.append(
            "<tr data-license-known=\"{known}\" data-policy=\"{policy}\" data-denied=\"{denied}\">"
            "<td>{name}</td>"
            "<td>{version}</td>"
            "<td><span class=\"chip\">{license}</span></td>"
            "<td>{policy_label}</td>"
            "<td>{denied_label}</td>"
            "</tr>".format(
                known=r["known"],
                policy=r["policy"],
                denied=r["denied"],
                name=r["name"],
                version=r["version"],
                license=lic_text,
                policy_label=_policy_label(r["policy"]),
                denied_label=("Yes" if r["denied"] == "yes" else "No"),
            )
        )
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", required=True)
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("-t", "--generated-at", default="")
    parser.add_argument("-v", "--version", default="")
    parser.add_argument("-d", "--denylist", default="")
    args = parser.parse_args()

    data = json.loads(Path(args.input).read_text(encoding="utf-8-sig"))
    if args.denylist:
        denylist_path = Path(args.denylist)
    else:
        denylist_path = Path(args.input).parent / "license-denylist.txt"
    deny_patterns = _load_deny_patterns(denylist_path)
    rows = iter_rows(data, deny_patterns)
    html = HTML_TEMPLATE
    html = html.replace("__SOURCE__", "pip-licenses.json")
    html = html.replace("__GENERATED_AT__", args.generated_at or "unknown")
    html = html.replace("__VERSION__", args.version or "unknown")
    html = html.replace("__ROWS__", render_rows(rows))
    Path(args.output).write_text(html, encoding="utf-8")


if __name__ == "__main__":
    main()
