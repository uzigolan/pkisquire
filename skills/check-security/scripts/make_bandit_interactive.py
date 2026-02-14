import argparse
import json
from pathlib import Path


def build_html(rows):
    html = """<!doctype html>
<html>
<head>
  <meta charset=\"utf-8\" />
  <title>Static Code Security Analysis</title>
  <style>
    body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; }
    h1 { margin: 0 0 8px 0; }
    .controls { display: flex; gap: 12px; flex-wrap: wrap; margin: 12px 0 16px; align-items: center; }
    .spacer { flex: 1 1 auto; }
    select, input { padding: 6px 8px; font-size: 14px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; vertical-align: top; }
    th { background: #f2f2f2; cursor: pointer; user-select: none; }
    tr:nth-child(even) { background: #fafafa; }
    .pill { padding: 2px 6px; border-radius: 4px; font-size: 12px; }
    .sev-high { background: #ffebee; color: #b71c1c; }
    .sev-med { background: #fff8e1; color: #8d6e00; }
    .sev-low { background: #e8f5e9; color: #1b5e20; }
    .code { white-space: pre-wrap; font-family: Consolas, monospace; font-size: 12px; }
    .muted { color: #666; }
  </style>
</head>
<body>
  <h1>Static Code Security Analysis</h1>
  <div class=\"muted\">Bandit findings for local Python source files, including severity, confidence, CWE, and code context.</div>
  <div class=\"muted\">__META__</div>

  <div class=\"controls\">
    <label>Show:
      <select id=\"pageSize\" onchange=\"changePageSize()\">
        <option value=\"10\" selected>10</option>
        <option value=\"25\">25</option>
        <option value=\"50\">50</option>
      </select>
    </label>
    <span class=\"muted\" id=\"pageInfo\"></span>
    <input id=\"search\" type=\"text\" placeholder=\"Search text or file\" />
    <select id=\"severity\">
      <option value=\"\">All severities</option>
      <option value=\"HIGH\">HIGH</option>
      <option value=\"MEDIUM\">MEDIUM</option>
      <option value=\"LOW\">LOW</option>
    </select>
    <select id=\"confidence\">
      <option value=\"\">All confidence</option>
      <option value=\"HIGH\">HIGH</option>
      <option value=\"MEDIUM\">MEDIUM</option>
      <option value=\"LOW\">LOW</option>
    </select>
    <span class=\"spacer\"></span>
    <button type=\"button\" onclick=\"previousPage()\">Previous</button>
    <button type=\"button\" onclick=\"nextPage()\">Next</button>
  </div>

  <table id=\"tbl\">
    <thead>
      <tr>
        <th data-key=\"severity\">Severity</th>
        <th data-key=\"confidence\">Confidence</th>
        <th data-key=\"test_id\">Test ID</th>
        <th data-key=\"file\">File</th>
        <th data-key=\"line\">Line</th>
        <th data-key=\"text\">Issue</th>
        <th data-key=\"cwe\">CWE</th>
        <th data-key=\"more_info\">More Info</th>
        <th>Code</th>
      </tr>
    </thead>
    <tbody></tbody>
  </table>

<script>
const rows = __ROWS__;
let sortKey = 'severity';
let sortAsc = true;
let currentPage = 1;
let pageSize = 10;
let filteredRows = rows.slice();

function sevClass(sev) {
  if (sev === 'HIGH') return 'sev-high';
  if (sev === 'MEDIUM') return 'sev-med';
  return 'sev-low';
}

function render(resetPage = false) {
  const q = document.getElementById('search').value.toLowerCase();
  const sev = document.getElementById('severity').value;
  const conf = document.getElementById('confidence').value;

  filteredRows = rows.filter(r => {
    const hay = (r.text + ' ' + r.file + ' ' + r.test_id + ' ' + r.test_name + ' ' + r.code).toLowerCase();
    if (q && !hay.includes(q)) return false;
    if (sev && r.severity !== sev) return false;
    if (conf && r.confidence !== conf) return false;
    return true;
  });

  filteredRows.sort((a,b) => {
    const av = a[sortKey] ?? '';
    const bv = b[sortKey] ?? '';
    if (av === bv) return 0;
    if (sortAsc) return av > bv ? 1 : -1;
    return av < bv ? 1 : -1;
  });

  if (resetPage) currentPage = 1;
  renderPage(currentPage);
}

function renderPage(page) {
  const total = filteredRows.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  currentPage = Math.min(Math.max(1, page), totalPages);
  const start = (currentPage - 1) * pageSize;
  const end = start + pageSize;
  const tbody = document.querySelector('#tbl tbody');
  tbody.innerHTML = '';
  for (const r of filteredRows.slice(start, end)) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class=\"pill ${sevClass(r.severity)}\">${r.severity}</span></td>
      <td>${r.confidence}</td>
      <td>${r.test_id}</td>
      <td>${r.file}</td>
      <td>${r.line}</td>
      <td>${r.text}</td>
      <td>${r.cwe}</td>
      <td>${r.more_info}</td>
      <td class=\"code\">${r.code}</td>
    `;
    tbody.appendChild(tr);
  }
  const shownStart = total === 0 ? 0 : start + 1;
  const shownEnd = Math.min(end, total);
  document.getElementById('pageInfo').textContent = `Page ${currentPage}/${totalPages} | Showing ${shownStart}-${shownEnd}`;
}

for (const el of ['search','severity','confidence']) {
  document.getElementById(el).addEventListener('input', () => render(true));
  document.getElementById(el).addEventListener('change', () => render(true));
}

document.querySelectorAll('th[data-key]').forEach(th => {
  th.addEventListener('click', () => {
    const key = th.getAttribute('data-key');
    if (sortKey === key) {
      sortAsc = !sortAsc;
    } else {
      sortKey = key;
      sortAsc = true;
    }
    render(false);
  });
});

function changePageSize() {
  pageSize = parseInt(document.getElementById('pageSize').value, 10) || 10;
  render(true);
}

function nextPage() {
  renderPage(currentPage + 1);
}

function previousPage() {
  renderPage(currentPage - 1);
}

render(true);
</script>
</body>
</html>
"""
    return html


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', required=True)
    parser.add_argument('-o', '--output', required=True)
    parser.add_argument('-t', '--generated-at', default='')
    parser.add_argument('-v', '--version', default='')
    args = parser.parse_args()

    src = Path(args.input)
    data = json.loads(src.read_text(encoding='utf-8'))
    results = data.get('results', [])

    rows = []
    for r in results:
        rows.append({
            'severity': r.get('issue_severity', ''),
            'confidence': r.get('issue_confidence', ''),
            'test_id': r.get('test_id', ''),
            'test_name': r.get('test_name', ''),
            'file': r.get('filename', ''),
            'line': r.get('line_number', ''),
            'text': r.get('issue_text', ''),
            'cwe': (r.get('issue_cwe') or {}).get('id', ''),
            'more_info': r.get('more_info', ''),
            'code': r.get('code', ''),
        })

    generated_at = args.generated_at or 'unknown'
    version = args.version or 'unknown'
    meta = f"Source: bandit-report.json | Generated at: {generated_at} | Version: {version}"
    html = build_html(rows).replace('__ROWS__', json.dumps(rows)).replace('__META__', meta)
    Path(args.output).write_text(html, encoding='utf-8')


if __name__ == '__main__':
    main()
