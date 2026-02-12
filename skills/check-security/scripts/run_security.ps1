param(
    [string]$Root = (Resolve-Path .)
)

$ErrorActionPreference = 'Stop'

$security = Join-Path $Root 'security'
$historyRoot = Join-Path $security 'history'
$ts = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$historyDir = Join-Path $historyRoot $ts
$generatedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'
$versionFile = Join-Path $Root 'version.txt'
$version = ''
if (Test-Path $versionFile) {
    $version = (Get-Content $versionFile -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
}
if (-not $version) {
    $version = 'unknown'
}

New-Item -ItemType Directory -Force $security | Out-Null
New-Item -ItemType Directory -Force $historyRoot | Out-Null
New-Item -ItemType Directory -Force $historyDir | Out-Null

$venvBandit = Join-Path $Root '.venv\Scripts\bandit.exe'
$venvPipAudit = Join-Path $Root '.venv\Scripts\pip-audit.exe'
$venvPython = Join-Path $Root '.venv\Scripts\python.exe'

if (-not (Test-Path $venvPython)) {
    throw 'Python venv not found at .venv. Create/activate it first.'
}

if (-not (Test-Path $venvBandit)) {
    & $venvPython -m pip install --quiet bandit
}

if (-not (Test-Path $venvPipAudit)) {
    & $venvPython -m pip install --quiet pip-audit
}

# Bandit scans: only app.py and its local imports
$depList = & $venvPython (Join-Path $PSScriptRoot 'resolve_app_deps.py') -r $Root -e 'app.py'
$depList = $depList | Where-Object { $_ -and (Test-Path $_) }

if (-not $depList) {
    throw 'No dependency files found for app.py.'
}

& $venvBandit -f json -o (Join-Path $security 'bandit-report.json') $depList
& $venvBandit -f html -o (Join-Path $security 'bandit-report.html') $depList

# Embed timestamp into Bandit HTML report
$banditHtml = Get-Content (Join-Path $security 'bandit-report.html') -Raw
$stampDiv = @"
<div style="font-family: Segoe UI, Arial, sans-serif; margin: 12px 0; color: #555;">Generated at: $generatedAt | Version: $version</div>
"@
if ($banditHtml -match '<body[^>]*>') {
    $banditHtml = $banditHtml -replace '<body[^>]*>', ('$&' + $stampDiv)
} else {
    $banditHtml = $stampDiv + $banditHtml
}
Set-Content -Path (Join-Path $security 'bandit-report.html') -Value $banditHtml -Encoding UTF8

# Interactive HTML from JSON
& $venvPython (Join-Path $PSScriptRoot 'make_bandit_interactive.py') -i (Join-Path $security 'bandit-report.json') -o (Join-Path $security 'bandit-report-interactive.html') -t $generatedAt -v $version

# pip-audit report
$pipAuditPath = Join-Path $security 'pip-audit.txt'
$pipAuditJson = Join-Path $security 'pip-audit.json'
"Generated at: $generatedAt | Version: $version" | Out-File -FilePath $pipAuditPath -Encoding ascii
& $venvPipAudit -r (Join-Path $Root 'requirements.txt') | Out-File -FilePath $pipAuditPath -Encoding ascii -Append

# pip-audit JSON (for interactive report)
& $venvPipAudit -r (Join-Path $Root 'requirements.txt') -f json | Set-Content -Path $pipAuditJson -Encoding UTF8

@"
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>pip-audit report</title>
  <style>
    body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; }
    pre { background: #f5f5f5; padding: 16px; border-radius: 6px; }
  </style>
</head>
<body>
  <h1>pip-audit report</h1>
  <div style="color: #555; margin-bottom: 12px;">Generated at: $generatedAt | Version: $version</div>
  <pre>
"@ | Set-Content -Path (Join-Path $security 'pip-audit.html') -Encoding Ascii

Get-Content (Join-Path $security 'pip-audit.txt') | Add-Content -Path (Join-Path $security 'pip-audit.html') -Encoding Ascii

@"
  </pre>
</body>
</html>
"@ | Add-Content -Path (Join-Path $security 'pip-audit.html') -Encoding Ascii

# Interactive HTML from JSON
& $venvPython (Join-Path $PSScriptRoot 'make_pip_audit_interactive.py') -i $pipAuditJson -o (Join-Path $security 'pip-audit-interactive.html') -t $generatedAt -v $version

# Snapshot into history
Copy-Item -Force (Join-Path $security 'bandit-report.json') $historyDir
Copy-Item -Force (Join-Path $security 'bandit-report.html') $historyDir
Copy-Item -Force (Join-Path $security 'bandit-report-interactive.html') $historyDir
Copy-Item -Force (Join-Path $security 'pip-audit.txt') $historyDir
Copy-Item -Force (Join-Path $security 'pip-audit.html') $historyDir
Copy-Item -Force (Join-Path $security 'pip-audit.json') $historyDir
Copy-Item -Force (Join-Path $security 'pip-audit-interactive.html') $historyDir

Write-Host "Security reports updated. History: $historyDir"
