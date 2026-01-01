<#
.SYNOPSIS
  Generate a challenge password via the API token flow.

.DESCRIPTION
  Uses the seed token in config.ini [DEFAULT] tests_api_token to call
  /api/challenge_passwords and prints the returned password + expiry.

.PARAMETER BaseUrl
  Base URL of the server (default: https://localhost:443).

.PARAMETER Token
  API token to use. If omitted, tries to read tests_api_token from config.ini.

.PARAMETER Validity
  Optional validity override (e.g., 30m, 2h, 1d).
#>
[CmdletBinding()]
param(
    [string]$BaseUrl = "http://localhost:80",
    [string]$Token = $null,
    [switch]$SkipTlsVerify,
    [switch]$VerboseOutput
)

function Get-ConfigValue {
    param(
        [string]$Path,
        [string]$Section,
        [string]$Key
    )
    $content = Get-Content -Path $Path -Raw -ErrorAction Stop
    $pattern = "(?s)\[$Section\].*?$Key\s*=\s*(.+)"
    $match = [regex]::Match($content, $pattern)
    if ($match.Success) {
        return $match.Groups[1].Value.Trim()
    }
    return $null
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$configPath = Join-Path $repoRoot "config.ini"

if (-not $Token) {
    try {
        $Token = Get-ConfigValue -Path $configPath -Section "DEFAULT" -Key "tests_api_token"
    } catch {
        Write-Error "Failed to read config.ini: $_"
        exit 1
    }
}

if (-not $Token) {
    Write-Error "API token is required. Pass -Token or set [DEFAULT] tests_api_token in config.ini."
    exit 1
}

$body = @{}

try {
    # Prefer TLS12; optionally skip cert validation for local/self-signed
    try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 } catch {}
    if ($SkipTlsVerify) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }
    $headers = @{
        Authorization = "Bearer $Token"
    }
    $bodyJson = "{}"
    $uri = ("{0}/api/challenge_passwords" -f $BaseUrl.TrimEnd('/'))
    if ($VerboseOutput) {
        Write-Host "[DEBUG] BaseUrl        : $BaseUrl" -ForegroundColor DarkGray
        Write-Host "[DEBUG] Token (plain)  : $Token" -ForegroundColor DarkGray
        Write-Host "[DEBUG] Headers        : $($headers | ConvertTo-Json -Compress)" -ForegroundColor DarkGray
        Write-Host "[DEBUG] Body JSON      : $bodyJson" -ForegroundColor DarkGray
        Write-Host "[DEBUG] POST           : $uri" -ForegroundColor DarkGray
    }
    $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $bodyJson -ContentType "application/json"
} catch {
    $msg = $_.Exception.Message
    try {
        $respStream = $_.Exception.Response.GetResponseStream()
        if ($respStream) {
            $reader = New-Object System.IO.StreamReader($respStream)
            $respBody = $reader.ReadToEnd()
            if ($respBody) { $msg += "`nResponse body: $respBody" }
        }
    } catch {}
    Write-Error "Request failed: $msg"
    exit 1
}

if ($response.error) {
    Write-Error "API error: $($response.error)"
    exit 1
}

Write-Host "Challenge password created:" -ForegroundColor Cyan
Write-Host "  Value     : $($response.value)"
Write-Host "  Expires   : $($response.expires_at)"
Write-Host "  Validity  : $($response.validity)"
Write-Host "  User ID   : $($response.user_id)"
