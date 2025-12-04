# pyscep.ps1 - Python SCEP tools
# Usage: .\pyscep.ps1 OPERATION [OPTIONS]

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$WorkspaceRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)
$Python = Join-Path $WorkspaceRoot ".venv\Scripts\python.exe"
$env:PATH = "C:\Program Files\OpenSSL-Win64\bin;$env:PATH"

# Get all arguments
$AllArgs = $args

# Check if operation is provided
if ($AllArgs.Count -eq 0) {
    Write-Host "Usage: pyscep OPERATION [OPTIONS]"
    Write-Host ""
    Write-Host "Available OPERATIONs:"
    Write-Host "  getca       Get CA certificate"
    Write-Host "  getcaps     Get CA capabilities"
    Write-Host "  enroll      Enroll certificate"
    Write-Host ""
    Write-Host "Use 'pyscep OPERATION --help' for more information"
    exit 1
}

$Operation = $AllArgs[0]
$RemainingArgs = $AllArgs[1..($AllArgs.Count-1)]

# Handle different operations
switch ($Operation.ToLower()) {
    "enroll" {
        # Use scep_enroll.py for enroll operation
        $EnrollScript = Join-Path $WorkspaceRoot "tests\bin\scep_enroll.py"
        & $Python $EnrollScript @RemainingArgs
        exit $LASTEXITCODE
    }
    { $_ -in "getca", "getcaps" } {
        # Use scep_tool.py for other operations
        $ToolScript = Join-Path $WorkspaceRoot "tests\bin\scep_tool.py"
        & $Python $ToolScript $Operation @RemainingArgs
        exit $LASTEXITCODE
    }
    default {
        Write-Host "Unknown operation: $Operation (only getca, getcaps, enroll are supported)"
        exit 1
    }
}
