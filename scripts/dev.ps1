param(
    [string]$Python = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not $Python -and $env:TIANTI_PYTHON) { $Python = $env:TIANTI_PYTHON }
if (-not $Python) {
    $bundled = Join-Path $env:USERPROFILE ".dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe"
    if (Test-Path $bundled) { $Python = $bundled }
}
if (-not $Python) {
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) { $Python = $cmd.Source }
}
if (-not $Python) { throw "找不到 Python 3.12（设置 TIANTI_PYTHON 环境变量指定解释器）" }

Write-Host "=== tianti version --check ==="
& $Python -m tianti version --check
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "=== unittest ==="
& $Python -m unittest discover -s tests -t . -v
exit $LASTEXITCODE
