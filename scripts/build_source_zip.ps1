param(
    [string]$Version = "0.3.0"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$dist = Join-Path $root "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null
$staging = Join-Path $env:TEMP ("yutian_src_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $staging | Out-Null

$exclude = @(".git", ".build-venv", "build", "dist", "out", "work", "logs", "__pycache__", ".pytest_cache")
foreach ($item in Get-ChildItem $root -Force) {
    if ($exclude -contains $item.Name) { continue }
    Copy-Item $item.FullName (Join-Path $staging $item.Name) -Recurse -Force
}
Get-ChildItem $staging -Directory -Recurse -Filter __pycache__ -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

$bat = @(
    "@echo off",
    'cd /d "%~dp0"',
    'python -m tianti gui',
    "if errorlevel 1 pause"
)
Set-Content -Path (Join-Path $staging "启动御天分析.bat") -Value $bat -Encoding Default

$zip = Join-Path $dist ("御天分析-{0}-源码包.zip" -f $Version)
Compress-Archive -Path (Join-Path $staging "*") -DestinationPath $zip -CompressionLevel Optimal -Force
Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "已生成：$zip"
Write-Host "目标机需要 Python 3.12（标准库即可，tkinter 必需）"
