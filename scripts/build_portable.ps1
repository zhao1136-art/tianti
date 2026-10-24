param(
    [string]$Version = "0.3.0"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$venvPy = Join-Path $root ".build-venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
    throw "缺少打包环境：先创建 .build-venv 并安装 pyinstaller（见 README 打包章节）"
}

$appName = "御天分析"
$dist = Join-Path $root "dist"
$build = Join-Path $root "build"
Remove-Item $dist, $build -Recurse -Force -ErrorAction SilentlyContinue

$hidden = @(
    "tianti.sandbox.containment",
    "tianti.sandbox.replay",
    "tianti.sandbox.telemetry_etw",
    "tianti.sandbox.snapshot",
    "tianti.sandbox.netmon",
    "tianti.sandbox.isolation",
    "tianti.sandbox.watchdog",
    "tianti.rules.engine",
    "tianti.detect.detectors",
    "tianti.report.html",
    "tianti.report.jsonr",
    "tianti.api.httpd"
)
$hiddenArgs = @()
foreach ($moduleName in $hidden) { $hiddenArgs += @("--hidden-import", $moduleName) }
# 懒加载/动态 import 的模块（scoring、static 解析器、tools 等）整包收集，避免冻结后走后备路径
$hiddenArgs += @("--collect-submodules", "tianti", "--collect-submodules", "tools")

Write-Host "=== 构建 GUI（onedir, windowed）==="
$guiArgs = @("-m", "PyInstaller", "--noconfirm", "--clean", "--windowed", "--onedir", "--name", $appName,
    "--paths", $root, "--distpath", $dist, "--workpath", $build) + $hiddenArgs + @("packaging\gui_entry.py")
& $venvPy $guiArgs
if ($LASTEXITCODE -ne 0) { throw "GUI 构建失败" }

Write-Host "=== 构建 CLI（onefile, console）==="
$cliArgs = @("-m", "PyInstaller", "--noconfirm", "--clean", "--console", "--onefile", "--name", "tianti",
    "--paths", $root, "--distpath", $dist, "--workpath", $build) + $hiddenArgs + @("packaging\cli_entry.py")
& $venvPy $cliArgs
if ($LASTEXITCODE -ne 0) { throw "CLI 构建失败" }

$pkg = Join-Path $dist $appName
Write-Host "=== 复制运行时数据 ==="
foreach ($dirName in @("rules", "detectors", "config")) {
    Copy-Item (Join-Path $root $dirName) (Join-Path $pkg $dirName) -Recurse -Force
}
Copy-Item (Join-Path $root "README.md") $pkg -Force
Copy-Item (Join-Path $root "THIRD_PARTY.md") $pkg -Force
New-Item -ItemType Directory -Force -Path (Join-Path $pkg "docs") | Out-Null
Copy-Item (Join-Path $root "docs\*") (Join-Path $pkg "docs") -Recurse -Force
New-Item -ItemType Directory -Force -Path (Join-Path $pkg "tests\fixtures\traces") | Out-Null
Copy-Item (Join-Path $root "tests\fixtures\traces\*.json") (Join-Path $pkg "tests\fixtures\traces") -Force

Copy-Item (Join-Path $dist "tianti.exe") (Join-Path $pkg "tianti.exe") -Force

$batLines = @(
    "@echo off",
    'cd /d "%~dp0"',
    'start "" "御天分析.exe"'
)
Set-Content -Path (Join-Path $pkg "启动御天分析.bat") -Value $batLines -Encoding Default

$zip = Join-Path $dist ("御天分析-{0}-便携版.zip" -f $Version)
Write-Host "=== 打包 zip ==="
Compress-Archive -Path (Join-Path $pkg "*") -DestinationPath $zip -CompressionLevel Optimal -Force

$size = [math]::Round((Get-ChildItem $dist -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1MB, 1)
Write-Host "完成：$zip"
Write-Host "目录大小：$size MB"
Get-ChildItem $pkg | Select-Object Name | Format-Table -AutoSize | Out-String -Width 80
