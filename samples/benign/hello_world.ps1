# ============================================================================
# TianTi QA 良性对照样本：hello world（BENIGN）
# ----------------------------------------------------------------------------
# 用途：正常脚本基线，用于验证规则/检测器对良性脚本不产生 critical 命中。
# 安全边界：只打印文本、在 %TEMP%\tianti_sim\ 写一个标记文件并删除；
#           不联网、不修改注册表、不启动子进程。
# ============================================================================
$ErrorActionPreference = "Stop"
$simRoot = Join-Path $env:TEMP "tianti_sim"
New-Item -ItemType Directory -Force -Path $simRoot | Out-Null
$marker = Join-Path $simRoot "benign_hello.marker"
Set-Content -Path $marker -Value "hello from benign sample"
Write-Output "Hello from TianTi benign sample"
Get-Content -Path $marker | Out-Null
Remove-Item -Path $marker -Force -ErrorAction SilentlyContinue
