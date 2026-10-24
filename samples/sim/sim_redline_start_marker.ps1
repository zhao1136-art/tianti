# ============================================================================
# TianTi QA 红线探针（无害）：fail-closed 执行标记（SIMULATION ONLY）
# ----------------------------------------------------------------------------
# 用途：验证"断网隔离失败时不得执行样本"。脚本一开始就写 executed.marker，
#       若 fail-closed 生效，脚本不会被执行，标记文件不应出现。
# 安全边界：
#   * 只写脚本所在目录下 executed.marker，然后 sleep 2s；
#   * 不联网、不修改系统；
#   * 本脚本不是恶意代码。
# 用法：
#   powershell -NoProfile -ExecutionPolicy Bypass -File sim_redline_start_marker.ps1
# ============================================================================
$ErrorActionPreference = "Continue"
if ($PSScriptRoot) { $here = $PSScriptRoot } else { $here = (Get-Location).Path }
Set-Content -Path (Join-Path $here "executed.marker") -Value ("executed pid=" + $PID + " at " + (Get-Date -Format o))
Write-Output "SIM(fail-closed): started"
Start-Sleep -Seconds 2
