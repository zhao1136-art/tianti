# ============================================================================
# TianTi QA 无害模拟样本：长时运行触发超时（SIMULATION ONLY）
# ----------------------------------------------------------------------------
# 用途：验证 watchdog 超时强杀：脚本持续 120s 写心跳，沙箱应按策略超时终止，
#       产出 sandbox.terminated_by = timeout，且进程树被杀、无残留。
# 安全边界：
#   * 只写脚本所在目录下的 timeout.heartbeat；
#   * 不联网、不修改注册表/系统、不启动额外进程；
#   * 本脚本不是恶意代码。
# 用法：
#   powershell -NoProfile -ExecutionPolicy Bypass -File sim_timeout.ps1
# ============================================================================
$ErrorActionPreference = "Continue"
if ($PSScriptRoot) { $here = $PSScriptRoot } else { $here = (Get-Location).Path }
$heartbeat = Join-Path $here "timeout.heartbeat"
for ($i = 0; $i -lt 1200; $i++) {
    Add-Content -Path $heartbeat -Value ("alive " + (Get-Date -Format o))
    Start-Sleep -Milliseconds 100
}
