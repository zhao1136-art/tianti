# ============================================================================
# TianTi QA 无害模拟样本：启动子进程 + 心跳（SIMULATION ONLY）
# ----------------------------------------------------------------------------
# 用途：验证 process create / 进程树跟随 / 超时强杀后无残留进程。
#       父进程启动一个隐藏的 powershell 子进程，两者每 100ms 往
#       spawn_child.heartbeat 追加一行；杀死进程树后心跳必须停止增长。
# 安全边界：
#   * 子进程只写心跳文件，无网络、无注册表、无系统修改；
#   * 子进程脚本在运行时生成于脚本所在目录（沙箱工作目录内）；
#   * 默认最长运行 20s（父）+ ChildSeconds（子），由沙箱超时先杀；
#   * 本脚本不是恶意代码。
# 用法：
#   powershell -NoProfile -ExecutionPolicy Bypass -File sim_spawn_child.ps1 [-ChildSeconds 30]
# ============================================================================
param([int]$ChildSeconds = 30)

$ErrorActionPreference = "Continue"
if ($PSScriptRoot) { $here = $PSScriptRoot } else { $here = (Get-Location).Path }
$childScript = Join-Path $here "sim_child_heartbeat.ps1"
$heartbeat = Join-Path $here "spawn_child.heartbeat"

$childBody = @'
param([string]$Path, [int]$Seconds)
$count = $Seconds * 10
for ($i = 0; $i -lt $count; $i++) {
    Add-Content -Path $Path -Value ("child " + (Get-Date -Format o))
    Start-Sleep -Milliseconds 100
}
'@
Set-Content -Path $childScript -Value $childBody -Encoding UTF8

$childArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $childScript, "-Path", $heartbeat, "-Seconds", $ChildSeconds)
Start-Process -FilePath "powershell.exe" -ArgumentList $childArgs -WindowStyle Hidden | Out-Null

for ($i = 0; $i -lt 200; $i++) {
    Add-Content -Path $heartbeat -Value ("parent " + (Get-Date -Format o))
    Start-Sleep -Milliseconds 100
}
