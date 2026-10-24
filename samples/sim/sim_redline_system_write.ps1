# ============================================================================
# TianTi QA 红线探针（无害）：尝试写系统目录（SIMULATION ONLY）
# ----------------------------------------------------------------------------
# 用途：验证 containment 沙箱对系统目录写入的限制；无论成功/被拒绝都记录结果，
#       结果写入脚本所在目录 system_write.result，便于测试断言。
# 安全边界：
#   * 只尝试创建 1 个纯文本探针 C:\Windows\tianti_qa_redline_probe.txt；
#   * 不覆盖、不删除任何系统文件；测试结束会清理该探针；
#   * 不联网、不修改注册表；
#   * 本脚本不是恶意代码。
# 用法：
#   powershell -NoProfile -ExecutionPolicy Bypass -File sim_redline_system_write.ps1
# ============================================================================
$ErrorActionPreference = "Continue"
if ($PSScriptRoot) { $here = $PSScriptRoot } else { $here = (Get-Location).Path }
$result = Join-Path $here "system_write.result"
$probe = "C:\Windows\tianti_qa_redline_probe.txt"
$status = "unknown"
try {
    Set-Content -Path $probe -Value "tianti qa redline probe - harmless text" -ErrorAction Stop
    $status = "write_allowed"
}
catch {
    $status = "write_blocked: " + $_.Exception.GetType().Name
}
Set-Content -Path $result -Value $status
Write-Output ("SIM(redline): system dir write -> " + $status)
