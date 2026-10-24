# ============================================================================
# TianTi QA 无害模拟样本：批量写文件（SIMULATION ONLY）
# ----------------------------------------------------------------------------
# 用途：产生大量 file create/write 事件，用于匹配/检测/评分性能与"批量加密模拟"
#       的良性替身（本脚本只写固定小文本，不做加密、不删改用户文件）。
# 安全边界：
#   * 只写脚本所在目录下的 bulk\ 子目录（沙箱中即工作目录内）；
#   * 不触碰系统目录、不修改注册表、不联网；
#   * -Clean 只删除自己创建的 bulk\ 目录；
#   * 本脚本不是恶意代码。
# 用法：
#   powershell -NoProfile -ExecutionPolicy Bypass -File sim_bulk_write.ps1 [-Count 200] [-Clean]
# ============================================================================
param([int]$Count = 200, [switch]$Clean)

$ErrorActionPreference = "Continue"
if ($PSScriptRoot) { $here = $PSScriptRoot } else { $here = (Get-Location).Path }
$bulk = Join-Path $here "bulk"
New-Item -ItemType Directory -Force -Path $bulk | Out-Null

for ($i = 1; $i -le $Count; $i++) {
    $path = Join-Path $bulk ("sim_{0:D4}.dat" -f $i)
    Set-Content -Path $path -Value ("tianti sim bulk data {0}" -f $i) -Encoding ASCII
}

$marker = Join-Path $here "bulk_write.marker"
Set-Content -Path $marker -Value ("wrote {0} files to {1}" -f $Count, $bulk)
Write-Output ("SIM: bulk write complete, count=" + $Count)

if ($Clean) {
    Remove-Item -Path $bulk -Recurse -Force -ErrorAction SilentlyContinue
    Write-Output "SIM: bulk dir cleaned"
}
