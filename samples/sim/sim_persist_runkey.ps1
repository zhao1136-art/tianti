# ============================================================================
# TianTi QA 无害模拟样本：模拟 Run 键持久化（SIMULATION ONLY）
# ----------------------------------------------------------------------------
# 用途：供沙箱/规则/检测器联调，产生 "registry set ...\CurrentVersion\Run\*" 行为。
# 安全边界：
#   * 默认 dry-run，只写 %TEMP%\tianti_sim\ 下的标记文件，不修改真实注册表；
#   * 仅当显式传入 -Execute 才写 HKCU Run 键，并在 finally 中立刻删除；
#   * 无下载、无外联、无删除系统文件、无提权操作；
#   * 本脚本不是恶意代码，禁止用于真实攻击场景。
# 用法：
#   powershell -NoProfile -ExecutionPolicy Bypass -File sim_persist_runkey.ps1 [-Execute]
# ============================================================================
param([switch]$Execute)

$ErrorActionPreference = "Continue"
$simRoot = Join-Path $env:TEMP "tianti_sim"
New-Item -ItemType Directory -Force -Path $simRoot | Out-Null
$marker = Join-Path $simRoot "persist_runkey.marker"
Set-Content -Path $marker -Value ("sim persist start " + (Get-Date -Format o))

$runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$valueName = "TianTiSimProbe"

if ($Execute) {
    try {
        Set-ItemProperty -Path $runKey -Name $valueName -Value "cmd.exe /c echo tianti-sim" -ErrorAction Stop
        Write-Output ("SIM: wrote Run key " + $runKey + "\" + $valueName)
        Add-Content -Path $marker -Value "run-key-written"
    }
    catch {
        Write-Output ("SIM: run key write failed: " + $_.Exception.Message)
        Add-Content -Path $marker -Value "run-key-failed"
    }
    finally {
        # 自清理：不留下任何持久化痕迹
        Remove-ItemProperty -Path $runKey -Name $valueName -ErrorAction SilentlyContinue
    }
}
else {
    Write-Output ("SIM(dry-run): would write " + $runKey + "\" + $valueName)
    Add-Content -Path $marker -Value "dry-run"
}

Add-Content -Path $marker -Value "done"
