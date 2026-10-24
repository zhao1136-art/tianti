# ============================================================================
# 天体引擎无害模拟样本（SIMULATION ONLY）：低完整性语义验证
# ----------------------------------------------------------------------------
# 用途：验证 integrity:low 的实际语义——
#   * 写入受限：尝试写 C:\Windows\tianti_sandbox_lowil_probe.txt 应被拒绝；
#   * 读/执行不受限：读取 C:\Windows\System32\cmd.exe 与启动 cmd 子进程应成功；
#   * 工作目录已打低完整性标签，因此工作目录内写入应成功。
# 安全边界：只创建 1 个无害文本探针并记录结果；不联网、不改注册表；
#           本脚本不是恶意代码。
# ============================================================================
$ErrorActionPreference = "Continue"
if ($PSScriptRoot) { $here = $PSScriptRoot } else { $here = (Get-Location).Path }
$lines = @()
$probe = "C:\Windows\tianti_sandbox_lowil_probe.txt"

try {
    Set-Content -Path $probe -Value "harmless low integrity probe" -ErrorAction Stop
    $lines += "system_write=allowed"
}
catch {
    $lines += "system_write=blocked"
}

try {
    $fs = [System.IO.File]::OpenRead("C:\Windows\System32\cmd.exe")
    $buf = New-Object byte[] 2
    [void]$fs.Read($buf, 0, 2)
    $fs.Close()
    $lines += "system_read=ok"
}
catch {
    $lines += "system_read=blocked"
}

try {
    Set-Content -Path (Join-Path $here "low_integrity.workdir.txt") -Value "workdir_write_ok" -ErrorAction Stop
    $lines += "workdir_write=ok"
}
catch {
    $lines += "workdir_write=blocked"
}

try {
    $proc = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList "/c", "exit 0" -WindowStyle Hidden -PassThru -Wait
    if ($proc.ExitCode -eq 0) { $lines += "child_execute=ok" } else { $lines += "child_execute=failed" }
}
catch {
    $lines += "child_execute=failed"
}

Set-Content -Path (Join-Path $here "low_integrity.result") -Value $lines
