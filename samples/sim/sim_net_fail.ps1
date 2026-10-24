# ============================================================================
# TianTi QA 无害模拟样本：外联失败（SIMULATION ONLY）
# ----------------------------------------------------------------------------
# 用途：模拟样本尝试外联，产生 network connect/dns 事件；目标均为
#       RFC 5737 / RFC 2606 保留地址（192.0.2.0/24、203.0.113.0/24、.invalid），
#       不存在真实服务，不携带任何数据、不下载任何内容。
# 安全边界：
#   * 只做 DNS 查询与 TCP 连接尝试，每条连接 1.5s 超时；
#   * 不发送数据、不读取本地文件、不修改系统；
#   * 结果写到脚本所在目录的 net_fail.result（沙箱工作目录内）；
#   * 本脚本不是恶意代码。
# 用法：
#   powershell -NoProfile -ExecutionPolicy Bypass -File sim_net_fail.ps1
# ============================================================================
$ErrorActionPreference = "Continue"
if ($PSScriptRoot) { $here = $PSScriptRoot } else { $here = (Get-Location).Path }
$result = Join-Path $here "net_fail.result"
$lines = @()

$targets = @(
    @("192.0.2.1", 443),
    @("203.0.113.1", 80)
)

foreach ($target in $targets) {
    $hostName = $target[0]
    $port = [int]$target[1]
    $client = New-Object System.Net.Sockets.TcpClient
    $connected = $false
    try {
        $iar = $client.BeginConnect($hostName, $port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne(1500)) {
            try {
                $client.EndConnect($iar)
                $connected = $true
            }
            catch {
                $connected = $false
            }
        }
    }
    catch {
        $connected = $false
    }
    finally {
        $client.Close()
    }
    $lines += ("tcp {0}:{1} connected={2}" -f $hostName, $port, $connected)
}

try {
    $addresses = [System.Net.Dns]::GetHostAddresses("tianti-sim.invalid")
    $lines += ("dns tianti-sim.invalid resolved=" + $addresses.Count)
}
catch {
    $lines += "dns tianti-sim.invalid failed"
}

Set-Content -Path $result -Value $lines
Write-Output ($lines -join "; ")
