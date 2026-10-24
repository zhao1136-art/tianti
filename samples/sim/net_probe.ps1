# 天体引擎无害模拟样本（sim）：尝试一次 TCP 外联，用于验证断网生效（fail-closed 防火墙）。
# 无论是否连通都只把结果写入工作目录，不做其他动作。
$ErrorActionPreference = 'Stop'
$result = 'unknown'
try {
    $client = New-Object System.Net.Sockets.TcpClient
    $iar = $client.BeginConnect('1.1.1.1', 443, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne(2000)) { throw 'connect-timeout' }
    $client.EndConnect($iar)
    $result = 'connected'
    $client.Close()
} catch {
    $result = 'blocked: ' + $_.Exception.Message
}
Set-Content -Path (Join-Path (Get-Location) 'net_result.txt') -Value $result -Encoding UTF8
