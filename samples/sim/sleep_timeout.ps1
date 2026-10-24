# 天体引擎无害模拟样本（sim）：启动长驻子进程后 sleep，用于验证超时强杀与进程树清理。
$ErrorActionPreference = 'SilentlyContinue'
Start-Process -FilePath "$env:SystemRoot\System32\ping.exe" -ArgumentList "-n", "30", "127.0.0.1" -WindowStyle Hidden | Out-Null
Start-Sleep -Seconds 5
