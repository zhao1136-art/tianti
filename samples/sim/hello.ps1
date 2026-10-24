# 天体引擎无害模拟样本（sim）：写文件 + 启动子进程 + 标准输出
# 仅用于沙箱端到端测试，不含任何恶意行为。
$ErrorActionPreference = 'Stop'
Write-Output "tianti hello sim"

New-Item -ItemType Directory -Path .\notes -Force | Out-Null
Set-Content -Path .\notes\hello.txt -Value "hello from tianti sandbox" -Encoding UTF8

New-Item -ItemType Directory -Path .\drops -Force | Out-Null
Set-Content -Path .\drops\payload.bin -Value ("A" * 512) -Encoding ASCII

cmd.exe /c "echo child-process-from-hello" | Out-Null
Write-Output "hello sim done"
