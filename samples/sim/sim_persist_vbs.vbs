' ============================================================================
' TianTi QA 无害模拟样本：VBS 持久化模拟（SIMULATION ONLY）
' ----------------------------------------------------------------------------
' 用途：产生 VBS 脚本行为（file write / 可选 registry set）用于静态与沙箱联调。
' 安全边界：
'   * 默认 dry-run，只写脚本同目录 persist_vbs.marker；
'   * 仅当命令行显式传入 --execute 才写 HKCU Run 键，写入后立即删除；
'   * 不下载、不联网、不删除文件；
'   * 本脚本不是恶意代码。
' 用法：wscript.exe sim_persist_vbs.vbs [--execute]
' ============================================================================
Option Explicit

Dim shell, fso, here, marker, runKey, valueName, execute, args, i
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
here = fso.GetParentFolderName(WScript.ScriptFullName)
marker = here & "\persist_vbs.marker"
runKey = "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\"
valueName = "TianTiSimProbeVbs"

Dim logFile
Set logFile = fso.CreateTextFile(marker, True)
logFile.WriteLine "sim persist vbs start"

execute = False
Set args = WScript.Arguments
For i = 0 To args.Count - 1
    If LCase(args(i)) = "--execute" Then execute = True
Next

If execute Then
    shell.RegWrite runKey & valueName, "wscript.exe //nologo """ & WScript.ScriptFullName & """", "REG_SZ"
    shell.RegDelete runKey & valueName
    logFile.WriteLine "run-key-written-and-removed"
Else
    logFile.WriteLine "dry-run"
End If

logFile.WriteLine "done"
logFile.Close
WScript.Echo "SIM(vbs): persistence simulation complete"
