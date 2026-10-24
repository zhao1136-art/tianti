@echo off
REM ============================================================================
REM TianTi QA 良性对照样本：批处理 hello（BENIGN）
REM ----------------------------------------------------------------------------
REM 用途：正常批处理基线，输出文本并清理自己的临时文件。
REM 安全边界：不联网、不修改注册表、不删除批处理目录外的文件。
REM ============================================================================
echo Hello from TianTi benign batch sample
set "MARKER=%TEMP%\tianti_sim\benign_batch.marker"
if not exist "%TEMP%\tianti_sim" mkdir "%TEMP%\tianti_sim"
> "%MARKER%" echo benign batch marker
type "%MARKER%"
del /q "%MARKER%" 2>nul
exit /b 0
