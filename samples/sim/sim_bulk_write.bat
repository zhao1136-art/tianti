@echo off
REM ============================================================================
REM TianTi QA 无害模拟样本：批处理批量写文件（SIMULATION ONLY）
REM ----------------------------------------------------------------------------
REM 用途：产生 file create/write 事件，用于批处理脚本静态/沙箱联调。
REM 安全边界：
REM   * 只写脚本目录下 bat_bulk\ 子目录（沙箱中即工作目录内）的 50 个文本文件；
REM   * 不触碰系统目录、不修改注册表、不联网、不删除其他文件；
REM   * 本脚本不是恶意代码。
REM 用法：cmd /c sim_bulk_write.bat
REM ============================================================================
setlocal
set "BASE=%~dp0"
set "BULK=%BASE%bat_bulk"
if not exist "%BULK%" mkdir "%BULK%"
for /L %%i in (1,1,50) do (
    > "%BULK%\sim_%%i.dat" echo tianti sim bat bulk %%i
)
> "%BASE%bat_bulk.marker" echo wrote 50 files
echo SIM(bat): bulk write complete
endlocal
