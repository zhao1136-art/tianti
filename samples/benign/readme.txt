TianTi QA 良性语料说明（BENIGN CORPUS）
=========================================

本目录只放无害的良性对照样本，用于验证：
  1. 规则引擎 / 检测器不会对正常脚本产生 critical 命中；
  2. 评分判定对良性样本给出 clean 或 suspicious 且 score < 40；
  3. 静态预筛 / 归档解析可正常处理文本、脚本、zip。

包含内容：
  * hello_world.ps1   - 正常 PowerShell 脚本（打印 + 临时标记文件）
  * hello_batch.bat   - 正常批处理脚本
  * readme.txt        - 本文件
  * benign_data.zip   - 由上述文本/脚本打包的良性 zip（防压缩炸弹误报基线）
  * notepad_copy.exe  - 系统程序 notepad.exe 的本地副本（不随仓库分发，见 corpus.md）

安全边界：本目录所有文件均无害、不可疑，不含任何真实恶意代码或宏。
许可证说明见 tests/corpus.md。
