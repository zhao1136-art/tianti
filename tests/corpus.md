# 测试语料说明（corpus）

本文记录 `tests/` 与 `samples/` 中语料的**来源、用途、许可证与安全边界**。
总原则：**不纳入、不下载、不执行真实恶意样本**；本机只跑无害模拟脚本与系统程序副本。

## 1. 语料清单

| 语料 | 位置 | 来源 | 用途 | 许可证 / 再分发 |
|------|------|------|------|-----------------|
| golden trace ×3 | `tests/fixtures/traces/golden_*.json` | Lead 手工合成（事件基于 docs/TRACE_SCHEMA.md 示例） | 契约回归、规则/检测/评分基线 | 项目内部原创，随仓库分发 |
| 期望与基线 | `tests/fixtures/regression/*.json` | QA 依据 PLAN/THREAT_MODEL 编写；基线由 CLI 实测固化 | 回归断言、漂移检测 | 项目内部原创 |
| 模拟行为脚本 | `samples/sim/*` | QA 自写（PowerShell/VBS/批处理） | 沙箱观测、规则/检测联调、红线测试、性能 | 项目内部原创，随仓库分发 |
| 良性脚本/文本 | `samples/benign/*.ps1|.bat|.txt` | QA 自写 | 良性对照、误报率基线 | 项目内部原创，随仓库分发 |
| 良性 zip | `samples/benign/benign_data.zip` | QA 用上述文本/脚本打包（Python zipfile） | 归档解析、压缩炸弹误报基线 | 项目内部原创，随仓库分发 |
| 系统程序副本 | `samples/benign/notepad_copy.exe` | 本机 `C:\Windows\System32\notepad.exe` 拷贝（**不提交**） | 良性 PE 对照 | Microsoft Windows 系统程序，专有许可；**仅本机测试，不随仓库再分发**。`samples/benign/.gitignore` 忽略 `*.exe`；公开仓库前请删除。 |
| EICAR | 不落盘 | 标准防病毒测试字符串 | 静态识别用例（文本，不执行） | 公开测试串，非恶意代码；由测试在内存中生成，避免 AV 误隔离 |
| 上游 capa 规则（未来） | `rules/` 子集 | flare-capa-rules | 差分测试 oracle | Apache-2.0，保留头部与 NOTICE |

## 2. 各语料用途与期望

### 2.1 golden trace

- `golden_ransom_sim.json`：Run 键持久化 + 卷影删除 + 批量加密写 + 外联 → 期望 `malicious`，score ≥ 40。
- `golden_injection.json`：VirtualAllocEx/WriteProcessMemory/远程线程 + AMSI + 外联 → 期望 `malicious`。
- `golden_benign_installer.json`：正常安装器写文件/注册表/一次网络连接 → 期望 `clean` 或 `suspicious`，score < 40。
- 期望明细见 `tests/fixtures/regression/golden_expectations.json`。

### 2.2 samples/sim（无害模拟）

| 脚本 | 模拟行为 | 安全边界 |
|------|----------|----------|
| `sim_persist_runkey.ps1` | Run 键持久化 | 默认 dry-run 只写 `%TEMP%\tianti_sim`；`-Execute` 才写 HKCU Run 且 finally 立即删除 |
| `sim_bulk_write.ps1` | 批量写文件 | 只写脚本目录 `bulk\`；`-Clean` 只删自己目录 |
| `sim_net_fail.ps1` | 外联失败/DNS | 仅 RFC 5737/2606 保留地址（192.0.2.1:443、203.0.113.1:80、`.invalid`），不携带数据 |
| `sim_spawn_child.ps1` | 启动子进程 + 心跳 | 子进程只写心跳；用于观测与超时杀树验证 |
| `sim_timeout.ps1` | 长时运行 | 只写心跳，用于超时强杀 |
| `sim_persist_vbs.vbs` | VBS 持久化模拟 | 默认 dry-run；`--execute` 写 Run 后立即删除 |
| `sim_bulk_write.bat` | 批处理批量写 | 只写脚本目录 `bat_bulk\` |
| `sim_redline_system_write.ps1` | 红线探针：写 `C:\Windows` | 只创建 1 个纯文本探针，测试清理；不覆盖系统文件 |
| `sim_redline_start_marker.ps1` | 红线探针：fail-closed | 只写 `executed.marker`；fail-closed 生效时不应被执行 |

所有 sim 脚本头部含 `SIMULATION ONLY` 与「无害」声明；红线测试自动扫描，
禁止出现下载器（DownloadString/Invoke-WebRequest/bitsadmin/mshta 等）与破坏性命令
（format、vssadmin delete、bcdedit、diskpart 等）。

### 2.3 samples/benign（良性对照）

- `hello_world.ps1` / `hello_batch.bat` / `readme.txt` / `benign_data.zip`：正常脚本与打包基线。
- `notepad_copy.exe`：真实签名系统 PE 的本地副本（不提交），用于 PE 解析/静态预筛的良性样本。
- 误报率（FPR）口径（Lead 决策）：`malicious` 记为误报；`suspicious` 单列为观察项，
  报告同时给出两者计数/比例。v1 不跑 benign 全量 scan（需执行样本），推迟到 v1.1 独立 VM 补齐。

## 3. 安全边界（强制）

1. 本机只允许：自写无害模拟脚本、良性脚本/文本/zip、系统程序副本、EICAR 文本（内存）。
2. 不下载、不传播、不内置任何真实恶意样本、漏洞利用、C2 地址、凭据。
3. 外联目标只允许保留地址/`.invalid`；脚本不发送数据、不解析响应。
4. 持久化类模拟默认 dry-run；任何真实注册表写入必须写入后立即自清理。
5. 执行类测试必须：限时、断网、优先 containment、测试后清理临时文件；红线用例只在 `samples/sim` 范围执行。
6. 语料中不得包含用户隐私数据、本机真实用户名/路径（除测试必需的 `C:\Windows` 探针常量）。
7. 新增二进制语料需说明来源与许可证，不得提交专有/大体积文件（`.exe` 已 gitignore）。

## 4. 维护规则

- 新增 sim 脚本：文件名 `sim_*.ps1|vbs|bat`，必须写头部用途 + 安全边界 + 用法，并跑
  `& $PY -m unittest tests.integration.test_redline.SampleCorpusSafetyTests -v`。
- 新增 benign 样本：优先文本/自写脚本；二进制走 `.gitignore` + 本文件登记来源与许可证。
- 更新 golden trace：契约/场景变更需 Lead 评审，并同步更新 `golden_expectations.json` 与基线。
- 语料只增不改语义；废弃语料需说明原因并经 Lead 确认。

## 5. 环境风险提示（360 HIPS）

本机 360 HIPS 会删除含密集恶意命令字面量的 Python 测试文件（本机已实测多次，非版本控制问题）。
因此：

1. 测试 `.py` 中禁止堆叠恶意命令字面量；需要检测关键字时用字符串拼接构造；
2. 新增/修改测试文件后立即校验文件存在（`Test-Path`）；
3. 若测试文件"神秘消失"，先检查 360 隔离区/日志，不要误判为并发写盘竞争；
4. `.md`/语料说明中的关键字仅作文档引用，不参与执行。
