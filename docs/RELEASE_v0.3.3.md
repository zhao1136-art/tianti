# 御天分析 v0.3.3 发布报告（观测面与 capa 归因修复）

- 发布日期：2026-10-31
- 类型：检测质量修复（行为兼容；沙箱执行方式不变）
- 交付：`dist\御天分析-0.3.3-便携版.zip`

## 1. 修复：样本写临时文件不可观测

- **根因**：快照只覆盖 `work\<trace>\c`，样本写 `%TEMP%` 的文件落在快照之外；且实测 PowerShell 探针只产生 process 事件。
- **修复**：沙箱子进程的 `TEMP` / `TMP` 重定向到 `work\<trace>\c\_tmp`（快照范围内），并给该目录打低完整性标签。
- **效果**（本机探针：写 `%TEMP%\probe_tmp.txt` + 当前目录 `probe_cwd.txt`）：
  - 修复前：`file_writes=0`，全部为 process 事件；
  - 修复后：`file_writes=2`，事件含 `file:create/write`，`trace.extra.env` 记录 TEMP/TMP 路径。

## 2. 修复：capa 把沙箱启动命令行当样本行为

- **根因**：containment 启动脚本用 `powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File <样本>`，capa 的
  「PowerShell 执行 / 隐藏窗口 / 绕过执行策略 / spawn shell」等规则命中证据全部是根进程创建事件 `e00001`；
  良性脚本因此虚高，真实 PE 反而没有这些命中。
- **修复**：`pipeline.run_rules` 增加 harness 过滤——**证据 id 全部来自根进程启动事件的 RuleMatch 不计分并丢弃**，
  同时在结果备注记录「已过滤 N 条由沙箱启动命令行触发的能力命中（harness 噪声）」。
- **效果**：良性 `hello.ps1` 的 4 条 harness 命中全部被过滤（0 条保留）；
  真实行为（文件/注册表/子进程事件）产生的命中保留；detect 侧原有的根进程排除继续生效。
- 说明：过滤依据 `trace.extra.launch`（真实沙箱 trace 都有）；golden 回放/无 launch 信息的轨迹不误伤。

## 3. 验证

- 新增测试：沙箱 TEMP 重定向文件事件、harness 仅证据过滤、无 launch 不误伤；
- 全量：**403 tests OK（1 skipped）**；
- 打包版实测：`tianti trace` 探针含 `file:create/write` 且 `extra.env` 正确；`scan hello.ps1` 显示 harness 过滤备注。

## 4. 仍未解决（下一步计划）

| 项 | 现状 | 计划 |
|----|------|------|
| ETW 定向采集 | 默认关闭；GeneralProfile 开销过大 | 只开 Kernel-Registry/File/Network 三个 provider 的自定义 profile，拿真事件流（含被拒绝的写尝试） |
| 网络观测 | `network=blocked`，外联被防火墙阻断，连接表看不到尝试 | 增加「放行但记录」模拟网络 / ETW 网络事件，激活 c2_connect |
| 快照范围外写入 | 写 `C:\Windows`、用户目录绝对路径看不到 | 低完整性已阻止破坏；要做"尝试可见"需 ETW |
| 注册表低完整性写 | 低完整性令牌写 HKCU/HKLM 常被拒绝，快照看不到失败尝试 | 同上，ETW Registry 事件 |

## 5. 兼容性

- 沙箱执行/隔离/超时/断网策略不变，仅增加环境变量重定向与过滤逻辑；
- 有效压缩包、DLL 静态、Office 宏等行为不变。
