# 误报登记单（false positives）

> 维护：QA。原则：**不改评分代码**，只登记证据与建议，交 detect / rules owner 评估。
> 复现口径：`python -m tianti replay <trace>`（回放不执行样本）或
> `python -m tianti scan <sample> --policy fast`（需 containment 就绪、仅无害样本）。

## FP-001 hello_world.ps1 被判 suspicious（script_exec_bypass 根进程误报）

| 项 | 内容 |
|----|------|
| 状态 | **detect 已修复（perf/误报优化完成，2026-10-24）**；QA 待 containment 解除暂停后用 scan 复测确认 |
| 样本 | `samples/benign/hello_world.ps1`（自写良性脚本，仅打印 + 临时文件） |
| 判定 | 修复前 suspicious，score 25.2（Lead 实测）；修复后待复测 |
| 命中 | `script_exec_bypass`（PowerShell -ExecutionPolicy Bypass，medium，TA0002/T1059.001）、`hidden_execution`（隐藏执行，medium，TA0005/T1564）；抑制后仍有 capability + 静态分 |
| 根因 | 沙箱 harness 自身以 `-ExecutionPolicy Bypass -NoProfile` 启动样本，事件把 harness 命令行当样本行为；脚本本身没有绕过动作 |
| 建议 | 1) `script_exec_bypass` / `hidden_execution` 排除「根进程由沙箱 harness 启动」的命令行（或按 sample_image/父进程识别 harness）；2) 根进程命令行不计入这两个检测器证据；3) 良性样本不应因 harness 参数产生任何命中 |
| 影响 | 良性 FPR；hello_world 无任何危险行为却被判 suspicious |
| 复现 | `python -m tianti scan samples\benign\hello_world.ps1 --policy fast`（containment 就绪时）与对应 trace 回放 |

## FP-002 golden_benign_installer 评分偏高（观察项）

| 项 | 内容 |
|----|------|
| 状态 | 已随评分/抑制修复消失（clean），保留记录 |
| 样本 | `tests/fixtures/traces/golden_benign_installer.json`（合成良性安装器） |
| 判定 | 修复后 clean，score 0.0（2026-10-24 基线实测；修复前 suspicious 15.0） |
| 观察 | capability 分来自正常安装器的一次网络连接；建议 rules 评估是否对"单次普通外联"降权，但不影响当前验收（<40） |
| 复现 | `python -m tianti replay tests/fixtures/traces/golden_benign_installer.json --format json` |

## 口径与决策（Lead 2026-10-24）

- **FPR 口径**：`malicious` 记为误报；`suspicious` 单列为观察项，报告同时给出两者计数/比例。
- **benign 全量 scan**：v1 不做（需执行样本），推迟到 v1.1 在独立 VM 环境补齐；本表仅保留 golden trace 与已完成实测的数据。
- **FP-001**：detect 声称已修复 script_exec_bypass/hidden_execution 根进程误报；scan 级复测受 containment 暂停影响，状态保持"待复测"，解禁后在 VM/受控环境复测并更新本表。
- FP-002 已随评分/抑制修复消失（golden_benign_installer 现 suspicious 15.0，仅 `直连裸 IP 地址` 一条规则命中，<40 非 malicious）。

## 处理约定

1. owner 修复后，QA 重新跑对应 benign 样本/golden，并在本表更新状态（已修复 / 保留）。
2. 修复涉及评分语义变化时，按 `tests/README.md §4` 流程由 owner 通知 Lead+QA 后重新固化 baseline。
3. 本表是误报唯一入口；报告/PR 中引用 FP 编号。
