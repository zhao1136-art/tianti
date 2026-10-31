# 御天分析 v0.3.4 发布报告（注册表观测补完：定向 ETW）

- 发布日期：2026-10-31
- 类型：检测能力补完（默认开启，可关闭）
- 交付：`dist\御天分析-0.3.4-便携版.zip`

## 1. 背景

低完整性沙箱会**拒绝**写 `HKCU\...\Run` 等注册表键；快照 net-diff 只能看到"最终变化"，
因此被拒绝的写尝试、写后即删的瞬时行为都不可见 → Run/RunOnce、Winlogon、Defender、LSASS 等
注册表类检测器永不触发。

## 2. 方案：Kernel-Registry 定向 ETW（不碰 GeneralProfile）

| 项 | 值 |
|----|----|
| 采集 | `logman create trace ... -pf <registry provider>` + `tracerpt` |
| Provider | Microsoft-Windows-Kernel-Registry（全 keyword） |
| 开销 | start ~65ms、stop ~50ms、tracerpt ~2s（XML ~20MB，系统级事件 ~16k 条） |
| 过滤 | 只保留沙箱进程树 pid + 关注路径（Run/RunOnce/Winlogon/Defender/LSASS/SAM/SECURITY/VBox/VMware/QEMU/Startup 等） |
| 产出 | `registry:set/delete/query` 事件；`args.denied=true` 表示被拒绝的写尝试（STATUS 0xC0000022） |

## 3. 实测（本机）

探针：`Set-ItemProperty HKCU:\...\CurrentVersion\Run`（低完整性下被拒绝）

| 指标 | 结果 |
|------|------|
| ETW 产出 | 2 条 registry 事件，其中 1 条 denied（`...\CurrentVersion\Run\`） |
| 检测器 | `Run/RunOnce 自启动` hit（high，18 分） |
| 判定 | `malicious 49.5`（修复前 clean） |
| 良性 `hello.ps1` | 仍 `clean 5.0`，无检测器误报 |
| 单次沙箱耗时 | ~3.4s → ~7.1s（ETW 约 +3.5s；缓存命中不受影响） |

## 4. 开关（按策略）

- `fast`：`registry_etw=false`（且 backend=replay，本来不跑 ETW）；
- `deep` / `paranoid`：`registry_etw=true`（默认开启）；
- 全局兜底：`config/engine.json` 的 `"sandbox": {"registry_etw": true}`；
- 强制关闭：环境变量 `TIANTI_NO_REGISTRY_ETW=1` 或 `ContainmentBackend(registry_etw=False)`（红线计时测试即用此方式隔离 ETW 开销）；
- 不可用（非管理员/无 logman）时自动回退快照 diff，并在 trace 备注说明。

## 5. 覆盖的检测器

Run/RunOnce 自启动、Winlogon Userinit、Defender 篡改、LSASS 访问、凭据 hive 查询、环境探测
（VBox/VMware/QEMU 查询）等注册表类检测器现在都有事件来源。
**仍未覆盖**：`startup_folder_drop`（需要文件系统 Startup 目录观测/重定向，下一步），
以及被防火墙拒绝的网络外联（C2）——需网络放行观测或 ETW network provider。

## 6. 验证

- 新增：ETW 拒绝写尝试集成测试（含检测器联动）、ETW 关闭回退测试；
- 全量：**405 tests OK（1 skipped）**；
- 打包版：`trace` 探针含 `registry:set/denied`，`scan` 良性样本 clean；
- 产物 SHA256 见 `dist\SHA256SUMS.txt`。
