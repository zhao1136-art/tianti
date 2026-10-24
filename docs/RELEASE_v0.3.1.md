# 御天分析 v0.3.1 发布报告（沙箱扫描优化）

- 发布日期：2026-10-24
- 产品：御天分析（Yutian Analysis）/ 引擎 TianTi
- 类型：性能优化补丁（行为兼容，默认仍可沙箱执行）
- 交付：`dist\御天分析-0.3.1-便携版.zip`

## 1. 优化内容

| # | 优化 | 说明 |
|---|------|------|
| 1 | **轨迹缓存** | 相同样本 sha256 + 策略命中上次沙箱轨迹，直接回放分析，**不重复执行样本**。默认开启；`--no-cache` / GUI「复用轨迹缓存」可关 |
| 2 | **静态模式** | `scan --static-only` / GUI「仅静态分析（不执行样本）」：完全跳过沙箱，只跑静态预筛 + 规则/检测/评分 |
| 3 | **fast 策略跳过注册表快照** | fast 档 `registry_snapshot=false`，省约 0.24s；deep/paranoid 保留 |
| 4 | **分阶段耗时** | `trace.extra.timings` 记录 workspace/isolation/snapshots/launch/execute/terminate/cleanup/total，便于持续优化 |
| 5 | GUI/CLI 开关 | CLI `--static-only --no-cache`；GUI 两个复选框；API 对应参数 |

## 2. 实测（本机，hello.ps1 良性模拟样本）

| 场景 | 耗时 |
|------|------|
| 首次沙箱执行（deep） | **3.42 s** |
| 同一样本第二次扫描（缓存命中，不执行） | **0.04 s**（≈85×） |
| 静态模式（不执行） | **0.04 s** |

首次执行的分阶段耗时：workspace 0.035s / isolation 0.761s / snapshots_before 0.998s / launch 1.016s / execute 1.812s / terminate 1.889s / cleanup 2.469s（累计）。

## 2.1 打包版实测（v0.3.1 便携包，命令行冷启动）

| 场景 | 耗时 |
|------|------|
| 首次沙箱执行（hello.ps1，deep，含引擎冷启动） | 3.53 s |
| 同一样本第二次扫描（缓存命中） | 1.15 s |
| 仅静态分析（notepad.exe，--static-only） | 1.09 s |

说明：CLI 为 onedir 打包（消除 onefile 解包开销），冷启动约 0.7–0.9s，其余为分析/沙箱时间。

## 2.2 更多文件类型（本版新增）

| 类型 | 示例后缀 | 处理 |
|------|----------|------|
| 通用数据 | `.dat` `.bin` `.db` `.tmp` `.raw` | 静态分析 + 内嵌载荷探测（PE/ZIP/宏/脚本标记） |
| 文档/快捷方式/邮件 | `.pdf` `.lnk` `.url` `.eml` `.msg` | 类型识别 + 静态信号 |
| 代码 | `.py` `.class` | 类型识别 + 文本/字节特征 |
| 安装包/证书/字体 | `.msi` `.msp` `.cer` `.crt` `.pem` `.ttf` `.ttc` `.otf` | 类型识别 + 静态信号 |
| 镜像/其它归档 | `.iso` `.img` `.vhd` `.wim` `.cab` `.gz` `.tar` | 类型识别（归档级静态分析） |

`.dat` 里的内嵌 PE（偏移处 MZ+PE 头）会产出 `data.embedded_pe` 信号；含 PowerShell/CreateObject 等文本会产出 `data.script_marker`。

## 3. 兼容性

- 默认行为不变：不勾选静态/缓存时仍按原策略执行沙箱；
- 缓存键包含引擎版本、样本 sha256、策略名、超时、max_events、网络策略，策略或版本变化自动失效；
- 缓存只保存沙箱轨迹（不含规则/检测结论），规则/检测器更新不受缓存影响；
- 安全边界不变：沙箱执行仍需管理员权限、默认断网、低完整性、超时强杀。

## 4. 验证

- 全量测试：**380 tests OK（1 skipped）**；
- 打包产物：`tianti.exe version --check`、`scan --static-only`、二次扫描缓存命中、GUI `--smoke` 均通过；
- 产物 SHA256 见 `dist\SHA256SUMS.txt`。

## 5. 已知限制

- 首次执行仍受沙箱固定开销影响（防火墙/低完整性/快照约 1.3–2.5s），程序自身运行时间另计；
- 缓存会占用 `work\trace_cache\` 磁盘空间（每个样本一条 trace，可随时删除）；
- rar/7z 仍不解压；DLL 动态加载仍不接入（见 v0.3.0 报告）。
