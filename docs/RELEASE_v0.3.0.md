# 御天分析 v0.3.0 发布报告

- 产品名称：御天分析（Yutian Analysis）
- 引擎内核：天体引擎 TianTi v0.3.0
- 发布日期：2026-10-24
- 发布提交：`73a5816`（tag `v0.3.0`）
- 发布形态：Windows x64 便携版（免安装、内置 Python 运行时）
- 交付文件：`dist\御天分析-0.3.0-便携版.zip`

---

## 1. 发布概览

| 项 | 值 |
|----|----|
| 版本 | v0.3.0 |
| 压缩包大小 | 26,962,147 字节（约 26.9 MB） |
| 解压后大小 | 约 45.5 MB / 1715 个文件 |
| SHA256 | `42F577655EC8D45F31C53E87A5C5A5A877BA9906D1CCA9F57E818DC8C537A4D8` |
| 运行环境 | Windows 10 x64（19045）实测；打包内置 Python 3.12.14 + tkinter |
| 依赖 | 无外部 Python/第三方运行时依赖（capa 规则库随包） |
| 许可证 | 自研代码 + 上游 capa-rules（Apache-2.0，见 `THIRD_PARTY.md`） |

## 2. 交付内容

```
御天分析-0.3.0-便携版\
├─ 御天分析.exe          GUI 主程序（PyInstaller onedir，windowed）
├─ tianti.exe            CLI（PyInstaller onefile，供命令行与 GUI 沙箱子进程使用）
├─ 启动御天分析.bat      双击启动 GUI
├─ _internal\            内置 Python 3.12.14 运行时、tkinter、依赖
├─ rules\                679 个规则文件（54 条自研 + 625 条上游 capa-rules）
│  └─ upstream\          官方规则（默认不加载，需 --include-upstream / 配置开启）
├─ detectors\            26 个危险行为检测器（YAML）
├─ config\engine.json    策略（fast/deep/paranoid）、评分、规则开关
├─ tests\fixtures\traces\ 3 份 golden trace（演示与离线回放）
├─ docs\                 使用/规则/评分/威胁模型/发布报告等文档
├─ README.md
└─ THIRD_PARTY.md
```

## 3. 功能清单（v0.3.0）

### 3.1 静态预筛

- PE32/PE64：DOS/NT 头、节区与熵、导入/导出、签名目录、overlay、checksum、加壳/可疑节启发；
- 脚本：PowerShell/VBS/JS/BAT 特征（编码命令、下载、隐藏窗口、持久化、卷影删除等）；
- 压缩包：zip 清单与安全展开（100 条 / 64MB / 单文件 32MB 上限）；
- **Office 宏提取（本版新增）**：OOXML（docx/xlsm/pptm…）与 OLE（doc/xls/ppt），最小 CFB 解析、宏流识别、自动执行入口与可疑 API 关键字；
- EICAR 已知测试文件识别（不执行）。

### 3.2 沙箱与观测

- containment 后端：受限令牌 + 低完整性（S-1-16-4096）+ Job Object（内存/CPU/进程数/KILL_ON_CLOSE）+ 按程序防火墙 + 超时硬杀 + 进程树清理；
- 事件覆盖：process / file / registry / network（ETW 可选、默认关闭）；
- replay 后端：离线回放轨迹，零执行风险，CI 与规则调参主力；
- 沙箱红线：写系统目录被拒、断网生效、超时杀整棵树、无残留进程/防火墙规则。

### 3.3 capa 兼容规则引擎

- 零依赖 YAML 子集解析；and/or/not/optional/count/match（DAG）；scope 支持 process/thread/call/span/file；
- 54 条自研动态规则（持久化/注入/防御规避/凭证/C2/勒索/发现/暂存/横向）；
- 上游 capa-rules 接入：1054 条候选 → 625 条可解析动态规则入库；加载 547 条（54 自研 + 493 上游，132 条因依赖剪枝）；官方动态规则兼容率 77.1%；
- 默认关闭上游包，保持基线稳定；`--include-upstream` 开启。

### 3.4 危险行为检测与判定

- 26 条检测器，覆盖 10 个 ATT&CK 战术（TA0002/3/4/5/6/7/8/9/11/40）；
- 评分 = 战术加权能力分 + 检测器分 + 静态信号分；critical 硬规则、抑制/白名单、置信度；
- 每条结论带事件 id 证据链，可回溯到时间线。

### 3.5 交付层

- GUI「御天分析」：沙箱执行 / 离线回放 / 自动三种模式；策略与上游规则开关；结果表 + 详情（摘要/能力/危险行为/时间线/静态信号/压缩包/原始 JSON/备注）；批量汇总矩阵（统计 + 排序 + CSV 导出）；扫描中可「停止」并强杀当前沙箱进程树；
- CLI：version / trace / replay / scan / rules / detectors / report / convert-cape / serve / gui；
- 报告：单文件 HTML（无外链）+ JSON；
- 本地 API：127.0.0.1 的 /health /metrics /rules /scan /result。

### 3.6 输入类型

| 类型 | 处理 |
|------|------|
| PE exe | 静态 + 沙箱执行 |
| ps1 / bat / cmd / js / vbs | 静态 + 脚本宿主执行 |
| zip | 展开逐条目静态分析 + 聚合判定 |
| Office（docx/xlsm/pptm/doc/xls/ppt） | 静态 + 宏提取 |
| DLL/SYS、rar/7z、PDF、文本/JSON、图片等 | 仅静态分析 |
| tianti.trace/1 JSON | 离线回放 |
| CAPE/capa 动态报告 | convert-cape 转轨迹后分析 |

## 4. 质量与验证

### 4.1 自动化测试

| 项 | 结果 |
|----|------|
| 全量测试 | **376 tests OK，1 skipped**（60s；skip 为默认停用的 DLL 加载实验用例） |
| 单元测试 | 289+（规则 58 / 检测 63 / 静态 29+Office 15 / GUI 18 / 归档 13 等） |
| 集成测试 | 沙箱 14 + 红线 5 + CLI 24 + 规则命中 6 + 判定 9 + 归档/回归 |
| golden 判定 | 勒索模拟 **malicious 182.35**；注入 **malicious 107.6**；良性安装器 suspicious 15.0（<40） |
| 打包产物验证 | version --check（rules 679/detectors 26/backends ok）、replay 182.35、docm 宏识别、zip 逐条目、GUI --smoke exit 0 |

### 4.2 性能（10k 合成事件，实测）

| 阶段 | 1k 事件 | 10k 事件 | 说明 |
|------|---------|----------|------|
| rules 匹配（54 条） | 38.8 ms | 375 ms | 升级前 ~2.8s，已优化 7x |
| detect（26 检测器，含加载） | 165 ms | 1450 ms | 升级前 9.5s/1k，已优化 ~60x |
| scoring | 4.3 ms | 29.6 ms | 远低于预算 |
| trace 构造 | — | 219 ms | |
| schema 校验 | — | 29 ms | |
| JSON 往返 | — | 327 ms | |
| CLI replay 2k（端到端） | — | 1.40 s | |

含上游 547 条规则时：rules 1k ≈ 237 ms、10k ≈ 1.98 s（可选开启，默认不启用）。

### 4.3 沙箱红线（全部通过）

1. 写 `C:\Windows\` 被低完整性拒绝；
2. 子进程被观测，后端返回后无残留；
3. 超时强杀整棵进程树；
4. 防火墙默认断网，外联被拒；
5. 断网失败时 fail-closed（不执行样本）。

## 5. 已知问题与限制

| # | 问题 | 影响 | 处置/计划 |
|---|------|------|-----------|
| 1 | 本机无虚拟化，containment 是受限执行而非 VM | 只适合无害样本，不能安全分析真实恶意样本 | 文档明示；vm 后端接口预留 |
| 2 | **DLL 动态加载未接入** | 扫 DLL 仅静态分析 | 代码保留但 pipeline 排除；集成测试默认 skip（见 §6 事故记录） |
| 3 | ETW 采集默认关闭 | api/thread/memory 级事件缺失，上游 api 规则命中少 | 实测开销过高（~97s/样本），保留 opt-in；可用 CAPE 报告回放补 |
| 4 | 上游动态规则依赖 api 级特征 | 本地沙箱默认无 API hook | 提供 convert-cape；后续可接 emulation/API trace |
| 5 | rules 10k 375ms（含上游 1.98s） | 超出 PLAN 300ms 目标 | 已记录技术债，可加词级倒排 |
| 6 | 签名校验为路径信任占位 | 不能验证证书链 | 报告自动标注 placeholder |
| 7 | Office 宏只做关键字扫描 | 未解压 MS-OVBA、未反编译 VBA 源码 | macro_present 可靠，源码级分析待 v2 |
| 8 | rar/7z 不解压；zip 嵌套不递归 | 仅归档级/一层分析 | 安全上限优先，后续可扩展 |
| 9 | GUI 目录上限 100 文件、CLI 200 | 大批量需分批 | 已有提示 |
| 10 | 本机火绒 HIPS 会拦截/隔离模拟样本与 EICAR 字节码 | 测试/扫描偶发弹窗 | EICAR 已改运行时拼接；样本执行属预期行为 |
| 11 | 便携版首次启动 1–2s（onefile CLI 解包） | 体验 | 可改 onedir CLI 或常驻服务 |
| 12 | cmd 直接运行中文可能乱码 | 显示 | `chcp 65001` 或 PowerShell |

## 6. 事故记录（2026-10-24，发布前）

- **现象**：15:00–15:05 期间 DLL 加载实验的集成测试反复用 rundll32 加载 `version.dll` 的任意导出，产生 5 次 rundll32 崩溃；随后 Windows Explorer 于 15:04:27–15:04:56 连续崩溃 13 次（模块 twinui.pcshell.dll / ucrtbase.dll，0xc0000409）。
- **处置**：立即停用该测试（现默认 skip，需 `TIANTI_TEST_DLL_LOADING=1` 显式开启）；DLL 动态加载**不接入**产品路径；Explorer 自 15:06:27 重启后稳定，无残留进程/注册表变更（regsvr32 从未真正执行）。
- **结论**：DLL 加载实验代码保留在 `tianti/sandbox/containment.py` 作为参考，产品行为不受影响（DLL 始终静态分析）。后续如要做，需改用独立 loader 进程而非 rundll32 调用任意导出。

## 7. 安装与使用

### 7.1 便携版（推荐）

1. 解压 `御天分析-0.3.0-便携版.zip` 到任意目录（避免系统目录/中文路径过长）；
2. 双击 `启动御天分析.bat` 或 `御天分析.exe`；
3. 选择文件/目录 → 自动模式（trace 回放 / 其他沙箱执行）→ 查看结果与汇总 → 可导出 HTML/CSV。

### 7.2 CLI

```powershell
.\tianti.exe version --check
.\tianti.exe scan 样本.exe --policy deep --format both --out out\
.\tianti.exe replay tests\fixtures\traces\golden_ransom_sim.json --format summary
.\tianti.exe scan 文档.docm --format summary
.\tianti.exe scan 包.zip --format both
```

### 7.3 权限与安全

- 沙箱动态执行需要**管理员权限**（防火墙规则 + 低完整性令牌）；非管理员会明确报错/回退；
- 默认断网、限时、强杀；仅用于无害样本与本机测试；
- 真实恶意样本分析请使用独立 VM。

### 7.4 升级/卸载

- 便携版无安装过程：覆盖解压新版本即可；删除目录即卸载；
- 用户数据在 `out\`（结果/报告）与 `work\`（沙箱临时），可随时删除。

## 8. 相对上一版（v0.2.x）的变更

1. **新增** Office 宏提取（OOXML/OLE + CFB 解析 + 宏信号）；
2. **新增** zip 逐条目静态分析与聚合判定（CLI/GUI/HTML 展示，安全上限）；
3. **新增** PyInstaller 便携版打包（GUI + CLI + 规则/配置，免 Python）；
4. **新增** 冻结环境路径适配（config 根目录、GUI 调 CLI 子进程）；
5. **修复** Office 容器被当普通 zip 展开导致宏信号丢失；归档聚合不丢顶层静态结论；
6. **修复** 打包后懒加载模块缺失导致评分走后备路径（182.35 → 100.0）；
7. **DLL 加载**：代码保留、不接入；实验测试默认 skip（事故记录见 §6）；
8. 版本号 0.2.2 → 0.3.0。

## 9. 第三方与许可

- 上游规则库：Mandiant capa-rules（Apache-2.0），导入 625 条可解析动态规则，保留原始文件与许可证；
- 测试期参考：flare-capa（Apache-2.0，未随包分发）；
- 其余为自研代码，运行时仅依赖 Python 标准库 + tkinter；
- 完整声明见包内 `THIRD_PARTY.md` 与 `rules\upstream\LICENSE.txt`。

## 10. 附录

### A. 验收命令

```powershell
# 开发环境
python -m unittest discover -s tests -t . -v
# 打包产物
dist\御天分析\tianti.exe version --check
dist\御天分析\tianti.exe replay tests\fixtures\traces\golden_ransom_sim.json --format summary
dist\御天分析\御天分析.exe --smoke
```

### B. 产物哈希

- 文件：`dist\御天分析-0.3.0-便携版.zip`
- SHA256：`42F577655EC8D45F31C53E87A5C5A5A877BA9906D1CCA9F57E818DC8C537A4D8`
- 大小：26,962,147 字节

### C. 文档索引

- `README.md`：总览/命令/输入类型/打包
- `docs\GUI.md`：御天分析前端使用说明
- `docs\PLAN.md`、`docs\ARCH.md`、`docs\TRACE_SCHEMA.md`、`docs\RULES.md`、`docs\SCORING.md`、`docs\THREAT_MODEL.md`
