# 天体引擎（TianTi）—「沙箱 + capa 规则 + 危险行为检测」杀毒引擎实施计划

- 版本：v0.1（计划稿，尚未开工）
- 日期：2026-10-24
- 作者：Lead（Agent Teams 编排）
- 工作目录：G:\天体引擎
- 变更记录：M0 起代码目录 `engine/` 更名为 `tianti/`（import 包名与 CLI 一致：`python -m tianti`）

---

## 0. 结论先行

**推荐路线**：Python 3.12（本机自带运行时）+ 零第三方运行时依赖，先做一条**可回放、可评测、可解释**的行为分析流水线；沙箱用「隔离执行 + ETW 观测」实现（本机无虚拟化，见 §2）；capa 规则引擎自研兼容（官方 capa 仅作差分测试 oracle）；危险行为检测用 YAML 声明式 DSL + 评分判定。

**为什么不是传统杀毒架构**：本项目定位是「全新模式」——不做特征码/病毒库比对，而是把文件放进沙箱跑起来，采集真实行为，用 capa 语义规则识别「它具备什么能力」，用检测器识别「它做成了什么危害」，最后给出带证据链和 ATT&CK 映射的结论。

**关键实测结论（决定架构的三条）**：
1. 本机无 VT / 无 Hyper-V / 无 Windows Sandbox → **真虚拟机沙箱不可行**，沙箱必须是「受限执行 + 观测」，并保留 VM 后端接口。
2. 本机无 C/C++/Rust/Go 工具链 → 运行时只用 Python 3.12（DSH 自带）+ 标准库；pytest 也未预装，测试用 `unittest`。
3. admin 权限 + `wpr.exe / tracerpt.exe / wevtutil.exe` 可用 → **ETW 内核事件采集可行**，这是行为观测的主数据源；`pip` 可用（需 `--trusted-host`），可下载 `flare-capa 10.0.0` 作差分 oracle。

**规模预估**：约 10.5 个工程师日，5 个并行 teammate + QA，日历 3–4 天可到 v0.1 可演示；单样本端到端 P95 ≤ 60s（deep 策略）。

---

## 1. 目标与非目标

### 1.1 v1 必须做到（验收口径）

| # | 能力 | 验收标准 |
|---|------|----------|
| G1 | 样本接入与类型识别 | PE32/PE64/脚本(PowerShell/VBS/JS)/压缩包/Office 宏容器识别，输出类型与哈希 |
| G2 | 静态预筛 | PE 头/节区/导入表/资源/签名/熵/加壳启发，脚本关键 API 提取；< 100ms/样本 |
| G3 | 沙箱执行与观测 | 隔离执行 → 归一化行为轨迹（Trace），覆盖 文件/注册表/进程/线程/模块/网络/服务/计划任务/令牌/内存 事件 |
| G4 | capa 兼容规则引擎 | 解析 capa 10 风格 YAML，支持 and/or/not/count/optional/subscope/match 引用，输出命名空间 + ATT&CK/MBC 元数据 |
| G5 | 危险行为检测 | ≥ 25 个检测器，覆盖持久化/提权/凭证/防御规避/发现/横向/收集/C2/影响 全域，支持时序与聚合 |
| G6 | 风险评分与判定 | 输出 clean / suspicious / malicious + 置信度 + 评分明细 + 证据链（可回溯到事件 id）+ 抑制/白名单 |
| G7 | 交付形态 | CLI 全流程；单文件 HTML 报告；本地 HTTP API（127.0.0.1） |
| G8 | 可回归 | 单元测试 + 端到端集成测试 + golden trace 回归 + 与官方 capa 的差分测试 + 语料评测矩阵 |

### 1.2 v1 明确不做（避免范围爆炸）

- 不做内核驱动 / minifilter 实时防护 / 常驻监控。
- 不做云查杀、样本库同步、特征码更新服务。
- 不做真 VM 沙箱（本机不可行；只留 `SandboxBackend` 接口 + 文档说明上机要求）。
- 不做 capa 语法全集（覆盖表见 §5.3，不支持项**显式报错**而非静默跳过）。
- 不做 Windows 之外的平台（接口留白即可）。

### 1.3 交付物清单

`docs/PLAN.md`（本文）、`docs/ARCH.md`、`docs/TRACE_SCHEMA.md`、`docs/RULES.md`、`docs/THREAT_MODEL.md`、`tianti/` 代码、`rules/` 规则包、`detectors/` 检测器包、`tests/`、CLI/API/HTML 报告、`README.md` 使用说明。

---

## 2. 环境约束（已实测，2026-10-24）

| 项 | 实测值 | 对设计的影响 |
|----|--------|--------------|
| OS | Windows 10 Enterprise 19045 / PS 5.1 | 只用 Win10 稳定 API；脚本避免 PS7 语法 |
| 权限 | 管理员 | ETW 内核 provider、防火墙规则、服务/驱动观测可用 |
| CPU/RAM | AMD Athlon X4 860K / 3.9 GB | 并发=1，事件量裁剪，禁止多沙箱并行 |
| 磁盘 | G: 39.8 GB 可用 | 沙箱工作区 + trace 存储够用；trace 做压缩与上限 |
| 虚拟化 | HypervisorPresent=False，Hyper-V/Sandbox/VMPlatform 均 Disabled | **VM 沙箱不可行**；Windows Sandbox 不可用 |
| 编译器 | 无 rustc/cargo/go/dotnet/cl/cmake/gcc | 纯 Python 3.12；不做原生 DLL 注入 |
| Python | 3.12.14（DSH 自带），pip 26.2.1 | 运行时零第三方依赖；测试用 unittest |
| 网络 | HTTPS 直连可用；pip 需 `--trusted-host`；GitHub 直连不通 | 上游 capa-rules 可能拉不到 → **自研规则包为主**，上游仅尽力导入 |
| 可下载 | `flare-capa 10.0.0` wheel 可下载（1.2 MB，不含规则本体） | 官方 capa 可作差分 oracle（仅 dev 依赖） |
| 安全边界 | 无隔离 VM | **本机只允许跑无害/模拟样本**；真恶意样本需外部 VM，见 §4.6 |

> 备注：`wpr.exe`、`tracerpt.exe`、`wevtutil.exe`、`logman.exe`、`sc`、`schtasks`、`reg` 均实测存在；`xperf` 不存在（不需要）。

---

## 3. 总体架构

### 3.1 数据流

```
样本入 ─→ 静态预筛 ─→ 沙箱执行/观测 ─→ 归一化 Trace ─→ 语义识别 ─→ 判定/报告
intake     static       sandbox          normalize      rules+detectors   verdict
                                                          (可回放 JSON)
```

- **可回放是核心设计**：Trace 一旦落盘，规则/检测器/评分的全部开发与 CI 都可离线跑，不依赖真实执行。这决定了团队可以并行。
- 五个层次**只能通过契约通信**：`BehaviorTrace`（§3.3）、`RuleMatch`、`DetectorHit`、`Verdict`。

### 3.2 分层职责

| 层 | 包 | 职责 | 不做什么 |
|----|----|------|----------|
| L0 接入 | `tianti/core`、`tianti/static` | 文件入库、哈希、类型识别、静态特征 | 不执行样本 |
| L1 执行 | `tianti/sandbox` | 隔离、限时、观测、产出原始事件 | 不做语义、不下结论 |
| L2 归一化 | `tianti/trace` | 事件模型、清洗、去噪、派生指标、IO | 不做规则匹配 |
| L3 语义 | `tianti/rules`、`tianti/detect` | capa 规则匹配、危险行为检测 | 不做最终判定 |
| L4 判定 | `tianti/detect/scoring.py`、`verdict.py` | 合并证据、评分、置信度、抑制、判定 | 不采集数据 |
| L5 交付 | `tianti/cli.py`、`tianti/api`、`tianti/report` | CLI/API/HTML 报告 | 不含分析逻辑 |

### 3.3 核心契约：`tianti.trace/1`

```json
{
  "trace_id": "20261024T103500Z-7f3a9c21",
  "schema": "tianti.trace/1",
  "created_at": "2026-10-24T10:35:00+08:00",
  "sample": {"name": "demo.ps1", "sha256": "...", "size": 2048, "type": "script/powershell"},
  "engine": {"version": "0.1.0", "backend": "containment", "policy": "deep"},
  "sandbox": {
    "host": "WIN10-19045",
    "isolation": ["restricted_token", "job_object", "fw_block_out", "workdir_redirect"],
    "limits": {"timeout_s": 20, "mem_mb": 512, "cpu_s": 10, "net": "blocked"},
    "started_at": "...", "ended_at": "...", "terminated_by": "timeout"
  },
  "events": [
    {"id": "e0001", "ts": 0.812, "pid": 4120, "tid": 4124, "ppid": 4000,
     "image": "C:\\\\Users\\\\...\\\\powershell.exe",
     "category": "process", "action": "create",
     "target": "C:\\\\Windows\\\\System32\\\\cmd.exe",
     "args": {"command_line": "cmd.exe /c whoami", "integrity": "medium"},
     "source": "etw:process", "confidence": "high"}
  ],
  "summary": {"processes": 3, "file_writes": 12, "reg_sets": 2, "net_connects": 0,
              "dropped_files": [], "first_seen": 0.0}
}
```

**事件分类（category/action）**：
- `process`: create / exit / suspend
- `thread`: create / remote_create
- `image`: load / unload
- `file`: create / write / read / delete / rename / set_attr
- `registry`: set / create / delete / query
- `network`: connect / listen / dns / send / recv
- `service`: create / start / config
- `scheduled_task`: create / run
- `token`: impersonate / elevate
- `memory`: alloc / protect / map / write
- `api`: call（仅 hook/模拟后端产出，字段含 `api`、`args`、`ret`）
- `security`: amsi / etw / defender 触达

**约定**：`ts` 为沙箱相对启动秒数（float）；`id` 全局唯一且稳定（同一轨迹重算不变）；`source` 标注数据来源；`confidence` ∈ high/medium/low，供评分加权。

### 3.4 目录结构（写范围即按此切分）

```
G:\天体引擎\
├─ README.md
├─ docs\                    PLAN / ARCH / TRACE_SCHEMA / RULES / THREAT_MODEL
├─ tianti\
│  ├─ __init__.py          版本号 0.1.0
│  ├─ cli.py               CLI 入口（delivery）
│  ├─ core\                配置、样本库、哈希、日志、错误、工具（core-static）
│  ├─ static\              PE 解析、脚本提取、压缩包、熵、签名、加壳启发（core-static）
│  ├─ sandbox\             base(协议) / containment / emulation(可选) / replay / watchdog
│  │                       / isolation / telemetry_etw / snapshot / netmon（sandbox）
│  ├─ trace\               schema / normalize / metrics / replay_io（Lead 定契约，sandbox 实现采集→模型）
│  ├─ rules\               yamlmini / parser / features / matcher / engine / packs（rules）
│  ├─ detect\              dsl / detectors / scoring / verdict / suppress（detect）
│  ├─ api\                 httpd（delivery）
│  └─ report\              jsonr / html / mitre（delivery）
├─ rules\
│  ├─ capability\*.yml     自研 capa 格式规则（rules）
│  └─ attack\*.yml         ATT&CK 视角规则（rules）
├─ detectors\*.yml         危险行为检测器（detect）
├─ samples\
│  ├─ sim\                 无害行为模拟样本（powershell/vbs/自造 PE）
│  ├─ benign\              无害对照样本
│  └─ quarantine\          样本库（只读、不可执行、xor+sha256 混淆存储）
├─ config\engine.json      运行配置 + policy 档位
├─ tools\                  下载上游规则、ETW 探针、bench、trace 合成
├─ scripts\                run_tests.ps1 / dev.ps1
└─ tests\                  unit / integration / fixtures / corpus / golden
```

---

## 4. 沙箱设计（执行 + 观测）

### 4.1 后端接口（冻结契约）

```python
class SandboxBackend(Protocol):
    name: str
    def available(self) -> tuple[bool, str]: ...
    def run(self, sample: Sample, policy: SandboxPolicy, on_event=None) -> Trace: ...
```

三个实现：
- `containment`（v1 主后端，本机可用）
- `replay`（v1 必做，零风险、CI 主力）
- `emulation`（v1.1 可选：Qiling/Unicorn，pip 可选依赖）
- `vm`（仅接口 + 文档，v2）

### 4.2 containment 后端：隔离

| 手段 | 实现 | 说明 |
|------|------|------|
| 工作目录重定向 | 样本复制到 `work\<trace_id>\c\`，cwd 指向此处；执行后清理 | 行为落盘可追踪 |
| 受限令牌 | `CreateRestrictedToken(DISABLE_MAX_PRIVILEGES)` + `CreateProcessAsUser` | 降权，避免改系统 |
| 任务对象 | Job Object：内存/CPU 上限、`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`、进程数上限 | 防炸弹，杀树可靠 |
| 网络阻断 | 优先 AppContainer 无网络能力；降级 `netsh advfirewall` 按程序路径 block in/out，finally 清理 | 默认无外联，避免真实 C2 |
| UI/交互 | 隐藏窗口、`STARTF_USESHOWWINDOW`、禁止剪贴板/桌面交互 | 静默执行 |
| 完整性 | 中完整性令牌；驱动/服务修改记录而非拦截（标注 confidence） | 能力边界明确 |
| 超时 | watchdog + 子进程树枚举（`CreateToolhelp32Snapshot`）强杀 | 默认 20s，deep 60s |

> 方案 A（AppContainer）与方案 B（受限令牌 + 防火墙）在 M3 第 1 天做可行性验证，选通一个并写入 `docs/THREAT_MODEL.md`。**安全红线见 §4.6。**

### 4.3 containment 后端：观测

主数据源 **ETW**（admin 可用）：
- 采集：`wpr -start <profile>` 或 `logman start/stop` 订阅内核 provider（`Microsoft-Windows-Kernel-Process/Thread/Image/File/Registry/Network` + `TcpIp`），只采沙箱时间窗与进程树。
- 解析：`tracerpt <etl> -of XML` → `xml.etree` 流式解析 → 事件（含 pid/ppid/path/status）。
- 降级路径（无 admin 或 ETW 失败）：`ReadDirectoryChangesW` 文件监听 + 关键注册表子树前后快照（`reg export` 差异）+ `GetExtendedTcpTable`(ctypes) 轮询 + 进程树轮询；`confidence=medium`。

辅助观测：
- 文件落地物：工作目录 diff + 哈希，写入 `summary.dropped_files`。
- 进程树：快照差分，记录父子与命令行（`NtQueryInformationProcess` / WMI 兜底）。
- 网络：连接表 + DNS（ETW `Microsoft-Windows-DNS-Client`）。
- 反规避信号（只记录不拦截）：VM/沙箱探测（注册表 `HKLM\SYSTEM\CurrentControlSet\Services\VBox*`/`VMware*` 查询、`GetSystemInfo` 核心数、已知分析进程名枚举）、`IsDebuggerPresent`、调试端口查询、长时间 sleep。这些作为检测器「环境探测」的证据。

### 4.4 replay 后端

读 `trace.json`（或 JSONL），按时间序重放事件流，可直接喂给规则/检测器/评分。用于：规则开发、CI、演示、跨环境复现。要求 trace 带 schema 版本，兼容 `tianti.trace/1`。

### 4.5 观测保真度分级（写进报告）

`api(high)` > `etw(high)` > `snapshot(medium)` > `static-infer(low)`。评分时按来源加权，报告里明示「结论基于何种保真度」。

### 4.6 安全红线（硬约束）

1. 本机只跑：EICAR（文本，不执行）、系统自带程序的拷贝、自写模拟行为脚本（标注 `sim`）。
2. 不下载、不传播、不内置任何真实恶意样本；`samples/` 中一律无害。
3. 沙箱默认断网；断网失败则中止执行（fail-closed）。
4. 所有执行有超时与强杀，执行后清理工作区并重置注册表快照差异。
5. 样本库目录 ACL 拒绝执行；样本重命名 + 混淆存储；引擎**永不自动执行**未经策略允许的路径。
6. 真实恶意样本评测需外置 VM，本计划不含。

---

## 5. capa 规则引擎（自研兼容）

### 5.1 规则模型（capa 10 风格子集）

```yaml
rule:
  meta:
    name: 写入 Run 键实现自启动
    namespace: persistence/registry/run-key
    scope: process
    authors: [tianti]
    description: 通过 HKCU/HKLM Run 键实现开机自启
    att&ck:
      - Persistence::Registry Run Keys / Startup Folder [T1547.001]
    mbc:
      - Anti-Behavioral Analysis::... [B0001]
  features:
    - and:
      - registry set: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\*
      - optional:
        - match: 创建子进程
    - or:
      - string: /enc
      - count(api(call, name="PowerShell")): 2 or more
```

支持：`and / or / not / optional / count(...) / subscope / match`；元数据：`name/namespace/scope/authors/description/att&ck/mbc/examples`；作用域：`process / thread / call / span / file`。

### 5.2 动态特征映射（Trace → capa 特征）

| Trace 事件 | capa 特征（示例） | 说明 |
|------------|-------------------|------|
| `api:call` | `api: <name>`、`number/string/bytes` 参数特征 | 仅 hook/模拟后端有 |
| `file:*` | `file: <path>`、`write file`、`delete file` | 路径归一化（变量展开、大小写不敏感） |
| `registry:*` | `registry set/delete/query: <key>` | 键路径归一化 |
| `process:create` | `process: <image>`、`create process` | 命令行作为 string 特征 |
| `network:connect` | `host: / ip: / port:`（扩展特征） | capa 原语法无，使用扩展命名空间 |
| `thread:remote_create`、`memory:protect` | `create thread`、`allocate memory`、`protect memory` | 注入类规则基础 |
| `image:load` | `load image: <dll>` | DLL 侧加载识别 |

路径/键名归一化后建立特征索引（倒排），规则匹配按 scope 实例化（process 级：pid；call 级：事件；span 级：时间窗）。

### 5.3 覆盖矩阵（v1）

| 能力 | v1 | 备注 |
|------|----|------|
| 逻辑组合 and/or/not/optional/count | 支持 | count 支持 `n or more` / 精确 |
| 规则引用 match + 依赖 DAG | 支持 | 环检测报错 |
| 作用域 process/thread/call/span/file | 支持 | span = 进程内时间窗 |
| 元数据 att&ck / mbc / namespace | 支持 | 直接驱动评分与报告 |
| string / number / bytes / offset | 支持 | 十六进制与正则 |
| 静态特征（sections/imports/strings/mnemonics） | 部分 | v1 仅 PE 头/导入/字符串；指令级不做 |
| characteristic / operand / property / basic block / instruction scope | 不支持 | 解析报 unsupported，规则跳过并计数（不静默） |
| 规则包 | 自研 40+ 条 | 上游 capa-rules 若可达则导入子集 + 许可说明 |

### 5.4 匹配算法与性能

- 规则依赖图拓扑排序 → 自底向上求值 → `match` 引用命中缓存。
- 特征倒排索引（特征→事件 id），避免 O(规则×事件)。
- 预算：50 条规则 × 10k 事件 < 300ms；上游全量（约 1000 条）作为 v2 目标。

### 5.5 mini-YAML 解析器（零依赖）

capa 规则只用到 YAML 子集：mapping、sequence、scalar（引号/裸值）、块标量、flow 序列、注释、锚点（可选）。自研约 400–600 行，带行号错误定位与 unsupported 节点上报。**理由**：运行时零依赖 + 完全掌控报错。
若 M4 发现自研成本超期，降级：dev 侧 `pip install pyyaml --trusted-host`，生产侧仍用自研，双解析器差分测试。

### 5.6 差分验证（关键质量手段）

`tools/capa_diff.py`：同一份 trace/样本，分别用 (a) 自研引擎、(b) `flare-capa 10` 官方引擎跑，输出能力集合差异；已知差异登记在 `tests/capa_known_diffs.md`。若官方格式与我们的 trace 不兼容，退化为「同一规则对同一合成特征集」的单元级差分。

---

## 6. 危险行为检测（heuristic detectors）

### 6.1 检测器清单（v1 目标 26 条，按 ATT&CK 战术分组）

| # | id | 名称 | 战术 | 关键证据 | 严重度 |
|---|----|------|------|----------|--------|
| 1 | run_key_persistence | Run/RunOnce 自启动 | TA0003 | registry set Run* | high |
| 2 | startup_folder_drop | 启动目录投放 | TA0003 | file write \Startup\ | high |
| 3 | service_persistence | 安装服务 | TA0003/T1543.003 | service create | high |
| 4 | scheduled_task_persistence | 计划任务 | TA0003/T1053.005 | schtasks / XML 写入 | high |
| 5 | winlogon_userinit | Winlogon/Userinit 篡改 | TA0003/T1547.004 | registry set | critical |
| 6 | lsass_access | LSASS 访问/转储 | TA0006/T1003.001 | 进程句柄/dump | critical |
| 7 | credential_hive_access | SAM/SECURITY/浏览器凭据 | TA0006/T1552 | file read/registry save | high |
| 8 | token_impersonation | 令牌窃取/模拟 | TA0004/T1134 | token impersonate | high |
| 9 | uac_bypass | UAC 绕过链 | TA0004/T1548.002 | fodhelper/eventvwr/computerdefaults | high |
| 10 | process_injection | 进程注入 | TA0005/T1055 | alloc+write+remote thread/APC/mapping | critical |
| 11 | amsi_etw_patch | AMSI/ETW 打补丁 | TA0005/T1562.001 | api 序列 / 写 amsi.dll | critical |
| 12 | defender_tamper | 关闭 Defender | TA0005/T1562.001 | reg set Disable* / Set-MpPreference | high |
| 13 | log_clearing | 清日志 | TA0005/T1070.001 | wevtutil cl / Clear-EventLog | high |
| 14 | shadow_copy_delete | 删卷影/禁用恢复 | TA0040/T1490 | vssadmin/wbadmin/bcdedit | critical |
| 15 | lolbin_abuse | 系统工具滥用 | TA0005/T1218 | rundll32/regsvr32/mshta/certutil | medium |
| 16 | hidden_execution | 隐藏执行 | TA0005/T1564 | -w hidden / -enc / 隐藏窗口 | medium |
| 17 | masquerading_path | 伪装系统文件名 | TA0005/T1036 | 系统名 + 非系统目录 | medium |
| 18 | env_probe | 环境/沙箱探测 | TA0005/T1497 | VM 注册表/进程/核心数探测 | medium |
| 19 | office_spawn_shell | Office→Shell 子进程 | TA0002/T1059 | 父进程 Office + cmd/ps | high |
| 20 | script_exec_bypass | 脚本执行策略绕过 | TA0002/T1059.001 | -ExecutionPolicy Bypass | medium |
| 21 | recon_commands | 主机发现 | TA0007/T1082 | whoami/net user/systeminfo | medium |
| 22 | archive_staging | 打包暂存 | TA0009/T1560 | rar/7z/zip 生成 | high |
| 23 | c2_connect | 外联 C2 | TA0011/T1071 | 外连公网 IP/非常用端口 | high |
| 24 | dns_query_anomaly | DNS 异常查询 | TA0011/T1071.004 | 长标签/高熵域名 | medium |
| 25 | remote_admin_share | 横向移动 | TA0008/T1021.002 | ADMIN$ 拷贝 + 服务创建 | critical |
| 26 | ransomware_mass_ops | 勒索批量加密/删除 | TA0040/T1486 | 短时高熵改写 + 大量 rename/delete | critical |

v1.1 扩展（可选）：bits_job、com_hijack、wmi_subscription、clipboard_hijack、data_exfil_upload。

### 6.2 检测器 DSL（YAML → 编译为 Python 谓词）

```yaml
detector: ransomware_mass_ops
name: 短时间批量高熵文件改写
tactic: TA0040
technique: T1486
severity: critical
score: 40
window_s: 10
match:
  all:
    - category: file
      action: [write, rename]
    - aggregate:
        distinct: [target]
        count: ">= 20"
    - any:
        - file_ext_in: [".locked", ".enc", ".crypt"]
        - entropy_gt: 7.2
suppress:
  - image_signed: true
  - path_under: ["C:\\Program Files\\"]
evidence: events
```

DSL 支持：`all/any/not`、`aggregate(distinct,count)`、`window_s`、`sequence`（多步时序）、`suppress`（签名/路径/白名单）、`evidence` 取值方式；复杂状态机（注入链）可直接用 Python 检测器实现并注册到同一引擎，输出统一 `DetectorHit`。

### 6.3 评分与判定模型

`score = Σ(capability 权重) + Σ(detector.score × 抑制系数) + Σ(static 信号)`

- capability 权重按命中 ATT&CK 战术给基础分（持久化 10 / 提权凭证 15 / 防御规避 8 / 收集 8 / C2 15 / 影响 20），命名空间可覆盖。
- 硬规则：任一 `critical` 检测器命中 → 至少 `malicious`；≥2 个不同战术命中 → 置信度提升。
- 阈值（默认，可配）：`< 10 clean`、`10–39 suspicious`、`>= 40 malicious`。
- 置信度：由证据来源保真度（§4.5）+ 证据数量 + 抑制比例计算，范围 0–1。
- 抑制：白名单路径/签名/已知工具降权 50%–100%，记录 `suppressed` 明细，保证可解释。
- 输出：`Verdict` 含 score/阈值分解/证据链（引用事件 id）/战术集合/ATT&CK 矩阵。

### 6.4 可解释性要求

每个结论必须回答三问：**哪条规则/检测器、基于哪些事件、为什么扣分/加分**。JSON 报告含 `event_ids`，HTML 报告渲染证据时间线，可回溯到 trace 事件。

---

## 7. 交付形态

### 7.1 CLI（`python -m tianti ...`）

| 命令 | 作用 | 示例 |
|------|------|------|
| `scan <path>` | 全流程扫描（文件/目录） | `python -m tianti scan samples\sim\demo.ps1 --policy deep --out out\` |
| `trace <sample>` | 只跑沙箱出 trace | `... trace demo.ps1 --out out\t.json` |
| `replay <trace>` | 离线重放 + 规则/检测器/评分 | `... replay out\t.json --format json` |
| `rules list/validate/match` | 规则包管理与调试 | `... rules match out\t.json` |
| `detectors list/run` | 检测器管理 | `... detectors run out\t.json` |
| `report <result>` | 生成 HTML | `... report out\result.json --html` |
| `serve` | 本地 API | `... serve --port 8765` |
| `version` | 版本/环境自检 | `... version --check` |

### 7.2 本地 HTTP API（stdlib `http.server`，仅 127.0.0.1）

`GET /health`、`POST /scan`（路径或 base64，返回 task_id）、`GET /result/{id}`、`GET /rules`、`GET /trace/{id}`（脱敏后可下载）、`GET /metrics`。JSON 协议，可选本地 token。

### 7.3 HTML 报告（单文件，无外部资源）

摘要（结论/分数/置信度）→ 文件信息与静态特征 → 沙箱执行摘要（进程树、时间线、落地物）→ 能力（按命名空间分组，ATT&CK 标注）→ 危险行为（严重度排序，证据链）→ 评分明细 → ATT&CK 矩阵热图 → 免责声明与保真度说明。纯内联 CSS/JS，双击可开。

### 7.4 配置与策略档位

`fast`（静态 + 浅沙箱 10s）、`deep`（默认，20s，全事件）、`paranoid`（60s，含网络与内存事件）。配置 `config/engine.json`，支持 per-scan 覆盖；字段：超时、内存/CPU、网络、事件上限、规则包路径、白名单。

---

## 8. 工程规范

- Python 3.12，`from __future__ import annotations`，类型注解 + dataclass；模块级 docstring。
- **运行时零第三方依赖**（stdlib only）；dev 可选依赖（官方 capa/PyYAML）只进 `tools/`，不得被 `tianti/` import。
- 错误体系：`TiantiError` → `ConfigError / SampleError / SandboxError / RuleError / DetectorError`；CLI 统一捕获输出结构化错误。
- 日志：JSONL（`trace_id`、`stage`、`elapsed_ms`），默认 `logs/`。
- 测试：`unittest`，`python -m unittest discover -s tests -v`；golden trace 放 `tests/golden/`。
- 版本：`tianti/__init__.py: __version__ = "0.1.0"`；契约变更必须 bump schema 版本。
- Git：`git init`；Lead 每完成一个里程碑打 tag；teammate 写范围互不重叠，冲突由 Lead 合并。

---

## 9. 里程碑（M0–M7）

| 里程碑 | 内容 | 关键交付 | 验收标准 | 依赖 | 预估 |
|--------|------|----------|----------|------|------|
| **M0 地基与契约**（Lead） | 仓库骨架、配置、错误/日志、Trace schema v1 + JSON Schema、`SandboxBackend` 协议、空实现、3 份 golden trace、dev 脚本、git 初始化 | 骨架代码 + `docs/TRACE_SCHEMA.md` | `python -m tianti version` 通过；schema 校验 golden 通过；`unittest` 绿；**契约冻结** | — | 0.5d |
| **M1 静态预筛**（core-static） | PE 解析（DOS/NT/节区/导入/资源/时间戳/签名/熵/加壳启发）、脚本提取、归档展开、哈希/IoC 名单、类型识别 | `tianti/static/*`、`tianti/core/*` | 10 个 fixture 解析正确；EICAR 识别；单样本 < 100ms；畸形 PE 不崩溃 | M0 | 1d |
| **M2 归一化 + 回放**（sandbox+Lead） | 事件模型落地、normalizer、派生指标、JSON/JSONL IO、replay 后端、合成 trace 语料（>=8 场景） | `tianti/trace/*`、`tests/fixtures/traces/*` | 回放确定性（同输入同输出）；schema round-trip；指标计算正确 | M0 | 1d |
| **M3 containment 沙箱**（sandbox） | 隔离方案验证（AppContainer vs 受限令牌+防火墙）、job object、watchdog、ETW 采集与 XML 解析、文件/注册表快照 diff、连接表、降级路径 | `tianti/sandbox/*`；真实 trace | 模拟样本端到端产出 >=5 类事件；超时强杀有效；断网生效；隔离测试通过 | M0/M2 | 2d |
| **M4 capa 规则引擎**（rules） | mini-YAML、规则模型、特征提取、匹配器（count/optional/match/依赖图）、规则包 40+、CLI match、差分脚本 | `tianti/rules/*`、`rules/*` | 20+ 内置规则用例通过；官方 capa 差分差异有清单；不支持语法显式报错 | M2 | 2d |
| **M5 检测器 + 判定**（detect） | DSL 编译器、26 检测器、评分/置信度/抑制/硬规则、证据链、ATT&CK 矩阵 | `tianti/detect/*`、`detectors/*` | 每检测器正/反例通过；语料端到端判定合理；良性样本误报率 <= 5% | M2/M4 | 2d |
| **M6 交付**（delivery） | CLI 全命令、HTML 报告、本地 API、规则/检测器管理、README 与用法 | `tianti/cli.py`、`tianti/api/`、`tianti/report/` | 一条命令完成扫描并生成可读报告；API 冒烟通过；`--help` 完整 | M1/M3/M5 | 1d |
| **M7 评测与加固**（QA+Lead） | 语料评测矩阵、性能预算、鲁棒性（畸形/超大/压缩炸弹/超时）、威胁模型、已知差异文档 | `docs/THREAT_MODEL.md`、评测报告 | 评测表可复现；无 P0 缺陷；红线测试通过 | M6 | 1d |

总计 ≈10.5 人日；并行后日历 3–4 天可演示。

---

## 10. 团队分工（Agent Teams，共享同盘）

| 成员 | 职责 | 写范围（互不重叠） | 启动时机 | 关键产出 |
|------|------|--------------------|----------|----------|
| **Lead** | 架构、契约、集成、评审、终检、文档 | `tianti/trace/schema.py`、`tianti/trace/normalize.py` 契约部分、`docs/*`、`README.md`、`tianti/__init__.py` | M0 | 契约冻结 + 集成 |
| core-static | 静态分析 + 样本接入 | `tianti/static/`、`tianti/core/` | M1 | PE/脚本/归档解析 |
| sandbox | 沙箱执行与观测 | `tianti/sandbox/`、`tianti/trace/replay_io.py`、`tianti/trace/metrics.py` | M2 | containment + replay 后端 |
| rules | capa 规则引擎 + 规则包 | `tianti/rules/`、`rules/`、`tools/capa_diff.py` | M2（等 M0 契约） | 匹配引擎 + 40 规则 |
| detect | 检测器 + 评分判定 | `tianti/detect/`、`detectors/` | M2（等 M2/M4 契约） | 26 检测器 + Verdict |
| delivery | CLI/API/报告 | `tianti/cli.py`、`tianti/api/`、`tianti/report/`、`scripts/` | M1（骨架先占位） | 端到端可用 |
| **qa** | 测试、语料、评测、红线验证 | `tests/`（golden 由 Lead 生成） | M1 | 测试矩阵与缺陷单 |

**协作规则**：
1. M0 结束时 Lead 冻结 4 个契约：`Trace` schema、`SandboxBackend` 协议、`RuleMatch`/`DetectorHit` 结构、`Verdict` 结构。改动需 Lead 评审 + 版本 bump。
2. 共享任务板：每个里程碑拆任务，`write_scopes` 与上表一致；`blocked_by` 表达依赖（M3<-M0/M2，M4<-M2，M5<-M2/M4，M6<-M1/M3/M5）。
3. 所有 teammate 只通过契约文件通信；禁止跨范围改别人文件，需要改动先发消息。
4. Lead 每完成一个里程碑跑全量测试 + 红线检查，再放行下一个依赖。
5. qa 只写 `tests/`，报告缺陷给对应 owner，不改引擎代码。

---

## 11. 测试与评测

### 11.1 测试分层

| 层 | 内容 | 通过标准 |
|----|------|----------|
| 单元 | PE 解析、YAML 解析、特征提取、匹配器、每个检测器正反例、评分函数、抑制 | 覆盖率 >= 75%，全绿 |
| 契约 | Trace schema 校验、golden trace round-trip、Verdict 结构 | 100% 通过 |
| 集成 | 静态→沙箱→规则→检测→报告 三条链路（脚本模拟样本 / 回放 trace / 目录扫描） | 端到端产出报告 |
| 差分 | 自研 vs 官方 capa（能力集合） | 差异登记且逐条说明 |
| 鲁棒 | 畸形 PE、0 字节、超大文件、压缩炸弹、超时样本、断网失败 | 不崩溃、超时可控、fail-closed |
| 安全 | 逃逸尝试（写系统目录/起子进程/连网/改服务）被限制或记录 | 红线测试全过 |

### 11.2 语料

- `samples/sim/`：自写 PowerShell/VBS/批处理行为模拟（持久化、注入模拟、批量加密模拟、C2 模拟连接）——**只做行为，不含恶意代码**。
- `samples/benign/`：系统自带程序拷贝、正常脚本。
- EICAR：静态识别用例（不执行）。
- 公开行为报告回放：`tools/report2trace.py` 把 CAPE/capa 格式报告转成 `tianti.trace/1`，用于扩充语料（无真实样本）。
- 真恶意样本：不在本机；后续在独立 VM 环境评测。

### 11.3 评测矩阵（M7 产出）

| 指标 | 目标 |
|------|------|
| 静态分析耗时 | P95 < 100ms |
| 沙箱单样本耗时 | deep 策略 P95 < 25s（上限 60s） |
| 规则匹配 | 50 规则 × 10k 事件 < 300ms |
| 报告生成 | < 500ms |
| 检测器 | 模拟语料 TPR >= 90%，良性 FPR <= 5% |
| 判定准确率 | 模拟语料三分类 >= 85% |
| 内存峰值 | 沙箱进程 + 引擎 < 1.2 GB |

---

## 12. 风险与对策

| 风险 | 影响 | 对策 |
|------|------|------|
| 无虚拟化，真恶意样本不可跑 | 无法做真实评测 | 明确安全边界；模拟样本 + 公开报告回放；VM 后端接口 + 上机文档 |
| 无编译器，无法做用户态 hook | 观测粒度受限 | ETW 内核事件为主 + 快照 diff 兜底；`api` 级特征由 emulation 后端补（可选） |
| 4 GB 内存 / 单核偏弱 | 并发与事件量受限 | 并发 1；事件上限与裁剪；trace 压缩；超时分级 |
| ETW 需 admin，事件量大 | 采集失败或 trace 爆炸 | 降级路径；白名单 provider；事件上限 + 丢弃计数标注 |
| capa 语法覆盖不全 | 上游规则不可全用 | 覆盖表 + 显式报错 + 差分清单；v1 只承诺子集 |
| 自研 YAML 解析器成本超期 | M4 延期 | 降级：dev 用 PyYAML，生产保留自研；双解析器差分 |
| 误报 | 判定不可信 | 抑制/白名单/签名降权；阈值保守；证据链强制 |
| 样本执行风险 | 本机污染 | 红线 §4.6：断网、低权、job 限制、超时强杀、只跑无害样本 |
| 上游规则/代码许可 | 合规 | capa/capa-rules 为 Apache-2.0；导入保留头部与 NOTICE；自研代码独立许可说明 |
| 契约漂移 | 集成返工 | M0 冻结 + 版本 bump + Lead 评审 |

---

## 13. 待确认决策（附默认值，可直接按默认开工）

1. **平台范围**：默认仅 Windows（沙箱与观测都基于 Win10）；Linux/ELF 只留静态分析接口。默认：接口留白，不实现。
2. **交付形态优先级**：CLI 优先，HTML 报告次之，API 最后；v1 不做 Web UI。默认：只有静态 HTML 报告。
3. **依赖策略**：运行时零依赖、dev 可选装（官方 capa/PyYAML）。默认：生产不允许第三方依赖。
4. **规则来源**：自研 40+ 条 capa 格式规则为主，上游规则尽力导入（GitHub 不通则跳过）；全量兼容留 v2。默认：v1 子集。
5. **评测样本**：只用无害模拟样本 + 公开报告回放；真样本需外置 VM。默认：不在本机做。
6. **命名**：默认「天体引擎 / TianTi」，CLI 前缀 `tianti`；改名请早说（影响包名/规则命名空间）。

---

## 14. 下一步

1. 你确认本计划（或提出修改：平台/依赖/交付形态/规则来源）。
2. 我按 M0 开工：初始化仓库骨架、冻结四个契约、写 `docs/TRACE_SCHEMA.md` 与 golden trace，并拉起 5 个 teammate（core-static / sandbox / rules / detect / delivery）+ qa。
3. M0 完成后进入并行开发，每个里程碑交付后我做全量测试 + 红线检查再放行。

> 免责声明：本引擎为行为分析原型，结论不构成安全保证；沙箱隔离能力受本机条件限制，禁止在本机执行不受信任的真实恶意样本。
