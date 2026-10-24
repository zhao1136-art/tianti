# 规则格式（capa 10 风格子集）

## 1. 文件与命名

- 规则放 `rules/capability/**/*.yml` 与 `rules/attack/**/*.yml`，一个文件一条规则。
- `rule.meta.namespace` 用目录式命名空间：`persistence/registry/run-key`。
- 文件内 `rule.features` 为逻辑树，顶层必须是一个逻辑节点（and/or/not/optional/count）。

## 2. meta 字段

| 字段 | 必填 | 说明 |
|------|------|------|
| `name` | 是 | 规则名（可中文） |
| `namespace` | 是 | 命名空间，报告按它分组 |
| `scope` | 是 | process / thread / call / span / file |
| `authors` | 否 | 作者列表 |
| `description` | 否 | 说明 |
| `att&ck` | 否 | `战术::技术 [Txxxx.xxx]` 列表，用于评分与矩阵 |
| `mbc` | 否 | 同风格的方法行为元数据 |
| `examples` | 否 | 示例（哈希/名称，不含真实样本） |

## 3. 支持的特征（v1）

| 特征 | 写法 | 说明 |
|------|------|------|
| 文件动作 | `file: <path>`、`write file: <path>` | 路径大小写不敏感，支持通配 |
| 注册表动作 | `registry set: <key>`、`registry query: <key>` | 键路径归一化 |
| 进程创建 | `process: <image>`、`create process: <image>` | 命令行作为 string 子特征 |
| 映像加载 | `load image: <dll>` | |
| 网络（扩展） | `ip: 1.2.3.4`、`port: 8443`、`host: example.com` | 自研扩展特征 |
| 内存/线程 | `allocate memory`、`protect memory`、`create thread`、`remote thread` | 注入类规则 |
| 安全组件 | `amsi`、`etw` | security 事件 |
| 字符串 | `string: /regex/` 或 `string: plain` | 从命令行/参数提取 |
| 数值 | `number: 0x1000`、`number: 4096` | |
| 逻辑 | `and`、`or`、`not`、`optional` | 可嵌套 |
| 计数 | `count(api(call, name="VirtualAllocEx")): 3 or more` | 支持精确值 |
| 规则引用 | `match: <规则名>` | 依赖 DAG，环检测报错 |
| 子作用域 | `subscope` | 仅 process/call/span |

## 4. 明确不支持（v1）

`characteristic`、`operand`、`property`、`basic block` scope、
`instruction` scope、指令级 `mnemonic`、`offset` 精确到指令、静态节区 `bytes` 语义。

遇到不支持项：解析器记录 `unsupported`，该规则跳过并计数（`RuleSet.unsupported`），
**不静默忽略**，报告与 CLI 可见。

## 5. 示例

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
  features:
    - and:
      - registry set: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\*
      - optional:
        - create process: cmd.exe
```

## 6. 编写检查清单

1. scope 选对：进程级行为用 `process`；单次 API 语义用 `call`。
2. 每个特征都要能被某类 Trace 事件满足（对照 docs/TRACE_SCHEMA.md §3.1）。
3. 规则名不与已有规则重名（CI 校验）。
4. 有 ATT&CK 映射的必须写 `att&ck`，否则评分拿不到战术权重。
5. 新增规则必须带正例夹具（可用 `tests/fixtures/traces/` 合成）。

## 7. 差分验证

`tools/capa_diff.py`：同一份 trace 分别用自研引擎与官方 `flare-capa` 跑，比对能力集合。
已知差异登记在 `tests/capa_known_diffs.md`。官方 capa 不支持我们的扩展特征（ip/port/host），属预期差异。

## 8. 上游 capa 规则包（rules/upstream/，默认关闭）

来源：Mandiant 官方 capa-rules（本地镜像 `H:\capa-rules-master`），Apache-2.0，完整许可见 `rules/upstream/LICENSE.txt`，来源与条数见 `rules/upstream/SOURCE.md`。

**导入工具**：`tools/import_capa_rules.py`

```powershell
# 只生成分类报告
python tools/import_capa_rules.py --source H:\capa-rules-master --report out\capa_import_report.json
# 复制可解析规则到 rules/upstream/（幂等 + prune）
python tools/import_capa_rules.py --source H:\capa-rules-master --dest rules/upstream --copy --prune
```

**兼容性口径（本次导入，1054 条候选）**：

| 分类 | 数量 | 说明 |
|------|------|------|
| ok（动态可匹配） | 625 | 已入库；scope 映射后 span 317 / call 214 / file 93 / process 1 |
| unsupported | 429 | 静态特征（offset/operand/property/mnemonic/instruction/basic block/bytes 等）或 dynamic=unsupported 或 Linux/Android-only |
| error | 0 | 解析器已覆盖官方动态规则语法 |
| non_rule | 3 | .github CI 配置 |

官方 dynamic 规则兼容率：625/875 = 71.4%；剔除 Linux/Android-only 后 **625/811 = 77.1%**。
加载时 132 条上游规则因 `match` 引用的其他规则未导入被剪枝（`RuleSet.unsupported` 显式上报，不静默）。

**启用方式**（默认关闭，保持 54 条自研规则基线）：

```powershell
python -m tianti replay <trace.json> --include-upstream
python -m tianti rules validate --include-upstream
python -m tianti scan <sample> --include-upstream
```

或配置 `config/engine.json`：`rules.include_upstream = true`。

**效果（golden trace）**：默认 15/1/6 → +upstream 16/1/6（ransom 新增 `delete volume shadow copies` [T1490]）。
**性能**：默认 1k 37ms / 10k 388ms；+upstream（547 条）1k 237ms / 10k 1.98s。

**语义差异（已知）**：
- 上游规则依赖 `api:` 级动态特征；本地 containment 沙箱 ETW 默认关闭时 api 事件很少，真正发挥需要 CAPE/capa 报告回放（`python -m tianti convert-cape`）或后续 emulation/API trace 后端。
- 上游 `string`/`substring` 语义为动态字符串参数，本引擎按事件 target/args 文本匹配，偏保守。
- `count(match(...))` 阈值 >1 时按「引用规则命中即计 1」近似，可能漏报。
