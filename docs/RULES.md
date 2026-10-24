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
