# 架构说明

## 1. 分层

```
L0 接入   tianti/core, tianti/static     样本哈希/类型/静态特征      不执行
L1 执行   tianti/sandbox                 隔离、限时、观测、出事件     不做语义
L2 归一化 tianti/trace                   契约、清洗、指标、IO/回放    不做匹配
L3 语义   tianti/rules, tianti/detect    capa 规则 + 危险行为检测     不下结论
L4 判定   tianti/core/verdict + detect   评分、置信度、抑制、证据链   不采集
L5 交付   tianti/cli, api, report        CLI / HTTP / HTML           不含分析
```

依赖方向严格单向：L1 只依赖 core+trace；L3 只依赖 trace+core；L4 依赖 L3 的输出结构。

## 2. 冻结契约

| 契约 | 文件 | 产出方 | 消费方 |
|------|------|--------|--------|
| Trace | `tianti/trace/schema.py` | sandbox | normalize/rules/detect/report |
| SandboxBackend | `tianti/sandbox/base.py` | sandbox | CLI/编排 |
| RuleMatch | `tianti/rules/base.py` | rules | scoring/report |
| DetectorHit | `tianti/detect/base.py` | detect | scoring/report |
| Verdict | `tianti/core/verdict.py` | detect/scoring | report/api |

变更流程：改契约 -> 改 docs -> bump 版本 -> Lead 评审 -> 通知所有 owner。

## 3. 关键设计决策

1. **可回放优先**：Trace 可落盘、可重放、可合成，规则/检测器开发不依赖真实执行。
2. **后端可插拔**：containment（本机）/ replay（CI）/ emulation（可选）/ vm（未来）。
3. **零运行时依赖**：只用 Python 3.12 标准库；官方 capa 只作为差分测试 oracle 存在。
4. **观测保真度显式化**：来源与置信度进入 Trace，评分按保真度加权，报告可见。
5. **可解释性强制**：每条结论必须引用事件 id；评分明细逐项可查。

## 4. 数据流（scan 一次调用）

```
scan(path)
  -> Sample.from_path / static.analyze            (L0)
  -> sandbox.run(sample, policy) -> Trace          (L1)
  -> trace metrics（可选）                          (L2)
  -> rules.match(trace) -> [RuleMatch]            (L3)
  -> detect.run(trace) -> [DetectorHit]           (L3)
  -> scoring.score(matches, hits, static) -> Verdict (L4)
  -> report.render(result) -> out/*.json / *.html (L5)
```

## 5. 扩展点

- 新沙箱后端：实现 `SandboxBackend`，在模块导出 `BACKEND`，CLI 自动识别可用性。
- 新规则特征：在 `tianti/rules/features.py` 注册特征提取器 + 在 RULES.md 声明。
- 新检测器：YAML（`detectors/*.yml`）或 Python 类（注册到 detect registry），输出 `DetectorHit`。
- 新报告格式：`tianti/report/` 下新增渲染器，输入统一 `ScanResult`。

## 6. 失败模式

| 场景 | 行为 |
|------|------|
| 沙箱不可用 | 明确报错，回退 replay（若允许）并在 Verdict.notes 标注 |
| 断网失败 | fail-closed：中止执行，不跑样本 |
| 轨迹被截断 | `summary.truncated=true`，报告标注，评分置信度下调 |
| 规则语法不支持 | 规则跳过 + `RuleSet.unsupported` 记录 + 报告可见 |
| 检测器异常 | 单检测器失败不影响其他检测器，错误汇总到 notes |
