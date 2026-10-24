# 天体引擎 / TianTi

沙箱行为分析型杀毒引擎（全新模式）：**沙箱执行 + capa 规则识别能力 + 危险行为检测**。
不做特征码比对，只看文件「跑起来做了什么」。

## 状态

| 里程碑 | 内容 | 状态 |
|--------|------|------|
| M0 | 地基与契约（Trace / SandboxBackend / RuleMatch+DetectorHit / Verdict） | 进行中 |
| M1 | 静态预筛（PE/脚本/归档/熵/加壳启发） | 待启动 |
| M2 | 归一化 + 回放后端 | 待启动 |
| M3 | containment 沙箱（隔离 + ETW 观测） | 待启动 |
| M4 | capa 兼容规则引擎 + 规则包 | 待启动 |
| M5 | 危险行为检测器 + 评分判定 | 待启动 |
| M6 | CLI / HTML 报告 / 本地 API | 待启动 |
| M7 | 评测与加固 | 待启动 |

计划全文见 [docs/PLAN.md](docs/PLAN.md)。

## 快速开始

```powershell
# 版本与环境自检
python -m tianti version --check

# 跑测试（使用 DSH 自带 Python 也可）
powershell -ExecutionPolicy Bypass -File scripts\run_tests.ps1
```

## 目录

```
tianti/       引擎包（core/trace/sandbox/rules/detect/static/api/report）
rules/        capa 格式能力规则
detectors/    危险行为检测器
samples/      无害样本（sim 模拟行为 / benign 对照 / quarantine 样本库）
tests/        单元/集成/golden trace
docs/         计划、架构、Trace 契约、规则格式、威胁模型
```

## 安全红线

- 本机只允许无害样本、EICAR（文本）与自写「模拟行为」脚本。
- 不内置、不下载真实恶意样本；沙箱默认断网、限时、强杀。
- 本项目为行为分析原型，结论不构成安全保证。

## 许可

自研代码：见仓库说明；如导入上游 capa 规则（Apache-2.0）将保留其头部与 NOTICE。
