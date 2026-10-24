# TianTi 测试说明（QA）

本目录是引擎的质量门：单元 / 契约 / 集成 / 差分 / 鲁棒 / 安全六层。
所有测试使用 Python 标准库 `unittest`，**运行时零第三方依赖**。

## 1. 运行方式

解释器必须用绝对路径（PATH 里的 `python` 是 Store 占位符）：

```powershell
# 全量（cwd = G:\天体引擎）
& "C:\Users\Administrator\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe" -m unittest discover -s tests -t . -v

# 单模块
& $PY -m unittest tests.integration.test_regression -v
& $PY -m unittest tests.integration.test_redline -v
& $PY -m unittest tests.perf.test_perf_smoke -v

# 或使用脚本（自动发现 DSH Python）
powershell -ExecutionPolicy Bypass -File scripts\run_tests.ps1
```

约定：

- 测试根为仓库根（`-t .`），`tests` 是包（有 `__init__.py`），可用 `from tests import qa_helpers`。
- 新增子目录必须带 `__init__.py`（如 `tests/perf/__init__.py`）。
- 用例必须可从仓库根独立运行，不依赖 cwd、网络、真实恶意样本。

## 2. 测试矩阵

| 层 | 目录 / 文件 | 覆盖内容 | 通过标准 |
|----|-------------|----------|----------|
| 单元 | `tests/unit/test_*.py`（各 owner） | PE/脚本/归档解析、YAML、规则匹配、检测器、评分、报告、CLI | 全绿；关键函数有正反例 |
| 契约 | `tests/unit/test_schema.py`、`test_contracts.py`、`tests/integration/test_regression.py`（GoldenTraceContractRegression） | Trace `tianti.trace/1` 校验、golden round-trip、summary 可重算、Verdict 结构 | 100% 通过；契约漂移立即失败 |
| 集成 | `tests/integration/test_*.py`（各 owner）+ `test_regression.py`（CliReplayRegression） | 静态→沙箱→规则→检测→评分→CLI 全链路 | 产出合法 Trace / Verdict；判定符合期望 |
| 差分 | `tools/capa_diff.py`（rules）+ `tests/capa_known_diffs.md` | 自研引擎 vs 官方 capa 能力集合 | 差异逐条登记说明 |
| 鲁棒 | 各 owner 单元用例 + `test_redline.py` 语料自检 | 畸形 PE、0 字节、超大文件、压缩炸弹、超时、断网失败 | 不崩溃、超时可控、fail-closed |
| 安全 | `tests/integration/test_redline.py` | 系统目录写入、子进程观测/残留、断网、超时杀树、fail-closed、语料无害性 | 红线用例通过；未就绪模块 skip 且原因明确 |
| 性能 | `tests/perf/test_perf_smoke.py` | 10k 事件构造/校验/JSON/规则/检测/CLI 耗时 | 低于宽松阈值，结果落 `tests/perf/last_perf.json` |

### 2.1 QA 维护的文件（本目录内新增，不覆盖 owner 文件）

| 文件 | 作用 |
|------|------|
| `tests/README.md` | 本文件：测试矩阵与规范 |
| `tests/corpus.md` | 语料来源、用途、许可证、安全边界 |
| `tests/qa_helpers.py` | 公共工具：路径、可选模块探测、CLI 调用、心跳/残留进程检查 |
| `tests/integration/test_regression.py` | golden trace 回归（契约 + CLI 端到端 + 基线） |
| `tests/integration/test_redline.py` | 安全红线（沙箱隔离/断网/超时/fail-closed/语料无害） |
| `tests/perf/test_perf_smoke.py` | 性能冒烟 + `last_perf.json` 快照 |
| `tests/fixtures/regression/golden_expectations.json` | 3 份 golden trace 的期望判定/规则/检测器 |
| `tests/fixtures/regression/golden_baseline.json` | 首次可用时自动固化的结论基线（见 §4） |
| `samples/sim/`、`samples/benign/` | 无害模拟语料与良性对照（见 `corpus.md`） |

> 纪律：**只新增自己的文件，绝不删除/覆盖/重命名他人测试文件**。需要清理先发消息。

## 3. skip 约定（未就绪模块）

后续里程碑模块可能尚未就绪，用例必须优雅降级，不允许"红着等实现"：

- skip 原因**必须**以 `未就绪:` 开头（常量 `qa_helpers.SKIP_PREFIX`），说明缺哪个模块/接口；
- 用 `unittest.SkipTest` / `self.skipTest(...)`，禁止 `return` 静默通过；
- 模块探测统一走 `qa_helpers.import_optional()` / `containment_backend()`，返回 `(None, 原因)`；
- 一旦模块可用（`available() == True` / CLI 可解析），同一用例必须转为真实断言；
- 只读/只写公开契约（Trace / RuleMatch / DetectorHit / Verdict / CLI JSON），
  不 import 私有实现细节；确需内部注入点时在用例中明确标注并联系 owner。

CLI 相关测试纪律（Lead）：新增 CLI 用例另建 `test_cli_contract.py` 之类文件，
**不断言退出码 3 / “尚未实现”** 等占位行为；本仓库回归测试把"CLI 尚不可用"当作 skip 条件，而非断言对象。

## 4. golden trace 回归

- 输入：`tests/fixtures/traces/golden_{ransom_sim,injection,benign_installer}.json`。
- 期望：`tests/fixtures/regression/golden_expectations.json`
  - `event_count` / `sample_type` / `required` 事件类别；
  - `verdict_allowed` / `min_score` / `max_score`（阈值来自 PLAN §6.3）；
  - `rule_hints`（任一命中）与 `required_detectors`（检测器 id 必须命中）。
- 端到端：`python -m tianti replay <trace> --format json` → 提取 `verdict.verdict` / `score` /
  `matches` / `hits`，断言判定与分数范围。
- 基线：首次 CLI 可用且**结论满足期望**时，自动写
  `tests/fixtures/regression/golden_baseline.json`（含 `generated_at` / `generated_by` /
  `source` 元数据）；之后逐项比对 verdict/score/规则名/检测器 id。结论漂移 → 失败。
- 基线更新流程（谁改评分谁触发）：
  1. 任何修改评分/规则/检测器语义的 owner（detect / rules / delivery）必须先通知 Lead 与 QA，并说明预期变化；
  2. Lead 确认冻结后，QA 删除 `golden_baseline.json` 并重跑
     `python -m unittest tests.integration.test_regression -v`，由测试自动重新固化（记录命令与时间）；
  3. QA 在同一条消息里报告新旧 verdict/score 差异；未通知的漂移一律按回归缺陷处理。
- 基线不得在结论不满足期望时生成，避免把缺陷固化成 golden。

## 5. 性能冒烟

`tests/perf/test_perf_smoke.py`：

- 合成 10,000 事件混合 Trace（进程/文件/注册表/网络/内存/线程/API），不依赖真实执行；
- 阶段（分开计时，便于定位慢点）：`trace_build_10k`、`schema_validate_10k`、
  `json_roundtrip_10k`、`rules_match_10k`（冷启动 + 热启动）、`detect_10k`、
  `scoring_10k`、`cli_replay_2k`（CLI 端到端 2k 事件，只作冒烟，避免 10k CLI 抖动/挂起）；
- 阈值宽松（见文件 `THRESHOLDS_MS`），只拦截数量级回退，避免机器抖动误报；
- 重阶段（rules/detect/scoring）由子进程 `tests/perf/perf_worker.py` 在 1k/10k 两个规模计时，
  子进程有硬超时（默认 90s），卡死会记为 timeout 而不是挂起整个测试套件；1k→10k 倍率用于判断线性度。
- 每次运行写 `tests/perf/last_perf.json`：

```json
{
  "schema": "tianti.qa.perf/1",
  "generated_at": "...",
  "events": 10000,
  "stages": {
    "trace_build_10k": {"elapsed_ms": 42.0, "threshold_ms": 3000.0, "status": "pass"},
    "rules_match_10k": {"status": "skipped", "reason": "未就绪: ..."},
    "detect_10k": {"elapsed_ms": 120.0, "threshold_ms": 5000.0, "status": "pass"}
  }
}
```

该文件是生成物，已在 `tests/perf/.gitignore` 忽略。查看当前性能：

```powershell
Get-Content tests\perf\last_perf.json -Raw | ConvertFrom-Json | Select-Object -ExpandProperty stages
```

## 6. 安全红线测试

`tests/integration/test_redline.py`，红线来源 `docs/THREAT_MODEL.md §4`：

| 用例 | 红线 | 判定 |
|------|------|------|
| `SampleCorpusSafetyTests.*` | R1 | sim/benign 无下载器/破坏性命令/可执行文件，脚本头有 SIMULATION ONLY + 无害声明；zip 非炸弹 |
| `PolicyRedlineDefaultsTests.*` | R2/R3 | 默认策略全部 `network=blocked` 且 `0 < timeout_s <= 60`；golden trace 声明隔离 |
| `test_system_dir_write_is_restricted_or_recorded` | R4 | 写 `C:\Windows\` 要么被阻止，要么有 file 事件可审计 |
| `test_child_process_is_observed_and_tree_terminated` | R3 | 子进程被观测；进程树全部退出；OS 层无命令行含 workdir 唯一名的残留进程 |
| `test_timeout_terminates_whole_tree` | R3 | `terminated_by=timeout`，无残留进程 |
| `test_network_is_blocked_or_attempt_recorded` | R2 | 隔离列表声明网络阻断；无成功外联事件 |
| `test_fail_closed_when_network_isolation_unavailable` | R2 | 注入断网失败后**不得执行样本**（不返回 trace、无执行标记） |

containment 未就绪时整组 skip；fail-closed 若找不到可注入点（如
`isolation.Isolation._install_firewall_rules`）也 skip，并提示联系 sandbox owner。
测试只执行 `samples/sim` 下自写无害脚本，探针文件测试结束即清理。

## 7. 如何新增用例

1. 选层：单元→`tests/unit/`，跨层/真实执行→`tests/integration/`，性能→`tests/perf/`。
2. 命名：`test_<主题>.py` / 类 `XxxTests` / 方法 `test_<行为>`；避免与 owner 文件重名。
3. 模板：

```python
from __future__ import annotations
import unittest
from tests import qa_helpers as qa

class FeatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module, cls.reason = qa.import_optional("tianti.some.module")

    def test_behaviour(self) -> None:
        if self.module is None:
            self.skipTest(self.reason)  # "未就绪: ..."
        self.assertEqual(...)
```

4. 夹具：小型 JSON 放 `tests/fixtures/`；不要提交真实恶意样本、大二进制、带 PII 的 trace。
5. 确定性：固定输入、固定阈值；时间/随机/进程表相关断言留余量（参考 `wait_heartbeat_stopped`）。
6. 安全：需要执行时只用 `samples/sim`、`samples/benign`；禁止外联真实地址；测试结束清理临时文件。
7. 新增/修改 golden 期望：先与 Lead 对齐，再改 `golden_expectations.json`；不要擅自改契约。

## 8. 缺陷报告模板（QA → owner + Lead）

```
[owner] 失败用例: tests/xxx.py::Class::test_name
复现命令: & $PY -m unittest tests.xxx -v
期望: <契约/文档依据>
实际: <输出/异常摘要，附 verdict/score/事件 id>
影响: <红线/回归/性能/误报>
备注: <是否未就绪 skip、是否与并发写盘有关>
```

归因映射：`tianti/static|core` → core-static；`tianti/sandbox|trace/replay_io|metrics` → sandbox；
`tianti/rules|rules/` → rules；`tianti/detect|detectors/` → detect；`tianti/cli|report|api` → delivery；
契约/schema/docs → Lead。

## 9. 当前状态与已知限制

- 全量测试结果、通过/失败/跳过计数、benign FPR 与性能数字由 QA 每轮写入交付报告（`send_message` 给 Lead），
  本文件只维护"方法/规范"，不复制易过期的数字。
- 性能阈值是冒烟级，不是验收级；正式预算见 `docs/PLAN.md §11.3`。
- 本机无 VM：红线测试只能验证"受限执行"边界，不能证明对真实恶意样本的隔离强度（见 `docs/THREAT_MODEL.md`）。
- 环境风险（360 HIPS）：本机 360 会删除含**密集恶意命令字面量**的 `.py`（已实测多次）。因此测试源码中禁止堆叠恶意命令字面量，涉及检测关键字时用字符串拼接（如 `"vss" + "admin delete"`）；写入测试文件后建议立即校验存在性，最终报告需注明该风险。
