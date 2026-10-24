# 评分、抑制与判定（L4）

> 代码：`tianti/detect/scoring.py`、`tianti/detect/suppress.py`、`tianti/core/verdict.py`
> 配置：`config/engine.json` 的 `scoring` 段

## 1. 分数构成

```
score = Σ capability（按 ATT&CK 战术权重，同战术递减）
      + Σ detector.score × 抑制系数
      + Σ static.signal.score
```

- **capability**：capa 规则命中（RuleMatch）。权重由规则 meta 的 ATT&CK 战术决定：
  TA0004/TA0006/TA0008/TA0011 = 15，TA0040 = 20，TA0003 = 10，
  TA0002/TA0005/TA0009 = 8，TA0001 = 6，TA0007 = 5；无战术命中给 4。
  同战术第 2 条 ×0.65、第 3 条起 ×0.30（下限 0.25），保证分数单调且不因规则多而爆炸。
- **detector**：危险行为检测器自带 `score`（严重度映射：critical 25–40、high 15–20、medium 5–10），
  乘抑制系数后计入。
- **static**：静态信号自带 `score`（low=2 / medium=5 / high=10 / critical=20；EICAR 显式 0）。
  静态信号只加分不扣分。

## 2. 抑制（suppress）语义

| 触发 | 系数 | 说明 |
|------|------|------|
| 样本自身路径/哈希命中白名单 | 0.0（完全抑制） | 只有「样本自己」在白名单才整体压制 |
| 事件级 target/image 命中白名单/可信路径 | 0.5 | 只降权，不归零 |
| 检测器 YAML `suppress`（可信安装目录等） | 0.25 | 同上 |
| critical 检测器保底 | ≥0.5 | critical 永不完全抑制（最多降 50%） |

**默认白名单为空**：`config/engine.json` 的 `whitelist_paths` 默认 `[]`。
不要把 `C:\Windows\` 当默认可信路径——cmd.exe/powershell.exe 往往是样本的「工具」而不是「可信来源」。
被抑制的命中仍保留在 `Verdict.items` 中（`suppressed=true` + reason），可解释性不丢。

签名校验当前是**基于可信路径的占位实现**（非证书链验证）。一旦发生路径信任导致的抑制，
`Verdict.notes` 会自动追加固定说明，报告需展示该 note。

## 3. 阈值与判定

| 分数 | 判定 |
|------|------|
| < 10（clean_below） | clean |
| 10–39 | suspicious |
| ≥ 40（malicious_at） | malicious |

**critical 硬规则**：未被完全抑制（系数 ≥ 0.5）的 critical 检测器命中，分数至少抬到 40 → malicious；
跨 ≥2 个战术命中额外 +0.05 置信度。

## 4. 置信度

`confidence = confidence_from(score, 证据事件数, 来源保真度, 抑制比例)`（0–1）：
证据多、来源 high（etw/api）提分；抑制比例高与轨迹截断（`trace.summary.truncated` ×0.9）扣分。

## 5. 证据链

每个 `ScoreItem` 的 `evidence` 都是 trace 事件 id，报告可逐条回溯到时间线。
禁止「只有结论、没有证据」的命中——这是评审硬要求。

## 6. 检测器清单（26 条）

| 严重度 | 检测器 |
|--------|--------|
| critical | winlogon_userinit、lsass_access、process_injection、amsi_etw_patch、shadow_copy_delete、remote_admin_share、ransomware_mass_ops |
| high | run_key_persistence、startup_folder_drop、service_persistence、scheduled_task_persistence、credential_hive_access、token_impersonation、uac_bypass、defender_tamper、log_clearing、office_spawn_shell、archive_staging、c2_connect |
| medium | lolbin_abuse、hidden_execution、masquerading_path、env_probe、script_exec_bypass、recon_commands、dns_query_anomaly |

覆盖战术：TA0002/TA0003/TA0004/TA0005/TA0006/TA0007/TA0008/TA0009/TA0011/TA0040。

## 7. 已知误报与调参

- `script_exec_bypass` 会命中沙箱宿主自身的 `-ExecutionPolicy Bypass`：
  detect 已排除「根进程」（第一条 process:create / 样本镜像）的启动命令行，只有样本自己 spawn 的进程才算。
- 良性脚本若使用隐藏窗口/解析执行，仍可能落到 suspicious（10–39）：这是有意的保守策略，报告会给出证据。
- 调参入口：`config/engine.json` 的 `scoring`（阈值、战术权重、白名单）+ 检测器 YAML 的 `score/suppress`。
  改评分后必须重新固化 `tests/fixtures/regression/golden_expectations.json`（QA 负责，见 tests/README.md）。
