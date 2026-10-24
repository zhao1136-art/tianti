# 威胁模型与安全红线

## 1. 资产

- 本机文件系统与注册表（不得被样本修改）
- 样本库（不得被执行、不得外传）
- 分析结果与证据（不得被样本篡改）
- 用户数据（不得被样本外联）

## 2. 信任边界

```
不可信：被检样本、样本释放的文件、样本发起的网络请求
半可信：ETW/快照采集到的数据（可能被样本伪造行为误导）
可信：引擎自身代码、规则包（需评审）、配置文件
```

## 3. 隔离手段（M3 定稿：受限令牌 + 低完整性 + Job Object + 防火墙）

最终选型（实测生效，红线用例通过）：

- **受限令牌**：CreateRestrictedToken(DISABLE_MAX_PRIVILEGES)；
- **低完整性**：TokenIntegrityLevel = SECURITY_MANDATORY_LOW_RID（S-1-16-4096），工作目录 icacls /setintegritylevel (OI)(CI)L；
  低完整性使写入受限（含 C:\Windows），但**读/执行不受限**（不防读取，只防破坏）；
- **Job Object**：内存/CPU/活动进程数上限 + JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE；Assign 失败即 fail-closed（绝不 Job 外执行）；
- **网络**：netsh advfirewall 按程序 block in/out，add 后 show 校验，失败 fail-closed，finally 清理；
- **兜底**：timeout_s+5s 硬杀线程（kill_tree + TerminateJobObject）+ 主等待全程 deadline + 根进程死亡校验；
- **隔离声明**写入 trace.sandbox.isolation（restricted_token / integrity:low / job_object / fw_block_* / ...），
  trace.extra.launch 记录根进程命令行，trace.extra.integrity 注明限制语义。

已知限制：按程序防火墙只覆盖被启动镜像（如 powershell.exe），其拉起的其他 exe 外联不在规则内；
低完整性不限制读取；本方案不是虚拟化隔离。

## 4. 红线（硬约束，不可绕过）

1. 本机只跑无害样本、EICAR（文本）与自写模拟行为脚本；不下载/不内置真实恶意样本。
2. 沙箱默认断网；断网失败 -> fail-closed，中止执行。
3. 所有执行必须有超时；超时/异常必须杀掉整个进程树。
4. 样本库只读、不可执行；引擎永不自动执行未授权路径。
5. 不采集与样本无关的用户数据；报告只输出分析所需信息。
6. 真实恶意样本评测需独立 VM 环境，本机不做。

## 5. 残余风险

| 风险 | 说明 | 缓解 |
|------|------|------|
| 逃逸 | 受限执行不是虚拟化隔离 | 低权 + 断网 + 超时；文档明示边界；未来 VM 后端 |
| 真实感染 | 断网/低权失败时样本可能真跑 | fail-closed；仅无害样本；执行前校验隔离生效 |
| 数据外泄 | 恶意样本主动外联 | 默认断网；连接表仅观测 |
| 行为伪造 | 样本可伪造事件误导检测 | 保真度分级；多源交叉；critical 需多证据 |
| 资源耗尽 | 样本占满内存/CPU | Job Object 限额 + 并发 1 |
| 报告泄露 | trace 含本地路径/用户信息 | 本地存储；导出时脱敏 |

## 6. 合规

- 不提供样本下载；不内置签名/病毒库。
- 上游 capa / capa-rules 为 Apache-2.0，导入规则保留头部与 NOTICE。
- 用户对自己的样本负责；工具仅做本地分析。
