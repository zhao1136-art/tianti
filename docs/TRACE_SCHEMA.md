# 行为轨迹契约：tianti.trace/1

> 本文件与 `tianti/trace/schema.py` 同步维护。**改字段必须先改这里，再 bump 版本。**

## 1. 定位

Trace 是引擎的中央契约：

```
L1 沙箱后端  --产出-->  Trace  --消费-->  L2 归一化/指标
                                --消费-->  L3 capa 规则匹配 / 危险行为检测
                                --消费-->  L4 评分判定 / 报告
```

只要 Trace 落盘，后面的所有分析都能离线（replay）完成。这是并行开发和 CI 的基础。

## 2. 顶层结构

| 字段 | 类型 | 说明 |
|------|------|------|
| `trace_id` | string | `YYYYMMDDThhmmssZ-xxxxxxxx`（UTC + 8 位随机 hex） |
| `schema` | string | 固定 `tianti.trace/1` |
| `created_at` | string | ISO-8601 带时区 |
| `sample` | object | `{name, sha256, size, type}`，sha256 为 64 位小写 hex |
| `engine` | object | `{version, backend, policy}` |
| `sandbox` | object | `{host, isolation[], limits{timeout_s,mem_mb,cpu_s,network}, started_at, ended_at, terminated_by}` |
| `events` | array | 行为事件，`ts` 必须非降序、`id` 全局唯一 |
| `summary` | object | 派生统计（事件计数、落地物、是否截断） |
| `extra` | object? | 后端附带信息（可选，消费方必须容忍缺失） |

## 3. 事件模型

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `id` | string | 是 | `e00001` 递增，同一次 trace 内稳定 |
| `ts` | number | 是 | 沙箱启动后的相对秒数（float，>= 0） |
| `category` | string | 是 | 见下表 |
| `action` | string | 是 | 见下表 |
| `pid` / `tid` / `ppid` | int? | 否 | 进程/线程号 |
| `image` | string? | 否 | 发起动作的镜像路径 |
| `target` | string? | 否 | 动作对象（文件路径、注册表键、域名:端口、目标进程等） |
| `args` | object | 否 | 动作参数（命令行、访问掩码、返回码等，必须 JSON 可序列化） |
| `source` | string | 是 | 数据来源，见 §5 |
| `confidence` | string | 是 | high / medium / low |

### 3.1 类别与动作

| category | action | 典型 target |
|----------|--------|-------------|
| process | create / exit / suspend / resume | 子进程镜像路径 |
| thread | create / remote_create / exit | 目标进程 |
| image | load / unload | DLL 路径 |
| file | create / write / read / delete / rename / set_attr / open | 文件路径 |
| registry | set / create / delete / query / rename | 注册表键路径 |
| network | connect / listen / dns / send / recv / close | `ip:port` / 域名 |
| service | create / start / config / delete | 服务名 |
| scheduled_task | create / run / delete | 任务名 |
| token | impersonate / elevate / adjust | 目标进程/用户 |
| memory | alloc / protect / map / write / free | 目标进程 |
| api | call | API 名（args.api） |
| security | amsi / etw / defender / other | 组件名 |

## 4. 示例

```json
{
  "trace_id": "20261024T103500Z-7f3a9c21",
  "schema": "tianti.trace/1",
  "created_at": "2026-10-24T10:35:00+08:00",
  "sample": {"name": "demo.ps1", "sha256": "0000000000000000000000000000000000000000000000000000000000000000", "size": 2048, "type": "script/powershell"},
  "engine": {"version": "0.1.0", "backend": "containment", "policy": "deep"},
  "sandbox": {
    "host": "WIN10-19045",
    "isolation": ["restricted_token", "job_object", "fw_block_out"],
    "limits": {"timeout_s": 20, "mem_mb": 512, "cpu_s": 10, "network": "blocked"},
    "started_at": "2026-10-24T10:35:00+08:00",
    "ended_at": "2026-10-24T10:35:12+08:00",
    "terminated_by": "exited"
  },
  "events": [
    {"id": "e00001", "ts": 0.31, "pid": 4120, "ppid": 4000,
     "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "category": "process", "action": "create",
     "target": "C:\\Windows\\System32\\cmd.exe",
     "args": {"command_line": "cmd.exe /c vssadmin delete shadows /all /quiet"},
     "source": "etw:process", "confidence": "high"}
  ],
  "summary": {"processes": 1, "file_writes": 0, "reg_sets": 0, "net_connects": 0,
              "dropped_files": [], "first_seen": 0.31, "event_count": 1,
              "dropped": 0, "truncated": false}
}
```

## 5. 来源与保真度

| source 前缀 | 来源 | 保真度 |
|-------------|------|--------|
| `api:` | hook/模拟后端抓到 API 调用 | high |
| `etw:` | ETW 内核/用户 provider | high |
| `snapshot:` | 前后快照 diff | medium |
| `poll:` | 轮询（进程树/连接表） | medium |
| `static:` | 静态推断 | low |
| `selftest:` | 自检 | — |

评分时按保真度加权；报告中必须显示结论依赖的来源。

## 6. 校验规则（validate_payload）

- `schema` 必须等于 `tianti.trace/1`
- `trace_id` 必须匹配正则
- `sample.sha256` 必须 64 位小写 hex；`size` 非负整数
- `events[].id` 非空且唯一；`events[].ts` 非负且**非降序**
- `events[].category` 必须在类别表内；`action` 必须在对应类别的动作表内
- `confidence` 属于 {high, medium, low}；`args` 必须是对象
- 顶层 `engine` / `sandbox` / `summary` 必须是对象

校验失败抛 `TraceError`（含全部错误列表）。`python -m tianti version --check` 会做一次 round-trip 自检。

## 7. 版本与兼容

- 新增可选字段：不 bump 版本（消费方需容忍未知字段）。
- 修改语义/必填/枚举：必须 bump 到 `tianti.trace/2` 并保留旧解析器一个版本。
- 解析入口：`tianti.trace.load / loads / validate_payload`。

## 8. 裁剪语义

- `max_events` 由策略决定（fast 5000 / deep 20000 / paranoid 50000）。
- 超限事件被丢弃并计数：`summary.dropped > 0` 时 `summary.truncated = true`。
- 规则/检测器必须能处理截断轨迹，报告需标注「轨迹被截断」。
