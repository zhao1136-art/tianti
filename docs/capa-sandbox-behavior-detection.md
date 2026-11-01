# 用 capa 规则做沙箱行为检测：不靠特征码，只看程序「跑起来做了什么」

> 天体引擎 / TianTi —— 一个开源的沙箱行为分析型检测引擎
> 代码：https://github.com/zhao1136-art/tianti

---

## 一、先说为什么要绕开特征码

做静态查杀最痛苦的不是写规则，是**特征码天生追不上变种**。

一个家族出一百个样本，改字符串、加壳、换编译器、混淆控制流，特征码就得跟着出一百条。更别提现在常见的做法：直接从 GitHub 拉个开源 C2、用合法的系统工具执行恶意动作（LOLBin），文件本身干干净净，一行可疑代码都没有。

所以换个角度：**不看文件长得像什么，只看它跑起来做了什么。**

比如勒索软件，不管你用什么语言写、加几层壳，最终都要：

- 遍历文件系统
- 打开一批文件写入
- 删除卷影副本（`vssadmin` / `wmic shadowcopy`）

这些动作在沙箱里是观测得到的，而且**跟样本怎么混淆无关**。这就是行为检测的价值。

## 二、为什么选 capa 的规则格式

[capa](https://github.com/mandiant/capa) 是 Mandiant 开源的能力识别工具。它的核心不是引擎，是**那几千条 YAML 规则** —— 每条规则描述一个「能力」，并且挂上 MITRE ATT&CK 战术编号。

规则长这样（我仓库里自写的一条，真实的）：

```yaml
rule:
  meta:
    name: '生成压缩包文件'
    namespace: 'collection/staging/archive-file'
    scope: 'process'
    authors: [tianti]
    description: '落地 zip/rar/7z 压缩包用于暂存或外传'
    att&ck:
      - 'Collection::Archive Collected Data [T1560]'
  features:
    - or:
      - file write: '*.zip'
      - file write: '*.rar'
      - file write: '*.7z'
      - file create: '*.zip'
```

选它的理由很实在：

- **规则是数据不是代码** —— 加检测能力不用改引擎，加 YAML 就行
- **自带 ATT&CK 映射** —— 可以直接用战术编号给分数加权，不用另建一套分类
- **有几千条现成规则** —— Mandiant 维护的 capa-rules，Apache-2.0，能直接用
- **社区在维护** —— 新手法出现，上游会跟进

## 三、真正的难点：capa 原本吃什么，沙箱能喂什么

这里是最花时间的地方，也是最容易低估的地方。

**capa 原生有两种输入：**

- PE 文件的静态特征（导入表、字符串、section 属性……）
- CAPE 沙箱生成的 JSON 报告（API 调用序列）

**而我的沙箱只有 Trace。** 一个自己定义的、归一化过的事件流：进程创建、文件写入、注册表操作、网络连接、内存保护变更……

也就是说，**我得自己写一个兼容 capa 语法的规则引擎**，把规则里的 feature 翻译成对 Trace 的查询。

规则里的 `scope` 决定了匹配的时间窗口，这个很关键：

| scope | 匹配窗口 | 适用场景 |
|---|---|---|
| `process` | 整个进程生命周期 | 「这个进程做过什么」（最常用） |
| `thread` | 单线程 | 线程级行为 |
| `call` | 单次调用 | API 级特征 |
| `span` | 指定时间跨度 | 「几秒内连续发生」 |
| `file` | 单个文件对象 | 文件级特征 |

还有一些 capa 语法必须实现：`or` / `and` / `optional` / `count()` / `string` 正则 / `2 or more` 这种组合计数。YAML 只用一个子集，所以我写了个轻量解析器 —— **这是后文会提到的技术债**。

## 四、光有规则不够，还要有「危险行为检测器」

capa 规则描述的是**「具备什么能力」**，但「能力」不等于「恶意」。

`Archive Collected Data` 这条规则，勒索软件会命中，你装个 WinRAR 也会命中。所以还需要一层：检测器判断这个能力**在这个上下文里是不是危险**。

我写了 26 个检测器，每个带严重度和分数。举个例子（真实的 `amsi_etw_patch.yml`）：

```yaml
# 防御规避：AMSI/ETW 打补丁（critical）
detector: amsi_etw_patch
name: AMSI/ETW 绕过或打补丁
tactic: TA0005
technique: T1562.001
severity: critical
score: 25
match:
  any:
    - category: security
      action: [amsi, etw]
    - category: api
      action: call
      arg:
        api: ['AmsiScanBuffer', 'AmsiOpenSession', 'EtwEventWrite', 'NtTraceEvent', 'EtwEventWriteFull']
    - category: memory
      action: protect
      target: ['*amsi*', '*ntdll*']
      arg:
        protect: '*EXECUTE_READWRITE*'
evidence: events
```

这条的意思是：有程序去调 `AmsiScanBuffer` / 给 ntdll 里的代码段改成可写可执行 —— 正常软件不会这么干。

## 五、评分：怎么把「一堆命中」变成一个结论

这部分我调了很久，因为最怕的是**规则一多分数就爆**，随便什么程序都能攒够分。

最终的分数字段：

```
score = Σ capability（按 ATT&CK 战术权重，同战术递减）
      + Σ detector.score × 抑制系数
      + Σ static.signal.score
```

### ① capability（capa 规则命中）按战术加权

| 战术 | 权重 |
|---|---|
| TA0040（影响／破坏） | 20 |
| TA0004 提权 / TA0006 凭证 / TA0008 横向 / TA0011 C2 | 15 |
| TA0003 持久化 | 10 |
| TA0002 执行 / TA0005 防御规避 / TA0009 收集 | 8 |
| TA0001 初始访问 | 6 |
| TA0007 发现 | 5 |
| 无战术命中 | 4 |

**关键是同战术递减**：第 2 条 ×0.65，第 3 条起 ×0.30（下限 0.25）。

为什么这么做 —— 一个样本如果命中 10 条「收集」类规则，那是同一个行为做了 10 遍，**不该给 10 倍分**。但也不能给 0，所以设个下限。这样分数单调，且不会因为规则多而爆炸。

### ② detector（检测器）带自己的分数

严重度映射：critical 25–40、high 15–20、medium 5–10。

### ③ static（静态信号）只加分不扣分

low=2 / medium=5 / high=10 / critical=20。

### ④ 抑制：白名单不是「一律放行」

| 触发条件 | 系数 | 说明 |
|---|---|---|
| 样本**自己**的路径/哈希命中白名单 | 0.0 | 完全抑制 |
| 事件的 target/image 命中可信路径 | 0.5 | 只降权，不归零 |
| 检测器 YAML 里配置的可信目录 | 0.25 | 同上 |
| critical 检测器 | ≥0.5 | critical 永不完全抑制（最多降 50%） |

**默认白名单是空的。** 这条我特意写进了文档：

> 不要把 `C:\Windows\` 当默认可信路径 —— `cmd.exe` / `powershell.exe` 往往是样本的「工具」而不是「可信来源」。

被抑制的命中仍然保留在结果里（标 `suppressed=true` 并给出原因），**可解释性不能丢** —— 用户得能看到「我知道这个动作，但我选择不报」。

## 六、实测数据（都在这台机器上跑出来的）

| 项目 | 数字 |
|---|---|
| 自写能力规则 | 46 条（+ 8 条 ATT&CK 专用规则） |
| 上游 capa 规则 | 625 个 YAML 文件，实际加载 493 条 |
| 危险行为检测器 | 26 个 |
| 10k 规则匹配耗时 | 约 591 ms |

## 七、踩过的坑（这部分大概比正文更有用）

### 坑 1：625 个规则文件，只加载了 493 条

剩下 132 条被剪枝了 —— 因为它们依赖的规则没导入。capa 规则之间可以互相引用（一条规则的条件可以是「命中另一条规则」），上游有依赖关系网，你只拷一部分就会断链。

### 坑 2：大量规则依赖 API 级轨迹，而我的沙箱默认没有 API hook

这是最尴尬的一个。capa 规则里很多条件写着 `api: CreateRemoteThread` 这种东西，那是 API 级别的观测。而我的 containment 沙箱默认**不做 API hook**（性能考虑），只有 ETW 采到的事件。

结果就是：这批规则**能加载、能编译、但永远不会命中**。

目前的办法是用 CAPE 报告回放，或者后续做 emulation 后端。这是明确的能力缺口，我写进已知限制了。

### 坑 3：string 特征线性扫描，性能不达标

10k 条规则 591 ms，目标是 300 ms。原因很直白 —— string 特征是逐个线性扫的，没有倒排索引。要再快得上词级倒排，还没做。

### 坑 4：YAML 子集解析器写了两份

`tianti/rules/yamlmini.py` 和 `tianti/detect/yamlmini.py` —— 同样是技术债，改语法得改两处。

### 坑 5（最坑）：DLL 动态加载会让 explorer 崩溃

本来想支持 rundll32/regsvr32 调用 DLL 导出函数。结果是：用任意导出函数调 DLL 会崩，实测伴随 explorer 崩溃循环。

最后的处理：代码留着，但**明确排除在 pipeline 之外**（`dynamically_executable` 直接判否）。宁可不支持，也不能让用户桌面崩。

## 八、和真正的杀软比，差在哪

诚实说：

- **沙箱不是真隔离** —— `engine: copy` 只隔离样本自身及同目录，样本里写死的 `C:\Windows\...` 绝对路径照样打到真实系统
- **没有驱动层** —— 纯用户态，绕过 ETW 的手法（直接系统调用）看不到
- **不是实时的** —— 这是「拿一个文件来，跑一遍，给结论」，不是实时防护
- **结论不构成安全保证** —— 行为分析有天然误报，尤其遇到安装包、系统工具

所以它的定位很明确：**沙箱分析/取证辅助工具**，不是拿来替代 Windows Defender 的。

## 九、项目地址

**https://github.com/zhao1136-art/tianti**

- Python 3.10+，纯本地运行，样本不出网
- 沙箱默认断网、限时、强杀
- 只内置无害样本（EICAR 文本 + 自写模拟行为脚本），**不内置也不下载真实恶意样本**
- 许可：**禁止商业使用**（PolyForm Noncommercial 1.0.0）。上游 capa 规则仍为 Apache-2.0

## 十、最后

这个项目的意义不是「做出一个能用的杀软」—— 那需要团队、需要驱动、需要证书，个人做不出来。

它的意义是**把「行为检测到底能做多少、做不到什么」这个问题摊开来看**：规则怎么写、分数怎么算、什么情况下会漏、为什么会漏。

上面那些坑，包括我还没解决的（API 级轨迹缺失、性能不达标、DLL 加载崩溃），都写在 README 的「已知限制」和「技术债」里，没有藏。

欢迎拍砖，也欢迎指路：**如果你知道怎么在无 API hook 的前提下让那 132 条规则生效，非常想听。**
