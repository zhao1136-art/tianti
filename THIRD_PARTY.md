# 第三方组件与许可

## capa-rules（Mandiant 官方规则库）

- 来源：本地镜像 `H:\capa-rules-master`（github.com/mandiant/capa-rules，master 分支）
- 许可证：**Apache License 2.0**，完整文本随包保留在 `rules/upstream/LICENSE.txt`
- 实际入库：625 条可解析的动态作用域规则（`rules/upstream/`，约 0.9MB）；加载 547 条（54 自研 + 493 上游，132 条因依赖剪枝）。
- 使用方式：`tools/import_capa_rules.py` 扫描上游规则，只导入动态作用域可映射的规则到 `rules/upstream/`；
  默认**不加载**（保持 54 条自研规则基线），需要时用 `--include-upstream` 或 `config/engine.json` 的 `rules.include_upstream=true` 启用。
- 引擎侧适配：`meta.scopes.dynamic` 映射到本引擎作用域（`span of calls`→`span`、`call`→`call`、`file`→`file`、`process`→`process`），
  不支持的静态特征（section/bytes/characteristic/instruction/mnemonic 等）会被过滤并记录在导入报告中。
- 修改说明：导入过程不修改规则语义与文件内容；仅按可解析性筛选。规则文件名、命名空间、ATT&CK/MBC 元数据保持原样。
- 溯源：`rules/upstream/SOURCE.md` 记录来源路径、导入时间、规则数量；本文件记录许可与使用方式。

## flare-capa（仅测试期差分 oracle，未随包分发）

- 用途：开发期差分测试参考（`pip download flare-capa` 得到 wheel），**不进入运行时依赖**。
- 许可证：Apache License 2.0。

## 其他

- 本项目其余代码为自研，Python 标准库之外无运行时第三方依赖。
