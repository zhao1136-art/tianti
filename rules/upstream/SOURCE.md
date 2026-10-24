# 上游 capa-rules 规则包（可选）

- 来源：`H:\capa-rules-master`
- 上游项目：mandiant/capa-rules（Apache-2.0）
- 导入时间：2026-10-24T14:26:14+08:00
- 上游 commit：unknown
- 导入规则数：625（分类 ok）
- 分类统计：ok=625 / unsupported=429 / error=0 / non_rule=0
- 规则 scope 分布：{"call": 214, "file": 93, "process": 1, "span": 317}

## 说明
- 本目录由 `tools/import_capa_rules.py` 生成，默认不参与规则匹配（`include_upstream=false`）。
- 官方规则为 Apache-2.0，原始文件内容与版权头保持不变，见 LICENSE.txt。
- 上游 `meta.scopes.dynamic` 已映射为本引擎 scope：span of calls→span、call、file、process；
  dynamic=unsupported 与仅静态可匹配的规则未导入。
- match 引用因依赖规则未导入时，加载阶段会跳过引用方并计入 RuleSet.unsupported。
