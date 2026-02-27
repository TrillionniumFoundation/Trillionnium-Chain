# M1 运行稳定性清单（Run Stability）

## 目标
任何失败都可定位、可复现、可审计。

## 必做项
- [ ] 统一退出码：`EXIT_CODE + reason + stage + run_tag`
- [ ] 关键脚本统一启用：`set -euo pipefail`
- [ ] 关键脚本统一错误钩子：`trap 'on_err ...' ERR`
- [ ] 失败时落盘：
  - [ ] stdout/stderr tail（最近 200 行）
  - [ ] 参数快照（配置文件 + hash）
  - [ ] 输入指纹（文件 hash / 数据版本）
  - [ ] 关键上下文（task_id, symbol, strategy_id, time range）
- [ ] 统一失败产物目录：`run/failures/<run_tag>/`
- [ ] 错误分类字典（临时可 json）：`infra|data|logic|contract|timeout|rate_limit`

## 验收标准
- [ ] 任意一个故意注入错误，能在 2 分钟内定位到 stage + reason。
- [ ] 同一错误重复触发，产物结构一致。

## 建议门禁命令
```bash
# 示例：注入失败并验证落盘
./scripts/v2/inject_failure_smoke.sh
./scripts/v2/check_failure_artifacts.sh
```
