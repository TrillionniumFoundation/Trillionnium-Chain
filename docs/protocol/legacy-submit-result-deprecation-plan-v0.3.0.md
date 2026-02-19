# Legacy `submit-result` 下线计划（v0.3.0）

更新日期：2026-02-19  
目标：在可回滚、可观测前提下，将 `allow_legacy_submit_result` 从 `true` 平滑切换到 `false`。

---

## 1) 背景

当前链仍保留 legacy `submit-result` 兼容入口（`allow_legacy_submit_result=true`），用于历史调用平稳过渡。  
为收口协议语义并降低双路径维护成本，需完成下线。

---

## 2) 三阶段切换策略

## Phase A — Announce（公告期，1天）

- 参数：保持 `allow_legacy_submit_result=true`
- 动作：
  - 发布治理提案草案与切换窗口
  - 对外明确迁移目标接口（commit/reveal）
  - 每日输出 legacy 调用观测报表（次数、来源、失败率）
- 进入下一阶段门槛：
  - 连续 24h 无新增高风险告警

## Phase B — Canary（灰度期，半天~1天）

- 参数：仍为 `true`，但按灰度规则对新任务默认走 v1 路径
- 动作：
  - 执行 P0/P1 gate（至少 1 轮）
  - 跑升级演练 checklist 并归档 run 证据
  - 监控 legacy 调用占比是否持续下降
- 进入下一阶段门槛：
  - P0/P1 gate: `fail=0 && skip=0`
  - 关键路径错误率低于阈值（见第 4 节）

## Phase C — Full Disable（正式下线）

- 参数：`allow_legacy_submit_result=false`
- 动作：
  - 在治理提案通过后执行参数切换
  - 升级后立即复跑 P0/P1 gate
  - 对外发布“legacy 已关闭”的版本公告
- 稳定观察窗口：
  - 至少 2~4 小时持续监控

---

## 3) 治理提案建议字段

- 提案类型：`Software Upgrade + Parameter Update`
- 目标参数：

```json
{
  "allow_legacy_submit_result": false
}
```

- 必附证据：
  1. `data/upgrade-runs/<ts>/` 演练目录
  2. `data/p0-acceptance/<ts>/summary.json`
  3. `data/p1-negative/<ts>/summary.json`
  4. 回滚演练记录

---

## 4) 回滚阈值（硬条件）

满足任一即触发回滚：

1. 出块异常：5 分钟内无法稳定出块；
2. 查询异常：`params/task/challenge` 任一关键查询不可用；
3. 回归失败：P0/P1 任一 gate 失败；
4. 错误率阈值：
   - 关键交易路径失败率 > 2%（5 分钟滑窗）；
   - challenge/resolve 异常率 > 1%（5 分钟滑窗）。

---

## 5) 执行检查单（下线日）

- [ ] 确认治理提案通过
- [ ] 执行参数切换交易
- [ ] 记录切换区块高度
- [ ] 运行 `./scripts/p0_merge_gate.sh`
- [ ] 运行 `./scripts/p1_negative_suite.sh`
- [ ] 归档产物路径到 `STATUS.md`
- [ ] 观察窗口结束后发布结论（GO / ROLLBACK）

---

## 6) 结论

建议按“三阶段 + 硬阈值回滚”推进。  
先证明可观测与可回滚，再做最终关闭，避免一次性切换带来的不可控风险。
