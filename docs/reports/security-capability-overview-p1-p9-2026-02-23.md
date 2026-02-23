# TRNM Security Capability Overview (P1–P9) — 2026-02-23

## 当前状态
- 主分支：`main`
- 安全能力阶段：**P1–P9 已完成并落地**
- 运行形态：协议防护 + 运营可观测 + 告警治理 + 周报机制

---

## P1–P9 能力地图

### P1：参数与接口基线硬化
- 治理参数 value schema（严格类型/范围）
- RPC 高成本查询 hard cap
- strict real-cli 真实性门禁

### P2：PoUW 生命周期硬化
- deadline/timeout 状态迁移
- challenge 最小押金约束
- timeout/bond 门禁脚本

### P3：执行与审计闭环
- node 自动 timeout 扫描（可开关）
- 事件审计字段统一（node/rpc 对齐）
- challenge 经济最小闭环（可验证）

### P4：资金流可审计化
- challenge escrow / forfeits 资金路径
- RPC 经济审计字段扩展
- fundflow gate + runbook

### P5：运营查询与对账
- challenge treasury 运营查询入口
- 日对账脚本 + nightly 非阻断接入
- 对账 runbook

### P6：日报化运营视图
- daily security summary 自动产出
- workflow summary + artifact 输出

### P7：告警通知与异常摘要
- 告警投递（含 iMessage 通道）
- 7天阈值建议器
- TopN 异常摘要与 gate

### P8：告警质量提升
- INFO/WARN/CRITICAL 分级
- exact/class dedup + 聚合 + 分级 cooldown
- 失败重试 + dead-letter + replay
- daily summary 增加发送统计与最近状态

### P9：告警治理与周报
- 阈值建议转可应用 env（dry-run）
- quiet-hours + WARN 升级治理策略
- weekly alert governance 报告（nightly 非阻断）

---

## 当前关键脚本（值班常用）
- `scripts/v2/pr6_alert_rules_gate.sh`
- `scripts/v2/pr7_alert_delivery_gate.sh`
- `scripts/v2/pr7_topn_summary_gate.sh`
- `scripts/v2/pr7_threshold_advisor.py`
- `scripts/v2/pr9_apply_thresholds_dry_run.sh`
- `scripts/v2/pr9_weekly_alert_governance.py`

---

## 关键产物路径
- 日报：`run/pr6-ops/daily-security-summary.md`
- TopN：`run/pr7-topn/*/topn-anomaly-summary.md`
- 阈值建议：`run/pr7-threshold-advisor/*/threshold-advice.{json,md}`
- 告警状态：`run/pr7-alert-delivery/state.json`
- 周报：`run/pr9/weekly-alert-governance.md`

---

## 建议下一阶段（P10）
1. 告警策略治理化（配置版本化 + 审批流）
2. 多通道告警路由策略（主/备 + 升级通知）
3. 周报自动差异分析（与上周阈值/异常对比）
