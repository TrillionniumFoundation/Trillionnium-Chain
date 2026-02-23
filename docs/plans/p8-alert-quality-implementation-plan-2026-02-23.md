# P8 实施计划：告警质量提升（2026-02-23）

## 决策默认值（本次先按此执行）
- 主通道：iMessage（保留 Slack/Telegram 作为后备）
- 自动保护动作：仅 dry-run（不改线上参数）

## 目标
把现有 PR6/PR7 的“可告警”升级为“低噪声、可追溯、可恢复”。

---

## Issue P8-1：告警分级与抑噪
**Owner:** Ops/Alerting  
**预估工时:** 0.5-1 天

### 范围
- `scripts/v2/pr7_alert_delivery.py`
- `scripts/v2/pr7_alert_delivery_gate.sh`

### 任务
- [ ] 增加级别：`INFO | WARN | CRITICAL`
- [ ] 同类告警聚合（窗口内合并成一条）
- [ ] 冷却时间（cooldown）支持按级别配置

### 验收
- [ ] 连续同类 WARN 在窗口内仅发 1 条
- [ ] CRITICAL 可绕过部分抑噪规则（但仍去重）

---

## Issue P8-2：通知可靠性（重试+死信）
**Owner:** Ops/Runtime  
**预估工时:** 1 天

### 范围
- `scripts/v2/pr7_alert_delivery.py`
- `run/pr7-alert-delivery/`（状态落盘）

### 任务
- [ ] 发送失败重试（指数退避）
- [ ] 超过重试次数写入 dead-letter
- [ ] 增加 dead-letter 重放脚本

### 验收
- [ ] 模拟发送失败后，dead-letter 可见
- [ ] 重放后可成功补发并清理 dead-letter

---

## Issue P8-3：告警可观测性
**Owner:** Observability  
**预估工时:** 0.5 天

### 范围
- `scripts/v2/pr6_daily_security_summary.py`
- `docs/runbooks/pr7-alert-delivery.md`

### 任务
- [ ] 每日摘要增加 `alerts_sent/alerts_suppressed/alerts_failed` 计数
- [ ] 增加最近一次发送状态与失败原因

### 验收
- [ ] daily summary 可直接看见告警成功率

---

## Issue P8-4：回归门禁
**Owner:** CI/Gates  
**预估工时:** 0.5 天

### 范围
- `.github/workflows/rust-l1-nightly-health.yml`
- `scripts/v2/*gate*.sh`

### 任务
- [ ] 增加 PR7 发送逻辑 dry-run 回归步骤（非阻断）
- [ ] 增加 dead-letter 为空检查（阻断可选）

### 验收
- [ ] nightly 产物包含 alert-delivery 统计文件

---

## 里程碑与顺序
1. P8-1（降噪）
2. P8-2（可靠性）
3. P8-3（可观测）
4. P8-4（门禁）

目标完成标志：
- iMessage 告警 24h 内无重复轰炸
- 发送失败可恢复且有审计轨迹
- daily summary 可直接用于值班判断
