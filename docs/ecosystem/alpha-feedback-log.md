# Ecosystem Alpha Feedback Log (C3)

更新时间：2026-02-21

> 用于结构化记录外部开发者反馈，确保可复现、可分级、可追踪。

## 字段规范
- `feedback_id`: 唯一编号（例如 ALPHA-0001）
- `source`: 反馈来源（dev handle / org）
- `component`: 影响模块（rpc / sdk / docs / node / governance）
- `severity`: `S0|S1|S2|S3`
- `repro_steps`: 复现步骤（可执行）
- `expected`: 期望行为
- `actual`: 实际行为
- `status`: `open|triaged|in_progress|fixed|closed`
- `owner`: 负责人
- `linked_issue`: 对应 issue/commit/PR
- `updated_at`: 更新时间

---

## Entries

### ALPHA-0001
- source: internal-smoke
- component: docs
- severity: S3
- repro_steps: run `scripts/v2/ecosystem_examples_smoke.sh`
- expected: all example commands executable
- actual: pass
- status: closed
- owner: core
- linked_issue: `4a4ddf1`
- updated_at: 2026-02-21

### ALPHA-0002
- source: dev-partner
- component: rpc
- severity: S2
- repro_steps: TODO
- expected: TODO
- actual: TODO
- status: open
- owner: core
- linked_issue: TBD
- updated_at: 2026-02-21
