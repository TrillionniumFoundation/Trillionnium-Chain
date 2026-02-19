# Legacy Submit Observability Spec (Draft)

更新日期：2026-02-19  
状态：Draft

## 1. 目的

在 P3 硬退役前，用可审计数据证明 legacy `SubmitResult` 真实使用情况，支撑删除决策。

## 2. 观测对象

- 入口：`MsgSubmitResult`（legacy path）
- 维度：调用次数、成功/失败、失败原因、调用账户、区块高度区间

## 3. 事件与字段规范（建议）

新增或统一事件：`workload_legacy_submit_observe`

字段建议：
- `task_id`
- `worker`
- `height`
- `tx_hash`
- `result`：`accepted | rejected`
- `reason`：
  - `legacy_disabled`
  - `invalid_state_transition`
  - `unauthorized_worker`
  - `other`

> 说明：若不希望新增事件类型，也可在现有 `workload_submit_result` 事件上扩展字段并保持兼容。

## 4. 指标口径

按天输出：
- `legacy_submit_total`
- `legacy_submit_accepted`
- `legacy_submit_rejected`
- `legacy_submit_rejected_by_reason{reason=*}`
- `distinct_workers_legacy_submit`

## 5. 日报模板

```text
Date: YYYY-MM-DD
Env: <testnet|staging>
Window: [start_height, end_height]

legacy_submit_total: X
legacy_submit_accepted: A
legacy_submit_rejected: R
rejected_breakdown:
  - legacy_disabled: n1
  - invalid_state_transition: n2
  - unauthorized_worker: n3
  - other: n4
distinct_workers_legacy_submit: W

Decision hint:
- If total==0 for >=14 days in all target envs, P3 delete gate can be opened.
```

## 6. 数据归档

建议目录：
- `data/observability/legacy-submit/YYYY-MM-DD.txt`
- `data/observability/legacy-submit/weekly-summary-YYYY-WW.md`

生成脚本（新增）：
- `scripts/legacy_submit_daily_report.sh`

示例：
```bash
bash scripts/legacy_submit_daily_report.sh
# 或
DATE_TAG=2026-02-19 OUT_DIR=data/observability/legacy-submit bash scripts/legacy_submit_daily_report.sh
```

## 7. 删除门槛建议（与 P3 对齐）

- 连续 14 天 `legacy_submit_total == 0`
- 发布渠道已完成迁移通知
- P0/P1 在删除分支持续绿

## 8. 非目标

- 本文不定义链外日志采集基础设施（ELK/Prometheus）实现细节
- 本文不替代升级公告模板