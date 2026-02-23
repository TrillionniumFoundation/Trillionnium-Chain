# PR-5 Runbook：Challenge Treasury / Forfeits 查询与对账

> 目标：给运维一个“可执行、可审计、可留痕”的最小流程，覆盖 **查询** + **每日对账**。

## 0. 适用范围

- 代码范围：Rust L1 + PoUW challenge 经济字段
- 关键字段：
  - `treasury_delta`
  - `challenger_delta`
  - `bond_disposition`（`posted` / `forfeited` / `refunded`）
  - `resolution_code`

## 1. 前置条件

- 已有可查询的事件日志（建议先跑过 PR-4 gate 或 event field check）
- 本地具备 `python3`
- 工作目录为仓库根目录

可快速准备样本日志：

```bash
cd trillionnium-rust
MVP_MODE=prod ALLOW_MISSING_RESOLVE_EVENT=0 ./scripts/check_event_fields.sh
cd ..
```

## 2. 快速查询（按 Task）

在 `trillionnium-rust/` 下执行：

```bash
cargo run -q -p trnm-rpc -- query-events --task-id <TASK_ID> --limit 100
```

判定要点：
- 至少能看到 `challenge` 与对应 `resolve`
- `resolve` 中出现 `bond_disposition`
- 字段可用于审计追溯（`tx_hash`、`resolution_code`、`challenger`）

## 3. 每日对账（聚合报表）

在仓库根目录执行：

```bash
./scripts/v2/pr5_treasury_reconcile_report.sh
```

默认行为：
- 自动发现日志源（`event-field-check.log` → `parallel-sanity.log` → `node*.log`）
- 聚合 `challenge/resolve` 事件
- 按 UTC 日汇总：
  - `challenge_events`
  - `resolve_events`
  - `posted/forfeited/refunded` 计数
  - `treasury_delta_sum`
  - `challenger_delta_sum`

产物：
- `run/pr5-reconcile/<timestamp>/summary.txt`
- `run/pr5-reconcile/<timestamp>/reconcile.json`

可选参数：

```bash
SOURCE_LOG=trillionnium-rust/run/node1.log \
OUT_DIR=/tmp/pr5-reconcile \
./scripts/v2/pr5_treasury_reconcile_report.sh
```

## 4. 值班判定规则（建议）

- `summary.txt` 中 `status=PASS` 才视为“已出报表”
- 若 `forfeited_count`/`refunded_count` 异常突增：
  1. 抽样 `task_id` 回查 `query-events`
  2. 对比 `resolution_code` 是否集中在单一失败原因
  3. 关联 `run/node*.log` 判断是否系统性故障

## 5. 故障处理

### 场景 A：`status=SKIP` 且提示 no_event_log_found

- 说明：当前运行目录没有可用事件日志
- 处理：
  1. 先运行 event-field check 或相关 gate 产生日志
  2. 或通过 `SOURCE_LOG` 指定已有日志路径

### 场景 B：有 challenge 无 resolve

- 说明：可能任务尚未进入终态，或日志窗口不完整
- 处理：
  1. 拉大查询窗口（`--limit`）
  2. 在 node 日志中按 `task_id` 搜索全链路

## 6. 验收清单（PR-5）

- [ ] `query-events` 可稳定查询 challenge/resolve 审计字段
- [ ] 对账脚本可生成 `summary.txt` + `reconcile.json`
- [ ] 汇总项包含 posted/forfeited/refunded 与 delta 累计
- [ ] 日志缺失时脚本给出可执行提示（SKIP + hint）
