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
- `challenger_delta` 可用于守恒核算（posted/refunded/forfeited/open）

口径说明（Round11 热修统一）：
- `forfeited_total`（event/PR5）与 RPC `cumulative_forfeited` 同属**累计流量口径**，用于一致性校验。
- RPC `current_forfeits_balance` 属于**时点余额口径**（stock），可能因后续 burn/spend/划转而低于累计值，不作为 triad gate 的强约束。

## 3. 每日对账（聚合报表）

### 3.0 三方一致性闭环（event / PR5 / RPC treasury）

在仓库根目录执行：

```bash
./scripts/v2/pr5_event_rpc_treasury_consistency_gate.sh
```

该 gate 会：
- 基于 `event-field-check.log`（必要时自动生成）做事件侧解析
- 运行 `pr5_treasury_reconcile_report.sh` 生成 PR5 守恒结果
- 调用 `trnm-rpc query-challenge-treasury --limit 200 --json` 获取 treasury 视图
- 输出 `triad-consistency.txt`，并对以下不一致直接 FAIL：
  - PR5 非 PASS 或 `conservation.gap!=0`
  - event 与 PR5 记录数不一致
  - RPC treasury challenge/resolve 事件覆盖不足
  - RPC `cumulative_forfeited` 低于事件侧推导值（统一按“累计没收流量”口径比对）

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
- 增加资金守恒核算字段：
  - `conservation.posted_total`
  - `conservation.refunded_total`
  - `conservation.forfeited_total`
  - `conservation.open_bond_total`
  - `conservation.gap`（应为 `0`）
- 新增对 `treasury_delta` 语义校验（当前 MVP 规则）：`challenge/resolve` 事件中 `treasury_delta` 应为 `0`；非 0 记为异常并置 `status=FAIL`
- 当 `status=FAIL` 时脚本会返回非 0 退出码（默认阻断 CI / gate）

产物：
- `run/pr5-reconcile/<timestamp>/summary.txt`
- `run/pr5-reconcile/<timestamp>/reconcile.json`

可选参数：

```bash
SOURCE_LOG=trillionnium-rust/run/node1.log \
OUT_DIR=/tmp/pr5-reconcile \
./scripts/v2/pr5_treasury_reconcile_report.sh
```

兼容模式（仅应急）：

```bash
# status=FAIL 仍输出报表，但进程返回 0（不建议常态化）
PR5_RECONCILE_SOFT_FAIL=1 ./scripts/v2/pr5_treasury_reconcile_report.sh
```

## 4. 值班判定规则（建议）

- `summary.txt` 中 `status=PASS` 才视为“已出报表”
- `summary.txt` 中 `conservation.gap=0` 才视为“资金守恒一致”
- `summary.txt`/`conservation.detail.*` 出现 `nonzero treasury_delta` 视为高优先级数据语义异常
- 若 `conservation.detail_count>0` 或 `status=FAIL`：
  1. 优先处理 `conservation.detail.*` 首条错误
  2. 按 `task_id` 反查 challenge/resolve 对应关系
  3. 确认是否存在窗口截断（缺 challenge 或缺 resolve）
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

### 场景 C：RPC 异常重放（duplicate resolve/challenge replay）

- 现象：`query-challenge-treasury` 出现：
  - `anomaly.code=duplicate_event_replay`：同一 challenge treasury 事件被等价重放（通常同 `task_id` + `tx_id`）；
  - 或 `anomaly.code=resolve_without_posted_bond`：重复/乱序 `resolve` 未命中已挂账 bond。
- 判定：若 `current_forfeits_balance`/`cumulative_forfeited` 未重复增加，且 `daily_summary.forfeited/refunded` 未双计，可判定为重放噪声而非资金异常。
- triad gate 语义：
  - `duplicate_event_replay` / `resolve_without_posted_bond` 被归类为已知异常码，仅记录在 `detail.*` 与 `rpc.anomaly_*` 字段，不单独触发 FAIL；
  - 未知 `anomaly.code` 视为语义漂移，triad gate 直接 FAIL（需人工确认是否新版本语义变更）。
- 处理：
  1. 以首次有效事件为准，按 `task_id` + `tx_id` 回查 node 日志确认重复来源
  2. 保留 anomaly 证据（`run/pr5-reconcile/*/rpc-challenge-treasury.json`）供后续 RPC 去重修复
  3. 若发现余额或计数被双计，升级为 P1 并阻断 triad gate

## Red Team 复验命令

```bash
cd /Users/qianqi/.openclaw/workspace/TrillionniumChain
./scripts/v2/pr5_reconcile_conservation_test.sh
./scripts/v2/pr5_event_rpc_treasury_consistency_test.sh
./scripts/v2/pr5_event_rpc_treasury_consistency_gate.sh
```

## 6. 验收清单（PR-5）

- [ ] `query-events` 可稳定查询 challenge/resolve 审计字段
- [ ] 对账脚本可生成 `summary.txt` + `reconcile.json`
- [ ] 汇总项包含 posted/forfeited/refunded 与 delta 累计
- [ ] 守恒核算字段完整（`conservation.*`）且 `conservation.gap=0`
- [ ] 日志缺失时脚本给出可执行提示（SKIP + hint）
