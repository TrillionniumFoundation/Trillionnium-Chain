# Operations（Agent↔User Phase A 补充）

> 适用范围：`trillionnium/crates/trnm-rpc` Phase A 可靠性与 relay 语义。

## 新增参数

### 1) 批量 ACK（relay）

`RelayAckRequest` 新增：

- `upto_seq: Option<u64>`：按 session 内消息序号做“前缀批量 ACK”（`sequence <= upto_seq` 全部确认）。
- `envelope_ids: Vec<u64>` 仍保留，兼容单条/批量按 ID ACK。

建议：
- 实时消费端优先用 `upto_seq`，可减少 ACK 请求数量与去重复杂度。
- 对跨会话 ACK 无效（仅作用于当前 `session_id`）。

### 2) Retry 熔断（reliability）

`RetryConfig` 参数：

- `base_backoff_ms`：重试基础退避
- `max_backoff_ms`：重试退避上限
- `max_attempts`：单消息最大重试次数（超限后丢弃 pending）
- `circuit_breaker_threshold`：触发熔断阈值（连续失败计数）
- `circuit_open_ms`：熔断打开窗口（窗口内暂停重试发放）

## 排障方法

### A. ACK 批量异常

现象：`poll` 仍返回已处理消息。

排查：
1. 确认 ACK 请求 `session_id` 与消息一致。
2. 使用 `upto_seq` 时，确认阈值序号覆盖到目标消息（`sequence <= upto_seq`）。
3. 混用 `envelope_ids` 与 `upto_seq` 时，以服务端返回 `acked` 数量核对预期。

### B. Retry 无重放 / 重试突然停止

现象：`collect_due_retries` 返回空，但存在 pending。

排查：
1. 检查是否触发熔断窗口（circuit open）。
2. 检查是否达到 `max_attempts`（达到后 pending 会被清理）。
3. 核对当前时间戳与 `next_retry_at_unix_ms`、`circuit_open_ms`。

## 持久化 store（生产默认）

Phase A gate 默认使用 sqlite 持久化 reliability store（用于重启后去重 smoke）：

- `RELIABILITY_STORE`：`sqlite`（默认）或 `memory`（显式兼容模式）
- `RELIABILITY_DB_PATH`：sqlite DB 路径覆盖项；未设置时默认顺序为：`$XDG_STATE_HOME/trillionnium/reliability.sqlite` → `$HOME/.trillionnium/reliability.sqlite` → `run/reliability/reliability.sqlite`

示例：

```bash
cd trillionnium
RELIABILITY_STORE=sqlite \
RELIABILITY_DB_PATH=run/health/reliability-phasea.sqlite \
./scripts/run_agent_user_phasea_gate.sh
```

排障：
- 现象：sqlite smoke 未执行
  - 检查是否显式设置了 `RELIABILITY_STORE=memory`（该模式下会跳过 sqlite smoke）
- 现象：报错 `expected sqlite db created`
  - 检查 `RELIABILITY_DB_PATH`（若设置）目录是否可写
  - 检查 gate 报告里是否出现 `reliability_db_path=...`

## Soak SLO 门禁（Phase A）

新增脚本：`trillionnium/scripts/run_phasea_soak_gate.sh`

用途：读取 soak / fault 报告并按阈值做自动判定，默认阈值：

- `COMMIT_QUEUED >= 99%`
- `proof_verify_fail = 0`
- `store_rejected <= 0`（可配）
- `retry_exhausted <= 0`（可配）

默认输入文件（可被环境变量覆盖）：

- `SOAK_RESULT`：默认优先匹配 `run/health/phasea-soak-*`，其次 `run/health/*phasea*soak*`
- `FAULT_RESULT`：默认优先匹配 `run/health/request-fault-injection-*`

阈值环境变量：

- `MIN_COMMIT_QUEUED_PCT`（默认 `99`）
- `MAX_PROOF_VERIFY_FAIL`（默认 `0`）
- `MAX_STORE_REJECTED`（默认 `0`）
- `MAX_RETRY_EXHAUSTED`（默认 `0`）

输出：`run/health/phasea-soak-gate-<timestamp>.txt`

示例：

```bash
cd trillionnium
SOAK_RESULT=run/health/phasea-soak-20260222-200000.txt \
FAULT_RESULT=run/health/request-fault-injection-20260222-200010.txt \
MAX_STORE_REJECTED=2 \
MAX_RETRY_EXHAUSTED=1 \
./scripts/run_phasea_soak_gate.sh
```

失败判定：任一指标越阈值即非 0 退出，并在报告中写入 `phasea_soak_gate.fail=...`。

## 门禁与 CI 纳管

已纳入 `run_agent_user_phasea_gate.sh` 的显式检查：

- `relay_ack_upto_seq_batch_and_boundaries`
- `circuit_breaker_opens_and_recovers_after_window`
- `reliability_persistent_store_smoke`（当 `RELIABILITY_STORE=sqlite` 时执行）

CI workflow：`.github/workflows/agent-user-phasea-gate.yml`（调用上述 gate 脚本）。

## 产品层最小 API 测试步骤（Create Account -> Balance -> Transfer -> GetTx）

建议按固定顺序执行（与脚本化联调一致）：

1. 创建/准备测试账户（`ALICE_ADDR`、`BOB_ADDR`）
2. `balance(ALICE_ADDR)` 确认初始余额
3. `nonce(ALICE_ADDR)` 获取下一 nonce
4. `sendTx(from,to,amount,nonce,signature)` 发起转账
5. `getTx(txHash)` 轮询至终态（`committed/success`）

可直接复用仓库根目录 `OPERATIONS.md` 中同名章节示例命令。

一键脚本（推荐）：

```bash
./scripts/v2/product_layer_smoke.sh
```

脚本会按 `wallet create -> query balance -> tx transfer -> getTx` 顺序执行，并输出统一结果：
- `[SMOKE][PASS] ...` / `[SMOKE][FAIL] ...`
- `address=...`
- `tx_hash=...`
- `status=...`

## RPC 服务化（P2-1 第一步）

最小常驻服务（health endpoint）：

```bash
./scripts/v2/rpc_service_up.sh
curl -sS http://127.0.0.1:8545/health
./scripts/v2/rpc_service_down.sh
```

默认文件：
- PID: `run/rpc-service.pid`
- Log: `run/rpc-service.log`

可配置环境变量：
- `HOST`（默认 `127.0.0.1`）
- `PORT`（默认 `8545`）
- `PID_FILE`
- `LOG_FILE`

## Dev Stack 启停（P2-1）

一键拉起：

```bash
./scripts/v2/dev_stack_up.sh
```

一键停止：

```bash
./scripts/v2/dev_stack_down.sh
```

默认服务：
- RPC health: `http://127.0.0.1:8545/health`
- Faucet health: `http://127.0.0.1:8546/health`
- Explorer: `http://127.0.0.1:8090`

## P1-4 集成门禁（sdk 示例 + product smoke + rpc_contract_v1）

新增串联脚本：`scripts/v2/run_p1_integration_gate.sh`

执行顺序（失败即停）：
1. `examples/sdk-js/quickstart.js` 语法与示例文件校验（sdk 示例 smoke）
2. `scripts/v2/product_layer_smoke.sh`（产品层最小 API smoke）
   - gate 会额外强制断言 `status` 为终态，且必须是 `committed/fail`（不允许 `pending`）
3. `cargo test -p trnm-rpc --test rpc_contract_v1`（RPC 合约回归）

本地执行：

```bash
./scripts/v2/run_p1_integration_gate.sh
```

产物目录：
- 默认写入 `run/p1-integration-gate/<timestamp>/`
- 每一步分别输出 `<step>.log`

CI：
- `.github/workflows/trnm-merge-gates.yml` 已加入 `P1-4 integration gate` hard gate step
- 任一步骤失败将直接中止该 workflow job

## PR-4 门禁（罚没资金流向 + 审计字段可见）

在仓库根目录执行：

```bash
./scripts/v2/pr4_challenge_fundflow_audit_gate.sh
```

执行顺序（失败即停）：
1. `bond_forfeiture_flow_test`：`trnm-pouw` challenge 失败 → bond 罚没路径。
2. `bond_refund_flow_test`：`trnm-pouw` challenge 成功（worker slashed）→ bond 返还路径。
3. `event_audit_fields_visibility`：运行 `trillionnium/scripts/check_event_fields.sh`，并强制检查 resolve 事件审计字段。

强制字段（resolve event）：
- `signer=`
- `challenger=`
- `tx_hash=`
- `slash_worker=`
- `resolution_code=`

产物目录：
- 默认：`run/pr4-gates/<timestamp>/`
- 汇总：`summary.txt`
- 日志：`*.log`

验收 checklist（PR-4）：
- [ ] gate 脚本退出码 = 0
- [ ] `summary.txt` 包含 `status=PASS`
- [ ] 罚没路径测试通过（forfeiture）
- [ ] 返还路径测试通过（refund）
- [ ] resolve 事件审计字段全部可见

## PR-5 运维查询与对账（Challenge Treasury / Forfeits）

### 1) 快速查询（按 task）

在 `trillionnium/` 下执行：

```bash
cargo run -q -p trnm-rpc -- query-events --task-id <TASK_ID> --limit 100
```

重点关注字段：
- `event_type`（challenge / resolve）
- `treasury_delta`
- `challenger_delta`
- `bond_disposition`（posted / forfeited / refunded）
- `resolution_code`

### 2) 每日对账（日志聚合）

在仓库根目录执行：

```bash
./scripts/v2/pr5_treasury_reconcile_report.sh
```

默认输入优先级：
1. `trillionnium/run/event-field-check.log`
2. `trillionnium/run/parallel-sanity.log`
3. `trillionnium/run/node1.log` / `node2.log` / `node3.log`

输出：
- `run/pr5-reconcile/<timestamp>/summary.txt`
- `run/pr5-reconcile/<timestamp>/reconcile.json`

可选环境变量：
- `SOURCE_LOG=<path>`：指定输入日志
- `OUT_DIR=<path>`：指定输出目录

### 3) PR-5 验收清单

- [ ] `query-events` 可查到 `challenge/resolve` 事件
- [ ] 事件返回包含 `treasury_delta/challenger_delta/bond_disposition`
- [ ] 对账脚本成功输出 `summary.txt`
- [ ] `summary.txt` 中 `status=PASS`

Runbook：`docs/runbooks/pr5-challenge-treasury-reconcile.md`

## PR-6 Alert Rules（Challenge Treasury 异常告警）

执行：

```bash
./scripts/v2/pr6_alert_rules_gate.sh
```

默认输出：
- `run/pr6-alerts/<timestamp>/summary.txt`
- 机器可解析字段：`status=PASS|WARN|FAIL` + `rule.*`

阈值参数（环境变量）：
- `FAIL_UNRESOLVED_CHALLENGES` / `WARN_UNRESOLVED_CHALLENGES`
- `FAIL_FORFEITS_DAILY_INCREASE` / `WARN_FORFEITS_DAILY_INCREASE`
- `FAIL_ESCROW_NONZERO_HOURS` / `WARN_ESCROW_NONZERO_HOURS`
- `CI_HARD_FAIL_ON_WARN=1`（WARN 也返回非 0）

Runbook：`docs/runbooks/pr6-alert-rules.md`

## PR-7 Alert Delivery（告警投递）

将 PR-6 `WARN/FAIL` 告警投递到消息通道（Slack webhook 或 Telegram bot），并提供窗口去重防抖。

执行（推荐串联）：

```bash
DRY_RUN=1 ALERT_NOTIFY_CHANNEL=slack ./scripts/v2/pr7_alert_delivery_gate.sh
```

常用环境变量：
- `ALERT_NOTIFY_CHANNEL=slack|telegram`
- `ALERT_NOTIFY_MIN_LEVEL=WARN|FAIL`
- `ALERT_NOTIFY_DEDUP_SECONDS=1800`
- `ALERT_NOTIFY_STATE_FILE=run/pr7-alert-delivery/state.json`
- `DRY_RUN=1`（本地演示，不依赖真实密钥）
- Slack: `SLACK_WEBHOOK_URL`
- Telegram: `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`

Runbook：`docs/runbooks/pr7-alert-delivery.md`

## PR-6 Nightly Security 日报（自动化）

nightly 在流程末尾自动生成日报：

- 产物：`run/pr6-ops/daily-security-summary.md`
- 本地手动重跑：`python3 ./scripts/v2/pr6_daily_security_summary.py`
- Workflow Summary 小节：`PR-6 Daily Security Ops`

Runbook：`docs/runbooks/pr6-nightly-security-summary.md`

## PR-9 Weekly Alert Governance（每周告警治理）

每周治理报告（非阻断）聚合以下指标：告警总量、抑制率、失败率、TopN异常、阈值建议变更。

执行：

```bash
python3 ./scripts/v2/pr9_weekly_alert_governance.py
```

默认输出：
- `run/pr9/weekly-alert-governance.md`

nightly 接入建议：
- workflow step 使用 `continue-on-error: true`
- 上传 `run/pr9/**` 到 artifacts
- Step Summary 增加 `PR-9 Weekly Alert Governance`

Runbook：`docs/runbooks/pr9-weekly-alert-governance.md`

## 一键回滚（Phase A）

仓库根目录提供回滚脚本：`scripts/rollback_phasea.sh`

```bash
./scripts/rollback_phasea.sh <commit-or-tag>
# 跳过确认（CI/自动化场景）
./scripts/rollback_phasea.sh <commit-or-tag> --yes
```

行为：
1. 解析并校验目标 commit/tag
2. 交互确认（默认需输入 `ROLLBACK`）
3. `git checkout --detach <target>` 切换代码
4. 运行态清理（devnet 关闭、常见进程清理、phaseA 临时文件清理）
5. 执行最小验证：`trillionnium/scripts/run_agent_user_phasea_gate.sh`

安全约束：
- 默认拒绝脏工作区（可用 `ALLOW_DIRTY=1` 显式覆盖）
- 任一步骤失败即退出（`set -euo pipefail`）
- 回滚日志与 gate 产物路径：`run/rollback-phasea/<timestamp>/`
