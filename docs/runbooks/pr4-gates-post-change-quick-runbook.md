# PR-4 Post-change Quick Runbook

## 目标
快速验证 PR-4 门禁是否满足：
1. challenge bond 罚没/返还资金流向正确；
2. resolve 事件审计字段可见。

## 一键执行
在仓库根目录：

```bash
cd /Users/qianqi/.openclaw/workspace/TrillionniumChain
./scripts/v2/pr4_challenge_fundflow_audit_gate.sh
```

可选：自定义产物目录

```bash
RUN_DIR=/tmp/trnm-pr4-gates ./scripts/v2/pr4_challenge_fundflow_audit_gate.sh
```

## 结果定位
默认产物：`run/pr4-gates/<timestamp>/`

重点文件：
- `summary.txt`（最终 PASS/FAIL）
- `bond_forfeiture_flow_test.log`
- `bond_refund_flow_test.log`
- `event_audit_fields_visibility.log`

事件源日志（由脚本引用）：
- `trillionnium-rust/run/event-field-check.log`

## 验收步骤（3 分钟）
1. 检查脚本退出码为 `0`。
2. 打开 `summary.txt`，确认：
   - `status=PASS`
   - `bond_forfeiture_test=...`
   - `bond_refund_test=...`
3. 在 `summary.txt` 的 `resolve_event=` 行确认包含：
   - `signer=`
   - `challenger=`
   - `tx_hash=`
   - `slash_worker=`
   - `resolution_code=`

## 常见失败与处理
- `missing event log` / `no resolve event found`
  - 重跑 gate，确认本地可执行 `trillionnium-rust/scripts/check_event_fields.sh`。
- `resolve event missing token ...`
  - 检查 `trillionnium-rust/run/event-field-check.log` 中 resolve 事件行是否字段退化。
- `cargo test` 相关失败
  - 先在 `trillionnium-rust` 下单独执行日志中失败的测试名定位。

## 最小回归命令（拆分执行）
```bash
cd /Users/qianqi/.openclaw/workspace/TrillionniumChain/trillionnium-rust
cargo test -q -p trnm-pouw challenge_uses_governance_window_and_resolve_marks_bond_outcome -- --nocapture
cargo test -q -p trnm-pouw resolve_refunds_challenge_bond_when_worker_slashed -- --nocapture
./scripts/check_event_fields.sh
```