# GO-ready 收口最终证据包（Web4）

> 历史证据说明：本文档仅记录 **2026-03-03 当次 Web4 收口/并 main 前证据**，不是当前仓库的 release readiness 权威结论。当前总体验收口径请以仓库根 `RELEASE_READINESS.md` 为准。

- 分支：`merge/web4-integration-2026-03-02`
- 日期：2026-03-03（Asia/Shanghai）
- 目标：清理工作区残留、补齐门禁盲区回归、提供并 main 前可复验证据。

## 本轮微补丁（可回滚）

### 变更文件
1. `trillionnium-rust/crates/trnm-rpc/tests/submit_message_ingress_persistence.rs`
   - 覆盖 `submit-message` 在存在历史高位 `task_id` + 脏行场景下，必须采用 `max(task_id)+1`。
   - 覆盖 ingress 原子写后不残留 `.<file>.tmp-*` 临时文件。
2. `trillionnium-rust/crates/trnm-rpc/tests/dispatch_submit_serial_consistency.rs`
   - 并发压测 `submit-message` 与 `dispatch-open` 同文件写入串行一致性。
   - 断言所有追加写入保留、`task_id` 无重复、锁文件不泄漏。
3. `docs/archive/web4-history/GO_READY_EVIDENCE_WEB4_2026-03-03.md`（本文档）

## 门禁执行与结果

### 1) 全仓测试
```bash
cd trillionnium-rust
cargo test --workspace
```
结果：✅ 通过（exit code 0）。

### 2) Web4 聚合门禁
```bash
./scripts/v2/web4_release_aggregate_gate.sh
```
结果：✅ 通过（包含 required Web4 high-risk gates）。

### 3) X2 门禁
```bash
./scripts/v2/x2_settlement_contract_gate.sh
```
结果：✅ 通过。

### 4) I2 门禁
```bash
./scripts/v2/i2_token_lifecycle_gate.sh
```
结果：✅ 通过。

## 工作区残留清理

- 删除未纳入收口目标的临时规划文档：
  - `docs/development/WEB4_CODE_REVIEW_7_PATCH_CLOSEOUT_2026-03-03.md`

## 回滚说明

本轮为单一微补丁提交，可通过：
```bash
git revert <this_commit_sha>
```
进行完整回滚。

## GO-ready 结论

- [x] 工作区残留已清理
- [x] 门禁盲区（ingress 持久化与并发串行一致性）已补测
- [x] `cargo test --workspace` 绿灯
- [x] `web4_release_aggregate_gate` 绿灯
- [x] `x2`/`i2` gates 绿灯
- [x] 并 main 前证据包已落盘

结论：**GO-ready（可并 main）**。
