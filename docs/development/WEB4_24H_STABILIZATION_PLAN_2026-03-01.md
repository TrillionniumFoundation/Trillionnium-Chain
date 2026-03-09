# Web4 24h Stabilization Plan (2026-03-01)

## 目标
在不牺牲 MVXIDAE 持续迭代吞吐的前提下，将当前状态从 CONDITIONAL GO 提升到稳定 GO。

## 当前风险快照
- 工作区存在未提交改动（核心路径）：
  - `trillionnium-rust/crates/trnm-rpc/src/reliability.rs`
  - `trillionnium-rust/crates/trnm-rpc/tests/query_capability_audit.rs`
  - `trillionnium-rust/crates/trnm-cli/src/main.rs`
  - `trillionnium-rust/crates/trnm-cli/tests/mvp_smoke.rs`
  - `trillionnium-rust/crates/trnm-state/src/lib.rs`
  - `trillionnium-rust/crates/trnm-pouw/src/lib.rs`
  - `trillionnium-rust/crates/trnm-node/src/main.rs`
  - `trillionnium-rust/crates/trnm-types/src/transcript.rs`
- 未跟踪内容：`docs/development/`, `micro_patch.diff`
- 近期主要风险：Lane MV 在控制字符/收据解析耦合点存在反复回滚历史。

---

## T+0h ~ T+2h：工作区收口（P0）

### Step 1: 建立快照与分支保护
```bash
cd /Users/qianqi/.openclaw/workspace/TrillionniumChain
git rev-parse --abbrev-ref HEAD
git status --short
git add -A
git stash push -u -m "wip/pre-stabilization-2026-03-01"
```

### Step 2: 逐域恢复与最小提交（建议顺序）
1. `trnm-rpc` reliability + tests（I2-RPC）
2. `trnm-cli` mvp smoke 对齐
3. `trnm-state` DID snapshot/revocation 边界
4. 其余文件按 lane 归类回放

每个域执行模式：
```bash
git stash pop
# 只选择本域文件
git add <files>
# 跑域内 targeted tests + 必要 gate
# 绿灯后提交
```

### Step 3: 若混杂度高，采用分片回放
```bash
git restore --staged .
git checkout -- .
git stash apply
# 逐文件 checkout 到新分支提交
```

---

## T+2h ~ T+8h：高风险点消耦（P1）

### Lane MV（优先）
目标：将 control-char 过滤与 envelope parser 解耦，避免反复回滚。

DoD：
- 过滤层独立函数/模块，不影响解析主路径。
- 对 zero-width/control-only payload 行为有明确契约测试。
- 回归测试覆盖：兼容旧别名、分隔符变体、空白/控制字符边界。

### Lane XI
目标：I2 capability audit 查询可靠性收口。

DoD：
- `query_capability_audit` 行为稳定（not-found / expired / revoked 语义一致）。
- XI 两条 gate 在改动影响范围内保持通过：
  - `./scripts/v2/x2_settlement_contract_gate.sh`
  - `./scripts/v2/i2_token_lifecycle_gate.sh`

### Lane DAE
目标：D3 provenance 最小化与 E2 审计导出一致性。

DoD：
- public-tier 输出最小化策略稳定。
- audit export 对 `llm2`/compact schema 兼容稳定。

---

## T+8h ~ T+24h：回归压测与发布判定（P1）

### 必跑基线
```bash
cd /Users/qianqi/.openclaw/workspace/TrillionniumChain/trillionnium-rust
cargo test --workspace
cd ..
./scripts/v2/governance_value_schema_reject_test.sh
./scripts/v2/emergency_pause_drill.sh
./trillionnium-rust/scripts/run_consensus_fault_matrix.sh
```

### GO 判定门槛
- 过去 24h：
  - lane 回滚率 < 8%
  - 无连续 3 次同类根因回滚
  - 无核心路径未提交脏状态
- 必跑基线全绿。
- Supervisor 输出可从 CONDITIONAL GO 切到 GO。

---

## 自动化调度建议（立即生效）
- 保持 MV/XI/DAE 三 lane 在线。
- XI 若再次连续 2 次 rate-limit/error：临时降频至 10m，稳定后恢复 5m。
- Supervisor 保持 3h；若连续 2 次限流，临时调到 6h。

---

## 记录规范
每个微补丁必须记录：
- changed files
- commands/gates
- pass/fail
- rollback command
- root-cause tag（若失败）

> 说明：本计划仅做收口与稳定性提升，不扩展新大功能面。