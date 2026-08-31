# TRNM 拆分优先级路线图（2026-03-19）

> BL09 retirement-prep note: 本路线图保留的 `trnm-pouw` crate、测试基线与拆分优先级描述，仅应用于迁移期兼容、decomposition guardrails 或 provenance / audit evidence 留痕，不能解读为当前默认 payout authority，也不重新授权默认 work-unit payout path。若 PoCO settlement 已成为主结算路径，对外付款判断与默认结算 authority 仍应以 PoCO settlement anchor 为准。

## 当前阶段判断

项目已从“爆破巨石”进入“中后期收口 + 测试稳定化”阶段。

### 当前事实
- `trnm-pouw` 已完成 **千行清零**，当前最大块降至 856 行级。
- 当前 `cargo test -p trnm-pouw --lib -q` 稳定基线：**897 passed; 0 failed**。
- 历史上出现过 **903 passed** 口径，但最后 6 个测试差额尚未高置信定位；当前不应继续低置信盲补。
- 全仓新的最大结构债已转向：
  - `trnm-state/tests/*`
  - `trnm-bridge-poc/tests/*`
  - `trnm-pouw` 的 800 行级中块

---

## 一、全项目优先级分层

## P0：继续拆，但必须绑定测试名基线

### 1. `trnm-pouw`
**当前最大块**
- `src/verification/tests.rs` — 856
- `src/common/metrics.rs` — 847
- `src/verification/real_tee_backend_tests_exchange_termination_ack_budget.rs` — 840
- `src/verification/real_tee_backend_tests_profiles_http_session/chunk_termination_classification_token.rs` — 807
- `src/common/apply_path/tests/create_accept_parts/resolve_pause_paths.rs` — 798

**策略**
- 继续拆，但每一刀都必须同时执行：
  1. `cargo test -p trnm-pouw --lib -q`
  2. `cargo test -p trnm-pouw --lib -- --list > baseline.txt`
- 没有 test-list 基线的拆分，不再视为完整验收。

**推荐下一刀（按优先级）**
1. `src/verification/tests.rs`
2. `src/common/metrics.rs`
3. `src/verification/real_tee_backend_tests_exchange_termination_ack_budget.rs`
4. `src/verification/real_tee_backend_tests_profiles_http_session/chunk_termination_classification_token.rs`
5. `src/common/apply_path/tests/create_accept_parts/resolve_pause_paths.rs`

**额外纪律**
- 子任务回传不可信，主代理必须二次核树：
  - 文件是否真实生成
  - 父入口是否真的变薄
  - 测试数是否回退

---

## P1：应升级为新主战场

### 2. `trnm-state`
**当前最大块**
- `tests/state_root_regression/regression.rs` — 2531
- `tests/m1_pause_resolve_escrow_invariant/lifecycle.rs` — 2015
- `tests/m1_pause_resolve_escrow_invariant/members.rs` — 1410
- `tests/state_root_regression/boundaries.rs` — 998
- `src/tests/governance/emergency_pause.rs` — 779

**判断**
- 已成为全仓新的最大结构债来源。
- 主要问题不是生产实现，而是超大测试树。

**推荐拆分策略**
- `state_root_regression/*`：按 regression / boundaries / restore / objects / balances / governance 分组
- `m1_pause_resolve_escrow_invariant/*`：按 lifecycle / members / toggle / unpause / edge cases 分组
- 统一改为“父入口 + 子场景模块”结构

**推荐下一刀（按优先级）**
1. `tests/state_root_regression/regression.rs`
2. `tests/m1_pause_resolve_escrow_invariant/lifecycle.rs`
3. `tests/m1_pause_resolve_escrow_invariant/members.rs`
4. `tests/state_root_regression/boundaries.rs`

---

### 3. `trnm-bridge-poc`
**当前最大块**
- `tests/x2_settlement_loop.rs` — 2124
- `tests/x3_compensation_matrix.rs` — 934
- `tests/integration_tests.rs` — 808

**判断**
- 结构债明显，但尚未系统治理。
- 适合按业务场景做成矩阵型测试子模块。

**推荐拆分策略**
- `x2_settlement_loop.rs`：按 happy path / recovery / replay / timeout / settlement edge cases 拆
- `x3_compensation_matrix.rs`：按 compensation path / failure matrix / retry / invariants 拆
- `integration_tests.rs`：按 integration domain 分簇

**推荐下一刀（按优先级）**
1. `tests/x2_settlement_loop.rs`
2. `tests/x3_compensation_matrix.rs`
3. `tests/integration_tests.rs`

---

## P2：先审计，再决定是否继续拆

### 4. `trnm-rpc`
**当前最大块**
- `src/runtime/core.rs` — 525

**额外信号**
- 当前工作树变动数全仓最高（约 156 条）

**判断**
- 结构债不是第一问题。
- 当前风险更像是：改动面大、收口一致性可能下滑。

**建议**
- 暂缓继续机械拆分
- 先做一轮：
  - 接口/模块一致性审计
  - 测试入口整理审计
  - 未使用模块/重复 helper 清理审计

---

### 5. `trnm-node`
**当前最大块**
- `src/summary.rs` — 474

**判断**
- 已脱离主战场。
- 适合正常维护与中型整理，不必作为头号优先级。

---

## P3：可视为阶段性健康

### 6. `trnm-mempool`
- 当前最大块：`src/tests/recovery_tests.rs` — 393
- 主体巨石已拆散，结构上比较健康。

### 7. `trnm-worker-agent`
- 当前最大块：`src/llm_runtime_tx.rs` — 316
- 已进入中后期收口。

### 8. `trnm-cli`
- 当前最大块：`src/tx/parse.rs` — 475
- 不再是结构风险源。

### 9. `trnm-executor`
- 当前最大块：`src/tests/env_auto_tests/auto_numeric_parser_tests.rs` — 445
- 中小块范围，正常整理即可。

### 10. `trnm-types`
- 当前最大块：`src/interop_identity/tests/settlement/route.rs` — 430
- 基本脱离主战场。

### 11. `trnm-oracle`
- 当前最大块：225
- 可视为阶段性收官。

---

## 二、流程级改进（强烈建议立即执行）

## 1. 建立“拆分验收三件套”
每次拆分结束，必须同时记录：

1. **文件结构结果**
   - 父入口是否真正变薄
   - 新子模块是否真实生成
2. **测试结果**
   - `cargo test ...`
3. **测试名基线**
   - `cargo test ... -- --list`

没有第 3 项，不算完整验收。

---

## 2. 对 `trnm-pouw` 建立专用 baseline 机制
建议固定输出到类似：

- `artifacts/testlists/trnm-pouw-lib-YYYYMMDD-HHMM.txt`

用途：
- 防测试静默掉线
- 支撑后续真实集合差分
- 让“903 vs 897”这类问题可直接追证

---

## 3. 子任务回传降级为“提示”，不再视为事实
当前经验表明，子任务回传会出现：
- 空回传
- 废话回传
- 结构完成但测试挂线没说清

因此主代理要默认做二次核验：
- `wc -l`
- `git status --short`
- `cargo test`
- 必要时 `--list`

---

## 三、推荐的下一阶段执行顺序

### 路线 A：继续聚焦 `trnm-pouw`
适合目标：把当前主战场彻底做漂亮

顺序：
1. `src/verification/tests.rs`
2. `src/common/metrics.rs`
3. `src/verification/...ack_budget.rs`
4. `src/verification/...classification_token.rs`
5. `src/common/apply_path/tests/create_accept_parts/resolve_pause_paths.rs`

前提：必须绑定 test-list 基线。

---

### 路线 B：开始全项目分流
适合目标：从“单仓主战场”切到“全仓收口”

顺序：
1. `trnm-state/tests/state_root_regression/regression.rs`
2. `trnm-state/tests/m1_pause_resolve_escrow_invariant/lifecycle.rs`
3. `trnm-bridge-poc/tests/x2_settlement_loop.rs`
4. `trnm-state/tests/m1_pause_resolve_escrow_invariant/members.rs`
5. `trnm-bridge-poc/tests/x3_compensation_matrix.rs`

---

## 四、最终判断

### 现在最重要的，不再是“还能不能继续拆”
而是：

> **如何在继续拆的同时，不再让测试拓扑静默回退。**

### 我对当前全项目的判断是
- 结构治理：已经非常成功
- 后续重点：测试稳定化 + 战场分流
- `trnm-pouw`：继续拆，但必须带 baseline
- `trnm-state` / `trnm-bridge-poc`：应该正式接棒进入下一阶段主战场

---

## 五、推荐立即执行的具体动作

### 选项 1：继续 `trnm-pouw`
- 开一波 2~3 线，拆 `verification/tests.rs` / `common/metrics.rs` / `ack_budget.rs`
- 同时建立 `--list` baseline 产物

### 选项 2：切主战场到 `trnm-state`
- 先打 `state_root_regression/regression.rs`
- 再打 `m1_pause_resolve_escrow_invariant/lifecycle.rs`

### 选项 3：先做流程治理
- 给 `trnm-pouw` 的拆分流程补上 baseline 机制
- 然后再继续批量拆分
