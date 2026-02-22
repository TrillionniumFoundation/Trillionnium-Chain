# RC 本地演练与参数口径冻结检查（2026-02-22 13:20 CST）

## 1) 当前生效参数口径（冻结）
来源：`crates/trnm-worker-agent/src/main.rs`（`resolve_u32/resolve_u64` + `resolve_*_policy`）

统一优先级：**CLI > ENV > Default**（CLI 若不满足最小值则回退到 ENV/Default）

### TX Adapter（FlushSubmissions）
- `max_retries`
  - CLI: `--max-retries`
  - ENV: `TRNM_TX_ADAPTER_MAX_RETRIES`
  - Default: `3`
  - Min: `0`
- `backoff_ms`
  - CLI: `--backoff-ms`
  - ENV: `TRNM_TX_ADAPTER_BACKOFF_MS`
  - Default: `200`
  - Min: `0`

### LLM Adapter（RunAssigned）
- `max_retries`
  - CLI: `--llm-adapter-max-retries`
  - ENV: `TRNM_LLM_ADAPTER_MAX_RETRIES`
  - Default: `2`
  - Min: `0`
- `backoff_ms`
  - CLI: `--llm-adapter-backoff-ms`
  - ENV: `TRNM_LLM_ADAPTER_BACKOFF_MS`
  - Default: `200`
  - Min: `0`
- `timeout_ms`
  - CLI: `--llm-adapter-timeout-ms`
  - ENV: `TRNM_LLM_ADAPTER_TIMEOUT_MS`
  - Default: `10000`
  - Min: `1`

> 口径旁证：`docs/worker-agent-timeout-retry-runbook.md`

---

## 2) RC 脚本执行

### 主路径（优先）
```bash
SKIP_STREAK_CHECK=1 TXS=500 THRESHOLD_PROFILE=stage1 ./scripts/release_rc.sh
```
- 输出目录：`release/rc-20260222-131955`
- 执行到 protocol freeze checks 阶段失败（exit code 4）
- 阻塞点：`scripts/check_event_fields.sh` 在 `prod` 模式下要求 resolve 事件，当前日志缺失。
- 关键信息：`no resolve event line found in run/event-field-check.log`

### 最小可替代演练（环境受限时）
```bash
ALLOW_MISSING_RESOLVE_EVENT=1 ./scripts/check_event_fields.sh
ALLOW_PARTIAL_EVENT_REPLAY=1 ./scripts/check_event_replay_smoke.sh
TXS=100 ./scripts/run_bench_matrix.sh
TXS=100 ./scripts/run_bench_mixed_matrix.sh
THRESHOLD_PROFILE=stage1 ./scripts/enforce_ci_thresholds.sh
```
- 结果：全部通过

---

## 3) 证据路径

### release 侧（主路径）
- `release/rc-20260222-131955/nightly-streak.log`
- `release/rc-20260222-131955/cargo-test.log`
- `release/rc-20260222-131955/state-root-audit.log`
- `release/rc-20260222-131955/parallel-sanity.log`
- `release/rc-20260222-131955/validation-mode.log`
- `release/rc-20260222-131955/event-field-check.log`（失败点）

### run/health 侧
- `run/audit/state-root-audit-20260222-132023.txt`
- `run/bench/bench-matrix-20260222-132045.txt`
- `run/bench/bench-mixed-matrix-20260222-132052.txt`

### docs/reports 侧
- `docs/reports/rc-local-rehearsal-20260222-132044/summary.md`
- `docs/reports/rc-local-rehearsal-20260222-132044/check_event_fields_allow_missing.log`
- `docs/reports/rc-local-rehearsal-20260222-132044/check_event_replay_allow_partial.log`
- `docs/reports/rc-local-rehearsal-20260222-132044/bench_matrix_txs100.log`
- `docs/reports/rc-local-rehearsal-20260222-132044/bench_mixed_matrix_txs100.log`
- `docs/reports/rc-local-rehearsal-20260222-132044/enforce_thresholds_stage1.log`

---

## 4) PASS/FAIL 总结

- **严格 RC（`release_rc.sh`, `MVP_MODE=prod`）: FAIL**
  - 原因：事件字段冻结检查缺少 resolve event。
- **最小替代 RC 演练（放宽 dev/beta 兼容开关）: PASS**
  - event replay smoke / benchmark / threshold enforcement 全部 PASS。

## 建议下一步
1. 补齐/修复 resolve 事件产出链路（或在 prod 前确认 resolve 生命周期用例已覆盖）。
2. 在 CI 增加 `MVP_MODE=prod` 的事件字段门禁前置，避免 RC 末段才暴露。
3. 若当前阶段仍是 dev/beta，显式在 RC 任务参数中标注 `ALLOW_MISSING_RESOLVE_EVENT=1` 的临时豁免及截止时间。
