# Rust L1 Testnet Launch Sheet (v1)

日期：2026-02-19  
适用分支：`main`  
适用阶段：测试网首发（小窗口）

## 1) 冻结参数（v1）

### 节点执行参数
- `block_ms=5`
- `max_blocks=6`（仅 preflight/sanity；正式运行按运维窗口配置）
- `demo_tasks=8`
- `demo_keys=3`
- `parallel_workers=4`

### 基准参数
- Classic matrix: `TXS=5000`
- Mixed matrix: `TXS=5000`, `read_fanout=3`, `write_every in {1,2,4}`

### SLO 门禁阈值
- State root audit：必须 `ok=true mismatch=0 missing=0`
- Classic bench：`BENCH_WARN_MS=300`, `BENCH_MAX_MS=600`
- Mixed bench：`BENCH_MIXED_WARN_MS=300`, `BENCH_MIXED_MAX_MS=600`
- Parallel sanity：日志中禁止出现 `apply_error` / `rollback=true`

---

## 2) Go/No-Go 清单

执行：

```bash
cd trillionnium-rust
./scripts/testnet_preflight.sh
```

通过条件（全部满足才可 Go）：
1. `cargo test --workspace` 通过
2. `run/audit/state-root-audit-*.txt` 显示 `summary ok=true mismatch=0 missing=0`
3. `run/parallel-sanity.log` 无 `apply_error|rollback=true`
4. 生成 `run/preflight/go-no-go-*.txt` 且 `status=GO`

关键产物：
- `run/preflight/preflight-latest.log`
- `run/preflight/go-no-go-latest.txt`
- `run/audit/state-root-audit-*.txt`
- `run/bench/bench-matrix-*.txt`
- `run/bench/bench-mixed-matrix-*.txt`
- `run/bench/executor-profile-summary-*.txt`

---

## 3) 启动窗口建议

### 窗口 A（首发）
- 时长：30~60 分钟
- 策略：只开最小集节点，实时盯日志和 state root
- 目标：验证稳定性与可回滚性，不追求吞吐上限

### 窗口 B（扩展）
- 条件：窗口 A 无异常
- 动作：延长运行时间并增加 workload 压力

---

## 4) 回滚触发条件（任一满足即回滚）

1. 任意节点出现连续执行异常（`apply_error`）
2. 出现 `rollback=true` 异常峰值（非预期）
3. state root 审计出现 `mismatch>0` 或 `missing>0`
4. preflight 连续 2 次 No-Go

回滚参考：`docs/runbooks/rust-l1-rollback-runbook.md`

---

## 5) 发布口径（对内）

- 当前测试网版本：Rust L1 MVP（并行执行 + 状态根对账 + SLO 门禁）
- 风险策略：性能优先，但一致性红线不可突破
- 变更策略：先小窗口验证，再扩展规模
