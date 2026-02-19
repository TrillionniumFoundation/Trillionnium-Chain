# Release Note — P2 Throughput Breakthrough RC (2026-02-19)

## Summary
P2（高吞吐与并发执行）已完成首轮 RC：
- `trnm-executor` 分组核心从近 O(n²) 的逐组逐笔冲突扫描，切换为对象访问索引驱动分组（近 O(n·(R+W))）
- `trnm-bench` 增加 `--profile`，可输出分组与冲突统计用于持续优化
- 在 `txs=20000` 的全矩阵样本中，`elapsed_ms` 平均提升约 **99.70%**（相对 Day1 基线）

## What Changed

### 1) Executor grouping algorithm (break change, performance-first)
- Affected crate: `trillionnium-rust/crates/trnm-executor`
- New logic:
  - 维护 `latest_writer_group` / `latest_reader_group`
  - 对每笔交易计算最小可放置组 `required_group`
  - 避免对已有组做全量 pairwise 扫描

### 2) Profiling support
- Affected crate: `trillionnium-rust/crates/trnm-bench`
- New flag: `--profile`
- New outputs:
  - `profile.max_group_size`
  - `profile.min_group_size`
  - `profile.avg_group_size`
  - `profile.conflict_checks`
  - `profile.conflict_hits`
  - `profile.conflict_hit_rate`

## Validation Evidence

### Day5 RC close-out (latest)
- RC package: `trillionnium-rust/release/rc-20260219-211609/`
- Manifest: `trillionnium-rust/release/rc-20260219-211609/manifest.txt`
- Workspace tests: pass (`cargo test --workspace`)
- State root audit: pass (`trillionnium-rust/run/audit/state-root-audit-20260219-211304.txt`, `ok=true mismatch=0 missing=0`)
- Classic matrix (TXS=5000): `trillionnium-rust/run/bench/bench-matrix-20260219-211313.txt`
- Mixed matrix (TXS=5000): `trillionnium-rust/run/bench/bench-mixed-matrix-20260219-211319.txt`
- Executor profile summary: `trillionnium-rust/run/bench/executor-profile-summary-20260219-211329.txt`

### Baseline (Day1)
```bash
TXS=20000 ./scripts/run_bench_matrix.sh
```
Artifact:
- `trillionnium-rust/run/bench/bench-matrix-20260219-201531.txt`

### Optimized matrix
```bash
TXS=20000 ./scripts/run_bench_matrix.sh
```
Artifacts:
- `trillionnium-rust/run/bench/bench-matrix-20260219-202118.txt`
- `trillionnium-rust/run/bench/bench-matrix-20260219-202254.txt`

Representative results:
- `keys=20000`: `15769ms -> 36ms`
- `keys=2000`: `8790ms -> 26~27ms`
- `keys=10`: `8307ms -> 26ms`

### Regression subset (Day4)
1. Workspace tests
```bash
cargo test -q --workspace
```
Result: pass

2. State root audit
```bash
./scripts/audit_state_roots.sh
```
Artifact:
- `trillionnium-rust/run/audit/state-root-audit-20260219-202251.txt`
Result: `ok=true mismatch=0 missing=0 heights=3`

## Risk Register

1. **Behavioral compatibility risk (medium)**
   - 分组实现方式变化，虽语义目标不变，但属于核心调度路径改写。
   - Mitigation: 已通过现有 tests + state_root audit + matrix 回归。

2. **Metric interpretation risk (low)**
   - 新 profiling 中 `conflict_checks/hits` 采用轻量近似计数，不等同旧版 pairwise 精确扫描口径。
   - Mitigation: 保留字段说明，避免跨版本误解。

3. **Future workload shape risk (medium)**
   - 当前基准以热点键分布模型为主，真实业务混合读写模式可能出现新瓶颈。
   - Mitigation: 下一阶段补充 mixed workload benches（多读多写、对象扇出、burst）。

## Rollback Plan
若线上/测试网出现调度异常或稳定性回退，按以下执行：
- 参考：`docs/runbooks/rust-l1-rollback-runbook.md`
- 快速路径：
  1) `./scripts/devnet_down.sh`
  2) 归档 `run/` 证据
  3) 切回 Go/Cosmos 主线并做健康检查
  4) 重跑 P0/P1 门禁确认恢复

## Next Recommended Step (Post-P2 RC)
- 建立 mixed workload 基准集并接入 nightly
- 对 executor 增加更细粒度热点对象统计（Top-K）
- 在 RC 之后做一次参数寻优（group/batch 策略）形成 P2.1