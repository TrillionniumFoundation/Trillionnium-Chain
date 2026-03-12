# Oracle Baseline (Lane D, 2026-03-05)

## 范围

本次仅交付**观测与基线产物**，不改核心执行逻辑。

指标口径（离线基线脚本产出）：

- `oracle_ingest_latency_ms`
- `oracle_stale_reject_total`
- `oracle_quorum_reject_total`
- `oracle_drift_reject_total`
- `oracle_source_cardinality`（所有通过校验样本中的最大 source 基数，避免被最后一个通过样本覆盖）

## 可复现命令

```bash
cd trillionnium-rust
./scripts/run_oracle_baseline.sh
```

或分步执行：

```bash
python3 scripts/oracle/benchmark_oracle_metrics.py \
  --input scripts/oracle/fixtures/oracle_baseline_cases.json

python3 scripts/oracle/benchmark_oracle_metrics.py \
  --bench --bench-count 1000 --bench-rounds 10
```

## 一次样例结果

```json
{
  "oracle_ingest_latency_ms": 0.015,
  "oracle_stale_reject_total": 1,
  "oracle_quorum_reject_total": 1,
  "oracle_drift_reject_total": 1,
  "oracle_source_cardinality": 3,
  "accepted_total": 1,
  "sample_count": 4
}
```

```json
{
  "bench_rounds": 10,
  "bench_count": 1000,
  "ingest_latency_p50_ms": 1.051,
  "ingest_latency_p95_ms": 1.066,
  "ingest_latency_max_ms": 1.066
}
```

## 指标契约

机器可读契约文件：`docs/reports/oracle-metrics-contract.json`

该文件固定了：

- 指标名（append-stable，不随意改名）
- 类型与单位
- 离线 bridge 口径与 bench 口径的边界
- 基本一致性约束（例如 reject/accept 与 `sample_count` 的守恒关系）

## 本地/CI 执行建议

- 本地：直接运行 `./scripts/run_oracle_baseline.sh`
- CI：增加一个 job 执行同一命令（仅依赖 `python3`，无额外系统包）

示例（CI step）：

```bash
python3 --version
./scripts/run_oracle_baseline.sh
```

## Rust crate bridge contract

L16 现已在 `crates/trnm-oracle/src/lib.rs` 暴露稳定 bridge 输出：

- `OracleValidationObservation`
- `OracleValidationMetrics`
- `OracleValidationReport`
- `validate_snapshot_observed(...)`

约束：

- reject 维度继续固定为 `stale / quorum / drift`
- metrics 命名继续固定为：
  - `oracle_stale_reject_total`
  - `oracle_quorum_reject_total`
  - `oracle_drift_reject_total`
  - `oracle_source_cardinality`
  - `accepted_total`
  - `sample_count`
- 单次 snapshot bridge 报告中 `sample_count=1`
- `oracle_source_cardinality` 口径为当前 snapshot 的 canonical source cardinality

这样 RPC/HTTP bridge 后续只需要复用该稳定结构，不必各自再实现一套命名映射。

## 瓶颈与下一步

### 当前瓶颈

1. 当前指标为**离线观测口径**，尚未进入节点实时 metrics/exporter。  
2. `oracle_ingest_latency_ms` 反映的是脚本验证路径耗时，不是节点内真实 ingest 关键路径耗时。  
3. 基线输入规模较小（功能性样例 + 轻量压测），尚未覆盖高并发/高 feed 数场景。

### 下一步

1. 将同名指标接入节点内统一 metrics 管道（日志/Prometheus 任一），保持字段名不变。  
2. 增加大样本回放（10k~100k snapshots）和多 feed 混合压测，输出 p50/p95/p99。  
3. 在 CI 增加阈值门禁（如 ingest p95、reject 比例上限），把 baseline 从“报告”升级为“阻断门”。
