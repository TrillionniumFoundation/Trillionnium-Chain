# Rust L1 Testnet Readiness Runbook

日期：2026-02-19
目标：在进入真实测试网前，用统一 preflight 脚本做“可上线前最后检查”。

## 一键执行

```bash
cd trillionnium-rust
./scripts/testnet_preflight.sh
```

## 检查项

1. 基础环境
   - Rust toolchain / cargo 可用
   - 关键配置文件存在（node1/2/3）
2. 代码健康
   - `cargo test --workspace`
3. 执行路径健康
   - 单节点并行模式 sanity（禁止 `apply_error` / `rollback=true`）
4. 多节点一致性
   - `devnet_up/down + audit_state_roots.sh`
   - 结果必须：`ok=true mismatch=0 missing=0`
5. 性能基线（快速）
   - classic/mixed matrix（`TXS=5000`）
   - profiling summary 生成成功

## 产物

- `run/preflight/preflight-<timestamp>.log`
- `run/audit/state-root-audit-<timestamp>.txt`
- `run/bench/bench-matrix-<timestamp>.txt`
- `run/bench/bench-mixed-matrix-<timestamp>.txt`
- `run/bench/executor-profile-summary-<timestamp>.txt`

## 通过标准（Go/No-Go）

- 所有步骤返回码为 0
- preflight log 中最后一行出现：`[OK] testnet preflight passed`

## 失败处理

- 先看 preflight log 对应失败段落
- 如为一致性失败：优先检查 `run/node*.log` 与 audit 报告
- 如为性能阈值问题：先确认是否是机器负载尖峰，再复跑一次
- 如仍失败：按 `docs/runbooks/rust-l1-rollback-runbook.md` 执行回退