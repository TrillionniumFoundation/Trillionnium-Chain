# Rust L1 Release Guard（P2.2）

更新时间：2026-02-20

## 目标
在打 RC tag 前，把“是否可发版”从口头判断变成可审计规则。

## RC 放行硬条件

1. **Nightly 连续 3 次全绿（必须）**
   - Workflow：`rust-l1-nightly-health`
   - 口径：同一主分支上最近连续 3 次 run 均 `success`
   - 任意一次失败会把 streak 归零

2. **协议与并行红线全通过（必须）**
   - workspace tests
   - state-root audit (`ok=true mismatch=0 missing=0`)
   - parallel sanity（无 `apply_error` / `rollback=true`）
   - v1 event field freeze
   - v1 event replay smoke

3. **性能阈值满足当前阶段（必须）**
   - 由 `scripts/enforce_ci_thresholds.sh` 统一执行
   - 默认阶段：`stage1`
   - 收紧阶段：`stage2`（24h 稳定观察后切换）

## 阈值阶段策略

- **stage1（当前默认）**
  - classic: warn=300, hard=600
  - mixed:   warn=300, hard=600

- **stage2（收紧版）**
  - classic: warn=240, hard=480
  - mixed:   warn=280, hard=560

## 推荐发布流程

1. 先确认 nightly green streak >= 3
2. 运行 `./scripts/release_rc.sh`
3. 检查 `release/rc-*/manifest.txt` 与 evidence 目录完整
4. 再打 RC tag

## Evidence 清单（RC 包必须包含）

- `nightly-streak.log`
- `cargo-test.log`
- `state-root-audit.log`
- `parallel-sanity.log`
- `event-field-check.log`
- `event-replay-smoke.log`
- `bench-matrix.log`
- `bench-mixed-matrix.log`
- `threshold-enforcement.log`
- `manifest.txt`
