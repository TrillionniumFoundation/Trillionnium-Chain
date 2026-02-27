# Consensus v1 Freeze

Status: frozen-minimum (laneA)
Last updated: 2026-02-27
Scope: finality, recovery, fault behavior, auth

## 1) Finality & Height Semantics

- `height` 单调递增，提交成功后才会推进 `next_height`。
- `round` 允许在同一高度内递增（timeout/round-change）。
- 仅在区块提交后写入共识 WAL 元数据，避免“预提交推进高度”。

## 2) Recovery Source of Truth

恢复以 `run/consensus-wal/` 为准：

- `consensus-wal-meta.toml`：WAL 条目链
- `consensus-checkpoints.toml`：checkpoint 锚点
- `consensus-wal.toml`：`next_height` / lock 信息

恢复流程约束：

1. 先校验 WAL 链连续性；
2. 不连续或损坏时回退到最近可验证 checkpoint；
3. 恢复后 `next_height` 必须与恢复状态一致，禁止跳高。

## 3) Message Auth & Replay Guard

- 共识消息必须具备 signer 身份与签名校验。
- 非法 signer / 签名失败必须 fail-closed 拒绝。
- replay nonce 必须单调（重复或倒退直接拒绝并记拒绝统计）。

## 4) Timeout / Round-change

- round-change 由 timeout 触发，参数化但默认安全值不可在运行时隐式漂移。
- timeout 导致 round 前进，不得绕过签名与 replay 检查。

## 5) Security Fault Matrix (v1 minimum)

必须可重复执行并产出结构化报告（脚本入口）：

- `trillionnium-rust/scripts/run_consensus_fault_matrix.sh`
- `trillionnium-rust/scripts/run_consensus_security_matrix.sh`

最小覆盖：节点重启、网络延迟/抖动、消息认证失败路径。

## 6) Frozen Error Semantics (minimum)

以下错误语义在 v1 冻结（文案可微调，语义不可变）：

- 签名无效：拒绝当前消息，不推进高度。
- nonce/replay 冲突：拒绝当前消息并记录 replay 计数。
- WAL 校验失败：停止向前推进，执行 checkpoint 回退恢复。

## 7) Change Policy

- 任何变更需同时提交：代码 + 测试/脚本 + 文档更新。
- v1 冻结范围内变更默认视为 breaking，需显式评审与回滚路径。
