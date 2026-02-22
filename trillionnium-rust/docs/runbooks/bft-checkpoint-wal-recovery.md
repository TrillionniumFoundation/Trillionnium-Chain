# BFT Checkpoint + WAL 校验恢复（稳定性增强 #2）

## 目标

在 `trnm-node` 重启恢复前，先校验 WAL 元数据链；若发现不一致，回滚到最近有效 checkpoint，避免把损坏 WAL 直接用于恢复。

## 新增文件（`--bft-wal-dir` 下）

- `consensus-wal.toml`：兼容旧逻辑的恢复指针（`next_height/last_round/lock`）
- `consensus-wal-meta.toml`：按高度记录 `WalMeta`（含 `prev_hash_hex` 链）
- `consensus-checkpoints.toml`：每 N 个已提交块写一条 `CheckpointMeta`

## 核心参数

- `--bft-checkpoint-interval <N>`（默认 `5`）
  - 每 N 个 **committed** block 写一次 checkpoint 元数据

## 恢复流程

1. 读取 `consensus-wal-meta.toml` + `consensus-checkpoints.toml`
2. 校验 `WalMeta.prev_hash_hex` 链连续性
3. 以 `(height,state_root,wal_entry_hash)` 匹配有效 checkpoint
4. 若发现断链/不一致：
   - 截断 WAL 到最近有效 checkpoint
   - 同步截断 checkpoint 列表
   - 重新写 `consensus-wal.toml` 指针
5. 从 `checkpoint.height + 1` 继续出块

## 最小验证

```bash
cd trillionnium-rust
cargo test -p trnm-state -p trnm-node
```

关键测试：

- `trnm-state`:
  - `wal_checkpoint_verification_picks_latest_valid`
  - `wal_checkpoint_verification_falls_back_on_chain_break`
- `trnm-node`:
  - `recover_truncates_to_latest_valid_checkpoint`

## 兼容性说明

- 未移除原 `consensus-wal.toml`，现有 gate / 脚本可继续读取恢复指针。
- 新增元数据与 checkpoint 文件是增强路径，不改变原共识模拟主流程。