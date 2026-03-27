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

## 值班侧可直接观察的日志 / 错误信号

恢复扫描会把“保留了多少已提交 WAL、checkpoint 是否落后、是否发生尾部截断”直接编码到摘要里。值班排障时优先 grep 下面这些固定短语：

- `retained no committed WAL entries`
  - 含义：恢复后没有保留任何已提交 WAL 记录；通常表示只能从 genesis / 空目录重新起步。
- `retained 1 committed WAL entry through height <H>` / `retained <N> committed WAL entries through height <H>`
  - 含义：恢复扫描确认了可保留的已提交 WAL 尾部高度。
- `checkpoint lags retained WAL tip by <N> block(s)`
  - 含义：checkpoint 仍然有效，但比保留的已提交 WAL 末端更旧；这不是损坏信号，本质上是在提示 checkpoint 粒度落后于已验证 WAL tip。
- `no retained checkpoint metadata`
  - 含义：找到了可保留的已提交 WAL，但没有可一同保留的 checkpoint 元数据；需要结合 `metadata-only recovery` 语义判断是否可安全启动。
- `repaired WAL tail required truncation`
  - 含义：检测到了损坏 / 重复 / 断链尾部，恢复流程已执行 fail-closed 截断；这是需要记入 incident note 的明确信号。
- `refusing metadata-only recovery`
  - 含义：当前节点实现仍然不会仅凭元数据恢复 `StateStore` 快照或重放已提交块；即使 WAL/checkpoint 元数据链本身通过校验，也会拒绝继续启动。

## 推荐分诊顺序

1. 先看是否出现 `repaired WAL tail required truncation`。
   - 若出现：按“已自动修复尾部、但需要人工留痕”处理，记录受影响高度范围与保留的 checkpoint 高度。
2. 再看是否出现 `refusing metadata-only recovery`。
   - 若出现：说明恢复是 **fail-closed** 的，不应把它误判成“节点已经完成状态恢复”。
3. 若只看到 `checkpoint lags retained WAL tip by ...`，但没有截断 / 拒绝恢复：
   - 优先判定为正常 checkpoint 粒度差，而不是 WAL 损坏。
4. 若只看到 `retained no committed WAL entries`：
   - 结合 `--bft-wal-dir` 是否为新目录、是否预期从 fresh start 启动来判断；单独出现它不等于数据损坏。

## Incident note 最小模板

- `wal_dir`: `<path>`
- `last_retained_checkpoint`: `<height|none>`
- `next_startup_height`: `<height>`
- `wal_tail_truncated`: `<yes|no>`
- `metadata_only_recovery_refused`: `<yes|no>`
- `retained_wal_summary`: `<原始摘要短语>`
