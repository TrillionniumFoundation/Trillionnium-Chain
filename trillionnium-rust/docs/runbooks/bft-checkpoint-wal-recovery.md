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

## Checkpoint 证据链接（面向 light-verifier / 审计面）

每个 checkpoint 不是只靠高度定位，而是靠下面这组可交叉验证的证据：

- `CheckpointMeta.height`
- `CheckpointMeta.state_root_hex`
- `CheckpointMeta.wal_entry_hash_hex`
- `WalMeta.prev_hash_hex`（把当前 WAL 条目接回前一个已确认条目）

推荐把它理解为三层约束：

1. **checkpoint 锚点**：`(height, state_root_hex, wal_entry_hash_hex)` 必须命中同一条已提交 WAL 元数据。
2. **链式连续性**：命中的 WAL 条目还必须通过 `prev_hash_hex` 与前序条目形成连续哈希链。
3. **冲突 fail-closed**：若某个候选 checkpoint 的 `wal_entry_hash_hex` 命中 retained WAL 条目，但 `state_root_hex` 与该条目的已验证状态根不一致，则它不能被当作“同一锚点的等价副本”接受，必须回退到更早且仍可交叉验证的 checkpoint。

这意味着 light-verifier 或人工审计都不能只看 `height` 或只看 `state_root_hex`：

- 只有高度相同，不足以证明命中的是同一条 canonical WAL 记录；
- 只有 `state_root_hex` 相同，不足以证明前序提交链没有漂移；
- 即便 `wal_entry_hash_hex` 相同，只要 `state_root_hex` 不一致，也必须按冲突证据处理，不能把它当作同一检查点的可接受变体；
- 对 light-verifier / DA 摘要面，这种“`wal_entry_hash_hex` 命中但 `state_root_hex` 冲突”的情况必须标记为 **unavailable / fail-closed**，而不是降级成“弱匹配”或“同哈希可接受变体”；
- 必须同时检查 checkpoint 三元组与 `prev_hash_hex` 连续性，才能确认恢复锚点既命中正确状态，又命中正确提交历史。

对于**同一高度出现多条候选元数据**的情况，还要维持跨 surface 一致的 canonical 排序语义：

- `WalMeta` 先按 `(height, round, proposal_hash, committed, state_root_hex, prev_hash_hex)` 排序；
- `CheckpointMeta` 先按 `(height, state_root_hex, wal_entry_hash_hex)` 排序；
- 因此 light-verifier / 审计脚本如果要输出“该高度的第一条/最后一条”摘要，必须先按上述顺序 canonicalize，再做索引或聚合。

一个最小例子：

- 若同一高度 `2` 下有两条 checkpoint：
  - `(2, root-a, hash-a)`
  - `(2, root-z, hash-b)`
- canonical 排序后，light-verifier 的“first” 必须是 `(2, root-a, hash-a)`；
- 同一份证据上的“last” 必须是 `(2, root-z, hash-b)`；
- 不能把文件原始枚举顺序、TOML 反序列化顺序或哈希表遍历顺序当成 canonical 语义。

否则，不同读取路径即便面对**同一组证据文件**，也可能因为枚举顺序不同而得出不同的“canonical checkpoint / predecessor linkage”摘要。

另外，解析这两份元数据文件时也应保持 **fail-closed**：

- 缺失 `CheckpointMeta.state_root_hex` 或 `CheckpointMeta.wal_entry_hash_hex` 时，不能默默补默认值；
- 出现未知字段、重复字段或结构歧义时，不能“尽力继续”并产出 light-verifier 摘要；
- 对 DA / light-verifier 面，更安全的行为是把该证据批次标记为 **invalid / unavailable**，等待人工修复或节点重写 canonical 元数据，而不是输出看似完整但语义不可信的摘要。

这能避免下游把“字段残缺的 checkpoint 证据”误当作可验证锚点，从而把本该显式暴露的证据损坏静默吞掉。

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