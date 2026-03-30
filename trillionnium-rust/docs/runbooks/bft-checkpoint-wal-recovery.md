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
- `retained checkpoint height <C> is ahead of retained WAL tip height <H>; investigate WAL/checkpoint mismatch`
  - 含义：恢复扫描发现“还能保留的 checkpoint 高度”反而高于“还能保留的已提交 WAL tip”，这通常意味着值班侧正在看一组彼此不一致的 WAL/checkpoint 元数据，或此前目录切换 / 尾部截断后留下了漂移痕迹；应按 mismatch 事件处理，而不是继续假设这是正常 lag。
- `no retained checkpoint metadata`
  - 含义：找到了可保留的已提交 WAL，但没有可一同保留的 checkpoint 元数据；需要结合 `metadata-only recovery` 语义判断是否可安全启动。
- `repaired WAL tail required truncation`
  - 含义：检测到了损坏 / 重复 / 断链尾部，恢复流程已执行 fail-closed 截断；这是需要记入 incident note 的明确信号。
  - 联合判读：若它与 `retained no committed WAL entries` 以及 `last retained checkpoint: <H>` 同时出现，不要误记成“完全空目录”。这更可能表示**可保留的已提交 WAL 已归零，但仍保留了一个可识别的 checkpoint 落点**；值班记录里应同时抄下 `last retained checkpoint` 与 `next startup height`，避免把“checkpoint-only retained after truncation”误判成 genesis 重启。
- `refusing metadata-only recovery`
  - 含义：当前节点实现仍然不会仅凭元数据恢复 `StateStore` 快照或重放已提交块；即使 WAL/checkpoint 元数据链本身通过校验，也会拒绝继续启动。
- `next startup height: <H>`
  - 含义：这是 metadata-only recovery 拒绝路径里最值得记录的恢复落点，表示**如果后续改为可恢复路径或补齐状态快照，节点理论上会从哪个高度继续**。
  - 读取建议：把它与 `[bft-recover] restored height=<H0> ...` 一起抄进 incident note；若两者不一致，优先以拒绝报错里的 `next startup height` 作为“预期继续高度”，再回查是否发生了 WAL 尾部截断或 checkpoint 漂移。
- `last retained checkpoint: <H|none>`
  - 含义：这是 metadata-only recovery 拒绝报错里最直接的 checkpoint 落点字段，表示恢复扫描最终认定还能一起保留的 checkpoint 高度；`none` 说明当前只能依赖保留的 WAL 元数据继续判断，不能假设存在可直接落脚的 checkpoint。
  - 读取建议：若同时出现 `no retained checkpoint metadata`，优先把这里的原始值原样记入 incident note；若这里是具体高度，再与 `[bft-recover] restored ... checkpoint=<C>` 互相核对，二者不一致时应优先回查是否发生了 WAL 尾部截断、checkpoint 漂移或目录看错。
- `verified WAL/checkpoint metadata`
  - 含义：恢复流程已经确认当前保留下来的 WAL/checkpoint 元数据链自洽；它只说明“元数据校验通过”，**不**等于应用状态已经恢复完成，必须和 `refusing metadata-only recovery` / `next startup height` 一起解读。
- `incident clue: metadata_only_recovery=1 wal_entries_retained=<N> wal_tail_truncated=<true|false>`
  - 含义：这是 metadata-only recovery 拒绝报错里最适合直接抄进告警注释或 incident note 的固定 clue 串；`wal_entries_retained` 表示恢复扫描最终还能确认保留的已提交 WAL 条数，`wal_tail_truncated` 表示本次恢复前是否发生了 fail-closed 尾部截断。
  - 读取建议：若 `wal_entries_retained=0`，优先按 fresh start / 空目录 / 元数据全失配方向排查；若 `wal_tail_truncated=true`，把它与 `repaired WAL tail required truncation` 绑定记录，不要只记“metadata-only recovery 被拒绝”而漏掉已发生过自动截断。
- `[bft-recover] restored height=<H> lock=<L> checkpoint=<C> truncated=<true|false> metadata_only_recovery=<true|false>`
  - 含义：这是恢复扫描结束后的结构化摘要行，适合值班侧第一眼确认“节点准备从哪个高度继续、是否带锁恢复、是否发生过截断、当前是否落入 metadata-only recovery 拒绝路径”。
  - 读取建议：若 `truncated=true`，继续向上 grep `repaired WAL tail required truncation`；若 `metadata_only_recovery=true`，继续 grep `refusing metadata-only recovery` 以拿到带 `retained_wal_summary` 的完整拒绝原因；若 `checkpoint=none`，再结合 `retained no committed WAL entries` / `no retained checkpoint metadata` 判断这是 fresh start 还是 checkpoint 元数据缺失。
- `[bft-wal] existing default WAL state detected at <A>; isolating this run in <B> (pass --bft-wal-mode reuse to recover prior state explicitly)`
  - 含义：节点发现默认 WAL 目录里已有旧状态，因此本次启动被自动隔离到新的 session 子目录；这通常是“为了避免误复用旧 WAL 的保护动作”，**不是**恢复成功信号。值班侧应立刻记录原目录 `<A>` 与自动隔离目录 `<B>`，避免把新进程产生的空白 WAL 误当成历史恢复结果。
- `[bft-wal] using wal_dir=<PATH>`
  - 含义：这是**本次进程实际使用的 WAL 目录**，应当作为值班排障时引用路径的唯一准绳。只要上面出现过自动隔离提示，就必须以这里的 `<PATH>` 为准，而不是继续沿用配置文件里的默认目录或历史截图里的旧目录。
- `refusing to reuse existing BFT WAL state at <A> (pass --bft-wal-mode reuse to recover, or choose a fresh --bft-wal-dir)`
  - 含义：节点以 fail-closed 方式拒绝复用已经存在状态的 WAL 目录；常见于值班侧显式传了 `--bft-wal-mode fail-if-exists`，或把原本应当新建的目录指到了历史恢复目录。它说明“启动前保护已触发”，**不是** WAL 校验失败，也不是自动修复已经发生。

## 推荐分诊顺序

1. 先看是否出现 `repaired WAL tail required truncation`。
   - 若出现：按“已自动修复尾部、但需要人工留痕”处理，记录受影响高度范围与保留的 checkpoint 高度。
2. 再看是否出现 `refusing metadata-only recovery`。
   - 若出现：说明恢复是 **fail-closed** 的，不应把它误判成“节点已经完成状态恢复”。
3. 若只看到 `checkpoint lags retained WAL tip by ...`，但没有截断 / 拒绝恢复：
   - 优先判定为正常 checkpoint 粒度差，而不是 WAL 损坏。
4. 若看到 `[bft-wal] existing default WAL state detected ... isolating this run in ...`：
   - 先确认值班人员当前查看的是旧目录还是自动隔离后的新目录；如果目录搞混，后续所有“是否真的恢复到历史 tip”的判断都会失真。
   - 立刻继续 grep 同次启动里的 `[bft-wal] using wal_dir=<PATH>`，并把该 `<PATH>` 记为本次 incident 的 `wal_dir`；不要继续沿用旧默认目录或手工猜测的 session 子目录。
5. 若只看到 `retained no committed WAL entries`：
   - 结合 `--bft-wal-dir` 是否为新目录、是否预期从 fresh start 启动来判断；单独出现它不等于数据损坏。
6. 若看到 `refusing to reuse existing BFT WAL state at ...`：
   - 优先判定为启动前保护命中，而不是 WAL 校验失败；先记录当次 `--bft-wal-mode`、被拒绝的目录路径，以及值班侧本来是否预期复用旧状态。
   - 只有在确认本次确实要恢复历史 WAL 时，才切到 `--bft-wal-mode reuse` 重试；否则应改用新的 `--bft-wal-dir`，避免把“目录复用策略错误”误报成数据损坏 incident。

## Incident note 最小模板

- `wal_dir`: `<path>`（优先填写同次启动日志里的 `[bft-wal] using wal_dir=<PATH>`）
- `startup_wal_mode`: `<reuse|fail-if-exists|isolated-default>`
- `last_retained_checkpoint`: `<height|none>`
- `next_startup_height`: `<height>`
- `wal_tail_truncated`: `<yes|no>`
- `metadata_only_recovery_refused`: `<yes|no>`
- `default_wal_isolation_triggered`: `<yes|no>`
- `original_default_wal_dir`: `<path|n/a>`
- `isolated_run_dir`: `<path|n/a>`
- `reuse_existing_wal_denied`: `<yes|no>`
- `rejected_wal_dir`: `<path|n/a>`
- `recovery_summary_line`: ``<[bft-recover] restored height=...>`（原样抄录结构化摘要行，便于和告警/日志查询关联）
- `retained_wal_summary`: `<原始摘要短语>`
