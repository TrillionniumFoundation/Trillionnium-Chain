# BFT Checkpoint + WAL 校验恢复（稳定性增强 #2）

## 目标

在 `trnm-node` 重启恢复前，先校验 WAL 元数据链；若发现不一致，回滚到最近有效 checkpoint，避免把损坏 WAL 直接用于恢复。

这份 runbook 面向 **MN08 preflight / rollback / disaster-recovery** 场景：不仅说明恢复逻辑，还给出一套可直接复跑、可回滚、可审计的演练方式。

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

## 预演前提（fail-closed）

在执行任何恢复演练前，先确认：

- 位于目标 worktree：`/Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN08-ops-preflight-recovery-drill`
- 当前分支：`lane/mn08-ops-preflight-recovery-drill`
- `git status --short` 为空（干净工作树）

如果是 lane 内部自动化/cron 触发，建议显式传入：

- `EXPECTED_WORKTREE_ROOT`
- `EXPECTED_BRANCH_REF`
- `EXPECTED_HEAD`（建议默认带上；这样可把“同 worktree / 同分支但 HEAD 已漂移”的情况也 fail-closed 掉）

其中 `EXPECTED_BRANCH_REF` 可以写成短分支名（如 `lane/mn08-ops-preflight-recovery-drill`）或完整 ref（如 `refs/heads/lane/mn08-ops-preflight-recovery-drill`）；脚本会统一规范化为 `refs/heads/*` 后再校验。

这样脚本会在 worktree、branch、HEAD 任一不匹配时直接失败，而不是在错误 worktree 上误做恢复演练。

## 标准恢复演练

### 1) 单独执行 restart-recovery drill

```bash
cd /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN08-ops-preflight-recovery-drill/trillionnium
EXPECTED_HEAD="$(git rev-parse HEAD)" \
EXPECTED_WORKTREE_ROOT=/Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN08-ops-preflight-recovery-drill \
EXPECTED_BRANCH_REF=lane/mn08-ops-preflight-recovery-drill \
RUNS=3 \
./scripts/check_bft_restart_recovery.sh
```

如果是 supervisor / cron 已经分配了固定 commit，优先直接把该 SHA 写进 `EXPECTED_HEAD`；不要依赖人工复制当前终端里的 `git rev-parse HEAD` 结果。

预期结果：

- 标准输出最后一行形如：

```text
[OK] bft restart recovery passed: /.../run/bft-restart-recovery-<timestamp>.txt
```

- 生成的 PASS 报告会记录：
  - `git_worktree_root`
  - `git_branch_ref`
  - `git_head`
  - `replay_command`
  - `rollback_command`
  - `pre_log_glob` / `post_log_glob`

### 2) 执行完整 preflight（含 restart-recovery drill）

```bash
cd /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN08-ops-preflight-recovery-drill/trillionnium
EXPECTED_HEAD="$(git rev-parse HEAD)" \
EXPECTED_WORKTREE_ROOT=/Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN08-ops-preflight-recovery-drill \
EXPECTED_BRANCH_REF=lane/mn08-ops-preflight-recovery-drill \
RECOVERY_RUNS=1 \
./scripts/testnet_preflight.sh
```

该路径会额外执行：

- shell 语法检查
- workspace tests
- parallel sanity
- devnet + state-root audit
- quick benchmark matrix

成功后生成的 `run/preflight/go-no-go-<timestamp>.txt` 现在会显式记录 `recovery_report=`，便于直接跳转到对应的 restart-recovery PASS 报告，而不用再按时间戳猜最新文件。

适合做 lane 级预演，不适合当作最小 smoke replacement。

## 审计与回放

两类脚本都输出 **可回放命令** 与 **可回滚命令**：

- `replay_command`：用于在相同 lane 绑定条件下重跑演练
- `rollback_command`：用于删除本次演练产生的 report / WAL / 日志等临时工件

建议复盘时直接从报告中提取，而不是手写路径；脚本产出的 `replay_command=` 会保留规范化后的 lane 绑定参数（含 `refs/heads/*` 形式的分支 ref）：

```bash
report="run/bft-restart-recovery-<timestamp>.txt"
awk -F= '/^replay_command=/ { sub(/^replay_command=/, ""); print; exit }' "$report"
awk -F= '/^rollback_command=/ { sub(/^rollback_command=/, ""); print; exit }' "$report"
```

如果要清理本次演练工件，优先执行报告里的 `rollback_command`，避免遗漏 `pre/post` 日志或 WAL 目录。

## 最小验证

```bash
cd trillionnium
cargo test -p trnm-state -p trnm-node
```

关键测试：

- `trnm-state`:
  - `wal_checkpoint_verification_picks_latest_valid`
  - `wal_checkpoint_verification_falls_back_on_chain_break`
- `trnm-node`:
  - `recover_truncates_to_latest_valid_checkpoint`

## 失败分流

- **worktree / branch 不匹配**：先修正到正确 lane，再重跑；不要在错误 worktree 里“顺手验证”。
- **dirty worktree**：先清理或另开干净 worktree；恢复演练必须是 clean-tree rehearsal。
- **缺少 PASS 报告**：本轮结果不可作为审计证据，应视为失败。
- **日志中出现 `apply_error` 或 `rollback=true`**：说明恢复后执行路径不干净，不能进入更高一级的 preflight 结论。
- **metadata-only recovery**：当前实现仍 fail-closed；需要 fresh `--bft-wal-dir` 或后续补全 state snapshot + replay 能力。

## 兼容性说明

- 未移除原 `consensus-wal.toml`，现有 gate / 脚本可继续读取恢复指针。
- 新增元数据与 checkpoint 文件是增强路径，不改变原共识模拟主流程。
- 本文新增的是 operator reproducibility / audit guidance，不改变运行时代码路径。
