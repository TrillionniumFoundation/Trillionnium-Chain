# Local Release Evidence Runbook

## 单命令生成证据包

在 `trillionnium` 子仓库根目录执行：

```bash
./scripts/run_local_release_evidence.sh
```

脚本会串联以下检查：

> 注意：该脚本生成的是 **release evidence bundle**，不是“必定通过”的绿色证明。任一步骤失败时，脚本会 **fail-closed**，并在 `summary.txt` 中把对应步骤记为 `FAIL(...)`；是否可用于当前 release/readiness 判断，必须结合仓库根 `RELEASE_READINESS.md` 与本次 `summary.txt` 一起看。

1. `cargo test`（关键包：`trnm-node` / `trnm-worker-agent` / `trnm-rpc` / `trnm-pouw` / `trnm-state`）
2. `scripts/check_request_tx_binding.sh`
3. `scripts/run_request_fault_injection.sh`
4. challenge reexec 入口（必跑；优先使用 `TRNM_CHALLENGE_REEXEC_ENTRY` 显式固定入口，否则按脚本内置候选列表做确定性解析；若仍无法解析到入口则直接记为 FAIL）

输出目录统一为：

- `run/health/evidence-<timestamp>/`
- 汇总文件：`run/health/evidence-<timestamp>/summary.txt`
- 各步骤日志：`*.log`
- 子脚本证据文件（例如 `request-tx-binding-*.txt`、`request-fault-injection-*.txt`）

判读规则：
- `summary.txt` 是本次证据包的**唯一汇总入口**。
- 只要任一步骤记为 `FAIL(...)`，本次证据包就只能作为失败/差距留痕，**不能**被表述为“当前 release-ready 证明”。
- 若需要引用历史成功证据，必须明确它是历史轮次产物，不能覆盖当前 truth-source。

可选：通过 `OUT_DIR` 指定证据根目录：

```bash
OUT_DIR=/tmp/trnm-evidence ./scripts/run_local_release_evidence.sh
```

## Operator handoff / 引用纪律清单

在把本地证据包交给 validator/operator/release reviewer 之前，先按下面清单逐项确认：

0. **先确认 worktree / branch / commit 身份，再引用任何 evidence 字段。**
   - 运行：`git rev-parse --show-toplevel && git branch --show-current && git rev-parse HEAD && git status --short && git worktree list --porcelain`
   - `git rev-parse --show-toplevel` 必须与本次演练目标 worktree 一致。
   - `git branch --show-current` 不能为空；若为空，按 detached HEAD 处理，直接视为 **No-Go**，不要继续把 `summary.txt` 当成可交接证据。
   - `summary.txt` 中的 `git_worktree_branch_ref=` 若为 `<detached-or-unbound>`，同样按 **No-Go** 处理；先解释 worktree 绑定异常，再讨论其他日志。
   - `git status --short` 非空时，只能把本轮证据当作脏树留痕，不能口述成 clean-tree release evidence。
   - 若本轮由 lane/supervisor 指定了**固定 worktree 路径 + 固定 branch ref**，不要靠 shell prompt 目测；优先复用共享的 fail-closed helper：

```bash
EXPECTED_WORKTREE_ROOT="/abs/path/from-ticket-or-lane"
EXPECTED_BRANCH_REF="refs/heads/lane/assigned-branch"
EXPECTED_HEAD=""

./scripts/v2/verify_lane_worktree.sh \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF" \
  ${EXPECTED_HEAD:+--expected-head "$EXPECTED_HEAD"}
```

   - 若在 air-gapped/debugging 场景下必须手写断言块，再退回到等价的原始 shell 断言；默认不要复制/改写该 helper 的逻辑，以免 runbook 与脚本漂移。

   - 只有在上述断言通过后，才开始 `./scripts/run_local_release_evidence.sh` / `./scripts/release_rc.sh`，避免把错误 worktree 上生成的 artifact 误交接给 validator/operator。

1. **先看 `summary.txt` / `manifest.txt`，不要凭终端滚屏口述结论。**
   - local evidence 以 `summary.txt` 为唯一汇总入口。
   - RC rehearsal 以 `manifest.txt` 为审计入口；必要时再展开对应 `*.log`。
2. **先看 `result=` / `pass_count=` / `fail_count=`，再看单项日志。**
   - 只要出现任意 `FAIL(...)`，本轮就只能算失败留痕，不能表述成当前 release-ready 证据。
3. **引用命令时优先复制脚本产出的 `replay_command=` / `rollback_command=`。**
   - 不要手工重写成“差不多一样”的命令，避免漏掉 deterministic 前缀、`OUT_DIR`、或固定的 `TRNM_CHALLENGE_REEXEC_ENTRY`。
4. **把历史证据和当前 truth-source 明确分开。**
   - `historical_evidence_only=true` 表示它只能证明“这轮本地/历史演练发生过什么”，不能替代仓库根 `RELEASE_READINESS.md` 的当前结论。
5. **交接时至少带上 4 个锚点字段。**
   - `git_branch=`
   - `git_head=`
   - `generated_at=`
   - `truth_source=`

推荐交接口径：

> “本次证据包/RC manifest 仅说明该分支在该时间点、该环境下的本地演练结果；当前是否可发布，仍以 `truth_source=` 指向的 `RELEASE_READINESS.md` 为准。”

这条口径的目的，是把 Cosmos/CometBFT 式的 validator/operator handoff 做到 **可审计、可复放、可回滚**，避免“终端看起来绿过一次”就被误转述成 release 结论。

## RC 复现与回滚留痕（M3）

为减少“同命令不同结果”的波动，建议在采集证据前固定环境，并优先使用与 `RELEASE_READINESS.md` 一致的 deterministic 前缀：

```bash
env TZ=UTC LC_ALL=C LANG=C SOURCE_DATE_EPOCH=1704067200 \
  CARGO_TERM_COLOR=never \
  RUST_BACKTRACE=1 \
  CARGO_BUILD_JOBS=1 \
  ./scripts/run_local_release_evidence.sh
```

如需二次复跑比对，请保持命令与环境完全一致，再连续执行一次相同命令，避免把一次性绿灯误判为稳定 release 证据。

执行完成后，`summary.txt` 末尾至少应包含以下字段（由脚本生成时，直接以生成值为准，不要手工改写）：

> 说明：`env_*` 记录的是**本次实际执行时生效的环境**，因此如果调用者在外层 shell 已经导出了某个变量（例如 `LANG=zh_CN.UTF-8`），这里会如实保留该值；`replay_env_*` 才是脚本写入的**确定性复放基线**。做 RC 复放、审计引用或文档摘录时，应优先引用 `replay_env_*` 与 `replay_command=`，不要把一次性本地继承环境误写成可复放标准环境。

- 本次证据目录绝对路径：`evidence_dir=<abs-path>`
- 复放输出根目录：`replay_out_dir=<abs-path>`（应为固定、可审计的绝对路径；`replay_command=` 中的 `OUT_DIR` 应与之对应）
- 生成该证据包的分支与提交：`git_branch=<branch>` / `git_head=<sha>`
- UTC 时间戳：`generated_at=<utc-ts>`
- 实际覆盖环境：`env_trnm_challenge_reexec_entry=<value|<unset>>`
- 复放环境：`replay_env_trnm_challenge_reexec_entry=<resolved-entry-absolute-path>`；若本轮未解析到入口，则显式记为 `<entry_not_found>`，不要保留待定占位符；文档引用时也必须原样保留该 sentinel，不能省略或改写成“待补”。
- 解析后的入口：`challenge_reexec_entry=<resolved-entry-absolute-path>`；若未解析到入口，同样显式记为 `<entry_not_found>`，便于失败证据审计；不要把缺口手工润色成模糊描述。
- 复放命令：优先直接引用 `replay_command=` 字段；若需说明其结构，应是包含 deterministic 前缀、`OUT_DIR` 与固定 `TRNM_CHALLENGE_REEXEC_ENTRY` 的单行命令，例如：`env TZ=UTC LC_ALL=C LANG=C SOURCE_DATE_EPOCH=1704067200 CARGO_TERM_COLOR=never RUST_BACKTRACE=1 CARGO_BUILD_JOBS=1 OUT_DIR='<evidence-root>' TRNM_CHALLENGE_REEXEC_ENTRY='<resolved-entry-absolute-path>' ./scripts/run_local_release_evidence.sh`
- 回滚命令：`rollback_command=rm -rf <evidence_dir>`（仅删除本次生成目录）

若直接引用脚本生成的 `summary.txt`，应以其中的 `replay_command=` 字段为准；不要手写成缺少 deterministic 前缀、缺少 `OUT_DIR`、或缺少 `TRNM_CHALLENGE_REEXEC_ENTRY` 固定值的裸命令，避免把不可复现的本地环境差异带进 RC 证据链。

## RC manifest 对齐要求

`./scripts/release_rc.sh` 生成的 `release/rc-*/manifest.txt` 也应保持与本页一致的可复放字段，至少包括：

- 当前 truth-source 指针（`truth_source=`，应指向仓库根 `RELEASE_READINESS.md`）
- 历史证据边界声明（例如 `historical_evidence_only=true`、`evidence_scope=local_rc_rehearsal_not_current_release_ready_claim`）
- 实际执行时生效的 deterministic 环境（`env_*`）
- 建议复放环境（`replay_env_*`）
- 影响 RC 结果的关键执行旋钮（至少 `env_mvp_mode` / `env_allow_missing_resolve_event` / `env_allow_partial_event_replay` / `env_txs` / `env_threshold_profile` 及对应 `replay_env_*`）
- 单行 `replay_command=`（建议包含 deterministic 前缀，并固定 `OUT_DIR='<rc-base-dir>'`，避免 RC 复放时把产物写到不同调用目录下）
- 单行 `rollback_command=`（RC manifest 中应优先回滚 `rc_out_dir` 的绝对路径，而不是依赖调用目录的相对路径）

这样可以避免 RC 证据包只有产物列表、却缺少“如何按同一环境重放”这一关键链路，保证当前 truth-source 与历史/本地证据之间的审计接口一致。
