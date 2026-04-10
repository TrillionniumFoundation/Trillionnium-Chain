# TRNM Validator / Operator Release Handoff Template — 2026-03-26

适用范围：validator/operator 的内部 rehearsal、release handoff、升级窗口准备。

目标：借鉴 Cosmos / CometBFT 的运维纪律，把**谁在什么 worktree / branch / commit 上，用哪份二进制、哪组配置、按什么回滚入口执行**一次性交代清楚，减少 handoff 口径漂移。

> 这是一份 fail-closed 模板：字段缺失时，不应把本轮状态描述成 release-ready。

---

## 1. Run identity（先固定身份，再跑动作）

在任何 bring-up、滚动升级、validator handoff 之前，先固定本次运行身份：

```text
operator_id=
window_type=rehearsal|upgrade|rollback|handoff
change_ticket=
started_at_utc=
worktree_root=
workspace_root=
branch=
branch_ref=
head_sha=
commit_short=
worktree_status=clean|dirty
```

最低要求：
- `worktree_root` / `workspace_root` 说明证据来自哪棵树；
- `branch_ref` / `head_sha` 说明不是“某条大概的分支”，而是精确引用；
- `worktree_status=dirty` 时，必须把 dirty 口径明确列为风险项，不能省略。

推荐先执行：

```bash
./scripts/v2/collect_release_operator_preflight.sh \
  --operator-id "$OPERATOR_ID" \
  --window-type "$WINDOW_TYPE" \
  --change-ticket "$CHANGE_TICKET" \
  --started-at-utc "$STARTED_AT_UTC" \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF" \
  --expected-head "$EXPECTED_HEAD" \
  --previous-stable-anchor "$PREVIOUS_STABLE_ANCHOR" \
  --rollback-entrypoint "$ROLLBACK_ENTRYPOINT"
```

该脚本会直接输出 `operator_id/window_type/change_ticket/started_at_utc`，避免 handoff 记录最前面的运行身份字段靠手工补写时遗漏。

同时建议把 helper 输出直接 tee 到可审计文件，避免 handoff 字段靠终端回看或手工二次整理：

```bash
mkdir -p trillionnium/run/preflight
./scripts/v2/collect_release_operator_preflight.sh \
  --operator-id "$OPERATOR_ID" \
  --window-type "$WINDOW_TYPE" \
  --change-ticket "$CHANGE_TICKET" \
  --started-at-utc "$STARTED_AT_UTC" \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF" \
  --expected-head "$EXPECTED_HEAD" \
  --previous-stable-anchor "$PREVIOUS_STABLE_ANCHOR" \
  --rollback-entrypoint "$ROLLBACK_ENTRYPOINT" \
  | tee "trillionnium/run/preflight/operator-preflight-${STARTED_AT_UTC:-$(date -u +%Y%m%dT%H%M%SZ)}.txt"
```

如果只是先做 fail-closed 身份校验、暂时还不生成完整 handoff 记录，可先单独运行：

```bash
./scripts/v2/verify_lane_worktree.sh \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF" \
  --expected-head "$EXPECTED_HEAD"
```

约束说明：
- `verify_lane_worktree.sh` 的分支参数仍是二选一：这里优先传 `--expected-branch-ref`，不要把“短分支名看起来对”误当成 handoff 证据已绑定完成；
- `collect_release_operator_preflight.sh` 为了兼容上游调用，**可以**同时接收 `--expected-branch` 与 `--expected-branch-ref`，但两者必须归一到同一条 `refs/heads/...`；若不一致会直接 fail-closed；
- 对 handoff / release runbook，仍以 `--expected-branch-ref` 作为主口径，避免不同 worktree 里只凭短分支名目测；
- `EXPECTED_BRANCH_REF` 优先使用完整 `refs/heads/...` 形式，不要只靠短分支名目测；
- `EXPECTED_HEAD` 应来自本轮准备交接/升级的那次实际提交，而不是“当前大概最新”的 commit；
- 任一比较失败时，应立即把本轮标记为 `worktree mismatch` / `handoff blocked`，不要继续补跑 smoke 或收集 release 证据。

---

## 2. Binary binding（节点二进制与 CLI 二进制分别绑定）

Cosmos 风格运维里，最怕的是“节点跑的是 A，操作员查询/提交用的是 B，但 handoff 里把它们写成同一份构建”。

因此 `trnm-node` 与 `trnm-cli` 必须分别记录：

```text
binary_path=
binary_sha256=
build_command=
cli_binary_path=
cli_binary_sha256=
cli_build_command=
```

最低要求：
- 节点进程版本和 CLI 版本分开写；
- 如果 CLI 未构建，明确写 `<not-built>`，不要留空；
- `binary_path` / `cli_binary_path` 应记录为 worktree 内可复现的绝对路径，避免相对路径受当前 shell 目录影响；
- handoff 接收方必须能据此在本地重建同一份二进制指纹。

---

## 3. Validator set / config binding（把配置也钉住）

对于 validator/operator release discipline，配置与二进制同等重要。至少固定：

```text
config_set_id=
chain_id=
genesis_sha256=
validator_count=
seed_mode=static|dynamic|mixed
p2p_allowlist_source=
node1_config_sha256=
node2_config_sha256=
node3_config_sha256=
node4_config_sha256=
```

如果本轮未启用某个节点，明确写：

```text
node4_config_sha256=<not-used>
```

建议命令：

```bash
cd trillionnium
for f in configs/node1.toml configs/node2.toml configs/node3.toml configs/node4.toml; do
  if [[ -f "$f" ]]; then
    shasum -a 256 "$f"
  fi
done
```

记录目的：
- 防止“同一份 smoke 证据”被错误复用到另一组 validator 配置；
- 防止 rehearsal / testnet / day-1 launch 使用了不同 `chain_id` 或 genesis，但 handoff 仍被口头描述成“同一轮”；
- 防止 peer / seed / 端口变更后，handoff 文本仍沿用旧指纹。

---

## 4. Pre-window checklist（升级窗口前）

进入 release / rehearsal 窗口前，至少确认：

- 已验证当前 worktree 与 lane branch 匹配；
- 已记录 `previous_stable_anchor`；
- 已指定 `rollback_entrypoint`；
- 已记录本轮使用的 `trnm-node` / `trnm-cli` 二进制指纹；
- 已记录 validator 配置指纹，以及 `chain_id` / `genesis_sha256`；
- 已明确窗口角色：rehearsal / upgrade / rollback / handoff；
- 已明确谁是执行者、谁是观察者、谁有 rollback 决策权。

建议附加角色模板：

```text
executor=
observer=
rollback_owner=
release_owner=
```

---

## 5. During-window evidence（窗口中要留什么证据）

最少保留以下原始事实：

```text
upgrade_started_at_utc=
first_new_binary_pid=
first_new_binary_log_path=
height_before=
height_after=
commit_events_observed=
apply_error_seen=yes|no
rollback_seen=yes|no
```

若是多节点滚动升级，按节点单列：

```text
node1_status=done|rolled-back|skipped
node1_height_before=
node1_height_after=
node1_log=
node1_binary_sha256=
```

判断口径：
- 出现 `apply_error` 或非预期 `rollback=true`，本轮不能描述成成功升级；
- 若任何节点未完成证据绑定，就不能写“全体 validator 已完成 handoff”。

---

## 6. Rollback discipline（回滚纪律）

回滚描述必须能回答三件事：

```text
previous_stable_anchor=
rollback_entrypoint=
rollback_trigger=
```

其中：
- `previous_stable_anchor`：回到哪个 commit/tag；
- `rollback_entrypoint`：通过哪条脚本/命令回滚；
- `rollback_trigger`：为什么回滚，例如 `apply_error`、height stall、config drift、binary mismatch。

推荐把触发原因限定成简洁标签，避免事后口径发散：

```text
rollback_trigger=apply_error|height_stall|config_drift|binary_mismatch|operator_abort
```

---

## 7. Handoff minimum payload（交接最小载荷）

handoff 给下一位 operator / release owner 时，至少附：

```text
branch_ref=
head_sha=
worktree_root=
workspace_root=
binary_sha256=
cli_binary_sha256=
config_set_id=
previous_stable_anchor=
rollback_entrypoint=
window_outcome=pass|blocked|rolled-back
```

若 `window_outcome != pass`，必须再附：

```text
blocker_summary=
next_safe_action=
```

推荐 `next_safe_action` 只写下一步可执行动作，不写泛泛建议。例如：
- `rebuild trnm-cli from current head and re-run preflight capture`
- `restore previous stable anchor and re-check validator config hashes`

---

## 8. Copy/paste skeleton

```text
operator_id=
window_type=
change_ticket=
started_at_utc=
worktree_root=
workspace_root=
branch=
branch_ref=
head_sha=
commit_short=
worktree_status=

binary_path=
binary_sha256=
build_command=
cli_binary_path=
cli_binary_sha256=
cli_build_command=

config_set_id=
chain_id=
genesis_sha256=
validator_count=
seed_mode=
p2p_allowlist_source=
node1_config_sha256=
node2_config_sha256=
node3_config_sha256=
node4_config_sha256=

executor=
observer=
rollback_owner=
release_owner=

height_before=
height_after=
commit_events_observed=
apply_error_seen=
rollback_seen=

previous_stable_anchor=
rollback_entrypoint=
rollback_trigger=

window_outcome=
blocker_summary=
next_safe_action=
```

---

## 9. Safe-use note

这份模板的目的不是制造更多 paperwork，而是把 release/operator 证据从“口头说明”升级为“可回放、可归因、可回滚”的结构化 handoff。

只要以下任一项缺失，就不要使用“release-ready”“validator handoff complete”“upgrade finished”之类表述：

- worktree/branch/head 未绑定；
- `trnm-node` / `trnm-cli` 二进制未分开绑定；
- validator 配置指纹未记录；
- previous stable anchor / rollback entrypoint 未记录；
- 窗口结果没有附上 blocker 或下一步安全动作。
