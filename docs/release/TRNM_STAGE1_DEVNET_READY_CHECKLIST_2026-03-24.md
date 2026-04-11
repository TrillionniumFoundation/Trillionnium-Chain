# TRNM Stage-1 Devnet Ready Checklist (Internal) — 2026-03-24

适用范围：内部 devnet bring-up / smoke / evidence 收口，**不是** public release-ready 声明。

当前提交：`909a0c682` (`main`)

## 结论

**结论：可视为“接近 internal devnet-ready”，但还不是 RC-ready。**

原因：
- 最小 4 节点 BFT smoke 已通过，可作为 stage-1 bring-up 正向证据；
- 敏感 crate 的 test inventory 已刷新，可用于后续 gate 收口；
- 但仓库当前仍有大规模 dirty tree（`git status --short` 共 **411** 条，其中 **409** 条在 `trillionnium/` 下），因此**不能**把当前工作树直接当作稳定 RC 候选。

## Stage-1 的最小通过定义

内部 devnet-ready 的最低门槛建议收敛为以下 7 项：

1. **工作区身份固定**
   - 记录 `git branch --show-current`
   - 记录 `git rev-parse --short HEAD`
   - 记录 dirty/clean 状态
   - 目的：避免“在什么树上跑出来的”说不清。

2. **最小 bring-up 路径可执行**
   - 3 节点本地 bring-up：`trillionnium/scripts/devnet_up.sh`
   - 3 节点停止：`trillionnium/scripts/devnet_down.sh`
   - 说明：这是最短路径；仅依赖 `configs/node{1,2,3}.toml` 与 `trnm-node`。

3. **BFT 4 节点 smoke 通过**
   - 命令：`trillionnium/scripts/check_bft_4node_smoke.sh`
   - 通过标准：每个节点都出现 commit 事件与 committed-height 统计，且没有 `apply_error` / `rollback=true`。

4. **状态一致性 / state-root 审计路径存在**
   - RC 脚本已把 `audit_state_roots.sh` 纳入主链路；
   - stage-1 阶段至少要确认这条脚本路径存在，且后续可挂到更完整 RC rehearsal。

5. **关键 crate 测试面固定**
   - 至少为 `trnm-state` / `trnm-rpc` / `trnm-node` / `trnm-pouw` / `trnm-worker-agent` / `trnm-cli` 刷新 test inventory；
   - 用来防止“测试条目在漂移，但门禁只记得旧名字”。

6. **运维预检 / 回滚锚点固定**
   - 记录本次 smoke / rehearsal 使用的分支名、提交短 SHA、构建时间与产物位置；
   - 若使用本地二进制，至少记录 `sha256sum`（或平台等价命令）与生成命令；
   - 若 bring-up / 巡检 / handoff 同时依赖 `trnm-node` 与 `trnm-cli`，两者都要单独记录二进制路径、hash 与 build command，避免“节点进程版本”和“操作员查询/发布工具版本”被误认为同一份构建；
   - 明确上一稳定锚点（上一个已知可恢复的 commit/tag）与回滚入口脚本；
   - 目的：避免出现“跑的是哪一个二进制”和“回退到哪里”说不清。

7. **本地提交门禁与 handoff 口径固定**
   - 对外发布、打 tag、生成 release note 之前，先把本轮证据收敛到一个**本地已提交**的 path-scoped commit；
   - commit message 应明确作用域（例如 `docs(release): ...` / `trnm-node: ...` / `trnm-cli: ...`），避免把 unrelated dirty tree 混进 release 叙事；
   - handoff 至少附上：`branch`、`commit_short`、`binary_sha256`、`previous_stable_anchor`、`rollback_entrypoint`；
   - 若 required tests 未绿，则允许保留本地改动继续修复，但**不得**把该状态描述成 release candidate。

8. **repo hygiene blocker 单独挂牌**
   - dirty tree、历史文档漂移、未归档的大批新增文件，必须单列为 blocker；
   - 不允许因为 smoke 通过，就把整个仓库描述成“release-ready”。

## 操作员预检记录模板（建议每次 rehearsal 都填写）

在执行 bring-up / smoke 前，先固定以下信息：

```text
operator_id=
worktree_root=
workspace_root=
branch=
branch_ref=
head_sha=
commit_short=
worktree_status=clean|dirty
binary_path=
binary_sha256=
build_command=
cli_binary_path=
cli_binary_sha256=
cli_build_command=
previous_stable_anchor=
rollback_entrypoint=
```

最少要求：
- `worktree_root` 与 `workspace_root` 能回答“证据究竟是在哪个 worktree / cargo workspace 里跑出来的”；
- `workspace_root` 必须位于当前 `worktree_root` 之内；若指向别的目录（哪怕是另一个 lane worktree 或外部 checkout），预检脚本应直接 fail-closed，避免把当前 lane 的 branch/commit 与外部构建产物混写进同一份 handoff；
- `branch` / `branch_ref` / `head_sha` 与 `commit_short` 共同固定这次证据绑定的是哪一条 lane 引用与哪一个精确提交，避免只记录短 branch 名后在多 worktree 并行时发生同名误判；
- 预检命令中显式传入 `--expected-branch-ref "refs/heads/$EXPECTED_BRANCH"`，可把“采集到的 branch_ref”与“操作者声称要验证的 refs/heads/... ”绑定到同一条 fail-closed 校验链路，而不是仅靠脚本推导；
- `binary_sha256` 与 `build_command` 能回答“这次跑的到底是哪一个 `trnm-node` 构建”；
- 若本轮使用 `trnm-cli` 做查询 / handoff / 预检，则 `cli_binary_sha256` 与 `cli_build_command` 必须能回答“操作员看到的结果来自哪一个 CLI 构建”；
- `previous_stable_anchor` 与 `rollback_entrypoint` 能回答“失败后退回哪里、怎么退”。

建议把上述字段做成一次性预检采集，避免手填时漏项或把不同 worktree 的值抄混。优先直接使用脚本：`scripts/v2/collect_release_operator_preflight.sh`

```bash
./scripts/v2/collect_release_operator_preflight.sh \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch "$EXPECTED_BRANCH" \
  --expected-branch-ref "refs/heads/$EXPECTED_BRANCH" \
  --expected-head "$EXPECTED_HEAD" \
  --previous-stable-anchor "${PREVIOUS_STABLE_ANCHOR:-<fill-me>}" \
  --rollback-entrypoint "${ROLLBACK_ENTRYPOINT:-./scripts/devnet_down.sh}"
```

若只想人工理解脚本采集了哪些字段，可参考它的等价展开：

```bash
cd trillionnium
WORKTREE_ROOT="$(git rev-parse --show-toplevel)"
WORKSPACE_ROOT="$(pwd)"
printf 'operator_id=%s\n' "${OPERATOR_ID:-<fill-me>}"
printf 'worktree_root=%s\n' "$WORKTREE_ROOT"
printf 'workspace_root=%s\n' "$WORKSPACE_ROOT"
CURRENT_BRANCH="$(git branch --show-current)"
CURRENT_HEAD="$(git rev-parse HEAD)"
test -n "$CURRENT_BRANCH"
printf 'branch=%s\n' "$CURRENT_BRANCH"
printf 'branch_ref=%s\n' "refs/heads/$CURRENT_BRANCH"
printf 'head_sha=%s\n' "$CURRENT_HEAD"
printf 'commit_short=%s\n' "${CURRENT_HEAD:0:9}"
printf 'worktree_status=%s\n' "$(test -z "$(git status --short)" && echo clean || echo dirty)"
printf 'binary_path=%s\n' "$WORKSPACE_ROOT/target/debug/trnm-node"
printf 'build_command=%s\n' 'cargo build -p trnm-node'
shasum -a 256 target/debug/trnm-node | awk '{printf "binary_sha256=%s\n", $1}'
printf 'cli_binary_path=%s\n' "$WORKSPACE_ROOT/target/debug/trnm-cli"
printf 'cli_build_command=%s\n' 'cargo build -p trnm-cli'
if [[ -x target/debug/trnm-cli ]]; then
  shasum -a 256 target/debug/trnm-cli | awk '{printf "cli_binary_sha256=%s\n", $1}'
else
  printf 'cli_binary_sha256=%s\n' '<not-built>'
fi
printf 'previous_stable_anchor=%s\n' "${PREVIOUS_STABLE_ANCHOR:-<fill-me>}"
printf 'rollback_entrypoint=%s\n' "${ROLLBACK_ENTRYPOINT:-./scripts/devnet_down.sh}"
```

若本轮涉及 validator 配置或 peer 变更，额外固定配置指纹，避免 smoke 证据与实际 bring-up 配置脱钩：

```bash
cd trillionnium
for f in configs/node1.toml configs/node2.toml configs/node3.toml configs/node4.toml; do
  shasum -a 256 "$f"
done
```

建议把输出直接附到 rehearsal/evidence 记录中；这样至少能回答三件事：
1. 本轮是哪个操作员、在哪个 worktree/workspace/branch/commit 上执行；
2. 实际启动的是哪一个 `trnm-node` 二进制；
3. 参与 bring-up 的节点配置是否与证据记录一致。

若仓库同时存在多个 lane worktree，建议在正式 bring-up 前先做一次 fail-closed 预检，避免把别的 worktree 的 branch/commit/binary 误抄到当前证据。**预期 worktree root 与预期 lane branch 必须同时固定**，若本轮要固化证据，还应把预期 `HEAD` 一并钉住。`verify_lane_worktree.sh` 统一使用 `--expected-branch-ref`（可传短分支名或完整 `refs/heads/...`，脚本会规范化并 fail-closed 校验）；不要把别的 helper 支持的 `--expected-branch` 口径误套到这里。对 handoff / release 证据，优先固定完整 `refs/heads/...` 形式：

```bash
EXPECTED_WORKTREE_ROOT="/absolute/path/to/this/worktree"
EXPECTED_BRANCH="lane/refXX-scope-name"
EXPECTED_BRANCH_REF="refs/heads/$EXPECTED_BRANCH"
EXPECTED_HEAD="$(git -C "$EXPECTED_WORKTREE_ROOT" rev-parse HEAD)"
cd "$EXPECTED_WORKTREE_ROOT"
./scripts/v2/verify_lane_worktree.sh \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF" \
  --expected-head "$EXPECTED_HEAD"
```

脚本位置：`scripts/v2/verify_lane_worktree.sh`

若只需要人工 spot-check，也至少保留以下原始命令输出到 evidence：

```bash
pwd
git rev-parse --show-toplevel
git branch --show-current
git rev-parse HEAD
```

对 lane worktree，建议把**期望路径与期望分支**直接写进本轮命令，避免仅靠人工比对输出：

```bash
EXPECTED_WORKTREE_ROOT="/absolute/path/to/this/worktree"
EXPECTED_BRANCH="lane/refXX-scope-name"
test "$(pwd)" = "$EXPECTED_WORKTREE_ROOT"
test "$(git rev-parse --show-toplevel)" = "$EXPECTED_WORKTREE_ROOT"
test "$(git branch --show-current)" = "$EXPECTED_BRANCH"
```

只要任一比较失败，就应立即停止当前 bring-up / smoke / release 证据收集，并把这次运行标记为 **worktree mismatch**，不要继续补跑后续门禁。

对于 lane 化运行，建议把 `EXPECTED_WORKTREE_ROOT` / `EXPECTED_BRANCH` / `EXPECTED_HEAD` 作为 runbook 参数或环境变量显式传入，而不是依赖人工目测当前 shell 提示符；这样在多 worktree 并行时可以更稳地 fail-closed，也能避免把别的 worktree 的 commit 误记成当前 bring-up 证据。 

## 最小 bring-up 路径

在仓库根目录下：

```bash
cd trillionnium
./scripts/devnet_up.sh
# 查看日志
ls run/node{1,2,3}.log
./scripts/devnet_down.sh
```

默认参数（可由环境变量覆盖）：
- node1: `block-ms=500`, `max-blocks=5`
- node2: `block-ms=700`, `max-blocks=5`
- node3: `block-ms=900`, `max-blocks=5`

默认配置文件：
- `configs/node1.toml` → `127.0.0.1:26657`
- `configs/node2.toml` → `127.0.0.1:27657`
- `configs/node3.toml` → `127.0.0.1:28657`
- 4 节点 smoke 额外使用 `configs/node4.toml` → `127.0.0.1:29657`

## 本轮已刷新证据

### 1) 4 节点 BFT smoke

已执行：

```bash
cd trillionnium
./scripts/check_bft_4node_smoke.sh
```

结果：**PASS**

证据文件：
- `trillionnium/run/bft4-smoke-20260324-163130.txt`
- `trillionnium/run/bft4-node1-20260324-163130.log`
- `trillionnium/run/bft4-node2-20260324-163130.log`
- `trillionnium/run/bft4-node3-20260324-163130.log`
- `trillionnium/run/bft4-node4-20260324-163130.log`

摘要：
- node1 commit events = 4
- node2 commit events = 4
- node3 commit events = 4
- node4 commit events = 4
- 未见 `apply_error` / `rollback=true`

### 2) 敏感 crate 测试 inventory

已刷新到：`trillionnium/artifacts/devnet-ready/testlists/`

| crate | lines |
|---|---:|
| `trnm-state` | 521 |
| `trnm-rpc` | 460 |
| `trnm-node` | 263 |
| `trnm-pouw` | 906 |
| `trnm-worker-agent` | 177 |
| `trnm-cli` | 66 |
| **total** | **2393** |

说明：这些 `.list` 文件来自 `cargo test -p <crate> -- --list`，用于固定当前测试面，而不是宣称全部已执行通过。

## 当前 blocker（阻止提升为 RC-ready）

### Blocker A — 工作树严重不洁

`git status --short` 当前共 **411** 条变更：
- `BACKLOG.md`: 1
- `ROADMAP.md`: 1
- `trillionnium`: 409

证据文件：
- `docs/archive/devnet-ready-history/repo-hygiene-2026-03-24.json`

含义：
- 当前可做 stage-1 bring-up / smoke / inventory；
- **不适合**直接把这棵树作为 release candidate 或对外口径 truth source。

### Blocker B — release/readiness truth-source 仍需与当前树继续对齐

已有 `RELEASE_READINESS.md` 明确禁止把历史 evidence 误读为“当前全仓已发布就绪”；
但当前 dirty tree 和大量新增/拆分文件意味着：
- 现有 truth-source 只足够说明“不能夸大”；
- 还不足以说明“当前这一棵树已收口为稳定 RC”。

### Blocker C — 完整 RC rehearsal 尚未重新跑完

本轮没有执行完整：
- `trillionnium/scripts/run_local_release_evidence.sh`
- `trillionnium/scripts/release_rc.sh`

原因不是脚本不存在，而是当前 dirty tree 规模过大，先做它们会把“局部 smoke 绿”误包装成“整仓 RC 绿”。

## 建议的后续顺序

1. 先冻结/清理 dirty tree，至少做到 path-scoped clean；
2. 在 clean tree 上重复：
   - `./scripts/check_bft_4node_smoke.sh`
   - `./scripts/check_query_audit_smoke.sh`
   - `cargo test -p trnm-state --lib -- --test-threads=1`
   - `cargo test -p trnm-rpc --lib -- --test-threads=1`
3. 再执行：
   - `./scripts/run_local_release_evidence.sh`
   - `./scripts/release_rc.sh`
4. 最后更新 `RELEASE_READINESS.md` 结论段，而不是反过来。

## 操作员命令口径（避免路径歧义）

为避免在仓库根目录与 `trillionnium/` 工作区之间切换时误跑命令，建议固定如下口径：

- 若当前目录是仓库根：

```bash
cd trillionnium
cargo test -p trnm-node -- --test-threads=1
cargo test -p trnm-cli -- --test-threads=1
```

- 若当前目录已经是 `trillionnium/`：直接执行同样的 `cargo test -p ...` 命令即可。

- 在证据或 runbook 中记录命令时，优先保留**执行目录 + 原始命令**，避免事后无法判断 `cargo` 是在哪个 workspace 下运行。

## 回滚

本轮仅新增文档/工件索引；若需回滚：

```bash
git checkout -- docs/release/TRNM_STAGE1_DEVNET_READY_CHECKLIST_2026-03-24.md trillionnium/artifacts/devnet-ready docs/archive/devnet-ready-history
```
