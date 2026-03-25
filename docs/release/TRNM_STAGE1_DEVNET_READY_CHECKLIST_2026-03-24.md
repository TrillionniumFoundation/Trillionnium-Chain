# TRNM Stage-1 Devnet Ready Checklist (Internal) — 2026-03-24

适用范围：内部 devnet bring-up / smoke / evidence 收口，**不是** public release-ready 声明。

当前提交：`909a0c682` (`main`)

## 结论

**结论：可视为“接近 internal devnet-ready”，但还不是 RC-ready。**

原因：
- 最小 4 节点 BFT smoke 已通过，可作为 stage-1 bring-up 正向证据；
- 敏感 crate 的 test inventory 已刷新，可用于后续 gate 收口；
- 但仓库当前仍有大规模 dirty tree（`git status --short` 共 **411** 条，其中 **409** 条在 `trillionnium-rust/` 下），因此**不能**把当前工作树直接当作稳定 RC 候选。

## Stage-1 的最小通过定义

内部 devnet-ready 的最低门槛建议收敛为以下 7 项：

1. **工作区身份固定**
   - 记录 `git branch --show-current`
   - 记录 `git rev-parse --short HEAD`
   - 记录 dirty/clean 状态
   - 目的：避免“在什么树上跑出来的”说不清。

2. **最小 bring-up 路径可执行**
   - 3 节点本地 bring-up：`trillionnium-rust/scripts/devnet_up.sh`
   - 3 节点停止：`trillionnium-rust/scripts/devnet_down.sh`
   - 说明：这是最短路径；仅依赖 `configs/node{1,2,3}.toml` 与 `trnm-node`。

3. **BFT 4 节点 smoke 通过**
   - 命令：`trillionnium-rust/scripts/check_bft_4node_smoke.sh`
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
   - 明确上一稳定锚点（上一个已知可恢复的 commit/tag）与回滚入口脚本；
   - 目的：避免出现“跑的是哪一个二进制”和“回退到哪里”说不清。

7. **repo hygiene blocker 单独挂牌**
   - dirty tree、历史文档漂移、未归档的大批新增文件，必须单列为 blocker；
   - 不允许因为 smoke 通过，就把整个仓库描述成“release-ready”。

## 操作员预检记录模板（建议每次 rehearsal 都填写）

在执行 bring-up / smoke 前，先固定以下信息：

```text
operator_id=
branch=
commit_short=
worktree_status=clean|dirty
binary_path=
binary_sha256=
build_command=
previous_stable_anchor=
rollback_entrypoint=
```

最少要求：
- `branch` 与 `commit_short` 可直接映射到本次证据；
- `binary_sha256` 与 `build_command` 能回答“这次跑的到底是哪一个构建”；
- `previous_stable_anchor` 与 `rollback_entrypoint` 能回答“失败后退回哪里、怎么退”。

建议把上述字段做成一次性预检采集，避免手填时漏项或把不同 worktree 的值抄混：

```bash
cd trillionnium-rust
printf 'operator_id=%s\n' "${OPERATOR_ID:-<fill-me>}"
printf 'branch=%s\n' "$(git branch --show-current)"
printf 'commit_short=%s\n' "$(git rev-parse --short HEAD)"
printf 'worktree_status=%s\n' "$(test -z "$(git status --short)" && echo clean || echo dirty)"
printf 'binary_path=%s\n' "$(pwd)/target/debug/trnm-node"
printf 'build_command=%s\n' 'cargo build -p trnm-node'
shasum -a 256 target/debug/trnm-node | awk '{printf "binary_sha256=%s\n", $1}'
printf 'previous_stable_anchor=%s\n' "${PREVIOUS_STABLE_ANCHOR:-<fill-me>}"
printf 'rollback_entrypoint=%s\n' "${ROLLBACK_ENTRYPOINT:-./scripts/devnet_down.sh}"
```

若本轮涉及 validator 配置或 peer 变更，额外固定配置指纹，避免 smoke 证据与实际 bring-up 配置脱钩：

```bash
cd trillionnium-rust
for f in configs/node1.toml configs/node2.toml configs/node3.toml configs/node4.toml; do
  shasum -a 256 "$f"
done
```

建议把输出直接附到 rehearsal/evidence 记录中；这样至少能回答三件事：
1. 本轮是哪个操作员、在哪个 worktree/branch/commit 上执行；
2. 实际启动的是哪一个 `trnm-node` 二进制；
3. 参与 bring-up 的节点配置是否与证据记录一致。

## 最小 bring-up 路径

在仓库根目录下：

```bash
cd trillionnium-rust
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
cd trillionnium-rust
./scripts/check_bft_4node_smoke.sh
```

结果：**PASS**

证据文件：
- `trillionnium-rust/run/bft4-smoke-20260324-163130.txt`
- `trillionnium-rust/run/bft4-node1-20260324-163130.log`
- `trillionnium-rust/run/bft4-node2-20260324-163130.log`
- `trillionnium-rust/run/bft4-node3-20260324-163130.log`
- `trillionnium-rust/run/bft4-node4-20260324-163130.log`

摘要：
- node1 commit events = 4
- node2 commit events = 4
- node3 commit events = 4
- node4 commit events = 4
- 未见 `apply_error` / `rollback=true`

### 2) 敏感 crate 测试 inventory

已刷新到：`trillionnium-rust/artifacts/devnet-ready/testlists/`

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
- `trillionnium-rust`: 409

证据文件：
- `artifacts/devnet-ready/repo-hygiene-2026-03-24.json`

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
- `trillionnium-rust/scripts/run_local_release_evidence.sh`
- `trillionnium-rust/scripts/release_rc.sh`

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

为避免在仓库根目录与 `trillionnium-rust/` 工作区之间切换时误跑命令，建议固定如下口径：

- 若当前目录是仓库根：

```bash
cd trillionnium-rust
cargo test -p trnm-node -- --test-threads=1
cargo test -p trnm-cli -- --test-threads=1
```

- 若当前目录已经是 `trillionnium-rust/`：直接执行同样的 `cargo test -p ...` 命令即可。

- 在证据或 runbook 中记录命令时，优先保留**执行目录 + 原始命令**，避免事后无法判断 `cargo` 是在哪个 workspace 下运行。

## 回滚

本轮仅新增文档/工件索引；若需回滚：

```bash
git checkout -- docs/release/TRNM_STAGE1_DEVNET_READY_CHECKLIST_2026-03-24.md trillionnium-rust/artifacts/devnet-ready artifacts/devnet-ready
```
