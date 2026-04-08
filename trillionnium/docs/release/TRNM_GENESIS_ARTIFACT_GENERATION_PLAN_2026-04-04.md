# TRNM Genesis Artifact Generation Plan (2026-04-04)

评估快照：
- `origin/main = 35da4109e`
- 当前工作树 HEAD（本轮原型来源）=`b74758fac`

## 结论

TRNM 当前 repo 中**没有现成已提交的真实 genesis artifact**，也**没有显式暴露的 genesis 生成子命令**。

因此，本轮采用的最小可执行策略是：

> **把 height-1 的零 demo load checkpoint/WAL 证据束，作为当前架构下的 local-rehearsal genesis candidate artifact。**

这不是 public-mainnet genesis closure；
但它已经把“没有 artifact / 没有 hash”推进到了：
- 有一份可引用的 local candidate bundle
- 有一条可复跑的生成路径
- 有一份接上 validator config bundle 的 ceremony packet skeleton

---

## 1. 为什么当前要用 checkpoint/WAL bundle，而不是 `genesis.json`

### 1.1 当前仓里没有已提交的真实 genesis 文件
本轮 artifact discovery 结果是：
- 未找到当前 mainline 可直接使用的 `genesis*.json|toml|yaml` artifact
- 未找到真实 `genesis_artifact_path=` / `genesis_artifact_sha256=` 已落盘值
- `trnm-cli` / `trnm-node` 的 CLI help 里也未暴露 genesis 生成子命令

### 1.2 当前代码对“genesis boundary”的最强结构化锚点，是 height-1 checkpoint/WAL
`trnm-state::CheckpointMeta::evidence_summary()` 已明确把：
- `height == 1` 标记为 `checkpoint_height_boundary_kind=genesis`

同时，`trnm-state` 的 checkpoint/WAL 绑定已经提供：
- `state_root_hex`
- `wal_entry_hash_hex`
- `checkpoint_commitment`
- checkpoint/WAL 的 tuple-hash 绑定语义

这说明：
- 在当前 Rust L1 代码结构里，**height-1 checkpoint + WAL** 比一个 repo 中并不存在的 `genesis.json` 更接近真实的 genesis anchor surface。

---

## 2. 本轮已完成的原型动作

### 2.1 修复 `demo-tasks=0` 语义
本轮先修复了一个真实 blocker：
- 之前 `trnm-node --demo-tasks 0` 仍会强行注入 1 条 demo task；
- 已修复为真正允许零 demo load；
- 并加入最小测试：`build_demo_mempool_respects_zero_demo_tasks`。

本地提交：
- `b74758fac` — `fix(node): honor zero demo tasks for genesis rehearsal`

### 2.2 生成零 demo load 的 height-1 isolated run
已实际运行：

```bash
cargo run -q -p trnm-node -- \
  --config configs/node1.toml \
  --max-blocks 1 \
  --demo-tasks 0 \
  --bft-checkpoint-interval 1 \
  --bft-wal-dir run/genesis-candidate-20260404-b74758fac-log
```

关键结果：
- `[block] ... height=1 txs=0 groups=0 ...`
- `[bft-checkpoint] height=1`
- `state_root = a965ffa8c1777b4cd4009fd1a940fd2fba58fd3faa6dcd3e11655f28b213d46e`
- `wal_entry_hash = 4f8a336dd57a0daaf1051f27362a31d21ecd4604e16076eb28a7e9b181655756`

说明：
- 这次 height-1 anchor 不再被 demo tx 污染；
- 更适合作为当前架构下的 local genesis candidate evidence。

### 2.3 生成并冻结一份 local-rehearsal genesis candidate bundle
已生成：
- bundle tar:
  - `/Users/qianqi/.openclaw/workspace/TrillionniumChain/trillionnium/run/genesis-artifact-candidates/trnm-genesis-candidate-local-rehearsal-2026-04-04-b74758fac.tar.gz`
- SHA256:
  - `0cf37d6ae68baa3ac1af1db89c3b225cf669f072aa3f531681448dbcf995108f`

bundle 内容包括：
- `consensus-checkpoints.toml`
- `consensus-wal-meta.toml`
- `consensus-wal.toml`
- `generation.log`
- `validator-configs/node1.toml .. node4.toml`
- `GENESIS_ARTIFACT_MANIFEST.toml`

### 2.4 生成 local-rehearsal ceremony packet skeleton
已生成：
- `/Users/qianqi/.openclaw/workspace/TrillionniumChain/trillionnium/run/genesis-artifact-candidates/trnm-genesis-candidate-local-rehearsal-2026-04-04-b74758fac.packet.txt`

它已经把以下字段接起来：
- `genesis_artifact_path=`
- `genesis_artifact_sha256=`
- `validator_entry=`（从当前 config bundle 派生）
- `validator_entry_hash=`

仍保留 placeholder 的部分：
- `validator_owner=`
- `operator_contact=`
- `operator_ack=`
- `operator_ack_signature_path=` / `operator_ack_digest=`

这符合当前 scope：**local-rehearsal**，不是 public-mainnet-input。

### 2.5 生成 operator-handoff draft packet
已生成：
- `/Users/qianqi/.openclaw/workspace/TrillionniumChain/trillionnium/run/genesis-artifact-candidates/trnm-genesis-candidate-operator-handoff-draft-2026-04-04-b74758fac.packet.txt`

它复用了同一份 candidate bundle 与 SHA256，但把 ceremony scope 提升到 **operator-handoff**，用于下一步补齐：
- `validator_owner=`
- `operator_contact=`
- `operator_ack=`
- `operator_ack_signature_path=` / `operator_ack_digest=`

因此，当前已经不是“只有 local-rehearsal packet”，而是已经有一份可继续填充的 **operator-handoff 初稿**。

---

## 3. 推荐的 artifact 定义（当前阶段）

### 当前推荐定义
在当前 repo 架构下，建议把下面这份 tar bundle 视为：

> **TRNM local-rehearsal genesis candidate artifact**

即：
- 一次零 demo load、单高度、isolated BFT run 产生的 height-1 checkpoint/WAL anchor；
- 外加 validator config bundle 和生成日志；
- 外加 manifest / hash 冻结。

### 为什么它目前只能叫 `candidate`
因为它还不满足 public mainnet 的要求：
- 只做了单节点 proof run，而不是 4-node live operator bootstrap rehearsal
- 没有真实 operator ownership / acknowledgment
- 没有 public-mainnet-input scope 下的 non-placeholder packet
- 还没有正式 ceremony distribution path / rollback owner governance packet

---

## 4. 从 local candidate 走到 public-mainnet artifact 的最小升级路线

### Step A — 固化当前 candidate 口径
最小要求：
- 把本轮生成命令、artifact path、SHA256、state_root、wal_entry_hash 写入 release doc / handoff
- 明确它的 scope 是 `local-rehearsal`，不能外推为 public mainnet closure

### Step B — 把 single-node proof run 升级为 4-node controlled bootstrap rehearsal
最小要求：
- 用完整 4-node validator bundle
- 明确 startup order
- 保留 shared packet / log / rollback evidence
- 产出 one-shot bootstrap summary

### Step C — 把 packet 从 `local-rehearsal` 升级为 `operator-handoff`
最小要求：
- 填入真实 `validator_owner=`
- 填入真实 `operator_contact=`
- 每个 operator 给出 `operator_ack=`
- 至少给出 durable `operator_ack_digest=` 或 `operator_ack_signature_path=`

### Step D — 最后才是 `public-mainnet-input`
最小要求：
- 明确 distribution path
- 明确 rollback owner
- 明确 validator_set_version
- 非 placeholder ceremony id / timestamp / path / hash
- 与 signer / network / bootstrap topology 一起走 release gate

---

## 5. 现在最值得继续做的下一步

如果要继续往前推进，我建议下一步不是再造文档，而是：

> **把这份 local-rehearsal candidate 正式挂到 validator handoff / genesis closure 文档链里，并准备一次 4-node controlled bootstrap rehearsal。**

具体最小动作：
1. 在 release 文档里记录本轮 candidate bundle path + SHA256
2. 生成一份 `operator-handoff` scope 的 packet 初稿
3. 准备 4-node bootstrap rehearsal 的输入表（owner/contact/startup order/rollback owner）

当前输入表已落盘：
- `trillionnium/docs/release/TRNM_GENESIS_OPERATOR_HANDOFF_INPUT_SHEET_2026-04-04.md`

---

## 6. 当前状态一句话

截至本轮：

> **TRNM 已经从“没有真实 genesis artifact”推进到“有一份 local-rehearsal genesis candidate bundle + frozen SHA256 + ceremony packet skeleton”，但离 public-mainnet genesis closure 仍有明显距离。**
