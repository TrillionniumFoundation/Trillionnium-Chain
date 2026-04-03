# TRNM Genesis Closure Status (2026-04-04)

评估快照：`origin/main = 35da4109e`

## 结论

**结论：创世区块相关工作尚未闭环，不能视为“已搞定”。**

更准确地说：
- **genesis artifact 的生成/校验/分发 checklist 已具备；**
- **validator bootstrap / rotation / DR 的 runbook 和 fail-closed helper 已具备；**
- **但 public-mainnet 语境下所需的真实 signed ceremony / operator evidence / DR rebuild evidence 仍未闭环。**

因此，TRNM 当前的 genesis 状态应表述为：

> **documented but not operationally closed for public mainnet**

---

## 1. 当前已有内容（What exists now）

### 1.1 Genesis generation / validation checklist
已存在：
- `trillionnium-rust/docs/runbooks/genesis-generation-checklist.md`

它已经明确要求：
- 绑定 exact worktree / branch
- 指定唯一 genesis artifact path
- 计算并冻结 `genesis_artifact_sha256`
- 校验 validator config bundle
- 生成 ceremony packet skeleton
- 明确 rollback

这意味着：
- TRNM 已经不再停留在“口头说有 genesis 流程”；
- 至少已有一份 **fail-closed 的 genesis artifact 操作模板**。

### 1.2 Validator bootstrap / re-bootstrap runbook
已存在：
- `trillionnium-rust/docs/runbooks/validator-bootstrap-rebootstrap.md`

它已经把以下要素写明：
- worktree / branch / commit identity 验证
- config bundle 校验
- shared ceremony packet 的最低字段要求
- startup / re-bootstrap 的 fail-closed stop conditions

这意味着：
- TRNM 已经具备“从干净 worktree 启动 validator”的文档路径；
- 但这仍是 **runbook-level closure**，不是 public-mainnet-ready 证明。

### 1.3 Validator replacement / rotation / DR runbook
已存在：
- `trillionnium-rust/docs/runbooks/validator-rotation-dr.md`
- `trillionnium-rust/scripts/v2/extract_validator_rotation_dr_fields.sh`

它已经覆盖：
- replacement / rotation / dr_rebuild 三种 cutover kind
- config bundle evidence capture
- DR report path / replay / rollback extraction
- signed/acknowledged handoff evidence 的最低要求

这意味着：
- TRNM 已经不再缺少“operator lifecycle 的文档壳”；
- 但还缺 **真实演练产物**。

### 1.4 Validator config bundle checker
已存在：
- `trillionnium-rust/scripts/v2/check_validator_config_bundle.py`

它已经能 fail-closed 校验：
- TOML 解析
- `node_id` / `rpc_addr` / `p2p_addr` 存在性与合法性
- bundle 内 identity / 监听地址唯一性
- `--emit-ceremony-packet` 生成 ceremony packet skeleton
- `public-mainnet-input` 模式下对 placeholder/path/hash/version 的严格拒绝

这意味着：
- genesis / validator ceremony 至少已有一个可执行的 bundle-level 守门器；
- 但它验证的是 **配置一致性**，不是“主网创世闭环已完成”。

### 1.5 Release / handoff discipline
已存在：
- `trillionnium-rust/docs/release/TRNM_VALIDATOR_RELEASE_HANDOFF.md`

它已经把以下纪律写清：
- release rehearsal 只能在 clean worktree 上执行
- artifact path / branch / head / worktree identity 要显式记录
- local evidence / RC artifacts 不能外推为 public-mainnet-ready

这意味着：
- TRNM 的 validator-side evidence discipline 有文档基础；
- 但目前仍主要是 **Stage-1 / RC rehearsal discipline**。

---

## 2. 当前仍未闭环的部分（What is still open）

依据 `trillionnium-rust/docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md`，
`Genesis + validator/operator lifecycle` 仍然是 **P0 launch blocker**。

当前仍未闭环的关键点包括：

### 2.1 缺真实 signed genesis ceremony packet
虽然现在已经有 ceremony packet skeleton / checklist，但仍缺：
- 一份真实生成的 genesis artifact
- 一份与之绑定的 `genesis_artifact_sha256`
- 一份非 placeholder 的 ceremony packet
- 每个 validator owner 的真实 acknowledgment / signature evidence

### 2.2 缺 live operator artifact 驱动的 bootstrap 证据
当前文档更多回答的是：
- “如果要做，应该怎么 fail-closed 地做”

但仍未回答：
- “是否已经基于当前 mainline 真做过一轮可审计的 bootstrap rehearsal？”

也就是说，缺的是：
- path-resolved packet
- operator ownership evidence
- startup order note
- rollback owner
- actual pass/fail bundle

### 2.3 缺 validator replacement / rotation automation 或真实 rehearshal
目前 replacement / rotation / DR 有 runbook，但仍缺：
- 一次真实的 replacement / rotation 演练产物
- 一次带 artifacts 的 DR rebuild 演练
- 一组可引用的 `dr_summary_path=` / `dr_replay_command=` / `dr_rollback_command=` 证据

### 2.4 缺与 signer / network / bootstrap topology 的联动闭环
创世并不是一个孤立文件问题。
要进入 public mainnet，genesis 还必须和这些外围闭环对上：
- signer / keystore 模型
- bootstrap peer / network formation
- validator identity / ownership ceremony
- join/rejoin / sync acceptance

当前这些领域仍然都在 mainnet P0 列表里，因此 genesis 不能单独被算作已完成。

---

## 3. 现状表（Status table）

| 子项 | 当前状态 | 已有证据 | 仍缺什么 | 判定 |
|---|---|---|---|---|
| genesis artifact checklist | 已具备 | `trillionnium-rust/docs/runbooks/genesis-generation-checklist.md` | 真实 artifact + hash + packet | 部分完成 |
| validator config bundle validation | 已具备 | `trillionnium-rust/scripts/v2/check_validator_config_bundle.py` | 对当前 mainline 的真实 ceremony bundle run | 部分完成 |
| bootstrap / re-bootstrap runbook | 已具备 | `trillionnium-rust/docs/runbooks/validator-bootstrap-rebootstrap.md` | 一轮可审计 bootstrap rehearsal evidence | 部分完成 |
| replacement / rotation / DR runbook | 已具备 | `trillionnium-rust/docs/runbooks/validator-rotation-dr.md` | 真实 signed rotation / DR rebuild evidence | 部分完成 |
| release / handoff discipline | 已具备 | `trillionnium-rust/docs/release/TRNM_VALIDATOR_RELEASE_HANDOFF.md` | 与 genesis ceremony packet 绑定后的真实 handoff bundle | 部分完成 |
| public-mainnet genesis closure | 未闭环 | gap matrix / blocker board 仍列为 P0 | signed ceremony + operator packet + DR / rollback evidence | **未完成** |

---

## 4. 对外口径建议（How to describe it now）

当前最安全、最准确的说法是：

### 可以说
- TRNM 已经具备 **genesis generation / validation / handoff 的 fail-closed 文档与工具骨架**。
- validator bootstrap / re-bootstrap / rotation / DR 的 runbook 已形成。
- config-bundle checker 与 ceremony packet skeleton 已存在。

### 不可以说
- 创世区块已经完全搞定。
- validator bootstrap / ceremony 已经 operationally closed。
- public mainnet 的 genesis / validator lifecycle blocker 已关闭。

---

## 5. 把这块真正关掉所需的最小下一步（Minimum closure sequence）

要把“genesis documented”推进到“genesis operationally closed for launch input”，最小还需要这 4 步：

1. **生成一个真实 genesis artifact**
   - 明确 `genesis_artifact_path=`
   - 明确 `genesis_artifact_sha256=`
   - 明确 `validator_set_version=`

2. **基于当前 validator config bundle 生成非 placeholder ceremony packet**
   - 使用 `trillionnium-rust/scripts/v2/check_validator_config_bundle.py --emit-ceremony-packet`
   - 填完整 `ceremony_id=` / `packet_generated_at=` / `packet_distribution_path=` / `rollback_owner=`

3. **做一次真实 bootstrap / operator handoff rehearsal**
   - 绑定 exact worktree / branch / head
   - 保留 `operator_ack=` / `operator_ack_signature_path=` 或 digest
   - 形成一个可引用的 handoff bundle

4. **再做一次 replacement / DR rebuild evidence**
   - 至少形成一份带 `dr_summary_path=` / `dr_replay_command=` / `dr_rollback_command=` 的真实演练记录

只有完成上述 4 步后，才更接近把 P0.2 从“文档存在”推进到“可审计闭环”。

---

## 6. 最终判断

截至 `origin/main = 35da4109e`：

- **创世相关文档与脚本：有**
- **创世相关 operator 流程骨架：有**
- **创世相关 public-mainnet operational closure：没有**

所以本项当前结论是：

> **Genesis closure status = Partial / Documented / Not yet closed for public mainnet.**
