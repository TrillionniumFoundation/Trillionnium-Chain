# Chain PQ R2：未闭合组合与明确拒绝边界

状态：**HOLD**。本报告是现有开发计划下的实现门槛说明，不是另一份路线图。
源码根目录：`/workspace/scratch/52b001730263/chain-pq-integration`。
审查日期：2026-10-29。所有路径均相对该根目录；本报告不把拒绝能力当成迁移完成。

## 1. continuous checkpoint owner + NPQ6

实际路径：

- `trillionnium/crates/trnm-pon-node/src/store/operator_continuous_owner.rs`：
  `open_operator_continuous_checkpoint` 仍从受保护 catalog 读取旧 checkpoint
  spec/bootstrap，调用 `Settings::development_with_operator_checkpoint_tile`。
- `trillionnium/crates/trnm-pon-node/src/operator_checkpoint_tile.rs`：旧构造器
  将 Ed25519 `SignedLifecycleTaskV2` 对应状态放入 genesis，并在打开时完整 replay。
- `trillionnium/crates/trnm-pon-node/src/operator_continuous_lease.rs`：
  `LeaseEdge::lease/check_declarations` 解析 `DemandLeaseV2`。
- `trillionnium/crates/trnm-pon-node/src/store/operator_continuous_owner.rs`：四处
  `lifecycle_task_lease` 与 tag 22 `AtomicRenewTaskV3` 仍是经典租约路径。
- `trillionnium/crates/trnm-pon-node/src/store.rs`：
  `PQ_NETWORK_OWNER_COMBINATION` 明确不接受 PQ network 与 continuous owner 组合。
- `trillionnium/crates/trnm-pon-node/src/store/operator_mining_owner.rs`：
  `install_mining_marker` 保留 `OWNER_MINING_FRESH_NAMESPACE_REQUIRED`；不能先以
  普通 owner 导入已有账本，再将其偷换为 continuous namespace。

已实现的 PQ Identity、TaskView、allocation、budget、recovery 签名仍作用于原
continuous 管理 owner；这不证明其底层 checkpoint 工作账本已成为 NPQ6。

下一步必须同时闭合四个点：受保护且完整固定的 **PQ catalog**；没有 genesis/签名
循环的 **真实 bootstrap 链或单独审议的确定性 genesis 语义**；由实际 parent State
解析的 **TaskV5 lease/renewal**；在原 CPU、Journal、恢复债务和最终签名 TaskView
约束下完成的 **初始化阶段**。直接换 magic、取消 fresh-state 规则或放宽组合 gate
均不构成上述实现。

## 2. 研究 archive 与 PQ application

`trillionnium/crates/trnm-pon-node/src/authenticated_state_archive.rs` 的
`AuthenticatedStateArchive::open_with_progress/source` 主要绑定
network/parameters/genesis，没有单独的 PQ profile 拒绝规则；执行 checkpoint 与
重验中的 packet digest 仍调用经典 `packet.encode()`。含大 NPQ6 交易的包不能通过
该经典编码路径。不能把这种稍后失败描述成完整、已验收的显式 PQ 拒绝，更不能称为
已迁移的 PQ archive。

下一步门槛：由原 archive owner 明确选择 settings-aware codec 与独立摘要域，
保留完整 state witness、native block、撤销/重组绑定；以带真实 PQ 交易的
导入、cold reopen、错块/错 profile 负向测试验收。若暂不迁移，应在开始 archive
操作之前给出明确受信 profile 拒绝。

相邻但不同的边界：`store/native_authenticated.rs` 的经典 codec 受独立
`AuthenticatedV1` backend 限制；`store/authenticated_migration.rs` 明确要求
Legacy source。`store/public_reader.rs` 是 `cfg(test)` 两阶段研究 reader。
这些隔离或研究实现均不是 PQ archive 完成证据。

## 3. Chain CLI / public-submit 自动父恢复

实际未迁移表面：

- `trillionnium/crates/trnm-pon-node/src/main.rs` 的 push、packet-status、submit
  和部分 packet 输出仍使用经典 `Packet::decode/encode` 与经典网络 caller。
- `trillionnium/crates/trnm-pon-node/src/public_submit.rs` 的父恢复 session、
  packet 精确比较和重发仍使用经典编码与 `PinnedPublicClient`。
- `trillionnium/crates/trnm-pon-node/src/peer_polling.rs` 的原 poller 明确调用
  `require_classical_network_profile()`，在 PQ backend 上返回
  `PQ_NETWORK_REQUIRED`，不继续轮询。这是拒绝，不是 PQ poller 实现。
- `ingress/public_v2.rs` 同样明确拒绝 PQ backend。

新的 `call_public_history_pq_v4` / `sync_from_public_history_pq_v4` library API
不能替代这些 CLI 和自动恢复入口的完成证明。下一步需要受保护的 PQ CLI 配置、
公钥/身份与 settings 绑定、明确版本选择，并在原提交与父恢复 owner 上完成
丢 ACK、断连、撤销、deadline、nonce、reorg 和 cold-reopen 的全链路测试。

## 4. 本轮证据与不得推导的结论

组件窗口中实测：四项 PQ operator、三项 PQ History、两项原 Journal/paid History
回归通过；FullV6 History 首轮在 ancestry projection 失败。root 已修该投影；随后
发现并修复 settings-selected completion identity。最终新源码的重编译/测试结果
必须由 root 的正式验证窗口补记，本报告不预写 PASS。

PNQ2 是有限预算的 loopback signed plaintext 开发 profile。其持久 SQLite ingress
计数与 paid History 的共享 intake/原 mutation CPU 不是同一种账本。本轮不能关闭
生产加密/PQ TLS身份、WAN服务、物理反回滚、量子有效 PoN 工作或证明系统独立审计。
