# 剩余吞吐工作的源码对应关系

固定源码：`5eb05ee0d14e3d1a59975154c3800b94c05fd7e1`；tree：`523345bbbf2e1fbfe85cf6949297a3774dd06d50`。只读分析，没有新增验收或 TPS 结论。

## 无状态准备并行、状态结果确定性提交

### 已有机制

- M06 已用有界 scoped workers 准备和验签，workers 只接受 1/2/4/8。全部已启动 workers 在返回前 join，结果按原交易索引排序；错误在原位置消耗。 [execute_with_state_inputs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs#L2914) · [canonical apply loop](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs#L3115)
- 余额、nonce、费用、receipts 按原顺序应用；冲突在当前状态 canonical replay 一次，不重复主签名验证。Growth partial view、PQ accounts V2、单 worker、全同 sender 使用串行状态路径，独立准备/验签仍可并行。 [execute_with_state_inputs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs#L2914) · [canonical apply loop](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs#L3115)
- 普通 shared admission 可在私有 prepared artifact 形成后释放 Node mutex 执行 M06，再获取 owner 并由 commit_shared_admission 重验 epoch/current context；子阶段仍使用同一原 deadline 和 CPU 账户。 [admit_shared_checked](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/ingress.rs#L1316) · [Node::commit_shared_admission](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store/detached_admission.rs#L358)

### 范围与剩余工作

- detached_execution_supported 排除 owner_policy、mining_owner、continuous_owner、PermanentAccountGrowthV2、Growth profile、active root rejection cache，不能声称所有入口都脱离 owner 锁。 [Node::detached_execution_supported](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store/detached_admission.rs#L176)
- 需按真实普通入口量化 prepare、owner wait、state read/commit、全部 worker CPU。同一共享 0.25 CPU 下多线程本身不增加容量；已有并行代码不是公网 TPS 证明。 [admit_shared_checked](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/ingress.rs#L1316) · [execute_with_state_inputs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs#L2914)

## 模型传输与控制资源分离

### 已有机制

- Cell 下载已有有限连接、响应字节、重试和绝对 deadline。bounded serving 使用有界 workers、独立已验证只读 cache reader，不持 SQLite lock 跨 socket I/O。 [CellPeerLimitsV1 / fetch_cell_with_schedule / request_with_retry](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-data-availability/src/cell/network.rs#L41) · [serve_cells_bounded](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-data-availability/src/cell/network/serving.rs#L103)
- repair_native_cell 要求绑定 CPU、下载字节、attempt reservation，在 effect window 内执行；其结果只是单次 invocation observation，不是 durable whole-lifecycle receipt。 [Node::repair_native_cell](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store/storage_service.rs#L269)
- material runtime bridge 精确绑定材料、plan、contract，解决 provenance/runtime 兼容边界；不能据此推导主机资源隔离。 [_MaterialRuntimeBridgeV1.verify_loaded_contract](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/scripts/llm_neural_read_worker.py#L192)

### 范围与剩余工作

- Cell serving 源码明确不承诺攻击者占满全部 slots 时仍公平服务；独立模块和 bounded queues 不能证明 CPU、NIC、磁盘竞争下的链业务 deadline。 [serving fairness scope](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-data-availability/src/cell/network/serving.rs#L102)
- 需同一固定 Host 同时运行大 Cell 传输/模型加载及真实签名确认、撤回、恢复，分别报告 Cell GB/s、冷/热加载分位数、链业务完成率与延迟和共同预算中的资源消耗。 [CellPeerLimitsV1 / fetch_cell_with_schedule / request_with_retry](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-data-availability/src/cell/network.rs#L41) · [serve_cells_bounded](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-data-availability/src/cell/network/serving.rs#L103) · [Node::repair_native_cell](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store/storage_service.rs#L269)

## 恶意负载下的诚实业务完成率

### 已有机制

- 同一 CPU domain epoch 内跨 listeners 共享连接、body/output、read/mutation grants 和 challenges。原连接 64、paid body 8 MiB；read body reserve 128 KiB、control output reserve 512 KiB 从原总量分区。 [ListenerIntake](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/intake.rs#L20) · [original aggregate public capacities](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs#L102)
- 原总连接满时可取消至少 250 ms 未付费输入空闲连接，但 slot 只在实际 lease drop 后释放。Challenge 在熵/签名前预留，取消不退款。 [ListenerIntake::cancel_idle_unpaid_under_pressure](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/intake.rs#L159) · [ListenerIntake::try_challenge](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/intake.rs#L197)
- 原共享 CPU 为 2 s burst、0.25 CPU refill、100 ms start reserve、2 workers。完整 W1 identity 只在原账户内获得有限完成优先权；4096 digest slots 满或重复时不给额外优先权，普通验证/恢复继续。 [PaidMutationCpuBudget constants](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs#L17) · [LiveRequestCpu::promote_verified_identity](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs#L567)

### 范围与剩余工作

- PublicPolicy scope 明确含 no-general-distinct-valid-W1-fairness；重复包抑制、有限队列和单项控制通过不能推广为通用恶意负载公平性。 [PublicPolicy::id declared scope](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs#L436)
- 继续保留原 campaign/F0 的所有阶段、计划槽、预算、失败和未完成分母，验证新 challenge、假 trace、不同合法 W1、冷缓存和恢复并发下诚实业务能否完成。 [PublicPolicy::id declared scope](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs#L436) · [ListenerIntake](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/intake.rs#L20)

## PQ 的字节、验签、缓存与传播容量

### 已有机制

- ML-DSA-65 signature 固定 3309 bytes。V3 PQ 仅缓存 immutable key expansion，8 slots，以完整 SPKI 和 expected key ID 命中，仅成功验签后 publish，不缓存验签 verdict，也不持锁跨 crypto。 [ML_DSA_65_SIGNATURE_BYTES](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-protocol/src/pq_frame.rs#L10) · [VerifierCache / verify](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/pq_identity/verifier_cache.rs#L19)
- AuthenticationBudget 在验签前计 attempt/bytes，记录实际 CPU；失败、replay、cache hit 不退款，未知 clock/panic fail closed。history profile 明确 read-head-and-history-only、no-production-qualification。 [AuthenticationBudget::perform](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/pq_identity.rs#L159) · [PublicPolicy::pq_history_id](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/pq_identity.rs#L223)
- Native Accounts V2 与 Application V6 有不同显式上限；Application V6 每 envelope 16384 bytes、每 block 64 transactions / 64 verifications。 [Native Accounts V2 / Application V6 capacities](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-protocol/src/pq_native_accounts_v2.rs#L20)

### 范围与剩余工作

- 需分别测 cache hit、冷 expansion、超过 8 key 的 churn、无效签名、完整消息字节与复制传播率，并计入同一 Host 原总预算。 [VerifierCache / verify](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/pq_identity/verifier_cache.rs#L19) · [AuthenticationBudget::perform](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/pq_identity.rs#L159) · [Native Accounts V2 / Application V6 capacities](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-protocol/src/pq_native_accounts_v2.rs#L20)
- 只读 PQ history profile 与显式 policy-based PQ network 不能直接代表全部普通变更入口完成公网 PQ 容量验收。 [PublicPolicy::pq_history_id](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/pq_identity.rs#L223) · [Node::open_with_pq_network](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store/pq_network.rs#L54) · [Node::pq_network_status](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store/pq_network.rs#L181)

量纲示例：假设每交易一个 3309-byte signature、假设 10000 TPS，仅签名为 33090000 B/s（33.09 MB/s）。不是已达到的吞吐，不含交易、key、work proof、重复传播或验签 CPU。

## 贯通普通入口、查询、恢复与 PQ 配置

### 已有机制

- StateBackend 将 AuthenticatedV1、PermanentAccountGrowthV2、PqNetworkV2、PqContinuousV3、PqWitnessV4 分开。本轮 post-write readback schema 只在 AuthenticatedV1 启用，不能假设覆盖所有 profile。 [StateBackend](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store.rs#L1273) · [post-write schema selection](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store.rs#L2090)
- read_active_with_readback 仍读 slot State 并验证 continuity/commitment/authenticated state；state_at_with_readback 向后查 snapshot，再沿 deltas 向前重建并检查中间状态。 [Node::read_active_with_readback](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store.rs#L3348) · [Node::state_at_with_readback](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store.rs#L3695)
- recover 对 Growth 进入专用路径，其他路径保留 owner guards、resume intent、最高 work 激活。Growth cold-open 在同一读事务内逐 block 验 header/W1、execute、比较 state/deltas/receipts，再审计 roots、storage partition 和 epoch。 [Node::recover](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store.rs#L6256) · [Node::growth_cold_open](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store/growth/recovery.rs#L701)
- PQ network/witness 有显式 opener 与持久 policy/replay owner，witness opener 要求既有外部 witness，反 rollback 检查必须保留。 [Node::open_with_pq_network](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store/pq_network.rs#L54) · [Node::open_with_pq_witness](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store/pq_network.rs#L102) · [Node::check_pq_witness_open](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store/pq_rollback_witness.rs#L340)

### 范围与剩余工作

- 完整 State/历史读取、Growth cold replay、PQ owner/witness 路径仍需分别容量预算；同 writer no-write epoch 的有限历史后缀 receipt 不能证明这些路径都消除了 N/H 成本。 [Node::read_active_with_readback](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store.rs#L3348) · [Node::state_at_with_readback](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store.rs#L3695) · [Node::growth_cold_open](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store/growth/recovery.rs#L701) · [post-write schema selection](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store.rs#L2090)
- 按各现有 profile、真实状态规模 N、历史长度 H、冷/热缓存验证 submit/query/reopen/recovery，在现有账本和 ownership 边界贯通增量读取；开发 fixture 的低难度确认不能换算成生产六块确认时间。 [StateBackend](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store.rs#L1273) · [admit_shared_checked](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/ingress.rs#L1316) · [Node::recover](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store.rs#L6256) · [Node::growth_cold_open](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store/growth/recovery.rs#L701)

## 两处候选的结论边界

Host 父目录 FD 候选针对重复路径解析，仍逐次实际读取和验证。有限 history suffix receipt 只在同 writer、同 no-write epoch 内复用已完整验证的历史。二者均不能单独证明公网吞吐、通用公平性、模型资源隔离或所有 profile 的增量恢复已完成。

分别报告已确认 TPS、有效工作率、Cell bytes/s、冷/热模型加载延迟、实际单位成本质量收益。

Public links use `9e50ca8e1ce655ef2f4686bd0ab58120b30c4632`; every referenced file was independently checked byte-identical to the recorded original source. This changes link availability, not the execution status.
