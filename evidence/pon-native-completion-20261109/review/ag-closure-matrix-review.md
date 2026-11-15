# A–G 实际关闭矩阵与 D/E/F 后续条件

审阅快照：2026-11-09。供唯一开发计划与 PR 引用；更新既有工作包的状态及证据，不新增独立准入门。**A–G 整体均为 HOLD；已完成的局部修复、有限模型验证与生产资格分别记账。**

## 1. 源身份与本轮证据

- **B/D/E/F：** `TrillionniumFoundation/Trillionnium-Chain`，PR #821，commit `e798d7125724d4b9f98c24d00cc80031f2eab4a9`，tree `f77b6240b845425e0fc75e88abb09e6cfa3a71c0`。完整隔离源为 `/data/chain-abg-70ae-20261108/source`。以下 D/E/F 路径均相对该源。
- **A/C：** PR #820 的独立 continuation，commit `c247d623704b1cce2307fa31b21cab045063e0f6`，tree `098f1aaa991ac04c70177982929b3cc39d9f8009`；完整源为 `/data/chain-learning-exit-70ae-20261109`。截至本快照，逐文件字节与 mode 核验、原 preflight 已通过；正式红绿回执仍待完成，尚无新 commit/PR。不能把 A/C 修复或其准备阶段结果移记为 #821 资格。
- **已直接核实：** clean #821 上既有 9 个纯 Python 模块，实际 **255 项全部通过**，各模块实际数量与预期一致，合计约 **12.85 秒**。证据 `/data/chain-abg-70ae-20261108/evidence/def-finite-baseline`，job `1a1be2ef5e8-138b0-905`。当时并行进行基线 Cargo 编译；这批结果只证明有限模型控制通过，不测原压力合同或实际成本上下界。
- **B 原生基线须保留两次记录：** 首次过滤器选中 **0 项**，wrapper 以 `AssertionError` 失败，不能计 PASS；root 随后在 `evidence/baseline-native-corrected-filter` 独立执行正确 exact filter，报告 **1 passed**、source-after 完整检查 PASS 且 clean，job `1a1be30c792-138b0-911`。后一次不覆盖第一次；本审阅者直接看过首次日志，后一次状态由 root 提供。

## 2. 实际关闭矩阵

| 工作包 | 本轮实际到达的位置 | 状态及下一闭合条件 |
| --- | --- | --- |
| **A：冻结真实工作族** | #820 原 owner 驱动与完整源身份已固定；正在修复 start/query 对进程完成的误判。 | **HOLD。** 固定真实工作族的完整 context、所有允许输入、数值语义、共享规则、原 owner 调用链和唯一信用身份；独立重放与该完整定义一致。驱动边界修复不能代替工作族完备性。 |
| **B：持久总预算与完整父块门** | 严格 native completion 资格补丁已实现、冻结并完成独立静态审阅；资格来自完整原生关系，promotion 只影响调度。原生基线控制已得到独立修正回执，候选同字节红绿仍待回执。 | **HOLD。** 在原 0.25 CPU、2 GiB、原 deadline 下同时满足恶意负载预算与诚实业务；覆盖 held、detached、Growth、共享/独占 History 及真实大包路径；完成全入口持久总账和 clean reopen 的可信 embedding 边界。 |
| **C：真实 Hepta 闭环** | #820 两文件修复区分数值 Candidate/NoUpdate 与服务完成；UNKNOWN/FAILED、保留额度及原状态不被 query 改写，query 不重放。完整 consumer 检索未见 pending 被其他安装/支付消费者采纳。 | **HOLD。** 正式源上完成进程边界红绿；然后以同预算完成 no-change、cell-only、routing-only、joint 四臂真实 encoder/router/adapter/评估连接，保留合法 NoUpdate，并取得真实 FinalUse 与独立确认。 |
| **D：最便宜合法工作** | #821 已有成本合约、合法优化目录、期望搜索模型与固定成功率合约；本轮相关有限模型测试通过。 | **HOLD。** 通用合约有 12 个未知 L/U 端点，MU1 合约有 32 个；先为 A/C 的冻结关系取得可复核候选 U，并为完整合法策略类给出有明确前提的 L 或否决该 profile。 |
| **E：信用与生命周期** | 共同信用、摊销势能、有限生命周期及尾界/组合模块存在；成功语义不一致已有拒绝机制。 | **HOLD。** 实际完整竞争历史能嵌入证书模型，初始势能及隐藏进度有界，跨任务/分支/规模/重启的共享成本和风险组合前提成立。有限状态控制不能补齐这些前提。 |
| **F：调难与原生迁移** | 已有固定概率研究合约、分支时间模型、Rust research schedule 和只读 reader。 | **HOLD。** 由原 owner 在一致快照中绑定真实 parent、State、工作、信用和预算；覆盖 header、同步、恢复、激活点 reorg，并联合验证时间变化、算力阶跃和信用组合。现有研究 reader 不提供原生接纳授权。 |
| **G：同版本联合验收** | 已有来源明确的局部证据；A/C 与 B/D/E/F 仍是两个独立源。 | **HOLD。** 在最终同一源码、原资源和原 deadline 上，同时运行完整证明后端、WAN、冷启动、长期运行、churn 与原对抗矩阵；历史结果、准备阶段结果和不同源结果不能拼成联合 PASS。 |

**B 当前最具体的诚实可达性风险：** 冷账户刚积累 100 ms 起始额度、单线程持续占满 CPU、没有额外空闲积累时，以 0.25 CPU 补充速率，只能持续约 `100/(1−0.25) = 133.3 ms` CPU。若完整关系 token 需要更长时间，未晋升请求可能先进入 sticky refusal。新的 cold 控制和 prepared-held 控制用于观察此边界；小样本通过仍不证明全部允许 State 或真实 `>8 MiB` 路径达标。不得通过增加初始额度、预热或延长原 deadline 来抹除此缺口。

## 3. D/E/F：沿用的原前提与下一交付

### D：成本定义必须先与真实关系对齐

`formal/pon-nakamoto-v1/contracts/cost-envelope-current-hold-v1.json` 的 6 个点、12 个未知端点属于其研究网格；`formal/pon-nakamoto-v1/fixed_probability_contract_v1.json` 的 16 个点、32 个未知端点属于 MU1、`u=1..8`。前者的 `u=16` 和 120000 ms 研究窗口不能直接移作后者或原业务 deadline 的资格。MU1 仍声明 `native_credit=false`，初始势能界为 null，10 项既有开放义务未闭合。

下一交付应直接补充这些现有合约所需的证据：冻结输入分布与合法选择范围；独立优化热缓存、结构化输入、共享预处理等合法候选，计入完整准备、失败与验证成本；分别建立经典和量子资源模型。**实测 U** 只适用于已说明的算法、输入、资源和成功语义；**L** 必须来自覆盖相应完整策略类的定理/归约及成立的前提。有限目录中的最小值不是所有合法算法的下界，理想 oracle 查询数也不是物理时间证明。

均值不能直接填入“到 deadline 前以固定概率成功所需硬总预算”的端点。一个严格有限例子：仅允许调用一次、无提前信息或重启、最终都成功、成本等于时间、deadline 为 7。分布 A 以 `1/4` 概率成本 1、`3/4` 概率成本 3；分布 B 以 `3/4` 概率成本 1、`1/4` 概率成本 7。二者均值都是 `5/2`，但半成功概率硬预算分别是 **3** 与 **1**。这不否定另一种目标下的集合包含事实：若目标本身是满足至少 α 成功的无 deadline **无条件期望成本**，兼容的必成功算法仍可提供候选期望上界。

已有 `credit_feasibility.py` 将 `SuccessStandard` 纳入 `Scope`，实际拒绝语义不一致的点。审阅的两个 CI runner 分别保留均值与固定预算报告；完整源 `rg` 匹配未提供新的错误接入证据。故本轮没有新增无人调用的 gate。继续使用现有接口时须绑定：源/关系与完整 context、成功事件及唯一信用身份、α 与成本目标、deadline 起点及停止规则、资源模型、策略/初始状态/共享历史、L/U 证据种类、信用归一化及自比较规则、条件尾界和原生授权来源。

### E：证书检查成立还需要实际历史满足前提

已有模块可以检查所声明的有限模型和代数条件。下一交付是实际关系到模型的覆盖论证：包含所有合法动作和所有可竞争历史，初始经典/量子状态与势能有界，共享准备成本真实计入，跨任务、分支、规模与 profile 迁移不免费重置隐藏进度。期望奖励/势能界还需相应的条件尾界前提，才能转成给定置信度结论。风险组合需共同 primitive 的生命周期查询界、事件次数界及初始分布条件；命名空间不同不自动意味着独立。

这项工作应落在现有 `lifecycle_cost_v1.py`、`amortized_cost_potential.py`、`finite_joint_state_certificate.py`、`stateful_tail.py`、`lifecycle_query_bound.py`、`certificate_composition.py`、`native_risk_ledger.py`（均在 `formal/pon-nakamoto-v1/`）及实际原生计费/信用映射上。255 项通过仅覆盖本次列明的 9 个测试模块，不是这些所有模块的本轮执行证明。

### F：研究算术到原生接纳仍有明确距离

`trillionnium/crates/trnm-pon-node/src/research_work_schedule.rs` 与 `scripts/pon_branch_work_schedule_reader.py` 提供研究分支算术和 W1 读取；文档明确其不重放 State、不授权原生接纳。本次未证明存在生产 bypass。下一交付是在实际原 owner 的新鲜 parent/State 和完整关系事务内完成权威绑定，并让全部 header、同步、恢复、激活及 reorg 路径保持同一语义。时间戳单调性本身不能给出压缩时间/私链赶时的安全结论；固定概率本身不能建立经典与量子共同信用。调难、真实资源到时间的映射和混合参与者的链性质需联合论证。

## 4. 可复核证据索引

- D/E/F 原始逐路径审阅、精确 blob、未知端点、十项开放义务、语义绑定与文献来源：`/workspace/scratch/70ae3f2c90d7/def-review.json`，SHA256 `98b4d03ddafd8bf7971f4cd36eef86e21984f50da3a9b9ea8aa3cdaccd005b56`。该文件保留审阅当时尚未取得完整 checkout 的事实；本快照补记之后的完整源及测试证据。
- 本轮 9 个既有测试及精确命令：`/workspace/scratch/70ae3f2c90d7/def-python-commands.json`，SHA256 `91dba3636dbdcdbcfb6adbd1e32250e705ceecdb8ecddcc255752b7200c86d9b`。模块数量依次为 cost envelope 29、branch time 31、lifecycle 31、credit envelope 40、normalized search 37、fixed probability 16、credit feasibility 31、amortized potential 34、independent potential 6，总计 255；命令清单本身不代替 root 的执行日志。
- 完整源调用点检索：`/workspace/scratch/70ae3f2c90d7/def-call-sites.txt`，4210 bytes，SHA256 `30737198010358d4396b49823f77d295f3ca754e70b4060f739b978f6b6192d4`。匹配落在上述 CI runner、测试、自身源记录及 CI contract；这是静态文本检索，不是动态调用完备性或全合法策略证明。
- 关键已有调用点：`scripts/ci/run_credit_envelope_checks.py`、`scripts/ci/run_work_time_contract_v1.py`、`formal/pon-nakamoto-v1/credit_feasibility.py`。F 的既有说明为 `docs/protocol/pon-nakamoto-v1/details/BRANCH_WORK_SCHEDULE_RESEARCH_V1.md` 与 `FIXED_PROBABILITY_COST_CONTRACT_V1.md`。
- B 独立静态审阅：`/workspace/scratch/70ae3f2c90d7/b-peer-review.json`，SHA256 `a0f42570ec1e2d1ef5dd7dd88eee55e347e1ad4240e9e9bc8c90c6a370a1622c`。冻结主 patch SHA256 `99fae1e27590c0e23c715850a815239b8e958f7dc264136082016bc4228006a8`；prepared-held addon `35780992872deba17a5f144816dea44294690652aaea16edd47adcf5bb135c4c`；其后独立 local-helper guard addon `7426da2e492a8a095d22bb19fde7a7000e6bcdb8751b9c41206d4fe13556362c`。guard addon 已另行静态核查：释放 guard 后才重入，公开 worker/History 先绑定原请求，未见新锁语义 blocker；不等于原生执行 PASS。
- A/C 变更实际路径：`scripts/run_learning_service_development.py`、`scripts/test_run_learning_service_development.py`，只归属 #820 continuation。状态来自该工作包负责人最新完整源核验与 consumer 检索回报；正式 84 项回执尚未纳入本快照。
