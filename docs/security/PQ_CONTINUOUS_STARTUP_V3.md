# PQ continuous startup V3：原 owner 组合安全契约

状态：**开发候选，HOLD；没有生产激活或 9.6 资格声明。** 本文记录既有
[唯一开发计划](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md) 下的实现与拒绝边界，
不是第二份开发计划。实现候选先保存于 `5e452fcab0fd77468d87ca950c489c53bd84c56e`；
随后补齐同一 controller 的非空 NPQ6 search 消费入口。测试源码存在不代表测试通过。

本轮已执行项目 preflight、所改 Rust 文件的 rustfmt 及 `git diff --check`；固定 Rust 1.95.0
和已固定的 PQ provider 环境下，`cargo +1.95.0 check --release --locked -p trnm-pon-node
--all-features --tests` 已通过，覆盖整合后的生产代码和测试源码。此检查没有链接或执行测试。
新的真实运行测试和严格 Clippy **尚未执行**。此前环境中不可恢复的提交、运行进程和输出
不能作为本候选的成功证据。最终运行状态应以本轮资格记录为准。

## 1. 要解决的授权循环

经典 continuous checkpoint 启动从受保护目录读取 `SignedLifecycleTaskV2` 和
`DemandLeaseV2`，再创建包含 bootstrap 任务的初始状态。NPQ6 任务签名则绑定实际 genesis。
把这样的签名直接塞进决定 genesis 的状态，会形成“先有签名还是先有 genesis”的循环。

[StartupSpec](../../trillionnium/crates/trnm-pon-node/src/operator_pq_startup.rs) 因此只提供公共
genesis 账户、余额、评估者和应用配置，以及本地 PQ 网络身份 pins。它不接收一个来自调用方的
genesis 状态快照、工作量值或“任务已经验证”布尔值。原 NPQ6 genesis 构造器先得到最终
network、parameters、genesis，任务双方随后对该确切上下文签名。

`StartupBundle::produce` 调用原 Node producer 生成两块连续的真实 consensus-maintenance
工作包：第一块只有 OPEN 18，第二块只有 REGISTER 21。后者的 requester 和 source 签名由
原 M06 TaskV5 状态 owner 解析当前账户后分别核验。producer 需要实际 active 为 genesis、
generation 为 0；它调用原 `make_consensus_maintenance`、`admit` 和 `activate_observed`。
consumer 再执行同一准入和激活路径。不存在直接写入累计工作量、绕过费用、增加隐含余额或
把签名本身算作 PoN 工作的步骤；只有原协议允许的状态转移与奖励会进入链上状态。

此 maintenance 选择只属于明确的启动 bundle。正常任务不合格时，不自动退回 maintenance。
共识仍由原 PoN 工作、状态与累计工作量规则决定，没有加入 BFT、stake 或评估者投票 fork choice。

## 2. 明确的版本和命名空间

| 对象 | 本候选的选择 | 拒绝边界 |
| --- | --- | --- |
| 受保护身份 | `restricted-continuous-identity-pq-v3` | 身份 schema 在解析目录和选择 wire 前固定；不能由签名验证失败触发切换 |
| controller launch | `restricted-owner-continuous-launch-pq-v3` | 外部固定 launch 摘要、两个角色公钥和 source/package context |
| StartupSpec | `restricted-continuous-pq-startup-spec-v1` | 规范 JSON、未知字段、错误 schema 和超限输入拒绝 |
| StartupBundle | `restricted-continuous-pq-startup-bundle-v1` | 恰好两包、线性父链、高度 1/2、确切 genesis、每包一笔指定 NPQ6 命令 |
| 应用与区块 | `pon-native-pq-application-v6`、NPQ6/PQP6 | 不接受经典或 NPQ2–NPQ5 作为替代 |
| SQLite backend | `PqContinuousV3` | schema 摘要域 `native-pq-continuous-owner-schema-v3`，必须是新 namespace |
| 材料目录 | `TRNM/PoN/ContinuousStartupCatalog/PQ/v1\0` | 恰好排序后的 `bootstrap`、`input`、`model`、`spec` 四个角色 |
| 交易列表承诺 | `TRNM/PoN/ContinuousOrderedTransactions/PQ/v6\0` | 原顺序、完整原始字节和显式 NPQ6 上限；经典列表保留原域与 2,048 字节上限 |
| 租约转换 | `restricted-continuous-lease-edge-pq-v2` | `TRNM/PoN/ContinuousLeaseEdge/PQ/v2\0` 与 DemandLeaseV5；经典 lease edge 不替代 |

数据库同时保存原 continuous owner marker 与精确 PQ 网络 policy bytes。普通
`open_with_pq_network` 不能打开该 namespace，旧经典 opener 也不能打开它。
`PQ_NETWORK_OWNER_COMBINATION` 仍拒绝未支持的组合；新增分支只接受由真实 PQ 目录构造、
持有私有 PreparedStartup 的 continuous owner，以及明确的 NPQ6 Settings。

这是 fresh-genesis 配置，不是运行中网络的高度激活或余额迁移。旧网络的最终确认、
旧密钥的先验可信性、PQ 预承诺和资产负债桥接仍有独立条件。

## 3. 原 Journal、CPU 和文件归属

入口仍是 [原 continuous owner](../../trillionnium/crates/trnm-pon-node/src/store/operator_continuous_owner.rs)
的 `Node::open_operator_continuous_checkpoint`。顺序仍为：认证受保护 view、打开原 Journal、
核对外部精确 journal head、认证预算与恢复证明、写入下一个 view、保留 `startup-catalog`
与 `parent-reconcile` 两份原 allocation，再启动原 `DurableOperation`。

新旧启动分支共享这一 Journal、CPU domain、fault sink 和 epoch。没有第二个优化器、
旁路账本、重启赠送余额或新造暖 CPU 账户。pristine Journal 才能走原首次启动；干净重启
使用原 clean-close 证明；已知非干净重启需要原 guardian/process 证明；未知债务维持拒绝。

[目录验证器](../../trillionnium/crates/trnm-pon-node/src/operator_continuous_policy.rs) 继续持有原文件
描述符，检查绝对路径、普通文件、单硬链接、UID、不可被 group/world 写入的权限、长度、
SHA-256、设备/inode 及时间元数据。加载期间和后续操作继续检查文件身份。目录总字节受原
512 MiB 及 allocation 中 material/DA 上限约束；Spec 与 Bundle 各限 512 KiB，model 与 input
各限 16,384 字节。旧经典分支仍要求原六个真实角色，未用占位 checkpoint/activation 冒充 PQ 文件。

真正导入两块包的阶段只发生在同一启动操作内：启动 CPU checkpoint、期限、两个 permit、
原 W1、M06 和 SQL owner 都保持有效。新库允许 reconcile 观察到 genesis/generation 0，
仅限数据库只有 genesis 一行且外部签名 view 精确指定 bundle 最终块/generation 2。
这不是一般的 parent 不匹配豁免。

临时启动权限还要求 packet 完整字节、执行的 parent/miner/height/交易列表、激活目标和
当时 active pair 都来自这份确切 bundle。启动成功或失败都会关闭 `startup_import`，不能在
正常收块阶段重新使用它。正常 continuous packet gate 仍要求声明的真实任务与专门 allocation。

## 4. 状态结果与失败语义

| 情况 | 原生状态和本地记录的结果 |
| --- | --- |
| 两包均通过 | 两次真实工作准入和激活后得到 bundle tip/generation 2；再检查当前 M06 task、双角色权限、租约、model/input/A/B |
| 目录、配置、签名或工作错误 | 返回失败；已保留 allocation、实际 CPU 结算和已提交原生块不会回滚退款或伪装成功 |
| 首包工作拒绝 | genesis 仍是 active；原启动 Journal 的预算、view、allocation 和结算记录继续存在 |
| 第二包前后中断 | 可能留下合法的已提交前缀；重启不猜测、不补写缺包、不制造干净关闭。需要独立恢复与新的外部授权判断 |
| 重复启动或旧 view/head | 原 Journal sequence、digest、allocation replay、精确外部 head 继续拒绝；不是重新申请免费 bootstrap |
| 干净冷重启 | 需要新的已签 view/allocations 与准确 head；保留包必须逐字节匹配，并仍是 active 链祖先；不重新执行 OPEN/REGISTER |
| 任务已撤销、过期或角色失效 | cold startup 和新工作都重新查询原 M06 当前状态，失败时 HOLD，不重放初始任务来恢复权限 |
| 本地 peer 撤销或网络预算已消耗 | 原 PQ 网络表继续保留；不会因 chain reorg 或重开恢复 |
| 合法链重组换掉启动前缀 | 不属于本候选自动恢复权限；外部受限 owner 维持明确 HOLD，而不是强行认可旧 catalog |

重新读取任务不依赖最初注册时的成功报告。NPQ6 分支调用 M06 `tasks_v5::eligible_task` 读取
实际 parent 的完整 DemandLeaseV5；经典分支才调用原 DemandLeaseV2。原子续租仍通过实际
NPQ6 kind 22、前后两份完整租约和实际已保留包核对，再在旧预算下记录原 lease witness。
只有租约哈希可以改变；任务、材料、来源、成本分类和资金声明不随转换隐式改变。
该 witness 不自动授予新预算或新工作权限。

## 5. 实际消费者与资源合同

已有主 CLI 的 `operator-continuous` 命令使用原 `OutsideLaunch`，调用
[Controller::open_pinned](../../trillionnium/crates/trnm-pon-node/src/operator_continuous_controller.rs)，
后者直接调用上述原 Node opener。`Inputs.materials` 接收四角色 PQ 目录，未增加另一个只作演示的
启动 owner。receiver/winner 路径按 Settings 调用 `Packet::decode_for_settings`；可选 PQ public
receiver 使用原 continuous CPU domain。

对实际 controller `Step::Search` 的复核发现原 hex 长度 4,096 限制会提前拒绝所有普通 NPQ6
交易。本候选补齐该消费点：Settings 必须来自已认证的 launch；NPQ6 使用以下边界，经典
设置仍保留 256 笔、单笔 2,048 字节限制。输入魔数不能选择宽松上限。

| NPQ6 搜索／收块资源 | 边界 |
| --- | --- |
| 每命令 | 16,384 原始字节；controller hex 最多 32,768 字符 |
| 每列表 | 64 命令、524,288 原始字节 |
| 预期交易授权验证 | 合计 64；双签计 2、含两份冲突证据的命令计 3 |
| 拒绝时机 | 原始长度、列表上限和显式 NPQ6 结构在新搜索和密码验证前检查 |
| 全包 | 按现有 Application V6 的 PQP6 编码与原证明执行；旧包编码不能绕回 |

原 search、receiver 和 pool 的交易列表消费者也使用受保护身份选定的同一列表承诺。
经典 mining helper 没有被整体放宽。64 次交易验证不包括 W1、任务资格重验、传输和本地
控制签名的全部成本，不能据此推导实际 TPS 或一个精确毫秒预算。

本次没有开放 generic History 对 continuous owner 的导入权限。原 Journal 尚无相应 allocation
时，`OWNER_CONTINUOUS_HISTORY_DURABLE_REQUIRED` 必须保持；普通 pinned poller 也仍明确拒绝
PQ namespace。上述受限 controller 接线完成，不等于无人值守全网分叉同步已验收。

## 6. 测试源码与当前验收状态

以下测试位于 [operator_pq_startup_tests.rs](../../trillionnium/crates/trnm-pon-node/src/operator_pq_startup_tests.rs)。
使用公开确定性研究密钥，但经过真实 ML-DSA、W1、M06、SQLite 与原 owner/Journal。
外部 Registry2 provenance 在这些 fixture 中是声明性的；不同测试密钥不代表独立管理员。
下表均已通过整合编译检查，运行状态仍为 **SOURCE PRESENT / NOT YET RUN**。

| 测试 | 验证目标 |
| --- | --- |
| `pq_continuous_real_bootstrap_receiver_and_cold_reopen_keep_state_fees_work_and_local_revocation` | 实际 producer → bootstrap consumer → 非空 NPQ6 receiver/activation → cold reopen；状态与费用路径相同、本地撤销不丢失 |
| `pq_continuous_original_search_owner_produces_registered_work_and_cannot_replay_allocation` | 原 search owner 实际产生已注册任务工作，重复 allocation 拒绝 |
| `pq_continuous_real_controller_nonempty_search_receiver_restart_and_wire_limits` | 原受保护 Controller 非空 NPQ6 Step::Search、收块、激活与重启；经典/NPQ5/超长/65 命令/66 验证尝试拒绝 |
| `pq_startup_strict_genesis_wire_shape_and_signature_boundaries_refuse_mutations` | 错 genesis、包顺序、多包、非规范 JSON、旧 schema、旧编码、错误任务签名和验证次数上限 |
| `pq_startup_invalid_work_spends_original_journal_and_refuses_automatic_retry` | 坏 W1 不生成成功链状态；原 Journal 支出保持，旧 head 重试拒绝 |
| `pq_continuous_revoked_actual_task_blocks_cold_restart_without_replaying_bootstrap` | 真实链上撤销后 cold startup 拒绝且不回放 OPEN/REGISTER |
| `pq_continuous_atomic_renewal_reconciles_actual_task_v5_owner_and_strict_lease_edge` | 真实 AtomicRenewTaskV5、实际前后租约、旧预算 witness 与跨 profile lease edge 拒绝 |

另有 [controller 单元回归](../../trillionnium/crates/trnm-pon-node/src/operator_continuous_controller_tests.rs)
`continuous_classical_search_decoder_keeps_original_2048_byte_limit`，确认旧 profile 没有随新限制放宽。
这些源码已通过固定工具链的整合编译检查，仍需实际执行，并接受独立复核和资源测试。

## 7. 保持开放的门槛

本组合没有证明 PQ 网络保密、生产 PQ TLS 对端身份、量子有效 PoN 工作难度、证明系统安全、
抗重放物理回滚、硬 CPU 抢占、跨故障域 Cell 可用性或 Hepta 最终产品效果。它没有给予任何
训练输出、模型版本或发布声明额外的共识权重。所有 production/public-network/independent
acceptance 标志保持 false。

继续适用 [Application V6 契约](PQ_APPLICATION_AUTHORIZATION_V6.md) 的其余独立门槛，以及
[PQ 网络 owner 契约](PQ_NATIVE_NETWORK_OWNER_V2.md) 中认证和保密分离、有限本地预算和
不支持组合的拒绝要求。本文只说明 continuous+NPQ6 的这一候选实现，不把旧文档中相关待办
自动标为运行验收完成，也不替代至少三组独立管理员和 72 小时 WAN 等原计划证据。
