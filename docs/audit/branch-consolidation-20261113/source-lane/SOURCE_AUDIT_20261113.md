# Trillionnium-Chain 分支整合：源码与权限边界审计

## 固定对象与结论

本报告审查现有整合候选 [PR #847](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/847)，固定提交为 `b683714cdd5ba241c16c335a81aebc12c1581902`，树为 `f11a77d95b665207206282f691efc9d1225f26ea`。其目标主线为 `dd6e1c3cbeacbdc532b0679297835b3a0aac78f0`。后续整合提交必须重新核对受影响的源码、声明与检查结果；本报告不是后续提交的执行证明。

**该候选适合作为继续整合的现有基线，但目前不能据此宣称已完成整仓合并、独立系统验收或生产资格。** 当前机器声明明确保留 `runtime_implemented=false`、`work_profile_qualified=false`、`production_candidate=false`、`production_consensus_activation=false`、`public_testnet_ready=false`、`release_ready=false`。分支清理必须建立在实际代码整合、原始提交可恢复及最终受保护主线门禁完成之后。

## 审计覆盖与可复查计数

| 检查 | 本次观察 |
| --- | --- |
| 完整 Git 树枚举 | 40,749 个条目；未发现符号链接或子模块条目 |
| 初始远程分支退休目录盘点 | 908 条分支，每条均成功读取其 crate 目录树 |
| 完整候选树一级目录计数 | evidence 35,260；formal 2,570；trillionnium 1,659；scripts 515；docs 338；config 79；其余 328 |
| 固定源码快照 | 从上述提交导出 trillionnium、scripts、config、.github、docs，共 2,630 文件、45,636,952 字节；逐文件重算 Git blob 身份，全部匹配固定树 |
| Rust 文件枚举 | trillionnium 1,580；formal 84；evidence 104；其他位置 15；全树共 1,783 |
| 工作区声明 | 26 个 crate 与 portability inventory 的 26 个条目一致 |
| 静态内部依赖声明 | 29 条内部边，126 条外部依赖声明；普通/构建图及包括 dev 的静态并图均未见环 |
| 不变量引用 | 21 项不变量，60 个独有源码路径，216 个测试选择器，涉及 40 个测试文件；路径和声明名称均存在 |
| PQ 权限声明现有 pin | 44 个文件全部与其声明的 SHA-256 相符；声明仍明确 coverage_complete=false |
| 工作流 action 引用 | 136 处 uses 引用均固定到完整提交或本地 action |
| 未实现宏扫描 | 活跃 Rust 文件未命中 todo! 或 unimplemented!；这项词法观察不证明功能完整 |

静态依赖图不是 Cargo 的实际特性/目标解析结果；函数声明存在不是测试已经收集或执行。上述文件数量也不是逐行人工证明覆盖率。本次深读聚焦退役规则、机器声明、模块职责、不变量、资格读器、恢复下界、工作来源认证及 SQLite I/O 边界；未重新运行原生系统、模型、外部支付、WAN、物理断电或攻击实验。

## 需要在整合中处理的具体项目

### S1：旧运维分支只有一个独有部署工作流，应作历史处置，不能恢复为活跃目标

分支 `ops/recover-qian-qi-20260925`，提交 `b1a787f0848c464a99b1f9854b6c133f933c5c47`，不属于当前 main 或固定候选的祖先。其父提交是 `c552c31c6d3c5ac47522a124e02c6b8bca4e23f2`；相对父提交只有一项新增：`.github/workflows/ops-recover-qian-qi.yml`。

这是 908 条初始分支中唯一仍带有全部 41 个已退役 crate 目录的分支头。**普通三方合并不会因此自动恢复全部 41 个目录**：这些目录在分支父代已经存在，主线的后续删除通常仍会保留。真正独有且会被引入的是恢复远端运行服务的 self-hosted 运维工作流。该工作流针对其旧分支的 push 事件，当前生产服务操作不属于本次源码整合范围。

当前 [AGENTS.md](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/b683714cdd5ba241c16c335a81aebc12c1581902/AGENTS.md) 与唯一开发计划明确禁止恢复退役部署工作流，并把已部署状态、密钥和运行服务排除在范围外。建议将这个精确提交及其原始 DAG 保存在可 fetch 的历史引用中，给出明确的“历史运维目的已退役、不进入活跃树”处置记录。不得通过复制旧分支全树恢复已删除组件。当前 repository checker 对 retired package 名称有门禁，但针对 required-baseline 的 self-hosted 检查并不能单独覆盖这项名称无退休关键词的历史工作流。

### S2：候选包含明确标记为本地实验的节点 test profile

[trillionnium/Cargo.toml](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/b683714cdd5ba241c16c335a81aebc12c1581902/trillionnium/Cargo.toml) 第 74 行明确写有 `LOCAL DEBUG EXPERIMENT ONLY`，要求独立完整 CI 后才能合并；随后为 `trnm-pon-node` 的 test profile 设置 `opt-level=3`，同时保留 debug assertions 和 overflow checks。

此设置没有直接改变 release profile，也没有关闭检查，但会改变测试二进制、执行时间和资源观察。最终整合必须明确保留或撤销这一选择，并在该决定后的精确树执行原有完整门禁。早先未包含该 profile 或未包含后续分支的测试记录不能替代新树结果。不能仅删除注释来表示独立 CI 已完成。

### S3：当前锁文件、reviewed source 和归档证据是不同对象

全树非 evidence 区域有 48 个 Cargo.toml 和 14 个 Cargo.lock，覆盖主工作区、fuzz、研究适配器、多个证明路线与 qualification capsule。根工作区通过不自动推出这些其他图均通过。现有 PQ 权限表的 44 个文件 pin 与固定候选匹配，但它的 `source_revision` 是经过声明的 `2bb56596e637908c44b5a2ef5984c9c37c7d3cc8`，范围是 curated-source-consistency-only。

合入新分支或修复当前 CI 时，应保留原来的成功和失败证据，审查实际依赖/行为差异，再更新受影响的 current-source 声明。不要把旧报告的原始源身份改写成新提交；不要把批量重算哈希当作独立语义审查或原测试重新执行。本次的 44-pin 匹配仅确认这一声明与当前字节一致，不声称全链权限追踪完整。

### S4：普通 Hepta 完整闭环仍由实际读器明确拒绝授予资格

[chain_hepta_qualification.py](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/b683714cdd5ba241c16c335a81aebc12c1581902/scripts/ci/chain_hepta_qualification.py) 在第 513 行保留 `RAW_OUTCOME_UNVERIFIED`，第 518–519 行返回 `result_payload_verified=false` 和 `current_materials_consistent=false`，第 704 行固定资格为 `HOLD_NO_GO`、权限为 `DENY_ALL`。

这不是可以在合并中“修正成成功”的占位值，而是尚无完整 native outcome adapter 和同一操作验收证明的诚实边界。跨分支存在训练、评估、Selection/NoUpdate、安装、消费者任务、支付或恢复文件，不代表这些阶段已经形成同一普通运行路径。合并时必须保留这个拒绝语义及其原始失败记录，直到对应真实链路经过独立验收。

### S5：恢复下界与来源认证仍依赖外部真实权限

[RecoveryFloorV4::from_external_pin](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/b683714cdd5ba241c16c335a81aebc12c1581902/trillionnium/crates/trnm-pon-node/src/root_recovery_v3/recovery_floor.rs) 校验形状并绑定完整 enrollment，但不会认证调用方提供的历史下界来自独立、足够新的恢复来源。代码第 29–30 行明确说明同一恢复状态提供的 pin 不产生独立回滚保证；新鲜度仍由恢复 owner 负责。

[qualified_work_task.rs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/b683714cdd5ba241c16c335a81aebc12c1581902/trillionnium/crates/trnm-crypto-primitives/src/qualified_work_task.rs) 同样区分严格来源签名、当前分支上下文和真实需求/授权/模型语义。私有构造可以防止未校验字节直接变成 checked fact；它不能证明物理独立性、合法需求或工作成本下界。归并分支时不得把这些显式信任前提升级成无条件系统保证。

### S6：Rust 安全子集和 SQLite 所有权边界应保持原有适用范围

主要 native library 使用 `forbid(unsafe_code)`，但 CLI 的受限 stdin 调用和 `trnm-sqlite-io-boundary` 的 FFI/VFS 边界仍有显式 unsafe。后者使用 `deny(unsafe_op_in_unsafe_fn)`，其 crate 文档明确限定为调用方独占的有限本地根目录和实际 inode；同 UID 的敌对文件系统修改和外部默认 VFS 连接不在其保证内。

该边界的 7 个根、每根最多 3 个 inode、每 inode 16 MiB 是逻辑高水位范围，不是完整存储成本、物理 allocated-block 配额或整链无限历史界。局部 Rust/SQLite 控制通过后，仍须保留物理断电、长期保管、外部操作恢复和独立运营的单独验收状态。这是适用范围审查，不是本次发现了可利用内存漏洞。

## 当前活跃树保持的退休与权限约束

固定候选没有恢复 inventory 中 41 个 decision=delete 的旧包，也没有恢复以下 6 个旧入口：`docs/protocol/poco-bft-v0`、`docs/protocol/poco-convergence-v1`、`docs/protocol/poco-ai-native-v1`、`web4-frontend`、`scripts/poco-fleet`、`docs/audits`。已有源码门禁检查 package inventory、retired symbols、Cargo path dependency 归属、当前机器声明、全部本地 Markdown 链接和必要检查工作流。

独立静态解析与现有 gate 的源码审查一致：保留的方向是 PoN/Nakamoto 式累计已验证 required-work，不是旧 PoCO-BFT、质量权重投票或自动退回旧共识。26 个现有组件分别归属 M00–M17；没有观察到新增未登记的活跃 crate。

21 项不变量在当前机器注册表内均保留适用范围与 remaining 项。需要继续保持的主要未闭合边界如下：

| 模块范围 | 当前组件范围 | 独立系统资格仍需解决 |
| --- | --- | --- |
| M00–M02 | 编解码、严格签名、实验工作和参考/原生分支构件 | 第三方验证、所有合法策略成本、原生公开共识与联合安全界 |
| M03–M04 | 本地 operation/revocation、受限传输与恢复容量 | 普通 FinalUse、独立 rollback frontier、公开网络公平与服务可达性 |
| M05–M08 | nonce、确定性执行、显式 SQLite backend、reorg 观察 | 完整 mempool/host 接线、历史存储成本、物理断电和外部补偿 |
| M09–M11 | Cell 字节身份、受限贡献、完整 roster/受控评估 | 独立 WAN 保管、真实未来窗口价值、来源/评估治理 |
| M12–M15 | 有限奖励/配额、存储重放、服务回执、development Node | 外部货币价值、真实 GPU 资金、普通消费者/effect、持续公开节点 |
| M16–M17 | 非权威建议与冻结证据检查 | 真实多代收益、独立复核、最终树原始门禁和部署资格 |

## 整合结束时应核对的具体结果

1. 每个初始和整合期间新增分支均有精确旧 SHA、合入/等价/退休处置及可恢复引用；旧运维分支的唯一部署工作流明确保留在历史中。
2. main 的最终内容包含保留成果及原始失败证据，保留 false/null/HOLD 和当初的源身份，未恢复旧协议/运行时/部署入口。
3. 所有最终 source pin 的变化均有实际差异审查；主工作区、fuzz 和受影响独立 Cargo 图按原 gate 执行，历史日志不重标为当前执行。
4. 必要检查在实际最终 head/prospective merge 上满足保护要求后才进行主线合并与分支删除；不以源码审查结果替代 CI，也不改变保护规则。
5. 分支列表最终读回确实只剩默认分支。该 Git 管理结果与 PoN/模型/安全/经济的产品资格分开报告。

## 机器记录

本目录的 `candidate-tree.json` 保存完整树枚举；`branch-retirement-inventory.json` 保存 908 条分支退休目录检查；`static-audit-summary.json` 保存依赖图、action pin 与路径检查；`active-snapshot-integrity.json` 保存 2,630 个文件的精确 Git blob 对照；`selector-and-authority-integrity.json` 保存 216 个选择器与 44 个 authority pin 对照。选择器记录保留了一次本次审计方法修正：初始词法检查误将 Python `Class.method` 当作 Rust 函数名，随后改为 Python AST；未修改仓库、未因此宣称项目测试失败。

本报告没有执行或复现攻击，没有修改远端分支、保护规则、服务或密钥，也没有更改共享候选源码。
