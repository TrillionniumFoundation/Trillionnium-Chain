# 最终 profile 边界复核：五项要求与未闭合项

审阅：`/root/pq_profile_review`；2026-11-10 America/New_York（2026-11-11 UTC）。只读核对最终提交 `cdd984808a088e6c2e13b1e1ae6630a94d500c89`，tree `1ed39b6ebe55cb00c238f26f6bfc9361ab93faec`；审阅开始时工作树干净。本报告不修改仓库、不执行 Cargo，也不把静态审阅计为原生测试。

**结论：Z 加固了现有研究应用的执行与恢复边界；经典 development 的真实状态效果仍然存在，生产合格 profile 集合仍为空。** 在以下代码与文档范围内，未发现把研究路径或局部验证提升为全链 PQ／生产资格的新增声明。[S1][s1] [S2][s2]

## 五项覆盖矩阵

| 用户要求 | Z 已落实及可核查依据 | 未闭合项／最终报告应保留的限制 |
| --- | --- | --- |
| **1. 哪种 profile 可成为网络有效节点** | `Config::check_account_profile` 对所有现有账户 profile 强制精确类型和值：`production_activation=false`、`not_mainnet=true`、`coin_atomic_unit="test-unit-no-market-value"`。缺失、`null`、错类型或改值均拒绝。显式 PQ 仍须通过原私有 owner 的配置校验。边界文档明确 **production-qualified profile set 为空**。[S1][s1] [S3][s3] | 这是运行时研究范围约束及资格声明，不是已经部署的生产准入协议。研究节点仍可在对应测试网络中验证区块、产生状态效果；没有新生产授权入口。未来必须独立批准绑定账户、peer、治理、发布、恢复和工作规则的完整激活转换。 |
| **2. 旧账户、旧授权、旧快照如何迁移** | 现有 Node 接口在同一 SQLite 只读快照中取实际已接纳 checkpoint；独立 pins 绑定 source network/genesis/checkpoint，另验 prior PQ registry commitment。M06 重算完整状态根，检查支持范围内的余额、nonce floors、任务／奖励负债及守恒；不支持的行即使为零也拒绝。迁移建立独立 PQ 研究 genesis，导入账户在匹配 anchor、原始 nonce、预承诺 PQ key 的 CLAIM 前保持锁定。[S4][s4] [S5][s5] | 保留侧链 checkpoint 也可作为输入，所以“已接纳”不证明 canonical membership 或外部 **finality**。注册表承诺不能证明其早于妥协而存在；本导入不会退休源网络资产或旧授权。完整授权域覆盖、独立 **retirement**、旧凭据被量子伪造后的归属，以及各回滚域的单调消费／撤销前沿仍须外部证据。旧快照不能靠改目录或标签变成 PQ 状态。 |
| **3. 哪些经典路径只能用于测试** | 普通 CLI 的 `--development` 未指定 PQ application 时仍进入 `Envelope::decode`、严格经典验签，再真实 debit／credit、nonce、fee；空块也有成熟奖励和补贴效果。新增 M06 测试明确保留这些行为。经典分支拒绝 `account_authorization_profile` 和任何 `native_pq_*` 字段，包含 `null`。私有 PQ owner 继续强制原配置校验；NPQ2–6 selector 即使为 `null` 也不进入经典执行，删 selector 不能卸除私有 owner。[S3][s3] [S6][s6] [S7][s7] | 限于无价值开发／研究账本，**并未删除经典执行路径**，也未将其限制成只在单元测试中编译。部分显式研究 listener 可以非 loopback；部分 operator 路由早于通用 `--development` 检查，依其既有 owner 合同和共享 guard。`pq-tls-serve` 实际调用 `Settings::development`，故 **PQ 传输不代表 PQ 账户授权**。[S1][s1] [S8][s8] |
| **4. 恢复、升级、配置错误能否重新打开经典授权** | 常规 opener 在 native namespace 效果前检查；cold-open 继续绑定 schema、parameters、genesis、PQ owner 与 witness。warm `namespace`／`recover`／activation 重新检查现行 scope，错误转为 `LocalStructure`，既有 `requires_owner_stop()` 能识别；普通 startup 错误与远端同名诊断不能制造该分类。Growth 的独立 activation 路径通过 `growth_guard→namespace`，在写事务及 no-op 返回前重检。已有 PQ/private-owner 配置与存储限制仍保留。[S9][s9] [S10][s10] | **合法旧经典开发快照仍可恢复为原经典研究账本**。本轮拒绝 scope 改标和 PQ 残留误落经典，不承诺永久关闭所有经典恢复，也不永久 fencing 任意库调用者。现有 PNQ2 witness 明确只保护三张 PNQ2 表；完整账户／reorg／其他 owner 状态及共同备份回滚不由它覆盖。独立单调状态的部署、持久性与全部 effect 绑定仍未闭合。[S11][s11] |
| **5. 网络参与者怎样共同验证 profile 与算法版本** | 已验证的 NPQ owner 经 `crypto_profile_id` 绑定固定算法／编码、network、parameters、genesis、NPQ 版本与 scope。PNQ2 `PolicyRecord` 还绑定 roster、generation、资源限额；`require_profile_claim` 比较外部声明与独立选定 ID。输入帧不能选择较弱 verifier。`CryptoProfilePolicy` 区分历史与当前选择；candidate 65／87 均不能产生 current selection。[S2][s2] [S12][s12] [S13][s13] | 本轮未给旧 wire 加入 profile 字段，不能称为完成了新全网 ID 握手、算法协商或共同治理激活。构造器要求 owner 提供已认证配置，不替 owner 认证配置。退役窗口的认证／持久化、最终权限、nonce、余额及 FinalUse 仍属实际 effect owner。profile 一致不证明生产资格、保密性或 PoN 工作的量子安全。 |

## 文档与代码 claim 核查

- **经典独立路径与 fallback 分开表述。** 本次追踪到的显式 PQ CLI 分派及 executor 分支直接返回其自身结果；未发现 PQ 验证失败后转入 Ed25519 的分支。已证明存在的是独立、可达、能产生真实效果的经典开发路径；不把限定范围的审查扩写为对任意未来实现的否定证明。[S3][s3] [S6][s6]
- **研究资格没有被提升。** 边界文档及开发计划前言保留 production admission 为空、迁移／独立恢复／whole-chain HOLD；CryptoProfile 文档保持 Draft／HOLD、candidate 无 current activation。`select_current` 的代码与该声明一致。[S1][s1] [S2][s2] [S13][s13] [S14][s14]
- **warm 停止语义需精确。** 文档中 warm owner “cannot continue” 应读为当前坏配置下受检操作拒绝、现有 service owner 收到停止分类；没有新增不可撤销的 Node 实例封禁状态。Node 测试自身会恢复原 Settings 后再次读状态，明确不证明永久 fencing。[S10][s10]
- **失败不等于所有外部效果归零。** 已有 Settings 的常规 opener 在 namespace 创建前拒绝；protected startup 尚未构造 Settings 时，授权读取、预算预留、失败 accounting／journal 仍按原顺序保留。growth observer 也可先建立有限私有快照。二者不赋予错误配置账本授权，不能被报告成“所有入口均零文件／零 journal 效果”。[S1][s1] [S15][s15]

## 验证归属与最终报告限制

本次只读检查了新增 **5 个 M06 测试和 4 个 Node 测试**的实际断言；这不是测试执行结果。Node 覆盖 fresh／cold／warm 的 legacy、authenticated 与真实 growth fixture，包含 scope 与 PQ marker 负控、cold-open 字节不变和 warm owner-stop 分类。[S7][s7] [S10][s10]

后续已另外核对保存的原始 context／result／stdout／stderr 及其日志哈希：同一 Z 的 [M06 原生执行][m06-run]有 18 个 suite，272 passed、0 failed、9 ignored、0 filtered，包含新增 5 项；[desktop Node 新增测试][node-run]为 4 passed、0 failed、0 ignored、1398 filtered，于 02:11:19 UTC 完成；[严格 workspace Clippy][clippy-run]按 `--all-targets --all-features -- -D warnings` 退出 0。**1398 filtered 不能计为通过，也不能由这 4 项推定完整 Node retained suite 通过。** 这些是原 runner 的真实执行，本审阅者没有重跑 Cargo。新的 [desktop repository-truth 完整重跑][repository-run]也已有退出 0 的终态；同包首次失败和环境修复记录仍原样保留。

本审阅者先前在同一 Z 实际完成的来源验证有独立记录：59 个 corpus 测试、43 个 source-integrity 测试、19 个 W1 lifetime 测试均通过；7 份 closure report 实际生成并逐一 `cmp` 通过。其正检仍返回 `HOLD_NO_GO`，不授予密码学或生产资格。详见[逐命令汇总][validation]。该汇总的 delegated-pending 字段保留其写入时状态，不能作为后续整条 lane 的结论。

完整 Rust baseline 等余下门禁仍须按各自真实终态汇总；不得将测试源码、局部通过或旧 cohort 当成本轮全量通过。此前 SIGKILL、EXDEV、缺 GNU time、ENOSPC 等失败记录不能抹除；本报告不据此诊断安全性，也不预报未结束的重跑成功。即使原生与全部工程门禁最终通过，上表的生产激活、外部 finality／retirement、全 effect 单调恢复与 whole-chain PQ 缺口仍保持开放。

## 代码与文档索引

- S1：[账户授权开发边界][s1]，第 1–7 节。
- S2：[CryptoProfile 合同][s2]，owner 选择、迁移／恢复义务及 HOLD。
- S3：[M06 executor][s3]，`Config::check_account_profile`、`prepare`、`execute_with_state_inputs`、`prepare_block_state_with_inputs`、`apply_authenticated_application`。
- S4：[Node checkpoint handoff][s4]，`inspect_pq_migration_checkpoint`、`prepare_pq_migration_checkpoint`。
- S5：[迁移 importer／CLAIM][s5]，`TrustedPqPrecommitments::pin_checkpoint`、`resolve_claim`、`apply_claim`。
- S6：[CLI 分派][s6]；[显式 PQ 本地入口][pq-local]。
- S7：[M06 实际状态效果与拒绝测试][s7]。
- S8：[PQ TLS 研究入口][s8]，`Settings::development`。
- S9：[Node store][s9]，common opener、storage context、namespace、recover、activate。
- S10：[Node scope 负控][s10]；[growth guard][growth]；[growth recovery][growth-recovery]；[Error 分类][error]。
- S11：[外部 rollback witness 范围][s11]；[PNQ2 三表 protected_root][witness-store]。
- S12：[NPQ profile 绑定][s12]；[PNQ2 owner policy][peer-policy]。
- S13：[CryptoProfile 实现][s13]，`select_current`、`select_historical`、`recheck_current`。
- S14：[开发计划当前前言][s14]；[whole-chain HOLD guard][whole-claim]。
- S15：[mining startup 顺序][s15]；[continuous startup 顺序][continuous]；[growth snapshot opener][growth]。

[s1]: sandbox:/workspace/scratch/a4188f5c86b5/chain-pq-profile-boundary/docs/security/ACCOUNT_AUTHORIZATION_DEVELOPMENT_BOUNDARY_20261110.md
[s2]: sandbox:/workspace/scratch/a4188f5c86b5/chain-pq-profile-boundary/docs/security/CRYPTO_PROFILE_V1_20261104.md
[s3]: sandbox:/workspace/scratch/a4188f5c86b5/chain-pq-profile-boundary/trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs
[s4]: sandbox:/workspace/scratch/a4188f5c86b5/chain-pq-profile-boundary/trillionnium/crates/trnm-pon-node/src/store/pq_migration_inventory.rs
[s5]: sandbox:/workspace/scratch/a4188f5c86b5/chain-pq-profile-boundary/trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/migration.rs
[s6]: sandbox:/workspace/scratch/a4188f5c86b5/chain-pq-profile-boundary/trillionnium/crates/trnm-pon-node/src/main.rs
[s7]: sandbox:/workspace/scratch/a4188f5c86b5/chain-pq-profile-boundary/trillionnium/crates/trnm-mvcc-fee/tests/account_development_scope.rs
[s8]: sandbox:/workspace/scratch/a4188f5c86b5/chain-pq-profile-boundary/trillionnium/crates/trnm-pon-node/src/pq_tls_cli.rs
[s9]: sandbox:/workspace/scratch/a4188f5c86b5/chain-pq-profile-boundary/trillionnium/crates/trnm-pon-node/src/store.rs
[s10]: sandbox:/workspace/scratch/a4188f5c86b5/chain-pq-profile-boundary/trillionnium/crates/trnm-pon-node/src/store/account_profile_scope_tests.rs
[s11]: sandbox:/workspace/scratch/a4188f5c86b5/chain-pq-profile-boundary/trillionnium/crates/trnm-pon-node/src/pq_rollback_witness.rs
[s12]: sandbox:/workspace/scratch/a4188f5c86b5/chain-pq-profile-boundary/trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2.rs
[s13]: sandbox:/workspace/scratch/a4188f5c86b5/chain-pq-profile-boundary/trillionnium/crates/trnm-protocol/src/crypto_profile.rs
[s14]: sandbox:/workspace/scratch/a4188f5c86b5/chain-pq-profile-boundary/docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md
[s15]: sandbox:/workspace/scratch/a4188f5c86b5/chain-pq-profile-boundary/trillionnium/crates/trnm-pon-node/src/store/operator_mining_owner.rs
[pq-local]: sandbox:/workspace/scratch/a4188f5c86b5/chain-pq-profile-boundary/trillionnium/crates/trnm-pon-node/src/pq_application_local.rs
[growth]: sandbox:/workspace/scratch/a4188f5c86b5/chain-pq-profile-boundary/trillionnium/crates/trnm-pon-node/src/store/growth.rs
[growth-recovery]: sandbox:/workspace/scratch/a4188f5c86b5/chain-pq-profile-boundary/trillionnium/crates/trnm-pon-node/src/store/growth/recovery.rs
[error]: sandbox:/workspace/scratch/a4188f5c86b5/chain-pq-profile-boundary/trillionnium/crates/trnm-pon-node/src/error.rs
[witness-store]: sandbox:/workspace/scratch/a4188f5c86b5/chain-pq-profile-boundary/trillionnium/crates/trnm-pon-node/src/store/pq_rollback_witness.rs
[peer-policy]: sandbox:/workspace/scratch/a4188f5c86b5/chain-pq-profile-boundary/trillionnium/crates/trnm-pon-node/src/ingress/pq_network.rs
[whole-claim]: sandbox:/workspace/scratch/a4188f5c86b5/chain-pq-profile-boundary/docs/security/WHOLE_CHAIN_PQ_CLAIM_GUARD_20261031.md
[continuous]: sandbox:/workspace/scratch/a4188f5c86b5/chain-pq-profile-boundary/trillionnium/crates/trnm-pon-node/src/store/operator_continuous_owner.rs
[validation]: sandbox:/workspace/scratch/a4188f5c86b5/coordination/source_validation_summary_z.json
[m06-run]: sandbox:/workspace/scratch/a4188f5c86b5/validation/cdd984808a088e6c2e13b1e1ae6630a94d500c89/m06-retained-tests/result.json
[node-run]: sandbox:/workspace/scratch/a4188f5c86b5/desktop-evidence/cdd984808a088e6c2e13b1e1ae6630a94d500c89/primary-evidence-v1/primary/validation/cdd984808a088e6c2e13b1e1ae6630a94d500c89/node-new-tests/result.json
[clippy-run]: sandbox:/workspace/scratch/a4188f5c86b5/desktop-evidence/cdd984808a088e6c2e13b1e1ae6630a94d500c89/primary-evidence-v1/primary/validation/cdd984808a088e6c2e13b1e1ae6630a94d500c89/strict-workspace-clippy/result.json
[repository-run]: sandbox:/workspace/scratch/a4188f5c86b5/desktop-evidence/cdd984808a088e6c2e13b1e1ae6630a94d500c89/repository-truth-evidence-v1/validation/repository-truth-runtime-python/result.json
