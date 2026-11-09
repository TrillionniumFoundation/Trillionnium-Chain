# Chain / Hepta 固定候选与关闭证据（2026-11-09）

**本批交付冻结一个可审阅的整合源码候选，并保留全部失败与未观测状态。总资格仍为 `HOLD_NO_GO`，权限为 `DENY_ALL`。**

## 固定身份

| 项目 | 固定值 |
| --- | --- |
| Chain 执行源码（M6） | `4dbeae12fa756fd662cc074390fcb628abe970ad` |
| Chain tree | `1943c3e69e3a717ce99d91aabc00eba4d37516f1` |
| Hepta 对应源码 | `71738345326b98d88b738250d2b84ecbcb466eb8` |
| Hepta tree | `bfd8384241bf09fcf79daa94f2ef9c9438f92ee4` |
| Proof profile | `trnm-w1-risc0-3.0.6-poseidon2-join-v2` |
| Proof descriptor SHA-256 | `da0c97f1c549e10ecfc066f6b0a9721147dc3d430eab6f53d502cbc7b91dd48c` |
| 集成候选 profile SHA-256 | `175524d6cafe93f1f175d272bee1b9be4d22c954909be3fca6d4955362900775` |
| Qualification plan SHA-256 | `94d02a1f21b9e33b5fb22ea53fe0445433aaa8e03d5f0ca446ad3c33cd3b3df8` |

这里区分执行源码和保存证据的后续提交，避免用包含后来报告的 HEAD 冒充先前运行源。[六次源版本的真实父关系](source/source-lineage.json)逐一核对原commit对象；本目录将随M6之后仅增加证据的提交发布。M4 与 M5 的 profile、plan、packet、review 及摘要原件分别保存在 [M4 历史绑定](qualification-history/M4/qualification-identities.json) 和 [M5 历史绑定](qualification-history/M5/qualification-identities.json)；当前 M6 由新 profile 逐层重算并再次运行原 qualification reader，返回合法 HOLD（exit 2）。
[candidate-profile.json](candidate-profile.json) 固定14份Chain选定lock输入（含研究/审计输入，不代表它们都参与本次编译）、两份 Hepta lock、证明 descriptor 和原验收预算。
[qualification-plan.json](qualification-plan.json)、[packet](qualification-packet.json) 及 [review](qualification-review.json) 使用既有 qualification reader；原生资格所需的普通 daemon 二进制、实际加载、解释器、库、环境、模型、loader、evaluator 和完整双工作树 source collector 未观测的字段保留 `null`。库测试 ELF 的实际身份另存，不填入普通 daemon 的 build/load 字段。
原生 case roster 尚未配置，空列表不表示豁免。工程检查放在独立证据目录，没有伪装成普通 daemon 的成功记录。

## 本次实际改变

保留三条输入的 Git 父关系完成合并：[#835](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/835) 的 `e2a02f9271b49f146e70806c8a66e161b5973971`、[#836](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/836) 的 `0746a462e80067b78317597f2fa4bacf5e3db958`、[#837](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/837) 的 `44330b91eb552fd20ef6f2e69bf5e6f1e8f5c0b0`。真实三方合并保留较新的 signer quorum preflight、Generation V3 witness API 和 `trnm-protocol` 普通依赖，未整文件覆盖回旧分支。

新增三个有明确边界的证据读取器：

1. **Learning scope join**：独立固定 Root initial checkpoint 与 scope，核对请求、操作、owner、初始 head、update rule，以及每份 Training 的组件约束。采用固定 Hepta 717 的 `{update_scope, update_rule, binding}` 形状。NoUpdate 也接受同样的训练约束检查。测试中的 Root profile 是 synthetic parser fixture，原生 checkpoint 是历史原件；它们不证明 717 普通 daemon 实际执行或张量更新 mask 正确。
2. **Campaign outcome reader**：保留计划轮次、已观察轮次、确认轮次和未观察轮次；仅在调用计数、完成、丢失、未知 CPU 等字段完整平衡时给出完整计量。部分已知 CPU 单列，缺测不变成零，嵌套 CPU 不相加。
3. **Proof profile binding**：明确选择 RISC0/BabyBear/Poseidon2/FRI profile，固定实际 image/control/parameter、映射契约及保存的输入；把 native-PNW1 生命周期实验和两个 P3 候选分开。15 项证明义务全部保留 `UNRESOLVED`，生命周期失败上界仍为 `null`。

更新了 44 路 authority、37 路 Root dependency 和 137 个 W1 本地输入的源码绑定，并保留历史版本和拒绝结果。源码 corpus 仍包含 967 个 required paths、1,059 个 blob pins。新增 CI workflow 在 PR head 与 prospective merge 两条 lane 分别运行三个读取器 suite；它没有执行原 Host 或 campaign，也没有把读取器成功命名为服务通过。

## 固定候选上的验证

### 当前 M6 的完整源码控制

| 固定 M6 的完整命令 | 结果 | unittest 耗时 |
| --- | --- | ---: |
| CI contract | 176 / 176 通过 | 105.315 秒 |
| Learning scope | 11 / 11 通过 | 1.664 秒 |
| Campaign reader | 23 / 23 通过 | 0.019 秒 |
| Proof profile controls | 26 / 26 通过 | 0.581 秒 |
| 完整 PQ research integration | 59 / 59 通过 | 201.071 秒 |
| 显式 descriptor 与 corpus CLI | 均 exit 0，资格保持 HOLD | — |

[M6 完整摘要](validation/M6-controls/summary.json) 对应 `4dbeae12`，全批为 2026-11-09 17:17:58–17:21:20 UTC。295 项均按完整文件执行，没有跳过、方法筛选或工程 timeout；前后 HEAD/tree、tracked status 和1,380份输入摘要一致，12份原fixture匹配冻结树，14份原stdout/stderr的大小及SHA全部核验。[Cargo graph、inventory与rustfmt](validation/final-source-structure-M6/results.json) 同样绑定干净M6。另从Hepta717原Git对象补核的[两锁原件记录](source/hepta-717-lock-object-verification.json)匹配既有摘要；它仍不是完整双工作树身份collector。

### 当前 M6 的实际五库验证

[M6 原生原件](validation/native-M6/README.md) 已在同一固定源码、Rust1.95.0、canonical static OpenSSL3.5.9 环境完成。原五包 selection 的实际编译产物全部无顶层过滤执行；workspace/all-features/lib check、严格 Clippy（`-D warnings`）与 rustfmt 均通过。

| M6 library | 通过 | 失败 | 顶层 ignored |
| --- | ---: | ---: | ---: |
| data-availability | 715 | 0 | 0 |
| crypto-primitives | 196 | 0 | 0 |
| pon-node | 1,359 | 0 | 39 |
| protocol | 113 | 0 | 2 |
| release-bundle | 67 | 0 | 0 |
| **合计** | **2,450** | **0** | **41** |

[五库 ELF 身份关联](validation/native-M6/artifact-direct-crossjoin.json)核对实际 compiler-artifact 与每次运行前后的 path、bytes、SHA-256、cfg(test)，并要求source/provider、test profile、package cwd和精确argv一致。只有node ELF字节相对M5 canonical改变，其余四库仍进行了本次实际执行。主包180份原文件及manifest、9个controller jobs的18条完整stdout/stderr均已核对；[root独立核验](validation/root-M6-native-delivery-review.json)直接从原stdout重算了上述主分母。

node主roster仍为1398，361.75秒完整结束。仅为保留成功测试输出增加`--show-output`；新journal的[完整child原文](validation/native-M6/journal-exact-child.log)记录一个实际测试、body完成及成功退出。四条nested摘要不加入顶层通过数。**41是顶层ignored计数**；部分helper由原有父测试显式调用，其中`held_file_substitution_child`有独立的nested成功记录。[作用域更正](validation/native-M6/ignored-scope-correction.json)撤回旧交接中“41项全部未执行／均为业务gate”的泛称，保留M5原件。原服务、容量、重型发布门槛仍开放；M6成功也不证明M5 EAGAIN的具体原因。

### 已保留的 M5 源码控制

| 固定 M5 的完整命令 | 结果 | unittest 耗时 |
| --- | --- | ---: |
| CI contract | 176 / 176 通过 | 84.369 秒 |
| Learning scope | 11 / 11 通过 | 1.209 秒 |
| Campaign reader | 23 / 23 通过 | 0.016 秒 |
| Proof profile controls | 26 / 26 通过 | 0.409 秒 |
| 完整 PQ research integration | 59 / 59 通过 | 171.667 秒 |
| 显式 descriptor 与 corpus CLI | 均 exit 0，资格保持 HOLD | — |

[M5 完整摘要](validation/M5-controls/summary.json) 对应 `3ad605ec`，全批为 2026-11-09 15:51:17–15:54:09 UTC。295 项 Python 控制均按完整测试文件运行，未筛选方法，工程超时没有触发。运行前后 HEAD/tree、空 tracked status 以及 1,380 份源码、配置和 fixture SHA-256 清单一致；12 份学习 fixture 同时匹配该冻结树的 Git blob 与原件摘要。所有14份 stdout/stderr 的大小和摘要均核验。

M4 `e4e4a8e049915ba09d9e97444b4709ce8769ce81` 的先前 176、11/23/26/59 项结果保留于 [原 CI summary](validation/ci-M4-passed/summary.json) 和 [原 readers summary](validation/readers-M4/summary.json)。它们不移名为 M5，也不与重复执行的当前测试相加。固定 M5 的 [locked/offline Cargo graph 与 inventory](validation/final-source-structure-M5/results.json) 另存，原 M4 版本同样保留。

绑定修订阶段另有 authority 18、Root 42、W1 14、profile 26 项控制通过，原输出及各输入摘要保留于 [binding-review](binding-review/m2-python-controls.json)。它们包含与上表重复运行的 profile 控制，不合并成虚增的测试总数，也不声称是 M4 全套原生资格。

失败记录同样保留：

- M3 的完整 176 项合同运行有一处 `pq_effect_root` 邻接清单失败。实际 CI lane 已有 11 条新增 Root 命令，独立预期清单未同步。M4 仅补齐这 11 条字面量，保留 before/after、唯一性及变异拒绝；[原失败](validation/ci-M3-failed/summary.json) 和成功重跑分别保存。
- 最早 scope 运行因 sparse checkout 尚未物化原 fixture 而执行零项；补齐的是原 Git 字节，没有改测试输入或断言。
- 最早完整 corpus 工程检查触及 240 秒 harness 上限，其间 CI 清单也正在修复，后续 guard 正确拒绝旧 pin。固定 M4 后无筛选重跑，在 218.423 秒完成 59 项，未触及独立 900 秒工程上限。该上限与 Host 4 秒、campaign 30 秒无关。
- 初次 CI 预运行被中断、reader 的旧失败／未知、打包停止与磁盘耗尽记录均保留；没有覆盖失败后仅留下最后一次成功。

### M4 原生库失败及 M5 的测试判据修正

[M4 原生原件](native/M4/README.md) 保存 ROG 上实际 locked/offline 检查：workspace/all-features/lib 的 check 与严格 Clippy 均 exit 0。第一次完整五库尝试包含 7 分 45 秒冷构建，在独立工程窗口结束时 crypto 196 项与 data-availability 714 项已通过，node 尚未完成，protocol/release-bundle 尚未执行。原 runner 把三个 node 子进程摘要错算为另外三个库；原汇总保留，更正另存，不能使用原错误的五库完成标志或总数。

确认旧进程、cgroup 和自有工作目录已停止后，M4 暖缓存重复运行在 23.93 秒以 Cargo 101 退出：crypto 196 项通过，data-availability 713 项通过、1 项失败，其他三库未运行。失败发生在完整哈希拒绝测试末尾的关闭 probe；该 probe 只要求原整数 fd 槽不存在，不能分辨原文件仍打开与整数槽被其他并行测试复用。现有日志没有证明哪一种是这次实际原因。

M5 修正此测试 probe，在原 File 存活时记录 fd/dev/ino，关闭后仍指向原对象就必须拒绝；另外加入明确要求 live-original panic 的负控。三个原测试的错误类型、哈希、取消、deadline、selection、usage 和无部分 bundle 断言均保持，生产 loader 与 M4 字节相同。[独立静态审阅](validation/fd-probe-static-review/README.md) 和 [M5 冻结记录](source/M5-freeze.json) 保存确切输入。本检查仍不证明所有 dup/mmap 引用已回收。

M5 的首次统一五包构建后的库测试暴露 fixture 环境缺项：release-bundle 67项中56通过、11项在要求显式`TRNM_PQ_OPENSSL`时拒绝，尚未进入双quorum断言。实际ELF动态链接系统OpenSSL3.5.5；它满足源码最低版本条件，但不能记为仓库原定的static3.5.9环境。[提供者依赖静态审阅](validation/provider-fixture-static-review/README.md)确认CLI生成DER之后，Rust进程内PKey/Signer及SLH验证仍依赖自己的链接库。原失败、动态库身份和后续canonical准备／重新编译／实际测试按不同环境组分别记录；ML-DSA-65 CLI smoke不能替代ML-DSA-87／SLH原测试。完成static3.5.9重新编译后，完整release-bundle实际67/67通过、无忽略／筛除；原11个fixture场景实际进入并通过，单独原执行记录保留其8.68秒耗时与新ELF身份。其他库及同环境check/Clippy的结果另列于最终原生记录，不由这一release成功推导。

### M5 canonical 完整终态与 M6 的测试隔离

[M5 五库原件](validation/native-M5/README.md) 已完成回收：统一五包构建产生的实际 ELF 在 static OpenSSL 3.5.9 环境逐一无过滤执行，workspace check 与严格 Clippy 通过；五个 harness 均完整结束，但结果为 **2,449 通过、1 失败、41 忽略、0 筛除**。这里的41是顶层ignored，包含由父测试调用的辅助用例；其完整含义见后续[作用域更正](validation/native-M6/ignored-scope-correction.json)，不由该数目推导所有body是否执行或业务gate通过。

| M5 library | 通过 | 失败 | 忽略 |
| --- | ---: | ---: | ---: |
| data-availability | 715 | 0 | 0 |
| crypto-primitives | 196 | 0 | 0 |
| pon-node | 1,358 | 1 | 39 |
| protocol | 113 | 0 | 2 |
| release-bundle | 67 | 0 | 0 |

node 唯一失败是原 `journal_unknown_publication_is_sticky_and_cold_replay_does_not_refund_attempt` 在 `drop(journal)` 后冷重开返回 IO `WouldBlock`。该次顶层运行 361.64 秒后以101结束，不是 timeout；两个长 continuity 用例均通过。日志没有同次失败的锁 inode、持锁 PID 或 spawn/exec 时序，因此原失败的因果保持未知。不同提供者环境的成功结果没有合并填补它。

[M6 冻结记录](source/M6-freeze.json) 与 [独立静态审阅](validation/journal-isolation-static-review/README.md) 对应新的 test-only 隔离：父分支先 exec 同一 ELF，再由 child 完整执行初始化、活 owner 的第二次 open 必须为 `WouldBlock`、原故障和 sticky-error、drop、cold open 及原持久化断言。父分支要求退出成功、确实执行一个测试和末尾完成标记；没有把初始化留父进程而靠 exec 关闭本用例自己的锁。原测试名、roster、60秒 plan 及所有原断言保留，生产 `Files`/`Journal`、Cargo.lock 均未变，没有加 retry/sleep/unlock。新结果只能说明该固定隔离用例的实际运行，不会反推 M5 的持锁原因，也不证明生产并发 spawn/exec 行为。

原生编译、Clippy、各次保留库测试、发布与资源阶段在 [execution-status.json](execution-status.json) 单独记录。库测试的工程 850/900 秒窗口不会替代 Host 4 秒或 campaign 30 秒，Python 成功也不推导普通 daemon 或原服务成功。

## 原始服务 campaign：仍然未通过

[原件审计包](original-campaign/README.md) 对 Actions [run 42591962205](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42591962205) / artifact `13662172930` 完成原始 ZIP、manifest 和 1,765 个被列出成员的字节核对。
原始提交是 **0746**，本轮没有把它改写成 M4、M5 或 M6 新跑。

- **0/3 campaign、0/9 phase 通过**；三次原 native exit 都是 101。
- 27 个计划确认轮次中，观察到 12 个、确认 3 个、未观察到 15 个。
- 九个 phase 都报告原始 deadline 失败；phase startup errors 为空，report validation failure 为 null。
- 66 次 History import、264 个 Host slots 的这批计量字段完整。v2 与历史 v1 的所有既有字段逐项相同，仅补强缺测处理与记录。

| 各 run 的 baseline 首个已确认轮次 | 总 wall 秒 | 7 次 History RPC 调用区间秒 | 7 次 import 含激活秒 | Host 检查数 | Host CPU 秒 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 22.587234241 | 0.081459041 | 20.586157016 | 83,097 | 3.962073483 |
| 2 | 22.601677296 | 0.142777959 | 20.455300312 | 83,098 | 3.954667645 |
| 3 | 22.605384997 | 0.082585348 | 20.469824653 | 83,098 | 3.949042770 |

这里的 RPC 区间是原 `network_call_wall_ns` 对应的完整受保护调用区间，含部分客户端结果序列化；它不是纯 RTT，也不包含整个 round 的其他 Submit RPC、独立的本地 confirmation 及其余工作。

这支持优先定位 History import／最终激活路径，不足以断言唯一根因。原始服务约束、receiver/client 状态、capacity 与 churn 都需要各自验收，不能由这三次首轮确认替代。
[History import 细分复核](history-import-review/README.md) 从原66条 import 中按 round 端点选出首轮21包，核对360个完整 span，并保留父子区间包含关系。每组7包内的完整持久化段为9.26–9.74秒，最后一页激活为5.30–5.44秒，prepare为3.51–3.67秒。持久化段并不等同于 SQL COMMIT；源码中的原 CPU refill 等待也可能发生在这些外层区间中，但尚未量化，不能据此改预算或删除原检查。原whole-phase累计快照与这些首轮子样本有不同分母，后续补充保持分开。

回收后的 [whole-phase 差值复核](history-import-review/snapshot-followup.md) 将完整baseline的30次import（27成功、3次Work失败）与原report逐条对齐。每个baseline都有18次新增SQL API调用，其wall合计依次60.487131、22.715299、124.194664毫秒；实际`account_graph` scope则为73次、18.138435／18.667194／18.420762秒。SQL四site生命周期闭合，未进入的site仍保留未进入。该观察排除了这几个已计量`Transaction::commit` API作为对应秒级区间主要来源的解释，不能排除事务内其他SQL/IO，也不能把account-graph中的原progress、Host/CPU检查点、解码或可能refill直接认定为根因。完整16stage端点、所有原未知能力边界和嵌套关系均保留。

原本地 76 MB ZIP 缓存曾因共享磁盘耗尽，在再次核对完整摘要后删除；远端原件当时 `expired=false`，声明 2026-12-09 到期。本轮随后重新取回同一 ZIP，完整大小和 SHA-256 与原 digest 一致。[原 baseline 快照回收包](original-history-snapshots/README.md) 核对三份原 report 的成员摘要，保存每份 baseline 的全部50个原字段及 report 顶层上下文，无损 gzip 解码值匹配；原Mac下载超时和后续前置拒绝也独立保留。回收记录仍属于0746的原失败运行，不是本轮新候选重跑，也不保证GitHub远端永不到期。

## 普通 daemon：缺少的是产品 owner 装配

[工程缺口文档](ordinary-daemon-717-engineering-gap.md) 逐文件固定 Hepta 717 的生产入口。`main.rs` 在 `AgentdProductionStartup::receive` 之后仍没有产品调用 `with_root_learning_stage_owners` / `with_circuit_task_bootstrap`；现有 `require_root_learning_assembled` 会拒绝缺 owner 的启动。

需要连接原有 `LearningIterationStageOwnerPortsV1` 的 `validate_recovery`、`execute_stage`、`prepare_proposal`、`receipt_attestation`，以及持久的 Circuit invocation / input / result owner。CURRENT 发布、selection 和 next-use 读回 API 已存在，但生产调用链未装配。research Generation V2 和 `cfg(test)` 的外部产物提案接口不能直接充当该生产实现。

固定 717 的 CI 与历史 f070 的实际研究训练／Root component 运行分别保存其来源；历史 NoUpdate、同测试进程冷读回、test ELF 或 `cargo check --bins` 都未填入本候选真实 daemon 二进制、安装、FinalUse、独立下一任务或 OS 冷恢复字段。

## PoN 与 PQ 的研究交付

[PoN 研究稿](final-pon-research.md) 和 [28 个源码锚点](final-pon-research-sources.json) 将全策略最低成本、资源到工作、工作到共识拆成可审查的证明义务：固定成功事件、逐路径预算、全部合法经典／量子策略、预处理与残留状态、所有竞争分支、动态 DAA／时钟／网络、停止时间及寿命组合。

报告保留五组已有条件命题和十类联合失败事件，明确哪些条件仍需证明。实测某算法的成本不能自动给出所有算法的成本下界；单实例工作困难也不能自动给出实际 CP/CQ/CG 的联合概率界。MU1 的 16 个成本点和通用示例的 6 个成本点继续为 null。

文献核对采用正式 ESA 2026 版本并区分其 Remark 4 与旧 arXiv 的 Remark 5.2；矩阵任务的安全性仍依赖相关低秩问题猜想。[最新 QROM 定点复核](qrom-latest-followup.md) 还找到了 Git 中已有的 102 页 Jan→March 原始比较记录，内部一致性 13/13 项通过；既有版本桥作为正面证据保留。本轮对官方原始 PDF 的重新获取返回 403，没有冒称重新执行文本／渲染比较。固定 profile 的两个版本字段描述本轮绑定时未独立复取的边界，不代表项目从未取得原件。实际 transcript／PCS／FRI 映射、online 参数顺序、q_V 计费、共享查询预算和完整失败事件组合仍待关闭。

## 按用户原顺序的关闭状态

| 优先级／工作 | 本轮可复核的进展 | 未关闭项 |
| --- | --- | --- |
| P0 固定整合候选 | 三父源收敛、两库源码／依赖／proof descriptor 固定 | 实际 build/load/model/loader/evaluator 身份与原生资格 |
| P0 普通 daemon 学习 | 范围读取器与生产装配缺口已落实到接口 | 同次训练、评价、Selection/NoUpdate、安装、FinalUse、独立下一任务、冷恢复 |
| P0 PoN／联合共识 | 条件命题、量词、资源、初态、DAA／时钟／网络和失败事件研究交付 | 全合法策略成本下界与实际联合安全界 |
| P1 原服务 | 原 campaign 完整分母、计量及失败证据可复核 | 4 秒 Host、独立 30 秒 campaign、History/capacity/churn 分别重跑通过 |
| P1 大模型 BT／保管 | 固定存储输入，明确完整版本契约 | 两层分块、多计划全覆盖、冷下载、删发布端缓存后恢复与真实加载 |
| P1 PQ profile | 唯一候选及实际源码映射冻结 | 15 项证明义务、实际构造映射、共享查询预算及全失败事件；本轮 PDF 复取未完成 |
| P2 独立运营／WAN | 原契约与证据要求未变 | 三个独立管理故障域、真实付款、持续租约／修复／失联／撤权及至少72小时 |
| P3 替代 PoW A/B | 全成本比较口径保留 | 同资源、同安全、同业务负载下的证明／传播／执行／恢复实测 |

原 [存储网络契约](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/097f59f505f8ec42f72e3b8255e6cb7822a70646/docs/development/specs/pon/CELL_STORAGE_NETWORK_ACCEPTANCE_V1.md) 的字节和预算保持不变。同机 loopback、多个目录、研究 watchdog 或八核 proving 结果都没有替代真实独立部署与原服务门槛。

## 发布记录的时间边界

本目录的publication字段保留各自观察时间，包含M4已发布时的历史检查及本次最终追加之前的状态。它们不声称最终证据提交已经发布或全部hosted checks通过，也不移名为M6运行结果。最终远端head以[原draft PR #847](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/847)的实际回读为准；本交付不执行合并或生产启用。
