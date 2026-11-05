# 2026-11-05 本轮同源实测与 ELF closure 修复证据

**结论：HOLD / NO-GO。** 本包保存本轮实际执行、失败反例、修复和精确源码检查，不关闭 P0、P1 或独立系统验收门禁。不同 commit 上的通过结果分别列出；它们不能拼成一个已通过所有门禁的发布组合。本轮固定的已发布 Chain 代码输入为 `2a8fee974b41fab6e2c4e662dcce1807fcd19bdd`，写入 `evidence.json::final_chain_commit`；这表示实际推送到既有 PR #688 的代码身份，不表示发布验收通过或后续分支永远不再前进。`final_hepta_commit` 仍为 `null`，`production_activation` 与全部 `gate_closed` 均为 `false`。后续完整发布组合应另附身份与回执，保留本包历史结果。

本包的实际进展是：找到并修复静态 ELF 依赖闭包误接受；在真实 loader 上保留错误行为；完成原生 crypto/example 测试与同批材料的完整算子、伪 transcript、优化普通算子对照；复验合法不更新、零奖励的结算结果；恢复缺失的精确 HEAD 历史材料，使完整源码验证恢复正常；修复实际主机工具发现环境并复核固定 OpenSSL 3.5.9 provider。所有这些进展均有下述范围限制。

## 1. 源码身份与并发组合

完整 commit、tree、父节点保存在 `evidence.json::source_anchors` 和 `raw/source-identities/` 的原始 Git commit 对象中。下表短标识均只是显示缩写。

| 标识 | 用途 | 精确 tree | 结果归属 |
| --- | --- | --- | --- |
| `6ee529046d29` | 原始执行源码 | `a045ad8f2eb9340ff73278236cc69350c1ddc424` | 4 个完整算子、2 个攻击 campaign、原始 141 测试、213 blob 恢复；不移植到后续身份 |
| `2534c56e2c15` | ELF 修复代码对象，父为 `6ee529` | `1f65a48a186125cf79e2a02866dbb38958e1d3f7` | 完整源码约束下 ELF 20 PASS；fmt、locked metadata PASS；初次 strict Clippy 环境失败 |
| `0841750c6716` | 第一轮并发上游 | `073399c988d70acbb8adf3f218683a8f7bc6a9c7` | 37 个已有改动，包括 fresh readback 准备复用与 History 私有逆序 spool；保留原始上游证据，不计作本包新跑 |
| `98897a742c5c` | 父为 `0841750`、`2534c56` 的组合代码对象 | `5a0be58db8d573df6cc465a0c7ff77766bf15ab0` | 本身份重跑 ELF/source controls、141 测试与 strict Clippy |
| `dda4cc473620` | 第二轮并发上游 | `95fc95096e795e8f7a63d5d8a31e77b43af2e399` | 9 个 CI/workflow/config/evidence 改动，加入精确 native roster；不把上游旧测试转记为本轮执行 |
| `eaacd1ef4245` | 父为 `dda4cc4`、`98897a7` 的 CI 合成代码对象 | `4a3cef276946f1b5c3f472adbf98bf9e7790854d` | 完整 source/native gates PASS；随后 Growth runtime 变动使结果只能归属本历史身份 |
| `657bf2a462ff` | 第三轮并发 Growth 上游 | `7ce7ac50f788dd421e7cc0c9ddb957ade3e8df73` | 16 个已有文件变化，包括实质 runtime 变动；保留上游改动，不能迁移前一身份原生结果 |
| `2a8fee974b41` | 父为 `657bf2a`、`eaacd1e` 的本轮固定已发布代码输入 | `b9627a51026e8d16a206b3952c3cda1d058d40ec` | 推入既有 PR #688；本身份检查单独记录，生产与系统验收仍 HOLD |

第一轮组合时，通用 `git add` 遗漏了 13 个受忽略规则影响、但已在上游提交的 `.log`。本地树与远端树比较拒绝了这个初始结果，随后按已核实的上游 blob 精确加入，完整保留原 37 文件。失败与修复分别保留在 初始遗漏记录（`raw/provenance/chain-composition-initial-index-missing-logs.json`） 和 组合记录（`raw/provenance/chain-composition.json`）。第二轮来历保存在 late composition（`raw/provenance/chain-late-composition.json`） 与对应 input JSON。

第三轮 Growth 变动使 source pin 检查实际 exit 1；按真实已变/新增路径更新 11 个 pin 后，来源检查恢复为 492 blob / 6 heads、仍 HOLD。失败与修复日志为 `growth-incoming-pins-before.log`、`growth-incoming-pins-after.log`，publication composition（`raw/provenance/chain-publication-composition.json`） 明确记录 `runtime_source_changed: true`、`prior_native_results_apply_to_new_tree: false`。真实发布与 ref 读回回执（`raw/verification/chain-code-publication.json`） 保存非 force 更新成功、原上游 `657bf2a` 和读回 `2a8fee`。本轮以固定 `2a8fee` 记录验收，后续提交另列。记录上游提交中的文字不等于独立复验其所有结论。

## 2. 实际执行的检查及失败

每条带 source-fence 的命令均保存执行前、执行后精确 commit/tree、完整工作树原始内容检查、argv、退出码、耗时与日志 SHA-256。身份检查自身不执行测试；测试结果由其包裹的实际命令产生。

| 源码 | 实际命令范围 | 结果 | 回执 |
| --- | --- | --- | --- |
| `6ee529` | `trnm-crypto-primitives --lib` 与 `pon_shared_material_v1` example | 135 + 6 = **141 PASS**；0 failed、0 ignored | crypto-and-shared-material-tests.json（`raw/verification/crypto-and-shared-material-tests.json`） |
| `2534c56` | `test_llm_runtime_release.py` 完整模块 | **20 PASS** | integrated-elf-closure-tests.json（`raw/verification/integrated-elf-closure-tests.json`） |
| `2534c56` | workspace `cargo fmt --check`；`cargo metadata --offline --locked` | 均 exit 0 | format（`raw/verification/integrated-format-check.json`）、metadata（`raw/verification/integrated-locked-graph.json`） |
| `2534c56` | workspace/all-targets/all-features Clippy，`-D warnings` | **exit 101**：缺少实际 pkg-config，openssl-sys 无法发现 OpenSSL；不是通过，也不是源码 lint 缺陷结论 | 失败回执（`raw/verification/strict-workspace-clippy.json`）及同名原始日志 |
| `98897a7` | ELF 20、source-integrity 43、PQ 来源、inventory、repository、fmt、all-features locked metadata | 命令 exit 0；PQ 检查仍 **HOLD_NO_GO**，488 精确 blob / 6 heads，3018 local links | composed-source-and-elf-controls.json（`raw/verification/composed-source-and-elf-controls.json`） |
| `98897a7` | 原生 crypto/example | **141 PASS**；0 failed、0 ignored | composed-crypto-shared-material-tests.json（`raw/verification/composed-crypto-shared-material-tests.json`） |
| `98897a7` | 固定 provider 环境下 strict workspace Clippy | **exit 0**；原始失败未覆盖 | composed-strict-workspace-clippy.json（`raw/verification/composed-strict-workspace-clippy.json`） |
| `eaacd1ef` | Growth 变动前组合完整 source/native gates | **exit 0**：ELF 20、source-integrity 43、native roster 9、crypto/example 141 PASS；fmt、all-features locked graph、strict Clippy、inventory 与 repository PASS；PQ 来源 490 blob / 6 heads 仍 **HOLD_NO_GO** | final-composed-source-native-gates.json（`raw/verification/final-composed-source-native-gates.json`） |
| `2a8fee` | 固定已发布输入的 Python/source gates | **exit 0**：ELF 20、source-integrity 43、native roster 9、phase-read 51 PASS；fmt、all-features locked graph、inventory 与 repository PASS；PQ 来源 492 blob / 6 heads 仍 **HOLD_NO_GO** | published-source-python-controls.json（`raw/verification/published-source-python-controls.json`） |
| `2a8fee` | 新增 Growth 原生回归与 strict Clippy | **PENDING_RESOURCE_SCHEDULING；尚未启动子进程**。6 个 selectors 预期选择 14 个 cases；没有本身份原生退出码，不能继承历史通过 | published-native-availability.json（`raw/verification/published-native-availability.json`） |

历史 `eaacd1ef` 命令在前后相同的 10006 个跟踪条目、963385833 字节上执行，总包装耗时约 135.941 秒。`2a8fee` 的 Python/source gates 则检查 10008 个条目、963463160 字节，总包装约 107.169 秒，repository 为 3022 local links。两者激活均为 false。`2a8fee` 的原生/Clippy 状态须以本身份另外的实际回执为准，不能从 `eaacd1ef` 迁移。

同一套 20 或 141 测试的多次执行不累计成更多独立测试。早期独立日志 `source-negative.log`、`pq-source-pins.log`、`integrated-runtime-release.log` 保留原字节；它们不额外创造一次带精确身份的验收。负对照测试中预期出现的 `receipt result: FAIL` 不是 unittest 套件失败，套件状态以退出码与最终统计判断。

原生排队回执的 `native_child_started` 为 false，`child_exit_code` 为 null。其 09:26:45 UTC 资源快照可用磁盘约 2.95 GB、cgroup 上限 8 GiB；`memory.current` 包含可回收文件页，单个快照不能证明本命令已资源拒绝。此前另一条 Hepta 流程的 6 次原 profile guard 中止也不能变成这条 Chain 命令的失败。本包只保存排队状态与来源说明；后续原生、Hepta、额外 source-guard 补丁结果应另附精确身份回执。

## 3. ELF 静态闭包：真实 RED、修复、GREEN 与误假设

被修复的是 `scripts/llm_runtime_release.py` 对其声明的**静态 ELF 依赖闭包**的错误接受。原代码只找到与依赖名称相符的路径，却未确保所有被引用目标都是合适的 ELF 对象。原始 `declare` 和独立 `readback` 均接受以下材料，而实际 loader 失败：

| 反例 | 原检查 | 实际行为 |
| --- | --- | --- |
| 将 `libc.so.6` 替换为同名普通文本 | 错误接受 | loader exit 127：`file too short` |
| 将 PT_INTERP 目标替换为文本，并保持可执行 mode | 错误接受 | `Exec format error`，errno 8 |
| 保留真实解释器 ELF，但移除执行 mode | 错误接受 | `Permission denied`，errno 13 |
| 将共享库的 `e_type` 改成 ET_EXEC | 错误接受 | loader exit 127：不能动态加载 executable |
| 将共享库的 `e_type` 改成 ET_CORE | 错误接受 | loader exit 127：无效 ELF 类型 |

这些原始结果在 original observation（`raw/evolution-receipts/elf-closure-original-observation.json`） 与 格式/权限分离反例（`raw/evolution-receipts/elf-loader-original-disambiguation.json`） 中。`elf-closure-red-v2` 在原实现上有 5 个失败回归断言；现有 class、字节序、machine 不匹配拒绝控制通过。最早的 4 RED 记录与后续 5 RED 记录均保留。

第一次修复还遗漏 ET_DYN 中的 PIE executable。将同架构真实 `/usr/bin/true` 复制成依赖 `libc.so.6`，前一候选仍接受，实际 loader 以 `cannot dynamically load position-independent executable` 拒绝。它的 SHA-256 为 `b860051e15938770f4164177f2fc2d4e1af26b226c9b0c3ea75a36d1be33a3cf`，`DT_FLAGS_1` 为 `134217729`。详见 PIE 实际观察（`raw/evolution-receipts/elf-closure-pie-original-observation.json`） 和 PIE RED（`raw/evolution-receipts/elf-closure-pie-red-v2.json`）。

最终补丁先解析真实 ELF 成员，再解析边；DT_NEEDED 目标必须是已解析、符合原 profile 的 ET_DYN，且不能带 `DF_1_PIE`；PT_INTERP 目标必须是真实 ELF 且可执行。保留既有 ABI/profile 约束，不新增普适的“PT_INTERP 不能是 PIE”规则。最终补丁（`raw/evolution-receipts/elf-closure-fix-v2.patch`） SHA-256 为 `fcc05160550f9a32a98f8e125276ed27035d63a78af31d93a3a507a674cca5ee`。

审查过程中还尝试了一个新的正断言：给真实 glibc loader 添加 PIE 标志后应仍能运行。实际触发 glibc assertion，exit 127，因此该假设被否定；失败完整保留在 `elf-closure-pie-red.json/.log`。没有把这个失败写成通过，也没有以它推导所有解释器的通用语义。把 `/usr/bin/true` 当解释器直接执行虽然退出 0，却未产生期望的 Python marker，同样不算 loader 成功。

最终本地模块 20/20 PASS、无 skip；随后在上述精确代码对象上分别重跑。原实现、首修复与最终修复对同一个合法 CPython 3.12 ELF/wheel fixture 生成的 manifest 与 readback **逐字节相同**，23687 字节、9 个原生成员，见 三方兼容记录（`raw/evolution-receipts/elf-closure-pie-compatible.json`）。兼容性仅覆盖这个实际 fixture，不宣称所有动态加载、符号版本、插件、syscall 或模型加载语义均已验证。

此缺陷有 checker 误接受与真实 loader 错误证据，但不是已证明的未授权 PQ 效果。原 readback 的 `runtime_execution_qualified`、`ordinary_installation_qualified`、`public_reward_eligible` 均为 false；本包不提升这些资格。

## 4. 同批真实材料的完整算子成本

四次运行的执行源码均为 `6ee529`，原生 runner SHA-256 均为 `ad4ddcb32a0128ce5b26b5c66628d851c593e916d88bfab3163a8169f7059ee1`。输入来自冻结的公开 Rust 变更归属任务，原始 corpus 源码为 `ef1fa4d48ab9894f3d7a4b1c797ca9e7e490b155`；模型与 evaluation bundle 的域哈希分别为 `16443887511f5ffbcdf611ce3ca6b6811bc699aad649961fce5a83c168534671`、`0308341b06b152167da48dc706ee82b7e691aa9ebb2c4d2d7d5cd6a55d12acd5`。域哈希与 JSON 文件 SHA-256 是不同量，完整映射位于 `evidence.json::complete_operator.material_provenance`。

每次处理同一个 64 样本 batch：257 维，base/router/3 delta 各 3 行，打包成 5 个 64×64 W1 tile。对照普通算子缓存 base+delta，只计算路由与被选 expert；每组 100 个 warm 样本，另记冷准备。两种 target × full-limb/transposed 四组均产生 5 个 winner，四组应用输出 SHA-256 相同：`f7f2ef71c1505eb9b75a6f7d370a8f3b146448a4c3807d8f44ca3c05cdf80234`。

| 运行 | 原生子进程 CPU ms | 子进程交换墙钟 ms | 普通冷准备+执行 ms | 普通 warm 中位数 μs | 原生墙钟 / warm |
| --- | ---: | ---: | ---: | ---: | ---: |
| target 0 / full-limb | 32.592 | 36.153159 | 1.341258 | 116.765 | 309.623× |
| target 0 / transposed | 43.824 | 155.605182 | 1.965537 | 120.639 | 1289.841× |
| target 1 / full-limb | 54.996 | 60.379635 | 1.041195 | 92.985 | 649.348× |
| target 1 / transposed | 57.860 | 62.079166 | 1.962130 | 83.350 | 744.801× |

来源是 `raw/execution/cell-*/report.json`、逐 tile `process.json`、完整原生 stdout/stderr，以及 `complete-operator-command-results.json`。成本报告绑定 Git HEAD/tree、9 个执行 Python 文件与实际 runner 的 SHA-256；这与第 2 节完整工作树前后 source-fence 是不同的证据范围。第一组 full-limb 的外层批量命令不在后者列表中；其完整 report 与五个实际子进程回执保留。其余三组与两个攻击 campaign 有外层 argv/exit 回执。不得捏造第一组的外层包装回执。

**310–1290× 的分母是优化普通算子的单 batch warm 中位数。** 分子包括真实子进程启动、挖掘、proof 构建、完整验证、第二个参考 verifier、诊断序列化与本地通信。它不是强合法 solver 的最小成本下界，也不是完整产品端到端收益率。整体实验在最终 report 写入前分别约为 1.757、1.888、1.560、2.039 秒，额外包含源语料重放、100 次 baseline、标量/NumPy 交叉核对等诊断工作，不能当成生产单次推理延迟。

每组真实本地 pipe 交换分别为 1667764、1667797、1682991、1682998 字节；每组另列 canonical matrices 163840、proof 245940、typed product 81920 字节。这些分项与总 pipe 数字重叠，不能相加重复计费。普通算子必要 MAC 为 98688，W1 padded MAC 为 1310720（必要工作密度约 7.529%）；5 个完整算子的 MAC 为 246720（约 18.823%）。未选择 expert、padding 和重复 challenge 不获得额外有用输出计数。

实验保留所有 nonce 尝试、失败搜索与未获有用性资格的记录。这里每个 tile 的 timeout 是 **60 秒的单子进程交换限额**，不是原始 4 秒业务门禁。硬件为共享 AMD EPYC 9V74，cgroup CPU quota 为 8 CPU、亲和性 0–8、内存上限 8 GiB；并发和内存压力未隔离。Python 3.12.14、NumPy 2.3.5，OMP/OPENBLAS 各 1 线程。未测 WAN、能耗、长期 stale 工作经济成本；没有预先规定的完整安全/收益预算验收通过。

## 5. 同材料伪 transcript、预处理复用与拒绝成本

两个 campaign 使用上面原样的 5 tile、同一原生 runner，执行源码仍为 `6ee529`。每组 4 cycles/tile，20 次 setup、40 个伪候选，完整原生记录保存在 `raw/execution/security-t0/` 与 `security-t1/`。

| campaign | 伪候选数 | 搜索尝试 | 攻击方 CPU ns | 原生拒绝 CPU ns | 原生拒绝 / 攻击 CPU |
| --- | ---: | ---: | ---: | ---: | ---: |
| target 0 | 40 | 78 | 1165756 | 17067967 | 14.6411× |
| target 1 | 40 | 1192 | 2776193 | 16769364 | 6.04042× |

合计 **80 个构造伪候选、360 次拒绝调用**：80 native、80 scalar-reference、200 cache。所有原生/标量预期拒绝与 cache 路径均观察到，control failures 为 0。360 是重复路径调用数，不是 360 个独立攻击样本。cache 的 cold/warm/churn/owner recreation 覆盖复用行为；进程内 owner recreation 不等同于持久恢复或物理断电。结果不证明最便宜攻击者成本、一般预处理安全下界或公共服务抗 DoS 预算成立。

打包器第一次汇总时误将 `scalar-reference` 路径写成 `scalar`，摘要曾漏计 80；完整性验证后的计数断言拒绝该摘要。修正匹配并保留 打包失败/修正记录（`raw/packaging-audit/count-validation-initial.json`），所有原始执行 JSONL 未变。

## 6. 冻结材料结算：合法不更新、0 奖励

实际结算 report（`raw/execution/model-settlement/report.json`） 重算了冻结评价，结果为 `not_adopted`、`model_reward: 0`，原因为预注册统计门槛未满足。完整输入、评价结果与模型工作材料保存在 `raw/settlement-input/`。

| 冻结分区 | 样本 | 组合模型正确数 | calibration 锁定强对照正确数 |
| --- | ---: | ---: | ---: |
| evaluation_a | 347 | 165 | 164 |
| evaluation_b | 281 | 147 | 151 |
| consumer | 251 | 155 | 154 |

这些是完整冻结分区的逐样本计数；统计门禁使用按源文件分组的指标与四重比较校正，不能用某一行多一个正确样本代替门禁。成本实验只取 consumer 的 64 样本 batch。已有探索见过这些分区；`future_window_accepted`、`independent_evaluators`、`ordinary_hepta_entry` 均为 false。结算使用固定逻辑时间、无市值 test unit；未证明真实资金转移、独立评价、未来窗口收益或普通产品安装—下一任务—结算—恢复闭环。

## 7. 完整源码恢复与主机 provider 修复

最初未修改的 source verifier 拒绝工作树：`index hides tracked worktree entries`。恢复过程从已有本地 Git object 数据库逐个还原 **213 个精确 HEAD blob，781622789 字节**，清除相应 skip 标记，网络 fetch 为 0。index stage SHA-256 前后均为 `9e4e804aa7a5ad35e43e0e2e8ae855e1aa02542b292f5122b0c80106fdb0c9d2`。随后相同 verifier 在 `6ee529` 上检查 9969 个跟踪条目、963163944 字节并通过。原失败 stdout/stderr、逐文件 blob/mode/length/SHA、恢复回执与未修改 verifier 的执行回执均在 `raw/liveness-work/`。

这恢复了可验证源码材料，不是独立 import、状态图、History 原业务基线或 F0 的通过。包内提供恢复 manifest，不重复封装 781 MB 历史材料；需从精确 Git 对象复取。首次算子开始时间与全量材料恢复的先后不作超出原记录的断言。

环境修复分两层：

1. host-pkgconf.json（`raw/verification/host-pkgconf.json`） 证明复用了真实 pkgconf 3.0.10，SHA-256 为 `2d3928b523d83db07323273b919ddccfea5ff356d541b909c50f0f31d69e7977`。未固定 3.5.9 `.pc` 路径时，它发现的是系统 OpenSSL **3.0.13**、系统 include/lib；这条诊断不构成 PQ provider 通过。
2. provider review（`raw/liveness-work/provider-review-20261105/review.json`） 固定实际 OpenSSL **3.5.9** install、CLI/SHA、STATIC、CONF/MODULES 与 PKG_CONFIG_PATH，复核旧构建 receipt 与当前五个原生文件哈希；实际 pkgconf/CLI/default provider 版本匹配。新鲜 ML-DSA-65 keygen/sign/正确消息 verify/错误消息拒绝通过，signature 3309 字节；绝对静态 `libcrypto.a` 小 C 探针通过。新鲜私钥已删除，包内只保留 review、env、probe 源码与 probe 二进制。

provider 来源 receipt SHA-256 为 `47e29ef3e9f4627de90f8da7995f92b66fbc17a4cb5e1d4952b632ec1eb488b0`；源码 tar pin 为 `603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a`；准备脚本 SHA-256 为 `ccdcf7e8bb9871607c73adc78624a607b616c227b7fe581b96c48761a3805bfa`。旧 build-and-smoke 日志、原 provider receipt 与精确 Git 脚本均保留。review 是既有 provider 的来源与功能复核，没有重新构建 OpenSSL、运行完整 upstream 测试或形成生产 PQ 安全结论；后来的 Cargo/Clippy 命令以各自独立回执为准。

review 的 `provider-fixed.env` 含本机绝对路径，迁移时必须重绑定实际路径和哈希，不能直接声称可移植。其附带 no-update 源码顺序审查原样保留，包括当时工作树 `MM` 状态；不借此固定 Hepta 最终 commit 或宣称完整运行成功。同一共享主机上的多 agent 检查不证明独立管理主体、独立副本或故障域。

## 8. 尚未完成的退出条件

| 门禁 | 本包能支持的范围 | 仍需同一固定组合的证据 |
| --- | --- | --- |
| P0-1 唯一组合 | 三次并发合成来历、固定 Chain 代码输入及各身份原生/源码检查 | 同一最终 Chain/Hepta/lockfile/二进制/配置绑定；普通入口真实调用与全门禁 |
| P0-2 完整 PQ 效果授权 | provider 功能、局部 crypto 测试、PQ 来源检查的 HOLD 边界 | 当前根下账户/治理/发布/恢复/CURRENT/FinalUse/消费记录；错域、旧代、降级、旧库、并发副本的实际效果拒绝 |
| P0-3 原始业务活性 | 完整源码材料恢复；保留并发 History/readback 改动 | 原无攻击基线、原 4 秒/16 敌对条件、独立 fixed-host F0，分别验收 |
| P0-4 成本与有用性 | 同批强普通算子与两种合法算术实现、伪 transcript、cache 路径、完整本地原始成本 | 强合法 solver 的充分竞争、预处理下界、失败/陈旧工作、WAN/能耗与预先预算 |
| P1-1 真实进化闭环 | 冻结评价重算与合法不更新、0 奖励 | 独立评价、完整 release/真实安装、下一任务实际效果、结算与恢复、未来窗口与整体收益 |
| P1-2 模型档案服务 | 静态 ELF 闭包缺陷修复及真实 loader fixture | 模型完整 closure、真实 loader、独立副本/纠删码、资金/续租/repair/GC；作者离线、节点丢失、重启与 WAN 承诺 |
| 发布门禁 | 保留源、环境、失败和各命令范围 | 密码/共识/经济/恶意负载、物理断电、长期运行；独立管理主体在固定发布物上签明范围 |

## 9. 文件、完整性与复验

本文的 `raw/...` 引用均为 ZIP 内成员，按下面命令解压后可直接读取；只提交本层文件时无需制造不存在的仓库链接。`raw.zip` 按路径排序、固定 ZIP entry 时间戳，保留所选原文件字节；原始 JSON/log 中的绝对路径是当时真实 argv/环境，不应改写成虚假的历史。新索引与以下重放步骤使用相对路径。包只含明确选择的目录；没有递归复制旧 provider 构建根或保留私钥。

- `evidence.json`：源码身份、命令回执、成本/拒绝/结算摘要、边界及每个 ZIP entry 的长度/SHA-256。
- `raw.zip`：原始执行记录、所有 RED/GREEN 与误假设失败、恢复 manifest、provider 来源、精确 Git 输入、观察到的原生 runner/pkgconf/probe。
- `SHA256SUMS`：本层交付文件哈希。
- `verify_evidence.py`：标准库完整性校验，只读 ZIP 和 JSON；不执行随包二进制、不替代业务测试。
- `assemble_evidence.py`：本次只读收集方法。重建要求原工作空间中的原材料与精确 Git 对象，不是完整源码 SDK。

先在本目录验证包，再解开相对路径：

```sh
sha256sum -c SHA256SUMS
python3 verify_evidence.py
python3 -m zipfile -e raw.zip .
```

重跑源码测试时，另备完整干净 checkout，并确认目标 commit。例如 ELF 模块的代码对象是 `2534c56e2c15d2c31a1e829e369bee84aec4be2f`；本轮固定的已发布 Chain 输入是 `2a8fee974b41fab6e2c4e662dcce1807fcd19bdd`。在相应源码根运行：

```sh
bash scripts/project-preflight.sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p test_llm_runtime_release.py -v
```

完整 source-fence 的原始 argv 见回执；重跑时通过 `scripts/ci/record_pq_native_command.py --kind head --candidate <commit> --tested <commit> --label <label> --output <仓库外目录> -- <command>` 记录新结果。重新运行会产生新的耗时和环境观察，不能复用本包作为新机器的实测回执。

成本重放须另备精确 `6ee529046d295e3175f09112492abee373f1f54c` checkout（以下命名为 `chain-at-6ee`），以及冻结 corpus 原提交对象。Rust 工具链由 `rust-toolchain.toml` 固定为 1.95.0，保留的 Cargo.lock 与相关配置均来自 `git show <commit>:<path>`；offline 构建还需要相同依赖缓存。在该源码根运行：

```sh
CARGO_TARGET_DIR=../replay-target CARGO_BUILD_JOBS=1 cargo build --offline --locked --release \
  --manifest-path trillionnium/Cargo.toml -p trnm-crypto-primitives --example pon_shared_material_v1
OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 python3 formal/pon-nakamoto-v1/experiments/shared_cell_operator_v1.py \
  --model ../raw/w1-inputs/model.json --tasks ../raw/w1-inputs/consumer.json \
  --evaluation-bundle ../raw/w1-inputs/evaluation-bundle.json \
  --bundle-hash 0308341b06b152167da48dc706ee82b7e691aa9ebb2c4d2d7d5cd6a55d12acd5 \
  --replay-source --runner ../replay-target/release/examples/pon_shared_material_v1 \
  --target-index 0 --cycles 1 --max-attempts 4096 --arithmetic full-limb \
  --out ../replay-out/cell-t0-full-limb
python3 scripts/ci/run_shared_material_security_v1.py \
  --material-dir ../replay-out/cell-t0-full-limb \
  --runner ../replay-target/release/examples/pon_shared_material_v1 \
  --target-index 0 --cycles 4 --max-attempts 4096 --out ../replay-out/security-t0
python3 formal/pon-nakamoto-v1/experiments/settle_model.py \
  --input ../raw/settlement-input --out ../replay-out/model-settlement \
  --bundle-hash 0308341b06b152167da48dc706ee82b7e691aa9ebb2c4d2d7d5cd6a55d12acd5
```

用 `--target-index 0/1` 与 `--arithmetic full-limb/transposed` 的四种组合补齐算子对照；攻击 campaign 分别复用对应 target 的 full-limb 材料，保存所有输出。应核对新 runner 的 SHA-256、精确输入与环境；本包没有签名的可复现构建证明。`rustc-info-observation.json` 是本机 Cargo 缓存中的编译器输出观察（rustc 1.95.0 / LLVM 22.1.2），不构成签名编译器来源或构建时二进制证明。
