# PoN 工作安全：八样本成本、缓存与原预算服务证据

**结论：HOLD / no activation。** 本包补齐了固定 V2 实验网格的八个实际样本，保留了完整合法策略成本、昂贵拒绝、局部缓存优化以及未完成的服务目标。它没有证明最便宜合法策略的成本下界，也没有取得工作安全、资源公平、公开网络或生产激活资格。**本包不支持提高出块频率。**

主实验 run [41330488677](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41330488677) 的 **12 个 cost jobs 成功、2 个原预算 service jobs 失败**。12 个 cost artifacts 含 16 份 native 捕获：V1、V2 各四份，false-trace 四路径及五路径各四份。服务中的四个无攻击 baseline 完成六深概率确认，四个 pressure 均未完成确认；四个独立客户端的 active 高度仍为 0。

后续 CI-only head `9cd91ed` 是单独的源码身份。其 run [41332206071](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41332206071) 已结束为 FAIL：八个旧 cost jobs 成功，四个 V2 jobs 全部 cancelled、没有对应 artifact，两个 service jobs 失败。**本包完整的四份 hosted V2 实测始终归属于 `3bbc` / `ea43`，不能改标为 `9cd91ed` 的新执行。** 后续状态见[当前代码快照](current-code-snapshot/README.md)、[原始 API 和服务读回](current-code-snapshot/summary.json)。

本轮继续采用 Nakamoto 式 PoN：累计要求目标对应的有效工作、独立验证和概率确认。模型评价 quorum 不成为账本终局，“六个确认”也不变成确定性终局。相关验收边界见[纯 PoN 工作安全模型](../../docs/protocol/pon-nakamoto-v1/details/PURE_PON_WORK_SECURITY_MODEL_V1.md)与 [V2 实验规范](../../docs/development/specs/pon/W1_LEGAL_STRATEGY_V2.md)。

## 1. 源码与执行身份

| 身份 | Commit | Tree | 本包所证明的范围 |
| --- | --- | --- | --- |
| 完整成本/服务实测 head | `3bbc0288d6b7b6ed7f2bf0ee70d99b3b14236129` | `f52299288ca23426e5186f37fb3a58788e40dbee` | 本地 V2 与主 run 的 head 捕获 |
| 同轮 prospective merge | `ea43b65fdd91b741b8f9e577061710dd2aebbb2e` | `f52299288ca23426e5186f37fb3a58788e40dbee` | 主 run 的 merge 捕获；有序 parents 为 base 与 head |
| Merge base | `0e9eac5d2a8cdb0a6f0cc7920f84e290e0d5d0d0` | 由保存的 source/API 记录定位 | merge 身份的父关系 |
| CI guard 后续代码 head | `9cd91ed69a0c69df42f8d7812d32d271df6e1998` | `60a521c7299febfe26a8c7d38d3420d490d07cd8` | 三文件 workflow/corpus/plan 修补；不能替代新的执行收据 |

主 run 的 source-before/after 均确认 6,856 tracked entries、792,504,967 bytes，前后无源码变化。独立成本复核同时核对原 archive/成员、manifest、保留 ELF、编译器、target 与全部整数分母：x64 ELF machine 为 62，ARM64 为 183；所有 measured/retained before/after binary pins 匹配实际文件。完整明细见 [hosted 成本复核](hosted-cost/hosted-cost-analysis.md)及其 [JSON](hosted-cost/hosted-cost-analysis.json)。

所有 cost lanes 继续使用 Rust 1.95.0、原 Cargo 默认 release 配置、`--locked` 与原 identity/build/native 命令上限 30/900/300 秒。12 份 metadata 图的 174 个 selected packages 和依赖边都在同一份 179-package Cargo.lock 中；排除文件定位元数据后 resolved graph 一致。工作区 lock SHA-256 为 `fbe64b5b4662405980becd75c81c9ef699a78b56449d71ed33185531db851c69`。

### 实施变更的边界

- V2 使用独立记录版本和挑战域，将固定 cohort 从 V1 两样本扩展到八样本；V1 默认语义保留。2 GiB 是 V2 研究证据 stream 的解析上限，没有提高 CPU、attempt、timeout、Host 或业务窗口预算。
- `ArithmeticFactCache` 的候选实现与其 FullLimb 控制另有局部对照；该对照没有升级为完整节点或公开服务实测。
- Header 回归检查逐字段绑定 wire bytes、challenge 和 block identity；CI-only 后续把精确该测试纳入显式验收。
- History 变更移除相邻且中间无实际工作的重复 Host 读取；真实 W1 progress boundaries 与原 deadline 的检查仍保留。其完整测试执行情况见第 6 节。

## 2. V2：八样本固定网格已完成，完整策略没有普遍加速

每条 hosted V2 lane 都覆盖五材料类 × 两 target × 三 reuse horizons（1、8、64），合计 30 shards。独立脚本从 frozen JSONL 重算 setup、每次搜索、失败 attempts、完整 proof digests 与整数 cohort CPU，再与原 reader 逐项对照；未导入项目 reader。此 hosted 审计不重复推导 AB product，也不独立重放完整 W1 transcript，原 native 完整验证结果继续单独保留。

| 每条 V2 lane 的对象 | 数量 |
| --- | ---: |
| 每 shard 实际 samples | 8 |
| 实际 setups / cohorts | 480 |
| 完整策略 searches | 11,680 |
| 已付 complete attempts | 195,832（每策略 97,916） |
| 完整 candidate 字节记录 | 5,840 |
| Product mutation 记录 | 11,680 |
| Native verifier calls | 93,440 |
| 去重搜索流 | 5,120 |
| 去重 attempted challenge 身份 | 86,318 |

每个搜索都实际到达 first hit，所有 misses 均计入成本；legal 原生结果全部为 `Accepted`，product-last 全部为 `Product`，semantic alerts 为空。策略、horizon 前缀、head/merge、x64/ARM 的相同搜索流逐项相等。**四条 V2 lane 总共仍是同一组 5,120 个确定性搜索流，不能计成四倍独立样本或新增 chainwork。** 不同流身份也不是理想随机预言机独立性的证明。

下表 CPU 是每条 lane 完整固定策略的整数总和，包括真实 setup、全部尝试、trial retention 和 proof hashing；公共材料生成、后续输出/缓冲区销毁、native verifier 分别记录。`Δ` 为 dispatcher / generic − 1，正数表示更慢。

| Lane | Artifact | Generic CPU 秒 | Dispatcher CPU 秒 | Dispatcher Δ | 30 个 shard 的 generic/dispatch 范围 |
| --- | ---: | ---: | ---: | ---: | ---: |
| x64 head | 13094025188 | 41.082052430 | 41.726853924 | +1.569545% | 0.943064–1.480990 |
| x64 merge | 13093301643 | 41.001259184 | 41.750666641 | +1.827767% | 0.902516–1.503594 |
| ARM64 head | 13093926141 | 69.321174848 | 72.161178712 | +4.096878% | 0.893970–1.118517 |
| ARM64 merge | 13093891287 | 69.350255952 | 72.191903184 | +4.097530% | 0.894032–1.120780 |

**冻结 dispatcher 在四条 lane 的完整总 CPU 都更高。** 每种材料类仍按其全部 target/horizon/sample 聚合，保留如下正负结果；完整双策略 CPU 和逐 shard 分子分母见 [hosted-cost-analysis.json](hosted-cost/hosted-cost-analysis.json)。

| 材料类 | x64 head Δ | x64 merge Δ | ARM64 head Δ | ARM64 merge Δ |
| --- | ---: | ---: | ---: | ---: |
| full-rank-field | +5.769107% | +6.048892% | +8.350903% | +8.374914% |
| zero | +4.834253% | +6.154780% | +11.799263% | +11.791962% |
| continuity-maintenance-v1 | −11.046401% | −11.120896% | −2.208135% | −2.187241% |
| one-zero-left-rank-one | +4.943224% | +3.887402% | +1.325973% | +1.282369% |
| one-zero-right-rank-one | +3.446143% | +4.328306% | +1.372452% | +1.384718% |

Maintenance 是四条 lane 都成立的局部结构性正例，其余四类完整聚合均更慢。不能跨样本/材料类/主机事后选择最佳结果并拼成“最快矿工”，也不能从完整网格的负结果推断 generic 已经最优。该网格的混合权重不是协议实际任务分布；任何实测实现耗时都不是最便宜合法攻击者的下界。

### 本地 V2 与 V1 历史语义

本地 `3bbc` 的同一 30-shard V2 网格也完整通过，generic CPU 为 **43.195096289 秒**，dispatcher 为 **44.375901107 秒**，dispatcher 多 **2.733655%**。其独立复核另重算了有限域 AB product、挑战、ticket 和完整 proof digest，但没有独立重放全部 transcript。**计时期间存在其他 native 编译**，只能称为非独占本地 x64 观察，不能声称隔离硬件稳定性。见 [local-v2/README-analysis.md](local-v2/README-analysis.md)、[整数结果](local-v2/independent-analysis.json)与 [RAW_INDEX](local-v2/RAW_INDEX.json)。

V1 四条 lane 保持原两样本与 V1 挑战域，每条实际 50,034 attempts、23,360 verifier calls；四条共享 1,280 去重搜索流、21,754 attempted challenge 身份。**V1 的八样本政策仍未满足**，其记录没有改标为 V2。

| V1 lane | Artifact | Generic CPU 秒 | Dispatcher CPU 秒 | Dispatcher Δ |
| --- | ---: | ---: | ---: | ---: |
| x64 head | 13093416862 | 10.479927495 | 10.603538586 | +1.179503% |
| x64 merge | 13093776046 | 10.496243288 | 10.632923140 | +1.302179% |
| ARM64 head | 13093480950 | 17.722648504 | 18.399973784 | +3.821806% |
| ARM64 merge | 13093421854 | 17.723816464 | 18.398611680 | +3.807279% |

## 3. False-trace：正确拒绝与拒绝经济性分别验收

每份捕获为九类 × 八个真实 setup × 每 setup 四次搜索，实际共 573 次 hash attempts、288 次候选搜索。四路径与五路径捕获分别有 1,152 / 1,440 次 native verifier calls；全部返回 `Transcript`，没有 valid-proof acquisition。八份捕获共用同一组 288 个确定性搜索流。

以下分母是各自捕获中完整 attacker cohort CPU（setup + 全部 misses 与 hits），分子是同捕获 production 完整原语拒绝 CPU。四路径与五路径具有各自实际计时窗口和分母，保持分开。

| Lane | Artifact / 捕获 | Attacker 完整 CPU 秒 | Production 拒绝 CPU 秒 | 比值 |
| --- | --- | ---: | ---: | ---: |
| ARM64 head | 13093136677 / 四路径 | 0.009399456 | 0.198225712 | 21.089062 |
| ARM64 head | 13093136677 / 五路径 | 0.009923824 | 0.197660000 | 19.917725 |
| x64 head | 13093396655 / 四路径 | 0.004961609 | 0.113546188 | 22.884953 |
| x64 head | 13093396655 / 五路径 | 0.005848001 | 0.113597193 | 19.424961 |
| x64 merge | 13093436001 / 四路径 | 0.005001261 | 0.113341276 | 22.662540 |
| x64 merge | 13093436001 / 五路径 | 0.005762731 | 0.114107705 | 19.800977 |
| ARM64 merge | 13093880577 / 四路径 | 0.008735520 | 0.198071400 | 22.674254 |
| ARM64 merge | 13093880577 / 五路径 | 0.009271168 | 0.197991256 | 21.355589 |

本次整体比值为 **19.424961–22.884953**。各材料类、各 verifier 路径的完整整数分子分母及区间均保留在成本 JSON。它是固定源码/runner 下的原语拒绝观察，不包括公网 fanout、签名、队列、存储与业务确认，不能写成公网攻击放大率；也不能直接与历史 6.86–7.90 的不同源码、主机、复用方式及分母作因果比较。

## 4. ArithmeticFactCache：有限局部改善，暖路径存在回退

[Cache README](cache-benchmark/README.md)、[build manifest](cache-benchmark/build-manifest.json) 和 [summary](cache-benchmark/summary.json) 保存独立 selected-source harness 对照。Baseline 恢复 `7c5caf5bce1396976808a0f504c4163fbc1aed44` 的 `pon_work.rs` 及全部 tracked 子模块；candidate 的逐字节源码快照、锁文件和实际 ELF 同样保留。两者只在 `arithmetic_facts.rs` 及新增 test-only FullLimb 控制处不同。

两个 harness 使用同一 main、相同四个精确直接依赖、相同 resolved lock，全部 registry version/checksum 与原 workspace lock 一致。Rust 1.95.0、默认 release、`--locked --offline`，无 compiler/profile override。实验只有三个固定 dense-material seeds、八种 case、每 seed/case 128 次调用，三轮各启动新进程，顺序为 baseline/candidate、candidate/baseline、baseline/candidate。重复轮次不增加独立材料样本。

以下为每轮三个 seeds 聚合的 candidate / baseline CPU 比值；小于 1 才表示该聚合减少 CPU。

| Case | 第 1 轮 | 第 2 轮 | 第 3 轮 |
| --- | ---: | ---: | ---: |
| cold_false_trace | 0.733811 | 0.734345 | 0.730407 |
| cold_last_product | 0.847735 | 0.782216 | 0.704303 |
| cold_valid | 0.917707 | 0.849986 | 0.715914 |
| trace_only_upgrade | 0.729288 | 0.759356 | 0.791558 |
| capacity1_alternating_challenge_eviction | 0.758718 | 0.661658 | 0.739546 |
| warm_false_trace | 0.997828 | 1.098396 | 0.882910 |
| warm_last_product | 0.994665 | 1.148093 | 0.961934 |
| warm_valid | 1.218061 | 1.084874 | 0.911415 |

冷路径逐轮聚合均有改善，但逐 seed 仍有回退：cold_false_trace 的九对中一对大于 1（最大 1.046794），cold_valid 有两对（最大 1.163944）。**warm-valid 前两轮变慢，三轮不支持稳定加速结论；其他暖路径也有回退。** 全部六条 raw JSONL、stderr、命令与源文件读回保留。

共 18,432 次完整调用，semantic alerts 为 0；实测 transcript replays 11,520、product completions 9,216。Fixture target 为全 `ff`，没有 ticket 搜索；fixture 构造、cache 分配/prefill 另记，计时区包含 verify 调用与固定循环/预分配结果保留，随后再做 reference 对照和 JSON 输出。**这里没有 attacker 成本分母，没有原固定 Host 服务验收，也没有全 workspace 或生产资格。** 容量一 eviction 的每次访问 miss，但只交替两个 challenge，不能称为全新挑战洪泛。

## 5. 原 Host 服务：四个 pressure 的独立 active 高度均为 0

完整独立读回见 [analysis-service.md](hosted-service/analysis-service.md) 与 [analysis-service.json](hosted-service/analysis-service.json)。原始 ZIP 为 [13092834210.zip](hosted-service/13092834210.zip) 和 [13093520419.zip](hosted-service/13093520419.zip)，来源及 digest 见对应 [head receipt](hosted-service/head-zip-receipt.json)、[merge receipt](hosted-service/prospective-merge-zip-receipt.json) 和 [API 快照](hosted-service/all-artifacts-api.json)。

Host 预算保持 `cpu.max = 25000 100000`（0.25 CPU）、burst 0、memory 2 GiB、swap 0、pids 256；每个业务窗口仍为 **4 秒**，pressure 为 **16 workers**。限额/身份前后不变，没有 Host read error、OOM 或准备失败。软件 mutation meter 的初始 2 秒 credit、每秒 0.25 秒 CPU refill、worker limit 2 均保持，四个 pressure 的 CPU refusal 都为 0；余额充足没有使业务目标完成。

| 场景 | baseline 最后 ACK / 确认完成（秒） | pressure 最后 ACK（秒） | 收到 History 页数 | 独立库最高已存块 / active | 失败位置 |
| --- | ---: | ---: | ---: | ---: | --- |
| head / original | 0.232 / 1.699 | 1.579 | 3 | 3 / **0** | 第 4 次 History 网络 I/O 截止后返回 |
| head / fresh | 0.232 / 1.692 | 1.751 | 3 | 2 / **0** | 第 3 页原生重放 `PUBLIC_REQUEST_DEADLINE` |
| merge / original | 0.311 / 3.401 | 2.368 | 1 | 0 / **0** | 首页原生重放 `PUBLIC_REQUEST_DEADLINE` |
| merge / fresh | 0.377 / 3.477 | 2.851 | 1 | 0 / **0** | 首页原生重放 `PUBLIC_REQUEST_DEADLINE` |

秒数按表中精度四舍五入；页数只表示成功网络响应，不等于原生验证、导入或激活完成。所有 receiver 已 ACK 七块并激活到高度 7，四个独立 pressure 客户端的 active 仍为 genesis。部分有效块存入独立库也不能计成 active 或 confirmed。没有攻击输入被接受，当前失败对象是业务可用性。

| Pressure | Receiver 全 W1 CPU 毫秒 | Receiver mutation 总 CPU 毫秒 | 独立 History+确认 CPU / wall 毫秒 | 攻击 calls / 完整拒绝响应 |
| --- | ---: | ---: | ---: | ---: |
| head / original | 252.422 | 471.467 | 130.596 / 2486.586 | 281 / 265 |
| head / fresh | 221.421 | 423.108 | 117.260 / 2300.806 | 248 / 232 |
| merge / original | 285.115 | 529.706 | 76.517 / 1691.085 | 208 / 192 |
| merge / fresh | 250.692 | 471.604 | 45.058 / 1198.219 | 184 / 168 |

全 W1 CPU 已包含在 mutation 总 CPU 内，攻击端构造 CPU 已包含在 joined worker CPU 内，均不得重复相加。fresh head/merge 实际构造提交 248/184 个唯一 challenge，收到 232/168 个 `WORK:Transcript`，截止附近的客户端 I/O 错误也保留。Host before/after 总计覆盖整个 controller 命令，不能除以某一场的四秒，也不能分配为单场因果占比。

此服务入口使用 `PublicServer::new`，**没有启用 `with_arithmetic_facts`**。局部 cache 改善不能用于解释这份服务验收。两条 lane 的 tree 和实际 ELF 完全相同，baseline 独立重放 CPU 仍有明显跨 runner 差异；当前没有受控前后对照，不能将较快 ACK 或多存几块归因于 History 去重。

### 当前代码 9cd91ed 的独立服务复测

[当前代码快照](current-code-snapshot/README.md)保留 run `41332206071` 的两个原服务 ZIP、四个 V2 取消日志及源码读回。实测 head 为 `9cd91ed69a0c69df42f8d7812d32d271df6e1998`，merge 为 `a70f0165379156da436d1c0be403e1effd3912c0`，均对应 tree `60a521c7299febfe26a8c7d38d3420d490d07cd8`；它们与上表的 3bbc/ea43 是分别执行、分别保存的结果。

| 当前代码场景 | baseline 确认完成（秒，约） | pressure 接收端 ACK / active 高度 | pressure 独立库已存块最高高度 / active | 独立确认数 |
| --- | ---: | ---: | ---: | ---: |
| head / original | 1.8933 | 7 / 7 | 2 / 0 | 0 |
| head / fresh | 1.8195 | 7 / 7 | 1 / 0 | 0 |
| merge / original | 1.9852 | 7 / 7 | 1 / 0 | 0 |
| merge / fresh | 1.9830 | 7 / 7 | 1 / 0 | 0 |

四个 pressure 都返回 `PUBLIC_REQUEST_DEADLINE`，原 4 秒、0.25 CPU、2 GiB 与 16 workers 不变；这是真正的当前代码服务失败，不能因部分块已保存而改写为完成。四条 V2 则在 runner shutdown 后取消且没有对应 artifact，本包保留取消日志，不推断未取得的完整成本结果。

## 6. 本地验证、History 未完成与后续 CI

原始记录见 [python-validation.json](validation/python-validation.json)、[native-validation.json](validation/native-validation.json) 及各自命令和日志 hash。Python 验证聚合为 PASS；native 聚合仍为 **FAIL**，因为 History lib-test 编译没有完成。

| 本地验证（3bbc） | 实际结果 / 范围 | 原始记录 |
| --- | --- | --- |
| V1 reader / V2 reader / cost runner | 12 / 11 / 45 tests pass | [V1](validation/v1-reader.log)、[V2](validation/v2-reader.log)、[runner](validation/cost-runner.log) |
| Source negatives / PQ negatives / CI contract / query bound | 34 / 34 / 95 / 21 tests pass | [source](validation/source-negatives.log)、[PQ](validation/pq-negatives.log)、[contract](validation/ci-contract.log)、[query](validation/query-bound.log) |
| W1 module | 104 pass | [w1-module.log](validation/w1-module.log) |
| Wire bindings | 18 pass、1 ignored；ignored 不计执行成功 | [wire-bindings.log](validation/wire-bindings.log) |
| Legal example / work-fuzz / retained rejection | 8 / 6 / 3 pass | [legal](validation/legal-example.log)、[fuzz](validation/work-fuzz.log)、[rejection](validation/retained-rejection.log) |
| Crypto all-features | 各原输出段为 116、5、4、5、2 pass；不与 W1 子集相加为独立覆盖 | [crypto-all-features.log](validation/crypto-all-features.log) |
| 三包 Clippy | crypto/protocol/node，all-targets、all-features、`-D warnings`，exit 0 | [命令](validation/clippy-command.json)、[退出](validation/clippy-exit.json)、[日志](validation/clippy.log) |
| Formatting / locked graph / corpus / source inventory | 对应检查 exit 0，范围由收据明确 | [native receipt](validation/native-validation.json)、[Python receipt](validation/python-validation.json) |
| History 原尝试 | Cargo exit 101；rustc SIGKILL；**0 History tests** | [history-original.log](validation/history-original.log)、[独立诊断](validation/history-sigkill-diagnostic.json) |
| History jobs=1 重试 | 同源、同 release/locked/offline 与原 900 秒 cap；再次编译 SIGKILL；**0 History tests** | [重试收据](validation/history-retry-jobs1.receipt.json)、[日志](validation/history-retry-jobs1.log) |

两次本地 History 失败都在 lib-test 编译完成之前，均无 test-running/result 行。第二次只把 Cargo build jobs 从 2 调为 1，没有修改 release、CPU/timeout 或业务预算。共享 executor cgroup 的内存压力/OOM 计数支持资源压力假设，但没有进程特定的证据把每次 SIGKILL 精确归到某次 OOM；不能称为已证实的 History 语义回归，也不能称为通过。

### Runtime 与 required-baseline 的实际状态

保留的 [runtime recipe](related-ci/runtime-recipe-3bbc-static.sh) 与 [related-ci triage](related-ci/triage-41330488724.json) 证明现有 workspace all-targets/all-features 的 Linux 测试选择静态包含三个无 `ignore` 的新 History 控制：

- `history_w1_checks_host_once_at_every_real_progress_boundary`；
- `history_w1_host_change_at_selected_and_unselected_boundaries_refuses_and_retries`；
- `history_w1_original_deadline_precedes_resource_and_complete_work`。

静态选择之后还有实际执行证据。**截至 2026-11-01 17:48 UTC 的后续查询，3bbc 的 head 与 merge runtime jobs 均为 cancelled；不能再把较早 17:40 快照中的 `in_progress` 当作最终状态。** 已取回的 [head 完整 cancelled 日志](related-ci/job-124919351641-cancelled.log)中，**18 个 History tests 均逐项实际出现 `... ok`，另一个 child test 为 ignored**；上述三个新测试在 **17:30:54 UTC** 明确通过。独立定位见 [History selector receipt](related-ci/history-selectors-from-cancelled-head.json)。

这一实际执行使用默认 test profile（`unoptimized + debuginfo`）及 `--all-features`。随后 **17:43:48 UTC** 在后续 store 容量测试期间出现 runner shutdown/cancelled，因此 **整个 Node lib suite、整个 runtime job、after-source 步骤均没有完整成功收据**。局部 History/debug 的 18 pass 必须保留，也不能外推为整个 suite 通过；本地 release 的两次编译 SIGKILL、0 tests 同样保留。Merge 日志获取返回 `BlobNotFound` 404，没有对应日志可确认其 History 实际执行，不能用 head 的行或静态包含补齐。

另一个 required-baseline run [41330488724](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41330488724) 的两个 protocol-contract artifact 均显示五个 named tests 通过，而四秒业务目标仍为 `CONFIRMATION_TARGET` 失败；这不是编译/语法或 stale test-count 问题。相关原 ZIP、API、日志及区分 named-test 与 finite-business target 的读回保留在 [related-ci](related-ci/triage-41330488724.json)，不与主 work-security run 的两个 service jobs 混为同一执行。

### 9cd91ed 只修复三文件 CI guard

[独立 review](ci-guard-followup/independent-review.md)、[source identity](ci-guard-followup/source-committed.json)、[guard 逐字节检查](ci-guard-followup/source-blob-guards.json) 与 [七项验证收据](ci-guard-followup/validation.json) 保留该修补的范围。相对 3bbc 仅改变：

1. `.github/workflows/pon-branch-encoding-acceptance.yml`：更新实际 wire source blob，17-pass 断言改为 18-pass，并通过全名 `--exact` 显式执行 `pon_wire::tests::every_header_field_binds_its_wire_bytes_challenge_and_block_identity`；保留 0 failed、1 ignored 和既有门禁。
2. `config/pon/pq-cross-branch-corpus-v1.json`：仅同步这一 workflow pin。
3. `docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`：记录问题、范围与尚未闭合的验收。

独立检查确认 **1,078 个 Rust 文件、53 个 Cargo/toolchain 输入、234 个 scripts、39 个其他 config 和 12 个其他 workflows 与 3bbc 字节相同**。这证明源码范围保持，没有产生新的 native 成功收据。旧 branch CI 首先死于 stale blob assertion，后面的 Cargo 命令只是打印出的 shell script，不能倒推 wire test 已经执行；17-pass 断言是后续潜在阻挡，二者一并修复。

9cd 后续主 work-security run 的实际结果为 **8 个旧 cost 成功、4 个 V2 cancelled 且无 artifact、2 个 service 失败**。旧完整 V2 实测继续链接 3bbc/ea43，source 等价不改变执行身份。本 README 的后续 CI 段落只引用已观察结果，不声明其他未收齐的 CI 全绿。

### 固定 PQ provider 的环境修复

本机系统 OpenSSL 3.0.13 不具备相关 all-feature 编译所需接口；旧失败输出的[保留片段](validation/old-provider-node-clippy-final-output-chunk.txt)不删除。使用原 `prepare_pq_provider.sh` 在隔离目录构建精确 OpenSSL **3.5.9**，source archive SHA-256 为 `603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a`，没有替换系统 OpenSSL，也没有伪造 GitHub Actions 环境。

[Provider receipt](pq-provider/provider.json) 与[完整 build/smoke 日志](pq-provider/build-and-smoke.log)确认 source digest、静态安装、ML-DSA-65 keygen/sign/verify 及错误消息拒绝。Preparation 本身没有执行 upstream 全测试或 Rust PQ suite；随后本地 crypto all-features 与 Clippy 的实际执行另有上述日志。该修复不构成独立密码实现、整链量子安全或生产资格。

## 7. 完整原始材料、来源与复核入口

| 目录 | 内容与来源 | 索引 / 读回 |
| --- | --- | --- |
| `hosted-cost/` | 主 run 的 12 个完整 artifact 文件集；保留源码读回、锁图、commands、全部 raw stdout/stderr、reader、manifest 与实际 ELF | [ARCHIVES.json](hosted-cost/ARCHIVES.json)、[独立报告](hosted-cost/hosted-cost-analysis.md)、[完整结果](hosted-cost/hosted-cost-analysis.json)、[复核脚本](hosted-cost/analyze-hosted-cost.py)、[原执行日志](hosted-cost/hosted-cost-analysis.log) |
| `hosted-cost-job-logs/` | 12 个 cost jobs 的 GitHub 日志 | 与 artifact/source 身份交叉定位，不代替 raw |
| `local-v2/` | 30 份 stdout/stderr 和执行 metadata/ELF，分存五个 raw tar.xz 与一个 metadata/binary tar.xz | [RAW_INDEX.json](local-v2/RAW_INDEX.json)、[独立分析](local-v2/README-analysis.md)、[JSON](local-v2/independent-analysis.json) |
| `cache-benchmark/` | 六次 raw streams、选定完整源码和实测二进制、构建/运行命令 | [INDEX.json](cache-benchmark/INDEX.json)、[README](cache-benchmark/README.md) |
| `hosted-service/` | 两份主 run 原始 ZIP、API、job logs、固定 Host/ELF/SQLite 与业务报告 | [分析](hosted-service/analysis-service.md)、[JSON](hosted-service/analysis-service.json) |
| `validation/` | 本地正负控制、原失败及重试、严格 Clippy 和 source receipt | [Python receipt](validation/python-validation.json)、[native receipt](validation/native-validation.json) |
| `pq-provider/` | 固定 provider 安装、环境、来源和 smoke | [provider.json](pq-provider/provider.json)、[build-and-smoke.log](pq-provider/build-and-smoke.log) |
| `ci-guard-followup/` | 9cd 三文件修补、校验与独立 review | [review](ci-guard-followup/independent-review.md)、[validation](ci-guard-followup/validation.json) |
| `related-ci/` | required-baseline 原 API、日志、两个 protocol ZIP、静态 runtime recipe | [triage](related-ci/triage-41330488724.json)、[integrity](related-ci/integrity-41330488724.json) |
| `current-code-snapshot/` | 9cd/a70 的两个原服务 ZIP、四个 V2 取消日志、API 与有限最终快照 | [README](current-code-snapshot/README.md)、[summary](current-code-snapshot/summary.json)、[INDEX](current-code-snapshot/INDEX.json) |

Hosted cost 保留 **808 个原 artifact 成员文件**，归档总压缩大小 180,351,232 bytes。其 `.tar.xz` 是逐成员等字节重压缩，不是原 GitHub ZIP 容器字节；原 ZIP 大小/hash 与每个原成员大小/hash 一起保存在 `ARCHIVES.json`。大归档按该索引的 `parts` 顺序拼接；必须核对各 part 和拼接后整体 digest。不能把新压缩容器的 hash 当成 GitHub 原 ZIP hash。

独立 [verify_evidence.py](verify_evidence.py) 流式核对归档/分片、成员路径和 hash/CRC、索引与保存的身份关系，不解压执行二进制、不重做 native 实验、不赋予工作或服务资格。从本目录运行：

```sh
python3 verify_evidence.py
```

该命令写 [verification-receipt.json](verification-receipt.json)。已有一次实际执行 exit 0，完整核对 hosted 12 个归档/808 个成员、local 六个归档/71 个文件、cache 45 个外层文件/43 个归档成员/10 个命令收据，以及 service 两个 ZIP/106 个成员，全部既有子索引字节检查 PASS。该次顶层 `INDEX.json` 尚未存在，原收据作为 [verification-subindexes-receipt.json](verification-subindexes-receipt.json) 保留，没有追记为已验证全集。

最终[顶层 INDEX](INDEX.json)覆盖封存文件全集，并排除自身及当前 verification receipt 以避免自引用。最终执行结果见 [verification-receipt.json](verification-receipt.json)；只有其中 `complete_top_level_inventory_verified=true` 才表示完整顶层集合已实际核验。原始子索引收据单独保留，字节复核 PASS 与成本/服务验收结论分别保留。

### 从封存 raw 复算

恢复到独立目录，使用索引列出的 part 顺序/成员路径，先做字节校验，再执行 reader 或纯 Python 审计。以 x64 head V2 为例，`13094025188.tar.xz.part01` 至 `.part05` 拼接后按索引 hash 核对，解包到 `<replay>/13094025188/`。保存的 3bbc 源码严格 reader 可以直接读取该目录内全部 30 份 raw：

```sh
python3 /path/to/3bbc-source/scripts/pon_w1_legal_strategy_reader_v2.py \
  /path/to/replay/13094025188/w1-legal-strategy-v2/campaign-*.stdout
```

本地 V2 的六个归档解包到同一空目录后也可使用同一 reader。原本地独立 AB/attempt 复核是会话内 inline Python，没有保留可单独复制的原脚本；本包保留该次结果、完整 raw 与可运行的项目 reader，不把后来脚本冒充原执行。

保存的 `analyze-hosted-cost.py` 原入口同时要求最初下载布局的 `<id>/`、`<id>.zip` 与 `<id>-receipt.json`，用于额外核对 GitHub ZIP 运输容器。本包的持久归档采用逐成员 tar.xz；完成本包字节验证并恢复全部 artifact 目录后，可复用该脚本的独立 raw 复核函数，跳过已经另由 `verify_evidence.py` 处理的运输封装：

```python
import importlib.util
import json
from pathlib import Path

bundle = Path('/path/to/pon-work-security-eight-samples-20261101')
restored = Path('/path/to/replay')  # 下有 12 个 artifact-id 目录
source = Path('/path/to/3bbc-source')
spec = importlib.util.spec_from_file_location(
    'cost_audit', bundle / 'hosted-cost/analyze-hosted-cost.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
audit = module.Audit(restored, source)
rows = json.loads((bundle / 'hosted-cost/ARCHIVES.json').read_text())['archives']
for row in rows:
    artifact = {'id': str(row['artifact_id']), 'name': row['artifact_name']}
    artifact.update(audit.source_graph(artifact))
    for directory in sorted((restored / artifact['id']).iterdir()):
        if not directory.is_dir():
            continue
        manifest, identity = audit.manifest(artifact, directory)
        if directory.name.startswith('w1-legal-strategy-'):
            result = audit.legal(directory, manifest, directory.name.rsplit('-', 1)[1])
        else:
            result = audit.false_trace(directory, manifest)
        print(json.dumps({'artifact': artifact['id'], 'identity': identity,
                          'raw_result': result}, ensure_ascii=False))
print({v: len(streams) for v, streams in audit.streams.items()})
```

该复算重新检查记录、整数成本和流身份，不重新执行 native，也不重放完整 transcript。所有例子中的源码与恢复目录均应替换为明确固定身份的新目录，原始封存材料保持只读。

## 8. 未取得的资格与后续验收对象

成本实验的原始 manifest/reader/campaign 与本包验收结论保持以下七项为 `false`：

| 字段 | 状态 |
| --- | --- |
| `hardness_accepted` | false |
| `work_profile_qualified` | false |
| `resource_fairness_qualified` | false |
| `public_service_measured` | false |
| `independent_hardware_qualified` | false |
| `public_network_ready` | false |
| `production_activation` | false |

V2 的 `policy_sample_count_satisfied=true` 仅关闭此次固定网格的样本数量不足。`fastest_adversary_lower_bound`、全材料/target 覆盖以及 reader 自身的 execution/transcript 认证边界仍未取得。上表字段属于各自成本捕获的声明范围；其中 `public_service_measured=false` 不表示本包从未执行服务测试。本包另行保留了真实服务实验，其业务结果为失败；不能把不同捕获的字段或测试结果合并为通过。

接下来的验收需要分别证明：完整关系验证和挑战绑定、最便宜合法策略的真实成本、错误工作拒绝与原预算业务完成，以及独立模型效用。缓存或微基准的局部改善不能替代其中任何一项。当前原四秒压力窗口仍未完成独立确认；保持 **HOLD / no activation**，不提高出块频率，也不把 CI 成功数、重复验证次数或 CPU 优势转化为额外 chainwork。
