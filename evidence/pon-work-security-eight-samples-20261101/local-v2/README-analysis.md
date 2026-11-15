# V2 完整合法策略实验：独立原始记录复核

**结果：30/30 native shards 完成，八样本数量缺口在此固定网格内补齐；全局成本安全与生产资格仍未取得。**

本复核读取已经完成的原始捕获，不启动第二次 native campaign，不修改原始 JSONL、stderr 或 manifest。独立聚合实现没有导入项目的 V1/V2 reader；先从原始记录重建身份、计数、成本与整数关系，再与原 reader/manifest 逐项核对。下文所有数字只属于本次本地 x64 观察。

## 固定身份与原预算

- Source commit：`3bbc0288d6b7b6ed7f2bf0ee70d99b3b14236129`
- Source tree：`f52299288ca23426e5186f37fb3a58788e40dbee`
- 实测与保留二进制 SHA-256：`f639e99394f7805dd83e2e2ad73e38a2c161b902705a75ba2a0c449530fd6cf1`
- 原 execution manifest SHA-256：`8d4a9caf9febed007f5de30b482bdae714f9b839d28c1937a2ca76ff447a24ff`
- 执行上下文：`local-native-preflight`；不冒充 GitHub-hosted 或 ARM。
- source-before 与 source-after 完全一致；各自核验 **6,856 tracked entries / 792,504,967 bytes**。独立查询 Git 的 commit、tree 与 clean 状态一致。
- 实际 34 个命令观察均为 exit 0、`timed_out=false`。其中 30 个 native shard 的上限均为 **300 秒**；三项 identity 上限仍为 30 秒，build 上限仍为 900 秒。
- 原 build 耗时 **286.616518672 秒**；单 shard 实际 wall 范围 **0.115012844–37.691420577 秒**；30 shard 命令 wall 合计 **238.719190926 秒**。这些命令 wall 包括其各自执行范围，不能当作单个策略 CPU。
- 30 个 campaign stderr 均为空。build stderr 仍保留 SQLite I/O boundary `UNQUALIFIED` 的 loader-directory 警告；该原语实验不据此取得完整 SQLite 或 Node 资格。

原始捕获位于 `w1-legal-strategy-v2/`。全部 30 份 `campaign-NN.stdout` 共 **692,491,059 bytes**。独立计算的每个 SHA-256 同时匹配原 execution manifest 和 reader 的 input digest；逐文件身份保存在与本报告同目录的 `independent-analysis.json`，没有把派生报告重标为原始捕获。JSON 的 `input_manifest_sha256` 是该派生 input inventory 的摘要；原 execution manifest 的摘要单独记录为 `capture_verification.manifest_sha256`。

## 实际执行计数与去重

| 对象 | 本次实际数量 | 解释 |
| --- | ---: | --- |
| 完整 shards | 30 | 五材料类 × 两 target × 三 reuse horizons |
| 每 shard 样本 | 8 | 真实出现 sample 0–7，各执行两策略 |
| 完整策略 setup/cohort | 480 | 每 cohort 一次真实 setup |
| 已执行策略搜索 | 11,680 | 两策略均保留所有失败尝试 |
| 完整已付 attempt | 195,832 | 每策略均为 97,916 |
| candidate 完整字节记录 | 5,840 | 包含 horizon 间重复身份 |
| 单独测量的 product mutations | 11,680 | 不当作新合法工作 |
| 完整 native verifier calls | 93,440 | 46,720 Accepted；46,720 Product 拒绝 |
| 搜索流身份去重 | 5,120 | 去重策略重复与 1/8/64 horizon 的相同前缀 |
| attempted challenge 身份去重 | 86,318 | 同 challenge 的 trial 身份逐项相等 |
| winning challenge/proof 身份去重 | 5,120 | 不等于原生已准入 blocks 或发行的 chainwork |
| exhaustion | 0 | 本次每个搜索实际找到 first hit；不是删去失败尝试 |

独立复核检查了每个 shard 的 complete end 与全部 record counts、sample/strategy 覆盖、唯一 setup、顺序 nonce、first-hit 停止、相同 horizon prefix、每策略完整 attempt 分母以及计时嵌套。材料的 canonical A/B、task hash 和精确有限域 AB product 均独立重算；每个 attempt 的 V2 challenge、ticket 和完整 proof digest 均重新计算，所有 candidate 字节及其摘要也被核对。

本复核**没有独立重放全部 W1 transcript**。完整 transcript 验证结论来自捕获中实际 native verifier 的 93,440 次结果，且同原严格 reader 的 semantic alerts 为空相符。正确的 AB product、task/ticket hash 或本复核的计数通过，均不能代替完整 transcript 关系验证。

5,120 个去重搜索流是精确身份计数，**不是**对 SHA-256 输出独立性或理想随机预言机模型的证明。两个策略、多个 horizon、重复 proof 及重复 verifier 调用均不增加独立已挖出的区块数量。

## 完整固定策略成本

表中 CPU 是真实 cohort 的整数 CPU 总和，包括一次 setup、全部 complete attempts、misses、trial retention 与完整 proof hashing。它不是最短单次采样，也不从不同样本中事后拼出“最优矿工”。

百分比为 `dispatch / generic - 1`：正数表示 dispatcher 消耗更多 CPU，负数表示它消耗更少。

| 材料类（该类全部两 target、三个 horizons、八 samples） | Prepared generic CPU 秒 | Frozen dispatcher CPU 秒 | Dispatcher CPU 变化 |
| --- | ---: | ---: | ---: |
| `full-rank-field` | 8.428264989 | 9.358291065 | +11.034609% |
| `zero` | 8.946471352 | 9.052370227 | +1.183694% |
| `continuity-maintenance-v1` | 8.601818389 | 7.658281325 | -10.969042% |
| `one-zero-left-rank-one` | 8.784534784 | 9.023105303 | +2.715801% |
| `one-zero-right-rank-one` | 8.434006775 | 9.283853187 | +10.076426% |
| **完整网格总计** | **43.195096289** | **44.375901107** | **+2.733655%** |

全网格固定策略比值为：

`generic / dispatcher = 43195096289 / 44375901107 = 0.9733908543028158`。

因此本次完整网格中，冻结 dispatcher 的实际 CPU 总成本比 generic **高 2.733654788%**。它仍有一个可复核的结构性正例：maintenance 全部观察总 CPU **少 10.969041909%**。其他四类完整聚合分别变慢，不能只保留 maintenance 的正例，也不能从全局负例推断 generic 已最优。

30 个完整 shard 聚合中，dispatcher 为 **17 个较快 / 13 个较慢**。各 shard 的 `generic / dispatcher` 范围为 **0.8019291824–1.8566025362**：

- 最低：zero、target-index 0、horizon 64；generic 490,325,131 ns，dispatcher 611,431,959 ns，dispatcher **多 24.699290398%**。
- 最高：zero、target-index 0、horizon 1；generic 12,598,255 ns，dispatcher 6,785,650 ns，dispatcher **少 46.138175485%**。

240 个单独配对 cohort 中，dispatcher 为 **111 个较快 / 129 个较慢**；比值范围 **0.4771857416–6.1715402339**。这些短观察差异完整保留，不能当作稳定硬件优势或事后选择策略的依据。完整整数成本、逐 shard 比值与这些诊断范围均保存在 JSON，未使用每样本最快 oracle。

两个完整策略在 30 个 shard 中的 CPU 区间如下。每个点都累加该 shard 的八个完整 cohort；不同 target 和 horizon 的工作数量不同，因此这些区间仅描述观测范围，不是等量任务的性能对照。

| 完整策略 | 最低 shard CPU 秒 | 最高 shard CPU 秒 |
| --- | ---: | ---: |
| `prepared-generic` | 0.007602588 | 7.274784969 |
| `frozen-public-dispatch-v1` | 0.004435346 | 7.816843422 |

公共材料生成另行记录；cohort 外的 retained-buffer destruction、hex/JSON 输出和 native verification 不在上述策略 CPU 总和内。trial retention 与 proof hashing 是攻击者可能省掉的证据开销，因此这些成本不是最便宜合法攻击者的下界。

## 仍然为 false 的资格与实际边界

原 reader 已将 `policy_sample_count_satisfied` 设为 true，且保持原政策最低八样本和原 policy bytes/hash。这只关闭此固定网格的样本数量不足。

全部七个资格/激活字段仍为 false：

- `hardness_accepted`
- `work_profile_qualified`
- `resource_fairness_qualified`
- `public_service_measured`
- `independent_hardware_qualified`
- `public_network_ready`
- `production_activation`

`all_policy_materials_or_targets_covered`、`fastest_adversary_lower_bound` 和 reader 的 `native_execution_authenticated` 也仍为 false。

**本次计时期间存在其他 native 编译。** Thread CPU 没有直接把别的进程 CPU 算入本线程，但资源竞争、缓存、调度、频率等仍可能影响观察。本次是非独占本地 x64 观察，不能声明隔离硬件稳定性、独立硬件复现或通用加速比。这里不使用历史 V1/不同主机的时间作因果性能比较。

五类任务、两种容易 target 和三个 horizons 仍不足以覆盖全部合法算法、任务选择、广泛预处理、GPU/FPGA/ASIC、能耗或量子成本。没有执行公开网络 confirmed-business 验收，没有证明模型增益，也没有因此获得生产激活资格。

