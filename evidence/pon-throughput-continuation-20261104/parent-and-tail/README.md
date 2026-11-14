# Parent readback and TCP-tail continuation

**本轮保留两个范围明确的默认运行时变更；完整吞吐、安全及启用条件仍未闭合。**
相对共同基底 `b8116f65789a85148254f870c678a44f895316de`，新增默认变更为完整
TCP 请求的尾字节取消，以及 DirectAppend 在末次写入之后接入既有事务读回。
parent-graph carry 与 M06 checked-prefix 两个候选均已归档并撤回默认源码。
本页汇总各自的源身份、保留结果和后续验收条件，不把历史测试合并为新源码的通过结果。
依据见 [TCP 记录](tcp/README.md)、[DirectAppend 首轮记录](append-first/receipt.json)、
[graph 恢复记录](graph-candidate/restoration.json) 与
[M06 恢复记录](state/prefix-three-arm/default-restoration.json)。

## 保留的默认变更及边界

### 完整请求之后的 TCP 尾字节

Public V3 在请求 body 已完整、处于 Enqueue 或 Await 时发现额外字节，会在内部记录
Transport 错误 `PUBLIC_TRAILING_INPUT`、关闭连接并设置原取消标志；不会向客户端发送
该错误的响应帧。等待 Challenge/Ready/grant 的阶段仍允许
合法下一帧提前到达，避免把提前发送的正常 body 当作尾数据。原任务、CPU 结算和资源
释放责任仍由原 owner 完成。对应源码及实际 localhost 控制分别见
[public_v3.rs](../../../trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs)、
[第一轮 TCP](tcp/README.md) 与 [第二轮 TCP](tcp/trimmed-schema/README.md)。

取消发生时已经持久提交的结果仍是事实；后续连接失败、未收到 ACK 或取消标志本身不能
证明回滚，已经排入 Output 的响应也可能继续发送。两轮控制覆盖正常提前 body、尾字节
保持连接、尾字节后半关闭和原有排队断开，但其本地经典 V3 结果不提供 PQ 握手、WAN 或
完整业务吞吐资格。见 [第二轮范围说明](tcp/trimmed-schema/README.md) 和
[当前原计划的最终写入与取消边界](../../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)。

### DirectAppend 的末写入读回

直接追加在最后一条 event 写入之后，存在合格 scope 时使用原始 writer 的既有 readback
scope，并在最后一个调用方回调之后复核未再发生写入。没有合格 scope 的回退仍保留
完整验证和原 writer 的事务身份检查，但不承诺严格的 write-epoch fence。
完整当前 State、账户图、祖先、event 和最终 generation
检查仍保留，SQL commit 仍归属 `Atomic`；账户图证明不跨 COMMIT。
实现与差分控制见 [store.rs](../../../trillionnium/crates/trnm-pon-node/src/store.rs)、
[append 控制](../../../trillionnium/crates/trnm-pon-node/src/store/append_readback_tests.rs) 和
[既有 readback](../../../trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback.rs)。
历史 f56/dd6a 源上的两项 append 加六项 reorg 控制共 8/8 通过，实际日志为
4.61 秒；这只归属于该次 [stdout](append-first/stdout.log) 和
[source/ELF receipt](append-first/receipt.json)。

这里有明确的错误身份边界：如果回调替换了原事务，事务 ABA 会按既有 reorg scope 规则
升级为 `NATIVE_POST_WRITE_SCOPE`，先发生的错误保留为 source。普通失败回调的错误优先序
与“同时发生事务替换”的升级规则需要分别判断，不能宣称所有异常身份都完全不变。
见 [共享事务尾部实现](../../../trillionnium/crates/trnm-pon-node/src/store.rs) 和
[原 reorg 控制](../../../trillionnium/crates/trnm-pon-node/src/store/reorg_readback_tests.rs)。

这些变更保留完整 State 与独立 W1 验证；它们没有把当前完整状态工作改成仅按 touched keys
增长的入口。M06 默认恢复、现有读回实现及其复杂度边界分别见
[M06 决策](state/prefix-three-arm/README.md)、
[readback 源码](../../../trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback.rs)
与 [原完整成本记录](../../pon-complete-cost-continuation-20261104/reproduction.json)。

## 归档而未启用的候选

| 候选 | 保留的否定结果 | 默认决策与原始材料 |
|---|---|---|
| 同一事务内跨 INSERT 延续父账户图证明 | 删除新增逐 INSERT catalog 查询后，68 个真实账户的转账样本仍有 **10.79% 描述性 CPU 回退**；catalog 资格也不足以独立证明物理页所有权。安全审阅未复现绕过，不将未完成论证写成已确认漏洞。 | **HOLD，恢复 b811 默认 publisher/scope。** [graph 总说明](graph-candidate/README.md)、[决策](graph-candidate/decision.json)、[全部成本读回](graph-candidate/cost-readback.json)。 |
| 同一不可变借用下的 canonical comparison / checked-prefix | 唯一一次预注册三臂实验保留 2,592 次返回，18 项比较中 16 项通过；128 键首失配和 4,096 键末失配相对 a10 的 p95 分别回退 **13.15% / 16.42%**，超过原 10% 上限。 | **HOLD，恢复三个 40a/b811 默认文件。** [M06 总说明](state/prefix-three-arm/README.md)、[完整决策输出](state/prefix-three-arm/raw/decision.stdout)、[恢复记录](state/prefix-three-arm/default-restoration.json)。 |

graph 的两轮描述统计没有充当 M06 的预注册门槛；M06 的一次原生观察测试成功也没有充当
性能 PASS。原候选、参考函数、失败、所有样本和 patch 均保留；后续默认源码不得沿用它们
的执行身份。见 [graph 三种源身份及 patch](graph-candidate/README.md) 与
[M06 完整归档校验](state/prefix-three-arm/archive-validation.json)。

## 证据索引：各源身份独立

| 包 | 实际范围及身份 | 可据此确认的结果 |
|---|---|---|
| [TCP 第一轮](tcp/README.md) | dirty 73ab，native map `f56cc35b…` / ELF `dd6a1dee…` | 五个指定 TCP 控制通过；先前 helper 反例失败和 Node 编译失败完整保留。没有执行整个注册套件。 |
| [TCP 第二轮](tcp/trimmed-schema/README.md) | dirty 73ab，native map `0e9dd281…` / ELF `65d283d5…` | 同五个 TCP 控制分别重跑通过；不属于后来 b811 或其 dirty successor。 |
| [DirectAppend 首轮](append-first/receipt.json) | 同第一轮 f56/dd6a ELF | [两项 append、六项 reorg](append-first/stdout.log) 通过；没有性能或新默认源码资格。 |
| [graph 候选](graph-candidate/README.md) | f56/dd6a、0e9d/65d2 两轮实测，加未实测的 b811 合成 patch | 各轮控制和成本独立保存；归档后默认撤回。 |
| [M06 三臂](state/prefix-three-arm/README.md) | dirty b811，native map `d88c7422…` / ELF `3fd395f7…` | 单次 16.25 秒观察完成；读取器 exit 1、HOLD；此前 [两臂记录](state/README.md) 保留自己的旧 manifest。 |
| [最终 CI 接线](ci-final/README.md) | b811 原 56 项加 DirectAppend 两项，**58 项声明选择** | YAML、shell、嵌入脚本及旧组保留的静态检查；不等于 58 次原生通过。PQ 原 49 项与另列的原 transaction-scope 13 项保留。 |
| [b811 hosted 业务读回](b811-hosted/README.md) | clean b811 / tree `fba28b38…`，原始 head runs | F0 与三批 campaign 的业务负结果；未测试本地 dirty 默认变更。 |

更早的 [CI/registry 观察](ci/README.md) 保留当时的候选和实际 ELF 名单；不能用历史
12/35/103、13/36/104 或临时 63 项接线代替现在的 58 项声明，更不能把列名当作执行。
最终接线与历史 63 项的独立快照均见 [ci-final](ci-final/README.md)。

## b811 业务负结果及不同阻塞点

clean b811 的 F0 原 30 秒窗口确认 **1/6**，三批 campaign 合计 **3/27**；另按固定
计划起点计算的四秒结果分别是 **0/6、0/27**。未执行到的轮次仍保留在分母内；F0 和三次
campaign 的 native 退出均为 101。原始结果、分母来源和完整失败见
[hosted 总说明](b811-hosted/README.md)、[F0 execution results](b811-hosted/f0/execution-results.json.gz)
与 [campaign results](b811-hosted/campaign/results.json)。

baseline 的末次失败落在独立客户端 packet work/history import 或 admission/commit
的 replay 截止时间；**F0 ROOT 压力阶段则是 0 次 History、0 次客户端 replay**。
后者的合法提交为 15 次尝试、4 次成功 ACK，其余包括 8 次资源暂不可用和 3 次
`FRAME_DEADLINE`，没有确认。不能把根本未执行 replay 的压力臂归因于客户端 replay。
逐页 fetch/replay 时间链与错误保留在 [F0 读回](b811-hosted/f0/report-derived-readback.json.gz)
及 [各 campaign 的读回索引](b811-hosted/README.md)。

这些 hosted 观察的 receiver 与独立 verifier 共用原 0.25 CPU / 2 GiB Host envelope，
各阶段计时包含嵌套关系，不能把 Host、account graph 和 commit 时间相加为新的总耗时。
它们还是受控同机 loopback；本地组件改善不建立该业务失败的因果修复。原资源和范围记录见
[hosted 预算说明](b811-hosted/README.md)。

## 最终默认源码的本地原生验证

本节更新先前 pending 检查点。并入 `69d2e06c` 的 History 失败页诊断后，最终组合的
1,190 项 native 输入 manifest 为 `ccc0b180a702aa012bb24ca0541c9d91592239083c141e3a289f0345acf9df8c`；
Node ELF 为 `5349b31b55279a52dd75b679c5c3a12cb0c0d784dc259098409bb376f056045d`。
各次构建、执行与严格 Clippy 的输入前后检查均一致；[最终原生包](final-native/README.md)
分别保留较早 b811 组合及这次 69d 组合，不能互换 source 身份。

69d 组合实际执行 **253 项不同的原生测试**：Node 指定控制 127 项、M06 完整 library
113 项、SQLite 原 transaction-scope 控制 13 项，全部通过。Node 的 127 项包括追加与
重组 8 项、authenticated storage 90 项、archive store 14 项、TCP/提交后取消 6 项，
以及随后补齐的 workspace 9 项；最后九项逐项经原 exact-test 读取器确认，未重复计算
前 118 项。M06 完整 library 另有 7 项 ignored；Node 被执行模块中有 5 项 ignored。
完整结果、命令、日志、实际 profile、source/ELF 前后哈希均在
[最终原生包](final-native/README.md)。

原 workspace **58 项选择**的 Node 40 项与 M06 18 项均可映射到这次实际通过的测试，
逐项核对及原 56 项保留证明见 [69d 注册与执行读回](ci-final/native-registry-69d2/README.md)；
仅有注册名或静态 YAML 不计作执行。Node 完整 ELF 注册仍是 1,019 项、其中 27 项
ignored；本地这次没有执行全部 Node library，也没有据此宣称完整 Node 或原业务门槛
已通过。Node、M06、SQLite 三个组件的 `--lib --tests --all-features` 严格 Clippy 通过；
原完整 Node、head/实际 merge、四秒/16-worker、F0/campaign 与独立客户端确认要求
继续保留，详见 [现有 CI 接线边界](ci-final/README.md)。

## 沿原计划继续闭合的条件

1. **原四秒、16-worker 业务门槛与 issue #639。** 保持原完整请求、原 Host/CPU 预算、
   独立 replay/确认和完整失败分母，在最终确切 source/head/实际 merge 上取得原 gate
   的结果；30 秒 F0/campaign 或单个网络控制不能替代它。此前四秒压力阶段确认 0/1 的
   记录与 issue 的独立证据义务仍在
   [原 16-attacker 业务记录](../../pon-full-closure-20261104/README.md) 和
   [History/model continuation](../../pon-history-model-read-20261104/README.md)。
2. **4,105-block History。** 原流程要求完整生成、四次续约、损坏拒绝、独立完整同步、
   State 相等及冷 reopen，连同固定 Host、原请求/import/server 截止时间和 job 上限。
   普通分页、索引分页、短 History 控制必须各自标明适用路径。原条件保留于
   [唯一开发计划](../../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)；
   [历史 4,105-block 观察](../../pon-six-axis-continuation-20261104/README.md) 不能直接标成
   本轮完成。
3. **完整状态 O(N) 与 W1 成本。** 下一步仍需在真实入口证明固定 touched set 下，随总状态
   增长的完整验证、恢复、内存和 owner 占用如何变化，并保留 canonical 错误、取消、损坏、
   最终 generation 和 writer 边界。可继续研究稳定已提交读视图及实际 delta 驱动的认证更新，
   但其安全与端到端收益需要新实现及完整成本证据。现有候选没有建立 O(k) 总成本，也没有
   提供最低合法 W1 工作成本或硬件公平性结论。范围依据为
   [M06 HOLD](state/prefix-three-arm/README.md)、[graph HOLD](graph-candidate/README.md) 与
   [W1 剩余义务](../../pon-history-model-read-20261104/README.md)。
4. **独立安全与运行资格。** 密码实现、完整证明关系、Fiat–Shamir/QROM、哈希宽度、
   批量或递归组合、量子工作搜索和预处理优势仍需独立审计；存储证明也必须解决实际
   ownership/freshness 边界。原计划还要求至少三组独立管理员/故障域和预注册至少 72 小时
   WAN 证据，并保留实际 Hepta 安装读回、撤销、恢复与合法 no-update 条件。
   依据见 [PQ 应用授权的未闭合门槛](../../../docs/security/PQ_APPLICATION_AUTHORIZATION_V6.md)、
   [原计划的 PN0–PN5 退出条件](../../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
   及 [存储安全未完成论证](graph-candidate/README.md)。

本轮不授予全链抗量子、公共网络、持续吞吐、模型效果或 activation 资格；这些分别属于上述
原验收条件，并继续保留独立结论。[PQ 边界](../../../docs/security/PQ_APPLICATION_AUTHORIZATION_V6.md)
和 [原计划](../../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md) 没有因本页证据整理而改变。
