# 690f 原始 Node 失败与独立 core 收口诊断

这是事后只读提取与源码分析。未修复失败，未修改原源码、refs、PR、CPU/时间预算或宿主 cgroup。此文件不补充声称原始 full Node 已取得缺失的 completion/source-after 回执。

源 commit：690f710c1b6808787996e86aa4c36bd53e1f3939；tree：b9ff2e5c4ca6e465b86cb4b2bd466ad831147899。

## 可核验结果

- 原库目标：1139 passed / 5 failed / 31 ignored，5106.26 s；原 log 第1366行。
- 本报告涵盖原始已完成目标中的8个失败：2个 CPU、3个 NPQ6 transport、3个 host-kernel prerequisite；不是整个后续补跑的 union 总结。
- 单独 recovery core job 1a1b6a40024-12894-58c：5个 gate exit0；32个顶层 harness 实际合计388 passed / 0 failed / 10 ignored。没有计入嵌套 summary、bench、measured 或 filtered 数量。

## 原始失败边界

| 失败 | 原始确定事实 | 尚未确定或不能宣称 |
|---|---|---|
| 大 genesis | authenticated=false；2.718s内原CPU门拒绝；初始2s+refill676.053ms，paid2686.700ms，结算−10.647ms；状态保持原值。 | 未定位唯一昂贵阶段；不代表authenticated=true失败。 |
| history 最后页 | 前6页通过且未早激活；page6在523.714ms后CPU拒绝；原deadline30s；结算+13.430ms。 | 该余额不是reserve时即时额；与25ms termination reserve不足相容，但无法排除前置checkpoint或更早activation检查。 |
| NPQ6 坏签名后恢复 | 原250ms witness exchange报DEADLINE，随后原owner fail-closed，合法帧命中UNAVAILABLE；外层reset。 | 不能称坏签名拒绝后成功恢复；process-local IDs不跨进程对应。 |
| NPQ6 cleanup | 第一次合法send出现FRAME_EOF；child CAS已commit，reply write broken_pipe；child连接338.837ms。 | 父端诊断触达原日志额度；不把第一个NPQ6的唯一原因外推本例。 |
| NPQ6 replay/restart | 第一次合法send FRAME_EOF；cleanup完整、child成功退出、worker已join。 | 未到replay/restart；缺父子phase，不确定唯一内部拒绝点。 |
| architecture comparison | 18/18样本errors=[PUBLIC_HOST_KERNEL_PARENT]、cold_reopen_equal=true、native_state_equal=false；834行要求所有errors为空而失败。 | 没有架构优胜、切换、独立运营方/WAN/生产资格；不从临时report路径重造完整报告。 |
| evaluation sync | 原CLI full-sync测试475行panic PUBLIC_HOST_KERNEL_PARENT。 | 后续host probe不是原测试逐时cgroup快照。 |
| mining service budget | 原CLI exit2，stderr PUBLIC_HOST_KERNEL_PARENT，102行panic。 | 不能把该缺失前置条件用于解释CPU或NPQ6失败。 |

全部3个NPQ6原cleanup均保留primary_error，观察到worker join与child成功退出；不能归类为child崩溃。

## architecture 的原合同与证据

原log1477–1494保留2个scenario × 3个mode × 3次sample的18条失败观测。实际panic为architecture_delivery_compare.rs:834:5，文本 retained native delivery/replay invariants failed。834–838行断言全部cold_reopen_equal为真且errors为空，本轮失败的是后者。

原trial复用相同完整签名packet，每个arm重新付费获取7个proof；普通public history接收调用在636行，errors收集在648行。原业务条件还包括32笔确认、depth6与required-work6、完整native状态相等、pool/submit成功和cold reopen。它不授予BFT finality。全部finite business targets本轮为false。

## 宿主缺失前置条件

独立只读probe 1a1b6ad9539-12894-5d1：uid1000；固定/sys/fs/cgroup/trnmponpublic.slice不存在；实际处于/user.slice/.../app.slice/Hepta job service。host_kernel_parent.rs:363–380要求canonical固定root-owned父域；1239行固定路径。未创建父域，未绕过guard。该probe发生在原运行之后，不重建原每个sample的membership快照。

## core 按目标核算

将stderr的32条Cargo Running记录与stdout的32个完整running-N/result块顺序对齐；每块declared tests均与passed+failed+ignored+measured相等，无nested块。保留example测试harness，含1个真实测试及8个零测试目标；零测试不增加通过数。

| 包 | 目标 | Passed | Failed | Ignored |
|---|---:|---:|---:|---:|
| trnm-mvcc-fee | 25 | 257 | 0 | 8 |
| trnm-protocol | 6 | 75 | 0 | 2 |
| trnm-service-settlement | 1 | 56 | 0 | 0 |
| 合计 | 32 | 388 | 0 | 10 |

逐目标名称、binary、stderr行号、stdout start/summary行号和原summary文本均在core-target-counts-690f-v1.json。5门原日志哈希与source-before/after关系以recovery-core-gates-690f-v1/summary.json为准，不替代原Node失败资格。

## 原始材料 SHA-256

| 材料 | Bytes | SHA-256 |
|---|---:|---|
| original_node_log | 268168 | a71fb8ad30a5b0d796e78ec5fe87671e957586fa9cb0bd89b31fe840207af1f1 |
| core_stdout | 44667 | e02cd5ff3bb86d3f12fa30f522ec7a2180a56604e0fb82eb9da0ff139702fc59 |
| core_stderr | 7091 | 12c04586aa96e2b0ba5c149517b983aad35aed42194ddd9fdb8ff6722be26633 |
| core_gate_summary | 7345 | 7ae138b863ab5c0469fb6a635d43e9ebd5b8f9109daa36e1de52363f719c23d9 |
| kernel_parent_probe | 3358 | 08d6c9ecc57fa98ec17b44674d014c3e4c1768f8da936a17f010c94f9d02bcdc |
| architecture_source | 36607 | a247c14aa7213a93275fc6a6089f37ebb7841da70d0ed08f4a62deb2d34de661 |
| host_kernel_source | 53670 | 6f4cf524831e8af8e23c954764e388d6d167f125c3de0dd19ce235630ce7df7d |

完整绝对路径、所有相关源码SHA和可点击的精确commit源码URL在node-690f-diagnosis-v1.json inputs；结构化架构原观测在architecture-failure-690f-v1.json；原CPU/PQ JSON观测及含换行raw-line SHA在node-failure-observations-690f-v1.json。

原目录本次观察到的文件：complete-node.log, environment.json, source-before.json, started.json, toolchain.json。没有补造原completion/source-after收尾材料。
