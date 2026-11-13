# PoN 四命题独立验收边界

状态：**HOLD / NO-GO**。本文补充唯一开发计划，规定独立证据和拒绝条件；不宣称真实客户、支付完整成本后的净收益或全部合法策略成本下界已经证明。基线为 `e2a02f9271b49f146e70806c8a66e161b5973971`。侧分支、历史运行和后续证据发布均保留各自身份，不能借用为当前整合提交的执行结论。

## 一、四项分别判断

| 命题 | 必需证据 | 现有材料能支持的范围 |
|---|---|---|
| 计算正确 | 指定程序、输入、数值语义、参数及输出关系；精确 proof 或独立重放 | 指定关系的检查；不能证明客户真实性、净效用或不可规避资源成本 |
| 有真实需求 | 委托客户与任务真实、当前预算、数据权利、用途和原期限；明确关联方与控制关系 | 签名、合同绑定和资金回读分别支持其声明或原生状态；不同公钥不证明独立客户 |
| 结果有用 | 未曝光的后续任务、独立评价、强且资源匹配的基线、完整成本、保留能力和实用增益 | 原始行与计划可重算条件化净收益统计；标签、成本和未来人群的真实性须另证 |
| 能抵抗 Sybil | 在固定成功概率、原期限和资源模型下，对所有允许联盟策略成立的界 | 实测实现、有限策略目录、有限模型及查询定理各有范围；不能自动升级为实际全算法下界 |

四栏可以引用同一原件，但各自说明支持的事实。合同散列、有效签名、付款记录和计算 proof 均不能充当其余命题的通用证明。项目预算与关联方需求可以是合法服务，应保留原分类；`external-attested` 仍包含对外部审查者的信任前提。

数据权利须绑定实际输入、权利人、许可操作、接收范围、有效期和撤销视图。合同中的输入与工作引用不等于这份证据；新增材料应采用显式版本，不重解释既有签名域或线格式。

## 二、资金、服务与改进的已有边界

[原生任务证据][native]已从 checked M12 store、Node 实际保留状态及重放的 payment owner 读取资金、交付承诺与历史支付，绑定任务、合同、anchor 和 journal，并区分历史支付与当前分支状态。其 `native_funding_verified` 有这个限定含义。导出 JSON 不是原生导入接口；本次 Python view 不认证其原生来源，也不执行资金回读。完整输出字节、物理成本、独立客户、独立评价者、外部需求及生产权限仍为未验证或 false。共同恢复所有数据库和外部围栏不在本地防回滚保证内。

[需求组合][demand]与[结果观察器][utility]保留各自有界去重范围。两份真实服务合同可以为同一结果支付原合同服务费，多个下游使用也可分别记录；它们不会产生多个新计算结果，也不得使同一改进因 nonce、身份、分支或包装变化而重复计入 bonus。共享准备只计一次，不能消失，也不能按每次使用重复计为不可复用的新计算成本。现有内容标识不证明全球语义等价。

正确完成、但未达到改进条件的评价可依原合同结算基础服务费。`NoUpdate` 本身不证明服务完成：[原评价策略][upgrade]也用它表示 `cancelled`、`timeout`、`execution-failed`。必须保留 reason、事件顺序及原服务 owner 的完成状态；不得把失败、取消和超时重标为成功评价。判断“不采用”可能有决策价值，其净价值仍需独立比较。

## 三、完整成本后的收益

评价先冻结任务、候选、强基线、未来窗口、统计规则、实际意义阈值和成本换算。每个必需基线分别比较：

\[
\Delta J_j=(V_{\mathrm{candidate}}-C_{\mathrm{candidate}})-(V_j-C_j).
\]

成本覆盖训练与数据、调参、准备与缓存驻留、全部失败尝试、评价、推理、通信、可用性与修复、迁移和保留；奖励或补贴不能抵扣资源消耗。不同单位不能直接相加，未知不是零，嵌套计时不能重复累计。累计 wall time 不是并行经过时间，单次峰值的最大值也不是并发总内存。

`quality_gain>0`、实际采用声明或签名的“成本完整”条件，都不单独证明上式为正。计划与摘要不足以重放评价，须有原始 rows、收据、完整动作历史与条件化统计假设。缺失或恢复后的全局历史、真实独立性、成本覆盖和部署人群有效性仍需外部证据。

## 四、联盟、概率和原期限下的成本

[W1][w1]采用模 `4294967291` 的精确整数语义。`PreparedTask::new` 缓存 A、B、AB；同一 A/B 更换 challenge 不创造新的 AB。合法低秩、稀疏、共享 base、缓存与批处理应保留。有限域乘加数、reference FLOPs、SHA 查询/压缩数、硬件时间、能量和账单分别计量，不能互作未经证明的下界。

幸运的首次尝试也可能获胜，故不要求每个中奖事件具有固定搜索成本。令实验 `E` 固定程序、输入权限、初态、原生接受与去重规则、概率空间、资源归属和原始绝对期限 `D`；`A_E` 包含所有允许联盟策略，`W` 为累计已接受信用，`R` 为联盟从生命周期起点支付的资源向量。目标可写成：

\[
\sup_{\pi\in\mathcal A_E}\Pr_E\!\left[
\exists t\le D:\ W_\pi(t)\ge w\ \land\ R_\pi(t)\preceq B
\right]\le\varepsilon_E(B,w,D).
\]

联盟共享初态、预处理、未发布结果、失败、放弃、恢复、跨轮保留及公共帮助必须计入或受定理明确约束；换身份或重组不重置物理成本。诚实验证者的消耗不能自动算成联盟已支付成本。若覆盖量子策略，还须包含状态准备、可逆计算、反计算、测量与保留状态。

[既有成本合同][cost]明确实测合法实现至多提供可达成本上界。有限成功样本未经同一概率与期限合同验证，甚至不是该实验的严格上界。全部策略覆盖、初态/帮助证书、查询模型到实际关系和资源的 reduction、具体哈希假设、量子生命周期及时间/DAA/信用/网络组合仍未闭合。固定时刻界不能替代停止事件界；单次界不能替代 lifetime 界。[V4 观测][v4]的 `1/2` 诊断目标不能填 `1/16` 实验或其 16 个未知成本点。

## 五、只读报告的接受含义

[四命题 view](../../formal/pon-nakamoto-v1/four_propositions_v1.py)通过原 reader 重放 supplied observations，逐栏输出 `MISSING/OBSERVED`、事实和未闭合义务；`proven=false`、`all_algorithm_cost_bound=null`，所有 authority 为 false，无总 PASS。空容器不算实际观察。共同标签相等不认证跨命题语义绑定，源码字节匹配不认证已加载程序或真实执行。

必须拒绝伪 true、摘要与原始重放不符、null 改零，以及不匹配的来源、profile、单位和绑定。不得拼接不同成功事件、target、概率、期限或资源合同来填下界；不得将经典 ROM、有限模型、参考操作数或签名观察升级为实际全算法证明。回归测试通过只说明这些报告规则在测试范围内成立，不改变四项命题、共识信用、奖励、采用或激活资格。

[native]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/e2a02f9271b49f146e70806c8a66e161b5973971/trillionnium/crates/trnm-pon-node/src/store/demand_evidence.rs
[demand]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/e2a02f9271b49f146e70806c8a66e161b5973971/formal/pon-nakamoto-v1/demand_evidence.py
[utility]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/e2a02f9271b49f146e70806c8a66e161b5973971/formal/pon-nakamoto-v1/work_utility.py
[upgrade]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/e2a02f9271b49f146e70806c8a66e161b5973971/formal/pon-nakamoto-v1/upgrade_policy.py
[w1]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/e2a02f9271b49f146e70806c8a66e161b5973971/trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs
[cost]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/e2a02f9271b49f146e70806c8a66e161b5973971/formal/pon-nakamoto-v1/work_profile_contract_v1.py
[v4]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/e2a02f9271b49f146e70806c8a66e161b5973971/docs/research/PON_W1_LIFECYCLE_COST_V4.md
