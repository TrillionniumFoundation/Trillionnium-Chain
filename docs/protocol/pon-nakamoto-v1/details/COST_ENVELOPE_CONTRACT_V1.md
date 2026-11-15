# 固定 p0、可变 u 的成本包络与联合证明接口 v1

Date: 2026-11-08. Status: **research component; production HOLD_NO_GO**.

本组件完成一个可独立复核的有限数学问题：给定明确成本区间、固定的矿工类别换算系数、信用精度、单调规则和联合批处理约束，判断公共信用函数是否存在。它不能把观测到的最快程序当作所有合法程序的成本下界，也不能把可行信用函数当作 CP/CQ/CG、实际 W1 工作、密码学安全、WAN 或 Hepta 迭代的证明。

Implementation: [cost_envelope_contract_v1.py](../../../../formal/pon-nakamoto-v1/cost_envelope_contract_v1.py).
Tests: [test_cost_envelope_contract_v1.py](../../../../formal/pon-nakamoto-v1/test_cost_envelope_contract_v1.py).

## 1. 先固定“成本”和“成功”的同一含义

令 F 为冻结的 work profile，包含输入合法域、全部自由度、数值语义、完整 verifier、成功事件、来源与证明身份。令 u 为 profile 允许的工作量参数，p0 为该 profile 中一个声明的合格彩票事件的中奖概率。链必须独立核实 p0 的实际语义；本组件只把它作为输入假设。

本版本唯一接受的主成功标准是 `total_cost_for_fixed_success_probability_by_deadline`：在同一截止时间与轮数上限内，以至少 alpha 的概率产生一个新鲜、完整 verifier 接受事件所需的总资源预算。alpha、deadline_ms 和 horizon_rounds 必须冻结，所有矿工类别与 u 使用同一标准。概率的作用域固定为 `declared_model_not_statistical_confidence`；有限模型概率不等于一次测量的置信度。

对矿工类别 j 和允许的完整策略 A，写

\[
 C_j(u;\alpha,d,H)=\inf\{B:\exists A,\ R_j(A,u)\le B,\ \Pr[N_F(A,u;d,H)\ge1]\ge\alpha\}.
\]

这只是定义，不是已证明的下界。资源 R_j 必须在合同中选定：例如串行时间、总门数、累积内存时间、能量，或带有固定汇率的向量。量子逻辑门、经典 MAC、美元与墙钟时间不可在没有换算假设的情况下直接相加。

R 是策略在该实验中的总资源上限，不能用条件于成功的平均资源替换。截止时间从冻结挑战的规定起点计算，准备阶段虽然可以发生在此前，其成本仍必须支付。

策略域至少包括预处理、低秩分解、缓存、联合批处理、跨任务共享中间量、nonce bank、失败、放弃、未发布、helper、分支搜索、恢复、跨版本存量、获胜后证明与传输。量子域还包括状态制备、可逆计算、uncomputation、量子存储、并行设备和跨轮相干状态。只计获胜者的运行时间无法定义该总预算。

测得一个完整 verifier 接受的优化策略，只给出相应最优成本的**上界**。有限策略表的最小值是该表的精确最小值；它不是全体合法算法的下界。公开帮助、初始状态和银行存量应明确支付或由单独的状态证书覆盖。

## 2. 固定 p0 有用，但不能单独完成归一化

在理想搜索模型中，对固定常数 alpha 和充足期限，若单次完整查询成本均按 u 线性增长，可以有

\[
 C_C(u)\asymp a_Cu/p_0,\qquad C_Q(u)\asymp a_Qu/\sqrt{p_0}.
\]

固定 p0 可以消除这两个理想表达式中随难度变化的相对放大因子；它不会消除硬件常数差异，也不证明实际单次查询线性、不可摊销或没有更好的算法。

反例：即使 p0 相同，若某个合法优化使 C_C(u)=u、C_Q(u)=sqrt(u)，则二者成本比仍随 u 变化。赢家专属证明开销、内存阈值、不同形状的矩阵、缓存命中和批处理也可能改变成本曲线。

另一个必须检查的自由度是挑选事件。若一个“尝试”实际容许从 m 个独立事件中挑一个赢家，其成功概率是 1-(1-p0)^m，而不是 p0。选择 tile、输入、盐、证明随机数或发布结果发生在什么阶段，必须在冻结 profile 中声明；本组件没有把该独立性假设或完整工作约化证出来。

固定成功概率、调整任务大小已有明确前例：[KW25] Remark 5.2。因此，本项目可主张的新增内容必须来自实际 W1 成本约束、联合优化库、证明和部署证据，不能来自这一设计选择本身。

## 3. 公共信用函数存在性的精确条件

选定每一矿工类别的固定正换算系数 a_j；它不能随着 u 或攻击路径变化。给出成本包络

\[
 L_j(u)\le C_j(u)\le U_j(u),\qquad
 \bar L_j=L_j/a_j,\quad\bar U_j=U_j/a_j.
\]

对容许失真 kappa >= 1，要求同一个公共信用 s(u) 对区间内的每个可能成本均满足

\[
 \bar C_j(u)/\kappa\le s(u)\le\kappa\bar C_j(u).
\]

**区间命题。** 对固定 u，上述鲁棒要求可行，当且仅当

\[
 A(u):=\max_j\bar U_j(u)/\kappa
 \ \le\ B(u):=\min_j\kappa\bar L_j(u).
\]

证明：左侧要求在最大可能成本处最严格，右侧要求在最小可能成本处最严格；它们的交集恰好是 [A(u),B(u)]。

在所有成本精确已知且 kappa=1 时，可行等价于 C_j(u)=a_j s(u)。这要求所有类别的成本曲线在固定尺度下成比例。对任意正 s，在同一 u 下

\[
 \frac{s(u)/C_Q(u)}{s(u)/C_C(u)}=\frac{C_C(u)}{C_Q(u)},
\]

所以更换公共信用函数无法改变这个相对效率比。

对精确已知成本，允许 kappa 失真时，点态条件也可写为 max_j(C_j/a_j) / min_j(C_j/a_j) <= kappa^2。代码直接比较有理数，避免对数、平方根与浮点误差。

区间可能较宽。鲁棒区间不可行表示不存在满足**整个声明区间**的信用函数；它不自动证明真实、未知成本本身不兼容。收紧合法的上下界可能改变结论。

## 4. 单调信用、整数精度与批处理的联合条件

令 u_1<...<u_n。若信用必须非递减，并必须是正精度 g 的整数倍，最小候选可递推为

\[
 s_i^{\min}=\operatorname{ceil}_g\bigl(\max(A(u_i),s_{i-1}^{\min})\bigr),
 \qquad s_0^{\min}=0.
\]

不要求非递减时去掉前一项；`credit_quantum=null` 时去掉向上取整。`credit_quantum={n:1,d:1}` 对应整数信用。

批处理另有一个**独立的期望信用约束**。它不是由固定 alpha 的成本推出的，也不能反过来认证 alpha 成功概率。每个批记录必须使用 `window_semantics=expected_accepted_credit_within_same_window`，并与主合同的 deadline_ms、horizon_rounds 完全相同。

对每个声明的完整批策略 b，令 m_bi>=0 为其在参数 u_i 上的期望新鲜接受数，R_b 为包括准备与失败的总成本上限，rho_b 为另外声明的每单位归一化成本信用上限，j(b) 为类别。额外要求

\[
 \sum_i m_{bi}s_i\le\rho_bR_b/a_{j(b)}.
\]

**联合有限命题。** 声明的区间、单调性、信用精度及全部上述批约束联合可行，当且仅当：每个 s_i^min <= B(u_i)，并且 s^min 通过每个批约束。

证明：递推构造在每个坐标都不大于任何可行信用向量；所有 m_bi 非负，故它也最小化每个批约束左侧。若最小候选违反一条上界，任何更大的向量同样违反。若全部通过，该候选就是可行证据。

例：单独任务成本 C(1)=1、C(2)=2，kappa=1，迫使 s(1)=1、s(2)=2。一个共享准备或缓存的批次若以总成本 2 产生各一个期望接受事件，rho=1 下要求 3<=2，形成精确反证。分别跑两个单任务基准会遗漏它。

本命题覆盖声明的批表，允许其中一行代表重复/混合策略的解析族；若未证明该族覆盖完整策略域，组件仍然是有限模型。本版本不推断未知批次，也不把“已覆盖”的布尔字段当证书。

## 5. 数据格式与证书范围

顶层 schema 必须精确为 `pon.cost-envelope.contract.v1`。所有字段和嵌套对象采用严格允许列表，未知字段与重复 JSON key 均被拒绝。

| 字段 | 强制语义 |
| --- | --- |
| `profile_sha256` | 64 位小写十六进制身份；只是绑定输入，不认证外部 profile |
| `p0` | 0<p0<1 的精确有理数；仍须实际 lottery 语义证明 |
| `success_standard` | 必须等于本文件第 1 节唯一成功标准 |
| `probability_scope` | 必须为 `declared_model_not_statistical_confidence` |
| `success_probability_target` | 0<alpha<=1 的统一成功概率要求 |
| `deadline_ms` / `horizon_rounds` | 正整数期限与轮数上限，所有比较使用同一窗口 |
| `work_levels` | 严格递增、唯一的正整数；布尔值不是整数 |
| `class_scales` | 每类一个固定正有理数 |
| `max_distortion` | 至少 1 的有理数 |
| `envelopes` | 每个类别与 u 的明确上下界及证据；缺行或 null 端点导致 HOLD |
| `nondecreasing` | 必须是真布尔值 |
| `credit_quantum` | null 或正有理数 |
| `batches` | 非负期望接受向量、完整成本和信用上限 |
| `failure_budget` | null 或第 6 节严格预算对象 |

有理数只有 `{"n":整数,"d":正整数}` 一种编码。分数必须已经约分；零只能是 0/1；布尔、浮点、字符串与多余键全部非法。每个整数最多 4096 bit，每个表最多 256 行。这些是离线检验器的计算边界，不是协议性能资格。

`envelopes[].evidence` 仅支持两种形式：

1. `kind=hypothesis` 和非空 `reference`：仅声明待证明成本假设。
2. `kind=finite_catalog`、`schema=pon.cost-envelope.finite-catalog.v1`、完整 `entries` 与 `minimum_strategy_id`。每行必须给出 `strategy_id`、`total_lifecycle_cost`、`success_probability`、`elapsed_ms`、`rounds`。这些是该有限模型定义的精确成功概率、完整预算和执行时窗；不是实际设备的统计估计或单侧置信界。检验器先筛掉未达到 alpha 或超过期限/轮数的策略，再重算其余策略的总成本最小值，核对最小值见证及区间包含关系。**不除以成功概率或接受次数。**这个证书仅证明表内满足同一成功标准的最小值。没有合格策略时见证必须为 null，结果 HOLD。

不能仅因为某真实策略的成功率下界低于 alpha，就断言它一定不合格；其实际成功率可能更高。类似地，宽松时间上界超过期限也不能证明真实策略必然逾期。此类不完整信息应保持 hypothesis/未知，不得写成 exact finite model certificate。被表外提前停止、重试或状态复用改变的策略，也属于尚待覆盖的额外算法。

输入 `certified=true`、`all_algorithms=true` 或任意未支持证据类别均不成立。源码/文献摘要、hash 身份和调用者给出的标签都不能认证真实算法下界。有限表的数值如何来自真实设备、是否遗漏算法和状态仍是外部义务。

结果把 `arithmetic_status`、`evidence_scope` 与 `production_gate` 分开：

- `FEASIBLE`：声明的有限有理数约束有可复核信用见证。
- `INFEASIBLE`：给出最小候选和违反的区间或批上界；不输出伪造的可行见证。
- `HOLD_MISSING_BOUNDS`：缺少任一类别/工作量的上下界。
- `HOLD_NO_QUALIFYING_STRATEGY`：某有限表没有同时满足成功概率、期限与轮数的策略。
- `evidence_scope`：仅可能是 `CONDITIONAL_HYPOTHESES` 或 `DECLARED_FINITE_MODEL_ONLY`。
- `production_gate`：始终 `HOLD_NO_GO`；全合法算法下界、混合共识证明保持 null。

CLI 默认退出码 3，不能误作发布门的成功。只有显式 `--arithmetic-only` 才在有限数学可行时退出 0；非法输入退出 2。该选项仍不改变 production gate。

## 6. 寿命失败预算必须保持未知与单调性

`pon.cost-envelope.failure-budget.v1` 接受一个目标概率和非空失败项列表。每项具有独立 id、精确概率上界或 null、发生次数上限或 null、作用域以及 reference。作用域仅为 `per_invocation` 或 `joint_lifetime`；后者只能计一次。

若所有适用上界确实已证明，联合界为

\[
 \epsilon_{\mathrm{life}}\le\min\left(1,\sum_i n_i\epsilon_i\right).
\]

该 union bound 不需要独立性。对适应性、重试和停止规则，使用的每项定理必须覆盖实际历史，或者提供整个寿命的一次性联合界。共享哈希应按共享的总查询预算进入适用定理，不能每个组件各自重置预算。

检验器同时保留未截断的 `known_union_subtotal`。增加失败、未发布尝试或调用次数不能减小它。任一概率或次数未知时，`total_failure_upper=null`，即使该行声称调用次数为零也不会默默删去未核实义务。小的输入概率只得到 `CONDITIONAL_WITHIN_TARGET`；不会产生“认证安全位数”。

## 7. 从成本包络到混合共识还缺什么

单个 alpha 成功成本与独立的均值批信用约束均不足以推出链安全。攻击者可以把相同均值集中在稀少的大批释放中。必须额外给出覆盖状态保留、批处理及分支的尾界，并定义时间上的适用窗口。本组件不会把期望单位成本冒充同置信度、同期限成本，也不会把有限成本筛选当作尾界。

一种可审核的后续接口是为合法策略状态 Z 构造非负势函数 h，以及固定有理数 r>1、b>=1，使

\[
 M_t=r^{W_t}b^{-R_t}h(Z_t)
\]

在声明的过滤下是非负超鞅。若 h>=h_min>0、资源最多 B、停止时间有界，则得到

\[
 \Pr(W_\tau\ge w)\le
 \min(1,h(Z_0)b^B/(h_{\min}r^w)).
\]

这个表达式说明为何初始 bank、预处理与状态恢复不能免费：它们进入 h(Z_0) 及其付费资格。此处给出的是条件化推导接口；本组件没有为真实 W1 构造这种势函数或验证量子状态转移。

| 联合证明接口 | 必须交付的实际内容 |
| --- | --- |
| 原语与工作约化 | 完整 W1 接受事件、量子/经典查询、成本模型及全部侧信道的约化损失 |
| 输入和初始状态 | 自由输入、全部预处理、helper、bank、私链、跨版本保留状态 |
| 时间与 DAA | 分支相关 anchor、整数舍入、timestamp、升级、权重及冷热恢复的一致语义 |
| CP | 确切剪枝单位、确认窗口、分支可达性和总失败概率 |
| CQ | 在明确块数/信用窗口内的诚实来源占比及资源到信用约化 |
| CG | 有效墙钟/轮时间中的诚实链增长下界，不只平均出块数 |
| 网络与计算时延 | 证明、传输、排队、admission、验证及恶意拒绝占用下的诚实送达界 |
| 寿命组合 | 全部窗口、升级、递归节点、失败、离线查询和共享原语的总预算 |

现有量子 backbone 结果不能直接给这些接口填 PASS。[CGKSW23] 在固定难度、诚实方经典、同步轮模型中给出查询级链搜索尾界及 CP/CQ 分析。其有限界保留 N+k 项；不能把渐近的每查询换算当作本项目的实际门数或资源证书。不同程度的诚实量子参与、可变 u、DAA 和动态网络条件仍须匹配或重新证明。

对 T 个有限轮窗口，若逐个区间有适用尾界，可对至多 T(T+1)/2 个区间再作 union bound。无限寿命不能简单乘一个无限窗口数；应使用 anytime 界、显式续期预算或其他正确组合。协议升级也不自动使攻击者遗忘共享原语的旧查询。

## 8. 最新原始资料及其边界

资料核对日为 2026-11-08。以下仅引用原始论文与作者/出版方存档；未把预印本假设当成已证定理。

| 标签与固定版本 | 本任务可使用的内容 | 不能外推的内容 |
| --- | --- | --- |
| [KW25] | Remark 5.2 固定成功率/可变规模；§5 区分单实例与摊销、streaming 条件 | 最优 MatMul transcript 成本仍依赖算法猜想；不是本项目的量子下界 |
| [BS24] | variable difficulty 与累计 work 在经典/量子成本之间的错配攻击 | 不证明所有混合共识都不可能，也不证明任意 timestamp 修改可防御 |
| [CGKSW23] | 多解 Bernoulli 搜索及 chain-of-PoWs 查询尾界；取代旧 2019 版本 | 非真实 W1 成本约化；非可变难度或完整诚实量子网络证明 |
| [GKL17] | 经典可变难度、参与变化及同步条件的证明框架 | 不能直接替换成量子查询成本或当前 ASERT 实现 |
| [GLPTZ24] | 变难度 ledger 的可组合分析与参与限制 | 不自动覆盖本项目外部付款、模型采用或量子组合 |
| [Ding26] | 有限数值类型中的 noise sensitivity 检查及局部单调条件下的验证算法 | 局部敏感性不排除更快整体算法，不证明完整工作成本 |
| [Pass26] | 明确经济模型中的挖矿、推理与 duplex 均衡 | 经济均衡不提供全合法算法成本下界或本项目正向付款证据 |
| [Basu26] | 一个部署系统中随机矩阵被接受的实测，提示作用来源与用途须独立核实 | 样本不能证明本项目真实执行或全部外部网络都无用 |

References:

- [KW25]: Ilan Komargodski and Omri Weinstein, *Proofs of Useful Work from Arbitrary Matrix Multiplication*, arXiv:2504.09971v4, 2025-11-13. [Fixed HTML](https://arxiv.org/html/2504.09971v4), especially §5, Remark 5.2, §6, Appendix B.
- [BS24]: Bolton Bailey and Or Sattath, *51% Attack via Difficulty Increase with a Small Quantum Miner*, arXiv:2403.08023v2, 2024-09-30. [Fixed HTML](https://arxiv.org/html/2403.08023v2), especially Remarks 1–2 and §4.
- [CGKSW23]: Alexandru Cojocaru, Juan Garay, Aggelos Kiayias, Fang Song, Petros Wallden, *Quantum Multi-Solution Bernoulli Search with Applications to Bitcoin's Post-Quantum Security*, arXiv:2012.15254v4, 2023-03-06; Quantum 7, 944 (2023). [Fixed HTML](https://arxiv.org/html/2012.15254v4), Theorem 3.1, Theorem 4.3, §4.4. This version explicitly supersedes ePrint 2019/1150.
- [GKL17]: Juan A. Garay, Aggelos Kiayias, Nikos Leonardos, *The Bitcoin Backbone Protocol with Chains of Variable Difficulty*, CRYPTO 2017; ePrint 2016/1048, revision dated 2019-08-25. [Archive/version metadata](https://eprint.iacr.org/2016/1048).
- [GLPTZ24]: Juan Garay, Yun Lu, Julien Prat, Brady Testa, Vassilis Zikas, *A Composability Treatment of Bitcoin's Transaction Ledger with Variable Difficulty*, ePrint 2024/1823, received 2024-11-07 and approved 2024-11-08. [Archive/version metadata](https://eprint.iacr.org/2024/1823).
- [Ding26]: Youlong Ding, *On Pearl Blockchain's Proof of Useful Work: Systematization and Flexibility*, arXiv:2610.25347v1, 2026-10-18. [Fixed HTML](https://arxiv.org/html/2610.25347v1).
- [Pass26]: Rafael Pass, *The Economics of Proof-of-Useful-Work*, arXiv:2606.06700v1, 2026-06-04. [Fixed version](https://arxiv.org/abs/2606.06700v1).
- [Basu26]: Abhinaba Basu, *The Usefulness Gap in Proof-of-Useful-Work: An Empirical Study of Pearl's cuPOW Protocol*, arXiv:2606.04819v2, 2026-06-05. [Fixed version](https://arxiv.org/abs/2606.04819v2).

## 9. 本轮验证与剩余交付

两份样例绑定 [work-profile-v1.json](../../../../config/pon/work-profile-v1.json) 的原始字节 SHA-256；检验器自己不读取或认证该外部文件：

- [cost-envelope-current-hold-v1.json](../../../../formal/pon-nakamoto-v1/contracts/cost-envelope-current-hold-v1.json)：当前 W1 的经典与量子上下界均为 null，结果 `HOLD_MISSING_BOUNDS`。u=1/4/16、p0=1/16、alpha=1/2、120000 ms 与一轮窗口均为研究输入假设；不是现行 n=64、rank=8 profile 的可调参数，也不是实际业务期限。`failure_budget=null`，总寿命失败界仍未知。
- [cost-envelope-counterexample-v1.json](../../../../formal/pon-nakamoto-v1/contracts/cost-envelope-counterexample-v1.json)：一个合成有限模型。独立任务的总成本是 1+u，其中准备费用 1 已支付；每次尝试无论成功或失败都支付 u，成功概率 1/2。批处理只共享准备费用，u=1 与 u=4 的总费用为 1+1+4=6，两个接受 bit 的四种结果等概率。单任务约束迫使信用 2 与 5，期望批信用为 7/2，但单独声明的 rho=1/2 上限只有 3，因此 `INFEASIBLE`。这不是实际 W1 或量子硬件性能测量。

本轮测试包含独立枚举：对 3^4 种两类成本表、2 种失真、2 种单调策略与 4 个批上界，遍历所有允许的整数信用组合，与检验器的存在性结论比较。另检查固定 alpha 筛除便宜但低成功率/过期/超轮数策略、同窗口约束、非比例反例、缓存批约束、类尺度、向上取整、伪造有限最小值见证、严格数值/JSON 编码、缺上下界 HOLD、预算单调性与 CLI 默认不放行。

运行：

```bash
bash scripts/project-preflight.sh
cd formal/pon-nakamoto-v1
python -m unittest test_cost_envelope_contract_v1 -v
```

下一层实际闭合需要：将完整 verifier 接受的优化记录绑定到冻结 profile；测量诚实与对抗策略的总成本分布；证明或明确保留全合法算法的下界缺口；证明状态与批处理尾界；在同一时间/DAA/权重与网络条件下建立 CP/CQ/CG；最后按完整寿命组合。有限 checker、单元测试和文献映射不关闭这些义务。

[KW25]: https://arxiv.org/html/2504.09971v4
[BS24]: https://arxiv.org/html/2403.08023v2
[CGKSW23]: https://arxiv.org/html/2012.15254v4
[GKL17]: https://eprint.iacr.org/2016/1048
[GLPTZ24]: https://eprint.iacr.org/2024/1823
[Ding26]: https://arxiv.org/html/2610.25347v1
[Pass26]: https://arxiv.org/abs/2606.06700v1
[Basu26]: https://arxiv.org/abs/2606.04819v2
