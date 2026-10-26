# W1 完整预算原生计奖实验与条件成本模型

## 1. 结论与来源

本轮闭合了上一轮“32次尝试先结束，无法比较相同预算下产出”的有限实验缺口：**30个主预算作业全部到达最终父状态，因预算耗尽停止，没有触发4096次安全上限**。15组producer与12组缓存比较均具有相同付费取得历史、相同最终父状态和完整一致的重叠研究身份前缀。完整读回验证了5,322份保留证明记录。

这没有闭合“实际W1的攻击者最低有效工作成本可信”的全局问题。观察器、接纳和重复检查占完整本地流程的大部分，这些成本不能自动施加给攻击矿工；单机有限观察也不是任意算法的成本下界。`all_project_blockers_closed`、`hardness_accepted`、`production_activation`保持false。

| 身份 | 值 |
| --- | --- |
| 实际测量及验证源码 | `922e4970ea387f09831f34f93168ceb7b18854ee` |
| 实际测量tree | `96b16e5e55e9ddf155d2e56172a40a13871def74` |
| 首次采集但reader拒绝的源码 | `4628f461d8935b0976f6703c7a5c78517bac2f4e` |
| 修正后正式采集UTC | 2026-10-26 00:29:10.795500 至 00:32:42.301245 |
| 注册plan SHA-256 | `951649d5d2b339dc4a13fafe61082534fe07083b21888d82e335d768dc96dcae` |
| 原始manifest SHA-256 | `2cea720f22a7b21f8e047a7e914c044619f2256b38b13fd452c2ad859dcd4be8` |
| 完整readback SHA-256 | `1b11d9a4f869b16b83a69f14c177ce662eccf952b09d115ffd78fb68d1ba37f9` |
| 冻结analysis SHA-256 | `cc8222330c11e8dc3f868ea19a6b39ab8d8d1ebe5a1e67177bcf5ce6e4298a58` |

本目录是后续证据发表提交，不能把发表commit冒称为采集源码。发表时同时澄清contract的原有措辞：保持活跃的是最终父状态，不再激活的是其上接纳的研究候选；执行逻辑及既有测量没有变化。日期标签20261025沿用本轮注册名称，测量和审查时间均明确报告UTC。所有逐作业结果及精确分子/分母见[summary.json](summary.json)，完整原始记录、第一次失败及实际二进制见[交付收据](delivery.json)。

## 2. 完整预算实验具体改变了什么

新增研究模式`budget-final-parent-v2`使用原Node开发权限，真实支付注册、原生辅助挖矿及续期成本。前三个研究父状态各做两次研究尝试并推进，然后固定第四个研究父状态，持续构造和原生接纳候选，直至完整策略CPU预算。最终研究父状态保持活跃；其上的研究候选只接纳，不再激活为新tip。

版本化的v2记录与读回保留原v1生命周期语义。独立`termination_budget_poll`记录真正停止理由，不能因为cap后的清理跨过B，就把cap伪装成预算停止。最多4096次最终父尝试是安全边界；碰到它就标记censored。原子阶段可跨过B，完整成本和最后记录都保留；只有原生接纳完成时刻不晚于B的语义不同研究票据才计入本报告的计奖数。

38个作业包含24个1秒主作业、6个0.5秒主作业，以及8个控制。两个主种子3101/3102在每一个策略/缓存单元内反转producer顺序；短预算种子3103仅作单次边界观察，没有用全局顺序平衡冒充每个单元的平衡。

`integer-paired-general`为通用整数配对实现。`structure-specialized`固定映射maintenance→`maintenance-limb`、zero→`blocked-zero`，只是已知算法比较，不标为全世界最快实现。hot/cold指算术准备复用策略，不代表处理器缓存被保证预热或清空。所有策略都支付同一套双任务取得成本；只取得maintenance等更便宜策略没有被本轮覆盖。

计入的流程包括任务取得、挑战筛选、失败尝试、proof生成、两个完整native验证观察、原生接纳与重复接纳检查、记录和结束清理。完整CPU回答这套本地实验流程的成本；原生接收端和观察器费用必须与矿工独立产出票据所需费用分别建模。不能把验证者做的工作追记为攻击者的最低工作。

## 3. 15组相同预算producer结果

计奖列是预算内完成原生接纳的不同**研究票据**，属于实验计数，不表示实际发币、成熟收益或同一活跃链上的奖励；机会列是预算内完成的不同研究语义机会。每个主作业另有10条原始辅助获胜记录，同一比较对内这10条身份匹配。该作业的全部工作计奖数=研究计奖数+10。精确分析另列实际消耗CPU的产出率及最终父状态计奖比，不能与相同B的比率互换。

| B | 策略 | 缓存 | seed | general 计奖 | specialized 计奖 | specialized/general | general 机会 | specialized 机会 |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1s | maintenance | hot | 3101 | 89 | 85 | 0.955056 | 171 | 167 |
| 1s | maintenance | cold | 3101 | 79 | 89 | 1.126582 | 159 | 170 |
| 1s | zero | cold | 3101 | 89 | 94 | 1.056180 | 159 | 169 |
| 1s | zero | hot | 3101 | 92 | 93 | 1.010870 | 167 | 168 |
| 1s | paid screen | hot | 3101 | 85 | 86 | 1.011765 | 147 | 149 |
| 1s | paid screen | cold | 3101 | 88 | 85 | 0.965909 | 152 | 148 |
| 1s | maintenance | cold | 3102 | 88 | 91 | 1.034091 | 159 | 167 |
| 1s | maintenance | hot | 3102 | 86 | 100 | 1.162791 | 157 | 180 |
| 1s | zero | hot | 3102 | 74 | 52 | 0.702703 | 169 | 127 |
| 1s | zero | cold | 3102 | 83 | 75 | 0.903614 | 196 | 171 |
| 1s | paid screen | cold | 3102 | 83 | 85 | 1.024096 | 157 | 161 |
| 1s | paid screen | hot | 3102 | 81 | 82 | 1.012346 | 151 | 154 |
| 0.5s | maintenance | hot | 3103 | 40 | 43 | 1.075000 | 90 | 94 |
| 0.5s | zero | hot | 3103 | 39 | 39 | 1.000000 | 75 | 73 |
| 0.5s | paid screen | hot | 3103 | 37 | 34 | 0.918919 | 77 | 70 |

专用producer为9组更多、5组更少、1组相同，观察范围**0.7027027–1.1627907**。相同的是zero/hot/3103的39对39，而完成机会为73对75，不能说两者完成工作相同。只有两组主种子、一组短预算种子；未建立期望优势、置信区间、最优算法或全局κ上界。上一轮prepared-generic的CPU率比值与本轮baseline及成本范围不同，不合并排名。

## 4. 12组缓存结果及保留的负结果

| 策略 | producer | seed | hot 计奖 | cold 计奖 | hot/cold |
| --- | --- | --- | ---: | ---: | ---: |
| maintenance | integer-paired-general | 3101 | 89 | 79 | 1.126582 |
| maintenance | structure-specialized | 3101 | 85 | 89 | 0.955056 |
| zero | structure-specialized | 3101 | 93 | 94 | 0.989362 |
| zero | integer-paired-general | 3101 | 92 | 89 | 1.033708 |
| paid screen | integer-paired-general | 3101 | 85 | 88 | 0.965909 |
| paid screen | structure-specialized | 3101 | 86 | 85 | 1.011765 |
| maintenance | integer-paired-general | 3102 | 86 | 88 | 0.977273 |
| maintenance | structure-specialized | 3102 | 100 | 91 | 1.098901 |
| zero | structure-specialized | 3102 | 52 | 75 | 0.693333 |
| zero | integer-paired-general | 3102 | 74 | 83 | 0.891566 |
| paid screen | integer-paired-general | 3102 | 81 | 83 | 0.975904 |
| paid screen | structure-specialized | 3102 | 82 | 85 | 0.964706 |

hot为4组更多、8组更少、没有相同；范围**0.6933333–1.1265823**。不能据此宣布缓存必然有害或有益。这些反事实作业发生在同一非独占宿主，不是独立设备重复实验。

最明显的zero/hot/3102负结果完整保留：专用/通用研究计奖52/74，专用hot/cold为52/75。独立只读事后诊断发现，专用hot首次zero-registration激活与readback累计CPU为186.597828ms，通用hot为2.142636ms；前缀activation累计差184.175711ms，占最终父状态进入时间差197.198082ms的大部分。前100份匹配proof生成CPU分别为34.842828ms和43.645900ms。

这些数字定位了留存记录中额外时间出现的阶段，**没有解释异常根因**；不能归因于blocked-zero算术较慢、硬件争用或内存限流。没有删除该作业、重跑替换样本或重调阈值。对应审查文件是`native-zero3102-posthoc-922e497.json`，其hash列于[validation.json](validation.json)。

## 5. 全部控制、计费与链增长边界

| 控制 | 实际结果 | 可接受解释 |
| --- | --- | --- |
| v2 cap hot | 10份研究proof、5个研究计奖；188.718552ms | `safety-cap-censored`，不是1秒最大产出 |
| v2 cap cold | 10份研究proof、5个研究计奖；153.279580ms | 同上；最终poll仍允许继续 |
| B=0 | 0票据，实际CPU0.078156ms | context前停止；记录观察和收尾成本 |
| B=1ms | 0票据，实际CPU10.250009ms | 未完成，超支9.250009ms；不是1ms硬实时保证 |
| v1 lifecycle hot | 2个研究计奖+8辅助；100.511009ms | 四个原权限控制完整通过 |
| v1 lifecycle cold | 2个研究计奖+8辅助；108.221298ms | 保留原v1完整生命周期 |
| joint AVX2 | 5份proof、3个命中 | 正确性与部分lane控制，attempt cap结束 |
| joint sequential | 5份proof、3个命中 | 同一控制关系；不是新的吞吐量实验 |

30个主预算作业的原子尾部超支范围2.639563–11.578055ms。共有**22次研究接纳晚于B，预算内credit全部为零**。每个主作业有3笔真实开发交易、2933开发费用单位，完成注册前拒绝、材料错配拒绝、续期后旧权限拒绝三项前置控制；耗尽预算后不假装完成撤销。因此v2的完整生命周期标志保持false。两个v1控制单独支付4笔交易、3336单位并完成四项控制。

所有主作业最终活跃高度5、chainwork10。固定最终父状态的兄弟候选不增加活跃链高度；不同反事实作业也不能相加。所以本轮**没有网络TPS或连续链增长吞吐量结论**。

## 6. 成本阶段与可测范围

| 主预算流程阶段 | 占完整策略CPU的观察范围 |
| --- | ---: |
| 研究proof生成 | 4.4090%–6.6292% |
| 两个native完整验证观察 | 16.4331%–24.1471% |
| 原生接纳与重复接纳检查 | 45.4814%–61.7456% |
| paid screen筛选，仅筛选策略 | 4.5874%–5.4250% |

每个范围取自不同作业，不能把各列极值相加成一个不存在的观测。保留native阶段、whole-child和GNU time的独立端点、带符号残差与打印容差；不把残差设零或作无证据因果解释。

宿主为AMD EPYC9V74/x86_64，9个允许逻辑CPU，子作业固定CPU2，CPU非独占，一个操作者。cgroup CPU上限800000/100000、memory.max为8GiB。单条命令最大RSS为11664KiB，不是并发总内存。GPU、能耗、实际内存带宽与网络传输未测，相关值保持null或false。整个构建+采集期间的memory.events计数变化不能定位到某个慢样本，更不能充当硬件证明。

## 7. “关系正确”到“工作昂贵”之间新增的精确结果

详见[成本游戏§9.2–9.3](../../docs/protocol/pon-nakamoto-v1/details/W1_COST_SECURITY_GAME.md#92-actual-compact-trace-prefix-algebra-and-a-charged-model)及[exact-models.json](exact-models.json)。本轮新增可检查的代数和模型边界，没有新增生产工作函数。

当前W1取N=64、噪声rank8、q=2^32−5。字面trace包含32768个前缀word，共131072字节；加domain/challenge为131120字节，普通SHA-256安排含padding共2049个compression block。实际提交proof为49188字节，未逐项携带全部前缀。这是布局和普通实现计数，不是任意算法必须支付的下界。

对任意前缀p，

\[
S_p=P_p+(A_{:p}X_{p:})Y+U(V_{:p}B_{p:})+U(V_{:p}X_{p:})Y.
\]

固定任务可准备P_p，但准备、储存和复用期必须计入P。零任务化为U(V_:p X_p:)Y。若有已提供的秩a、b因子，一个具体经典schedule的标量乘法上界为

\[
nab+mnab+mn^2\min(a,b),\qquad m=n/\mathrm{tile}.
\]

n=64、a=b=tile=8时为299008次；普通扰动矩阵及trace安排为327680次。若原任务rank1加rank8噪声，朴素rank9安排反而为341568次。以上均忽略加法、模约减、hash、编码、准备与传输，都是指定schedule的上界，不能宣称新的最快producer或下界。小维度独立算术控制不是新n64性能测量。

条件提取引理显式使用独立、分域的**理想整消息trace oracle**。准备和在线查询必须完整计入Q_P^tr、Q_A^tr；所有oracle相关advice均来自计费记录；至多G_out个完整输出必须在私有验证前固定；没有免费实时验证反馈；查询显式暴露字节或完整计费流。令q=Q_P^tr+Q_A^tr+G_out，从准备开始的保守坏事件界为

\[
\epsilon_{extract}\le\min\left(1,\frac{G_{out}+q(q-1)/2}{2^\lambda}\right).
\]

第一项是未查询canonical消息的猜中；第二项包括错误消息碰巧与canonical消息同digest的响应碰撞。只有已知准备表完整且无碰撞、无额外未知oracle答案advice时，才能使用u=Q_A^tr+G_out的条件界

\[
\min\left(1,\frac{G_{out}+Q_P^{tr}u+u(u-1)/2}{2^\lambda}\right).
\]

提取器复制/记录字节的成本必须公开；诚实验证者计算的前缀不能追记给攻击者。整消息oracle、理想compression oracle、实际SHA-256是三个模型。单位成本整消息oracle甚至不自动给出按字节读取成本。因此这只补齐条件性digest-to-transcript桥梁的声明，**尚未得到实际W1的Q_A(P,B)、G(P,B)、K0(P)、多实例direct-sum或物理成本下界**。

近期一手文献也要求保留这些边界：[ESA2026的矩阵PoUW论文](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ESA.2026.2)仍把最佳安全性表述为相关低秩系统问题的猜想；[详细v4](https://arxiv.org/html/2504.09971v4)的具体中间量假设不能只靠压缩digest长度直接实例化。[CRYPTO2018](https://eprint.iacr.org/2018/559)的不可摊销结论依赖其特定多项式结构。[2026-10预印本摘要](https://eprint.iacr.org/2026/2326)区分strong和non-amortizing PoW并给出其ROM/低成本验证条件下的障碍；本轮只核对其官方摘要与元数据，未把该定理冒称为对W1的直接证明或否定。

## 8. 完整记录、失败保留与验证

5,322是保留记录数：4392份真实研究proof（4382 parent+10 joint）、336份原Node辅助获胜记录，以及594份事后重建。**594包含336个原winner的重复重现和258个原始target miss**，不是594个miss，更不是额外计奖。原Node内部miss字节仍不是生成时保留，重建明确在结束后进行，不反馈给策略。完整独立重放按实际字节、关系、trace、目标和语义身份检查，后处理并行worker不改变被测成本。

第一版4628采集完成全部38作业，但既有严格reader因`waited_endpoint_allowance_ns`拼写不符要求的`waited_cpu_endpoint_allowance_ns`而拒绝`REGISTERED_OBSERVER_ALLOWANCES`。该批没有获得成功资格，也没有进入本报告比率。修正仅改变该注册字段，并加入collector前置拒绝及负例；38个命令、顺序、预算和cap全部不变，重新冻结922并完整fresh build和采集。两次二进制hash恰好相同，不据此复用旧的失败结果。两套原始数据和构建/reader日志全部保留。

实际922源码的本地验证：277项Python，203项Rust通过，保留2项原有ignore。whole-workspace/all-target/all-feature/release Clippy以-Dwarnings通过，fmt、inventory、repository links、锁定Cargo图和源码闭包检查通过。382个reader传递闭包文件、6161112字节都与Git blob匹配，闭包hash为`0bcd9b8c3f9ae34a98abca92d39e6faa2772b4a242ee9145c5e6c1906d0026dd`。未声称运行整个workspace的所有Rust测试，也未声称硬件、时钟或解释器认证。

独立数字复核重算了全部27对精确比率、时间戳计奖集合和身份前缀；独立原始记录复核检查停止、费用和阶段求和，没有重跑性能或伪称独立State执行。审查过程中只读字段分派错误、首次本地Clippy错误和预冻结顺序纠正均有保留记录。详见[validation.json](validation.json)。

原始完整core压缩包含423个成员，120117151字节，解压成员总1160710484字节；每个成员的大小与SHA-256都已解压核对。最终外层交付还包含readback、analysis、模型输出、所有验证与功能记录、CI原失败和后续观察；具体交付hash见[delivery.json](delivery.json)。

## 9. ARM修复与远端CI边界

旧b33源码在原生ARM head及merge中因研究样例AVX2专用import/enum无条件出现而严格Clippy失败。现已按实际架构限制这些项目，x86_64仍实际测试AVX2取消路径，非x86保留明确不支持的行为；没有allow/expect压掉警告，没有成功stub或静默fallback。

2026-10-26 00:41:54 UTC对922观察：PR337为draft/open，实际preview merge为`d893e0085dd7a697cd7e3150f34acc74c8cb3b9a`，8个workflow为5pending、3queued。diagnostic run40249550764中ARM head121338231848与merge121338231696均runner_id0、steps为空；x64两lane也尚未执行。修复源码不能替代真实ARM执行。

五个pending workflow有旧同PR串行run未结束；diagnostic自身没有concurrency group，所以取消旧run也不能保证解决其runner排队。API未给出runner未分配的底层原因。本轮没有取消、重跑或浏览器操作；工具无取消接口。后续发表commit必须取得自己的实际head/merge检查，不能继承922或旧b33结果。完整时间戳与run/job状态在证据包`922-final-hosted-ci-observation-v1.json`中。

## 10. 剩余blocker与下一步完成标准

[blockers.json](blockers.json)保留既有七个全局未决项，新增有限范围关闭项，不重命名未知问题以制造“全部关闭”。

| 全局项 | 仍缺的结果 | 当前结论 |
| --- | --- | --- |
| O01 资源→有效机会 | 实际W1/SHA-256、预处理、选择、批量的适用困难性假设/归约，绑定Q_A、G、K0、fanout与资源 | 条件提取和有限实验都不能替代 |
| O02 任意自适应策略 | 任意合法结构、长期复用、并行父森林、真正最快已知合法算法和可选取得策略 | 两开发任务及固定筛选策略覆盖不足 |
| O03 生产κ及链安全 | 明确可接受优势、参数、传播/DAA/重组/诚实增长与假设失效处理 | 本轮观察最大值不是安全上界 |
| O04 独立硬件物理成本 | 真实ARM/GPU/可得专用设备、独立操作者、joules/带宽/通信 | 单一非独占x64，远端ARM未执行 |
| O05 混合floor | 若采用：绑定、失败复用、消费唯一性、物理floor及成本可加性 | 条件对照，未启用 |
| O06 Hepta效用和权限 | 真实任务、外生需求、独立质量/毒化评估、采用和回滚证据 | 开发费用与工作正确不等于模型进步 |
| O07 ZK后扩增 | 若采用：任务/父状态/计奖身份绑定、健全性和多证明摊销全流程 | 未部署ZK，不能先授资格 |

本轮的后续决策是保留纯矩阵PoN主线，先把**矿工独立生成成本、诚实接收端成本、事后审计成本**明确拆开，再注册新的全流程攻击矩阵；不从当前阶段占比倒推出未经实测的矿工速度。必须保留实际生产关系，不把低成本拒绝路径伪造比率混成有效票据优势。所有已有原始失败、资格和模型采用规则保持原意。

在O01–O04得到相应证据前，当前W1不能被本轮报告授予可信最低工作成本或Hepta最终安全层资格。O05/O07仅在采纳对应架构时适用。真正的研究突破、真实硬件和有权限的远端执行是这些项的完成条件，继续增加同机PASS数量无法替代它们。
