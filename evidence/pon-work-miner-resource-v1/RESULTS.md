# W1 本轮结果与未闭合边界

最终实测源：`42bea72eb74409d72d580dad9bde08c1bce3f8f2`。本文件只报告此轮；第一轮与全部失败材料另行保留。原始hash、逐项结果和门禁见[摘要](summary.json)、[验证](validation.json)和[失败记录](failure-history.json)。

## 1. 实际做了什么

新原生程序顺序执行setup P、miner B、receiver、audit四个阶段。Miner不持有Node/Context/verifier回调，付费选择、噪声筛选、冷准备、完整proof、ticket及全部编码/本地flush计入B；接收验证与事后重放在随后独立阶段。输出完整可用时间晚于B，即使后来接纳，也没有预算内credit。

正常作业P=1s过程CPU、B=128ms过程CPU、保护cap=4096；四算法、两任务、两种准备策略、两个seed、1/4实际历史祖先、选择性/共享取得和付费筛选。它不是任意分叉森林或长期预处理实验。

## 2. 完整记录、预算与原生接纳

| 范围 | research proofs | B内完整proofs | B内中奖且随后接纳 |
| --- | ---: | ---: | ---: |
| 全部58项 | 6136 | 6091 | 2938 |
| 52个主实验 | 6128 | 6083 | 2938 |
| 6个控制 | 8 | 8 | 0 |

全部52个主实验均完成未删失预算观察。6608条完整保留记录=6136条research+192条原始setup winner+280条事后重建；后者含192条重复winner和88条miss，新增credit为零。45条晚proof中的26个晚winner全部排除。各job内部唯一计数的求和，不是跨job/跨轮全局唯一集合。

接纳只说明原Node接受候选：B内candidate work=5876，research canonical chainwork growth=0。实验没有激活这些research候选，没有产生链吞吐量、成熟奖励或当前Hepta模型升级。

## 3. 预注册成对比较

基准arm为`integer-paired-general`，cache比值为hot/cold。32组arm与18组cache均匹配完整付费取得、完整template bank和重叠语义前缀。

| 指标 | 32组arm最小—最大 | 18组cache最小—最大 |
| --- | ---: | ---: |
| 等B完整proof数量比 | 0.752874–1.551724 | 0.792593–1.630435 |
| 等B后续接纳winner数量比 | 0.695652–1.666667 | 0.738462–1.615385 |
| 按实际miner CPU的winner rate比 | 0.691995–1.676409 | 0.738712–1.611364 |
| 按setup+miner CPU的新增winner rate比 | 0.668956–1.795944 | 0.730981–1.618787 |

| arm | winner数高于基准 | 低于基准 |
| --- | ---: | ---: |
| `prepared-generic` | 3 | 5 |
| `structure-paired` | 9 | 7 |
| `structure-specialized` | 6 | 2 |

最终轮arm合计18高14低；cache15高3低。不能沿用第一轮structure-specialized的8/8较高结论：最终轮是6高2低。两轮不同观察分别保留，未挑选有利样本或将观测最大比值当作生产kappa上界。

4组acquisition比较虽均完成预算，但paid history、template bank与语义前缀不匹配，所有成对比率均为null。例：maintenance/hot的选择性取得setup约16.611ms、候选费用0；共享取得约32.640ms、候选费用1546。它们得到不同父状态和输入历史，不能把这两次结果解释为同一实例加速。费用单位与CPU没有相加；候选费用还须与active economy区分。

## 4. 成本口径和控制

| 阶段 | 全58项过程CPU之和（秒） |
| --- | ---: |
| setup | 2.395751420 |
| miner | 6.723005852 |
| receiver | 13.972339592 |
| audit | 8.726445868 |

四阶段合计31.817542732s。Whole-waited CPU减去原生完整过程CPU的有符号残差为3.240857–6.009961ms，未截成零。GNU time的百分之一秒打印与waited微秒端点分别按冻结的20ms、2µs口径对账。

主实验miner原子尾部超支61,240–2,653,428ns；每条晚完成输出仍留在成本中。主miner未归属到命名子阶段的CPU占34.7809946%–65.9139574%，不能把这些余额自动称作日志开销或从分母扣掉。完整诊断编码、本地输出形式也不是协议对最快攻击者强制的工作。

| 控制 | 观察结论 |
| --- | --- |
| P=0、P=1ms | setup不完整；没有research票据 |
| B=0、B=1ns | setup完整、miner因预算停止；没有research票据 |
| hot/cold cap=4 | 各4份完整proof、0 wins；标记censored，不当作完整预算产出 |

四个读回类型问题在冻结前修复：阶段时间整数/布尔别名、费用整数/浮点别名、未消费registration尾部的计数类型、step收据的Python相等别名。它们是审计解析规则问题，不能称为四个链上共识漏洞。合成的停止前缀反例明确保留其parser-fixture身份。

## 5. O01：条件资源归约及真实缺口

定义K0为预处理后已知中奖的剩余计奖能力，U0为已准备而彩票未揭示的机会。提取在第一次揭示lottery答案之前记录候选，不免费调用完整关系验证；所有被丢弃的早猜也进入R，晚开的header/task进入QC/QD的失败项。

在声明的多实例prefix假设和资源保持抽取器下，若 $\ell>h_{correct}$，则

$$M=\left\lfloor\frac{aB+b+d(P^{\prime},S^{\prime},F_0)+h_{candidate}E_{max}}{\ell-h_{correct}}\right\rfloor,\qquad n=\min\{U_0+M,Q_A^{lot}+G\}.$$

通过停止与补齐的耦合可给出 $\Pr[N\ge K_0+Lk]\le\Pr[\operatorname{Binom}(n,p)\ge k]+\epsilon$。坏事件中的输出也须受有限Nmax限制，才能得到包含epsilon*Nmax的期望上界。不能条件于未来“好事件”再假定二项独立。

这是条件归约，未证明实际SHA-256的temporal实例化、任意自适应多实例prefix下界、候选数Emax的物理约束或正净成本间隙。若提取器为输出字节付的成本抵消了所谓输出下界，分母不给有限界；模型返回null。实际L=1的block身份论证也不等于跨分叉经济消费安全或一次矩阵预处理只能产生一次机会。

一个八值trace空间、四次早猜的精确反例给出接受中奖概率1/4；最终最多输出一份，仍不能只用最终G=1计算1/8的早猜失败界。

## 6. O03：资源优势必须接入传播与诚实增长

原生规则精确给出 $w=\lfloor2^{256}/(T+1)\rfloor$。在另行声明的新鲜摘要条件均匀性假设下，目标对应 $p=(T+1)/2^{256}$，且$pw$并非恒为1。本轮实测header只覆盖 $T=2^{255}-1$、w=2；p=1/2是该假设下的目标概率，未被本轮实测证明，也不能认证动态DAA。

在固定目标、独立常数Poisson率、有效传播上界Delta等前提下，令 $a=\lambda_0\kappa q$、$h=\lambda_0(1-q)s$，条件 $a<h/(1+h\Delta)$ 给出

$$\kappa<\frac{(1-q)s}{q[1+\lambda_0(1-q)s\Delta]}.$$

取假设q=1/3、s=1、基准中奖率lambda0=0.1/s，严格kappa ceiling在Delta=0、1、10、20s时分别为2、1.875、1.2、6/7。它们是敏感性示例，非实测网络参数、配置选择或有限确认保证。kappa=1.25、Delta=10s时，即使事件份额5/13仍小于1/2，也已不在该模型可接受区内。

新加权可预测过程把初始bank、不同work和耦合失败epsilon列明。已知落后六个单位后的严格追赶，与等待六次诚实增长期间允许攻击者同时挖矿，是不同条件事件；另一个独立示例固定事件攻击份额r=1/3、零延迟、相同链权，并等待六次诚实增长；其私有竞赛概率为0.155308867776（初始bank=0）及0.366255144033（bank=2）。这些数值不能当作原Node六确认风险或任意攻击上界。

实际16块DAA、传播、reorg与诚实settlement过程仍未耦合到条件模型。假设失效响应仅在原有owner权限内提出撤回安全资格和暂停可选不可逆产品作用；未实现冻结共识、拒绝合法更重链或自动切换PoW。

## 7. O05/O07：后验证明与双重身份边界

若先算有用结果（成本u）并检查概率p的彩票，只给赢家生成成本z的证明，则未截断每次尝试平均成本为 $u+pz$，首次已证明赢家为 $u/p+z$。不能把每次抽签计为u+z。

精确控制B=36、u=z=9、p=1/2：每次先做完整pair的期望计奖为1，只对赢家做proof为9/8。两项工作各自的下界只支持max；没有非重叠资源或direct-sum论证，不能直接相加。

四种proof随机变体、p=1/2，即使最终只按同一credit key计一次，若proof bytes改变lottery input，至少一次中奖概率仍可达15/16。需要分别固定lottery身份和计奖/消费身份，再论证跨父状态消费范围、多证明摊销、失败复用及完整时序。当前未接入实际混合floor或ZK系统。

## 8. O04/O06：真实外部接受条件

本轮只观察一个非独占x86_64环境，未取得ARM/GPU/可得专用硬件、独立操作者、能耗仪表或物理带宽/WAN证据。energy保持null；没有用标签、模拟器或多个agent填补这些要求。

检阅的Hepta PR2559 head为c38e7727，仍draft/open/unmerged，其a7f7d3be是对stacked base的测试合并对象；配对Chain PR323，不是本研究PR337。三代study的历史执行归于旧tuple c636bf37/4ae2c7a8，采用合成算术检索、tabular Q32/HEPTTB01、同一管理员/主机。当前检阅和完整的原权限接口不能升级为三代神经训练、独立组织质量评估、遗忘证明或新服务执行。

关闭O06仍须实际授权需求/数据、确切已安装前代模型、独立未来材料与毒化/回归评估、原选择器采用或拒绝、durable CURRENT和回滚、普通服务实际下一次使用及三代神经谱系证据。有效work、履约费用、质量提升和采用权限分别判定。

## 9. 验证、失败保留和结论

最终源码：396项直接Python测试通过；canonical-plan门禁另外报告78项通过；选定Rust套件217通过，2项原有计时观察仍ignored。格式检查、嵌入式source inventory、394文件reader闭包和workspace/all-targets/all-features严格release Clippy通过。没有声明完整workspace Rust测试或独立硬件执行。

首轮漏清单、reader旧字节码拒绝、未填充的隔离checkout、磁盘不足、无更新stdin的pre-push拒绝以及冻结前对抗PoC均保留。所有修复使用原规则与新source身份，不放宽样本、预算、错误阈值或CI lane。

已关闭的是[blockers.json](blockers.json)中C15–C23明确限定的工程/数学接口子项。O01、O02、O03、O04、O06仍开放；O05、O07为未采用架构的条件义务，仍未标成closed。最终报告head和实际prospective merge的hosted执行另列E01，必须观察真实runner结果。

## 10. 原始研究资料

近期PoML预印本的Definition1使用电路深度，附录F对NIZK计算独立性另列Assumption3；本轮将其作为应显式列出假设的参考，没有把它转换成W1的CPU/能耗或任意多实例摊销下界。条件延迟公式依据Cao–Guo；带权延迟过程还参考Blake等的固定类型Poisson模型。三个文献的前提都需要独立映射到当前协议。

- Wong、Ciampi、Sarkar，2026-10-19：[Proof-of-Machine-Learning-Inference](https://arxiv.org/html/2610.26713v1)。
- Cao、Guo，2024-05-22版本：[Trade-off of Security, Latency, and Throughput of the Nakamoto Consensus](https://arxiv.org/html/2312.05506v3)。
- Blake、Feng、Wang、Yu，2026-01-14：[Rigorous and Generalized Proof of Security of Bitcoin Protocol with Bounded Network Delay](https://arxiv.org/html/2601.09082v1)。
