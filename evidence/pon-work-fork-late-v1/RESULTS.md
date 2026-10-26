# W1：实际分叉、延迟组装与 SHA 成本模型的本轮结果

本轮完成了 **42 组实际 fork／自适应资源实验、14 组延迟组装实验，以及一个实际执行 36 个非创世区块的 DAA 场景**。三者合计独立重放 **9,195 份完整证明记录**。这是记录执行总数，包含重复、不同反事实作业和明确标注的事后重构，不能解释成 9,195 张不同可计奖票据。

**O01–O07 没有全部关闭。** 本轮发现并排除了一条不能用于实际 SHA-256 的过强归约路线，同时给出一个具有明确适用范围的双向理想密码路径引理。成本安全仍缺实际原语实例化、物理资源转换及票据过程的组合；链安全与 Hepta 产品资格还有各自独立的证据缺口。所有原始关闭标准保留在 [blockers.json](blockers.json)。本轮不管理托管 CI。

## 1. 固定来源与证据入口

正式测量源码：`dac8e6167f19994222f636b0fa19cea8c5426d69`；Git tree：`0dabca690d55793fc62f1c6cb4c0fc9d73c52e48`。本报告属于之后的文档／证据发布，不得以发布提交替换实际测量提交。

两个计划在采样前提交。每套实验使用各自全新、locked/offline 的 Rust 1.95 release 构建；实际原生进程固定在软件可见 CPU 0。环境为同一非独占 x86_64 主机、同一操作者。没有独立 ARM/GPU/专用硬件、能耗或 WAN 带宽测量。软件观察不构成硬件或执行认证。

| 证据 | 内容 |
| --- | --- |
| [summary.json](summary.json) | 来源、外部 pins、总计和接受边界 |
| [fork-jobs.json](fork-jobs.json) | 全部 42 个作业的完整派生指标 |
| [fork-comparisons.json](fork-comparisons.json) | 全部 42 个预注册比较条目，含空比率及负结果 |
| [late-analysis.json](late-analysis.json)、[late-jobs.json](late-jobs.json) | 全部 14 个作业、四个配对、六个控制 |
| [daa-legality.json](daa-legality.json) | 实际构建、原生执行、36 份证明重放及遗漏范围 |
| [validation.json](validation.json)、[independent-reviews.json](independent-reviews.json) | 冻结源码本地验证、416 文件闭包、完整读回及独立软件数值复核 |
| [failure-history.json](failure-history.json) | 实现失败、读回拒绝、环境断连及恢复记录 |
| [blockers.json](blockers.json) | C24–C32 有限子义务与原 O01–O07 的独立状态 |
| [artifact-index.json](artifact-index.json)、[delivery.json](delivery.json) | 完整原始证据包的成员、字节与 SHA-256 |

完整 raw、逐证明读回、原始全量分析、测量二进制和失败记录属于证据包；Git 表格没有用抽样替代全量检查。Fork 比较文件仅去掉了重复嵌入的左右 job 对象，全部 job 指标仍在独立文件中。Late job 文件省略的逐机会身份／命中数组仍保留在完整 readback 中。

## 2. 最重要的新发现：实际 SHA-256 不支持旧的全局 arbitrary-CV 抽象

令固定消息块的 SHA-256 64 轮工作状态变换为可逆映射 \(E_b\)，省略最终 feed-forward。实际压缩为八个 32 位字的逐字模加：

$$
C(h,b)=h\boxplus E_b(h).
$$

逐轮反演可求出

$$
h^*=E_b^{-1}(0^{256}),\qquad C(h^*,b)=h^*.
$$

因此，允许攻击者任取中间状态时，“新压缩结果几乎不会等于旧查询输入”的全局事件界不能直接实例化为实际 SHA-256。这是一条具体反例，不应继续列成一个尚待乐观采纳的假设。

本轮新增 [实际 SHA 控制](../../formal/pon-nakamoto-v1/experiments/w1_sha256_model_boundary.py) 和 [三个测试](../../formal/pon-nakamoto-v1/experiments/test_w1_sha256_model_boundary.py)：标准 IV 多块结果与 `hashlib` 一致，轮变换前后可逆，零块、递增字节块和全 ff 块均具有所构造的 arbitrary-IV 固定点。NIST 托管论文的 Davies–Meyer 讨论也指出了 SHA-256 压缩固定点与随机函数抽象之间的区别；本轮没有把该论文的签名攻击迁移成 W1 攻击。

这没有给出标准 IV、固定 W1 framing、合法矩阵 prefix 和固定填充条件下的低成本有效票据。W1 的完整 trace 是否可走更便宜的合法路径，仍须在这些真实约束下分析。[多实例分析](../../docs/protocol/pon-nakamoto-v1/details/W1_MULTI_INSTANCE_COST_V2.md) 保留了这条区别。

## 3. 修复后的条件理论：允许付费逆查询的 rooted-path 引理

[完整证明](../../docs/protocol/pon-nakamoto-v1/details/W1_ROOTED_CIPHER_PATHS_V1.md) 使用一个明确不同的模型：对每个消息块取独立随机置换 \(P_b\)，允许攻击者付费查询正向和逆向；压缩为 \(h\boxplus P_b(h)\)。固定标准 IV 不由攻击者选择。全部预处理、失败搜索、外部提供信息的生成查询、在线查询和终端检查都有预先固定的上限。

定义 \(Q_P,Q_A\) 为捕获的预处理和在线调用，\(R\) 为完整 digest 引用总上限，\(G,V\) 为覆盖旧退休实例与新实例的有界 opening／额外审计查询，\(C=Q_P+Q_A+V\)。对 \(C\le2^{256}\)，独立审阅后的引理给出

$$
\Pr[2049m>Q_P+Q_A]
\le\delta_{\rm IC},\qquad
\delta_{\rm IC}\le
\min\!\left(1,\frac{2C(C+R)}{2^{256}-C+1}\right).
$$

这里 \(m\) 只计该检查覆盖的不同 challenge 的合法 canonical trace。W1 的全部 challenge 位于第一块，完整固定 trace 有 2,049 个压缩块。证明允许 `inverse(0)` 创建新的孤立自环；`Join` 按正文区分正、逆向查询的规则定义，包含接入旧顶点／引用以及 fresh forward 自环项，但不把新 inverse 自环本身算作失败。无 `Join` 时，标准 IV 可达部分保持向外树，不同首块的路径不合流。“最后一条缺失边”论证说明：合法完整引用的路径必须先于该引用暴露，审计的 \(V\) 不能回填成矿工查询。

显式给定 \(k\) 个相容初表项且其余置换均匀补全时，保留整实例例外 \(H\le k\)。当 \(k+C\le2^{256}\)，除去概率至多 \(\delta_{\rm seed}\) 的 `Join` 事件，有：

$$
2049\max(0,m-H)\le Q_P+Q_A,
\qquad
\delta_{\rm seed}\le
\min\!\left(1,\frac{2C(2k+C+R)}{2^{256}-k-C+1}\right).
$$

不能把初表只价格化为 \(k\) 条普通路径边；它可能预置 rooted cycles 与共享路径。也不能自动沿用空表模型的唯一 ticket 首边解析：初表中的两条首边可汇入同一个 CV，必须明确枚举所有完整引用并计入 \(R\)，或保留显式引用接口。扣除退休的 \(D_0\) 也要求已暴露 canonical 路径，或把对应旧引用纳入同一 \(G,V\) 检查。

这些结论是有限经典理想模型中的查询容量证明。它们没有证明实际 SHA 轮函数相当于该独立置换族，没有把查询换成 CPU／能耗，没有证明事后选出的有效引用是独立 Bernoulli 机会。一般 oracle-dependent advice 只得到保守且可能无用的 \(2^s\delta\) 联合界。上述限制继续属于 O01。

## 4. 实际 fork、付费选择与缓存：42 个作业全部完成

[实验合同](../../docs/protocol/pon-nakamoto-v1/details/W1_FORK_RESOURCE_RESEARCH_V1.md) 使用原始 Node 创建真实同时保留的兄弟分支，不以数组中的父 hash 标签冒充分叉。主观察覆盖 width/depth `(1,1)`、`(4,1)`、`(4,2)`，两种真实开发任务材料、两组固定种子、round-robin／按过去实付 service CPU 选择的策略，以及 lifetime/window 缓存、付费 noise screening 和新增 Strassen arm。

36 个主作业均完成准备、耗尽 **B=128 ms 进程 CPU**，且没有触及 4096 次保护 cap。所有 epoch 共用同一个 B；缓存清理、重建、筛选、丢弃候选和选择开销都继续扣费。准备使用独立 P=1 s 上限，其实际花费单独保留；不能把名义 P+B 当成每个作业都实际消费的同一总预算。Receiver 与 audit 在 miner 封存后执行。

| 计数 | 实际结果 |
| --- | ---: |
| 完整 proof 记录重放 | 5,816 |
| 原研究 proof 记录 | 4,508 |
| 原 setup 赢家记录 | 460 |
| 事后重构记录 | 848，其中 460 为重复赢家，388 为原内部 miss |
| B 内完整研究 proof | 4,474，主作业占 4,468 |
| B 内完整研究赢家，随后原 Node 接纳 | 2,189，主作业占 2,188 |
| 晚完成研究 proof／其中赢家 | 34／18，全部排除出 B 内信用 |
| B 内研究候选 work 之和 | 4,378 |
| 研究候选造成的规范链增长 | **0** |

每个原 Node 内部 miss 的重构明确发生在策略封存之后，不宣称其 proof 字节已在原搜索时留存，也不加新信用。最终活跃 tip 保持原已激活共同基点；接纳兄弟候选不等于连续出块或成熟奖励。

### 配对结果必须保留分流与退化

| 比较 | 注册条目 | 可配对 | 比率与结果 |
| --- | ---: | ---: | --- |
| 算法 arm／general | 20 | 12 | 7 高、5 低；B 内赢家比 **0.769231–1.184615** |
| window／lifetime | 4 | 4 | 四次观察均更高；**1.071429–1.431034** |
| adaptive／round-robin | 14 | 0 | 机会序列分流，全部保留 `null` |
| Strassen／specialized | 4 | 2 | 一低一高：**72/77=0.935065**、**66/54=1.222222**；另外两组为 `null` |

算法 arm 剩余八组也因自适应语义分流而保持空比率。注册分析器的通用拒绝原因同时列举了不完整／封顶／身份不匹配；本次全部主作业完整且未封顶，实际无法配对原因是重叠机会序列不同。不能把这些空值当成零优势，也不能把未配对数量比包装为相同机会流的算法加速。

窗口复用的四次较高观察没有定位出因果机制，不能据此声称重建通常优于长期缓存。原始完整记录保存和 JSON 编码仍占用矿工预算；这些诊断性开销不是协议强制的攻击者成本。范围、算法和策略有限，全部结果都不提供通用 \(\kappa\)。

## 5. 零任务 Strassen：乘法减少，实际收益并非单向

新增 exact finite-field producer 对所有 32,768 个规范 prefix、同一 challenge 下的完整 proof 与原实现保持等价。明确计算图中的标量乘积数由 **152,832 降至 126,864，减少 25,968，即约 16.9912%**。加法、模归约、变换、缓存与内存访问同时增加；等权汇总所有操作时不能直接称为总工作减少。

正式 fork 混合任务实验中，round-robin 的 Strassen arm 相对 general 两组 B 内赢家比为 **72/65=1.107692** 和 **66/60=1.1**。相对已有 specialized 的两组则是一负一正，见上表；自适应组不满足相同语义前缀条件，仍不配对。

另一个必须保留的成本口径负结果：seed5102 的 Strassen／general 虽有 B 内赢家比 66/60=1.1，纳入实际 setup CPU 后，setup＋miner 赢家率比降为 **0.959388128**。该总耗时率与同一名义 B 的产出比回答不同问题，不能只保留有利的一项。

这里测量的是含维护与零任务的注册策略。不能将整体赢家比改称为“零矩阵内核准确加速 16.99%”。这项结果继续说明：参考乘法计数只能描述一个实现，不能当成最快合法算法的下界。

## 6. 延迟组装：真实合法策略，三组增益、一组退化

[延迟组装合同](../../docs/protocol/pon-nakamoto-v1/details/W1_LATE_ASSEMBLY_V1.md) 保持同一个已付费准备的 integer-paired trace 内核。两个模式都先计算 ticket：eager 对每次尝试组装并交付完整 PNW1；deferred 仅在命中后组装并交付完整 PNW1。未中奖 trace 的完整证明在封存后为审计重构，信用为零。这不是“协议已经强制 proof-before-lottery”的实验。

| Seed | B | Eager 的 B 内完整赢家 | Deferred 的 B 内完整赢家 | Deferred／eager |
| --- | ---: | ---: | ---: | ---: |
| 4101 | 128 ms | 77 | 72 | **0.9350649351** |
| 4101 | 512 ms | 275 | 404 | **1.4690909091** |
| 4102 | 128 ms | 84 | 106 | **1.2619047619** |
| 4102 | 512 ms | 285 | 356 | **1.2491228070** |

八个主作业均完成准备并耗尽 B，没有触及 cap。共同原始前缀分别为 154、563、163、563；其中双方都在 B 内完成的共同前缀为 153、562、162、562。共同位置的 statement 与完整 proof 摘要匹配，不能把包含 late 记录的前一组数字全部计为 B 内机会。

全 14 个作业有 **3,319 次研究尝试**，其中 3,310 在 B 内，9 次晚完成。原生最终接纳 1,666 个研究赢家，其中 **1,661** 来自 B 内，另 **5** 个晚完成赢家被排除。3,343 份完整记录由 2,397 份原矿工 proof、922 份事后 miss proof、12 份原 setup 赢家和12份 setup 重构组成。B 内完整 proof 为2,389，不能与 B 内 trace 的3,310混用。

这里“可用”是本地输出管道完成 flush，不是网络交付或持久化落盘。原采集进程结束之后才生成 gzip，经过完整长度／SHA 校验后去掉冗余未压缩文件；压缩成本不属于原矿工 B。四阶段 CPU 总和与最后 native endpoint 还保留总计 184,304 ns 的 done 阶段边界及末尾汇总差额，完整子进程的其余启动、最终序列化、析构与包装器差额也没有被截断或默认为零。

这一合法策略说明，成本规格不能默认失败尝试都承担完整 proof 组装或未来 ZK 生成。实际优势仍取决于工作内核、命中概率、编码与机器状态；本次 128 ms/seed4101 的退化结果保持原样，没有换种子或重跑取优。

## 7. 动态 DAA：已经建立的条件关系与仍缺的链安全

对于实际 inclusive target 和整数计权，令

$$
p(T)=\frac{T+1}{2^{256}},\qquad
w(T)=\left\lfloor\frac{2^{256}}{T+1}\right\rfloor.
$$

若目标在对应回答之前固定、ticket 条件均匀且身份不重复，则任意自适应选择下

$$
\mathbb E[w(T_i)I_i\mid\mathcal F_{i-1}]\le1.
$$

[动态链权文档](../../docs/protocol/pon-nakamoto-v1/details/W1_NATIVE_DAA_RESOURCE_V2.md) 以此处理整个攻击分叉森林、加权初始赢家银行 \(W_0\)、可选停止和独立列出的失败项。只有初始票据数 \(K_0\) 不足以替代 \(W_0\)。有用的 DAA 跳跃界还要覆盖外部提供的祖先，不能只按攻击者自己的查询估计全部链深。

本轮实际原 Node 执行 36 个非创世区块，经历两个真实 retarget 边界。共同路径至高度30的链权135；三个高度31的合法时间戳选择，使高度32的块权重为31、7、2，最终分支链权为173、149、144。整片森林的唯一块工作和是196，最重分支是173。重复提交与较轻分支都没有改变较重 tip。全部36份完整证明及原目标、时间规则重放通过。

原生搜索共170次，内部134次失败的 proof 字节未在当时留存，因此该 DAA 场景仅证明规则合法性和实际执行，不能作为完整失败成本实验。时钟参数、16块 DAA、MTP11及skew120均未放宽。

攻击方的全森林上界没有诚实可见增长下界；也未给出完整数据获取、验证排队及传播过程。实际 common-prefix 违例到所证明过程越界的归约仍缺。提高难度或确认数不能自动补齐这些条件；在线更换工作函数或 DAA 也会产生需要重新证明的新协议过程。

## 8. Hepta：已有产品入口，尚无本轮真实采用闭环

本轮审阅的实际开发候选是 `de133b601e133917cbe1ae03efb3a2ffc06dcd4a`。[来源与资格说明](../../docs/protocol/pon-nakamoto-v1/details/W1_HEPTA_QUALIFICATION_V2.md) 确认普通神经 agentd 入口与受保护 bootstrap 线路已经存在，不能再把“没有神经入口”列为当前事实。

仍缺原有 owner 接纳的合格初始神经父模型、真实 CURRENT 读回、FinalUse issuer 与原 evaluator/selector 权限，以及普通下一任务的实际使用谱系。受控工程机制测试允许公开或已经见过的任务；未见过的未来 holdout 不是这类机制测试的入场条件。未来独立效益声明仍需要相应独立质量与毒化评估。

真实 no-update 周期能证明拒绝、对账和继续使用旧父模型，但不能替代成功跨节点完整 Cell 获取、获准安装、后续使用或三次有益发布。开发费用、模型加载、权重文件数和原生组件 forward 不等于模型进步。本轮没有新建 Hepta 采用权限，也没有把历史真实模型组件记录挪成当前 head 的产品执行证据。

## 9. 本地验证、失败与证据限制

精确测量源上：**152 项直接 Python 测试通过**；开发计划门另外执行 **50+28=78 项测试**。所选 Rust 测试共 **231 次通过**，保留原有 **2 项 ignored**；Node lib 另有689项被所选过滤器排除。这不是全工作区 Rust runtime 测试声明。整个 workspace/all-targets/all-features 的 locked/offline release Clippy `-D warnings`、格式、Cargo metadata、源码 inventory 与文档链接检查通过。

两次全量 reader 在读回前后均验证 **416 个 scripts/formal/config 文件、7,018,051 bytes** 与冻结 Git blob 完全一致。第一、第二次读回各因同一18个旧 ignored Python缓存而被拒绝；这些字节及四份失败回执均保留。旧缓存移出后以历史mtime再次出现，恢复机制未作推断。最终采用独立、仅含tracked文件的冻结 checkout，使用原封不动的reader完成两套全量重放。没有增加 exclude、降低阈值或重采性能。

工具连接曾暂时断开；恢复后原 collector 的完整成功结果、47个步骤和42个压缩作业均可核实，没有替换采样。构建缓存仅在测量二进制已复制且 SHA 核对后清理。原始数据、失败路径、负结果和旧阶段证据保持可追溯。

独立数值复核由同一操作者下的不同审阅代理执行，不冒充独立硬件运营者。所有 ratio 是有限描述性观察，不能用样本极值设定生产 \(\kappa\)。记录接纳量、候选工作量与规范链增长、网络 TPS、奖励成熟和模型效益均有独立含义。

## 10. 取舍与原始 blocker 状态

当前继续保留纯矩阵作为研究方向；本轮没有证据支持宣布实际最低工作成本、生产共识安全或自动模型升级资格已经成立。应继续使用显式的“资源预算—合法不同机会—加权攻击进展—诚实可见增长”接口，避免用参考 FLOPs 或接收方审计成本补缺失下界。

| 原项目 | 状态 | 真正剩余结果 |
| --- | --- | --- |
| O01 | OPEN | 实际 SHA rooted canonical-path 实例化、有效性／lottery 组合、advice、fanout及物理资源转换 |
| O02 | OPEN | 超出本次有限策略与理想查询模型的真实自适应、长期复用、合法结构和最快算法覆盖 |
| O03 | OPEN | 生产资源比、加权初始银行、诚实增长、完整传播、动态参与和所有分叉结算的联合参数 |
| O04 | OPEN | 真实独立 ARM/GPU/可得专用硬件及能耗、内存和网络带宽执行证据 |
| O05 | 条件项，未采用 | 采用混合时须完成基础工作绑定、失败复用、消费唯一性和可组合成本保证 |
| O06 | OPEN | 真正的神经父模型资格、普通任务、质量／毒化、采用／回滚与有益更新闭环 |
| O07 | 条件项，未采用 | 对实际 ZK 方案完成多证明摊销、联合 soundness 与计奖身份绑定 |

安全前提失效时应撤回相应安全／资格声明，并依据既有产品效果权限处理可选不可逆采用操作；共识继续遵守既有有效性与累计工作规则。这里没有实现或授权一个临时共识开关。C24–C32只关闭各自明示的子义务，不改写上表。

## 主要原始资料

- NIST，FIPS180-4，SHA-256轮函数与feed-forward：[官方PDF](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)。
- Perlner、Kelsey、Cooper，压缩固定点与模型边界：[NIST托管论文](https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=935143)。
- Coretti、Dodis、Guo，预处理与non-uniform ideal-cipher分析：[作者完整版本](https://cs.nyu.edu/~dodis/ps/ai-perms.pdf)。
- Carolan、Majenz，2026-09-23，双向压缩置换研究：[论文](https://arxiv.org/html/2609.28469v1)。本文没有把其中量子结果移作本轮经典路径定理。
- Bhaumik、Huang，2026-10-03，keyed oracle与ideal-cipher研究：[论文](https://arxiv.org/html/2610.04674v1)。
- Solomonik、Blaeser，2026-10-19，多矩阵同时运算：[论文](https://arxiv.org/html/2610.26563v1)。其近似或复数域结构不能直接替代本轮精确有限域实现。
- Wong、Ciampi、Sarkar，2026-10-19，PoML：[论文](https://arxiv.org/html/2610.26713v1)。construction-specific独立性与NIZK假设未被当作W1的已有证明。
- Wang等，可变算力下并行链：[论文](https://arxiv.org/html/2105.02927v2)；Garay、Kiayias、Shen，2026快速DAA：[官方记录](https://eprint.iacr.org/2026/1116)。这两者都不是本仓库16块DAA的自动证明。
- Cao、Guo，传播、安全、吞吐量的联合关系：[论文](https://arxiv.org/html/2312.05506v3)；Blake等，2026有界延迟安全模型：[论文](https://arxiv.org/html/2601.09082v1)。固定到达假设没有直接迁移到当前自适应任务／DAA。
