# P0 PoN 成本与联合共识：当前源码、条件命题及未闭合义务

日期：2026-11-09 UTC  
审阅源码：**f48840dead56de84fbae9d3b202b6c9ddd4a8291**  
性质：独立、防御性模型审阅；不修改仓库代码、契约、共识规则或任何资格字段。  
结论：**已有若干可严格证明的条件命题与有限证书；实际 W1 全合法策略成本下界、联合 CP/CQ/CG 概率界及生产资格仍为 HOLD。**

整理期间工作区 HEAD 推进至 e4e4a8e049915ba09d9e97444b4709ce8769ce81；最终逐文件检查确认，本报告的 28 个阅证文件仍与上述 f48840de 提交的对应 Git 对象完全相同。这个局部字节等同不推广为两棵完整源码树、构建结果或运行二进制的等同。

## 一、已完成的研究与当前结论

当前集成包含了完整关系定义、固定成功概率成本接口、信用可行性、跨任务成本记账、保留状态势函数、有限联合量子初始状态证书、原生首次回滚切口、带选择滞后的执行映射、完整有限事件覆盖和持久风险登记。不能把这些进展统称为“只有计划”；也不能把有限模型检查成功解释为实际全策略定理。[S1][S6][S9][S10][S13][S14][S15][S16][S17][S18][S19]

两个最重要的未闭合连接是：

1. **资源到工作：**真实允许的经典／量子实现、初始辅助信息和全部后续交互，是否都被同一资源模型及条件尾界覆盖。
2. **工作到共识：**同一已覆盖的工作过程，是否足以控制实际分支选择、完整验证与传输、确认前后的可见性、诚实竞争支、动态参与和所有失败事件。

具体数值仍有明确空缺。MU1 固定概率契约的两类算法、八个规模，共 **16 个成本点**，上下端点全部为 null，初始势上界也为 null。另一份通用包络样例的六个点仍全部为 null，寿命失败预算为 null。两份契约的参数域不同，不能合并成一张已证成本表。[S9][S11][S27]

本报告没有新运行 native 测试、基准、PoN campaign 或量子实验。引用源码中的历史测试数、执行示例或已有论文时，只使用其声明的原作用域；没有把它们记为本轮新执行。源码锚点和逐文件身份见附录与同目录的 final-pon-research-sources.json。

## 二、先分清当前存在的不同对象

| 对象 | 当前可确认的含义 | 尚不能取得的含义 |
|---|---|---|
| 原生 PNW1／W1 | 固定有限域、64 阶矩阵、完整 transcript 与原生 verifier；target 来自实际父分支 | 变量 u 的原生工作协议；最低物理成本；独立均匀中奖定理 |
| 当前原生信用 | 每块按其分支要求的 target 计算整数 required work，一次计入，使用有检查的累积运算 | 名义 FLOP、质量分、证明耗时、磁盘字节或签名数量可增加信用 |
| MU1 研究关系 | 固定理想中奖密度 1/16，u 为 1 至 8，研究信用 16u；实际 hash 为 SHA-256 | 原生 admission 已采用 16u；已证线性／直接和成本 |
| 通用成本包络样例 | u 为 1、4、16，成功阈值 1/2、120000 ms、一轮；均明确是研究假设 | 原生可调参数、实际设备能力、业务时限或 Host SLA |
| C0／C1 分支 schedule | 有限 4096 高度范围的固定 target／锚定整数 ASERT 研究接口 | 已替换当前 Node 的 retarget、时间、activation 或恢复策略 |
| RISC0 当前 proof profile | 已选择并绑定 RISC0 3.0.6、Poseidon2/BabyBear、join-v2 的源码／输入身份 | P3 或 native-PNW1 的预算自动适用；证明运行时间就是挖矿成本下界 |

原生关系、研究 MU1、通用参数样例、C0/C1 schedule 与 RISC0 证明是不同对象。不同对象可以通过经过证明的映射连接，不能仅凭同名 work、同一仓库或同时存在于一个提交中取得同一信用与安全单位。[S1][S2][S5][S9][S10][S11][S23]

历史成本契约冻结的是 b16bae2824e6c8236ef2011fc93a74df3ac7f039 的 1,747 文件清单。当前集成包含该契约，不表示当前树成为该历史 baseline。普通源码检查若拒绝当前树，该拒绝仍有效；显式历史重放只能证明指定历史输入与当前研究代码各自的作用域。[S6]

## 三、“全部合法策略下最小成本”应具有的精确量词

### 3.1 要冻结的实验

沿用已有成本包络的固定成功概率定义，至少固定以下输入：

- F：完整 profile，包括合法任务域、全部可选字段、数值语义、verifier、证明后端、工作身份和版本。
- h：开始时的合法历史／挑战上下文，包括父分支、target、任务资格、可用性窗口及升级状态。
- z₀：策略初始联合状态，包括公开材料、私有预处理、缓存、已经完成但未计入的结果和量子相关性。
- j：经典或量子算法／资源类别；资源换算及硬件能力的允许域必须先固定。
- α、d、H：同一个成功概率门槛、真实截止时间和轮数上限。
- ℒⱼ(F,h,z₀)：允许的全部自适应策略及后续交互；其定义不能以“现有脚本能执行”或“已测策略名录”代替。
- N：一个预先定义、去重的成功事件计数。完整 W1 verifier 接受与原生完整块被接收／可供采用是两个不同事件，必须说明本定理控制哪一个，并为二者提供连接。

定义可以写为：

$$
C_j^*(u;h,z_0,\alpha,d,H)
=
\inf\{B:\exists A\in\mathcal L_j(F,h,z_0),\
R_j^{\mathrm{total}}(A)\le B\ \text{逐路径成立},\
\Pr[N(A;d,H)\ge1]\ge\alpha\}.
$$

这是实验的定义，不是成本定理。若资源只限制期望，应另命名该目标并重做相应尾界；不能把成功条件下的平均成本替换为这里的逐路径总预算。若不存在满足成功标准的策略，数学上可约定该下确界为正无穷；有限表未找到策略并不能证明真实策略域为空。[S10]

### 3.2 下界究竟必须对谁成立

一个可用于跨任务／分支安全的下界，必须具有声明清楚的统一性，例如：

$$
\forall h\in\mathcal H_F,\quad
\forall z_0\in\mathcal Z(h),\quad
\forall A\in\mathcal L_j(F,h,z_0),\quad\forall B\ge0:
\quad
\bigl(R_j^{\mathrm{total}}(A)\le B\ \text{逐路径成立}
\ \land\ \Pr[N\ge1]\ge\alpha\bigr)
\Longrightarrow B\ge L_j(u).
$$

这里下界约束的是同一策略的确定预算 B；失败或立即放弃的单条路径可以实际消耗更少资源。

若 h 来自一个给定分布，应明确改为分布性结论，而不能把平均任务下界用于矿工可主动选择的任务。若只覆盖特定硬件、有限算法族或受限初始状态，应把这些限制写进定理名称和结论。

初始状态的允许域是实质条件。允许任意免费的已准备结果或 oracle 相关辅助信息，却只收费于观察窗口之后，通常不能获得所希望的正“新成本”下界。正确处理是从更早的真实起点记总成本，或提供足够的初始势／状态支配界；窗口、epoch、重启、profile 更新不会自动清空知识或已付款的计算。[S6][S13][S14]

### 3.3 必须纳入策略空间的自由度

现有契约已经列出：合法输入与任务选择、结构化和低秩材料、预处理、缓存、批处理、跨规模共享、公开帮助与外包、失败与放弃、未发布工作、所有竞争分支、跨版本存量、证明／编码选择、量子子域、状态制备、反计算、可变时间和并行搜索、保留相干状态。下一项证据应证明“真实实现可以被此模型模拟并保守收费”，而不是继续只增加一个策略名称。[S7][S9]

还必须明确“合法”的两层含义：

- 最终成功输出必须满足完整关系、原生上下文和去重规则。
- 策略可以在成功之前产生不合格结果、取消工作或请求外部验证；这些过程的资源消耗、公开信息及对诚实服务造成的负担不能被排除出环境模型。

本报告只界定证明范围，不构造任何针对实际系统的利用或复现流程。

### 3.4 实测结果的正确方向

一个已经证明满足同一成功概率、期限和完整预算标准的合法算法，给出最优成本的一个上界。一次成功样本只证明该次路径发生过；它本身不证明算法达到 α、其运行时间分布或其最坏预算。置信区间、截尾规则、独立重复与硬件范围需要另外建立。

有限策略表的最小值，只是表内最小值。未知算法可能更便宜；增加一个合法实现可能降低已知上界，却不会提高下界。一个完整 oracle 电路的构造成本也是该构造的成本，不能反向宣称任何合法实现至少需要这些门、时间或内存。[S6][S10][S15]

## 四、资源指标与全生命周期计量

| 资源维度 | 可以记录或约束什么 | 必须避免的代换 |
|---|---|---|
| CPU／GPU | 实际累计 CPU 核时、GPU 设备时、并行数量、调度归属 | 八核 proving 的墙钟时间当作单核成本或 Host 服务时限 |
| 墙钟与截止时间 | 挑战起点、准备完成、最终父绑定、证明完成、可用、接收和确认时间 | 将并行 worker 墙钟相加当作延迟；将 miner timestamp 当作物理时钟 |
| 内存 | 同时在用的峰值、内存时间积分、缓存冷暖状态 | 相加顺序阶段 RSS 峰值；未测量的内存写成零 |
| I/O／存储／网络 | 实际读写字节、网络字节、保留 byte-seconds、修复、重传 | 把发布量、种子缓存或 hash 身份当作持续可用 |
| 能量／费用 | 实际仪表能耗、账单与付款收据、固定价格假设 | 从 CPU 秒直接推导焦耳或已付款美元 |
| 量子查询 | 完整定义的查询接口、所有参与方、预处理与失败查询 | 从黑盒查询界直接推导物理时间或逻辑门下界 |
| 量子电路 | 制备、反射、正逆计算、测量、候选检查、门数／深度／宽度 | 忽略逆计算、失败候选、跨轮相干性和并行设备 |
| 物理量子机器 | 纠错、工厂、连接、注入、控制、复位、读出、等待期存储错误 | 把某个假设的 T 服务模型当作端到端设备误差界 |

若使用标量 R，应明确可加资源的固定价格。深度、峰值内存和并行墙钟一般是限制条件或独立维度，不能未经定义直接加入一个总数。多资源方案可以使用非负价格向量 κ，并把预算保持为分量上限；换算系数不能根据规模、矿工或观察到的有利结果事后改变。[S6][S10][S13]

生命周期账应覆盖准备、所有尝试、失败、取消、赢家出现后仍在飞行的计算、证明、验证、序列化、传输、状态执行、持久化、恢复、租约与修复。共享准备只付一次；已发生的失败与重组不退款。获胜后才构造的证明按实际发生频率收费，不应无理由加到每次搜索查询，也不能从总成本中删除。[S6][S26]

已有平稳更新成本式“准备费 + 单次完整期望成本／成功概率 + 成功后成本”只适用于它声明的平稳尝试、重试状态和一次性费用模型。自适应停止、任务共享、状态保留、父变化、并行或变时算法需要新的生命周期过程，不能强行代入同一个平均式。[S26]

当前 quantum resource clock 明确将初始化、复位、读出和部分经典控制放在所界定错误预算之外；它同时保留“非端到端机器失败界”“不是最便宜矿工”“没有安全定理”。这些范围声明必须随数值一起保留。[S21]

## 五、初始状态与观察范围的具体义务

需要分别声明并闭合下列内容：

1. **起点：**genesis、某固定 lifetime 起点或随机确认切口；随机切口必须是同一联合过滤中的停止时间。
2. **原点之前的成本：**公开训练不重复向每名矿工收费，但策略可获得的公开输出属于辅助信息；自付准备也不能消失。
3. **经典存量：**缓存、中间结果、私有完整分支、未发布有效证明、正在运行的工作与已计入的身份。
4. **量子存量：**与实际 oracle、帮助者和可访问环境相关的联合密度算子；单个 worker 的局部边缘分布不足以描述全部信息。
5. **外部帮助：**内容、时序、缺席、长度和回复选择可能传递信息；帮助接口的全局范围必须与模型一致。
6. **重启／升级：**保留存量和累计预算；不能以新的 journal、目录、profile 名或 checkpoint 重新取得免费初始状态。
7. **真实性与完整性：**签名、哈希链和源代码 pin 可以绑定声明；真实执行、最新历史及世界范围的完整覆盖各是另一项假设。
8. **参考实验预算：**量子状态转移定理要求同一后续策略在实际状态与独立参考状态上都满足硬预算和输出上限；只在观察到的实际路径上合规不够。[S13][S14][S17][S19]

已有 FJS1 证书逐项检查完整有限 oracle 表及其条件量子状态，并证明在输入支配条件下，参考实验成功界 B 可以转移为：

$$
\Pr_\rho(E)\le \min\{1,\lambda B+\epsilon_*\}.
$$

其前提包括同一个 oracle 独立参考状态、全部初始相关信息、相同后续操作和逐路径预算。它不是实际矿工联合状态的鉴证，也未建立真实 W1 的资源模拟。量子初始信息不能通过把它写成一个普通经典变量、一个 RAM 大小或一个“无缓存”布尔值来消除。[S14]

## 六、DAA、时间和网络必须在同一模型中成立

### 6.1 当前原生语义

源码中的 required work 为：

$$
w(T)=\left\lfloor\frac{2^{256}}{T+1}\right\rfloor,\qquad T>0.
$$

父分支已验证的历史决定 required target；周期调整使用整数运算、边界夹取及 pow limit。时间检查使用最多 11 个祖先的上中位数，以及调用方观察时钟加 future skew。普通 owner 与 growth owner 均保留各自实际 admission、activation 和恢复路径。[S2][S3][S4]

本轮只把这些内容作为模型应精确复现的程序语义。局部夹取、MTP、非零 target 和溢出拒绝都不足以单独推出物理资源公平或联合共识安全。需要证明实际可达历史中的资源到信用转换；不能把 target 比例、整数信用比例、平均查询数和真实时间互换。[S2][S8][S12]

当前 development 配置仍有深度 6 和工作量乘数 6。原生确认同时检查深度与 required-work 差；它没有因此获得“六后继等于某个失败概率”的结论。[S3][S28]

C0/C1 的锚、激活前后时间规则、完整父路径、有限高度范围和 DeferredUntil 分离已经有研究实现。该接口没有激活新的 Node 共识规则，也没有证明应用状态、付款、所有真实父选择和冷恢复都满足一个新安全模型。[S5]

### 6.2 缺少的环境合同

| 项目 | 联合定理至少需要的明确输入 |
|---|---|
| 时间来源 | 真实分析时钟与本地时钟误差／漂移模型；bootstrap、恢复后时钟、未来块 eligibility 和时间单位 |
| 网络同步性 | 同步、部分同步或其他明确定义；分区最长多久，何时开始保证送达；无此条件不得承诺持续 CG |
| 完整发布延迟 Δpub | body、proof、任务材料、应用验证、排队、带宽、重传、时间 eligibility、持久 admission 的整体界及失败概率 |
| 父绑定滞后 Γ | 最终绑定父分支到实际完成的持续时间或可证明取消界；完成后发布时间不能代替 |
| 选择的 score 差 | 诚实矿工与观察节点对仍可采用候选的 score 滞后上界；仅有秒数界还需信用到达／存量界 |
| 参与与资源 | 随时间变化的诚实／对手经典与量子预算、联合策略、离线与新加入模型、任务供给；节点数或名义 FLOP 占比不能代替 |
| 可用性 | 全部 ancestry 与依赖材料可实际取回，含剪枝、租约、续期、相关故障、修复与冷恢复 |
| 计算服务 | 有限验证能力、CPU 争用、恶意／无效输入的成本、背压与取消；不能假设网络到达即完成验证 |
| 初始竞争支 | 所有分析起点的私有／诚实竞争支、在途工作及量子保留进度，不仅是当前观察节点已看到的块 |
| 研究步长 | 一步内总信用上界或相应指数矩；单块信用上限不是每步总突发量上限 |

这些输入来自已有 paid-view-deficit / pacer 接口及生命周期范围，不是新增的网络安全结论。[S13][S15][S16][S17]

### 6.3 已有仿真实际覆盖的范围

honest_rate_model 假设参与者全部诚实、尝试等价且中奖均匀，使用确定性流体路径；它不是非线性随机过程的期望，也没有模拟 fork、排队、网络分区或完整 W1。

quantum_network_sim 是有限种子事件模型：经典 Poisson 到达、特定有限 Grover 试验策略、合成速率、固定接收延迟、完整祖先 bundle；没有带宽或 W1 验证模型，也没有穷尽最优量子策略。其全 nonce 域真实 marked 数仍未知。不能把一次有限事件结果解释成分布无关尾界或真实最廉价矿工。[S20][S22]

## 七、现在可以严格陈述的条件命题

以下均复用现有研究，不声明新的通用安全定理。

### 命题 A：理想经典首次查询的信用账

**输入假设：**每个不同 ticket 输入第一次被求值前，其合法 target 已可预测；在给定过去的条件下，理想 ticket 均匀；挑战绑定、重复信用和工作身份正确。所有相关首次查询，包括预处理、帮助者和委托求值，都计入。

设 M=2²⁵⁶，成功指示为 Iᵢ，信用为 wᵢ=floor(M/(Tᵢ+1))。则：

$$
\mathbb E[w_iI_i\mid\mathcal F_{i-1}]
=\frac{T_i+1}{M}\left\lfloor\frac{M}{T_i+1}\right\rfloor\le1.
$$

因此对有界停止时间 τ，总的候选新信用 Lτ 满足 E[Lτ]≤E[τ]；完整有效新信用被其逐路径支配。若每次信用不超过 W，并固定 r>1，还可用已有指数矩构造得到相应查询尾界。

**不覆盖：**均匀 oracle 的真实性、每次完整 W1 的最低资源、量子查询、诚实网络进度或确认失败概率。尤其不能把“首次查询数量”替换成“本机核时”，也不能排除帮助者后保留原结论。[S12]

### 命题 B：声明成本区间下的信用可行性

**输入假设：**同一成功实验，真实成本已经被 Lⱼ(u)、Uⱼ(u) 覆盖；固定正换算系数 aⱼ 与失真 κ≥1。

要求对区间内所有可能成本都有 Cⱼ/(aⱼκ)≤s(u)≤κCⱼ/aⱼ，等价于：

$$
\max_j\frac{U_j(u)}{a_j\kappa}
\le
\min_j\frac{\kappa L_j(u)}{a_j}.
$$

加入单调性、整数信用和非负批约束时，已有最小候选递推可以精确判定其声明的有限问题。

**不覆盖：**输入包络本身是否为真、表外批次、完整策略模拟、状态尾界和 CP/CQ/CG。区间不可行只否定该鲁棒区间要求；区间太宽时，不能据此宣称真实未知成本不可能兼容。更换同一尺度的公共信用也不能改变经典与量子之间原有的成本比。[S10][S26]

### 命题 C：保留联合状态的资源到信用尾界

**输入假设：**真实允许的每种动作，包括自适应选择、批处理、测量、停止、重启及发布，均有完全正 instrument 分支 Eₒ；分支资源 rₒ 和新信用 wₒ 与原生同一身份账一致。对每个可达公开状态 h 存在 Kₕ≥I，且固定 θ>0、κ≥0 满足：

$$
\sum_o e^{\theta w_o-\kappa\cdot r_o}
\mathcal E_o^*(K_{h_o})\preceq K_h.
$$

令 Vᵢ=Tr(Kₕᵢρᵢ)，则 Mᵢ=exp(θWᵢ−κ·Rᵢ)Vᵢ 为非负超鞅。由已有推导和 Ville 界：

$$
\Pr[\exists n:W_n\ge x,\ R_n\le B]
\le
\min\{1,V_0e^{\kappa\cdot B-\theta x}\}.
$$

其证明由 adjoint 恒等式、条件期望和非负超鞅最大值界组成；不要求独立同分布。随机起点需要同一过滤下的条件初始势或已证上界。参数若事后根据结果选择，需另加 mixture／union／anytime 处理。

**不覆盖：**当前并未为真实 W1 的所有经典／量子动作建立该 operator 证书，未证明 V₀ 的实际上界，未给出物理资源转换和诚实链屏障。有限状态模型里的数千个精确检查不能承担这些前提。密码失败应通过正确 coupling 或适应性的首次失败停止处理，不能条件化于未来“始终没有失败”的事件后继续使用原超鞅。[S13]

### 命题 D：原生首次本地移除的确定性必要条件

**输入假设：**正的原生块信用、实际 strict-greater activation、确认时块 b 在链 C₀ 中、之后第一次本地移除 b；所有权重和事件来自同一有效历史。

令 K=S(C₀)−S(parent(b))。在当前乘数为 6 的配置下 K≥7w(b)。首次替换的竞争支后缀权重严格大于 K；把它分成起点以前库存 I、以后对手新工作 A、以后诚实竞争支 Hₒff，可写成：

$$
I+A+H_{\mathrm{off}}>K_a+G.
$$

其中 Kₐ 是从实际共同祖先起算的确认链权重，G 是确认后保留 b 的本地 score 增量。

**不覆盖：**I、Hₒff 或 G 的概率律，以及跨节点提前观察。该式不是 A≥7w(b) 的无条件结论。跨节点比较可能只得到非严格不等式；较新的 execution certificate 还单独处理传播前窗口、候选选择 score 差和父绑定滞后。六后继仍无已证风险值。[S3][S4][S16][S17][S28]

### 命题 E：已有 later-window 条件桥和寿命风险记账

已有 execution certificate 要求资源过程与原生过程有完全相同的关系、输出身份、credit timing 和权重单位，并有真实 Δpub、Γ、选择 score 差及诚实进度界。若在停止时间 τ 有正、可测的净门槛 d，条件资源超鞅的初始值为 Vτ，且同一原概率律满足：

$$
\kappa R(c)-\theta J_g(c)\le\theta m
$$

对全部分析切口成立，则已有 later-window 结论为：

$$
\Pr[\text{later failure}\mid\mathcal F_\tau]
\le\min\{1,\epsilon_{\mathrm{late}}+V_\tau e^{-\theta(d-m)}\}.
$$

**仍是输入的量：**d、m、Vτ、整个执行范围的 εlate。它们不能从一次良好网络轨迹、单块失败率或事后观察到的较小库存直接填入。early window 必须独立覆盖；没有足够的已送达前缀保证时，该部分的有效上界可能只能为 1。[S17]

风险记账的另一条严格条件结论是：若每次预登记开始时都有真实条件风险界 εᵢ、失败事件完整包含在登记并集中，并且逐路径累计 εᵢ≤εlife，则并集风险≤εlife，不需要独立性。现有 EC1 可检查完整有限记录模型中的事件集合，PNRL1 可持久记账一份本地原生 journal；两者都没有认证全部世界执行或每次真实条件风险。因此账面 spent fraction 不是测得或证明的 native 风险。[S18][S19]

### CP、CQ、CG 仍需分别交付

- **CP：**明确按块数还是权重剪枝，包含跨节点、瞬时移除后恢复、传播前窗口、恢复与不同有效分支；证明每个失败均映射进同一受控尾事件。
- **CG：**在真实分析时间／轮次中建立诚实可用进度下界，包含无任务、离线、排队、分区及验证延迟；全体诚实发现的块之和不是自动可采用的屏障。
- **CQ：**在稳定区段中建立诚实来源的权重占比；如声明块数占比，还需将权重上下限及选择过程纳入额外转换。

现有 work-scale 文档给出这些条件推导接口及权重／块数的区分。它们不能从“平均诚实速率较大”或“小规模仿真未重组”自动得到。[S15][S17]

## 八、联合失败事件必须完整登记

建议沿用现有失败预算和事件覆盖语义，形成一张绑定到候选 F、全寿命 Hlife 和全部观察者／调用者范围的事件表。下列不是新发现的漏洞清单，而是联合定理必须给出概率上界或明确未知的边界。

| 失败类别 | 需要定义的事件与作用域 |
|---|---|
| 关系／证明错误 | 完整关系外输出被接受；具体 verifier、PCS/FRI、Fiat–Shamir、递归和参数绑定失败 |
| 身份／授权错误 | 工作身份或上下文绑定不成立，重复计入，原 owner 权限或声明来源失效 |
| oracle／约化误差 | 实际 hash 与理想模型、查询接口、side information 或模拟损失不满足 |
| 初始状态／成本模型失败 | 未覆盖辅助状态、帮助者、批次、保留进度；资源上限或转换未成立 |
| 诚实进度失败 | 任务／数据不可用、计算或证明未按界完成、有效输出无可用来源 |
| 网络／时间／选择失败 | 完整材料未在 Δpub 内可用，时钟界失效、Γ 失效、score 滞后超界 |
| 状态／恢复失败 | 原子状态、冷恢复、最新 checkpoint／预登记时序或完整历史假设失效 |
| 事件覆盖失败 | 遗漏确认、未成功／取消调用、瞬时移除、另一 owner／机器或历史被删后的尝试 |
| 共识目标失败 | 声明范围内任一 CP、CQ、CG 事件；每个事件的剪枝／窗口／观察时刻必须一致 |
| 生命周期扩张 | 任意起点、重试、升级、递归节点和共享原语查询超出原次数／期限预算 |

如果各项是覆盖实际自适应历史的每次界，或一次性 joint-lifetime 界，则可使用保守 union bound。相关性本身不阻止 union bound；缺少适用上界、次数或事件覆盖会阻止数值闭合。共享 hash 必须使用共享总查询预算，不能每组件、每节点或每次重启都重新使用同一份小预算。未知上界乘以声称的零次也不能抹去未核实义务。[S10][S18][S19]

当前已绑定的 RISC0 profile 继续有 15 个未解义务，实际寿命界为 null、全链资格和激活为 false；本 PoN 文献审阅不改变这些字段。[S23]

## 九、下一步必须交付的证据

| 顺序 | 具体交付 | 可关闭的范围与保留条件 |
|---|---|---|
| R0 | 单一实验定义：F、成功事件、α/d/H、任务选择域、资源单位、真实起点、参与者／观察者、失败事件 | 关闭歧义；不能关闭成本或共识定理 |
| R1 | 同条件合法算法上界记录：完整 source/build/binary、完整尝试分母、失败／截尾／在途尾巴、冷暖与共享账、成功概率论证 | 支持该算法的上界；不构成全算法下界 |
| R2 | 一个实际关系的 all-strategies reduction：完整合法实现到抽象动作／查询的模拟，保守资源损失、所有自由输入与量子联合状态 | 关闭被证明的模型类；未覆盖硬件／动作必须保留范围限制 |
| R3 | 真实允许初始状态和后续帮助的定理接口：付费起点或初始势上界、全局公开帮助、跨版本状态和参考预算 | 关闭相应状态前提；本地日志无法单独认证隐藏对手全状态 |
| R4 | 对同一动作类的多赢家／批处理／跨分支资源到信用尾界，或 operator／Bellman 证书及完备模拟证明 | 提供联合风险所需尾界；单赢家均值不合格 |
| R5 | 同一 native source 的确定性全事件映射：当前 target、时间、fork choice、完整状态、early/later、全部 observers、恢复／瞬时选择 | 关闭程序语义到失败事件的映射；有限轨迹仍不是全局概率律 |
| R6 | 明确且可据证评估的网络／时钟／资源假设，Δpub、Γ、score 差、诚实进度及其整个寿命失败界 | 为 CP/CQ/CG 输入环境界；明确哪些是条件假设、哪些已被部署观测支持 |
| R7 | 独立审阅的联合 CP/CQ/CG 证明，固定参数、选择窗口、量词与寿命组合；保留共享查询和每个未知项 | 只对已声明模型给出条件安全界；不能以资格布尔值代替证明 |
| R8 | 原契约的实际服务与 WAN 验收 | 单独关闭工程门槛；不反向证明最低计算成本 |

R2/R3/R4 是科学闭合的重点。继续增加有限优化样本有助于收紧已知上界和发现模型遗漏，但不能取代全策略模拟证明。如果最终选择以明确的计算难度猜想为前提，应写成“在假设 X、模型 Y 和损失 Z 下的结论”，并保留原生参数映射与量子范围未证部分；不能写成无条件全合法算法下界。

R5 应复用已有 native execution certificate 和 EC1，不另起一套只看成功确认的汇总。R7 应复用已有不退款风险账与停止时间接口，同时补上概率界和世界范围覆盖的前提；本地账的一致性与全世界的风险总体仍不同。[S17][S18][S19]

## 十、服务和真实部署门槛保持原值

原存储网络契约要求至少 **三个独立管理的故障域、至少 72 小时**，并分别观察冷暖、相关故障、churn、续租、修复、重启等。它明确要求原 **4 秒服务契约** 与独立 **30 秒压力 campaign** 分开，报告实际尾延迟、失败数及完整资源账。[S24]

因此，本研究中的 120000 ms 成功窗口、研究 runner 的 60／300 秒 watchdog、八核证明实验、有限数学运行时都不能替代 Host 的 4 秒约束。单机 loopback、多目录、多身份、多个本地进程也不能证明三个独立管理故障域或持续 WAN 服务。

原四秒回放文档保留了未在 4000 ms 内形成独立确认的历史失败；该失败不能被新的数学算术 PASS、换过 watchdog 的 runner 或仅重读日志覆盖。本轮不声称已重跑原服务、完成 72 小时运行或关闭该验收。[S25]

## 十一、本轮原始文献核对与使用边界

| 来源 | 本轮实际核对 | 允许使用的结论 |
|---|---|---|
| Komargodski–Weinstein，ESA 2026 出版版，2026-08-25 | 出版方页面及 17 页 PDF；Def. 3、Remark 4、相关安全假设和 streaming 区分 | 固定成功率／可变输入规模已有先例；最优安全仍明确依赖相关低秩问题的算法难度猜想。不是当前 W1／量子实现下界 |
| 同文 arXiv 2504.09971 | 页面显示最新 v4，2025-11-13 | repo 所引旧 Remark 5.2 需与正式版 Remark 4 分别标注；本轮未证明两个完整版本及实际实现等价 |
| Cojocaru 等，Quantum 7:944 / arXiv 2012.15254v4 | 官方页面、版本元数据及全文 §4.1、Theorem 4.3、§4.4 | 诚实经典参与者、同步轮和固定密度 query 模型下的结果；不能直接填入动态 DAA、诚实量子参与或真实 W1 物理成本 |
| Garay–Kiayias–Shen，Fast Difficulty Adjustment，CRYPTO 2026 | 作者机构的正式摘要；所连 ePrint 2026/1116 PDF 本次返回 403 | 摘要说明采用平行链与近似一致；本轮没有取得可核验全文，不使用其参数／定理替项目资格 |

对 Quantum Backbone 的查询结论，即便采用其完整有限表达式，也必须保留论文模型、N+k 修正及实际 inclusive-target 概率的转换。构造一个 W1 oracle 的门数不提供所需的全算法最低 query 成本。这一方向问题在现有 work-scale 研究中已明确记录。[S15]

原始来源：

- [ESA 2026 出版页面](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ESA.2026.2)
- [ESA 2026 正式 PDF](https://drops.dagstuhl.de/storage/00lipics/lipics-vol388-esa2026/LIPIcs.ESA.2026.2/LIPIcs.ESA.2026.2.pdf)
- [KW arXiv 当前版本元数据](https://arxiv.org/abs/2504.09971)
- [Quantum Backbone 当前版本元数据](https://arxiv.org/abs/2012.15254)
- [Quantum Backbone v4 全文](https://arxiv.org/html/2012.15254v4)
- [Quantum 期刊](https://quantum-journal.org/papers/q-2023-03-09-944/)
- [Fast DAA 官方摘要](https://www.iog.io/papers/fast-difficulty-adjustment-in-proof-of-work-consensus)
- [未成功取得的 Fast DAA 全文](https://eprint.iacr.org/2026/1116.pdf)

## 附录 A：实际文件锚点

所有本地锚点以本报告首部的 source commit 为准。L 后为单一定位行，章节／函数名给出语义入口。伴随 JSON 逐文件核对当前字节与该提交的 Git 对象，并记录 SHA-256 与 Git blob；它证明本次阅读身份，不是编译／加载／执行鉴证。

| 标号 | 本地来源 | 关键入口 |
|---|---|---|
| S1 | [pon_work.rs](sandbox:/workspace/scratch/481716a90d06/chain/trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs) | L21 常量；L423 verify |
| S2 | [consensus.rs](sandbox:/workspace/scratch/481716a90d06/chain/trillionnium/crates/trnm-pon-node/src/consensus.rs) | L141 required_work；L171 parent window；L188 retarget；L216 check_time |
| S3 | [store.rs](sandbox:/workspace/scratch/481716a90d06/chain/trillionnium/crates/trnm-pon-node/src/store.rs) | L4138 expected_target；L6110 activation_selection；L6652 activate_observed；L6763 confirmation limits |
| S4 | [growth/recovery.rs](sandbox:/workspace/scratch/481716a90d06/chain/trillionnium/crates/trnm-pon-node/src/store/growth/recovery.rs) | L171 header 检查；L213 admit_growth；L402 growth activation |
| S5 | [BRANCH_WORK_SCHEDULE_RESEARCH_V1.md](sandbox:/workspace/scratch/481716a90d06/chain/docs/protocol/pon-nakamoto-v1/details/BRANCH_WORK_SCHEDULE_RESEARCH_V1.md) | L3 authority；L29 finite contract；L67 required target |
| S6 | [WORK_COST_CONTRACT_V1.md](sandbox:/workspace/scratch/481716a90d06/chain/docs/protocol/pon-nakamoto-v1/details/WORK_COST_CONTRACT_V1.md) | L3 历史 source；L53 lifecycle；L132 historical replay |
| S7 | [PURE_PON_WORK_SECURITY_MODEL_V1.md](sandbox:/workspace/scratch/481716a90d06/chain/docs/protocol/pon-nakamoto-v1/details/PURE_PON_WORK_SECURITY_MODEL_V1.md) | L54 全部自由度；L77 cost assumptions |
| S8 | [JOINT_CONSENSUS_DAA_AUDIT_20261108.md](sandbox:/workspace/scratch/481716a90d06/chain/docs/protocol/pon-nakamoto-v1/details/JOINT_CONSENSUS_DAA_AUDIT_20261108.md) | L29 native contract；L225 acceptance obligations |
| S9 | [fixed_probability_contract_v1.json](sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/fixed_probability_contract_v1.json) | L2 accounting；L14 cost envelopes；L116 relation；L150 strategy classes；L176 open obligations |
| S10 | [COST_ENVELOPE_CONTRACT_V1.md](sandbox:/workspace/scratch/481716a90d06/chain/docs/protocol/pon-nakamoto-v1/details/COST_ENVELOPE_CONTRACT_V1.md) | L10 success/cost；L46 credit；L152 failure budget；L166 joint proof |
| S11 | [cost-envelope-current-hold-v1.json](sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/contracts/cost-envelope-current-hold-v1.json) | L17 window；L18 null envelopes；L80 null failure budget |
| S12 | [work_query_bound.py](sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/work_query_bound.py) | L1 conditional query accounting；L39 tail |
| S13 | [STATEFUL_RESOURCE_TAIL_V1.md](sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/STATEFUL_RESOURCE_TAIL_V1.md) | L5 operator theorem；L87 remaining actual-relation obligations |
| S14 | [FINITE_JOINT_STATE_CERTIFICATE_V1.md](sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/FINITE_JOINT_STATE_CERTIFICATE_V1.md) | L34 complete input；L105 transfer theorem |
| S15 | [WORK_SCALE_SECURITY_CONTRACT_V1.md](sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/WORK_SCALE_SECURITY_CONTRACT_V1.md) | L243 crossing lemma；L365 CP/CG/CQ interfaces；L462 query bound |
| S16 | [NATIVE_FORK_MAPPING_V1.md](sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/NATIVE_FORK_MAPPING_V1.md) | L42 首次本地移除；L71 诚实竞争支和库存 |
| S17 | [NATIVE_EXECUTION_CERTIFICATE_V1.md](sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/NATIVE_EXECUTION_CERTIFICATE_V1.md) | L234 later-window premises；L353 probability composition |
| S18 | [CERTIFICATE_EVENT_COVERAGE_V1.md](sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/CERTIFICATE_EVENT_COVERAGE_V1.md) | L101 complete target event；L136 composition theorem |
| S19 | [NATIVE_RISK_LEDGER_V1.md](sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/NATIVE_RISK_LEDGER_V1.md) | L126 exhaustive local reconciliation；L206 conditional risk |
| S20 | [quantum_network_sim.py](sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/quantum_network_sim.py) | L36 ASSUMPTIONS |
| S21 | [quantum_resource_clock.py](sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/quantum_resource_clock.py) | L195 certificate；L229 failure-budget scope |
| S22 | [honest_rate_model.py](sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/honest_rate_model.py) | L252 ASSUMPTIONS |
| S23 | [PQ_PROOF_PROFILE_BINDING_V1.md](sandbox:/workspace/scratch/481716a90d06/chain/docs/security/PQ_PROOF_PROFILE_BINDING_V1.md) | Selected identity、remaining qualification；配套 binding manifest |
| S24 | [CELL_STORAGE_NETWORK_ACCEPTANCE_V1.md](sandbox:/workspace/scratch/481716a90d06/chain/docs/development/specs/pon/CELL_STORAGE_NETWORK_ACCEPTANCE_V1.md) | L148 operational gate |
| S25 | [PON_ORIGINAL_FOUR_SECOND_REPLAY_STAGES_20261031.md](sandbox:/workspace/scratch/481716a90d06/chain/docs/security/PON_ORIGINAL_FOUR_SECOND_REPLAY_STAGES_20261031.md) | L9 original baseline；L33 unchanged closure gate |
| S26 | [CLASSICAL_QUANTUM_COST_AUDIT_20261108.md](sandbox:/workspace/scratch/481716a90d06/chain/docs/protocol/pon-nakamoto-v1/details/CLASSICAL_QUANTUM_COST_AUDIT_20261108.md) | L39 submission scope；L89 stationary renewal；L119 joint goal |
| S27 | [FIXED_PROBABILITY_COST_CONTRACT_V1.md](sandbox:/workspace/scratch/481716a90d06/chain/docs/protocol/pon-nakamoto-v1/details/FIXED_PROBABILITY_COST_CONTRACT_V1.md) | L74 credit feasibility；L112 additive potential；L217 next gate |
| S28 | [devnet-v1.json](sandbox:/workspace/scratch/481716a90d06/chain/config/pon/devnet-v1.json) | L8 timing；L14 confirmation settings |

## 附录 B：本报告允许的最终表述

可以表述为：

> 当前固定候选已经具备明确的研究接口和若干严格条件命题；实际全合法策略成本下界与联合共识资格仍未建立。下一项决定性证据是同一关系、同一资源账及同一初始状态下的全策略模拟／尾界，再与真实时间、网络、完整原生事件映射及全寿命失败预算组合。

不能表述为“全部合法策略均已覆盖”“固定 p0 已解决量子公平”“源码哈希相同即真实 daemon 已执行”“风险账支出即链失败率”“研究 watchdog 或 proving 完成即 Host 四秒通过”。这些结论不由本轮读取、已有有限证书或本文条件命题推出。


[S1]: sandbox:/workspace/scratch/481716a90d06/chain/trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs
[S2]: sandbox:/workspace/scratch/481716a90d06/chain/trillionnium/crates/trnm-pon-node/src/consensus.rs
[S3]: sandbox:/workspace/scratch/481716a90d06/chain/trillionnium/crates/trnm-pon-node/src/store.rs
[S4]: sandbox:/workspace/scratch/481716a90d06/chain/trillionnium/crates/trnm-pon-node/src/store/growth/recovery.rs
[S5]: sandbox:/workspace/scratch/481716a90d06/chain/docs/protocol/pon-nakamoto-v1/details/BRANCH_WORK_SCHEDULE_RESEARCH_V1.md
[S6]: sandbox:/workspace/scratch/481716a90d06/chain/docs/protocol/pon-nakamoto-v1/details/WORK_COST_CONTRACT_V1.md
[S7]: sandbox:/workspace/scratch/481716a90d06/chain/docs/protocol/pon-nakamoto-v1/details/PURE_PON_WORK_SECURITY_MODEL_V1.md
[S8]: sandbox:/workspace/scratch/481716a90d06/chain/docs/protocol/pon-nakamoto-v1/details/JOINT_CONSENSUS_DAA_AUDIT_20261108.md
[S9]: sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/fixed_probability_contract_v1.json
[S10]: sandbox:/workspace/scratch/481716a90d06/chain/docs/protocol/pon-nakamoto-v1/details/COST_ENVELOPE_CONTRACT_V1.md
[S11]: sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/contracts/cost-envelope-current-hold-v1.json
[S12]: sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/work_query_bound.py
[S13]: sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/STATEFUL_RESOURCE_TAIL_V1.md
[S14]: sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/FINITE_JOINT_STATE_CERTIFICATE_V1.md
[S15]: sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/WORK_SCALE_SECURITY_CONTRACT_V1.md
[S16]: sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/NATIVE_FORK_MAPPING_V1.md
[S17]: sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/NATIVE_EXECUTION_CERTIFICATE_V1.md
[S18]: sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/CERTIFICATE_EVENT_COVERAGE_V1.md
[S19]: sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/NATIVE_RISK_LEDGER_V1.md
[S20]: sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/quantum_network_sim.py
[S21]: sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/quantum_resource_clock.py
[S22]: sandbox:/workspace/scratch/481716a90d06/chain/formal/pon-nakamoto-v1/honest_rate_model.py
[S23]: sandbox:/workspace/scratch/481716a90d06/chain/docs/security/PQ_PROOF_PROFILE_BINDING_V1.md
[S24]: sandbox:/workspace/scratch/481716a90d06/chain/docs/development/specs/pon/CELL_STORAGE_NETWORK_ACCEPTANCE_V1.md
[S25]: sandbox:/workspace/scratch/481716a90d06/chain/docs/security/PON_ORIGINAL_FOUR_SECOND_REPLAY_STAGES_20261031.md
[S26]: sandbox:/workspace/scratch/481716a90d06/chain/docs/protocol/pon-nakamoto-v1/details/CLASSICAL_QUANTUM_COST_AUDIT_20261108.md
[S27]: sandbox:/workspace/scratch/481716a90d06/chain/docs/protocol/pon-nakamoto-v1/details/FIXED_PROBABILITY_COST_CONTRACT_V1.md
[S28]: sandbox:/workspace/scratch/481716a90d06/chain/config/pon/devnet-v1.json
