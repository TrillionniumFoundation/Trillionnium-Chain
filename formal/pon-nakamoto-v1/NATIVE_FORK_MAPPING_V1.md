# 原生首次回滚切口与有条件的全分支共同进度屏障

日期：2026-11-07（UTC）
状态：确定性局部归约已证明；同步／父选择时效前提下的共同屏障引理已证明；一般原生共同前缀概率界与六后继风险资格仍 OPEN / HOLD。

这份说明把前轮 WORK_SCALE_SECURITY_CONTRACT_V1.md 第 5.1 节的空接口向前推进了一步。它没有把前轮抽象 35、43、46、228 权重间隙解释成原生确认数。这里的 pacer 思路属于已有 Nakamoto 分析工具；本说明的价值是明确原生严格比较、实际六后继阈值、诚实竞争支、残留工作和完整验证延迟的接线条件，不主张一个新的通用共识定理。

## 1. 核对的源码与协议事实

成功读取并保存在 research_inputs/native_mapping/ 的开发候选规范/源码固定于：
adebe0bd78e6e1bdb55a599179ffe2313997170e
PR #688，分支 fix/chain-six-axis-performance-20261103。

文件：
- docs/protocol/pon-nakamoto-v1/CONSENSUS.md
- trillionnium/crates/trnm-pon-node/src/consensus.rs
- docs/protocol/pon-nakamoto-v1/details/PURE_PON_WORK_SECURITY_MODEL_V1.md
- docs/protocol/pon-nakamoto-v1/details/WORK_COST_DAA_BOUNDARIES.md
- docs/protocol/pon-nakamoto-v1/details/STATE_RECOVERY.md
- config/pon/devnet-v1.json

另外只读核对了已有 PR #774 本地 checkout：
the prior read-only PR #774 checkout
HEAD 2789e9d9999920d858c1b65d3bff29122079cb4e
其中 store.rs 的 activate_with_fault_and_progress、confirm_batch 路径及 growth/recovery.rs 的比较与上述规范一致。没有修改该共享 checkout。

原生事实：
1. 每块权重 w(b)=floor(2^256/(T_b+1))，T_b 是该分支要求的 target；累积权重由验证过的 ancestry 重算。
2. 原生 activate 在 candidate.work <= incumbent.work 时保留 incumbent，因此本地替换是严格 >。
3. confirmation 的 depth=tip.height-b.height，work_delta=S(tip)-S(b)，threshold=6*w(b)；两项均满足才 confirmed。
4. 六后继指 b 后面六块，work_delta 不含 b；不是把 b 算在内的六块。
5. 正式状态没有确定性 finality；更重有效链不因六块、成熟期、剪枝深度而拒绝。
6. header-only 不能成为可执行 active tip；完整 ancestry、body、work proof、应用依赖和状态根需验证。
7. 时间规则是 branch-local MTP11，加 protected now 的未来偏差检查。devnet 的 future_skew=120 秒、间隔16、目标10秒、clamp4；这些不是全局真实采矿时钟或通过安全资格的生产参数。
8. 当前原生工作权重没有可变 u 字段。固定 p0 / 可变 u 是另一个未激活工作关系的研究候选。代码中的确认门仍是 6*required_work(T)，不是 6*u*required_work(T)。若未来引入 u 加权而不另行修改确认策略，本文原生 u=1 的 7w(b) 下界不会自动继续成立；届时只能从实际实现重新推导 w(b)+6*required_work(T_b) 等门槛。

源码链接：
https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/adebe0bd78e6e1bdb55a599179ffe2313997170e/docs/protocol/pon-nakamoto-v1/CONSENSUS.md
https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/adebe0bd78e6e1bdb55a599179ffe2313997170e/trillionnium/crates/trnm-pon-node/src/consensus.rs
https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/adebe0bd78e6e1bdb55a599179ffe2313997170e/config/pon/devnet-v1.json

## 2. 引理 A：原生本地首次移除，严格切口不等式

用 S(C) 表示链尖端 C 的累积权重，W(C\\a)=S(C)-S(a) 表示去掉共同祖先 a 的前缀后剩余权重。所有非 genesis 块权重为正。

在真实分析时间 tau，某个诚实节点观察 C0，包含块 b，并返回原生 confirmed。令

K_b = S(C0)-S(parent(b))
    = w(b) + [S(C0)-S(b)] >= 7 w(b).

原生两道门是

height(C0)-height(b) >= 6,
S(C0)-S(b) >= 6 w(b).

这不是“任意七块”，也不是已证明的七单位风险间隙。K_b 是从 b 的父节点到确认尖端的实际权重；可大于 7w(b)。

设同一节点以后第一次移除 b 的 activation，把包含 b 的旧尖端 P 换成不包含 b 的 D。令 a=LCA(P,D)。则

W(D\\a) > W(P\\a) >= W(C0\\a) >= K_b >= 7w(b).       (A1)

证明：
- 本地 fork choice 只采用严格更大 score，因此 S(D)>S(P)。
- 从 tau 到第一次移除 b，任何中间 activation 都保留 b，且 score 单调不减；故 S(P)>=S(C0)。
- a 是 b 的严格祖先，因 P 含 b、D 不含 b；因此 a 也在 C0 中。
- 从前三个 score 同减 S(a)，得到前两项；a 不晚于 parent(b)，得到第三项。
- 最后一步直接使用原生 work-delta 门。证毕。

这里不要求 C0 是 P 的前缀。中间允许“保留 b，但替换 b 后继”的重组。因此简单地把旧六个后继视为永远留在 P 上是不必要、也可能错误的证明前提。

### 2.1 必须保留诚实竞争支与库存

把 D\\a 的块按截止 tau 分类：
I = tau 前已准备好的竞争支权重；
A = tau 后新准备好的攻击者权重；
H_off = tau 后新准备好的诚实竞争支权重。
令 G=S(P)-S(C0)>=0，K_a=S(C0)-S(a)>=K_b。

则精确恒等式与必要不等式为

I + A + H_off = W(D\\a) > K_a + G,
A > K_a + G - I - H_off.                              (A2)

整数权重下可写成 A >= K_a+G-I-H_off+1。攻击者新工作 A 可能为零。忽略 H_off 或把 I 随观察窗口重置为零，都能把正确的切口不等式变成错误的安全定理。

本引理只识别必要的分叉见证。它没有证明 H_off 小、I 小、G 大，也没有给 A 的概率律。

与其他报告字段的对应必须明确：本独立代码的 inventory_weight 包含所有 tau 前的竞争支块（攻击者和诚实均含），new_honest_offbranch_weight 只含 tau 后诚实块。若主报告改用 B_tau=仅 tau 前攻击者块、H_comp=竞争支的全部诚实块，则是另一种等价分区：
I=I_A_pre+I_H_pre，H_comp=I_H_pre+H_off，B_tau=I_A_pre，故 I+A+H_off=B_tau+A+H_comp。
不能把两个分区里同名的库存或诚实字段逐项当成相同数据。

### 2.2 跨节点只可用非严格比较

若早先 C0 已完整可用并验证到另一个诚实节点 v，且 v 已执行符合规范的最大 score 选择，而其当前链 D 不含 b，则

S(D) >= S(C0),  W(D\\a) >= W(C0\\a) >= K_b.          (A3)

可以取等号：两个节点先分别采用等重分支，后来都见到另一分支，仍各自保留 incumbent。不能把本地首次替换的严格 > 套在跨节点共同前缀比较上。

若没有完整可用性／选择前提，甚至 (A3) 都不成立。一个节点已见到七块，另一个节点暂时只见到 genesis，就能发生跨节点 prefix disagreement，后者链的 score 更小，并不需要攻击者超越任何已知链。

## 3. 引理 B：共同使用一个全分支攻击过程的有条件 pacer 屏障

这一引理证明一个具体的充分映射，不假定“六后继所以所有诚实节点都已同意 b”，也不把这种结论藏进 good event。它的额外前提是明确的操作合同，尚未在原生部署上定量认证。

### 3.1 两个不同的时间界

Delta_pub：
本引理要求的服务对象是确认锚链 C0，以及纳入诚实 pacer 的完整 ready 产物。从这些对象可由一个诚实 provider 提供，到本引理所覆盖的所有诚实观察／执行选链节点及诚实矿工可用其完整 ancestry/body/proof/应用依赖、完成验证、满足时间资格并可据此作选链决策的上界，记为 Delta_pub。这个接收集合必须包含最初确认节点和每个被比较的失败节点；只送到矿工而没有送到被观察节点，不够支持后文的 score 比较。该界包含传输、排队、重放验证、状态执行、必要的恢复、这些服务对象的时间资格等待和选链处理滞后。只有 header 到达的网络 RTT 不足以充当这个数。

特别要求在 tau 切面，确实有诚实 provider 按这一服务合同能够提供各被分析节点接纳 C0 所必需的全部资料。原生 confirmed 本身不自动证明历史剪枝之后仍可服务、完整恢复已结束或具备足够提供预算；这些必须另行核定。Delta_pub 不要求任意攻击者私链、尤其任意远未来时间戳的已完成私链，都在 Delta_pub 内获得时间资格或被公开。那些块可以计入 ready 库存，但不因此变成当前可采用候选。

每个纳入 pacer 的诚实完整产物，也必须从其 ready 切面起由诚实生产者或另一个诚实 provider 实际承担上述服务合同；不能把“如果有人提供才计时”当成无条件的 Delta_pub 保证。

Gamma：
每个会进入本诚实产出过程的块，从最终绑定父节点／工作 challenge 到完整输出的上界；该父节点在绑定时必须是当时该矿工已完全验证视图里的最大 score 链。也可用另一个经过证明的“旧父工作及时取消／丢弃”合同替代。

单独给出 Delta_pub 不会限制尚未完成的旧父任务。中奖后生成证明的长延迟、流水线内的工作、已启动的 GPU 批次都可能属于 Gamma。若 Gamma 没有有限全程界，需给其超界事件的联合概率，或把相应后续诚实竞争块持续记入 H_off；不能假装它们不产生。

逐块 Gamma 超界概率不是整个执行的超界概率。需要对所有相关块／任务的失效事件给条件联合上界、可求和风险分配或已经证明的 anytime 控制；只有在相应计数与条件前提也已证明时，才能使用有限并集界。同样的全程记账适用于多次提供、验证、恢复和选链处理延迟。

令 L=Delta_pub+Gamma，s=tau+L。分析始终使用物理／受保护分析时间，不用矿工 header.timestamp。

这里还有一个与矿工父选择不同的、必须单独核定的操作前提：在本引理覆盖的失败 activation 或跨节点观察切面，节点已选链的 score 至少为它全部已完整验证、满足时间资格且可采用候选的最大 score。已验证而仍在选链处理队列里的候选不能仅因“尚未激活”就从此集合删除。选择滞后必须进入 Delta_pub 的合同或已支付的操作失败事件。

原生单次调用 candidate.work>incumbent.work 只证明局部单调，单独不足以证明这个全候选最大化前提。例如某节点已能采用一条含 b 的100分链，却仍停在7分 incumbent，随后把它换成8分的 b-free 候选；严格8>7成立，但并未达到100分的公共 b-chain 门槛。引理 A 仍成立，引理 B 的失败到首次竞争映射则不能在缺少此最大化前提时使用。诚实矿工在父选择时取最大链，也不能代替观察／执行节点的这项全路径保证。

### 3.2 库存与新产出的定义

一个“ready”块／链在本证明中指：本块可输出的经典有效身份、完整 body、work proof、全部必需应用依赖均已齐备，并且整个 ancestry 也已完整齐备、可按固定 profile 验证；允许尚待本地未来时间资格的块。只有单块 proof、header 或训练产物已经算好不足以成为 ready。未公开的 ready 链计入；全部材料已经齐备但因未来 timestamp 暂缓接纳的链也计入库存。不能把延迟公开当成新计算。

ready 是历史中已经形成完整输出的单调事实，不因本地缓存清理、未公开、当前时间资格尚未满足或暂时不可取回而撤销；它与某节点在当前切面可采用该链是不同概念。ready 集合按父前缀闭合：一个块进入集合时，它的完整 ancestry 也已进入。如果某些后继的部分产物早已算好，但缺失祖先的完整输出后来才补齐，则祖先补齐可使许多块一起新 ready，必须记为本窗口的批量跳。此前的 partial 进度保留在初态 sigma／已证明的势能账户中，不准因换窗口而免付其资源成本。

可以用下列更精确的相对库存，而不必把共同祖先以前的全部链重收费：

I_tau = sup_{F ready at tau, b not in F}
        max(0, S(F)-S(parent(b))).

假设整个分析所需的相对库存满足 I_tau <= B0。这个上界必须同时覆盖所有公开或隐藏的 b-free 链。它没有自动覆盖任意残留量子状态；尚未测量／尚未形成可输出链的进度必须进入后续资源尾界的初态 sigma 或另一个经过证明的势能账户。

这里的相对库存也不同于代码某一具体 fork 上从 a 起算的 raw inventory_weight。对该 fork 的 tau 前前缀 F0，它们通过 S(F0)-S(parent(b)) 与 S(F0)-S(a) 的平移关联；K_a 同时比 K_b 多出 S(parent(b))-S(a)。相减时这些公共前缀项抵消，使用相对库存的共同上界是保守的。

A(tau,t) 是 tau 后所有相关分支中新 ready 的攻击者块的总权重，每个唯一身份只算一次。对所有分支计总和会高估某一竞争链的权重，但因此能同时支配攻击者事后选择任意 fork。父子整批完成／揭示时可有大跳；每块 w_max 不限制这一总跳。

资源／算符证书必须与这个计分时点对齐：A 在每个身份首次实现祖先完备 ready 时发一次 credit。如果单块 proof 在 tau 前已算好、却在 tau 后补齐祖先才首次 ready，后来的 credit 和此前付过的进度必须由起点势函数 V_tau 或等价 carry-in 账户承载。若另一个成本证书在单块 proof 完成等更早时刻已经发 credit，则必须额外证明从该早计分口径到 ready 口径的 carry-in 转换；不能把已经存在但尚未 ready 的输出直接算成零初态。未来时间资格满足、补充发布、重新取回或重复验证均不得再次发同一 credit。

H_init = 所有诚实新 ready 块在 (tau,s] 的总权重。
假设 H_init <= B_H。这是初始传播和旧父流水线窗口的突发界；不是“一块 w_max”。计入所有诚实块是保守的，至少包含这个窗口中的诚实竞争支。

还假设所有合法块权重 0<w<=w_max，工作身份／profile 绑定无失败，诚实节点不丢掉已可用最大链的比较能力，且3.1中分别针对矿工父选择、失败 activation 与观察节点的最大已验证 score 操作合同成立。

### 3.3 Greedy pacer

在 s 之后取第一个诚实 ready 块为 h1，完成时间 T1。
递归地，h_{j+1} 是第一个完成时间满足

T_{j+1} > T_j + L

的诚实 ready 块。定义

J(c)=sum_{j: h_j 的完成事件不晚于因果切面 c} w(h_j)，在 s 之前为0。

全文中的事件轨迹使用同一个带非递减物理时间的全序因果切面。tau、rho 是这一事件顺序上的切面；T_j 表示 pacer 完成事件的物理时间。写 J(t) 或 P_b(t) 时，总是指一个已经指定的因果切面上的值，不是把该物理时间上所有后来事件一起并入。尤其 J(rho)、P_b(rho)、库存和首次竞争见证必须在同一切面取值；与 rho 同 timestamp、但发生在 crossing 之后的完成／交付事件不计入 rho。边界交付尚未完成时，可以保守地视为尚未交付。

执行假设为局部有限：每个有限物理时间区间中只有有限次 ready、父选择、提供／交付、观察和 activation 事件，允许同 timestamp 的有限批量，不允许 Zeno 积聚。首次竞争、前缀切口和 greedy pacer 递归均在这个同一事件模型中定义；若要容许无限密集事件，需另行证明极限和停止时刻性质。

这里只定义一个全局的、由诚实产出轨迹决定的过程。没有为每个 fork 事后选择不同的“好诚实块”；也没有假定产出是 Poisson 或独立。

### 3.4 首次竞争之前，诚实父选择为什么包含 b

从 tau+Delta_pub 起，C0 已成为所有被分析的诚实观察／执行选链节点及诚实矿工完全可采用的候选。
固定一个有限、非空的相关诚实节点集合 H，包含最初确认节点、全部被比较的节点和所有诚实父选择者。令 V_v(c) 为节点 v 在切面 c 全部已完整验证、满足时间资格且真实可采用的候选链集合。公共进度不是要求每个节点保留完全同一条链，而定义为各节点最高可采用含 b 链 score 的共同下界：

P_b(c)=min_{v in H} max_{C in V_v(c), b in C} S(C).

在 tau+Delta_pub 之后，C0 的提供合同使内层集合均非空，P_b(c)>=S(C0)。视图保留合同进一步要求：对已交付的基准／pacer 链，每个相关节点持续保有该完整可采用链，或保有一条 score 不低且仍包含 b 的合格链，供父选择和选链比较使用。只缓存一个分数、承诺稍后恢复但当前尚不可采用，不满足这个前提。在首次竞争之前使用这一合同即可；它不是已证明的原生保留／恢复性质。

若分析范围允许新诚实节点加入，则必须把它们纳入明确的 bootstrap 合同：在进入 H 并受本比较覆盖之前获得相应完整可采用基准。不能把尚未同步的新节点直接放进共同下界后仍宣称同一 P_b 结论。本引理本身先在固定有限 H 上陈述，动态参与和 bootstrap 仍需另行接线。

考虑任一 b-free ready 链第一次达到相应公共 b-chain score 的事件。tau 到 tau+Delta_pub 之前使用固定门槛 S(C0)；之后使用 P_b(t)>=S(C0)。若在 tau 已有竞争链达到 S(C0)，则 I_tau>=K_b，净间隙已经非正，任何安全界本来就应返回 1。

在这个首次竞争事件 rho 之前：
- 一个最终父选择发生在 tau+Delta_pub 之后的诚实任务，能看到 C0；
- 所有 b-free ready 链 score 都严格小于公共 b-chain score；
- 因而最大 score 父选择必含 b。

这一步由“尚未首次竞争”推出，不是预先假定全网 common prefix。若一个诚实块在 s=tau+Delta_pub+Gamma 后完成，其最终父选择发生在 tau+Delta_pub 之后，所以在 rho 前这样的诚实块必含 b。由此，rho 见证链上的所有 tau 后诚实竞争块均落在初始窗口内，权重不超过 B_H。

即使物理时间相同，也按3.3规定的同一个因果事件顺序处理父选择、完成、可用和 activation；父选择在块完成前。整批攻击产出可以按父优先顺序展开作确定性记账，这不会减少 A，也不把相关批量变成独立概率试验。尾界仍需保留整批产出与残留状态的联合律。

### 3.5 Pacer 进度与末端 w_max

对完成事件在 rho 切面之前已发生的任意 pacer h_j：
第一个 pacer 的父选择至少看到 C0。
对以后 pacer，

父选择时间 >= T_j-Gamma > T_{j-1}+Delta_pub，

故依照提供与视图保留合同，它能够采用此前 pacer 的完整链，或一条 score 不低且仍含 b 的合格链；因此父 score 至少为 S(h_{j-1})。归纳得到

S(h_j) >= S(C0) + sum_{i<=j} w(h_i).

不需要这些 pacer 在同一条物理 ancestry 上；最大 score 的数值下界已经足够。

到 rho 已全体可用的 pacer 给出

P_b(rho) >= S(C0) + J_delivered(rho).

记 rho 切面的物理时间为 t_rho。尚未全体可采用、但在 rho 切面已完成的 pacer，其完成时间保守地落在闭区间 [t_rho-Delta_pub,t_rho]。左端点的交付如果尚未在 rho 前完成，也算尚未交付；右端点上 crossing 之后才完成的块仍不计入 J(rho)。各 T_j 相隔严格大于 L>=Delta_pub，故这个闭区间中至多有一个 pacer：

J(rho)-J_delivered(rho) <= w_max.                    (B1)

这是 w_max 在此映射中的确切用途。它没有限制所有诚实块、攻击者批量或全部在途库存的总量。

### 3.6 确定性结论与完整证明

若固定的原生确认 (b,tau,C0) 发生后，同一节点后来移除 b，或在 tau+Delta_pub 以后某个按规则选链的诚实节点采用不含 b 的链，则存在 t>=tau，使

A(tau,t) - J(t)
  >= K_b - B0 - B_H - w_max.                        (B2)

证明分两段：

(i) 首次竞争在 s 以前。
竞争链至少达到 S(C0)。它在 tau 的 ready 前缀 score 至多 S(parent(b))+B0，tau 后的攻击者权重至多 A(tau,t)，诚实权重至多 B_H。因 J=0，
A(tau,t)>=K_b-B0-B_H，蕴含 (B2)。

(ii) 首次竞争 rho>s。
由 3.4，竞争链的 tau 后诚实部分不超过 B_H；因此其 score 至多
S(parent(b))+B0+A(tau,rho)+B_H。
由 3.5 和首次竞争定义，其 score 至少
S(C0)+J(rho)-w_max。
相减即 (B2)。

为什么原生失败会先出现一次这样的竞争？
同节点首次移除时，引理 A 保证 D 严格超过 C0；若此时已超过传播窗口，3.1单独要求的观察／activation全候选最大化前提还保证 S(D)>=P_b。这里对 P_b 只需非严格 >=，并不由 candidate>incumbent 单独推出。传播完成后的跨节点不一致同样使用该观察节点的全候选最大化前提，并且该节点属于定义 P_b 的共同接收集合。因此两种情况均使首次竞争存在。证毕。

所以 (B2) 作为一个事件包含关系同时覆盖所有 fork。固定这一 (b,tau) 时不需要另外乘“分支数量”：A 是全分支总攻击权重，库存也是全分支 supremum，而首次竞争在所有分支中取最早发生者。

这是有条件的充分归约。B0、B_H、Delta_pub、Gamma、w_max、合法节点选择／完整可用性，以及联合过程 (A,J) 的尾界，仍然都需要自己的真实证据或模型定理。

## 4. 概率接线与不能省略的初始窗口

令 tau 是联合分析过滤 F_t 下的停止时刻。该过滤与资源证书、ready 计分、诚实进度、父选择、提供／交付、当前可采用视图和观察切面一致，不能把两个各自成立的过滤下结论直接拼接。b、C0、K_b 和所用参数 Delta_pub、Gamma、B0、B_H、w_max 必须是 F_tau 可测，或事先固定。不能观察后续分叉轨迹后再免费选择这些参数。令 E_op 是上述操作合同、库存与窗口界在整个声明范围同时成立的事件，包括所有相关块的 Gamma 和提供／选链失效的联合控制。对本引理覆盖的失败事件 F，有条件事件包含界为

P(F | F_tau) <= P(E_op^c | F_tau)
               + P(sup_t [A(tau,t)-J(t)] >= d | F_tau),
d=K_b-B0-B_H-w_max.                                 (C1)

若进一步证明 P(E_op^c | F_tau)<=epsilon_op(F_tau)，并在原过程的概率律下证明相同起点条件的尾界
P(sup_t [A(tau,t)-J(t)]>=d | F_tau)<=Xi_tau(d)，
则得到 min(1,epsilon_op(F_tau)+Xi_tau(d))。没有这些条件界时，(C1)只是正确的概率接线，不是数值资格。无条件结论可对 F_tau 再取期望。

d<=0 时只得到平凡界 1。尾界只条件于起点信息 F_tau，不能改为条件于“未来最终 E_op 成立”后再引用旧超鞅，因为这个未来条件会改变增量的条件律。也可以使用在首次前提失败前停止或显式耦合支配的过程，但必须先证明其在失败前覆盖本见证，并对该过程在原概率律下给出尾界。任意残留状态、起点择时与参数选择仍须落在所证明的同一个过滤和策略范围内。

尤其注意：初始缓冲窗口 J=0，而 A 可能增长。在任意原子时间步骤上假设
E[exp(theta*(Delta A-Delta J)) | past] <= 1
一般不可能成立。不能写出 (B2) 后就无条件搬来 exp(-theta*d)。

可行的后续证明方式包括：
- 对整个 A-J 跨越事件给一个真正的、覆盖残留计时器和量子状态的 anytime 尾界；
- 把初始攻击产出与初始诚实窗口一起纳入 s 时刻库存，并分别支付此前的失败事件，再从已论证的阶段开始；
- 构造带 renewal / 流水线剩余时间状态势能的非负超鞅；
- 用完整资源到权重尾界和诚实 pacer 下尾，针对声明的时间窗口族逐个控制并支付选择成本。

这些是下一层概率义务，本文没有选择未知的原生参数来把它们假定为真。固定交易／固定确认时间的界，也不自动覆盖攻击者等到库存很高再选择交易的策略。多次确认、多个起点、无限时域还需同时控制或可求和错误预算。

### 4.1 可选的资源势函数到 pacer 尾界桥

下面只是一个可以继续证明的精确接口，不断言原生资源律已经满足它。令 R(tau,c) 是与 ready 计分对齐、从 tau 起累计的已支付资源，theta>0、kappa>=0、m 为预先固定或 F_tau 可测参数；多资源时 kappa*R 表示非负系数与资源向量的内积。若在相关首次见证切面以前，另有同一联合过滤下的进度／预算合同

kappa*R(tau,c)-theta*J(c) <= theta*m,

则在 B2 的见证切面，逐路径有

theta*A(tau,c)-kappa*R(tau,c)
=theta*[A(tau,c)-J(c)]-[kappa*R(tau,c)-theta*J(c)]
>=theta*(d-m).                                      (C2)

若资源／算符证书已经在原概率律和同一个联合过滤下给出非负超鞅 M_c，起点 M_tau=V_tau，且在所用切面支配 exp(theta*A-kappa*R)，则条件 Ville 不等式给出跨越上界 V_tau*exp[-theta*(d-m)]。例如 M_c=exp(theta*A-kappa*R)*V_c 只有在已证明其超鞅性质以及 V_c>=1 时才具备这里要求的支配关系；一个未经认证的势函数名称不足以证明它。

令 epsilon(F_tau) 同时支付操作、库存、初始窗口以及新增资源／进度桥失效的全程条件联合概率，并要求 V_tau 是证书给出的 F_tau 可测起点值或已证明的起点上界。对于 d>0，得到条件充分界

P(F | F_tau)
<=min(1,epsilon(F_tau)+V_tau*exp[-theta*(d-m)]).       (C3)

d<=0 时本接口只输出平凡界1；即使 d>0，若 d-m 太小或 V_tau 太大，C3也可能仍然平凡。这里的 M、桥和条件概率仍在原过程下证明，不条件于 future good event。桥只在好事件上成立时，其失败已由 epsilon 付费；不能未经证明把好事件条件化后的过程叫作超鞅。V_tau 特别必须携带 tau 前已付但尚未祖先完备 ready 的 partial／残留状态；若早计分的资源证书未携带它，C3不能用于本 A 过程。

### 4.2 可求和时间分箱桥：不要求生产过程相互独立

本节把“资源尾界和诚实 pacer 下尾”接成明确的条件性接口。它不新增
原生规则，不给实际 W1 填入未知参数。动态参与版还须单独满足
[D1 的完整前提](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0ff81958a611d2c0be54d2ca839b955ae7cb2772/docs/protocol/pon-nakamoto-v1/details/DYNAMIC_PARTICIPATION_V1.md)；
该文档属于另一固定源码上的研究结果，不因此并入本候选。

固定同一起点停止时刻 tau、联合过滤和原概率律。A、J 沿用原定义：
首次祖先完备 ready 的全分支攻击累计权重和已完成 pacer 累计权重。
动态参与版另用 E 表示启动窗口后新 ready、且被排除出合格诚实过程
的累计权重；固定参与版取 E=0。E 不是可因后续归还而减少的余额。
A、E、J 及累计资源 R 从 tau 起计，起点均为零，且非负不减。

库存、启动诚实窗口与至多一个未交付 pacer 已在确定性归约的间隙

    d = K_b - B0 - B_H - w_max

中支付，不可省掉或重复扣除。只讨论 d>0；否则返回平凡界 1。
假设所分析失败事件 F 在操作合同成立时蕴含

    存在切面 c：A(c)+E(c)-J(c) >= d。                 (C4)

固定参与版由 B2 提供 C4；动态参与版须由其 D1 提供。用同一因果
事件序列的切面 c_0=tau<c_1<c_2<... 将范围覆盖为 (c_k,c_{k+1}]。
网格须预先固定或 F_tau 可测，覆盖全部声明切面与终点。物理时间
网格必须有已证明的时钟映射、局部有限性和端点事件语义；同 timestamp
但晚于 tau 的事件仍在第一个箱中。有限记录以后的箱保持 censored。
无限物理时间范围可用无有限积聚的可数网格，不能把未经覆盖的未来
解释成空箱。

每箱选择预定或 F_tau 可测的非负整数 j_k、e_k，以及累计资源向量
上界 B_k。要求同一起点条件下有实际概率界

    P(J(c_k)<j_k | F_tau) <= eps_J,k,
    P(E(c_{k+1})>e_k | F_tau) <= eps_E,k,
    P(R(c_{k+1})不在B_k以内 | F_tau) <= eps_R,k。      (C5)

每个 eps 需要自己的证明；平均产出率或有限轨迹不提供 C5。
固定参与版可取 e_k=0,eps_E,k=0。

再假设已有[残留状态资源证书](STATEFUL_RESOURCE_TAIL_V1.md)在同一过滤、
ready 计分口径和完整合法策略类上给出非负超鞅

    M(c)=z^{A(c)} exp(-kappa dot R(c)) V(c),
    z>1, kappa>=0, V(c)>=1, M(tau)<=v_tau。           (C6)

v_tau 必须是已证明的 F_tau 可测初态上界，携带公共帮助、预处理、
部分完成、量子相关寄存器及跨分支进度。若证书在更早的“单块 proof
完成”时计分，须先证明到 ready 口径的 carry-in 转换。一条实现的
查询计数或未经认证的势函数名称不能提供 C6。

令 a_k=ceil(d+j_k-e_k)。A 的整数权重使这个取整有效；若采用实数
信用则直接使用实数阈值，不得向上取整。定义

    a_k>0 时 q_k=min(1,v_tau exp(kappa dot B_k) z^{-a_k})；
    a_k<=0 时 q_k=1。                                (C7)

事件 A(c_{k+1})>=a_k 且 R(c_{k+1})<=B_k 蕴含
M(c_{k+1})>=z^{a_k}exp(-kappa dot B_k)。因此条件 Ville 不等式
控制其概率不超过 q_k，不需要对每个右端点另作可选停止。B_k 是从
tau 起的累计资源预算，不能在各端点将成本和初态势清零。

**条件性分箱引理。** 若操作合同的全程条件失败概率至多 eps_op，
则在上述前提下

    P(F | F_tau)
      <= min(1,eps_op
                  + sum_k [q_k+eps_J,k+eps_E,k+eps_R,k])。          (C8)

证明：若 C4 的见证 c 在第 k 箱且该箱 C5 的坏事件均未发生，由
单调性

    A(c_{k+1}) >= A(c)
               >= d+J(c)-E(c)
               >= d+j_k-e_k。

整数性给出阈值 a_k，而累计资源仍在 B_k 内；该见证故落入 C7
控制的事件。对所有箱与操作坏事件取并集界即得 C8。可数箱先取前
n 箱再取极限；小于 1 的无限寿命界需要实际风险和收敛且足够小。
证明不要求生产、参与、资源或各箱独立，也不在未来 good event 上
重新条件化超鞅。证毕。

本节继续使用**已完成** pacer J；d 已扣 w_max，不能再因未成熟
pacer 重扣一次。初态库存和 entry debt 的分区也须与所用确定性
归约一致。若合格参与者可以长期全离开，j_k 可能不能增长；若 e_k
无界，新进入者或旧 generation 的竞争产出可能吃掉全部间隙。因此
C8 不从平均资源份额推出链增长。对网格和参数的后验择优需要统一
证书、付费并集或预定混合，不能免费挑选最小观测值。

当前没有实际 W1 的 C5、C6、v_tau 或可求和风险证书。全策略成本
下界、原生 CP/CQ/CG、六后继数值风险、独立运营和生产激活均保持
OPEN / HOLD。增大 watchdog、使用八核 proving 或同机网络不能
提供这些前提。



## 5. 仍未闭合的一般共同前缀部分

(B2) 不覆盖 tau+Delta_pub 以前的一般跨节点共同前缀比较。一个节点看到六后继时，另一个节点可以仍不知道 b；后者没有比 C0 更重的链，因此也不必触发首次竞争门槛。

两种可研究的解决路线：
1. 保持原生六后继语义，证明“能出现深确认、但尚未共同可用”的早期突发／私有发布事件的概率，并与 (C1) 合并。这里必须从 tau 以前的历史起算，不能把它当作免费同步前提。
2. 对另行命名的新本地策略加入经过证明的可用性等待／成熟观察规则，再单独论证其含义。它会改变消费策略，不能倒过来宣称现有六后继已经具备同一风险界。

第二种不是本次实施建议或源码变更，仅说明不同语义的证明成本。现有六后继规则需要第一种原生完整映射或等价证明。

一般 weighted backbone 还需处理可变参与、所有法律 target/u 分支、重复攻击起点和全生命周期隐藏工作。当前原生 T>=1 只给出 w<=2^255 这个数学上有限但通常毫无实用余量的上限。固定 p0/可变 u 若被另行实现，实用上限应由共同合法 u_max 得出 w_max=u_max*floor(1/p0)，并证明所有竞争分支受约束。每16块 clamp4不是全分支共同绝对范围。

## 6. 明确反例

以下是有限树模型中的反例，不声称已在原生 W1 网络运行出同一攻击或测得相应概率。

A. 纯诚实分叉：
两个互不通信的诚实群体各自延长不同分支。一方 b 后已有六块，另一分支随后更重，前者回滚；攻击者产出 A=0。说明单独的攻击者尾界不能替代网络／诚实分叉项。

B. 有界延迟内的突发：
把上述所有完成事件放进一个有限 Delta 窗口再交付。无确定性每窗口产出上限时，六后继仍不能保证在窗口结束前全网共享该前缀。即使 mining 有很小概率快速连续成功，也需要在风险界中支付该概率。

C. 不限旧父流水线：
诚实矿工在看到 b 前选定旧父，任务或中奖后证明很久以后才完成。即使网络传播迅速，之后仍可能出现诚实竞争支；所以 Delta_pub 本身不能消除 H_off，Gamma／取消合同是独立条件。

D. 已有隐藏库存：
tau 前准备好更重链，tau 后零新工作发布，回滚成功。观测窗口的新 CPU / 新 oracle 查询数为零不代表攻击能力为零。

E. 单块 cap：
每块权重都是 1，攻击者一次使八块祖先完备的链 ready，分析步骤的总跳是 8。w_max=1 不推出每步骤 A_i<=1。

F. 等重跨节点：
两节点各自先采用不同但等重的分支；收到另一分支后仍保留当前链。因此跨节点必要比较为 >=，而本地替换为 >。

## 7. 独立可执行检查

文件：
native_fork_witness.py
test_native_fork_witness.py
native_fork_witness_results.json

运行：
python3 -m unittest -v test_native_fork_witness.py
python3 native_fork_witness.py --out fresh_results.json

原始输出文件不存在时才创建，避免静默覆盖既有报告。

实际检查：
- 17 项测试通过，最后一次观测运行耗时 2.936 秒。
- 穷举 6,564 个小型有根正权树，权重取 {1,2}，生产者标签取 {A,H}，原始非 genesis 节点最多4个。
- 检查 160,048 个有序分支比较和独立 LCA 计算。
- 对各 inclusion/竞争支添加六后继并构造最小严格超越，检查 86,516 个已确认首次移除必要见证。
- 另检查 pacer 末端窗口至多一块、双门不足、真实 inclusion 下界、同 b 重组后 score 单调、库存／诚实竞争支、早期跨节点缺少可比性、等重、不可用头、旧父流水线、批量权重等控制。

这些检查验证有限加法模型的算法与代数，不验证 W1 最低成本、实际随机过程、native Rust 全路径、时间戳／任务资格、服务性能或主网安全。报告中概率与安全资格字段均保留 null/false。

## 8. 文献核查和适用边界

1. Cao and Guo, Trade-off of Security, Latency, and Throughput of the Nakamoto Consensus, arXiv:2312.05506v3 (22 May 2024).
https://arxiv.org/html/2312.05506v3

已读其模型、balanced heights、pre-mining lead、pacer/jumper 与事件归约。关键方法提醒是：诚实分叉能补足攻击者的差额；先前私有领先需要单独控制；其给定交易时间不由攻击者择时。它采用自己的 Poisson 与单位区块模型，数值不能移到 PoN 变权、证明流水线和混合量子过程。

2. Garay, Kiayias and Leonardos, The Bitcoin Backbone Protocol with Chains of Variable Difficulty, CRYPTO 2017; ePrint revised 2019.
https://eprint.iacr.org/2016/1048

动态参与和难度需要额外环境条件与专门分析。该论文不能仅凭“都是最重链”就证明本项目 target/MTP/工作关系。

3. Garay, Lu, Prat, Testa and Zikas, A Composability Treatment of Bitcoin's Transaction Ledger with Variable Difficulty, FC 2025 revised proceedings published 2026.
https://eprint.iacr.org/2024/1823
https://researchportal.ip-paris.fr/en/publications/a-composability-treatment-of-bitcoins-transaction-ledger-with-var/

核对了作者页／预印本摘要，报告其在参与约束下的 simulation-based treatment。PDF 经可用浏览接口返回403，因此没有把未读定理的常数或具体假设当成已核定。它提供可组合建模方向，并不自动覆盖 W1 量子资源。

4. Garay, Kiayias and Shen, Fast Difficulty Adjustment in Proof-of-Work Consensus, CRYPTO 2026.
https://www.iog.io/papers/fast-difficulty-adjustment-in-proof-of-work-consensus

官方页确认2026论文与常数时间调难度主张。本文没有依赖其未在此复核的完整证明，也没有把其不同协议换成原生 PoN 的风险界。

最终资格：本次可准确新增“严格本地 cut lemma”和“含 Delta_pub+Gamma、诚实窗口、相对库存与 w_max 的全分支共同 pacer 充分归约”。实际资源尾、完整 early cross-node CP、操作参数联合概率与六后继数字风险均尚未闭合。
