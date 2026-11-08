# 验证成本转移、共享 owner 与工作公平性

**可记权工作资格：HOLD。实际 chainwork：0。生产激活：false。**

本轮把单 receiver 的验证预算推进到一个实际运行的共享 native owner，
补上显式计入验证者帮助的经典查询界，并用真实多进程 TCP 检查预算、
回执、错误请求、取消和传播成本。完整执行结果与交付身份见后文及
[acceptance.json](acceptance.json)。规范见
[GROUPED_RESOURCE_TRANSFER_V0.md](../../docs/development/specs/pon/GROUPED_RESOURCE_TRANSFER_V0.md)。

有一项结论已经比“尚未证明”更明确：**在当前允许的缓存范围内，严格为正的
逐 challenge 生产者新增神经 contraction 下界已被合法实现否定。**
业务 product 可以复用，新增 challenge 约束的是 security seal。
生产者之后的新增业务乘加为零，前期准备、存储、读取、seal、证明和验证仍有成本。
这不表示完整服务零成本，也不表示已经证明最优 CPU、GPU、能量或资金策略。

## 1. 精确源码与状态变化

| 项目 | 身份／范围 |
|---|---|
| 本轮父提交 | `37c1f3fe24c88476f39b0bd6e9ed32453bfc4551` |
| 本轮源码提交 | `e95e2eb9f456a37ec8841def69db79f49fbba7cb` |
| 本轮源码 tree | `c815d3710d5f7feffc043aed1aa6e003e03d3a10` |
| 交付分支 | `fix/chain-fresh-work-floor-20261107` |
| 工作关系 | 原来的精确 grouped int257 业务关系及固定 64 步 seal |
| 共识变化 | 不改变 W1、target 算法或 work registration；记权为 0 |

| 条件 | 本轮后的严格判定 |
|---|---|
| challenge 约束明确的新安全计算 | 保留实现和回归验证；不等价于新增神经计算 |
| 完整关系与独立 verifier | 保留 router、stable gather、selected expert、scatter 与原始系数 reference |
| merged／factor／sparse／cache 等合法策略 | 保留既有可重放结果；没有穷尽最优策略 |
| 经典条件性总查询界 | 增加显式外部验证帮助项的保守推论 |
| 攻击联盟查询界向实现转移 | 单可信 owner 的 callback 上界已落地；更强 endpoint-only 界与公开网络转移仍未建立 |
| 最低新鲜神经计算成本 | 当前缓存范围内，正的逐 challenge 生产者 contraction 下界被反例否定 |
| CPU／GPU／能耗／资金通用下界 | 未证明 |
| 独立任务／target 授权和真实需求 | 未建立；真实签名代码使用公开测试密钥 |
| 全网预算与完整证明／传播成本 | 新增本地 fanout 和共享 owner 成本；全网、WAN、TLS、可用性及生产证明成本仍不完整 |
| 量子安全 | 未证明；保留不能把经典界用于 coherent query 的精确控制 |
| 实际记权／生产激活 | 0／false |

这里的“独立 reference”指另一条计算／验签路径，不表示独立运营机构。
全部实验由同一受控环境执行。历史 smoke、正式 run 和审计使用过同一组确定性
fixtures，不能将一次 run 的先固定计划称为从未被历史查询过的随机 challenge。

## 2. 为什么新鲜神经下界在当前 profile 中不成立

令业务结果为 `y = F(task,input,model)`。合法准备阶段已经取得 y 后，
当前关系允许每个新 challenge 使用相同的 y，重新生成 statement／seal。
因此在准许的同一缓存范围内：

\[
C_{\mathrm{fresh,neural}}(c\mid y\text{ 已缓存})=0.
\]

操作计数非负，而现有合法实现达到零，因此不存在严格为正的逐 challenge
生产者 contraction 下界。这是对当前关系的构造性结论；没有用有限 nonce
窗口假装无限摊销，也没有把前期准备成本删除。

完整系统仍需支付：准备与缓存、读写与编码、security seal、证明生成、
独立 Cell 与 seal 重算、授权、存储和传播。不同输入复用 activation 仍受输入、
表示、模型版本及授权 scope 限制。正常的 factor／merged／sparse 优化继续合法，
精确数值关系保持不变。

上一轮 [208 项捷径观测](../pon-fresh-work-floor-20261107/shortcuts/report.json)
继续以其原始源码身份保存；其中比较 arm 共享 challenge，共 80 个不同 challenge，
不能把 208 个观测当作 208 张独立票。本轮没有把旧计时重新标成新源码实测。

## 3. 显式计入验证者帮助的经典推论

令 M=2^lambda，L 为固定 step 查询长度，C 为理论名义累计信用。
每个 candidate c 最多获得一次 `L floor(M/(T_c+1))` 名义奖额；这不允许任意
替换计权规则。其 target 必须在该 candidate 的任何 final-index 查询前固定，
也包括猜错 predecessor 的 speculative probe。
Q_A 为攻击联盟自己的全部相关 step 查询，Q_V 为其他方产生且能帮助该联盟的
step 查询。预处理、委托、公开 producer 服务、验证、历史复用和额外帮助都必须
在声明的会计时间范围内归属。设：

\[
Q_A\le q_A,\qquad Q_V\le B_V,\qquad \mu_A=\mathbb E[Q_A].
\]

将 `Q_total = Q_A + Q_V` 代入既有经典 aggregate theorem，得到：

\[
\mathbb E[C]\le
\min\!\left\{
L(\mu_A+B_V),\;
\mu_A+B_V+
\frac{L(q_A+B_V)(q_A+B_V+1)}{2M}
\right\}.
\]

完整推导、假设及有限控制在
[fresh_work_resource_transfer_v0.py](../../formal/pon-nakamoto-v1/fresh_work_resource_transfer_v0.py)。
原定理要求固定 candidate／target 的 chronology、独立 seed、注入式 oracle 域、
一次 candidate 最多一次信用和有界停止。实际 SHA256 digest 的绑定仍是额外假设。
转移到实现时，还必须以明确的最大准入总数和最大名义奖额，把坏事件概率换成
信用误差；不能用很小的失败概率覆盖无限增长的 award。
本推论允许被计入的验证者公开完整经典 transcript、结果与时间信息，因而无需
把当前 native 程序假定为没有 timing／cache 信息泄露。

**B_V 不是攻击者自己的账单。** 当外部帮助非零时，攻击者自己没有执行
chain steps 仍可能获得正的名义信用。总查询量约束不能直接推出攻击者自有
CPU、GPU 或资金下界，也不覆盖 coherent quantum queries。

若一个可信 owner 最多开始 K 次 callback，每次至多 R 次完整 L 步 replay，
则这些 callback 的 `Q_V_callbacks <= K R L`。只有它们覆盖全部相关帮助时，
才能取 `B_V = K R L`；否则还要加入其他 owner、epoch、公开服务、独立复验及
历史辅助。seed 查询、签名、解析、准备、存储和传输单独核算。

## 4. Native 共享 owner 实际保证了什么

新 owner 固定 epoch、generation、authority、receiver keys、candidate registry、
总额度及每 candidate 额度。它对实际本地 Node 执行 admission 检查，冻结完整
原始模型／请求，并自己执行完整原始系数 Cell verifier 与 64 步 seal。
服务没有不受计量的 `Prove` 操作，也不发可复制给 receiver 自行重放的执行许可。

| 事件 | 实际状态变化与查询处理 |
|---|---|
| 新请求 | 验 receiver／action／完整 fingerprint；同时检查总额度和 candidate 额度 |
| 开始昂贵验证 | 先持久预约，再提交 `started`，随后才能执行 Cell／seal |
| 正确 hit 或正确 miss | 原子提交结果并关闭 candidate；正确 miss 同样关闭 |
| 完全相同的已完成重试 | 返回历史 receipt；新增 Cell、seed、step 查询均为 0 |
| 相同 idempotency identity 配不同请求 | 拒绝 |
| `started` 后进程退出 | reopen 标记 unknown；不退款、不重跑，保留完整可能查询上界 |
| 未使用／放弃预约 | 不退额度；已关闭 candidate 的旧预约不能重算 |
| 两个 owner 打开同一 journal | 文件独占锁阻止并行合作 owner |
| 同 policy 新建第二个 journal | 可以各自获得额度；已加入明确反例控制 |

缓存响应明确声明 `new_candidate_completion=false`、receipt 为历史记录，且不
重新验证当前 Node 或 expiry。历史 `first_record=true` 不代表本次新增准入或记权。
所有 signature key 都是公开测试 fixture，不构成真实外部身份或密钥保管证据。

独立源码审查修复了一个真实缺口：原来 owner 漏检每个 request 的 scope 是否
等于 capsule 签名的 `authorization_scope`。负例现在改变 request scope、重新计算
承诺并重新双签；在签名有效的情况下仍因 scope 不符而拒绝。

K 的边界是一个可信且不被克隆／回滚的 owner、一个受保护 journal、一个固定
epoch，以及全部相关执行经过该 owner。它引入共享服务的信任与可用性依赖。
独立 receiver 如果再次完整验证，它们的查询必须重新加入 Q_V。此实现没有
全网 anti-Sybil、管理员防篡改、磁盘整体防回滚或公共 epoch 更新预算。

## 5. 本地正式 owner 观测与完整分母

[本地原始报告](owner/report.json)、[308 项复核](owner/review.json) 与
[完整 capture](owner/complete-capture.tar.gz) 对应 e95 精确源码。
计划固定 4 次 owner 启动、每阶段 2 个 receiver，共 8 个 receiver 进程和
30 次 TCP 请求。初次 prepare 是另一个进程。

| 观测 | 实际值 |
|---|---:|
| 同 journal 预约／额度 | 12／12 |
| 完成 callback | 11 |
| 已消耗但因 candidate 关闭而未执行的预约 | 1 |
| Owner seal steps／该 owner callback 条件上限 | 704／768 |
| Owner seed queries | 11 |
| 完整通过的 Cell replay | 11 |
| 错误 endpoint 拒绝／正确 hit | 8／3 |
| Producer seal steps／seed queries | 192／3 |
| 发往 owner／来自 owner 的保留应用帧 | 53,460／34,333 bytes |
| 新 chainwork | 0 |

另一条 Python 路径独立核对了 30 对原始 frame、SQLite 状态、完整模型／请求
承诺和 62 次 Ed25519 签名，共 308 项检查。3 个 scheduled hits 只描述此计划，
不估计中奖概率，不证明随机 oracle 前提。正确 miss 关闭由 native 控制另行验证。

| 不同费用来源 | 本次实际计数 |
|---|---:|
| 初次准备及四次启动的业务 MAC | 5 × 394,752 = 1,973,760 |
| 五次 model merge 加法 | 5 × 2,313 = 11,565 |
| Owner 完整 reference MAC | 11 × 37,008 = 407,088 |
| Campaign 独立 Python reference | 37,008 MAC + 48 adds |
| 事后独立审计 | 384 steps + 6 seeds + 37,008 MAC + 48 adds |

Owner 启动每次重建 16 个 canonical 业务产品。这是 K 之外的服务帮助和成本。
不完整或提前拒绝的 reference 调用不能一律乘以 37,008；实现分别保留已知完整
工作与 unknown 上界。事后审计及开发历史也不能从扩大的会计时间范围中删除。
这些 MAC 是所选完整重算策略的实际计数。当前关系允许的合法缓存或其他
reference 优化也可能降低验证成本；本报告不把重复准备或每次完整重算规定为
所有正确验证者必须付出的最低成本。可运行策略的成本给出可达上界，无法单靠
计时转成对所有合法策略成立的资源下界。

本地 campaign 测量区间为 1.416463437 秒 wall、0.467804997 秒 parent CPU、
0.951599 秒所有子进程 CPU。native `wait4` 的 0.133089 秒是后一项的子集，
嵌套 callback 时间同样不能再相加。parent 启动／导入／退出和最终 report 编码
在该计时区间外。机器共享且工作量含人工控制，不构成生产吞吐或硬件下界。

本地输出位于 tmpfs，并保留 target 路径导致 SQLite loader 未资格化的构建
warning；它支持受控进程重启与字节检查，不证明物理断电持久性。
最终 canonical ROG 构建与额外正式 run 已完成，作为独立观测列入验证部分，
没有覆写本地观测、旧成本或同一 K 的边界。

## 6. 反例与量子控制的精确范围

[有限报告](finite/report.json)、[精确源码控制](finite/summary.json) 和
[另一条精确多项式复算](reviews/finite-independent.json) 均保留原始结果。

| 控制 | 参数与结论 |
|---|---|
| 复制本地预算 | 8 个各 16 次的额度，总计 128；名义期望信用 4。错误套用单 journal 的界为 128/255，正确合计后的界为 128/31。 |
| 回复多泄露 endpoint 的一位 | lambda=8、T=127、L=64；最多 9 次验证、攻击者自己 0 chain steps，名义期望信用 64；错误 equality-only 界仅 1152/247。 |
| 猜中极小 target 的一个 endpoint | L=64、T=1；一次猜测的名义期望信用为 32，不随 hash 长度消失。 |
| 理想 Grover 查询策略 | 64 candidates、固定 p=1/64、5 轮；完整抽象查询 768，名义期望信用约 2237.382782，超出不适用的经典约 768 界。 |

前两项是有限模型反例，不声称当前 native 程序存在相应侧信道或已观察到伪造
ticket 成功。量子控制按 65 个 winner-count 等价类，对全部 2^64 种 marked subset
按其真实二项分布权重求和，保留无赢家和过旋转情形。
它完整计入 320 次正向 step query、320 次反计算、64 次测量后候选重算及
64 次独立 verifier 重算；成功率约 0.546236030661。
该控制使用相互独立且均匀的 endpoint、M=2^64 与固定 p=1/64；本次 native
fixture 的 target 对应 p=1/2。它们是不同的实验，不能将控制的数值当作当前
native fixture 的实际量子攻击结果。

独立复算使用 De Moivre 二项式恒等式，未调用生产模块的 Grover 振幅递推。
这仍是理想 black-box 策略，不是编译的 SHA256 量子电路、容错计算机成本、
GPU 加速比或量子算法最优性证明。
其中反计算指可逆 oracle 的反向调用，不是假设可以免费求 SHA256 原像；
真实授权下获得 64 个可搜索候选的过程及其电路成本也没有由这个有限模型实现。
[Zalka 的搜索分析](https://arxiv.org/abs/quant-ph/9711070)、
[后量子 PoSW 工作](https://arxiv.org/abs/2006.10972) 和
[compressed-oracle 的完整协议分析](https://eprint.iacr.org/2020/1305)
对应不同安全命题；hash-chain sequentiality 不能直接替代端点彩票的公平性证明。

## 7. 真实需求与付款连接仍缺什么

[精确源码需求连接审查](reviews/demand-bridge.json) 逐个绑定了六个现有组件：
M06 原生 task lifecycle、Node funding snapshot、原生 payment transition replay、
M12 本地 effect journal、consumer context，以及 grouped fresh admission。
本审查没有调用这些 owner 产生真实授权、付款或消费。

生产连接必须把同一个获授权任务／profile、输入／模型、真实资金 subject、
receiver／output、当前消费授权及原生支付观察连成可验证关系。
签名不能单独证明签署机构相互独立；相同内容不等于相同客户；不同 ticket 也不
等于不同真实需求。发送方 kernel 接受字节、server 成功 write 或客户端收到
receipt，都不能独自证明业务消费。

当前可确认的真实外部消费数与本 grouped output 的原生结算数都是 0。
本轮未虚构客户、付款、安装、生产 FinalUse 或独立运营方。

## 8. 最终验证、fanout 与交付

### 8.1 精确源码验证

ROG 在独立工作目录对源码 `e95e2eb9f456a37ec8841def69db79f49fbba7cb`
完成第二轮 canonical 验证：**24／24 个计划命令 PASS**，没有失败、跳过或超时。
对应 [原始 summary](rog/key-records/validation-canonical-v1/summary.json)、
[runner 绑定](rog/key-records/validation-canonical-v1/runner-bindings.json) 和
[完整日志归档](rog/validation-canonical-v1.tar.gz)。
三个 runner 都与本轮实际 Cargo build artifact 绑定，运行前后源码身份相同。
本轮使用正常 rustup launcher 与完整 sysroot loader 路径，保留了环境、锁文件、
依赖归档、provider receipt 和原始命令输出。最终三份 SQLite 构建输出均有
layout witness／build fence，未出现 `UNQUALIFIED` 标记。
实际构建产物及日志复核见
[SQLite qualification review](rog/key-records/readiness-capture-v1/preparation/sqlite-qualification-review-v1.json)。

| 本轮实际测试组 | 通过数 |
|---|---:|
| grouped Python／native（含 18 项 deployment cost） | 128 |
| 原条件查询界 | 21 |
| fresh query floor | 27 |
| resource transfer | 15 |
| native crypto 全 targets／features | 243 |
| header binding | 1 |
| fresh admission | 14 |
| verification authority | 18 |
| source integrity 负例 | 43 |
| CI contract | 103 |
| 合计 | **613** |

上述计数由本轮日志提取，见 [逐组计数](reviews/final-validation-counts.json)。
单独的 60 项有限模型重跑与开发／首轮历史不再叠加到 613。

第一次 ROG 验证也完成了 24 个命令，但产生 6 条 SQLite `UNQUALIFIED` 警告。
该轮完整保留于 [首轮历史归档](history/rog-initial/verification.json)，明确不作为
最终 canonical 环境资格证据。后续修正仅涉及本任务的启动环境和独立 target
目录，没有改变源码、Cargo graph、锁文件或公共 provider。

这些 gate 覆盖实际列出的测试、workspace／fuzz locked graph、格式、严格
workspace Clippy、源码完整性负例、CI contract 和 Markdown 链接；不声称已经
运行所有可能的 workspace unit tests、GitHub hosted CI 或 prospective merge CI。

### 8.2 真实进程 fanout

最终 [fanout 原始报告](rog/key-records/fanout-exact-rog/report.json) 与
[完整 capture](rog/fanout-exact-rog-v1.tar.gz) 在 ROG 的 ext4 上运行独立 receiver
进程及各自 SQLite journal，
而不是用一个内存计数器模拟多节点。每个 receiver 包含相同的六项固定计划：
有效请求、carrier replay、伪 endpoint、发送截断、发送完后丢弃响应和额度后拒绝。
另逐一把本地 256 个预约槽填满、重开 journal，并检查第 257 次在 Cell 之前拒绝。

| Receiver 数 | TCP 尝试 | 观察到的本地预约之和 | 完整 Cell 调用 | Reference MAC | Receiver 及其子进程 CPU 秒 |
|---:|---:|---:|---:|---:|---:|
| 1 | 6 | 256 | 4 | 148,032 | 0.309628 |
| 2 | 12 | 512 | 8 | 296,064 | 0.586721 |
| 4 | 24 | 1,024 | 16 | 592,128 | 1.198597 |

**本地 cap 会相加。** 当前独立 journal 没有全局 256 上限。表中额度填充控制
和六项网络请求是不同的观察维度，不能将 256 个预约写成 256 次完整 Cell。
三个 topology 合计 42 次 transport attempts，含 7 次发送截断和 7 次丢弃响应；
每个 topology 仍然只有 2 个不同 work ID 和 1 个 material content ID。
42 次传输不是 42 次独立出票，也不是 42 个客户或真实需求。

三组 receiver 实际接收的应用字节分别为 17,654、35,308、70,616；
客户端实际接收为 8,372、16,766、33,511 bytes。server 发送时 kernel 接受的
11,229、22,482、44,937 bytes 不是 peer 已读取或业务已消费的证明。
native 子进程 CPU 是表中 CPU 的子集，不能重复相加。全 campaign 另报告
parent CPU 0.323179142 秒、所有已等待子进程 CPU 2.860014 秒，覆盖范围不同，
不能把表中的 CPU 再加到这个总子进程值上。
Campaign 的 report 编码前 wall 区间为 7.178171716 秒；没有测量公网端到端延迟。

### 8.3 最终 ROG 共享 owner 与独立审计

最终 [ROG owner 报告](rog/key-records/owner-exact-rog/report.json) 和
[完整 capture](rog/owner-exact-rog-v1.tar.gz) 使用 SHA256 为
`895c08811f5ddfc99470915d4d6cd236dfea29afa4064daabe044fb9f58963ec`
的本轮 native runner；fanout 使用的 fresh runner 为
`d76a3d713149f9ed9660a54c5310244677150fed440f8be730076eb25a2bf1ef`。
两者都绑定同一源码提交，但属于不同的可执行程序和测量计划。

4 个阶段、8 个 receiver 进程、30 次请求得到 12 次预约、11 次完成及
1 次已消耗但未执行的预约。Owner 观察到 704 seal steps、11 seed queries，
完整 reference 为 407,088 MAC；生产者另有 192 steps 和 3 seeds。
五次准备／启动的 1,973,760 业务 MAC 与 11,565 merge adds 仍单列在 K 之外。
最终 ROG 应用帧为发往 owner 53,460 bytes、来自 owner 34,337 bytes。
parent CPU 为 0.275633212 秒，所有已等待子进程 CPU 为 0.866039 秒。
Campaign 的 report 编码前 wall 区间为 1.229068286 秒，native 子进程的
0.089744 秒已经包含在所有子进程 CPU 中。
这些受控本机数据没有替代公网部署成本或最便宜策略分析。

[可移植独立审计](rog/key-records/readiness-capture-v1/preparation/owner-independent-audit-v2.json)
完成 **325／325 检查**，核对了原始帧、SQLite、2 个 capsule
签名、30 个 receiver 签名及 30 个 owner response 签名，并额外绑定最终
验证 summary、源码、build log 与 runner artifact。环境资格由独立的
SQLite qualification review 另行核验。
审计本身新增 384 chain steps、6 seeds 及 37,008 MAC + 48 adds，不能并入
之前 owner 的 K 后声称仍只花 704 steps；扩大到整个会计时间范围时必须计入。
这里的 325 项是独立核对条件，不冒充 325 个 unit tests 或独立运营方。
审计另测得 wall 0.042287063 秒、parent CPU 0.031867835 秒及 Git helper
子进程 CPU 0.009487 秒；计时不含 Python／module 导入和最终 JSON 编码／退出。

### 8.4 交付与复现

源码已通过 HeptaRuntime 的 Mac 本地 GitHub 凭据通道正常推送，并完成 Git／API
双回读，见 [源码发布回读](provenance/source-github-readback.json)。交付分支为
`fix/chain-fresh-work-floor-20261107`。最终证据作为后续独立提交保存；该提交与
e95 的差异只允许本证据目录，执行过的源码身份始终标为 e95，不把后加的证据
误写成已执行的旧提交内容。未推进 main 或现有 integration candidate。

完整正式记录、复现参数、逐项测试数量及归档 SHA 由本目录的
[acceptance.json](acceptance.json) 和 [MANIFEST.json](MANIFEST.json) 索引。
[Runtime launch provenance](rog/runtime-launch-provenance-v1.json) 保存实际
Hepta job、executable、argv、受控环境和退出状态，包含验证、fanout、owner
及独立审计四个正式入口；没有导出继承环境或凭据。

复现时使用 e95 的独立 checkout，先运行仓库 preflight，准备记录中的
Python 3.12.3／numpy 1.26.4／cryptography 50.0.2、Rust 1.95.0、精确的
OpenSSL 3.5.9 provider 和 workspace／fuzz 两份锁定依赖缓存。材料源
`9fedf7ecbbe07177069c030592b4e03dcffebb81` 必须可读取；source replay 会独立
核对实际材料。依次按 provenance 的四个正式入口重跑，并替换为新的输出目录、
target 与 task idempotency identity，保留本轮原件。调用正常 `rustup run`，
不以手工直调 toolchain cargo 取代最终已资格化的 loader 环境。
Archive 与逐成员 readback 记录见
[ROG 回传核对](rog/transfer-readback-verification-v1.json) 和
[最终整包复核](reviews/root-evidence-readback.json)。

## 9. 失败历史、资源与复现边界

所有 raw packet、receipt、SQLite 和日志以 unchanged member bytes 归档，
附逐成员 SHA256／字节数清单，并完整读回核对。只规范化 tar/gzip 容器元数据。

- [Owner 开发与正式完整 capture](owner/complete-capture.tar.gz)：含首次编译、
  两次 Clippy 修正、ENOSPC 后原样重跑和 artifact JSON 浮点编码修复记录。
- [Fanout smoke 01–04](history/fanout-smoke-01-04.tar.gz)：含失败和空的／不完整输出，
  未观察到的部分成本保持未知，没有用后来的 PASS 替换。
- [Fanout smoke 05](history/fanout-smoke-05.tar.gz)：tmpfs 开发观测，不能冒充最终 ROG run。
- [理论开发记录](history/theory-development.tar.gz)：保留提交前控制与有限结果。
- [存储迁移记录](history/storage-relocation.tar.gz)：原 checkout 路径保留，复制的
  10,000 余个文件逐字节与模式核对；仅删除本任务可重建 debug cache。
- [首次 CI contract 存储失败](provenance/first-ci-contract-storage-failure.json)：
  原始大段输出未全部保留，明确记录该限制；没有补造完整失败日志。
- [Colab 优先调用记录](provenance/colab-priority-attempt.json)：分配了 task-owned CPU
  runtime，bind 因 `STATE_DESTINATION_CONFLICT` 被拒。官方 release／reconcile
  随后返回 `FIXED_RUNTIME_NOT_FOUND`，后续 available inventory 的 runtime 列表为空。
  没有宣称 release API 成功，没有改 profile 或账户保护，没有在 Colab 提交 workload。

外部公共网络的验证、TLS/WAN、复制可用性、生产证明生成／验证、真实授权服务、
能耗与资金计量仍未全部测量。全部条件补齐之前，这个 profile 继续为研究 HOLD。
