# 合法捷径与新出票成本：完整研究回执

**工程与有限实验：PASS。可记权工作资格：HOLD。实际 chainwork：0。**

本轮实现了一个有明确额外安全工作的研究 profile，给出了带假设的经典
random-oracle 查询量论证，并完成原生授权、完整关系验证、持久化预算和真实
localhost TCP 的成本记录。它仍未证明“有用神经计算本身”的最低实际资源成本，
也未建立攻击者自有 CPU、GPU、能量或资金支出的通用下界。

完整机器判定见 [acceptance.json](acceptance.json)。设计与数学范围见
[profile 规范](../../docs/development/specs/pon/GROUPED_FRESH_WORK_FLOOR_V0.md)。

## 1. 精确源码与交付状态

| 项目 | 身份／结果 |
|---|---|
| 本轮基础提交 | `9602cb704f97fb9c87d6fd379809bef468c3c1e8` |
| 实现提交 | `b9ccd327b363335ae6c219fd73565ab4ccaa9f17` |
| 最终验证源码 | `1e0eba75f4f4a4e24e17cbd0f263f915c1493ac7` |
| 最后一个源码变化 | 仅澄清模块文档：唯一规范证明的外层哈希本身不会增加票数 |
| 最终验证 | 21/21 命令 PASS，0 失败，0 未执行 |
| 最终捷径实验 | 208/208 数学关系验证通过 |
| 最终完整出票主计划 | 16/16 通过，7 命中、9 未命中，全部保留 |
| 额外控制项 | 251 项完整记录 |
| 远端交付 | GitHub 连接器返回 HTTP 403：account suspended；未推送新分支或创建新 PR |

最终验证前后都使用仓库原有的严格 source guard。两个 release executable 与
本次 Cargo metadata 的 target directory、成功构建结果和最终 SHA256 对应。
机器回执中的源码 SHA 指上述最终源码；保存本 evidence 目录的后续提交是证据
提交，不冒充重新执行过完整 hosted CI 的合并结果。

GitHub 账户错误的观测保留在 [准备记录](provenance/readiness.json)。本轮没有
换账户、换访问入口或绕过访问限制。原有 #688 集成方向和既有 W1 语义保留。

## 2. 新关系实际约束了什么

固定 profile 为 `pon-grouped-int257-sealed-research-v0`：16 个有序请求，3 个
expert、3 个输出、257 个特征，保留原来的精确整数关系、bias8 和最低索引 argmax。
router、stable gather、selected expert、scatter 和输出均由独立 reference 验证。

业务结果允许合法缓存。本轮生产者先付出 2,313 次 merged 权重加法和 2,160 个
sparse MAC，得到一个正确业务 product；之后每个 nonce 都复用它，**没有新的
神经 contraction**。这项优化被明确允许并计入准备成本。

新增工作是固定 64 步、逐步依赖前一状态的哈希关系：

\[
z_0=H_{\mathrm{seed}}(\mathrm{profile},c,s),\qquad
z_i=H_{\mathrm{step}}(\mathrm{profile},c,i,z_{i-1}),\quad i=1,\ldots,64.
\]

这里 c 由先验 candidate 派生，s 是完整正确 grouped statement 的规范承诺；
**ticket 就是最终状态 z64**。生产者实现合法复用 SHA256 的公共前缀状态。
因此，64 个模型中的 oracle 查询不能直接换算为 64 个等价 CPU 操作或 SHA256
compression，也不是物理能耗下界。

| 编码 | 精确字节数 |
|---|---:|
| canonical admission body | 728 |
| 双角色签名 capsule | 862 |
| 带 nonce 的 candidate | 742 |
| 固定 seal proof | 134 |
| 主计划完整 JSON packet | 3,522 或 3,523 |

64 种 JSON 空格编码复用同一规范证明、ticket 和 work ID；没有第二次首次记录。
只有允许未受工作约束的可变 proof/carrier 熵或额外可选 nonce 进入彩票，才可能
产生额外独立输入。对唯一规范证明再哈希一次，本身不构成这种倍增。

64 是有界研究参数；该构造增加了安全计算，不能由此声称已经实现内生有用
PoW、生产级安全强度、忽略不计的开销或 succinct proof。

## 3. 两个条件性查询界

[理论模块](../../formal/pon-nakamoto-v1/fresh_work_query_floor_v0.py) 同时保留
证明论证、显式假设、精确有理数计算和有限 transcript auditor。

### 包含验证者的总查询量

设 M=2^lambda，固定链长 L，candidate 在任何 final-index probe 之前已经唯一
固定 seed、profile、target；candidate/profile/index 的编码域不相交，seed 与尚未
揭示的链 oracle 输出独立；endpoint 直接作为 ticket；每个 candidate 最多计权一次。
名义记权为 L floor(M/(T+1))。Q 包括预处理、委托、失败、取消和验证者补做的
全部有关查询，并有确定上界 q。则在所述经典模型及有界停止条件下：

\[
\mathbb E[C]\leq
\min\left\{L\mathbb E[Q],\;
\mathbb E[Q]+\frac{Lq(q+1)}{2M}\right\}.
\]

完整前缀已经揭示的 final query，可以把预期信用收取到互不重复的 L 个输入；
未揭示前缀的投机 query 另加 predecessor 猜测项。这个论证没有把整个执行
条件化为“没有碰撞”。有限测试也保留了幸运反向猜测、丢弃候选和自适应停止。

这不是“每个成功个例必定花 64 次查询”的断言：幸运猜测仍可能成功。它也没有
把验证者的查询变成攻击者自己的支出。将模型中的 injective candidate 换成
实际 SHA256 digest，还需要独立绑定假设，以及最大 admission 和最大 award
约束下的失败概率传递。

### 只计算攻击联盟自己的查询

若额外假设攻击联盟查询 Q_A<=q、全体有关验证者合计最多 K 次提交、每次名义
award<=W_max、验证者只泄露规定的 endpoint equality 反馈、没有内部值或时间
侧信道，且正确 equality 后关闭该 candidate，则令 D=M-K(q+1)>0，有保守界：

\[
\mathbb E[C]\leq\min\left\{K W_{\max},\;
\frac{M}{D}\mathbb E[Q_A]
+\frac{Lq(q+1)}{2D}+\frac{K W_{\max}}{D}\right\}.
\]

M/D 保留了失败验证反馈造成的条件分布变化，最后一项保留没有查询 canonical
final input 的正确猜测。K 和 W_max 都需要真实依据，不能只把它们写成常量。

**小 target 的反例很具体。** L=64、T=1、一次直接猜测某个中奖 endpoint 时，
猜中概率是 1/M，中奖名义权重是 64(M/2)，所以期望名义信用为 **32**，与 hash
长度无关。很低的成功概率不等于很低的期望记权；target floor／award cap 不能省略。

这些是条件性数学论证与有限控制，不是对所有攻击者的机械化证明。当前原生
实现没有建立全网 K、无时间侧信道或联盟资源归属，因此 coalition implementation
transfer、物理／神经计算下界和量子安全标志均为 false。27 项理论控制全部通过。

## 4. 真正落地的授权与预算边界

新的原生 capsule 绑定完整任务、输入、模型、scope、generation、期限、nonce
窗口、付款对象，以及从实际本地 Node 读取的 network、parameters、genesis、
parent、prior state、height、generation 和 expected target。验证时重新检查 Node。
输出、proof、ticket 和依赖 challenge 的字段不会反向进入同一次 challenge。

两个签名角色使用不同外部固定公钥和角色域，另有单独保存的 expected body、
capsule digest 与 registry sequence/digest。例程使用真实 native strict Ed25519
验签，密钥是有意公开的受控测试密钥；这不证明独立运营方、PQ 签名或真实客户授权。
Python wire parser 独立重建完整模型／请求承诺与 candidate framing；原生 verifier
负责签名与实时 Node 检查；完整 receiver 再要求原始 base／delta 的独立计算。

仅有 nonce 上限不能阻止对同一 nonce 反复提交假 endpoint，因此新增单 journal
固定 **256 次验证预约**。预约在昂贵 Cell replay 前持久化，指纹绑定 mode、nonce、
statement、proof SHA256、capsule SHA256。claim 在认证和 seal replay 前消费，
错误、重复、放弃均不退款。私有不可复制 token 还绑定当前打开的 journal 实例；
同策略的另一 journal 或 reopen 前的旧 claimed token 不能搬来使用。

最终账本为 256 reserved、83 spent、0 remaining。未 claim 的预约也已消耗额度；
其中包含主动放弃和在 Python Cell 检查阶段拒绝的请求。第 257 次请求在完整
Cell 前拒绝。17 步取消留下预约但不返回 proof；reserved unknown 工作不能在
reopen 后成为免费新 nonce。

这是单 receiver/journal 的保证，不能覆盖克隆文件、多节点、Sybil 或管理员改写。
解析、签名、存储和传输仍有成本；正确性专用的纯数学 API 明确不提供服务配额。

## 5. 合法捷径反例与摊销

[最终 shortcut 记录](shortcuts/report.json) 包含 13 个 observation×16 轮，即
208 次关系检查。比较 arm 共享 challenge，因此实际是 **80 个不同 challenge**，
不是 208 个独立彩票查询。其中 112 次使用原始模型与原始 16 个输入，96 次是
明确标注的控制。全部业务输出和辅助输出由独立重建审计核对。

| 真实输入上的辅助关系 | direct 每轮 MAC | 已实现合法捷径每轮 MAC | 含准备和 16 轮的 direct／捷径总 MAC |
|---|---:|---:|---:|
| rank-one blinding | 31,964 | cached 3,180 | 536,096／75,552 |
| full-rank batch mixing | 90,464 | cached 1,536 | 1,472,096／73,920 |
| dropout | dense 24,672 | sparse 1,044–1,278 | 419,424／42,786 |

这些是实现操作计数，不能当作完整运行时间加速比。full-rank mixing 的 16 个
challenge 产生 16 个不同辅助输出、12 个不同 routing 向量，缓存投影仍然成立。
所以“输出变了”或“router 变了”并不足以证明必须重做原有昂贵计算。

真实 dropout 的 LUT 每轮为 0 MAC，但准备已花 **74,016 MAC**，超过 sparse 在
这 16 轮中的 **42,786 总 MAC**。它还支付 8,385 次准备加法、每轮 1,512 次
lookup／加法，以及 72,768 字节表有效载荷。稠密控制表为 12 MiB；这些载荷字节
不包含 Python 容器开销。零在线乘法既不代表零成本，也不代表当前窗口内最便宜。

原始业务输入保持 [-8,8] 和 bias8。辅助关系显式另设数值界，实际最大绝对值
为 rank-one 16、mixing 216（上界 264）、dropout 8；没有偷偷改变业务数值语义。
零模型是单独控制，不能替换已固定的真实模型。上述反例不宣称发现了当前 W1 漏洞。

## 6. 完整本地路径成本

[最终完整记录](fresh-work/report.json) 包括模型和 213 行 consumer 源重放、
输入读取、合法准备、签名、statement／proof 生成、额外 Python cross-check、
真实 localhost TCP、完整 Cell 与 seal 重算、数据库预算以及 packet／receipt
写入和读回。16 个主计划尝试之外的 251 控制项也包含在整轮成本内。

| 观测 | 最终值 | 范围 |
|---|---:|---|
| native 64 步 producer wall 中位数 | 9.274 微秒 | 仅额外 security seal 阶段 |
| 独立完整 Cell wall 中位数 | 6.477 毫秒 | 实际分开计算 base 和 delta：37,008 MAC、48 次输出加法 |
| TCP 完整 receiver 往返中位数 | 16.889 毫秒 | 含预算、认证、重算、持久化及应用层回执 |
| 主计划 whole attempt 中位数 | 26.964 毫秒 | 含绑定、原生生成、额外 Python trace、编码和完整 receiver |
| 全部 campaign wall | 3.202521 秒 | 16 主计划、251 控制及所述准备／记录 |
| Python 父进程 CPU | 1.285821 秒 | 已包含 receiver 线程 |
| 全部子进程 CPU | 1.264381 秒 | 包含源重放／Git helpers 和 native child |
| 其中 native-only CPU | 0.375407 秒 | 上一行的子集，不能再加一次 |

应用层 TCP 共发送 **308,793 字节**、接收 **231,293 字节**。原生请求／响应共
368 对，原始 packet 与 receipt 各 87 份。45 项独立审计逐份在子进程退出后
读回，核对 SHA、字节长度、计数、预算和 1,088 个 Python step preimage
（主计划 1,024，加独立 untrusted producer 64）。

机器为共享 AMD EPYC 9V74 环境；这些实验与验证任务有重叠，没有性能隔离，
不能当作吞吐 SLA 或硬件下界。没有新 GPU allocation。父进程、子进程及嵌套
阶段不可重复相加，也不能用整轮含人工控制的时间反推生产 TPS。

完整协议的真实 WAN/TLS、全网传播、复制可用性、生产证明系统和外部授权服务
成本仍未测全。Python 父进程启动／导入／退出、最终 report 编码明确在所述计时
之外；native child 启动和退出包含在其 lifetime／CPU 中。强杀 Python 可能留下
未知的中间阶段细节，没有声称具备完整 crash accounting。

## 7. 最终验证与独立审计

完整 [21 项验证摘要](validation/summary.json) 和
[逐命令记录](validation/commands.json) 对应最终源码，全部 PASS。

| 执行的测试组 | 结果 |
|---|---:|
| grouped Python 与 native 交叉测试 | 110 通过 |
| 原 conditional query bound | 21 通过 |
| 新 fresh-work 理论控制 | 27 通过 |
| crypto 所有 target／所有 feature | 合计 243 通过 |
| 原 header binding | 1 通过 |
| 新原生 admission／预算 | 14 通过 |
| source integrity 负例 | 43 通过 |
| CI contract 负例与结构检查 | 102 通过 |

还通过 locked workspace/fuzz graph、Rust format、严格 workspace/all-targets/
all-features Clippy（warnings 为错误）、source inventory、仓库及链接检查。
原有 18 项验证命令均保留，新增 3 项；并未执行全 workspace 的全部 unit tests、
原始大型服务 campaign 或该最终源码上的 hosted head/merge CI。

独立复核入口：

- [完整原生／字节／账本审计](reviews/final-native-audit.json)：45 项 PASS。
- [最终 shortcut 重绑定审计](reviews/final-shortcuts-followup-audit.json)：208 次
  非时间字段与独立重建一致，208 次都有本轮新计时；原始独立重建记录也保留。
- [最终理论审计](reviews/final-theory-followup-audit.json)：公式与限制一致，外层
  hash 表述问题关闭；有限测试不冒充机械化证明。

## 8. 原始数据、失败历史与复现

精确 raw packet 包含有意保留的尾随空格，原始日志也不做格式修补。它们放在
gzip tar 中，避免版本控制的 whitespace 检查迫使修改观测。每个 archive 都有
成员 SHA／字节数清单，已完整读回验证；只规范化容器元数据，不改变文件内容。

- [完整 fresh-work capture](fresh-work/complete-capture.tar.gz)：87 个 packet、
  receipt、native transcript、SQLite、签名 capsule、policy 以及原始结果。
- [完整最终 validation capture](validation/complete-capture.tar.gz)：21 条命令
  的原始日志、metadata graph、退出记录及 source guard。
- [全部开发与前一源码历史](history/complete-history.tar.gz)：保留失败和初版
  结果，不由后续成功覆盖。
- [开发失败说明](provenance/development-failures.json)：格式、CI 命令清单、
  存储不足的初次 copy test，以及短 SHA 参数错误的实际边界。
- [离线 fuzz cache 恢复](provenance/offline-fuzz-metadata-repair.tar.gz)：135 个
  原始 archive 对当前 lock checksum 验证；只对已核对公共源码做 hardlink／少量
  解包，没有合成 registry index、改 lockfile 或发起网络下载。

在包含既有基础提交、模型材料及历史 source Git objects 的 checkout 中，构建
release example，然后使用新的输出目录执行：

~~~bash
cargo build --offline --locked --release \
  --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --example grouped_fresh_admission_v0

PYTHONPATH=formal/pon-nakamoto-v1 python3 \
  formal/pon-nakamoto-v1/experiments/grouped_fresh_work_v0.py \
  --runner ABSOLUTE_RELEASE_EXAMPLE_PATH \
  --out NEW_ABSOLUTE_OUTPUT_DIRECTORY \
  --rounds 16 --replay-source \
  --source-sha 1e0eba75f4f4a4e24e17cbd0f263f915c1493ac7
~~~

完整 validation driver 已随源码提交，原始执行命令和 Rust 1.95／PQ OpenSSL／
Cargo 环境在本目录保留。输出为 create-only；source mismatch、缺少历史对象或
缺失依赖会失败，不会静默换数据或复用旧 PASS。

## 9. 可记权之前仍需要什么

1. 把所需安全保证明确为可审计的攻击联盟资源模型，建立与 concrete 实现及
   最便宜合法策略相容的界，处理预处理、委托、全网验证和量子搜索。
2. 实际独立治理的任务／target／profile 授权，以及真正用户需求、期限、输出
   消费和付款依据。公开 fixture 密钥和历史 corpus 不满足这些条件。
3. 若要主张有用计算硬度，需要新的有用关系及适用假设，并继续通过 merged、
   factor、sparse、cache、上下文复用和数值语义反例；额外哈希链不能替代此证明。
4. 全局 replay／验证预算与完整证明、验证、可用性、传播及服务经济性。
5. 正常集成与远端 head／merge 检查，以及原有生产资格门槛。

因此，本轮给出的可交付结果是完整源码、条件性数学论证、可重放实验和严格
边界；工作 profile 资格继续保持 HOLD，实际记权和生产激活继续为零。
