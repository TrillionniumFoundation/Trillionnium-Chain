# W1 fresh runtime、远端接收与资金 owner：2026-11-07

本记录报告真实完整证明、真实接收、失败操作与修复后的取消实验。各项资格分别判定；完整证明能够生成，不等于出块关键路径、业务预算、结算付款或完整密码学安全已经合格。

## 当前结论

| 工程门 | 本轮实证进展 | 仍未通过的条件 |
| --- | --- | --- |
| 原生 winner／receiver | 两份 fresh 证明均从原生 nonce 搜索取得的声明开始；独立 expected-artifacts；本地与 ROG 接收；父进程按原始时钟确认远端完整返回包在原始 deadline 内 | 部署网络中的真实 Node winner admission、全历史进程树资源计费、总体尾延迟 |
| 完整后端同资源实验 | 分段／平衡方案与顺序方案均完成 43 个新 segment、43 次 lift、42 次 join；各 1 份新完整证明，均无递归 checkpoint 复用 | 两种方案只有各 1 个固定输入样本；共享主机存在干扰；未证明因果优化或原业务资源条件达标 |
| 真实异步资金与操作 owner | 昂贵生成已经进入 NativeTask 与 M12 链；一份完整 proof 被严格验证；真实 r0vm 启动后的 owner 取消及独立进程冷重开通过 | 完整证明操作仍 Pending，GPU 用量未知、资源上限保留；昂贵任务的重组／超时全路径与 provider 一次性正向付款尚未闭合 |
| 部署收益与安全 | 两份新 receipt 上执行共同 Rayon=2 的 80 行 ABBA；原 4 秒预算的负向实测；独立绑定保留 | 验证成本与载荷体积均无收益；原业务预算不通过；完整密码学与生产资格继续 HOLD |

## 源码与实验身份

两份完整证明使用已提交的 A：`d3037ca5dfb6f301757c159b7888dca9b0317be0`，tree `d4a8f84cdc896b9454ce0d03a164f8916e6afdf9`。其运行目录、qualified ELF 和全部原始实验输出保持原样。

取消集成 C1：`cb557c5e59b00ba7c6b1d40f78fbe51031a26f11`，tree `7971aca2ff432ec8907bb69545a2c58d70b4a215`。C1 的实际昂贵取消试验在分发前失败，本记录保留该失败。

请求容量修复 C1b：`0f18f93f2d35b62c6ca6d63faf4f336d55cbf4bf`，tree `94334bb6b52cfd13040059a5e71f47d8cc9603f2`。仅提交 11 个已冻结文件，包括 6 个 runtime／测试文件、3 个 CI 文件、corpus pins 与唯一开发计划。修复后的实验使用新 operation、目录和研究 Node。

C1b 的精确源码资格已实际闭合：backend 13 条命令／22 项测试；native／verifier 21 条命令／243+2+7 项测试；owner／M12 14 条命令／Node async W1 子集 15 项及 M12 10 项测试；CI 19 条命令／471 项方法（其中 mandatory 104）。合计 67 条组件命令、770 项实际测试方法结果；聚合另有 4 条只读检查。3 个昂贵入口在这轮短控中明确 ignored，后续实际取消／冷重开各自单独运行 1 项，不混入 770。所有组件和聚合均实际 exit 0、完整且持久；旧 C1 的五个 ELF 在各门及聚合结束后实际重算哈希，均未改变。参见 [C1b qualification](qualification-C1b/qualification.json) 和 [完整资格原件](qualification-C1b/qualification-raw.tar.gz)。

各后端使用 SDK 3.0.6、固定 CPU r0vm 3.0.3 和保留的 guest ELF。guest SHA-256 为 `25718312ec3c6f5219d832e3516adfb5f82983156f669c5e7daa15bd22d1798f`。本轮未重编 guest，也未建立独立可复现构建或完整加密安全资格。缓存复制后的资格检查如实标记 `fresh_cargo_target=false`；新的目录不被算作独立新构建。

## 两份 fresh 完整证明

两组共用固定历史材料、nonce 起点 0、同一 native 输入及独立 expected-artifacts。各自实际搜索 1 次即取得该实验目标下的原生 winner；这不是随机、独立同分布的挖矿样本。两者各执行 9,040,798 cycles，均完成 43 个新 segment、43 次 lift、42 次 join。重复验证、253 条并行前缀发布和 903 次 checkpoint 再验证均不增加 fresh proof 计数。

两组在同一主机同时执行，实际各配置 8 CPU 配额与 8 GiB 内存，使用不同 CPU 集合。分段／平衡组配置 2 个 segment worker、2 个压缩 worker、每个 Rayon pool 4；顺序组配置 1／1／8。Rayon worker 计划不是进程树总 CPU 配额，也不意味着主机隔离。owner 路径和内层 verifier 设置也不同，因此这是一对有明确限制的资源配额对照。

| 实际观察 | funded 分段／平衡 | unfunded 顺序 |
| --- | ---: | ---: |
| fresh 完整证明数 | 1 | 1 |
| fresh pipeline，秒 | 6,044.373854 | 5,939.121782 |
| 外层 controller，秒 | 6,052.875037 | 5,947.749196 |
| segment 阶段 wall 合计，秒 | 3,587.708624（22 批） | 3,438.087902（43 次调用） |
| 递归压缩阶段，秒 | 2,438.986170 | 2,477.049590 |
| winner → 本地 receiver ACK，秒 | 6,059.180275 | 5,941.545213 |
| winner → 资金 owner 观察独立 verifier，秒 | 6,088.782819 | 不适用 |
| winner → 父进程收齐 ROG 返回包，秒 | 6,648.759587 | 6,658.476311 |
| receipt 字节 | 257,014 | 257,014 |

分段／平衡组 fresh pipeline 在本对样本中慢 **105.252072 秒**，比值 **1.017721824**。不能据此估计总体 p95／p99，也不能宣称并行分段或平衡递归带来可部署加速。历史 6,248.484 秒记录来自另一轮条件，未与本轮直接合并或改写。

SDK 调用计时包含后端启动／加载，外层 controller 保留 CLI、准备、源码检查和产物发布所在路径。并行实现记录 55 个显式 client constructor，合计约 0.294 秒；顺序实现没有同类探针，不代表其启动成本为零。本轮没有单独隔离全部加载成本。

两个最终 receipt 分别为：

- [funded succinct.bin](fresh-full/funded-balanced/succinct.bin)，SHA-256 `585808f32353a272c310595fa31b33f1ba160add53490c1673bf7fa6c6bc2e57`。
- [sequential succinct.bin](fresh-full/sequential-unfunded/succinct.bin)，SHA-256 `033586595c7c203acc48b48e16d969b1376a833244fa82f3b64edfdcc35033c2`。

共同 [input.bin](fresh-full/input.bin) 为 49,506 字节；[header.bin](fresh-full/header.bin) 为 318 字节；[expected-artifacts.bin](fresh-full/expected-artifacts.bin) 为独立的 64 字节期望值。完整分析见 [analysis.json](fresh-full/analysis.json)，公开原件及排除范围见 [publication-allowlist.json](fresh-full/publication-allowlist.json) 和 [fresh-full-public-raw.tar.gz](fresh-full/fresh-full-public-raw.tar.gz)。

## 真实 ROG receiver 与原始 deadline

ROG 使用由 A 源码资格检查得到的独立 verifier。两次 receiver 及两次接收后 readback 均实际 exit 0，且 Hepta 记录 `output_complete=true`、`output_durable=true`。原 ROG PID 的 birth identity 与原 cgroup 在后读回时均已不存在，没有 operation cancellation sidecar。

每个父进程用自己的原始 boot／monotonic 时钟记录完整返回包到达：funded 组距原 deadline 尚有 **542.217424 秒**，顺序组尚有 **533.531039 秒**。没有跨主机直接相减时钟，也没有延长原 proof deadline。

这一 winner→返回包时间包含人为／工具调度、文件传输、独立验证与取回；它不是纯网络 RTT 或部署 WAN 尾延迟。receiver 验证成功也不是链上 Node 对中奖区块的 admission。后读回时 scope 不存在，不能倒推完整历史资源所有权或所有后代均已由父进程 wait/reap。

证据：[funded 父时钟](crosshost-parent/funded-balanced.json)、[顺序父时钟](crosshost-parent/sequential-unfunded.json)、[父进程与传输原件](crosshost-parent/raw.tar.gz)、[ROG 接收原件](receivers/new-full-receivers-raw.tar.gz)、[ROG 原件索引](receivers/new-full-receivers-raw-index.json)。

## 同一 Rayon 设置下的新 ABBA

两份新 receipt 分别运行 10 个 ABBA block，各 20 次 native、20 次 proof verification，共 **80 planned／80 dispatched／80 accepted**；采用共同 Rayon=2、2 CPU 配额、8 GiB 内存和 CPU 集合 8,9。所有行的输入、实际环境、独立绑定、原始 stdout、退出值和资源 scope 都有记录。fresh generation 数仍是 2，不是 80。

| 内层 verifier 指标 | funded receipt | sequential receipt |
| --- | ---: | ---: |
| native 中位数，毫秒 | 2.658635 | 2.573996 |
| proof 中位数，毫秒 | 34.731047 | 34.570897 |
| proof／native 中位数比 | **13.063490** | **13.430828** |
| proof 样本 p95，毫秒 | 59.710534 | 60.466037 |
| proof 样本 p99，毫秒 | 63.550505 | 60.631674 |
| receipt／native payload 字节比 | **5.191573** | **5.191573** |

p95／p99 使用 nearest rank；每组 proof 只有 20 个重复验证样本，所以此 p99 就是该组样本最大值，不是证明生成或总体网络尾延迟。上述比值是中位数之比，不是配对比值估计。

冷进程外层 wall 比值约 1.002871／1.055614，内含监督轮询的约 0.28 秒底座，不能拿它掩盖内层验证成本。原完整运行内部 Rayon=4／8 的各 40 行比较另行保留，不和共同 Rayon=2 的新 ABBA 混合。

本轮测得的内层验证成本和载荷字节数均未优于 native；未建立部署传输收益。原始结果：[result.json](cost-common-rayon2/result.json)、[独立读回](cost-common-rayon2/readback.json)、[完整小型原件](cost-common-rayon2/raw.tar.gz)。首次读回脚本因可选 `cancellation_event` 字段缺失而失败，其失败也保留；后续只读修正没有重跑或增加 ABBA 行数。

## 原业务预算实测

新负向实验保留原 **4 秒、0.25 CPU、2 GiB** 限制，从 native 尝试前开始计时。实际原生 winner 在原点后约 14.711 毫秒出现；后续启动路径耗尽 deadline，程序退出 **124**，没有完整 proof、ACK 或资金操作。其 7.402 秒总观察包含终止清理，不能记作 proof 时间。当前 scope／原 PID birth identity 后读回消失。

这次没有执行原业务的 16 个 hostile 输入、1 笔唯一确认交易及 6 次确认全流程。业务资格仍不通过；较宽的研究实验预算没有替代原预算。原始记录：[result.json](original-budget/result.json)、[预算实验原件](original-budget/raw.tar.gz)。

## 昂贵生成接入 NativeTask／M12 后的实际状态

funded 完整生成确实从现有 NativeTask Reserve 和 M12 Prepare→Intent→BindJob 路径进入昂贵后端，并完成独立完整验证。然而 owner 状态及冷重开状态都为 **Pending**，原 NativeTask 仍 Reserved、剩余 1,000 单位，未出现 Receipt／Settle／Cancel 或 provider 付款。GPU 用量是 UNKNOWN；完整资源 cap 继续保留，没有凭 CPU 样本释放 GPU credit。

一次完整 proof 验证成功不授权付款。本记录不把本地 development fixture 的账户／task 身份当成跨研究 Node 的全球唯一身份，也不把隔离 Node 的 Reserve／Cancel admission 当成中奖 W1 区块的网络 admission。原数据库私有留存，公开的是哈希、事件链分析和有限聚合，不包含数据库原始页。

## 取消失败、修复与新操作

C1 原操作 `285bbcda30e7b735bdb828c1d2d838ab3f01501b00166a8074e271d83d0dc654` 的真实 job `1a1b7db09a3-12894-c8e` 以 **exit 101** 失败。其 target request 有 339 个文件 pin：原始 JSON **68,909 字节**，compact JSON **66,550 字节**。旧 64 KiB 读取上限在 target 分发前拒绝该请求；没有真实 r0vm 启动，没有有效 owner cancellation，也没有完整 proof。

原失败状态只留下 M12 Prepare／Intent 和 NativeTask Reserve；原 task 仍 Reserved／1,000，M12 全部 cap 保留，没有 BindJob、资源 credit、付款或 refund。原 operation、原 deadline 和原始文件均未重试／续期／改写。证据：[失败分析](failed-owner-C1/failure-analysis.json)、[资金状态读回](failed-owner-C1/funding-state.json)、[raw.tar.gz](failed-owner-C1/raw.tar.gz)、[raw-index.json](failed-owner-C1/raw-index.json)。

C1b 明确修改本地请求准入上限为 **128 KiB 原始 UTF-8 字节**。target、normal runtime 和 cancellation helper 使用同一有界严格 loader：最多读取上限加 1 字节；拒绝超限、非 UTF-8 编码（包括 UTF-16／UTF-32）、嵌套重复键、NaN／Infinity／浮点溢出、错误顶层及字段类型。完整 source pins 保留，result 上限仍为 64 KiB。

V2 canonical serialization、statement digest、clock domain、SQL schema／application identity 保持不变；它是本地原始输入容量策略修复。候选阶段实际 **13+7+7=27** 项测试通过，覆盖恰好 131,072 字节可接收、131,073 字节拒绝、2 MiB 输入只读 131,073 字节、339 个真实临时文件 pin 的有限非 proof child 与同 operation replay。旧失败 request 即使容量可读，仍因旧 source pin 被新 target 拒绝，未重新分发。证据：[候选测试](owner-request-capacity-repair/candidate-tests.json)、[独立静态复核](owner-request-capacity-repair/static-review.json)、[修复原件](owner-request-capacity-repair/raw.tar.gz)、[索引](owner-request-capacity-repair/raw-index.json)。

### 修复后实际昂贵取消与冷重开

新 operation 为 `ebe3c586d634730e7464f2e3661aea37f6ed7402c0d74f1a695224510d2e2f5e`，statement 为 `b8769801cf2824799954d43eba78dfa684a5107c11d96abca8092b0f1ea3659f`。它绑定上述真实 C1b 资格及新研究 Node；原始 deadline 是 `1167336972674704`，boot 为 `14f92beb-43c6-4786-839e-b57307ae8048`，只选择一次 600 秒研究取消窗口。

| 实际检查 | 观察结果 |
| --- | --- |
| 原昂贵取消 job | `1a1b80aa46c-12894-d18`，实际 succeeded／exit 0，完整、持久；精确 ignored selector 单独运行 1 项并通过，测试时长 31.54 秒 |
| 昂贵后端 | 实际观察固定 first prove command 及 live 固定 r0vm 子进程；1 次新生成尝试，0 份新完整 proof |
| 原 target 终态 | `terminal`，cause=`cancelled`，sticky cancel=true，may_dispatch_again=false；直接 child exit -9，子 cgroup 递归为空 |
| 原生 Cancel | 原 owner 签名 tag 3 位于 canonical ancestry；NativeTask cancelled、remaining=0，gross principal refund=1,000 |
| 新进程冷重开 | `1a1b80d2416-12894-d1e`，实际 succeeded／exit 0、完整持久；精确 cold selector 1 项通过，测试时长 0.35 秒 |
| 冷重开副作用 | 同一 statement／operation／原 deadline；生成分发 0、target cancel 请求 0、原生交易提交 0；target observation=OBSERVED |
| M12／付款 | cancellation 保留，begin=Pending；原资源 cap 保留，GPU UNKNOWN，provider payment=false |
| 两个外层 job 终态后的 scope | 4 个明确列出的 PID birth identity 均 ABSENT，原 main／child／cold 3 个指定 cgroup 均 ABSENT；完整历史 wait／reap 仍为 null |

31.54／0.35 秒是各自测试 body 的实际输出时长，不是完整 fresh proof 时间或总体取消尾延迟。冷读器读取保留的 worker result 和当前 worker identity；后续独立 scope 观察另行记录，不从 M12 状态推断递归进程清理。没有续期、重派原失败 C1 操作或把资源未知状态变为付款许可。

独立审计在两个原 job 终态后，只复制四个已关闭数据库，在私有副本中只读解码；没有连接或修改原数据库，没有调用 Node／M12／target。实际 M12 为 Prepare／Intent／BindJob／Cancel 各 1 条，完整序号、根哈希链与 payload 解码绑定通过；没有 Verified／Failure／Settlement／Payment，原资源 cap 和本地取消记录保留。

新的实际请求仍有 **339 个 file pins**：原始 JSON **68,944 字节**、canonical JSON **66,585 字节**，均没有缩到旧 64 KiB 上限以下。原始 SHA-256 为 `d1cf5f237edb4b2d24cd8136e51064a3fce1493fe186ca7d572814c989f77cf6`，canonical SHA-256 为 `090361c6425009b00738aa06e14d045ab16b68498a9ce36536424f768000e0e2`。源文件与二进制 pin 完整保留。

原 Cancel packet 全字节在规范链 height 2 中唯一匹配，owner nonce 为 **0→1→2**。账户余额实际为 **10,000,000→9,998,581→9,999,290**：本金退款为 1,000，Cancel 步骤净增为 **709**，Reserve→Cancel 全程净变为 **−710**。291／419 仅是费用相关算术残差；本次独立审计没有单独解码 wire 的 fee 字段，不能把残差说成独立手续费解码结果。两个相关 block 没有 provider 账户 delta，不据此宣称其完整账户余额为零。

这里验证的是原 packet 的一次规范包含、一次 Cancel 状态变化以及 cold 入口没有再提交；没有实际重发同一 wire 来测试拒绝，也没有由本审计独立重验签名或解码 Packet 交易列表。没有 cold 前数据库字节快照，因此不宣称 cold 前后数据库逐字节相同。详见 [独立资金与操作审计](owner-cancellation-C1b/funding-readback.json)、[审计公开原件](owner-cancellation-C1b/funding-audit-public.tar.gz) 和 [公开清单](owner-cancellation-C1b/funding-audit-allowlist.json)。

新试验的首次配置准备曾因 plan 父目录尚不存在而 exit 1；此时 plan、proof out、target、研究 Node 和 launch 均不存在，未选择 deadline、未触发资金或 target 分发。该失败原件保留；建立唯一空父目录后，原 builder 按同一配置参数完成准备。它不是第二次生成尝试。

证据：[真实昂贵取消](owner-cancellation-C1b/result.json)、[独立进程冷重开](owner-cancellation-C1b/cold-result.json)、[终态后 scope](owner-cancellation-C1b/scope-after.json)、[原始主 job 回执](owner-cancellation-C1b/original-job-receipt.json)、[原件包](owner-cancellation-C1b/raw.tar.gz)、[逐文件索引和排除项](owner-cancellation-C1b/raw-index.json)。

原派生连接器回执保持不变。辅助 uint64 `request_fingerprint` 的 JavaScript 数值精度问题通过追加两份原始工具响应文本予以说明；同一 idempotency key 的只读式 reconciliation 均返回 `reused=true`，未启动新进程或操作。主身份和 cold gate 使用精确 job ID、request digest、argv、source/config hash、boot 与 PID birth。详见 [精度读回记录](owner-cancellation-C1b/connector-integer-precision-readback.json)。

## 计算资源与资格边界

按要求优先通过 HeptaRuntime 的既有账户通道尝试 Kaggle／Colab。Kaggle 的真实 CUDA 分配、256 字节 host/device 往返成功；后续 CUDA build-only 请求在所有权检查 `NOTEBOOK_LIST_SCOPE` 被拒绝，状态 `REJECTED / NOT_SENT`。该探针和被拒绝的构建均产生 **0 份 W1 proof**。Colab 的既有 profile 绑定冲突及 foreign/busy kernel 的受控释放拒绝保留；后续只读 reconciliation 报 `FIXED_RUNTIME_NOT_FOUND`，没有伪记受控释放成功，也未覆盖其他 kernel。详见 [原 provider 记录](../pon-w1-runtime-recovery-20261107/provider/README.md)。

完整 AIR／递归 soundness、Fiat–Shamir／QROM 的完整参数与 128-bit PQ 资格、语义／编译器对应、对抗预计算与稀疏／低秩策略、全链 PQ／DA、真实模型效用、跨版本操作排他、全账本回滚、原业务门槛及生产部署仍未建立。单个实现门、source-integrity 检查、CPU／GPU 可用性探针和此处的严格 receipt 验证都不替代这些条件。

## 公开证据组织

| 路径 | 内容与范围 |
| --- | --- |
| [qualification-A](qualification-A/qualification.json) | A 的实际已提交源码／工具链／Cargo／测试／ELF 资格；完整小型原件压缩包同目录 |
| [qualification-C1](qualification-C1/qualification.json) | C1 实际资格；保留 stale 240 期望导致的失败及 243 项实际测试的独立核对 |
| [qualification-C1b](qualification-C1b/qualification.json) | 修复后实际源码资格与原 ELF 留存读回 |
| [fresh-full](fresh-full/analysis.json) | 两份 fresh 完整证明、最终 receipt、独立输入与允许公开原件清单 |
| [receivers 原件](receivers/new-full-receivers-raw-index.json) | 新 ROG receiver 的完整小型原件、hash 及真实终态 |
| [crosshost-parent 原件](crosshost-parent/raw-index.json) | 原父时钟、传输及完整返回包读回 |
| [cost-common-rayon2](cost-common-rayon2/result.json) | 新的 80 行共同条件成本对照，0 次新生成 |
| [original-budget](original-budget/result.json) | 原 4 秒预算失败和实际终止读回 |
| [cancellation-candidate-controls](cancellation-candidate-controls/raw-index.json) | 候选取消／重组／资源控制测试，不能代替真实昂贵取消运行 |
| [failed-owner-C1](failed-owner-C1/raw-index.json) | 原始真实失败及保留资金状态 |
| [owner-request-capacity-repair](owner-request-capacity-repair/raw-index.json) | 容量修复、27 项候选测试和独立静态复核 |
| [owner-cancellation-C1b](owner-cancellation-C1b/result.json) | 新原始 operation 的实际 expensive start／cancel／cold 结果 |

压缩包的逐成员字节数和 SHA-256 均经读回核对。公开小型原件不是整个 host 的完整备份；大型中间 seal／进程跟踪、私有数据库、构建 target 和 ELF 二进制不打包，保留明确的索引与排除原因。最终 [artifact-inventory.json](artifact-inventory.json) 列出本目录公开产物；它不包含自身哈希，以避免自引用。

最终发布提交的精确源码检查另做外部 attestation，引用被测 commit，不把事后资格结果写回该 commit 然后假称相同源已测。没有激活、部署或合并受保护主分支。
