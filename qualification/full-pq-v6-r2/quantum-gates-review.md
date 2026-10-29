# Chain PQ R2：PoN／W1 与证明系统的独立量子验收门槛

审查日期：2026-10-29。范围：当前工作副本
`/workspace/scratch/52b001730263/chain-pq-integration` 的实际源文件，以及下列一手文献。
文中源码路径均相对这个根目录。本轮只读审查；没有编译、运行 prover、执行量子电路、
修改 Rust／协议／参数，也没有把仓库历史实验当成本轮重新通过的测试。

## 结论与实际边界

**不能据此宣称整条 Chain 已抗量子，也不能由“透明 STARK”推导该结论。**
当前实际 Node 接受路径仍完整重放 PNW1；NPQ6 改的是授权／交易 profile，并未换掉
W1、256-bit 票据或周期难度规则。`formal/pon-nakamoto-v1/w1_zkvm` 和 `w1_batch`
是隔离的研究工作区，不是 Node 的已启用证明后端。

源码可确认以下事实：

- `trillionnium/crates/trnm-pon-node/src/store.rs` 的
  `WorkCheckedPacket::verify/verify_with_progress` 调用原 `pon_work::verify`；
  `Node::admit` 与父状态检查仍分别验证真实 parent、所需 target、时间、任务资格、
  M06 执行和根。前置 ticket 检查本身不会签发 `VerifiedWork`。
- `trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs` 实现
  `N=64`、`R=8`、`q=4294967291`，完整 PNW1 长度为 49,188 字节；
  challenge-bound noise、全部 transcript 更新和乘积重建均有实际代码。
  正确矩阵乘法及完整重放不是最低物理成本或量子难度的证明。
- `trillionnium/crates/trnm-pon-node/src/pq_application_v6.rs` 仍要求
  `packet.proof.len() == pon_work::PROOF_BYTES`，内层 header 仍是 318-byte PNH1。
  该 profile 没有接受 RISC Zero receipt 的替代分支。
- 研究 W1 host、独立 hardened verifier、batch loader／final verifier
  均在完整外部 receipt 解码前要求 `Succinct` tag `1`，随后再次调用
  `inner.succinct()`。所审查的这些应用入口**不存在 Groth16 接受分支**。
  RISC Zero 本身提供 Groth16／pairing 功能不等于这些入口接受它。[外1]

下面六项应分别记录验收结果；签名迁移或其中一项通过不能代替其他项。
其中第 1、2 项及第 6 项中的 zkVM 接线要求，适用于将研究证明路径升级为受信后端；
当前原生 W1 共识并没有以这些未启用 STARK 为信任基础。

## 1. 固定证明类型、版本与全部接受入口，保留 Groth16 拒绝

**已实现：**

- `formal/pon-nakamoto-v1/w1_zkvm/host/src/main.rs`：`decode_receipt` 检查
  16 MiB 上限、固定整数编码、无尾随字节和 tag；`verify` 固定 guest image、
  Succinct 类型和完整 public journal。
- `formal/pon-nakamoto-v1/w1_hardened_verifier/src/main.rs`：`decode`／`verify`
  有同类限制；`controls` 显式构造 `groth16_tag=2`、`fake_tag=3`、
  `composite_tag=0` 的拒绝控制。Cargo 启用 `disable-dev-mode`。
- `formal/pon-nakamoto-v1/w1_batch/host/src/main.rs`：`decode`、`load_leaves`
  和 `verify_batch` 固定完整 leaf／batch image，并要求最终无未解决 assumptions。
- staged prover 内部有 typed Composite／segment／lift／join 中间对象；
  它们不是完整外部 W1 最终接受分支。`verify-recursion` 命令明确输出
  `complete_w1_claim=false`，不能将其进程 exit 0 当成完整 W1 通过。

**仍需独立验收：** 在任何未来共识接线中，固定唯一允许的 receipt family、
hash suite、verifier parameters／control root、guest image、SDK／锁文件与升级规则。
禁止把 SDK 通用 `Receipt::verify` 直接暴露成“任一 receipt 类型通过即可”的入口。
Groth16 是 pairing-based 方案；它不能充当此处的 PQ 兜底。[外1][外2]

版本尤其需要拆开：原 host／guest 仍固定 `3.0.3`，hardened verifier 和 batch host
固定 `3.0.6`。仓库的
`evidence/pon-w1-verifier-hardening-20261028/paired-result.json` 保留了一项旧版接受、
新版拒绝的外部 `control_id` 单字节变更；它与上游 #3687 的绑定修复一致。[外3]
这是特定元数据绑定回归，**不是任意完整 W1 伪造证据**，也不是其他版本问题都已排除。
必须在实际部署 verifier 的完整 receipt 入口重做这组负向控制，不能继承旧 host 的通过。

## 2. 对精确 STARK／Fiat–Shamir／递归组合给出 QROM 安全论证

**已实现：** `formal/pon-nakamoto-v1/w1_zkvm/relation/src/lib.rs::native_replay` 调用完整原生关系，
不是采样检查；guest 暴露完整 header、trace、ticket、既有 work ID 和全部 C。
研究代码确有真实 STARK 生成／验证接口，proof randomness 不进入 PoN 票据。
历史完整证明报告在 `evidence/pon-w1-complete-succinct-20261028/README.md`；
这里只读取该历史记录，没有重跑其密码验证。

**未闭合：** 仓库没有在上述实现旁提供精确配置的完整量子 soundness 推导。
`formal/pon-nakamoto-v1/w1_zkvm/host/src/main.rs` 自身输出 `quantum_soundness_qualified=false`。
“无可信设置”不直接回答量子对手能否操纵多轮 transcript、承诺和挑战。
一般的 Fiat–Shamir QROM 定理有其协议、量子知识／soundness 和额外性质前提；
不能只因引用某个定理，就自动覆盖当前多轮 STARK、所有递归程序和所用哈希。[外4]
RISC Zero 的 2023 官方说明也明确区分 IOP 分析和经 Fiat–Shamir heuristic 得到的
非交互协议结论；那份文档不是当前 3.0.x 配置的逐项 PQ 证书。[外5]

**通过条件：** 输出并固定 base／recursion／resolve 的实际 field、扩域、FRI
查询／扩张参数、允许的 segment size、哈希及输出宽度、grinding 预算、
control-root 和组合层数；给出具体量子安全界及误差累积，区分已证明界和猜想界。
覆盖恶意 prover 的自适应、多目标和跨 proof grinding，以及承诺／挑战域分离。
再对 exact-source verifier 和 guest 做独立审计。不能把“ML-DSA-65”或一个
STARK 参数的名义经典位数借给整条证明链。

## 3. 按用途审计哈希宽度，不能统一称 SHA-256 为“128-bit PQ”

**实际字节：**

- `trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs` 的 `hash` 与 transcript
  使用 SHA-256；challenge、task、ticket、trace 均为 32 字节。
- `trillionnium/crates/trnm-protocol/src/pon_wire.rs` 的 header／block identity、
  账户 archive 分支与其他主协议承诺仍用 32-byte hash。
- `trillionnium/crates/trnm-protocol/src/pq_frame.rs` 已将 `payload_commitment`
  设为 48-byte SHA-384，但 `ml_dsa_65_key_id_from_spki` 仍返回 SHA-256 的
  32-byte key ID。局部扩大 payload commitment 没有迁移全链哈希。

**通过条件：** 给每个字段单独确定它需要的是原像、第二原像、碰撞、承诺绑定，
还是随机预言机／FS 安全；分析多用户和多目标损失、攻击者能选择的输入、寿命与查询量。
在理想黑盒查询模型下，256-bit 单目标原像搜索和通用碰撞搜索的量级不同：
前者为约 `2^128`，后者可为约 `2^(256/3)`；这些只是相应模型的查询量推导，
不是实际量子硬件时间，也不表示攻击者能以碰撞算法替换一个预先固定的根。[外6][外7]

若目标要求更高的量子碰撞裕度，需要显式评审更宽的承诺 profile，并同时迁移
wire、域、树／状态根、proof public input、历史兼容和激活规则。本轮没有这样改动。
不得用新的 manifest 签名掩盖旧承诺的安全界，也不得据一个 `2^85.3` 理想碰撞数字
宣称当前链已经存在实用资金窃取攻击。

## 4. 证明完整 W1 winner oracle 的有效成本，而不只是乘法正确

**已实现与模型假设的分界：** 原 W1 会重建挑战相关低秩噪声，按固定顺序散列全部
prefix accumulator，再验证 C 与 ticket。`pon_work.rs::PreparedTask` 及其相邻
`structured.rs`、maintenance／paired kernels 又说明公共任务准备、C 和部分
算术可以合法复用。一个正确 verifier 的耗时不是最便宜矿工算法的成本下界。

`formal/pon-nakamoto-v1/work_query_bound.py` 的期望 credit 界只针对经典的
首次理想均匀 ticket 查询；文件明确不将它视为物理成本或服务证书。
`formal/pon-nakamoto-v1/quantum_daa_model.py::cost_ratio` 的 `.sqrt()` 是人为给定的量子搜索成本假设，
不是可逆 W1 电路。Grover 的搜索加速适用于相应 oracle 模型，不自动给出此 W1
oracle 的实现、门数或现实吞吐量。[外6]

**通过条件：** 在明确硬件／预处理模型下，评估覆盖完整 task/header binding、
noise rejection、全部 transcript、乘积／ticket predicate 和 uncomputation 的
可逆 oracle；记录逻辑 qubits、T／Toffoli count 与 depth、内存访问、纠错开销和
物理时间假设。同时对 dense／zero／sparse／low-rank／重复任务、跨 nonce／parent
复用和批量策略做经典与量子成本分析。构造一个电路只给算法上界，不能自称最优下界。
中奖后的 zkVM 证明开销要单列；一次常数 post-winner 延迟不是搜索安全定理。

对应合同：`docs/protocol/pon-nakamoto-v1/details/PURE_PON_WORK_SECURITY_MODEL_V1.md`
第 2、3 节，以及 `formal/pon-nakamoto-v1/w1_batch/EXTERNAL_GATES_REVIEW.md`。

## 5. 用实际量子成本模型验收 DAA／chainwork／分叉选择

**确有原生实现：**

- `trillionnium/crates/trnm-pon-node/src/consensus.rs::required_work` 计算
  `floor(2^256/(T+1))`，累计 Work 是溢出受检的 512-bit 整数。
- `retarget` 和 `store.rs::expected_target` 使用真实分支祖先进行周期调整。
  当前开发参数为 16-block interval、10 秒 spacing、150 秒期望跨度、
  `[38,600]` 秒截断、median11、120 秒 future allowance；见
  `config/pon/devnet-v1.json`。这是当前规则，不是 ASERT。
- `trillionnium/crates/trnm-pon-node/tests/daa_adversarial_schedule.rs` 和
  `docs/protocol/pon-nakamoto-v1/details/WORK_COST_DAA_BOUNDARIES.md` 提供原生
  时间／难度边界测试及其证据范围，不能将有限控制误称经济安全证明。

**仍仅研究：** `formal/pon-nakamoto-v1/quantum_daa_model.py` 的 raw-ASERT、MTP-ASERT、固定概率／可变
工作量没有当前 native 激活路径。它执行整数算术，但假定攻击者 baseline rate 为
`0.25`，假定 cost 随 difficulty／work units 线性或平方根变化；没有实际量子
nonce 搜索、原生块接收、网络传播或随机私链成功率。模型文档明确保留这些限制。

若 difficulty 提高 c 倍、链权重提高 c 倍，而真实成本仅约提高 sqrt(c)，权重与
资源可能失配。Bailey–Sattath 给出了 Bitcoin 式设置的相关机制；它不直接证明
W1 可被实际攻击，但足以说明四倍截断、MTP 或更换 ASERT 不能凭名称关闭这个门槛。[外8]

**通过条件：** 将第 4 项的具体资源成本、诚实矿工反应、任务选择、传播／停机、
量子搜索中断和随机性带入真实 fork rule，证明或量化攻击阈值和确认风险；保留
反例和无结论运行。固定 p、按 u 给权重的候选还必须论证新增工作成本如何随 u
增长：若量子成本为 `u^alpha`、`alpha<1`，线性记账仍可再次放大资源优势。
不能直接把现有 chainwork 改为平方根或最长链来“修复”未经论证的模型。

## 6. 独立验收 native 接线、证明收益与恶意输入成本

**当前事实：** 原生 Node 有完整 W1 重放和原有 CPU／journal／恢复 owner；
研究 proof journal 只绑定 W1 子关系。`check_public_journal` 本身不是密码验证，
`verify-recursion`／只完成 segments／未解决 assumptions 也不是完整 W1 证明。
`formal/pon-nakamoto-v1/w1_batch/README.md` 当前仍记载真实 conditional／resolve pilot 未完成，
不能把 parser tests 或编译完成计为 batch cryptographic acceptance。

历史 single-work 报告明确记录过完整 Succinct，但实际收益门槛失败：
`evidence/pon-w1-complete-succinct-20261028/README.md` 给出
256,886-byte receipt 对 49,188-byte native witness，以及该固定输入下 hardened
decode-and-verify 中位数约为原生 replay 的 30.05 倍。它是历史单样本比较，
不是本轮重测，也不是所有硬件／所有规模的通用结论。

**通过条件：** 如果要采用证明加速，必须在明确的新 profile 下接入原 Node，
保持真实 parent、所需 target／时间、PQ TaskV5、M06 与 State／receipt roots 的
全部检查，以及一份逻辑 W1 只增加一次 chainwork。用真实完整 receipts 验收
错误 image／control root／journal、未解决 assumptions、重复 work、撤销／reorg、
重启、deadline 和付款／CPU 记账；测试合法长度但恶意 proof 的验证 CPU／内存上界。
对实际 NPQ6 服务测完整端到端吞吐、尾延迟、prover 集中度和外部节点可复现性，
不能只报 signature 或微基准。若仍采用原生 W1，STARK 接线要求可以保持未启用，
但第 3—5 项及原生恶意输入／网络安全门槛仍然存在。

## 一手参考与适用范围

- [外1] RISC Zero，[Trusted Setup Security](https://dev.risczero.com/api/trusted-setup-ceremony)：
  官方说明 Groth16 包装与 STARK Verify circuit；只用于区分 SDK 提供的证明种类。
- [外2] Jens Groth，[On the Size of Pairing-based Non-interactive Arguments](https://eprint.iacr.org/2016/260)；
  Peter Shor，[Polynomial-Time Algorithms for Prime Factorization and Discrete Logarithms on a Quantum Computer](https://arxiv.org/abs/quant-ph/9508027)。
  这里的工程推论是不能以经典 pairing 路径作为 PQ 接受兜底。
- [外3] RISC Zero，[control_id binding PR #3687](https://github.com/risc0/risc0/pull/3687)。
- [外4] Don、Fehr、Majenz、Schaffner，[Security of the Fiat-Shamir Transformation in the Quantum Random-Oracle Model](https://arxiv.org/abs/1902.07556v4)：
  一般定理及其前提，不是本候选具体 STARK／递归实例的审计报告。
- [外5] RISC Zero，[2023 proof-system draft](https://dev.risczero.com/proof-system-in-detail.pdf)，
  §3.4；该历史说明不替代 SDK 3.0.x 的精确参数核对。
- [外6] Grover，[A fast quantum mechanical algorithm for database search](https://arxiv.org/abs/quant-ph/9605043v3)。
- [外7] Brassard、Høyer、Tapp，[Quantum Algorithm for the Collision Problem](https://arxiv.org/abs/quant-ph/9705002)：
  黑盒查询复杂度与空间时间权衡，不是现实攻击成本估计。
- [外8] Bailey、Sattath，[51% Attack via Difficulty Increase with a Small Quantum Miner](https://arxiv.org/abs/2403.08023v2)：
  Bitcoin 式工作／难度机制的分析，不是本 Chain 的完整攻击实验。

本候选现有 `config/pon/pq-cross-branch-corpus-v1.json` 的
`quantum_pon_hardness_qualified=false`、`production_activation=false`
应继续保留。签名授权、工作成本、证明 soundness、承诺和共识经济安全需要各自的证据。
