# 原 campaign History import 的计时边界与下一处可测位置

本次新增事实把三次 baseline 首轮的约 20.5 秒导入，定位到 **9.26–9.74 秒的完整持久化段、5.30–5.44 秒的最后一页激活，以及 3.51–3.67 秒的准备段**。这些区间仍包含各自的检查点、等待和原有完整性检查，尚不能据此确定底层主因，也没有据此成立的安全源码优化。本次只读原证据和固定源码，没有修改仓库、预算或检查覆盖，没有运行新 campaign。

## 证据身份与分母

原测量来自 `0746a462e80067b78317597f2fa4bacf5e3db958`、tree `03c69f3120a84f49fd7a76d9564bba4ef0c4b24e`、二进制 SHA-256 `3afe1ecc5953bb4e5b3066fe07fb11b68a74faac787f4f81c5c15209a97a86f1`，后台为 `authenticated-v1`。输入是已保留的 `campaign0746-outcomes-v2.json.gz`；解压后 2,033,029 字节，SHA-256 `1b95b9e8bee728922480a8e40eb9730e750fc64a4c50c0e5cefe2ced1b38585a`。压缩原件身份、三个原 report 哈希、每条选中记录及全部纳秒数见 [review.json](review.json)。

选择规则是：逐 run 找到唯一的 baseline 和其首个已确认 round，再选择 client 全局起止时间完全落在该 round 内的全部 import。实际各为 7 条、索引 0–6，每条恰有一个 packet；没有按位置剪出前七条。21 条是原审计 **66 条 import 的定位子集**；失败的后续 round、其余模式和未观察到的计划任务仍在原审计分母中。原结果仍是 **0/3 campaign、0/9 phase 达标**。

静态比较对象为 **M5 `3ad605ecdac4b3b123dff83c1cb7458430acd776`**。九份相关源码中七份与 0746 字节相同；History importer 只多了原 Host callback 后的绝对 deadline 复检，CPU 模块只新增 PQ intake accounting 的可用性查询。原测量不能因此升级为 M5 实测。九份文件的双版本长度和完整 SHA-256 均在 JSON。

## 原测量的细分

下表单位为秒。前三行存在包含关系，不能相加；最后一行仅做总区间减去已知两类区间的算术余量，不命名为某种成本。

| 口径 | Run 1 | Run 2 | Run 3 |
| --- | ---: | ---: | ---: |
| 首个已确认 round（总区间） | 22.587234 | 22.601677 | 22.605385 |
| 7 次 client import（含最后激活） | 20.586157 | 20.455300 | 20.469825 |
| 关联的 7 次 History RPC 调用区间 | 0.081459 | 0.142778 | 0.082585 |
| 未归因的 round 余量 | 1.919618 | 2.003599 | 2.052975 |

**0.08–0.14 秒不是整个 round 的全部网络耗时，也不是纯线上传输或 RTT。** 该字段原本是每个 `Request::History` 的 `elapsed_wall_ns`，包围 protected RPC 调用及部分客户端结果/请求序列化。round 还先对七个业务 packet 运行 `Request::Submit` 循环（允许重试），导入后单独做 confirmation；这几段未包含在该 History RPC 合计中。依据：[RPC wrapper](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-pon-node/tests/support/multiprocess_support.rs#L243)、[round/Submit/History 调用顺序](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs#L998)。

对 21 个 packet 内部区间进一步汇总：

| 已有 native span 的 wall 区间 | Run 1 | Run 2 | Run 3 |
| --- | ---: | ---: | ---: |
| 完整 W1 work（7 次） | 1.346330 | 1.629238 | 1.666239 |
| admission_prepare（7 次） | 3.586564 | 3.510313 | 3.669358 |
| execution（7 次，含 root_commitment） | 0.009199 | 0.087796 | 0.009213 |
| commit（7 次完整持久化段） | 9.744349 | 9.262328 | 9.358990 |
| submit_result（1 次，最后一页激活） | 5.435483 | 5.397492 | 5.299740 |

表中五行是经区间核对后可分开的不同阶段。`admission` 是 prepare/execution/commit 的父区间，`root_commitment` 是 execution 的子区间，故未再相加。page/packet `history_import` 也只作父区间核验。所有实际进入的 **360 个 span** 均完整、有 CPU 和 wall 值，native `measurement_failures=0`；所有选中 Host 槽也完整。每个 observer 内的父子包含及所选叶区间不重叠已逐项核验。未分配的 page wall 余量仍保留：三 run 分别约 0.001865、0.079797、0.001824 秒，没有剪裁或摊给某个阶段。

七次 client import 的调用线程 CPU 分别为 4.667153、4.649522、4.649265 秒。它不含 scoped worker 的完整 CPU。Host 计量也嵌在原阶段内，并可能来自不同调用线程；不与这些 CPU 相加。wall 与 CPU 的差不能直接解释为 refill、磁盘或某一类等待。

## 源码收窄了哪些解释

### 1. `commit` 覆盖整个持久化/读回段，不能命名为 SQL COMMIT

[execution_observation::run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-pon-node/src/ingress/execution_observation.rs#L46) 先执行原 progress hook，成功后才改变阶段边界：`BeforePersistence` 结束 execution、开始 commit，直到原 action 返回。`persist_admission_execution` 在此后执行原事务、块/祖先/delta 写入、实际 delta 和 packet 字节读回、父/子 `state_at_with_readback` 比较、最终 active-state 与原 writer/snapshot 栅栏，再调用 `tx.commit()`。因此 9.26–9.74 秒内既有存储工作，也有完整读回和检查点。

现有源码已经围绕真实 `Transaction::commit` API 建了更窄的 observer，见 [持久化与最终 SQL 调用](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-pon-node/src/store.rs#L5103) 和 [SQL commit 独立观察器](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-pon-node/src/store/native_authenticated/history_arithmetic.rs#L473)。即使取得这个计量，它仍是 API 区间，不能直接视为物理 fsync。当前数据不支持更改同步策略、跳过读回，或将完整性检查当作可删除的重复工作。

### 2. 最后一页激活与 admission 连续，但有独立区间

每组七包只有最后一个 packet 的 `submit_result` 进入，且位于 admission 返回之后。[admit_packet / activate_packet](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-pon-node/src/ingress/history_import.rs#L292) 使用同一已付费 operation、同一个原绝对 deadline，调用 `activate_observed_with_termination`；没有新开一份预算。激活内部先检查 observed history，再走原 activation/reorg 路径，见 [实际激活入口](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-pon-node/src/store.rs#L6667)。5.30–5.44 秒是这一完整入口及其前后检查点的区间，尚未分成历史校验、读回、reorg 和实际 SQL API 的各自耗时。

### 3. 显式 `cpu_wait` 很小，不能排除稍后的 refill 等待

显式 `CpuWait` 只包住 `begin_cpu`；所选七页的 page 级合计约 0.402 秒，packet 级合计约 0.00035 秒。这个字段没有囊括所有后续等待。源码在完整 W1 形成 verified completion 后，允许 exclusive History 的原检查点在 `LiveRequestCpu::observe_with_control` 内按同一预算继续等待，每轮 sleep 至多 5 ms，仍反复检查原资源与绝对 deadline。原 refill 是 0.25 CPU 秒/秒；冷远程 History epoch 为 Node 级账户，不是逐页、逐 peer 重发的额度。依据：[begin_cpu / metered_observed](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-pon-node/src/ingress/history_import.rs#L168)、[实际 refill 等待分支](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs#L686)、[Node 级冷账户](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs#L968)。

这些等待会记在当时外层 prepare、commit 或 activation 等区间内。**本记录只确认该分支在源码上可发生，没有量出它在这些样本中实际发生了多少，更没有将它定为主因。**

### 4. 本组客户端走 `Owner::Exclusive`

[公开接收 wrapper](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-pon-node/src/ingress.rs#L2576) 明确把本地 verifier 作为 `Owner::Exclusive` 传入。因此 shared Node mutex 的 `try_lock` 等待分支不能用于解释这些 import。这个结论不排除其他锁、IO 等待或调度暂停；它只排除被误套到本样本上的那一个分支。

## 已有快照与最小下一份证据

原 harness 在 phase 前后保存 `client_native_history_arithmetic_before` 和 `client_native_history_arithmetic_after`；其中已有 16 个 native History stage 和四个实际 SQL commit site：`admission_persistence`、`atomic`、`reorg_step`、`reorg_termination`。见 [原报告写入点](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs#L1274)、[完整 observation 字段](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-pon-node/src/store/native_authenticated/history_arithmetic.rs#L342)。这些是嵌套的累计观察，不能把 16 行相加。

本记录冻结时，保留的 v2 摘要没有这两个原字段，本地完整报告尚不可读。原 ZIP 曾核验后删除，root 已授权另行只读回收同一远端 artifact `13662172930` / run `42591962205`；若回收成功，会把原快照与解释另存补充，不修改这份先前记录，也不称为新跑。**整个 phase 的 before/after 差包含失败的后续 round，不能冒充上面首轮七包的细分。** SQL observer 的 unknown、failed、abandoned、unwinding、in-flight 和 observation_failed 也必须保留。

最小的后续工作有清楚的顺序：

1. 先读取已存在的原 native/SQL 快照，核对原件哈希与生命周期，再在其真实 whole-phase 范围作差。没有必要先重造一个 SQL timer。
2. 若之后获准做正常 baseline profiling，只在上述真实 refill 等待分支记录受限的原 operation 级进入次数与实际 sleep 区间，并关联现有阶段。保持原资源 callback、deadline、错误优先级、收费和 refill 常量；完整记录观察开销与未知值。不能用 wall 减 CPU 冒充实测 sleep。
3. 用已有 native stage 定位读回与 activation。若仍不足，再给原 `state_at_with_readback`、最终 active/owner 栅栏、observed-history/activation/reorg 边界增加观察；保留所有原字节/状态比较、事务身份检查、失败/取消记录与 durable fact 语义。仅凭这些区间不能合理地增加缓存或减少 Host/签名/检查点覆盖。

这里没有建议放宽 CPU 域或服务预算。原 Host **4 秒**约束及独立 **30 秒** campaign 继续作为原验收口径；研究 watchdog、单独 proving 时间和当前源码静态相同均不能替代它们。

## 计时核验的一个实现细节

`ClientOperationStamp` 分别读取全局 monotonic 端点与 `Instant::elapsed`，它们不是同一次 clock sample。本次分析首个预检曾错误要求两者严格相等，在写出报告前拒绝；核对原源码后保留两个原值及其差（实际为 −10 至 +30 ns），仅用全局端点作 round 选择/排序。native span 仍要求原端点与 wall 严格一致，完整性和不重叠检查均保留。具体两次分析 attempt 写入 JSON，原始输入没有改变。
