# C0 两架构 cost 原始失败诊断

本次只读审阅固定 run **43567821538 / attempt 1**，所测 head 为 **dc42ce4df5cff79cc61c5addbaf01074b56b06ca**，tree 为 **9fda17fed2542b2baccaa34585bb00afd699e12b**。原记录的 source_before/source_after 相同，binary 前后 SHA 相同；所带 Rust 测试源与该 Git head 独立逐字 SHA 比对一致。41372 个 tracked entries 的完整核验是原 CI identity receipt 的记录，本次没有重新读取全仓3.99GB。

## 实际失败与成功范围

两次都通过五个具名 Rust 不变量测试，随后 Python 原严格验收拒绝 **CONFIRMATION_TARGET**，native child exit1。被拒绝的是原四秒内完成独立客户端确认的业务目标。原 Rust stdout 明确将不变量测试通过与该业务目标分开，因此不能据 cargo exit0 写成本或确认资格通过。

| 原观察 | x64 | arm64 |
|---|---:|---:|
| job | 132376957328 | 132376957441 |
| artifact | 14105076236 | 14104567861 |
| baseline 独立 replay records / accepted | 7 / 7 | 7 / 7 |
| pressure 独立 replay records / accepted | **1 / 0** | **5 / 4** |
| pressure 已成功返回的 honest submits | 7 / 7 | 7 / 7 |
| pressure client confirmed transactions | 0 | 0 |
| 最后 replay ended（原 phase ns） | 4000666550 | 4049014763 |
| 原失败 | PUBLIC_REQUEST_DEADLINE | PUBLIC_REQUEST_DEADLINE |

原条件保持 **4000000000 ns、16 workers、7 个诚实签名 packet、depth6**；Host limits 为 cpu.max=25000/100000、burst0、2GiB、swap0、pids256。Host controller failure=null、final_host_errors=[]，不是 Host 准备失败。no_attack_accepted/accounting_closed/receiver_matches_valid_honest_prefix 均为真；压力阶段 full_native_state_equal=false 对应独立 verifier 未完成，不能据此称接受了错误状态。

## x64 单次 replay 的可观察阶段

原 replay 从1.695999260s到4.000666550s，总2304.667290ms，调用线程CPU95.006035ms。page CPU reserve 阶段304.825847ms，56次 reserve 调用中55次预算拒绝，原2ms轮询累计申请睡110ms、实睡300.844881ms。durable begin95.605194ms。packet Work 阶段1796.920567ms、调用线程CPU82.609255ms；其中1099个实际 fresh Host checkpoint 的调用CPU合计78.779013ms、区间wall合计379.990588ms，均已嵌套在 Work 中，不能再次相加。Work 成功返回后仍没有完整Native/M06/output completion资格；最终原 commit 阶段触发绝对deadline。

## arm64 第五次的边界

前四次 replay 成功，每次完整Work均记录1099个Host checkpoint。第五次进入时只剩约247ms；durable begin约95.9ms，page reserve立即获准，并非再次等首个100ms预留。随后Work在337个Host checkpoint后遇deadline，未进入成功admission/commit。原迟归记录被拒绝，没有延长四秒或把迟归算通过。

## 源码与推断边界

实际调用链是 receive_public_page_from_before_observed → Owner::Exclusive → history_import::admit_packet → verify_history_work → WorkCheckedPacket::verify_with_progress → pon_work FullLimb。没有共享Node mutex等待阶段。每个page只提供1个packet，成功页按after推进；本组没有重复重试同一已接受page的证据。

当前history_import已去掉前后相邻、没有native work间隔的旧重复Host读取。每个原W1 progress仍需fresh Host读取；实际boot、调用线程cgroup、fresh parent、五文件limits、regular/nofollow/nonblock和末尾path fence都属于当前合同。不能以这次慢作为删除或缓存这些判断的理由。CPU账本、原绝对deadline、已花费CPU与未完成工作不升格语义同样必须保留。

原confirmation JSON没有每段kernel cpu.stat、off-CPU或syscall时序，所以wall减threadCPU只说明未在该线程消耗CPU的时间，不能直接命名为CFS throttle、磁盘等待或锁。整体wait4记录有大量system CPU与调度切换，仍不足以将它们逐项归给某个checkpoint。算法与低层成本候选由独立源码审阅另出结论；这里不声称已有修复或下一head必然失败。

## 原件完整性状态

封存本摘要时，两个job外层原log和各9个关键ZIP member已完整取得，逐member解压CRC/长度/SHA均通过；两份完整ZIP仍在固定Range/ETag续传，不能称全ZIP digest已经通过。初次120s下载部分、后续0响应连接超时，以及一次本地解析器缺import的失败均保留。未来全ZIP验证只能追加明确完成receipt，不改写此时点状态。

此审阅没有执行native、重跑CI、改源码/refs、cancel或dispatch。
