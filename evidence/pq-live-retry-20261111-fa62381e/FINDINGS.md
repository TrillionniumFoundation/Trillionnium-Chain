# S2 原始 native campaign：三次真实失败的只读取证

## 结论

三次预先声明的完整 campaign 都真实失败。每次都是 baseline 完成 1/3 个原定签名确认轮次，from-zero 和 late-product 各完成 0/3。九个 phase 都在同一个原定 30 秒窗口内的 History 导入路径返回 `PUBLIC_REQUEST_DEADLINE`；所有六个攻击 phase 都没有观察到原判据要求的真实 paid-credit depletion。

这是一组固定资源条件下的业务资格反例。现有证据没有证明它是本轮账户范围守卫或 witness retry 修复引起的回归，也没有证明可把它解释成偶发基础设施失败。Host 检查与 authenticated account graph 是已有观测中明确的耗时位置；尚未建立一个可直接合入、保持所有原安全边界的最小修复。

本文件及结构化摘要只解释既有记录。没有执行新的 Cargo 构建、原生测试、参数调整或源码修改。证据采集成功不改变原生 FAIL。

## 原始身份

- Commit: `3c98e08e92094bb79ac811b682192d7252a7c325`
- Tree: `34f4288927ec5e08430f7b2516db909859fab075`
- [GitHub run 43026071397 / job 130540971588](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43026071397/job/130540971588)
- [原 artifact 13858366171](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43026071397/artifacts/13858366171)
- 原 ZIP：75,865,526 bytes，SHA256 `7250117547e038c408cb9400d76759777f578c67979f0d0e3353dd7ee5051945`。
- 原实际 release libtest ELF：SHA256 `b45215393abf3b311edc0146754f83c2a2a360a210c714eb225605642e234a26`；原运行器记录的前后哈希相同。没有在本次取证中执行或复制该 ELF。
- 原命令：Cargo 1.95.0，`--locked --offline --release -p trnm-pon-node --test public_v3_multiprocess separate_process_work_and_signed_confirmation_campaign -- --exact --ignored --nocapture --test-threads=1`。
- 原构建 226.534931402 秒成功。三次运行分别 112.951295077、112.783080039、112.469937324 秒，全部原生退出码 101；原 600 秒外层时限未触发。
- 原输入保持 1,024 次签名 seed transfer、4 seed block、21 business block、三种 phase 各 30 秒、攻击者数量 0/24/24。
- 原控制器 CPU 上限 400%；receiver 和 verifier 同处原固定 public Host 父 cgroup，CPU 上限 25%、内存上限 2 GiB。

原 raw report、stderr、producer economics、准备报告、source/resource/compiler 记录均由原 ZIP 原样取出，逐项与其 `artifact-files.json` 的大小和 SHA256 比较。原 ZIP 本体单独保留在取证目录，压缩证据包不再包含该 ZIP 或编译产物。

## 三次结果

| 原 campaign | baseline | from-zero | late-product | producer economics | 原 native 结果 |
|---|---:|---:|---:|---|---|
| 1 | 1/3 确认 | 0/3 确认 | 0/3 确认 | complete=true | exit 101 |
| 2 | 1/3 确认 | 0/3 确认 | 0/3 确认 | complete=true | exit 101 |
| 3 | 1/3 确认 | 0/3 确认 | 0/3 确认 | complete=true | exit 101 |

以上分母是业务轮次，不是独立 libtest 数量。三个原生 libtest 各执行一个完整 campaign，均失败。

每份 stderr 的第一个 panic 都在 `public_v3_multiprocess.rs:1765`，即原 `finite experiment criteria` 断言。第 1541 行是捕获后保留失败材料并重抛，不是另一个独立首因。原 source 的 [判据组合与最终断言](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3c98e08e92094bb79ac811b682192d7252a7c325/trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs#L1744) 完全保留。

原报告无 phase startup error，报告回读验证没有失败。24 个攻击者全部 ready；各攻击者均正常返回，没有达到原 attempt cap，也没有被 parent 强制 kill。所有攻击响应保持非 ok。各 phase 的 mutation CPU clock failure 都为 0，最终 in-flight 为 0，没有 accounting unavailable。

Campaign 2 的 late-product 另外记录 `measurement_failures=1`，使 observer coverage 不完整；capacity=16384、accepted_connections_seen=2263、records_not_retained=0、counter_overflow=false。它是另一个真实未满足条件，未被忽略，也不是解释全部三次失败的共同原因。

## 30 秒窗口内停在哪里

原 [History 循环](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3c98e08e92094bb79ac811b682192d7252a7c325/trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs#L1032) 把同一个 absolute import deadline 传入普通完整 importer。该 deadline 在整个 phase 开始时建立，未给后续 page 新开 30 秒。

- 每次 baseline 发送并接受 14 个 business packet；14 次 History import 中 13 次成功。第 14 次对应第二轮完整页，在 `submit_result` / 激活路径上触发 deadline。第一轮已经确认，第三轮没有进入。
- 每次攻击 phase 接受 7 个 business packet；7 次 import 中 6 次成功。最后一次多数在激活边界结束；campaign 2 的两个攻击 phase 更早在 admission/commit 边界返回 deadline。第一轮未完成确认，余下两轮没有进入。
- 九个 phase 的 History import 调用 wall time 总和为 24.51–25.28 秒；其后已无足够原窗口完成剩余业务。最终 receiver/client state 不相同与未完成导入/激活同时出现；这些记录本身不能证明账本状态被错误接受或发生持久分叉。

可复核的结构化逐项记录见 `history-attribution-summary.json`。它保留最后一个 import 的开始/结束、原错误、packet 阶段及独立 Host 计数。

## 已定位的源代码与耗时位置

调用链为：

1. [receive_public_page_from_before_observed](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3c98e08e92094bb79ac811b682192d7252a7c325/trillionnium/crates/trnm-pon-node/src/ingress.rs#L2581) 在 resolve、initial、native checkpoint 和 final 上执行原 Host 检查。
2. [History Control.check](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3c98e08e92094bb79ac811b682192d7252a7c325/trillionnium/crates/trnm-pon-node/src/ingress/history_import.rs#L28) 先检查原 deadline，再检查 Host，再检查 deadline，拒绝晚到的成功。
3. [admit_packet 与 activate_packet](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3c98e08e92094bb79ac811b682192d7252a7c325/trillionnium/crates/trnm-pon-node/src/ingress/history_import.rs#L334) 把同一个 progress/Host 检查传入真实 W1、admission、commit 和 activation。
4. [verify_state_with_readback](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3c98e08e92094bb79ac811b682192d7252a7c325/trillionnium/crates/trnm-pon-node/src/store/native_authenticated.rs#L674) 对未获得既有受限 readback 复用的情况执行当前完整 SQL account graph 检查；原进度边界保留。
5. [KernelBudget.check](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3c98e08e92094bb79ac811b682192d7252a7c325/trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs#L336) 每次重新观察 boot ID、原父目录身份/权限、当前调用线程 cgroup 和五个限额文件。现有源码已经使用 stack buffer，并明确不缓存描述符、文件内容或先前资源判断。

三个 baseline 的 Host checkpoint 次数为 164,864、165,143、164,194，单独记录的 Host CPU 分别约 4.093、4.108、4.109 秒。Campaign 1 的 client native `account_graph` 阶段记录 122 次调用、17.114 秒 wall；整个 `verify_state` 的 wall 为 17.884 秒。相邻及父子阶段是嵌套记录，不能相加，Host 跨调用线程 CPU 也不能直接当作 importer 当前线程 CPU 的百分比。

内核观测同样显示固定上限在实际约束运行：baseline 有 333/347、334/348、334/348 个 period 被 throttled；攻击 phase 有 351–354 个 throttled period，总 period 为 353–355。该事实支持在原固定资源条件下分析进度成本，不构成提高 CPU 配额的授权或理由。

## paid-credit depletion 仍是独立资格缺口

六个攻击 phase 的已观测最低剩余 paid credit 在 1.974755349–1.983386118 秒附近；原 start reserve 是 0.1 秒，burst 是 2 秒。所有攻击 phase 的 `genuine_budget_depletion_observed` 和任一轮内 depletion 都为 false。

原 [paid_depletion](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3c98e08e92094bb79ac811b682192d7252a7c325/trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs#L302) 要求实际 paid-credit identity、低于原 reserve、真实已付 CPU debit，并拒绝未知时钟。物理 cgroup throttling、排队或 booked reservation 都不能替代这个判据。

因此，即使后续性能修改使三轮按时确认，也必须另外满足原真实 depletion 与重叠判据。这里没有把“观察到 CPU 限流”等同于“已付 credit 耗尽”，也没有从有限实验推出 W1 或量子挖矿安全。

## 是否适合立即修复

已有记录支持把后续工作集中在 authenticated account graph 的重复完整读取成本、History admission/commit/activation，以及 Host 每次真实检查的成本。它们尚不足以证明可安全删除某个 checkpoint、缓存某个 Host 结果，或扩大现有 readback 权限范围。

可保持原资源和判据的候选必须满足：只减少已证明等价的重复实现工作；保持每个原必要进度点、完整当前状态验证、原 SQL/readback/rollback 边界、同一个绝对 deadline 和原真实 CPU 计费。现有 scoped readback 是可进一步审查的机制，不能凭本次耗时观察增加复用资格。没有在冻结 S3 上实施任何候选，也没有声称已有可合入修复。

后续候选的验证应包括：原 Host 替换/迁移/配额变化与 late-success 拒绝控制、原 state/readback/rollback 负对照，以及同一固定资源、30 秒、0/24/24 攻击者、1024/4/21 输入的三个完整原 campaign。每次必须真实完成全部原确认、depletion 与覆盖条件；旧失败继续保留。

## 取证尝试与边界

先尝试了 HTTP Range。18 次响应都为 206，下载 422,007 bytes，取得八个小成员。临时取证脚本对单成员设置了 1 MiB 压缩、8 MiB 解压上限；`run-1-raw/report.json` 的实际压缩大小为 3,246,146 bytes、解压大小为 43,777,179 bytes，因此脚本拒绝继续，job `1a1caf268fe-2564-945` 退出 1。这不是 Range 不受支持，也不是 native 失败。其 stderr 回收曾发生 MCP 超时，最终已取得真实首因，早期未知记录仍保留。

经协调授权后下载完整原 ZIP，大小和已发布 SHA256 均匹配；所有选取成员再按原 manifest 核验。初次本地展开也因临时 16 MiB 单报告上限停止；随后按已知原大小流式读取、核验完整 raw report，未重新运行任何实验。采集和解压限制均未成为业务判据，也未修改原运行条件。
