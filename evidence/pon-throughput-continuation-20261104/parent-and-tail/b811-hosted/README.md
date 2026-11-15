# b811 原始 hosted F0 / 三批 campaign 读回

本包只记录已完成的 clean head **`b8116f65789a85148254f870c678a44f895316de`**，tree **`fba28b3870da952db979d4a7ea2ba1b0ee207134`**。两项任务的 source-before/source-after 均逐字相同，`kind=head`、`base=null`、`prospective_merge=null`。它们没有测量当前本地 dirty 候选。

入口：[summary.json](summary.json)、[artifact-manifest.json](artifact-manifest.json)、[SHA256SUMS](SHA256SUMS)。

## 原始结果与完整分母

| 原始任务 | native 退出 | 原 30 秒窗口确认 | 已观测 / 计划轮次 | 另列的四秒结果 |
|---|---:|---:|---:|---:|
| F0 | 101 | **1/6** | 3/6 | **0/6** |
| campaign 第 1 批 | 101 | **1/9** | 4/9 | 0/9 |
| campaign 第 2 批 | 101 | **1/9** | 4/9 | 0/9 |
| campaign 第 3 批 | 101 | **1/9** | 4/9 | 0/9 |
| campaign 三批合计 | 三次均 101 | **3/27** | 12/27 | **0/27** |

未执行到的计划轮次仍在分母内。每个 phase 预设三轮，时间为 t=1、5、9 秒；此常量及时间表达式从同一 b811 源码核对，[来源身份](denominator-source.json)。campaign 四秒结果是按同一固定时间表另算的诊断，不替换其原始 gate。网络 ACK 也不等于确认。

F0 的实际 reader failure 是 `BASELINE_MUST_PASS`，native failure 为 `NATIVE_F0_FAILED`。baseline 第 0 轮在 23.676604 秒确认；第 1 轮直到 23.676615 秒才开始并在 30.070615 秒结束，未确认；第 2 轮未执行到。ROOT 压力 phase 仅第 0 轮被观测且未确认，其余两轮未执行到。它的原始结果不是旧 40a 的 0/6。

三批 campaign 都只有 baseline 第 0 轮确认，分别在 21.306570、20.798219、21.299854 秒完成。其余 baseline 轮次和两种攻击 phase 没有确认。三批原 `finite_experiment_criteria_met` 均为 false，外层 `ORIGINAL_THREE_RUN_CAMPAIGN_FAILED`；原 report reader 没有格式验证失败，phase startup errors 与 finalization failures 均为空。这是保留业务负结果，不是把 reader 失败当成功。

## 客户端 replay 时间链与具体失败

| phase | replay 调用 / 成功 / 失败 | replay wall | replay 当前线程 CPU | Host 调用 / CPU | account_graph 调用 / CPU / wall | SQL commit API wall |
|---|---:|---:|---:|---:|---:|---:|
| F0 baseline | 10 / 9 / 1 | 24.969 s | 5.666 s | 101,536 / 4.823 s | 73 / 4.190 s / 17.875 s | 153.974 ms |
| campaign 1 baseline | 11 / 10 / 1 | 25.608 s | 5.929 s | 116,007 / 5.173 s | 80 / 4.369 s / 18.636 s | 20.731 ms |
| campaign 2 baseline | 11 / 10 / 1 | 25.415 s | 5.882 s | 118,162 / 5.112 s | 82 / 4.357 s / 18.696 s | 21.655 ms |
| campaign 3 baseline | 11 / 10 / 1 | 25.368 s | 5.829 s | 116,033 / 5.048 s | 81 / 4.289 s / 18.479 s | 19.561 ms |

这些是各自原始 phase 内的观测。完整 before/after、逐页 fetch → replay 时间、page/packet phases、具体错误和每个 counter 的差分均保留在下方四份 derived readback。**这些计时嵌套，不可把 Host、account_graph、packet commit 或 SQL commit 加到 replay 总耗时上。** `commit` phase 包含更大的原生工作，不能等同于 `Transaction::commit` API。Host CPU 也不是完整 worker CPU。

F0 baseline 的最后一次 fetch 在 29.893687 秒结束，随后 replay 在 29.893709 秒开始、30.070468 秒结束：失败发生在独立客户端的 packet `work` / `history_import`，错误为 `PUBLIC_REQUEST_DEADLINE`，不是该 fetch 失败。前三批 campaign 的 baseline 最后一次 replay 都在 admission/commit 路径触及同一截止时间；六个攻击 phase 也各有一次 replay deadline。campaign 1 late-product 的末次错误在 packet work，其余五个攻击 phase 的末次错误在 admission/commit。完整失败与成功页均保留。

**F0 ROOT 压力 phase 是另一个阻塞点：0 次 History、0 次客户端 replay。** 原始 honest 提交共 15 次尝试，4 次成功 ACK；其余为 8 次 `IO: Resource temporarily unavailable (os error 11)` 和 3 次 `FRAME_DEADLINE`。不能将这一臂归因到一个根本没有执行的客户端 replay。该 phase 有真实 signed ROOT 拒绝与 accepted-work/admission-refusal 重叠证据；hostile packet 的 live/cold absence、cold-state equality 和 paid CPU reconciliation 为 true，但合法计数/tip 与原确认要求不满足。

另保留一项观测缺口：campaign 1 的 from-zero phase `observer_complete=false`、`measurement_failures=1`，记录 135 的 `observation_failed=true`；没有把它改写为完整覆盖。各 campaign phase 都未观察到满足原谓词的 paid-credit depletion。

## 实际预算、硬件与清理

原 controller 为 `cpu.max=400000 100000`、16 GiB memory.max、nice 10。receiver 与独立 verifier 共处原 `trnmponpublic.slice`，上限 `cpu.max=25000 100000`（0.25 CPU）、2 GiB memory.max、swap 0、pids 256；调用方和攻击者仍在 controller 域。原 mutation CPU burst 为 2 秒、refill 为每秒 0.25 CPU 秒，phase 30 秒、M06 worker 1。实际 inside-before/after 和 controller resource 文件保留。它们是资源上限，不是预留物理算力。

两个任务都是受控同机 loopback，各自报告四个逻辑 CPU、x86_64、kernel 7.0.0-1017-azure，但两者 boot ID 不同。本包没有跨主机 ABBA、WAN、独立运营者、PQ 整链或生产吞吐资格，也不据这些轮次推断某项本地优化的因果效果。

F0 finalization 报告三个 service 均 known-empty、ownership-validated、无 cleanup failure；总 complete_success 为 false，保留原业务失败。campaign 只按其原结果记录 finalization_failures 为空，不用它替代 F0 的独立 known-empty 证明。

## 原始材料与可复核投影

- [F0 官方 run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41795900044)；[原 artifact](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41795900044/artifacts/13305647421)。
- [Campaign 官方 run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41795899819)；[原 artifact](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41795899819/artifacts/13304684338)。
- F0：[source-before](f0/source-before.json)、[source-after](f0/source-after.json)、[原 execution results](f0/execution-results.json.gz)、[原 finalization](f0/finalization-result.json.gz)、[原 stderr](f0/native.stderr.log)、[raw report 投影](f0/report-raw-projection.json.gz)、[逐页计时与差分](f0/report-derived-readback.json.gz)。
- Campaign：[原 results](campaign/results.json)、[source-before](campaign/source-before.json)、[source-after](campaign/source-after.json)。
- 第 1 批：[原 result](campaign/run-1-result.json)、[原 stderr](campaign/run-1.stderr.log)、[raw 投影](campaign/run-1-raw-projection.json.gz)、[逐页计时与差分](campaign/run-1-derived-readback.json.gz)。
- 第 2 批：[原 result](campaign/run-2-result.json)、[原 stderr](campaign/run-2.stderr.log)、[raw 投影](campaign/run-2-raw-projection.json.gz)、[逐页计时与差分](campaign/run-2-derived-readback.json.gz)。
- 第 3 批：[原 result](campaign/run-3-result.json)、[原 stderr](campaign/run-3.stderr.log)、[raw 投影](campaign/run-3-raw-projection.json.gz)、[逐页计时与差分](campaign/run-3-derived-readback.json.gz)。

两个 ZIP 的实际 size 与 SHA256 在读回时再次独立核对；四份完整 raw report 的 hash 还逐项匹配原 runner results。`artifact-manifest.json` 区分逐字复制的 archive member 与 JSON-pointer 投影。投影保存选中原值，并逐项回查原报告；它不是完整报告，也不冒充原始空白格式。全报告及未重复保存的累积采样、状态行和 payload 仍在明确标识的官方 ZIP 中。

每份 derived readback 保留整数纳秒，原生累积计数按同一 phase 的 after-before 计算，缺失轮次不会被删除。读取和整理本包没有重新运行 native、Cargo 或任何业务实验。

```bash
sha256sum --check SHA256SUMS
```
