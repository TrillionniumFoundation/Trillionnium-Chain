# C6 实际超时、退款、重组与独立冷恢复

本包记录冻结 C6 源码上的一个新 provider/M12 operation：昂贵 zkVM 进程实际启动后，按预声明的原始 120 秒 deadline 自然终止；实际 owner 先写入 `Failure Unknown`，再作显式取消并经研究 Node 执行 NativeCancel；有效替代分叉移除该取消，实际关闭并重开 Node/M12 后仍不重派，再恢复同一原始 Cancel 的 canonical ancestry。另一个独立进程完成冷恢复。主实验 **1 PASS / 123.43 秒**，独立冷恢复 **1 PASS / 0.35 秒**。

**资金与身份范围必须按独立研究 fixture 解读。** 本次 provider/M12 operation、statement、Node 数据目录、target 与输出目录均为新域；研究 Node 使用确定性 fixture 重建，因此 NativeTask 的 Cancel operation ID、wire、packet 和相关 canonical block bytes 与 C5 相同。本次没有打开或重放 C5 的 Node 数据库，没有向全局链发交易，也不能把 C5、C6 的研究本金退款相加为新资金收益。该范围区别保留在原始 plan/config、NativeTask 记录和本包 manifest 中。

**M12 的 `Done` 只表示派发生命周期终结。** `Failure Unknown` 的 `consumed=null`，原完整资源 cap 保留；GPU 与完整历史进程回收、完整资源计费仍未知。没有正向 provider 付款，没有新完整 proof，也没有完整 W1 winner header 的真实 Node admission 资格。旧 Pending 操作保持各自旧证据状态，本包没有追溯改判它们。

## 精确绑定

| 项目 | 本次实际值 |
| --- | --- |
| 执行源码 commit | `2bdd252aa6c300b7431b9ee897b254b7953cf562` |
| 执行源码 tree | `ac3cb7171c429fa5e12e29ee16839fa6f49f1b81` |
| Provider/M12 operation | `8058cfa81675504da3f0593b8df7c51cb0b1f3fd6db1daa4d3f83172a6d4eacc` |
| W1 generation statement | `52a53b4c6264f99141cda3d84ee5793dbd9a21778693848435809fbcd3fd4ca6` |
| Target job | `142e5b9c67fd1078cc1ecc29ac16152451829f41c22bcbae80cba6dd79a52ff1` |
| 主 Hepta job | `1a1b9fa4d54-12894-17e1`；succeeded / exit 0；output complete、durable |
| 独立 cold Hepta job | `1a1b9fdb57b-12894-17ef`；succeeded / exit 0；output complete、durable |
| 新实验根 | `/home/qian-qi/work/chain-w1-c6-timeout-reorg-20261108-ec265b-01` |
| Plan SHA-256 | `c38c7d6105d8658e5eb2403c9e990b902902a0073d19e9d499b33f28ccee044d` |
| Config SHA-256 | `20750c225e152c99ac19e05bb891b87bca01b8e451a752f405340be03128a7ea` |
| Boot ID | `14f92beb-43c6-4786-839e-b57307ae8048` |

本包只归属于上表的 C6 源码。它不把后续上游 commit 视为已完成同一运行验证。构建资格与失败保留路径见 [preparation provenance](raw/preparation-provenance.json)：owner 和 native 使用各自独立空 Cargo target 起点，但复用既有 registry/toolchain；backend 复用从 C5 复制、且经历 C6 第一轮 timeout/124 的 cache，`fresh_cargo_target=false`。原 backend 失败和原 core 的两项失败均保留，新资格或隔离复核没有改写它们。

## 原 deadline 与真实昂贵启动

实际 parent allocation 为 CPU quota `800000/100000`、MemoryMax `8589934592` 字节，CPU affinity 为 `[8,9,10,11,20,21,22,23]`。Proof plan 保持 segment workers 2、compression workers 2、Rayon threads 4。原研究预算是 `120000000000` ns；后续的只读终态观察与冷恢复不延长 proof deadline。

| 事件 | 同一 boot 的 monotonic ns |
| --- | ---: |
| 选择唯一原始 deadline 的时刻 | 1199223004629858 |
| live r0vm 已实际被观察 | 1199255881430349 |
| 原始 proof deadline | 1199343004629858 |
| target 记录的终止时刻 | 1199343395352233 |
| typed Failure Unknown 被写入 | 1199345481705597 |
| 显式 owner veto 被请求 | 1199345486900409 |

原始 deadline 到 target 终态相差 **390722375 ns = 0.390722375 秒**。这是超时终止与清理观察的延迟，不能当成完整 proof 完成时间；主测试的 123.43 秒还包含终态读取、取消、退款及重组验证。

live 启动原件固定 `prove-batch-0000` 的 r0vm PID `3668546` / birth `119925536`、其 runner PID `3668215` / birth `119925002`、两者实际 executable hashes、affinity、当前 child cgroup 与预先准备的 full-execution manifest。它不是只凭 controller 日志推断昂贵生成已启动。[启动原件](raw/run/owner-cancel-start/result.json)与[原 deadline 等待意图](raw/run/owner-timeout-wait-intent.json)均保留。

target 的真实终态为 `cause="original-deadline"`、`exit_code=-9`、`sticky_cancel=false`。此时尚未发生 owner veto，也没有 target cancel request；资源 `gpu_ns=null`、`memory_peak_bytes=null`、`resource_qualification="unknown"`。[主结果](main-result.json)保留完整 target readback。

## 终态、资金与分叉顺序

1. 原始 deadline 使已启动的生成终止，runtime 提交实际终态观察及父调用者等待结果。
2. 新 typed terminal adapter 记录 `Failure Unknown`。记录中的 `cancellation_at_failure=null`、`consumed=null`、`provider_payment_authorized=false`、`native_refund_authorized=false`，原 cap 保留。其时间戳早于显式 owner veto。
3. 研究 owner 发出显式取消；实际 Node 接受普通 NativeTask tag 3，canonical 记录给出 **gross 本金 1000**。超时本身与 GPU unknown 都不是退款授权。
4. 实际有效替代分叉移除原 Cancel：资金行回到 `Reserved / remaining=1000`，`refund_claim=false`。在这个分叉上实际关闭并重开 Node/M12，M12 仍 `Done`，不重派。
5. 通过合法分支扩展恢复同一原始 Cancel ancestry；不重新签 wire、不提交第二笔 Cancel。原 Cancel 观察、恢复后观察、主结果最终观察、独立冷恢复观察全对象相同。
6. 独立 cold process 读取原 operation 与原 deadline：`Done`、完整 cap 保留、0 新 generation dispatch、0 target cancel request、0 NativeTask transaction submission。

| 观察点 | NativeTask 状态 / remaining | Refund claim | Owner 账户余额 |
| --- | --- | --- | ---: |
| 原 Cancel canonical | Cancelled / 0 | gross 1000 | 9999290 |
| Cancel 被替代分叉移除 | Reserved / 1000 | false | 9998581 |
| 同原 Cancel 恢复 | Cancelled / 0 | 同一个 gross 1000 | 9999290 |

Provider 余额保持不变。这里的 gross 本金与账户净变化分开记录，不凭余额差额给费用重新定性。分叉恢复不是第二次退款铸造。[Typed Failure 原件](typed-failure.json)、[重组原件](reorg-result.json)、[独立冷恢复原件](cold-result.json)分别保留这些边界。

确定性研究 fixture 的原 Cancel ID 是 `dba9793565d7ae83790eaba3abb255fad2643d9b2d5696196a426ae289c7d83f`；wire SHA-256 为 `f73e5433dc740e181426a3e50fc5f4e54d19cd9a84a1c96043257f0bfcfeb17d`，packet SHA-256 为 `6a6125eceb7916ccf4afb673e9abeaa54d4c66ea6a21de5b0a45956dc4805295`。本包包含本次实际生成并使用的 wire/packet 字节；这些字节与 C5 相同不表示复用了旧研究 Node。

## 资源与资格边界

| 项目 | 本次证据支持的结论 |
| --- | --- |
| 派发生命周期 | 终态 Failure/Cancel 被保留；热、重组、独立 cold 均禁止重派；M12 begin 为 Done |
| 原资源 cap | CPU `960000000000` ns、GPU `240000000000` ns、内存上界 8 GiB、receipt 16 MiB 全部保留 |
| 实际资源结算 | `consumed=null`，完整资源计费未闭合，不能据此释放 cap |
| GPU / 内存峰值 | target 原件分别是 null / null；未以零补全 |
| 当前进程域 | 热观察 child cgroup 递归为空；最终只读观察原 parent/child cgroup 均不存在，六个已知原 PID/birth 均不在 |
| 完整历史进程树 | `all_descendants_reaped=null`；当前空域或已知 PID 不在不等于捕获并 wait/reap 了全部历史后代 |
| Provider 正向付款 | false |
| 新完整 proof | 0；只有一次实际新生成尝试及其 timeout 路径 |
| 完整 W1 header Node admission | 未建立；研究 NativeTask ledger 的真实分叉处理不替代该门 |
| 业务预算、总体尾延迟、加速收益 | 此单次 120 秒研究操作不提供这些结论 |
| 密码学、协议或生产资格 | 未建立 |

本次没有把另一个 collector 控制实验的历史回收资格移植到这条运行。最终只读核验没有打开数据库、没有发信号、没有新派发或交易；它只是核对原件、当前已知身份和精确源码。[最终只读核验](final-readonly-verification.json)以及[运行后源码 identity](raw/runtime-source-after.json)保留原结果。Source-only identity check 不计作测试。

## 构建与运行 provenance

运行使用 C6 的实际 Cargo artifact 和 exact-source checks：

- Owner ELF SHA-256：`66190e5b704edc538b42d18ef12750d134f85ae6da4eb42122681f814cd4efa6`，467878704 字节。
- Runner ELF SHA-256：`9ff491a702f6833a73c10129d688ad77a905fc7ebaedfbc8784c7f8c485b77ac`，47812232 字节；实际 runner source probe 指向 C6。
- Native winner SHA-256：`753c8c3610dcf0687e2d54f19e5c5b307dd54683bedabc7fe3d39eed57ee4b03`。
- Verifier SHA-256：`f9de534d894e4d0e012d31055fdc4a626addd5efd12ad19d61ff9d7d9867e7a1`。
- 固定上游 r0vm 3.0.3 SHA-256：`2acdf550f9aca4d05b74072463e4ed307c3824309c754a5cb5f93aa84f3390e6`。
- 保留原 guest SHA-256：`25718312ec3c6f5219d832e3516adfb5f82983156f669c5e7daa15bd22d1798f`；没有声称重新编译 guest。

`driver-v4.py` 与 C5 字节相同，SHA-256 为 `b66019d2f47c225174de4f69c508e2b163d69f915b1e9eada59eef9368317464`。C6 的新 owner artifact schema 经过独立、严格的外部字段映射：原 binding、完整资格 manifest、38 份原 stdout/stderr、实际 Cargo test artifact、ELF 和源码字段逐项核验；原件不改写。原 manifest 的 19 个命令及 37 PASS / 4 ignored 在导入中直接复算，没有把导入视为新测试。固定 C3 的六个 backend/native/source prefixes 仍无差异，未放松 guard。

## 文件与复核

主要原件有可读副本：`main-result.json`、`typed-failure.json`、`reorg-result.json`、`cold-result.json`、`plan.json`、`config.json`、`final-readonly-verification.json`。这些副本与 `raw/` 中原件逐字节一致。

`jobs.json` 保留主实验、独立 cold、prepare、owner schema import、最终只读核验的 authoritative status/read 与显式安全 argv。每个 job 的原始 `child.json`、`started.json`、`exit.json`、`exit.witness.json` 也按 allowlist 放在 `raw/jobs/`。没有公开继承环境、凭据、ELF 或私人 SQLite。

`raw.tar.gz` 仅包含 manifest 列出的 allowlisted 原件；`manifest.json` 给出逐文件 SHA-256、大小、来源映射和压缩包 SHA-256。完整实验材料保留在原路径，复制未修改 C5 或任何旧 operation。
