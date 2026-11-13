# C6 精确源码资格审阅：保留首轮失败与唯一隔离复核

被执行的源码为 [2bdd252aa6c300b7431b9ee897b254b7953cf562](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/2bdd252aa6c300b7431b9ee897b254b7953cf562)，tree 为 `ac3cb7171c429fa5e12e29ee16839fa6f49f1b81`。其两个有序父提交是 C5 `034aa74358e0a5fa33f33e83cb63669e9738da4b` 和新 base62 `62d2d90c9e1f4c8450c89843f1e08360a24283ce`。本目录是事后只读审阅与原件归档，不是被执行的源码提交。

## 实际终态与计数

| 记录 | 原 manifest 中命令数 | 普通测试的实际结果 | 原记录结论 |
| --- | ---: | --- | --- |
| [Core 首轮](core-attempt-01/summary.json) | 19 | 518 Python 方法执行：516 通过、2 失败、0 skip | 外层 exit 1；原 `qualification_complete=false` 保留 |
| [Owner / M12](owner/summary.json) | 19 | 37 Rust 通过；4 个 heavy 入口 ignored | 外层 exit 0 |
| [Native winner / verifier](native/summary.json) | 10 | 2 + 2 Rust 通过 | 外层 exit 0；准备目录回执单列，不算第 11 条命令 |
| [真实 receiver](receiver/summary.json) | 4 | 11 Python 通过、0 skip | 实际执行新 C6 verifier；使用留存证明材料 |
| [Backend attempt 02](backend-attempt-02/summary.json) | 7 | 无普通测试或完整证明生成 | 6 条 exit 0；source-only 探针按预声明 exit 1 |
| [唯一隔离 staged 复核](staged-isolated-01/summary.json) | 4 | 原 32 个 Python 方法全部通过、0 skip | 单独的新 attempt，未改 C6 字节或原参数 |

前五份组件原 manifest 的数组合计 **59 条命令**：57 条 exit 0、1 条预期 source-only probe exit 1、1 条首轮 staged 测试非预期 exit 1。普通套件首次队列合计 **568 通过、2 失败、4 个 ignored**。唯一隔离复核另有 4 条命令及 32 个通过的方法执行，其中 30 项重复首轮通过，2 项补足首轮失败；不把首轮改写成一次全绿结果。按所有这些普通执行累计，是 600 次通过、2 次失败；这不是 600 个新增方法。

[Backend attempt 01](backend-attempt-01/summary.json) 另行保留原 900 秒外层超时、exit 124、4 条已完成 exit 0 的前置命令和部分 build 输出。它未形成完整资格 manifest、成功 runner artifact 或后置 source guard。它不并入上述 59 条完整组件命令，更不被 attempt 02 的成功改写。

## 首轮失败与隔离复核的边界

首轮两项失败分别是实际 sleep 子进程超时控制与忽略 SIGTERM 后升级 SIGKILL 的控制。两者都在 `Popen` 之前耗尽本次原预算，得到 `DEADLINE_EXHAUSTED_BEFORE_SPAWN`；没有走到各自要求断言的已启动子进程分支。第二个方法在首条 SIGKILL 断言失败后，其后续 `OUTPUT_LIMIT` 子例没有执行。完整原 stderr、原 fixture 字节、生产计时源及事前审阅见 [首轮对抗复核](staged-observer-attempt1-review/review.json)。

原 fixture 声明的 wall budget 分别是 0.15 秒、0.2 秒。忽略 SIGTERM 的测试虽然 patch 了全局 grace 常量，函数默认参数在定义时已绑定；实际默认清理 grace 仍是 5 秒。没有 child-ready 握手。这些原有条件在隔离复核中保持不变，没有放宽 deadline、重置时钟或接受另一种失败原因。

唯一隔离复核在预声明之后执行；[launch binding](staged-isolated-01/raw-logs.tar.gz) 保留原失败记录、原 argv、相同 driver 的 SHA256、7 个已知 job 的终态/服务作用域观察及无已知并行资格构建的边界。审阅逐名比对原 32 个方法与新 32 个方法，确认相同集合，且原两个失败的方法随后通过。这是一次分开的负载条件观察；并发 I/O 导致首轮失败仍是解释假设，不是已经证明的因果结论，也没有建立任意负载下稳定通过的资格。

## 源码与构建来源

[冻结源码读回](source-freeze/summary.json) 保留实际 commit、tree、有序父提交及 clean worktree。C5 到 C6 的变更为共享 store、其 legacy reorg 测试、对应 workflow/corpus pin 和开发计划，共 5 个路径；20 个关键 W1、M12、deadline、cap、source guard 文件与 C5 字节一致。两处 pin 冲突逐项解决，未用整份 ours/theirs 覆盖；645 项 pin 集合和 C5 新增 W1 profile pin 保留。[原 base advance 审查](base-advance/summary.json) 与 [52 项 precommit pin 控制](pin-resolution/summary.json) 单独归档，不计为 C6 提交后的测试。

每个完成组件的实际 stdout/stderr 均按原 manifest 重算字节数与 SHA256；前后 source identity 都绑定同一 C6 commit/tree。原 argv、cwd、driver/plan、Cargo JSON 与 source-only probe 各自保留。审阅没有重新执行 source 全树 guard、测试、Cargo 或 Node。

Owner 从独立空目标目录开始；原 preparation 与实际 launch binding 匹配同一目标、device/inode 和准备回执哈希，Cargo 输出又绑定实际 owner test ELF。本轮审阅核对了 ELF 的 stat 和原 artifact receipt，未重复读取 468 MB ELF；不能把原 receipt 的 SHA 标成此次独立重算。Native winner 与 verifier 的 Cargo artifact、目标准备声明和实际二进制字节则均已独立核对。

Backend attempt 02 是新输出目录、新预声明 **1800 秒资格构建预算**，复用原失败 C6 build 的缓存，明确 `fresh_cargo_target=false`。新 runner 的实际字节重新验 SHA，Cargo JSON 路径来自 C6 checkout；其实际 source-only probe 先验证留存 guest 身份，再验证 C6 source，随后严格按预期报 `Error: unknown stage`。未创建 probe 任务目录。这个 1800 秒预算与研究 operation 的 120 秒原 deadline 是不同边界，未延长旧 900 秒 job。

Owner、native 的空 Cargo target 也复用了既有 registry 和工具链，不是独立 cleanroom 或可重现构建证明。Guest 保持留存原字节和 SDK image 校验，没有重新编译 guest。

## 这些结果不授予的资格

本资格包的完整新证明生成数为 **0**。真实 receiver 的 11 项控制使用原 `pon-w1-full-v2-20261105` 留存 receipt/input/header/独立 expected-artifacts，以及新 C6 verifier；它不等于重新生成两份 11 月 7 日证明，也不等于中奖 W1 被真实 Node admission 接受。Node/M12 中使用明确 verifier fixture 的付款控制不代表实际昂贵证明已获正向 provider 付款。

既有 ABBA 80 行的历史来源不因本轮单元控制通过而变成 C6 生成实验。完整生成总体尾延迟、因果加速、广域传播收益、原业务预算、完整历史进程树 wait/reap 与资源计费、GPU 用量、密码学及协议安全资格仍未建立。新 C6 研究操作与独立冷恢复已实际完成，分别执行 1 个 exact heavy 入口并通过；[独立生命周期审阅](lifecycle-independent-review/README.md) 核对自然 deadline 先于 owner veto、Unknown consumed=null/full cap、同一原 Cancel 的重组恢复和冷恢复 0 dispatch / 0 target cancel / 0 native tx。它们单列于普通方法队列之外，新增完整证明仍为 0。该独立研究 Node 的 NativeTask Cancel ID/wire/packet 与 C5 的确定性 fixture 相同；不能声称全球新链资金或把两轮退款累计为 2000。

对旧 D3 的 [C5 命令计数复核](c5-command-count-crosscheck.json) 确认原 `19+19+4+7+10=59` 已正确，无需改写原包或发布勘误。后续远端 base 或 PR merge ref 的变化另行评估，本包只绑定明确的 C6，不继承旧 `991168` merge 资格。

## 文件与审核范围

各子目录包含 summary、逐输出索引、原始日志 tar.gz 和 manifest。原件采用显式 allowlist，只归档日志、JSON 回执及相关 driver/plan；没有 ELF、SQLite、整个 Node state、进程环境转储或凭据。源字段中的有限工具链参数按原回执保留。

本包审阅完成表示这些原件、实际结果和计数已经核对。原 core 失败仍为失败；源码身份检查、有限控制及归档哈希都不自动授予生产、业务预算、完整资源或安全资格。

