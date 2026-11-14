# H5DF ARM64 原始 cross-arch-cost 失败

固定对象：commit 5df7ae6f482157c5f7fdcbcd52222117a965053f，tree 6be4940d38cc88782657f2684cbefe48866f8b9f；run 43621754143 / attempt 1 / job 132528769087 / artifact 14124468052。

原五个 native selectors 均实际 exit 0，各自具名 harness 显示 1 passed、0 failed、0 ignored。原业务校验器独立拒绝 CONFIRMATION_TARGET。源码、test SHA 与记录的 binary SHA 前后相同；Host 的五项限额及身份前后核对通过。binary 记录为 2ebad185…，未获取或执行 ELF。

Baseline 在 1.805452089 秒业务延迟内确认，7 次 History 回放全部接受。Pressure 保留 4 秒、16 workers、7 packets/depth 6：7 个 Submit ACK，4 次 History 响应，前三次回放接受；第四次在 3.302799444–4.001658537 秒返回 PUBLIC_REQUEST_DEADLINE，未完成确认。

第四次的 W1 work 已接受：600.582643 ms wall、32.751792 ms caller CPU；其中 Work 桶 1,099 次 fresh Host 全部通过。失败发生在后续 commit：93.329799 ms wall、1.905472 ms caller CPU，21 次归入 commit 的 Host 检查全部通过。全页 1,170 次 checkpoint 通过。该页是 exclusive owner，page/packet 各一次 CPU reserve 均 granted、没有 sleep，durable_begin 0.540461 ms。此位置与 x64 的 Work 阶段拒绝不同。

这些时钟嵌套且范围不同。Host 的累计 wall、调用线程 CPU、整 child cpu.stat 不能相加或用于断定唯一的调度、配额、I/O 原因。本次不提出已经验证的性能修复，也不放宽任何原控制。

取证保留第一次 selected GET 的 HOLD。root 明确批准的单次续读使用原 900 秒截止时间，8 个精确范围均返回 206；25 个成员的 local header、descriptor、CRC 与 SHA 核验通过。整 ZIP SHA 和其余成员 CRC 未验证。原始大报告保留在 selected-resume-001/members/，这里仅提供其 pin 与有界字段引用，未重复 packet wire bytes。

本地摘要脚本的首个语法错误和两次 64 KiB 输出上限拒绝也原样保留；它们不是新的 CI/native 结果。没有源码、Git/ref、配置、stage、原失败证据修改，没有新 native、build、test、probe 或远端写入。
