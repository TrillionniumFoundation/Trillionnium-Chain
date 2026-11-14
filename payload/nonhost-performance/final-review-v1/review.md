# R1 非 Host 关键路径静态复核

结论：没有找到证据足以支持的四秒修复补丁。本轮只读固定 R1 源码和既有原报告，没有运行测试、Host、网络请求或改动源码。

真实资源为 cpu.max=25000 100000，即 0.25 CPU；4 秒、16 个压力线程、7 包、深度 6、2 秒 RPC 与全部原 fresh Host 边界保持。

## 已排除的实现方向

- Exclusive History 只做一次 W1；已验证 packet 与 VerifiedWork 移入 admission，随后是必须的新鲜上下文/父状态/M06 检查。不存在共享 Node 等锁，也未发现 W1 内隐藏 completion sleep。
- 服务端 Submit 已采用借用式 canonical body，History 编码已移出 Node 锁。两者不是新的可用优化。
- 原 outer deadline 没有在客户端或 History 内更新。七次诚实提交的服务 CPU permit wait 合计仅 0.018–0.024 ms，不能解释秒级延迟。

## 原报告的新小分解

按 head original / head fresh / prospective original / prospective fresh 顺序，7 个诚实 Submit 的 caller CPU 合计为 5.962 / 5.887 / 6.327 / 6.370 ms，paid queue wall 为 105.413 / 505.683 / 203.432 / 693.972 ms，challenge wall 为 101.381 / 189.847 / 198.140 / 380.498 ms。服务端 work CPU 合计为 12.806 / 11.833 / 12.252 / 12.142 ms。这些独立字段可能嵌套，不可相加为总 CPU 或总 wall，更不能直接据此断言调度根因。

## 有依据但不足以解决目标的小候选

客户端 canonical_request 的 packet String 临时副本会立即丢弃，可设计保持相同逐项检查与错误顺序的借用验证接口。Response::message 的 unsigned JSON 深复制也可用逐字等价的借用序列化视图替换。然而前者没有独立 CPU 计量，后者所在 History response_encoding CPU 仅约 0.45–0.92 ms（1–2 次回复）。均未实施，不能称为四秒修复。

生产 V3 客户端未设置 TCP_NODELAY，而接受端设置了；报告未包含 ACK/未确认字节/内核 TCP 时序，不能据此认定 Nagle 或延迟 ACK 是原因。本轮不据猜测提出该补丁。

剩余缺口是 phase-local 等待原因和 syscall 阻塞时间；现有 task-clock 权限探测失败，无新授权诊断运行。后续若获得合适真实 Host 可观测能力，才可在原源码/原 binary/原条件下采这些信息。不会修改 fixtures、fresh Host 频率、预算或结果断言。
