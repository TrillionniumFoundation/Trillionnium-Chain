# 必需 protocol-contract 确认目标失败：精确时序复核

## 结论

远端 run 43531685339 的两个 protocol-contract 作业都被原外层门禁以 CONFIRMATION_TARGET 正确拒绝。五个具名 Rust 测试的原安全/记账断言通过，不等于 4 秒业务确认目标通过。此分析没有修改源码、重跑旧 campaign、增加预算、减少 Host 检查或授予任何生产资格。

已定位两次失败的实际时序，并排除了几个看似相关但不在路径上的移植。**尚未建立可测、保持全部原合同的小性能修复；该必需门禁仍阻止合并。** 最终组合源码必须重新通过同一原 4 秒、16 pressure workers 和完整 fresh Host 检查的门禁。

## 精确输入与两次不同的失败

两个 job 使用同一 Git tree c93086b354d75827ca96a42c7eaa3f8be8954311。Head 是 332d7f723d71707d88a2cffa52b3754579a46926；prospective commit 是 7139081ab4084ecbcd1e5bd7076a4e04426d1f4c。

| 观察项 | Head / job 132250690649 | Prospective / job 132250690954 |
|---|---:|---:|
| 无压力完整确认 | 2.099749121 秒 | 3.098989497 秒 |
| 压力下业务开始 | 0.072062559 秒 | 0.094607700 秒 |
| 7 个 Submit ACK 全部完成 | 0.942535738 秒 | 1.593801466 秒 |
| 成功 History 响应 | 7 | 3 |
| 完成独立重放的页数 | 6 | 2 |
| 最后一页重放开始 | 3.978203041 秒 | 3.997498446 秒 |
| 最后一页开始时剩余原窗口 | 21.796959 毫秒 | 2.501554 毫秒 |
| 最终拒绝 | 第 7 页 Work 中截止 | 第 3 页 Context 中截止，尚未进入 Work |

两个 receiver 实际都完成了 7 个合法业务包的 native Work。Head 的 7 个 ACK 与 7 个 History 仅证明对端响应完成；独立客户端仍要对每页执行原 W1、状态转换与持久化，故不能由响应数推导确认成功。

最后 prospective Context 持续 94.172065 毫秒墙钟，但只使用 0.379247 毫秒调用线程 CPU。Head 最后 Work 使用 82.317392 毫秒墙钟、4.421680 毫秒线程 CPU，然后保留原 PUBLIC_REQUEST_DEADLINE 拒绝。两者均未把超时解释成成功。

## 主要成本与等待位置

每个已完成独立重放包的 Work 阶段有 **1099 次实际 fresh Host checkpoint**。Head 压力下六个完整 Work 的线程 CPU 约为 45–51 毫秒，其中约 43–48 毫秒在 Host 检查测量内。Prospective 两个完整 Work 分别用 70.537260 / 69.681165 毫秒线程 CPU，其中 Host 为 67.053491 / 66.273982 毫秒。它们的墙钟分别约为 699 / 694 毫秒。

这些是嵌套度量，不能把 Host CPU 再加到 Work 或 replay CPU。HostGuard 在入口统计锁之后开始 CPU 计时，在出口统计锁之前结束；上述 Host 时间也不是整个 observer 聚合锁路径的时间。

原独立导入 CPU epoch 第一次约等待 400 毫秒，两种模式都存在。后续页与包的 grant 没有相同长等待；最后一次拒绝也不是又等一次 400 毫秒。解码一般远短于 Work；独立 Node 在这些记录中没有 context/admission/commit owner mutex 等待。部分提交或结果阶段有约 90 毫秒墙钟空档，但仅有几毫秒乃至几十微秒 CPU；原证据不能把这些空档直接说成 fsync 延迟。

按精确请求 body digest 关联到 receiver，Head 压力下首个合法请求在 challenge 队列等待 88.899958 毫秒，grant 仅 1.257118 毫秒，paid task queue 仅 1.515042 毫秒，receiver native Work 仅 1.064759 毫秒。因此早期提交变慢主要在 challenge 等待；后续独立重放的 Host 成本是另一个明确位置。

## 固定主机配额与因果边界

两份原 Host 观察都保持：

- cpu.max = 25000 100000，cpu.max.burst = 0；
- memory.max = 2147483648，memory.swap.max = 0，pids.max = 256；
- 同一次作业前后的 root 所有者、目录 inode、boot ID、当前 membership 与配额一致；
- 未出现 Host 检查错误或 OOM。

Head 和 prospective 的 boot ID、Azure worker 和区域不同，native suite 时间窗口也不重叠：00:48:31–00:49:19 与 01:10:58–01:12:03 UTC。因此不能把失败归因于这两个 job 在同一观察到的父 cgroup 中并跑。

约 100 毫秒周期的墙钟空档、强烈的 Host CPU 占比和原 suite 累计 throttle 计数支持固定 25% CPU 下竞争/节流这一主要解释。**累计 cgroup counters 覆盖完整五项 native suite，不能当成某一个 4 秒阶段或某一个 syscall 的逐段测量。** 当前证据尚不能精确分配每段 off-CPU 时间。

## 原 16 个攻击线程的 caller 分布

每条实际记录均符合：

    caller_fixture = 80 + ((attempt + worker * 37) % 150)

Head 有 442 次 client 调用、136 个身份；prospective 有 330 次、107 个身份。按完整客户端 [started, ended) 区间做扫线，同一 caller 最大并发分别为 **1 和 2**；所有 caller 的总并发均为 16，没有任何同一 caller 大于 2 的区间。客户端区间是实际 pending grant 的宽上界。

因此 r20 的同一 authenticated caller 两个 pending grants 合同不能被当作这次原始压力轨迹的性能修复。64 个 live caller 表也必须按实际释放合同评估，不能把整个 campaign 的累计身份数误作同时活动数。

## 已交叉核对的源码与无关移植

Host 热路径位于：

- src/host_kernel_parent.rs：kernel_parent::KernelBudget::check、read_context_text/read_context、open_current_parent、read_limit_text/read_limit_at/read_limits_at、in_parent_cgroup/cgroup_within_parent。
- src/ingress/history_import.rs：原 Control 与 Work checkpoint。
- src/ingress/history_import/observation.rs：HostGuard 与 observe_host。
- src/ingress/public_v3/scalar_cpu.rs：原调用线程 CPU 记账、保留额度和等待。

这些文件及原测试在本次只读检查树 2f2dec9de8bd464c83d5c7769abf2f76a2ca950a 中与失败 332d 对应 blob 相等。完整 SHA/OID 在结构化报告中。

Host 当前已使用 129 字节 limit 栈缓冲、257 字节 context 栈缓冲、保留长输入同流 fallback 和 immutable parent_relative。常见短文件成功路径按源码数有 8 次 fresh open、14 次 read（含显式 EOF）、8 次 close 和 2 次 metadata 观察；这是源码调用计数，尚非实际 strace。所有当前 boot、实际调用线程 membership、5 项 limits 和父目录首尾权限/身份仍必须读回。热路径没有 JSON 或完整配置 digest 重算。

原路径也已经采用借用 canonical Submit 解码及 negative Work rejection cache。Head 的 426 条拒绝 Work 中有 361 条实际 cache hit；prospective 的 316 条中有 267 条。不能再把这些已有行为列成待移植优化。

042e 的 per-call CheckedConfig 经只读交叉核对：它仅在一次调用内借用 immutable Config/Profile，保留真正签名扣费、当前 authority 检查、后续变配置拒绝、原错误次序和并行取消 join。该移植属于独立审计修复。本次原确认测试使用 Settings::development 的经典账户，native_pq_v2=None，首块是经典 64 字节签名 Envelope、其余六块为空交易；PQ transport authentication 计数为零。042e 与 c36 ML-DSA 展开缓存都没有被证明能改善此测试路径。

## 后续验收

任何性能补丁必须先证明实际重复工作及因果收益，同时保留全部动态 Host 读回、原 callback 边界、CPU/refill/债务结算、4 秒窗口和 16 workers。缓存动态 Host 值、跳过 EOF/身份检查、降低 gate 或把旧结果当新源码验收都不成立。

本轮未启动新的 native 压力运行。ROG 压力窗口由 root 统一调度，避免与其它已授权 native 验证争用。现有结果的准确状态仍是：源码审计与各项独立修复可继续整合，远端必需确认门禁尚未通过，不能据此安全合并 main。

## 证据索引

最终详细 JSON：confirmation-causal-analysis-v6.json  
便于读取的结构化摘要：confirmation-causal-summary-v6.json  
caller 完整分布：actual-caller-distribution-v1.json  
原始 zip、每页时序、Host 观察、原日志均保留在同一目录。各文件 SHA256 与原 GitHub artifact 摘要都列于 JSON；没有依赖未保存的口述结论。
