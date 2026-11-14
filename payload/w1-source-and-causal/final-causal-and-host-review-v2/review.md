# R1 W1 fresh-service：只读因果与 Host 合同闭合

## 当前结论

这两项 R1 hosted job 的业务门禁真实失败。两份 original 原 Rust test 返回 0，但报告未达到原窗口的独立六深度确认，wrapper 报 CONFIRMATION_TARGET；两份 fresh test 在保留原四秒/六深度断言处返回 101。四份 baseline 都完成，四份 pressure 都收到 7 个诚实 Submit ACK，最后一次独立 History replay 均拒绝 PUBLIC_REQUEST_DEADLINE。ACK 不能代替独立确认。

没有新增测试、native/Host 运行、采样、网络下载、源或 Git/ref 修改、stage 修改。本目录只封存既有原报告的读后归纳。尚无经过测量足以修复四秒结果的安全优化方案，也没有实现性能修改。

## 实际两条路径的区别

实际 fixture 绑定 127.0.0.1:0。Public V3 listener 按真实 local_addr 调 require_for_listener；对 loopback 返回 None，所以这次服务端 kernel_for_worker 和条件 50ms reactor Host verify 都没有运行。外层 hosted controller 的固定 cgroup 和原有限资源仍真实生效；不能将“外层限额生效”写成“loopback listener 内部持有 Some HostKernelBudget”。

普通服务端 full W1 仍有任务存活、账户 CPU checkpoint 等检查；该 ordinary checkpoint 的 resource callback 为空。严格 public History 入口则无论 source 是否 loopback，显式要求固定 Host parent。其 W1 进度 control 每次按原 absolute deadline → fresh resource → 同一 deadline 检查。实际独立 replay 是 Owner::Exclusive，没有共享 Node owner-wait，未启用另一条 wait 分支。

完整 W1 实际 1099 个边界检查不能等同 policy.id 调用次数，也不能套到提前中断的 replay。两个 original pressure 完整首包中，W1 calling-thread CPU 为 81.728/80.844ms，嵌套 Host CPU 为 78.012/77.032ms。baseline server 七包 full-W1 CPU 合计约 10.24–10.38ms，而七次严格 History replay 总线程 CPU 约 555–571ms。这些不是等价检查合同的速度比较，不能据此移除 History 检查。

## 当前合同及原控制依据

REMOTE_SYNC_W1_HOST_GUARD.md 的 Current API boundary 明示四个 exported public History 入口即使 loopback 也要求固定 Host。理由是 loopback locator 不证明来源，代理可携带远端不可信 proof；普通本地 serving 保留单独的开发兼容合同。PUBLIC_POOL_INTAKE_V3.md 的 listener 段与实际 None 选择一致。

当前 history_import_tests 的原控制明确要求每个真实 W1/native 边界检查一次，并覆盖原始非抽样边界上的 Host 变更拒绝、原 deadline 优先、错误保留、失败后重试。它们是源码审阅引用，不是本轮新运行的测试。

旧文档中“bounded cadence”及“每64 tile”是保留的历史候选叙述；当前 API 段已经警告旧例外不描述现有 public surface。不能用历史措辞替换当前每边界的语义。对应完整原选段见 original-controls-and-design-excerpts.txt。

## Host 每次成功检查的源级成本

checked_parent 的成功短文本路径有 8 次 fresh open（boot、parent、当前线程 membership、五个 limit），6 次 FD metadata、一次末尾 parent 路径 metadata、7 个完整 EOF 文本流/UTF-8 校验、4 个 u64 解析。以上是源码级成功操作计数。短读/EINTR/系统实现会改变实际 syscall 数；“各文件一次 payload read 加一次 EOF，共14次 read”仅是条件示例，绝非已测值。

短文本快速路径已使用 stack/Cow、held-parent-relative openat 和不可变身份。源码没有该路径上的 BTreeMap 计数解析或重复路径拼接，也没有可证明多余的相邻 Host callback。显式项目级短路径堆分配为零，不推断标准库内部零分配；较长 boot/membership 保留原同 FD 堆回退。

boot、parent 前身份、当次线程 membership、五个新鲜 limit、EOF/UTF-8/regular-file、parent 后身份和最终 limits 等价各自具有独立拒绝作用。前后 metadata fence 时间不同，不能合并。这里没有重复的 descriptor/source framing 哈希可安全删除，也没有可量化收益的 parser 替代已获证明。

## CPU 证据的范围

cpu-tables.md 给出八个 phase 与四组攻击线程分解。攻击 whole-worker CPU 约351–382ms；client-call 合计约187–298ms，包含 solution-search 已知约9–14ms；fresh 构造另约95ms，其中 packet encoding 约77ms。这些是嵌套计量，不可再相加。记录/转换/clone/循环等残差约70–85ms，未被单独测成纯 JSON。

各段 wall/CPU 来自不同 clock 和结束边界，某些调用延伸到原四秒后，service 包含 drain；不能拼成严格四秒 CPU 饼图。whole-child cpu.stat 证明该完整子命令存在节流，却无法把其全部节流时间归因给某次 W1。原报告缺少逐 syscall、parser、scheduler 或 classic reactor auth 的专用观测。

当前 first durable begin 约0.6–1.4ms，不能把旧 C0 的95ms样本继承为这次原因。大 wall 与小 calling-thread CPU 的差额本身也不能把 CFS 定为唯一原因。保留原 CPU 账户、refill、paid settlement、冷启动和全部检查。

## 处置

继续保留原四秒、16 worker、两秒 RPC、七包/六深度、原 absolute deadline 和所有 fresh Host/工作/签名验证。R1 中已有 PublicPolicy immutable-prefix cache，但本轮失败不支持宣称它已修复业务门禁。停止无证据的小哈希、降频或缓存 OS verdict 方案；不将本诊断或组件 PASS 升格为 hosted qualification。

summary.json 是当前紧凑事实；source-and-evidence-refs.json 给出固定 Git blob 与完整证据 pins；两份 excerpt 文件和 host-check-operation-excerpts.txt 供直接复审。所有新单文件均小于64KiB。大型原 ZIP/report 只引用，不重复复制。
