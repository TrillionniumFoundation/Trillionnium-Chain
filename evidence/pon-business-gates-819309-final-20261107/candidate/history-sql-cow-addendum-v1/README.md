# Legacy History / SQL / COW 静态审查补充

本补充只整理对冻结 819309fd312298e099642e1253b1d4ba07113e98（tree f9d63abb9e2931fd78e26ccb87e3a7955068f267）的既有只读结论。没有编辑源码、Git index/refs、原证据或已封存 read-only-review-v1；没有运行测试、Cargo、性能测量或业务门槛。ADDENDUM.json 保存实际读取的文件 SHA256、与该 Git commit 的逐文件一致性和只读过程来源。这不是新的完整 source verifier，也不证明任何性能门槛通过。

## 结论

主 state_at 热路径已有 prepared-statement 缓存。剩余少数普通 SQL 的重复编译可以独立研究，但没有实际成本证据证明其足以关闭 4 秒压力或原 History 门槛。完整 State 读取、根/continuity 校验、Host 进度检查、逐步提交和最后原子发布均有独立义务，不能把它们当成可删的缓存 miss。

## 三个不同的复杂度维度

| 路径 | 源码位置 | 应使用的成本变量 |
| --- | --- | --- |
| inactive parent 重建 | store.rs 3793–3911 | 最近实际保留 snapshot 到 tip 的尾长 r、沿途 delta、完整 State 大小 |
| active State 读取 | store.rs 3020–3114、3438–3493 | 当前 active slot 的完整 KV 大小 N |
| 最后一页 activation | ingress/history_import.rs 513–529；store.rs 6063–6097、6299–6418、6493 | 待激活路径 H、每步 delta、staging/active 全 State、逐步事务和最终发布 |

state_at 先检查实际 active tip；非 active 分支向后读取真实 block/parent/snapshot，找到 snapshot 后校验其规范字节、完整 root 和 continuity，再按原顺序回放 delta，对每个中间 State 检查 before-image、完整 root 和 continuity。按原单链每 128 高度 snapshot 正常保留时，r 常态不超过 127；snapshot 缺失、旧分支 checkpoint 被淘汰时必须回退更长历史。因此不能说每次 import 都从 genesis 遍历 H 块，也不能全局宣称 O(1)。本次没有测量逐 snapshot 命中、SQL 编译 CPU 或历史回放 CPU，不能把结构界限转换为实测节省。

同 writer parent/child prefix（store.rs 4988–5167；store/legacy_admission_readback.rs）仅适用于原写事务中非 active parent、非 128-height child。实际 parent 在所有预期写/trigger 后重建、完整检查并与执行 parent 比较；紧接的 child 才能消费这个一次性 prefix。实际 child snapshot 仍优先。active KV 与 historical snapshot/delta 来源不同，pre-execution parent 也不能跨写入替代 post-write parent。实际 packet/delta readback、ancestry、新旧 State、最后 active fence 和所有事务/取消边界保留。

最后 complete page 的 activation 沿用该请求原 deadline/CPU。它先检查当前观察时钟下的完整历史，随后构造完整 detach/attach steps；每步检查 before-image、更新 cursor、检查 staging 完整 State 和当前 active 完整 State，再提交。只有完整结束才一次发布 active/events/done。snapshot 不能跳过实际 cursor/event/事务序列。

## 原证据说明哪个阶段失败

d26 retained-sql-core-v1.json 和 native-outcome-core-v1.json 分别保留 SQL 事实与原 native 结果。x64 两条 lane 返回 3917/4105，未进入 reorg，后续 History RPC 失败且 server 原记录是 lifetime_expired。ARM 两条返回 4104/4105，实际全部 4105 packet 已存，但最后 activation 在 cursor 3916/3923 以 PUBLIC_REQUEST_DEADLINE 取消，active 仍为 genesis。validator 的 active 均到 4105。

这些是 d26 既有记录，不是当前 819 的重跑或新结论。block 行数、active State 大小、导入调用返回、最后激活必须分别判断；4000 多行本身不证明 CPU 归因。

## prepared statement 的现状与剩余小候选

record、metadata、active、slot、KV scan、snapshot lookup、delta scan、header projection/batch、ancestry shape/header/jump、delta INSERT、apply-delta KV 操作、当前 reorg step 和 reorg-row 验证都已使用 prepare_cached；每次仍绑定当前参数并读取实际行，没有跨调用行/State/权限 verdict。

锁定 rusqlite 0.39.0 的本地实际源码显示：Connection::execute（lib.rs 611–612）和 Connection::query_row（673–679）仍调用普通 prepare。以下重复编译点可作为后续小候选：

| 原位置 | 语句 | 允许研究的变化 |
| --- | --- | --- |
| ancestry_index.rs 418 | level 循环 INSERT ancestry_jump | 原调用点使用现有 bounded prepare_cached |
| store.rs 6066 / 6074 | activation 计划循环 INSERT steps | 同上，保留原 branch、progress 和受影响行数检查 |
| store.rs 6313 | 每步 UPDATE reorg cursor | 同上，保留实际写、读回、完整状态和 commit |

这仅省 SQL 程序编译，不能省 bind/step/rows/Host/commit。不要把 prepare 提到原 callback 之前，不保留活跃 rows，不扩大 cache 上限。steps/events 的整表 prepare 每个 scan 只有一次，缓存也只能少一次编译，不能减逐行完整校验。原缓存可能被 schema 失效或有界 LRU 替换，所以收益仍未知。

若另轮实施，先与原 uncached 调用做差分，cache capacity 0/1/默认分别核实际 SQL、原 Error/owner-stop、affected rows 和完整 charge/progress 序列；保留 trigger 省略写/改错行、warm 后 DDL/RESET、同连接写/rollback、参数换 block/cursor、取消等反例。现有 ancestry_index.rs 748–827 的准备语句测试覆盖读查询的 foreign write/rollback/回调计数，不能冒充新增写语句验证。本补充没有运行这些控制，也不建议未经成本证据扩展当前 root-fence 候选范围。

不能机械缓存所有查询。store/native_authenticated/post_write_readback.rs 45–70 明确要求两项 PRAGMA freshly prepared；133–144 的 writable_schema=RESET 必须执行到 DONE，使旧 VM 失效。保留这些 schema/owner/无写 epoch 检查；不能用缓存 catalog 或减少 prepare 来替代它们。

## touched-set / COW 的协议与迁移边界

STATE_RECOVERY.md 234–268 已限定同 writer prefix；271–323 将下一阶段列为新 root/profile 关系、精确 parent 与 aggregate 认证、完整 touched-account/mandatory-range 输入、原 single-writer COW 原子提交、保留旧或完整新状态发布、source-preserving 新目的地迁移、冷完整性审计与 untouched corruption 检测规则。

目标 O(W log A + bounded range/input) 不是现有 statement cache 或完整 State 算术缓存的性质。移除完整扫描会改变损坏发现模型，不能视为透明小修。当前最后 root-fence 提案仍读取完整实际 State，与这里的结构性工作分开；本补充未应用或验证该提案。

## 只读过程限制

原定位过程有两次 rg 使用少了 ingress/ 或 store/ 的路径，分别返回 2；随后通过实际 rg 定位读到了正确文件。它们只是定位准备错误，没有触发测试/native/业务门槛，不计作 native 失败。所有读取进程的终态、ID、解析文件来源列于 ADDENDUM.json。既有完整 native 终态和 full source-after 仍以 state 负责的原权威回执为准，本补充不替代它。
