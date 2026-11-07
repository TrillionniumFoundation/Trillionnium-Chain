# r16 最终报告准确性复核

## 范围与结论

本次只读审阅 `r16-evidence-draft.md`、`validation/r16-implementation-context.json`、现有来源/reader/Clippy 日志和相应冻结源码。没有修改仓库或草稿，没有重跑验证，也没有请求 GitHub。本文件为报告编辑建议，不是新增测试或资格证明。

审阅时完整 Cargo 运行仍由主任务管理；不能从本审阅推导它已经结束。主任务已确认 Clippy `-D warnings` 与 fmt 退出为 0。草稿的 HOLD、GitHub 阻塞、原固定 Host 压力未执行、历史失败保留等总体边界准确。

冻结实现：`2cd7353187bb58347ae7cbf884fef7aa2d05f610`；tree：`3f5e11d87787bc0329bbf443f60d02786e1598ce`。`r16-final-source-before.json` 与 implementation context 一致；该来源检查明确 `tests_executed_by_identity_check=false`。

## 优先修正的两处措辞

### 1. 不把 reader 的一致性检查写成独立确认验证

原句包含：`Timely success requires the original matching independent confirmation facts, depth/work relation and strict deadline.`

风险在于读者可能理解成 v4 重新验证了独立 verifier、完整 W1 或原始 target 导出的精确工作阈值。实际 `business_confirmation_summary` 检查的是保留字段：身份匹配、深度六、height 差六、结束时间在原截止前，以及 `work >= required >= 6`、`required % 6 == 0` 等必要的一致性条件。它没有重新执行 W1/State，没有从 target 重建精确阈值，也不认证来源、独立性或攻击预算。

建议替换为：

> Timely readback success requires complete, internally consistent retained confirmation observations, matching transaction/block/tip identifiers, the original fixed depth and necessary work relations, and a known end clock before the unchanged deadline. The reader does not independently verify W1, the target-derived work threshold, native execution, verifier independence or the attack budget.

相应实现已明确 `source_or_native_verification_performed=false`、`attacker_budget_verified=false`、`resource_fairness_qualified=false`。不需要改代码。

### 2. 分清真实 Submit 工作与跨上下文读请求回归

原句：`These controls exercise actual native signed work`，紧跟两个 TCP 回归的总述，容易让人以为所有回归均执行了原生 W1。

实际覆盖为：

- victim-Submit 回归构造含真实签名交易的原生区块；攻击者签错 caller 时在 spent/body/task/work 之前拒绝，随后正确 victim 请求完成原生提交。
- operation/body substitution 回归使用 `Head -> PoolStatus` 和 body 长度相同、内容不同的 `History` 请求；保留原签名 solution 可用，最后明确断言 `work_started == 0`。
- cold-zero 回归是一个连接、一个 Head、原截止内、无需客户端重试的有限行为检查，不是压力下服务率或完整历史同步证明。

建议替换为：

> The victim-Submit control uses a real native packet containing signed transactions. Separate read-request controls move an exact signed solution across operation, body and connection contexts, reject it before paid dispatch, and preserve the original solution's usability. These controls do not replace ledger authorization checks or service qualification.

## 收尾时必须保持的限定

1. `VALIDATION_TABLE_PENDING` 应由实际终止状态填入。可以列明已通过的 fmt、Clippy、来源与 reader 门禁；完整 workspace/all-targets/all-features 运行尚无最终结果时必须继续标为进行中，不能写全量通过。忽略、过滤、未到达的测试不算执行。
2. `Tested final implementation tree` 可改为 `Frozen implementation tree for the recorded validation`，减少把 source receipt 误认为全套测试完成的可能。后续 evidence commit 若尚未产生，相关描述用计划或条件语气；产生后列明其身份，并继续把本次实现测试绑定到上述实现 commit/tree。
3. 冷启动零信用应理解为受控 cold/restart account 路径；单连接 Head 成功只能支持该有限回归，不支持所有公开请求在压力下均能及时完成。
4. 正确保留认证与 mutation 的非可加范围：mutation 响应签名已经在 mutation 区间内；读响应没有 mutation owner；Host 总 CPU 仍需要真实 kernel-parent 观测。同步 crypto 不能强制抢占，已知超额形成债务。
5. GitHub 403 是读取当前 ref 时发生的外部连接阻塞。保留原文 `Sorry. Your account was suspended` 即可；不要把它写成代码失败、自动安全审查拒绝、远端已更新或 CI 已触发。

## 最终中文答复优先强调的五项成果

1. **共享认证 CPU 账户已经实现。** Cookie 签名、caller 验证、响应签名在原 intake 内预留并按已知实际 calling-thread CPU 结算；失败签名计费、未知不退款、冷启动零信用，不增加 Host 额度，也不引入完整同步的生命周期调用数上限。
2. **认证先于消耗的真实 TCP 回归已经补齐。** 明确区分 victim-Submit 的真实原生签名区块、跨 operation/body/connection 的读请求替换，以及 cold-zero 单连接 Head；原来的正确请求继续可用。
3. **启动与恢复的预算所有权检查得到加强。** 昂贵 State 读取前检查已有 domain；最后 ordinary listener/History 引用复核当前两账户；continuous clean close 要求实际 listener 释放和真实结算，保留 Busy 与未知故障的差别及已完成原生结果。
4. **r16 身份、向量和来源绑定已经建立。** 原 r10–r14 raw 与 r13/r14 arithmetic 字节保留，r15 未混入；历史 selector 名不冒充当前 revision；本地两提交和可应用交付材料保留冻结实现。
5. **业务完成率和延迟的可审读性得到补齐。** v4 保留全部三个原始 offered 轮次、计划时间和统一截止；成功样本经验 tails、含调度等待的延迟和实际开始后的延迟分别标明；删失/错误不产生有限全 offered tails，v1–v3 继续可重现。来源与 reader 门禁，以及 fmt/Clippy 的已通过结果可以分别报告。

## 最终中文答复优先强调的三项未完成

1. **远端交付未完成。** GitHub 当前连接读取 ref 即返回 403，因此没有本候选推送、新 PR 或新 hosted CI；bundle/patch/logs 是本地可审查和可应用交付，不是已发布证明。
2. **完整 Rust 验证结论以最终日志为准。** 审阅时完整 Cargo 运行仍在进行；不能用已通过的 fmt、Clippy、来源和 reader 门禁替代它的终止结果。
3. **原服务验收与安全结论尚未闭合。** 本地固定 parent/limits 缺失使 Host capture 拒绝，原 4 秒/16-hostile 压力没有运行；三次完整 0/24/24、完整 History、capacity/churn 与独立 WAN 仍是各自门槛。保留历史失败；本变更没有消除 W1 昂贵拒绝的不对称，也没有证明工作成本下界、匿名公平性或生产资格。

现有后续 CI 路线仍为 `pon-priority-acceptance.yml` 的 service-model 原始 Host launcher，以及 `pon-native-campaign-qualification.yml` 的三次完整原始 campaign。ROOT F0 为另一项诊断，不能替代它们。无需改变原压力参数。
