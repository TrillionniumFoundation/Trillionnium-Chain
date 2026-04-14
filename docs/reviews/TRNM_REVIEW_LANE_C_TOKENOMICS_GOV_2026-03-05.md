# TRNM Lane C Review（Tokenomics / Governance 经济安全）

- 日期：2026-03-05
- 范围：`trnm-state` / `trnm-pouw` / `trnm-node`
- 结论：发现 8 条 challenge（含 3 条 P0）

BL09 retirement-prep note: 本评审文档保留的 `trnm-pouw` / PoUW / resolve-authority 风险描述，仅应用于历史问题复盘、迁移期兼容分析与 provenance / audit evidence 留痕，不能解读为当前默认 payout authority，也不重新授权默认 work-unit payout path。若 PoCO settlement 已成为主结算路径，对外付款判断与默认结算 authority 仍应以 PoCO settlement anchor 为准。

---

## Top 3 P0（先看）

1. **P0-1 解析层“伪签名”导致 Resolve 权限可被任意提交者冒用**（`trnm-node`）
2. **P0-2 `set_gov_param_bootstrap_unchecked` 可绕过敏感参数 timelock 与治理流程**（`trnm-state`）
3. **P0-3 挑战奖励可从全局 slash treasury 回退支付，存在“库余额抽取”经济面**（`trnm-pouw`，**见下方 2026-03-12 状态更新：当前实现已不再符合该描述**）

### 2026-03-12 状态更新（L05 复核）

- 现行 `trnm-pouw` 实现下，challenge-success bounty 仅允许从**当前任务的 worker stake lock**支付；task-local slash principal 不足时会 **fail-closed**，不会再回退抽取 `treasury.worker_slashes`。
- 因此，原 Challenge 3 所描述的“从全局 slash treasury 回退支付 bounty、形成库余额抽取面”已不再是当前代码状态的准确表述。
- 当前更准确的残余风险是：**`default_slash_on_unresolved_challenge` 的治理控制面仍未完全打通**。也就是说，代码里已经预留了 challenged-timeout → slash 的治理开关，但 state 层 allowlist / governance schema 仍可能让该控制面在实际治理路径中不可达。
- 经济语义上还需要继续保持明确：当前 challenged-timeout 即使未来切到 `Slashed` 分支，也**不会自动发放 challenge-success bounty**；若产品后续要把 timeout-slash 也定义为 challenger 胜诉并发 bounty，需要单独设计 payout 来源、额度上限与防 farming 约束。
- 本轮 L05 补充了一条 fail-closed 回归：若 challenged task 的 `resolve_deadline_height` 元数据缺失，`apply_timeout` 必须在任何 escrow / slash treasury 余额变动前直接拒绝，避免脏状态被误终结。
- 同时，当前 fraud verifier 的 envelope 绑定面已对 `task_id` / `worker` / `proof_type` / `result_hash` 建立较完整的 fail-closed 回归覆盖：对大小写变体、全角分隔符、引号别名、重复绑定与缺失绑定都会直接拒绝，而不是尝试容错合并。这一收敛降低了挑战提交层通过 payload 歧义制造“看似同义、实则可绕过”的解释空间；当前 lane 的主要剩余风险仍更集中在 challenge timeout / resolve authority / governance wiring，而非 fraud envelope 再次回退到宽松解析。
- 另外，`trnm-pouw` 现行 resolve-authority 边界已经补上几条关键 fail-closed 约束：`resolve_authority` 不能再与 `system`、`treasury.challenge_escrow`、`treasury.challenge_forfeits`、`treasury.worker_slashes`、默认占位值 `governance.resolve_authority`、task `worker`、`challenger` 或 `creator` 角色重叠；多成员集合也会对空成员、重复成员、非 canonical 标识与 staged approval 失配直接拒绝。因而当前 authority 面的主要残余风险，更偏向“真实 signer 绑定 / committee auth context / governance wiring”这些跨层闭环，而不是同一批已收敛的账户别名或角色重叠再次放开。

---

## Challenge 1 — P0
### 标题
Resolve 授权被节点层“配置回填 signer”绕过（任意调用者可伪装成 authority）

### 证据
- `trnm-node/src/main.rs:1384-1394`
  - `verified_signer_of()` 对 `MockTx::Resolve` 直接返回链上参数 `resolve_authority`，而不是交易真实签名者。
- `trnm-node/src/main.rs:1704-1710`
  - `apply_resolve_at_height(..., resolver, signer, ...)` 使用了该伪造 signer。
- `trnm-pouw/src/lib.rs:964-983`
  - 只校验 `resolver == signer` 且 signer 命中 authority 成员，因此可被上层伪造输入满足。

### 复现（最小）
1. 设 `resolve_authority = "alice"`。
2. 任意外部用户提交 `Resolve{resolver:"alice"}`。
3. 节点把 signer 强制设为 `alice`，PoUW 授权检查通过，挑战可被非授权真实主体结案。

### 影响
- 直接破坏治理仲裁权限边界；可恶意 Slash 或放行。
- 经济后果：错误资金流（挑战 bond、worker stake、treasury 方向）被非法触发。

### 修复
- `verified_signer_of` 必须来自真实签名验证结果（tx envelope/crypto verify），不得从状态参数“合成 signer”。
- 在 `apply_resolve_at_height` 增加 `signer_proof`/`auth_context` 强约束，拒绝无签名上下文。

---

## Challenge 2 — P0（timelock 绕过）
### 标题
`set_gov_param_bootstrap_unchecked` 允许敏感参数即时生效，绕过 timelock

### 证据
- `trnm-state/src/lib.rs:571-616`
  - `set_gov_param_bootstrap_unchecked()` 直接 `upsert_gov_param_unchecked`。
- `trnm-state/src/lib.rs:634+`
  - 正常路径 `set_gov_param_with_action()` 才实现 sensitive timelock + pending 机制。

### 复现（最小）
1. 对敏感键（如 `challenge_min_bond` / `resolve_authority`）调用 `set_gov_param_bootstrap_unchecked`。
2. 参数立即写入对象，无 `activate_at_height` 延迟。

### 影响
- 治理延迟防线失效（“先公告后执行”被跳过）。
- 可与 Challenge 1 联动实现治理-结算联动攻击。

### 修复
- 将 `set_gov_param_bootstrap_unchecked` 限制为 `#[cfg(test)]` 或私有 API。
- 生产路径统一走 `set_gov_param_with_action`，并在调用侧做 capability gate。

---

## Challenge 3 — 已复核更正（原 P0“库余额抽取风险”描述失效）
### 标题
原“挑战成功奖励可从全局 `treasury.worker_slashes` 支付、存在可编排抽取”的描述已不再符合当前 `trnm-pouw` 实现；当前残余风险应改记为**challenged-timeout 的 slash 治理控制面仍未真正打通**。

### 当前代码状态（2026-03-12 复核）
- `trnm-pouw/src/lib.rs` 现行 `maybe_pay_challenge_success_bounty` 仅允许从**当前任务的 worker stake lock**支付。
- 若 task-local slash principal 不足，当前实现会 **fail-closed**，不会回退抽取全局 `treasury.worker_slashes`。
- challenged-timeout 路径即使未来切到 `Slashed` 分支，当前实现也**不会自动附带发放** challenge-success bounty。

### 当前更准确的风险表述
1. `default_slash_on_unresolved_challenge` 已在 `trnm-pouw` 中具备读取与 fail-closed 解析逻辑。
2. 但 state / governance allowlist 仍可能阻断该 key 进入可执行状态，导致治理面“名义可配置、实际不可达”。
3. 2026-03-12 的 L05 复核里，连测试期使用的 `set_gov_param_bootstrap_unchecked(..., "default_slash_on_unresolved_challenge", ...)` 也仍返回 `governance key not allowed: default_slash_on_unresolved_challenge`；这进一步说明当前阻断点确实位于 state / governance 接线，而不是 `trnm-pouw` 内部布尔解析路径。
4. 因而当前主要风险在**治理控制面接线不完整**，而不是 bounty 仍可从全局 slash treasury 被抽取。

### 影响
- 产品/治理层可能误以为 challenged-timeout 惩戒规则已可配置，实际仍固定停留在默认路径。
- 经济语义上，timeout 是否应进入 slash、是否应发放 bounty、由谁承担 payout，仍未形成一条真正可治理且可验证的闭环。

### 修复
- 在 state / governance schema 中同步打通 `default_slash_on_unresolved_challenge` 的 allowlist、治理流程与回归测试。
- 若产品后续希望把 timeout-slash 也定义为 challenger 胜诉并发 bounty，需要单独设计 payout 来源、额度上限与 anti-farming 约束；不要复用或重新打开全局 treasury fallback。
- 车道边界说明：该治理键的 allowlist / schema 接线位于 `trnm-state` 治理面，不属于当前 L05 owned paths；L05 这里应继续把 `trnm-pouw` 的 timeout / payout / slash 语义保持 fail-closed，并把治理面未接通明确记为跨-lane 依赖，而不是在本 lane 越权修改 state 层。

---

## Challenge 4 — P1（参数蠕变）
### 标题
20% rate-limit 可被多轮 timelock 复合放大（参数蠕变）

### 证据
- `trnm-state/src/lib.rs:158-169`
  - 单次变更限制 `GOV_SENSITIVE_PARAM_MAX_CHANGE_BPS=2000`（±20%）。
- `trnm-state/src/lib.rs:726-745`
  - `Replace` 可在 pending 期间重置目标值与激活高度。

### 复现（最小）
- 每次 +20%，每 20 blocks 一跳，数轮后可指数逼近边界极值（如 bond/window/bounty）。

### 影响
- 虽无一次性剧变，但可在可预期时间内完成“治理慢刀子”操纵。

### 修复
- 增加 epoch 累计漂移上限（如 24h / 1k blocks 总变化不超过 X%）。
- 对关键参数采用双阈值（单次 + 累计）并记录冷却期。

---

## Challenge 5 — P1
### 标题
emergency_pause 与结算路径语义冲突：挑战任务可能被冻结

### 证据
- `trnm-node/src/main.rs:1649-1652`
  - 节点层认为 pause 期间 `Resolve` 应可执行（高风险列表中排除）。
- `trnm-pouw/src/lib.rs:888-890`
  - `apply_resolve_at_height` 在 pause 时直接拒绝。
- `trnm-pouw/src/lib.rs:1059-1063`
  - `apply_timeout` 对 Challenged 状态也在 pause 时拒绝。

### 复现（最小）
1. 任务进入 `Challenged`，并有 escrow bond。
2. 打开 `emergency_pause=true`。
3. Resolve 和 timeout 都被拒；资金与状态悬挂，直到人工解除 pause。

### 影响
- 争议结算停摆；可能造成长期资金冻结与治理信誉风险。

### 修复
- 明确策略二选一：
  - A) pause 允许“只读+结算类”最小闭环；
  - B) pause 阻断全部状态迁移但提供治理紧急强制结算通道。

---

## Challenge 6 — P1
### 标题
“二次确认”机制可 Sybil，且未被执行路径实际强制

### 证据
- `trnm-state/src/lib.rs:317-339`
  - `stage_or_confirm_resolve_approval` 仅要求“第二个 approver 字符串不同”。
- 全仓搜索仅定义未接入执行流（未见 `trnm-node` / `trnm-pouw` 调用）。

### 复现（最小）
- 攻击者提交两次不同字符串 approver（`a1`,`a2`）即可达 `confirmations>=2`。

### 影响
- 若未来启用该机制而不绑定身份签名，会形成伪多签。
- 当前则属于“安全机制名义存在、实质未生效”。

### 修复
- approver 必须绑定签名身份与委员会成员集；
- 并在 resolve 执行前强制读取并验证审批对象。

### 2026-03-12 补充核查
- 当前 `trnm-pouw` 在 challenged task 进入 timeout 终态后，已经会主动 `clear_pending_resolve_approval(task_id)`，因此“过期后仍残留半完成审批对象、可被后续终态复用”的那条 stale-approval 风险已较之前收敛。
- 当前 `trnm-pouw` 也已经把 staged approval 真正接入 `apply_resolve_at_height`：当 `resolve_authority` 配置为多成员集合时，PoUW 侧会要求两个不同成员完成 staged/confirm 流程后才允许终态结算；若治理在首个 staged approval 之后把 resolver 集合改成单成员，或把首个 approver 从集合中移除，代码会 fail-closed 并清掉陈旧 staged state。
- 但这**不改变**本 Challenge 的主结论：所谓“二次确认”目前仍然没有形成真实的 signer-bound committee control。也就是说，staged approval 的生命周期 hygiene 与部分执行前校验已经增强，但审批身份仍主要绑定在字符串 actor / signer surface 上，而不是更强的 committee-auth context；这仍需要继续作为主修复方向。

---

## Challenge 7 — P1（奖励/惩罚守恒）
### 标题
Monetary policy 仅记账不铸销到账户，且节点主循环未触发 policy_tick

### 证据
- `trnm-state/src/lib.rs:887-935`
  - `policy_tick()` 仅更新 `MonetaryState` 计数器，不改 `balances`。
- `trnm-node/src/main.rs` 全文未调用 `policy_tick/should_trigger_policy_tick`。

### 复现（最小）
- 设置货币参数后跑块，账户余额侧看不到任何 mint/burn落账，只有（若调用）内部统计变化。

### 影响
- 奖励/惩罚与总量守恒无法在账本层闭环验证。
- 经济参数存在“看起来在治理，实际不生效”的治理幻觉。

### 修复
- 在 block commit 明确触发 policy tick；
- 将 mint/burn 记账到可审计系统账户并与总供应公式强校验。

---

## Challenge 8 — P2
### 标题
挑战超时默认“完成+退还挑战者 bond”，对 worker 侧惩戒不足

### 证据
- `trnm-pouw/src/lib.rs:1058-1070`
  - Challenged 超时分支：`task.status = Completed`，并 `refund_challenge_bond = true`。
- `trnm-pouw/src/lib.rs:1093-1099`
  - 执行退还 challenger bond。

### 复现（最小）
- 让争议进入 Challenged，等待 resolve_deadline 后调用 timeout。

### 影响
- 争议无人裁决时默认偏向“无惩罚完成”，降低恶意提交的威慑强度。

### 修复
- 超时策略改为可治理配置：`default_slash_on_unresolved_challenge`；
- 或引入保守中间态（冻结收益，待后续治理仲裁）。

### 2026-03-12 补充核查
- `trnm-pouw` 已读取 `default_slash_on_unresolved_challenge` 并按布尔值决定 challenged timeout 走 `Completed` 还是 `Slashed`。
- 现有 `trnm-pouw` 侧布尔解析已经按 **fail-closed** 处理：仅接受规范化的 `1/0/true/false/yes/no/on/off`，对前后空白、零宽字符或其他畸形别名直接拒绝，而不是宽松回退到某个经济终态。
- 但当前状态层 governance allowlist 仍未放行该 key；在测试环境尝试通过 `set_gov_param_bootstrap_unchecked(..., "default_slash_on_unresolved_challenge", "true")` 注入时，返回 `governance key not allowed: default_slash_on_unresolved_challenge`。
- 因而，当前风险不是“布尔值格式可能被错误解析”，而是更基础的**治理控制面不可达**：`trnm-pouw` 已具备读取与 fail-closed 解析逻辑，但现有 state/governance schema 仍阻断该参数进入可执行状态。
- 这意味着当前实现更接近“代码里预留了治理开关，但治理面实际上还无法配置”，默认路径仍然固定为 `Completed + refund challenger bond`。
- 若要把超时惩戒真正落成可治理经济规则，需要同步打通 state allowlist / governance schema 与对应回归测试，否则会形成“名义可配置、实际不可达”的控制面错觉。
- 另一个需要显式记录的经济语义是：当前 `trnm-pouw` 的 challenge-success bounty 只在**显式 slash resolve** 路径发放，且资金来源被限制为**当前任务的 worker stake lock**；challenged timeout 即使未来切到 `Slashed` 分支，也不会从全局 `treasury.worker_slashes` 或 timeout 路径额外发放 bounty。
- 这意味着“无人裁决超时 → 自动 slash → 直接领 bounty”的激励链路当前并不存在；若后续产品语义希望把 timeout-slash 也视为 challenger 胜诉，需要在设计上额外说明是否允许 payout、由谁承担，以及如何避免把无人裁决路径重新变成 bounty farming 面。
- 另外，原 Challenge 3 所述“challenge-success bounty 可从全局 `treasury.worker_slashes` 回退支付”的 P0 经济面，已不再符合当前 `trnm-pouw` 实现：现有实现只允许从**当前任务的 worker stake lock**支付 bounty，并在 task-local slash principal 不足时 fail-closed，而不会回退抽取全局 slash treasury。当前遗留风险更准确地说是：**timeout-slash 的治理控制面仍未真正打通**，而不是 bounty 仍可直接抽取全局 slash 库。
- 当前 L05 代码侧已覆盖的语义应单独记账：默认 challenged-timeout 仍固定走 `Completed + refund challenger bond`，不会碰全局 slash treasury；而合成的 slash-path 校验也要求资金流保持 task-local，并且**不会**因为 timeout 自动附带发放 challenge-success bounty。换言之，当前 PoUW 剩余风险主要在**治理键可达性/控制面接线**，而不是 timeout 结算路径在 `trnm-pouw` 内部重新打开了全局赏金抽取面。
- 2026-03-14 L05 再次用回归钉住了这一点：`default_slash_on_unresolved_challenge` 目前仍被 state governance allowlist 拒绝，PoUW 侧只能继续 fail-closed 地回落到默认 `false`，不能把该开关误当成已上线可治理参数。
- 2026-03-14 L05 还补了一条输入规范化回归：即使后续治理面接通，`default_slash_on_unresolved_challenge` 也必须继续拒绝 Unicode homoglyph 布尔别名（例如全角 `ｅ`、西里尔/希腊字母伪装的 `a/o`），避免把“看起来像 true/false/on/off”的非 ASCII 令牌误解析成经济终态开关。
- 同轮也补充钉住了 fullwidth digit / Unicode whitespace 变体（例如 `１` / `０` / `true\u00a0` / `o\u00a0n`）：这些“看起来像布尔开关”的输入必须保持 fail-closed，不能在未来治理接线完成后被宽松解析成 challenged-timeout 的经济终态切换。
- 2026-03-12 当前 L05 回归覆盖可明确锚定到两条语义测试：
  - `challenged_timeout_default_path_does_not_pay_bounty_or_touch_global_slash_treasury`
  - `challenged_timeout_slash_path_only_moves_task_local_stake_and_never_auto_pays_bounty`
  这两条测试分别约束：默认 timeout 只能退还 challenger bond 且不得触碰 `treasury.worker_slashes`；以及进入 slash 结算语义时，资金流也只能搬运当前任务的 worker stake lock，且**不会**顺带自动发放 challenge-success bounty。

---

## 额外说明（针对指令中的四个必答点）

1. **timelock 绕过**：见 Challenge 2（`set_gov_param_bootstrap_unchecked`）。
2. **参数蠕变**：见 Challenge 4（20% 复合漂移 + replace 重排）。
3. **奖励/惩罚守恒**：见 Challenge 7（policy tick 未落账、节点未触发）。
4. **库余额抽取风险**：Challenge 3 反映的是历史高风险面，但按 2026-03-12 的补充核查，当前 `trnm-pouw` 已不再允许 challenge-success bounty 回退抽取全局 `treasury.worker_slashes`；现阶段更准确的遗留风险是 Challenge 8 补充段指出的 **timeout-slash 治理控制面未真正打通**，即 `default_slash_on_unresolved_challenge` 仍停留在代码预留、治理侧不可达。

---

## 建议优先级

- 立即修复（72h）：Challenge 1/2/3
- 短期修复（1-2 周）：Challenge 4/5/7
- 中期修复（版本窗口）：Challenge 6/8
