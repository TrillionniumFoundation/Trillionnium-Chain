# TRNM Lane C Review（Tokenomics / Governance 经济安全）

- 日期：2026-03-05
- 范围：`trnm-state` / `trnm-pouw` / `trnm-node`
- 结论：发现 8 条 challenge（含 3 条 P0）

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

## Challenge 3 — P0（库余额抽取风险）
### 标题
挑战成功奖励可从全局 `treasury.worker_slashes` 支付，存在可编排抽取

### 证据
- `trnm-pouw/src/lib.rs:567-607`
  - `maybe_pay_challenge_success_bounty`：若 task lock 不足，则从 `WORKER_SLASH_TREASURY_ACCOUNT` 回退支付。
- `trnm-pouw/src/lib.rs:1018-1022`
  - resolve(slash=true) 时触发该奖励逻辑。
- `trnm-pouw/src/lib.rs:557-559`
  - worker 被 slash 的 stake 进入同一 treasury 池。

### 复现（最小）
1. 使用协同账号（worker/challenger 非同一账号，满足当前校验）循环构造可 slash 任务。
2. 在 worker 最小 stake 或 lock 可不足情况下，奖励从全局 slash 池补足。
3. 重复后可持续搬运历史 slash 池余额到 challenger 侧。

### 影响
- 全局惩罚库可被策略性“挖空”；惩罚资金不再服务公共安全缓冲。
- 形成逆激励：攻击者偏好制造可 slash 事件以提取库资金。

### 修复
- 挑战成功奖励仅允许来自**当前任务**可归属罚没，不得回退全局池。
- 或引入全局奖励预算上限/epoch 配额与速率限制。

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
- 但当前状态层 governance allowlist 仍未放行该 key；在测试环境尝试通过 `set_gov_param_bootstrap_unchecked(..., "default_slash_on_unresolved_challenge", "true")` 注入时，返回 `governance key not allowed: default_slash_on_unresolved_challenge`。
- 因而，当前风险不是“布尔值格式可能被错误解析”，而是更基础的**治理控制面不可达**：`trnm-pouw` 已具备读取与 fail-closed 解析逻辑，但现有 state/governance schema 仍阻断该参数进入可执行状态。
- 这意味着当前实现更接近“代码里预留了治理开关，但治理面实际上还无法配置”，默认路径仍然固定为 `Completed + refund challenger bond`。
- 若要把超时惩戒真正落成可治理经济规则，需要同步打通 state allowlist / governance schema 与对应回归测试，否则会形成“名义可配置、实际不可达”的控制面错觉。
- 另一个需要显式记录的经济语义是：当前 `trnm-pouw` 的 challenge-success bounty 只在**显式 slash resolve** 路径发放，且资金来源被限制为**当前任务的 worker stake lock**；challenged timeout 即使未来切到 `Slashed` 分支，也不会从全局 `treasury.worker_slashes` 或 timeout 路径额外发放 bounty。
- 这意味着“无人裁决超时 → 自动 slash → 直接领 bounty”的激励链路当前并不存在；若后续产品语义希望把 timeout-slash 也视为 challenger 胜诉，需要在设计上额外说明是否允许 payout、由谁承担，以及如何避免把无人裁决路径重新变成 bounty farming 面。
- 另外，原 Challenge 3 所述“challenge-success bounty 可从全局 `treasury.worker_slashes` 回退支付”的 P0 经济面，已不再符合当前 `trnm-pouw` 实现：现有实现只允许从**当前任务的 worker stake lock**支付 bounty，并在 task-local slash principal 不足时 fail-closed，而不会回退抽取全局 slash treasury。当前遗留风险更准确地说是：**timeout-slash 的治理控制面仍未真正打通**，而不是 bounty 仍可直接抽取全局 slash 库。
- 当前 L05 代码侧已覆盖的语义应单独记账：默认 challenged-timeout 仍固定走 `Completed + refund challenger bond`，不会碰全局 slash treasury；而合成的 slash-path 校验也要求资金流保持 task-local，并且**不会**因为 timeout 自动附带发放 challenge-success bounty。换言之，当前 PoUW 剩余风险主要在**治理键可达性/控制面接线**，而不是 timeout 结算路径在 `trnm-pouw` 内部重新打开了全局赏金抽取面。

---

## 额外说明（针对指令中的四个必答点）

1. **timelock 绕过**：见 Challenge 2（`set_gov_param_bootstrap_unchecked`）。
2. **参数蠕变**：见 Challenge 4（20% 复合漂移 + replace 重排）。
3. **奖励/惩罚守恒**：见 Challenge 7（policy tick 未落账、节点未触发）。
4. **库余额抽取风险**：见 Challenge 3（challenge bounty fallback 到全局 slash treasury）。

---

## 建议优先级

- 立即修复（72h）：Challenge 1/2/3
- 短期修复（1-2 周）：Challenge 4/5/7
- 中期修复（版本窗口）：Challenge 6/8
