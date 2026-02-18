# Trillionnium MVP 验收测试矩阵（5 场景）

> 目标：每个场景都要有“前置条件 / 步骤 / 通过标准 / 失败判据 / 关键事件”

## 场景 A：正常完成（Happy Path）
**前置条件**
- Worker 已注册并满足最小质押
- 账户余额足够支付 bounty + gas

**步骤**
1. 创建任务（含镜像、输入、赏金、deadline）
2. Worker 拉取并执行
3. Worker 提交结果
4. 经过最小验证后 finalize

**通过标准**
- 任务状态变为 `Finalized`
- Worker 收到 bounty
- 事件完整（create/submit/finalize）

**失败判据**
- 资金未转移或状态卡在 submitted

---

## 场景 B：超时未提交（Timeout）
**前置条件**
- 任务设置较短 deadline

**步骤**
1. 创建任务
2. Worker 不提交结果直到超过 deadline
3. 执行超时处理逻辑

**通过标准**
- 任务状态转为 `Expired`/`Failed`（以实现为准）
- 赏金按规则退回或进入可申诉态

**失败判据**
- 超时后仍可正常 finalize

---

## 场景 C：无效结果被挑战（Challenge Success）
**前置条件**
- 存在已提交但可证明错误的结果
- 处于 challenge window 内

**步骤**
1. 提交错误结果
2. 挑战者发起 challenge
3. 验证节点重放并裁决

**通过标准**
- 挑战成功，任务进入争议处理完成态
- 错误结果不被结算

**失败判据**
- 明显错误结果仍通过 finalize

---

## 场景 D：恶意结果触发 Slash
**前置条件**
- Worker 有可罚没质押

**步骤**
1. 复用场景 C 的挑战成功结果
2. 执行 slash-worker

**通过标准**
- 质押减少，且不超过上限（例如 <= 50%）
- slash 事件带有原因与金额
- 模块 authority 限制生效（非授权不能 slash）

**失败判据**
- 任意账户可直接 slash 或 slash 越界

---

## 场景 E：解质押冷却与提现
**前置条件**
- Worker 有有效质押并可申请 unbonding

**步骤**
1. `request-unbonding`
2. 冷却期内尝试 `finalize-unbonding`（应失败）
3. 冷却结束后再次 finalize（应成功）

**通过标准**
- 冷却前无法提现
- 冷却后可提现且金额正确
- lifecycle 事件完整

**失败判据**
- 可绕过冷却直接提现

---

## 总体验收门槛
- 5/5 场景通过
- 所有失败场景可稳定复现
- 每个场景至少 1 份日志证据 + 关键 tx hash
