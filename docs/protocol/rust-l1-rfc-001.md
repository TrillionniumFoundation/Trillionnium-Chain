# TRNM Rust L1 RFC-001（高吞吐任务流最小闭环）

状态：Draft-v0.1（待齐教授拍板）  
日期：2026-02-19  
决策约束：允许 break change；优先高吞吐任务流；1周交付测试网可运行最小版本。

---

## 1. 目标

在 7 天内交付 Rust-native L1 的最小可用版本（MVP），用于承载去中心化 AI agent 高并发任务流：

- 3 节点网络可持续出块
- PoUW 状态机核心路径可执行
- 冲突可判定、无冲突可并发执行
- 具备可追溯重演能力

非目标（本阶段不做）：
- 完整治理系统
- 通用智能合约生态
- 跨链桥与复杂经济扩展

---

## 2. 状态模型（对象化）

对象类型：

1. `TaskObject`
   - `task_id: u64`
   - `creator: Address`
   - `bounty: u128`
   - `status: enum { OPEN, ASSIGNED, COMMITTED, REVEALED, CHALLENGED, COMPLETED, SLASHED }`
   - `worker: Option<Address>`
   - `committed_hash: Option<Hash32>`
   - `result_hash: Option<Hash32>`
   - `reveal_salt: Option<Bytes32>`
   - `version: u64`

2. `WorkerObject`
   - `worker: Address`
   - `stake: u128`
   - `active: bool`
   - `slash_count: u32`
   - `version: u64`

3. `ChallengeObject`
   - `task_id: u64`
   - `challenger: Address`
   - `deposit: u128`
   - `opened_at_height: u64`
   - `resolved: bool`
   - `version: u64`

所有对象采用 `(object_id, version)` 版本化，禁止隐式覆盖写。

---

## 3. 交易模型（吞吐优先）

每笔交易必须显式声明：
- `read_set: Vec<ObjectRef>`
- `write_set: Vec<ObjectRef>`

调度规则：
- 两笔交易 `write/write` 或 `read/write` 冲突 => 不并行
- 无冲突 => 可并行执行
- 冲突交易进入串行队列（确定性顺序）

确定性要求：
- Canonical 序列化（固定字段顺序、固定编码）
- Hash 管线固定（SHA-256）
- 相同块输入在任意节点上输出相同状态根

---

## 4. PoUW 最小状态转移（MVP）

1. `CreateTask`
2. `AssignTask`
3. `CommitResult`
4. `RevealResult`
5. `ChallengeTask`
6. `ResolveChallenge`

Commit 规则：
`commit = sha256("{task_id}|{result_hash}|{reveal_salt}|{worker_address}")`

---

## 5. 性能目标（Week-1）

- 单分片任务流目标：
  - 峰值吞吐：>= 1,000 tx/s（任务型轻交易）
  - P95 延迟：<= 2s（本地 3 节点）
- 正确性目标：
  - 并发回放一致性 100%
  - 状态机关键场景回归通过率 100%

---

## 6. 回滚与风险控制

- 保留现有稳定分支为 fallback
- Rust L1 在 Week-1 期间仅作为新测试网分支
- 若出现以下任一情况，立即触发回滚：
  - 共识不稳定（频繁分叉/停块）
  - 回放不一致
  - 关键状态机错误（资金/惩罚路径异常）

---

## 7. 待拍板参数（今天必须定）

1. `challenge_window_blocks`（建议先沿用 100）
2. `challenge_deposit`（建议先沿用 1_000_000）
3. `worker_slash_percent_on_bad_result`（建议先沿用 20）
4. `minimum_worker_stake`（建议先沿用 100_000）

> 建议：Week-1 不改经济参数，只改执行架构，避免混淆变量。
