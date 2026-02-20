# Worker ↔ Chain 对接规范 v1（生产级）

更新日期：2026-02-19  
状态：Draft v1（用于实现冻结，已补充 contract smoke）

## 1. 目标

定义 Worker 与链上 PoUW 结算路径的最小生产规范，保证：
- 幂等（重复事件不会重复结算）
- 可恢复（崩溃后可续跑）
- 可观测（失败有统一字段可追踪）

Canonical 结算路径遵循：
`accept-task -> commit-result -> reveal-result -> (optional challenge-result)`

---

## 2. 最小字段契约

Worker 在执行后必须产出：
- `task_id`（链上任务 ID）
- `worker_addr`（绑定 worker）
- `result_hash`（业务结果哈希）
- `result_uri`（结果工件地址，如 IPFS CID）
- `reveal_salt`（仅 worker 本地安全持久化）
- `commit_hash = sha256(task_id|result_hash|reveal_salt|worker_addr)`

建议扩展（可选但推荐）：
- `execution_meta`：镜像 digest、运行时、退出码、耗时、资源用量摘要
- `trace_id`：链上事件与 worker 日志关联 ID

---

## 3. 状态与幂等策略

本地状态文件（建议 `worker_state.json`）至少包含：
- `last_height`
- `task_id -> phase`
- `task_id -> tx_hashes[]`
- `task_id -> reveal_salt`（加密存储或至少权限隔离）

phase 建议：
- `detected`
- `accepted`
- `executed`
- `committed`
- `revealed`
- `finalized`（链上完成/被挑战后已退出）

幂等规则：
1. 若链上已非预期前置状态（例如已 `COMMITTED`），跳过重复提交并推进本地 phase。
2. tx 广播返回 sequence mismatch 时必须重查 sequence 后重试。
3. 同一 task 的 commit/reveal 只能存在一个“活动提交器”（基于链上 worker 绑定）。

---

## 4. 重试与超时策略（建议默认）

- 广播模式：`sync`（当前链 CLI 支持）
- 提交后确认：轮询 `query tx`，超时 60s（每 1s）
- 重试上限：6 次
- 退避：`0.8s + attempt*0.3s`（线性）

可重试错误：
- `account sequence mismatch`
- 临时 RPC 网络错误（连接重置/超时）

不可重试错误（直接失败并告警）：
- 权限错误（非绑定 worker / authority-only）
- 状态机错误（非法状态迁移）
- 参数校验错误（hash 格式非法等）

---

## 5. 失败恢复

Worker 重启后恢复逻辑：
1. 读取本地 state。
2. 对每个未完成 task 查询链上真实状态。
3. 执行“状态对齐”：
   - 链上已到更后阶段 -> 本地 phase 前移，不重复发 tx。
   - 链上落后且本地有可继续材料（如 reveal_salt）-> 继续执行下一 tx。
4. 若 task 已进入 `CHALLENGED/SLASHED/COMPLETED`，本地标记 `finalized`。

---

## 6. 可观测性（日志与事件）

Worker 日志必须结构化至少包含：
- `timestamp`
- `level`
- `task_id`
- `phase`
- `tx_hash`
- `attempt`
- `error_code`（若失败）
- `trace_id`

链上对齐检查：
- 至少能按 `task_id` 对应到状态迁移与 `workload_fund_flow` 事件。
- 对失败 tx，保存 raw_log 原文用于复盘。

---

## 7. 安全要求

- `reveal_salt` 不上链前不得泄漏。
- 密钥管理禁止硬编码私钥；沿用 keyring/外部签名器。
- 不允许通过 legacy `update-task` 走生产结算。
- `submit-result` 仅作为兼容路径，不作为新实现默认。

---

## 8. 验收清单（P1-2 DoD）

- [ ] 单任务 happy path 稳定通过：accept -> commit -> reveal
- [ ] sequence mismatch 自动恢复通过
- [ ] worker 重启后可无重复结算地续跑
- [ ] 失败日志具备 task_id/tx_hash/phase 三元组
- [ ] 与 `INTERFACE_FREEZE_POUW_V1.md` 无冲突

---

## 9. 实施顺序（建议）

1. 在 worker 侧新增 phase 持久化与状态对齐器
2. 抽象 tx 提交器（广播+确认+重试）
3. 接入 commit/reveal 主路径
4. 加入故障注入测试（sequence/rpc timeout）
5. 回归到 `scripts/p0_acceptance.sh` 之后作为 P1 smoke

### 当前可执行检查（最小）

```bash
./scripts/worker_onchain_contract_smoke.sh
```

通过标准：输出 `[OK] worker onchain contract smoke passed`。
