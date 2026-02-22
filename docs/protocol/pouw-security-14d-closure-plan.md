# PoUW 上线前 14 天安全收口清单（v0.1）

目标：在不做破坏性重构前提下，把 PoUW 从“可用”推进到“可上线评审”。

## 验收总线（Day 14 必须同时满足）

1. 共识安全矩阵稳定通过（连续 3 次 PASS，且不同时间窗口）。
2. Agent↔User Phase A gate 连续 3 次 PASS。
3. replay/nonce/seq/timestamp 负向测试覆盖（最小 12 条）全绿。
4. 所有关键路径都有可追溯证据（run/health + summary + commit）。
5. 发布分支历史干净（仅最小必要 commit，禁止混入临时 merge 噪音）。

## Day 1-3：协议与校验硬化

- 固化 envelope 规范字段（version/type/seq/nonce/hash/sig）
- 统一错误码语义（BadSig/Replay/SeqRegression/TimeSkew）
- 增加校验单测：
  - 过期时间窗
  - 同 nonce 跨 session
  - seq 回退/跳跃
  - payload_hash 篡改

产物：
- `crates/trnm-types` 测试日志
- 错误码对照表（docs）

## Day 4-6：可靠性与状态管理

- 将内存态 dedup/pending 增加 TTL 清理策略
- ACK 批量确认（session + upto_seq）
- retry 上限与熔断策略（避免无限重试）
- 增加并发集成测试（多 session + 重试抖动）

产物：
- reliability 模块测试报告
- 参数基线（base/max backoff, retry max）

## Day 7-9：争议可验证性

- 增加 transcript segment hash/Merkle 根生成
- 提供 proof 查询接口（最小可用）
- challenge 流程接入 proof 校验桩
- 增加“缺片段/篡改片段”负向用例

产物：
- proof API 文档
- challenge 验证样例日志

## Day 10-11：门禁与回归

- 将 Phase A gate + consensus security matrix 打包成 one-shot gate
- CI 引入 required checks（PR 阶段强制）
- fail-fast：一处失败直接红灯并输出定位建议

产物：
- `.github/workflows/*gate*.yml`
- `scripts/run_*_gate.sh`

## Day 12-13：发布前演练

- 冷启动演练（空目录）
- 脏状态恢复演练（WAL/ingress 残留）
- 断网/重启恢复演练
- 生成上线 Runbook 与回滚手册

产物：
- 演练记录（run/health）
- `OPERATIONS.md` 回滚章节

## Day 14：Go/No-Go 评审

- 汇总：测试、门禁、已知风险、缓解措施
- 明确 3 类结论：
  - GO：可上线
  - CONDITIONAL GO：带限制上线
  - NO-GO：阻断项清单

产物：
- `docs/protocol/pouw-go-nogo-review-template.md`（可复用）

---

## 当前阻断项（已处理）

- Phase A gate 脚本参数解析错误：`--text` 引号转义不当导致被拆词。
- 已修复 `scripts/run_agent_user_phasea_gate.sh`，并本地复跑 PASS：
  - `status=COMMIT_QUEUED`
  - `verifier_status=accepted`

## 推荐节奏

- 每晚 1 次全量 gate
- 每次改动后至少 1 次最小 gate
- 每 3 天产出一次风险盘点（新增风险/已关闭风险）
