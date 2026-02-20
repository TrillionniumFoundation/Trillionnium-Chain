# Trillionnium 12周路线图：共识 → 治理 → Ecosystem

更新时间：2026-02-20

## 总原则
- 顺序固定：**先共识机制稳定，再最小治理上线，最后生态扩张**。
- 每阶段必须有“可量化退出条件（Exit Criteria）”，未达标不进入下一阶段。
- 默认以 Rust L1 主线为唯一真相源，避免多分支叙事。

---

## Phase A（Week 1-4）：共识机制收敛与抗压验证

### 目标
1. 明确并冻结共识/执行边界（出块、最终性、异常恢复）。
2. 完成多节点长稳压测与故障注入闭环。
3. 建立共识层 SLO 与红线告警。

### 关键交付
- `docs/protocol/consensus-v1-freeze.md`
- `scripts/run_consensus_fault_matrix.sh`（网络抖动/节点重启/延迟注入）
- `run/health/consensus-slo-*.md`（自动日报）

### Exit Criteria（必须全部满足）
- 连续 7 天 nightly 全绿（关键 gate 无红线）。
- 3 节点以上环境下，故障注入场景恢复成功率 ≥ 99%。
- 在目标负载下，最终性 P95 与吞吐波动均在阈值内（阈值写入文档并固化到 CI）。

---

## Phase B（Week 5-8）：链上治理最小可用（Gov-MVP）

### 目标
1. 上线治理最小闭环：提案、投票、执行、紧急刹车。
2. 治理参数与升级流程可审计、可回滚。
3. 把“治理失败模式”前置演练。

### 关键交付
- `docs/protocol/governance-mvp-v1.md`
- `docs/protocol/upgrade-governance-runbook.md`
- `scripts/gov_mvp_e2e.sh`（提案→投票→执行→验证）

### Exit Criteria
- Gov-MVP E2E 连续通过 20 次以上（含负向用例）。
- 至少 2 次“参数调整 + 回滚”演练成功并有审计记录。
- 紧急刹车机制演练通过（触发、恢复、追溯日志完整）。

---

## Phase C（Week 9-12）：Ecosystem 启动与开发者通路

### 目标
1. 固化开发者入口（SDK/API/示例/模板）。
2. 建立生态激励最小模型（grant/bounty/合作试点）。
3. 形成对外可复用 benchmark + narrative 套件。

### 关键交付
- `docs/ecosystem/dev-onboarding-v1.md`
- `examples/`（3个以上端到端样例）
- `docs/ecosystem/grant-program-v0.md`
- 对标报告：`docs/strategy/trnm-vs-solana-sui-quarterly.md`

### Exit Criteria
- 外部开发者（非核心成员）独立跑通示例 ≥ 5 组。
- 至少 2 个真实 PoC 项目进入持续迭代。
- 对外 benchmark 报告按月稳定发布（格式冻结）。

---

## 每周执行节奏（模板）
- 周一：目标与风险对齐（冻结本周 gate）
- 周二~周四：实现 + 回归 + 故障注入
- 周五：周报 + 决策 memo + 下周准入审查

---

## 风险与应对
1. **性能波动遮蔽语义问题**：强制 semantic gate 先于 perf gate。
2. **治理过早复杂化**：先 MVP，拒绝一次性上全功能宪法。
3. **生态叙事先行于稳定性**：对外承诺只基于已冻结接口与已验证 SLO。

---

## 立即下一步（本周）
1. 建立 `consensus-v1-freeze.md` 草案。
2. 定义共识层 5 个核心 SLO（最终性、恢复时间、分叉窗口、吞吐稳定性、错误率）。
3. 把 `run_consensus_fault_matrix.sh` 纳入 auto relay steps（对标版）。
