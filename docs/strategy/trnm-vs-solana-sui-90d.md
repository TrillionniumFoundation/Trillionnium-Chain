# Trillionnium 90-Day Catch-up Plan (vs Solana/Sui)

日期：2026-02-19  
目标：在不牺牲 PoUW 语义的前提下，把 Rust L1 从“可运行原型”推进到“可对外试运行网络（Dev/Test）”

## 0. North Star（90天终局）

到 D+90 达成：
1. **协议稳定**：v1 冻结语义全部落地（状态机/错误码/事件）。
2. **工程稳定**：连续 7 天 nightly 全绿，关键 gate 无回滚告警。
3. **性能可解释**：给出 classic/mixed 两类负载的稳定 P50/P95 基线。
4. **开发者可接入**：最小 SDK + 示例 dApp（任务创建/验证/挑战）。
5. **试运行网络**：3~5 节点 testnet，具备可重复部署与回滚 runbook。

---

## 1. 对标维度（与 Solana/Sui 比）

- **先不比生态体量**，先比“可运行性与可信度”：
  - 协议一致性
  - 性能稳定性
  - 运维可恢复性
  - 开发者上手门槛

- **阶段策略**：
  - D+0~30：把“正确性红线”焊死（像 Sui 的对象一致性哲学）
  - D+31~60：把“吞吐-延迟曲线”做平并可解释
  - D+61~90：把“外部可用性”做出来（SDK/文档/testnet）

---

## 2. 分阶段计划

## Phase A（D+0~30）：协议与正确性硬化

### A1. 状态机对齐（本周收口）
- [x] `accept_task: OPEN -> ASSIGNED`
- [x] `commit_result: ASSIGNED -> COMMITTED`
- [x] worker 绑定校验（Unauthorized）
- [x] 增加状态迁移矩阵测试（所有非法迁移显式断言 InvalidTransition）

### A2. 错误码稳定映射
- [ ] 对外错误码枚举固定（7个最小集合）
- [ ] state 层错误到协议错误映射覆盖表（文档+单测）

### A3. 事件审计闭环
- [x] 事件字段冻结检查脚本
- [x] 增加事件 schema 版本号（例如 `event_schema=v1`）
- [x] 增加事件样本回放测试（happy + forged reveal）

### A4. CI 红线强化
- [ ] nightly 增加“非法迁移回归集”
- [ ] state_root 审计加入抖动容忍策略与重试
- [ ] 引入 flaky 识别（同 case 连续运行 20 次）

**A 阶段验收指标**
- workspace tests 连续 5 天全绿
- state_root mismatch=0, missing=0（nightly）
- 协议冻结清单 100% 映射到测试项

---

## Phase B（D+31~60）：性能工程化（对标“可解释性能”）

### B1. 基线体系
- [ ] 固化 benchmark profile：classic / mixed / skewed-hotspot
- [ ] 输出统一报告：P50/P95、group_count、冲突率、CPU 时间分布
- [ ] 每次优化必须带 before/after 报告（可回滚）

### B2. 执行器优化主线（仅 Original 默认）
- [ ] 持续优化 `Original` 热路径（分配、哈希、局部性）
- [x] `AggressiveGreedy` 保持实验分支，不进入默认
- [ ] 增加“吞吐提升但语义不变”的自动证明脚本（回放+state_root）

### B3. 并行执行从预执行走向稳定并发
- [ ] 从当前 pre-exec 验证推进到受控并行 apply
- [x] 引入 deterministic apply 顺序约束（保证可重放）
- [x] 并发失败路径观测：冲突重试/回退原因统计

**B 阶段验收指标**
- 相比 D0 基线：mixed 负载 P95 降低 >= 30%
- 并行路径下 0 apply_error / 0 rollback 告警（7天）
- spot-check hard gate 无回归（连续 50 次）

---

## Phase C（D+61~90）：对外可用性（最小生态）

### C1. 节点与运维
- [ ] 一键 testnet 部署脚本（3~5 节点）
- [ ] 快照/恢复/回滚 runbook 完整演练
- [ ] 基础监控：出块、确认延迟、状态根一致性、错误码分布

### C2. 开发者入口
- [ ] 最小 SDK（Rust/TS 二选一优先）
- [ ] 示例应用：任务发布、worker 接单、commit/reveal、challenge
- [ ] 文档站最小闭环（Quickstart + API + 错误码 + 事件）

### C3. 安全与审计准备
- [ ] 威胁模型 v1（重放、前置、伪造 reveal、挑战滥用）
- [ ] 外部审计前 checklist（关键模块清单 + 不变量）

**C 阶段验收指标**
- 外部开发者 30 分钟内跑通 Quickstart
- testnet 稳定运行 >= 14 天
- 关键路径（create->resolve）SLO 可公开披露

---

## 3. 建议 KPI（每周看板）

1. 正确性：
   - `invalid_transition_regressions`
   - `state_root_mismatch_count`
2. 性能：
   - `bench_classic_p95_ms`
   - `bench_mixed_p95_ms`
   - `executor_conflict_hit_rate`
3. 稳定性：
   - `nightly_green_streak_days`
   - `parallel_sanity_failures`
4. 可用性：
   - `quickstart_time_to_success`
   - `testnet_uptime`

---

## 4. 战略结论（直白版）

- **短期不要跟 Solana/Sui 比“生态总量”**，先比“可验证的工程质量”。
- 你现在最有机会打赢的是：
  - AI 任务语义深度（PoUW 专用状态机）
  - 协议可塑性（快速迭代）
- 90 天目标不是“成为 Solana/Sui”，而是：
  - 成为一个 **在 AI Compute 任务结算场景里，稳定、可解释、可接入** 的专用链。
