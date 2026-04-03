# Trillionnium 开发总文档（统一调度版）

更新日期：2026-03-04 17:10 CST  
目标：将当前分散开发文档收敛为单一调度入口，统一“完成项 / 未完成项 / 下一步执行”。

---

## 0. 使用方式（从今天开始）

本文件作为**开发调度入口**（planning board），不是 release truth source。

- 日常推进：优先看本文件的 **第 3 节执行看板**
- 新增子任务：先写到本文件再开工
- 老文档不删，但视为“证据/历史”，不再作为主调度源
- 若与 `RELEASE_READINESS.md` 冲突：**发布口径以 `RELEASE_READINESS.md` 为准**；若与 `docs/archive/root-history/STATUS.md` 冲突：后者仅保留历史记录

### 0.1 入口地图（防止引用漂移）

- **当前是否 release-ready / 哪个文档能当真相源**：看仓库根 `RELEASE_READINESS.md`
- **开发排期 / lane 调度 / 下一步执行优先级**：看本文
- **ZKP 平台边界 / backend 抽象 / payload 与错误契约**：看 `docs/architecture/TRNM_ZKP_PLATFORM_V0.md`
- **混合参考架构（Solana / Sui / Conflux 分层借鉴原则）**：看 `docs/architecture/TRNM_HYBRID_REFERENCE_ARCHITECTURE_V0.md`
- **混合参考架构的 crate 级实施路线图**：看 `docs/development/TRNM_HYBRID_REFERENCE_CRATE_ROADMAP_V0.md`
- **`trnm-node` 可执行拆分方案（文件树 / 搬迁顺序 / 每刀 gate）**：看 `docs/development/TRNM_NODE_MODULE_SPLIT_PLAN_V0.md`
- **`trnm-node` PR-1 实际迁移清单（第一刀搬什么、怎么搬、怎么过 gate）**：看 `docs/development/TRNM_NODE_SPLIT_PR1_PLAN_V0.md`
- **benchmark closeout 方法、产物字段、micro→system bridge**：看 `docs/reports/TRNM_WEEK7_E2E_CLOSEOUT_BENCHMARK_SYSTEM_2026-03-10.md`
- **并发瓶颈图、8 周路线、对外并发 closeout 口径**：看 `docs/reports/TRNM_CONCURRENCY_BOTTLENECK_MAP_AND_8W_ROADMAP_2026-03-10.md`

> 规则：本文可以引用上述文档作为专题权威，但**不覆盖**它们各自的专题口径；反之，专题文档若涉及发布判断，也必须回指 `RELEASE_READINESS.md`。

---

## 1. 范围与当前基线

### 1.1 代码主线
- 主代码：`trillionnium-rust/`
- 前端主线：`web4-frontend/`

### 1.2 已统一纳入的文档簇
- 根级 / 历史入口：`README.md / docs/archive/root-history/STATUS.md / docs/archive/root-history/ROADMAP.md / docs/archive/root-history/BACKLOG.md / OPERATIONS.md`
- 开发：`docs/development/*`
- 架构：`docs/architecture/*`
- Rust 侧 runbook/报告：`trillionnium-rust/docs/*`
- Web4：`web4-frontend/docs/*`

---

## 2. 完成度评估（项目级）

## 2.1 总体完成度（当前）
- 工程总体：**78%**
- 内测可用：**85%**
- 主网就绪：**58%**

## 2.2 分域完成度

1) **PoUW 核心状态机**（create/accept/commit/reveal/challenge/resolve/timeout）  
- 完成度：**90%**  
- 状态：核心闭环稳定，门禁覆盖较高。

2) **PoUW 安全硬化**（auth signer + proof binding）  
- 完成度：**80%**  
- 已完成：
  - signer fallback 风险收敛（node）
  - proof 上下文绑定（task_id/worker/proof_type）
- 未完成：
  - TEE/ZK 真密码学验证后端接入

3) **BFT 共识主线**  
- 完成度：**70%**  
- 已完成：round/投票/WAL/checkpoint/recovery 基础链路  
- 未完成：
  - 网络化对抗能力（分区/恶意 gossip）
  - 共识验证者经济惩罚闭环

4) **并发架构重构（免费高并发入口）**  
- 完成度：**50%（进行中）**  
- 已完成：
  - Lane A：Consensus-DA-Execution 分层骨架（done）
  - Lane B：Mempool QoS 协议化（done）
- 进行中：
  - Lane C：RPC/Ingress 协议统一（running）
  - Phase 1 实装（running）

5) **自适应 Tokenomics（MonetaryState + policy_tick）**  
- 完成度：**40%（进行中）**  
- 已见进展：trnm-state 已有 policy_tick 相关测试项并通过  
- 未完成：node 触发接线、事件对外、治理护栏一体化

6) **Web4 前端与文档收口**  
- 完成度：**88%**  
- 已完成：
  - README + docs 重构
  - 旧只读链路清理
  - `ci:check` 全绿（默认 e2e 关闭）
- 未完成：
  - e2e 在目标环境稳定门禁化

---

## 3. 统一执行看板（唯一调度板）

## A. 已完成（Done）

- [x] PoUW v1 核心迁移与事件冻结（历史阶段，详见 `docs/archive/root-history/STATUS.md` / `docs/archive/root-history/BACKLOG.md`）
- [x] PoUW auth hardening（node）
- [x] PoUW proof binding（pouw verifier）
- [x] Lane A（protocol_layer 骨架 + 开关 + 测试）
- [x] Lane B（mempool 协议与 QoS + admission + 测试）
- [x] Web4 文档重构与旧文档迁移

## B. 进行中（In Progress）

1. **Lane C：RPC/Ingress 协议统一**
- 目标：submit-free-task 协议对象、幂等+配额、兼容层
- 期望产物：`trnm-rpc` 新测试与稳定接口

2. **Free Ingress Phase 1 实装**
- 目标：ingress queue + idempotency + basic quota + node 优先级调度
- 涉及：`trnm-rpc / trnm-mempool / trnm-node`

3. **MonetaryState + policy_tick 落地**
- 目标：state 接口 + node 触发 + 事件 + 测试

## C. 未完成（Next）

### P0（必须完成）
- [ ] 任务 bounty escrow 结算闭环（create 锁定、完成/超时/slash 路径守恒）
- [ ] resolve 权限最小多方化（去单点）
- [ ] 免费提交流量下 critical 交易不饿死门禁

### P1（强建议完成）
- [ ] challenge 奖励双上限（绝对 + 相对）
- [ ] 发行/销毁/流通状态统一到账本事件
- [ ] e2e 纳入 CI 可控门禁（可配置环境）

### P2（增强）
- [ ] DA 层与排序层继续解耦（Lane A 第二阶段）
- [ ] RL 建议器 shadow mode（不直控执行）
- [ ] 文档自动 lint + 引用一致性 gate

---

## 4. 统一调度规则（执行规范）

1) **优先级规则**
- 先 P0，后 P1，再 P2
- 安全路径（challenge/resolve/timeout）优先于吞吐优化

2) **提交规则**
- 每个 lane 独立 commit，避免巨型混合提交
- 每次提交必须附对应测试命令与结果

3) **门禁规则**
- Rust 侧至少通过：
  - `cargo test -p trnm-state`
  - `cargo test -p trnm-pouw`
  - `cargo test -p trnm-node`
  - `cargo test -p trnm-mempool`（涉及时）
- Web4 侧至少通过：
  - `npm run ci:check`

4) **文档规则**
- 本文件更新后，其他文档只做“证据/细节补充”
- 本文件只管理开发排期/执行优先级，不单独声明 release-ready
- 发布口径冲突时以根级 `RELEASE_READINESS.md` 为准；历史叙述冲突时以日期更明确的历史文档为准

---

## 5. 立即执行清单（未来 24h）

1. 收口运行中 lane（C + Phase1 + MonetaryState），生成一次合并汇报。  
2. 将 P0 经济闭环拆成 2 个子 PR：
   - PR-1：bounty escrow + 资金守恒测试
   - PR-2：resolve authority 多方化 + 安全门禁
3. 将本文件加入 README 入口，形成唯一调度入口。

---

## 6. 附：建议保留/归档策略

- 保留（持续维护）：
  - `README.md`, `docs/archive/root-history/STATUS.md`, `docs/archive/root-history/BACKLOG.md`, 本文件
- 归档（历史记录）：
  - 各阶段 closeout/report 文件保留只读，不再承载调度职责
- 清理建议：
  - 后续可将重复“计划类文档”迁移到 `docs/archive/`，仅保留链接

---

## 结论

项目进入“多 lane 并行收口”阶段：核心链路可用，安全与并发正在主线化。当前关键是把 **经济闭环（P0）** 与 **免费高并发协议化（P0/P1）** 收敛到可门禁、可发布、可回滚状态。