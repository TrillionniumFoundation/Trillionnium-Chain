# Trillionnium Web4 基础设施平台化开发总文档（Master）

> 版本：v1.0  
> 日期：2026-02-27  
> 状态：主文档（整合 docs 历史文档的统一入口与执行规范）

---

## 0. 文档目标与范围

本文件用于**统一整理历史 docs**，并给出一份可执行的、面向“Web4 基础设施平台化”的详细开发文档。

覆盖范围：
- Rust L1 内核（已完成主线）
- Web4 平台化能力（计算市场、可验证执行、互操作、身份信任、数据治理、Agent 协议、企业合规）
- 研发流程（测试、门禁、发布、运维）

> 说明：本文件为主入口规范；历史 docs 以归档/专题形式保留，关键审计信息在本文件持续汇总。

---

## 1. 当前状态（As-Is）

### 1.1 已完成（链内主线）
- Rust L1 核心状态机、共识/治理/执行路径已闭环。
- v1 接口冻结文档与最小稳定事件字段已落地。
- 核心门禁（governance / emergency pause / consensus fault matrix）已具备可执行验证链路。
- 工作区全量测试已完成收口，近期关键红点已修复（含 `trnm-rpc` 环境变量测试并发干扰问题）。

### 1.2 Web4 能力雷达（现状）
（来源：Appendix A.4 雷达快照；并与 `docs/archive/web4-history/WEB4_PHASE_B_MILESTONE_SNAPSHOT_2026-02-28.md` 对齐）
- Decentralized AI Compute Market：3/5
- Verifiable Execution (TEE/ZK/Fraud)：2/5
- Cross-chain Settlement & Interop：1/5
- Identity/AuthZ/Agent Trust：2/5
- Data Layer & Provenance：2/5
- Agent Protocol Compatibility (MCP/A2A)：2/5
- Enterprise Ops & Compliance：2/5

**结论**：链内工程已成熟，但 Web4 平台化尚未达标；需从“单链优化”转为“平台能力建设”。

---

## 2. Web4 平台化目标（To-Be）

### 2.1 平台定义
Trillionnium 目标不是“单链功能齐全”，而是“可被开发者和企业直接采用的 Web4 基础设施平台”，具备：
1. 去中心化 AI 计算市场（发布-撮合-执行-争议-结算）
2. 可验证执行层（作弊可检、证明可插拔、成本可度量）
3. 跨链结算与消息互操作
4. 跨组织身份与 Agent 信任体系
5. 数据标准、可追溯与隐私分级治理
6. Agent 协议兼容（MCP/A2A + 链上结算）
7. 企业级运维、审计与合规

### 2.2 平台级验收标准（Definition of Done）
达到“Web4 概念标准”至少满足：
- 7 大能力域评分均 ≥ 4/5，且无 1/5、2/5 短板
- 至少 2 条外部链完成可验证跨链结算 PoC
- DID + capability 权限模型在生产级流程可用
- Agent SDK 兼容 MCP/A2A 并有参考应用
- 企业审计包可一键导出，合规策略可配置可验证

---

## 3. 统一架构（Platform Architecture）

```
[Developer / Enterprise / Agent Runtime]
            |
            v
+----------------------------------------------+
| API Gateway / RPC / SDK (MCP/A2A adapters)  |
+----------------------------------------------+
            |
            v
+----------------------------------------------+
| Market Layer (task, bidding, reputation, SLA)|
+----------------------------------------------+
            |
            v
+----------------+   +-------------------------+
| Execution Plane|-->| Proof Plane (Fraud/TEE/ZK)|
+----------------+   +-------------------------+
            |                    |
            +---------+----------+
                      v
            +---------------------+
            | Settlement / Bridge |
            +---------------------+
                      |
                      v
            +---------------------+
            | Data & Provenance   |
            +---------------------+
                      |
                      v
            +---------------------+
            | Governance & Policy |
            +---------------------+
```

---

## 4. 平台化分期路线图

## Phase A（0-3 个月）：可信执行基础

### A1. 计算市场 MVP（产品化）
- 任务发布/接单/执行/结算/争议标准流程 API
- 最小信誉系统：成功率、超时率、争议率、处罚记录
- 定价与撮合：初版策略（静态+负载感知）

**验收**：
- 端到端成功率 ≥ 99%
- 争议处理链路可重放、可审计
- 市场指标看板可用（吞吐、结算时延、争议率）

### A2. 可验证执行抽象层
- 统一证明接口：`fraud_proof | tee_receipt | zk_receipt`（可扩展）
- 证明成本模型：验证耗时、链上成本、失败率

**验收**：
- 至少两类证明方式接入（Fraud + TEE）
- 验证失败可定位到任务粒度

### A3. 运营可观测性
- 链上事件到运营指标管道（OLAP / dashboard）
- SLO：结算延迟、回滚率、争议解决时长

**验收**：
- 核心 SLO 可视化 + 告警可触发

---

## Phase B（3-6 个月）：互操作与身份

### B1. 跨链结算最小集
- 支持 2 条主流链的资产/消息桥接（先最小可用）
- 跨链任务结算状态机（pending/finalized/reverted）

**验收**：
- 双链 PoC 连续 14 天稳定
- 跨链失败具备自动补偿/人工干预手册

### B2. DID + Capability 权限系统
- Agent、组织、服务账号统一身份
- capability token + 最小权限策略
- 权限变更与撤销审计

**验收**：
- 跨组织调用全链路鉴权可验证
- 撤权生效时间满足 SLO

### B3. Agent 协议兼容 SDK
- MCP/A2A adapter 标准化
- SDK：任务调用、结算回执、争议发起、审计查询

**验收**：
- 至少 2 个参考应用接入成功

---

## Phase C（6-12 个月）：平台化与企业化

### C1. 合规与策略引擎
- 地域策略、数据边界、风控规则
- 审计证据自动生成

### C2. 数据治理与溯源标准
- 任务数据标准、模型元数据、provenance schema
- 数据分级与隐私策略（公开/内部/受限）

### C3. 生态层
- 开发者门户、模板仓库、认证计划
- ISV/企业接入流程与 SLA 合同模板

**验收**：
- 企业试点上线并通过合规抽检
- 平台文档/SDK/样例三件套齐备

---

## 5. 研发执行规范（统一）

### 5.1 代码变更规则
- 单主题、可回滚、可验证
- 优先小步迭代，避免大爆炸重构
- 失败必须回滚并记录根因

### 5.2 测试与门禁规则
- 必跑：
  - `cargo test --workspace`
  - `scripts/v2/governance_value_schema_reject_test.sh`
  - `scripts/v2/emergency_pause_drill.sh`
  - `trillionnium/scripts/run_consensus_fault_matrix.sh`
- 变更影响到具体域时，必须补充 targeted tests

### 5.3 发布规则
- 未通过全量门禁禁止发布
- 发布必须附带：风险说明、回滚步骤、验收证据

---

## 6. 平台化任务分解（Work Breakdown）

## Track M（Market）
- M1：任务/报价/撮合 API
- M2：信誉与处罚模型
- M3：市场指标与报表

## Track V（Verification）
- V1：proof adapter trait + 插件体系
- V2：TEE receipt 落地
- V3：ZK receipt POC

## Track X（Cross-chain）
- X1：桥接抽象与状态机
- X2：双链最小结算闭环
- X3：补偿与对账

## Track I（Identity/Trust）
- I1：DID registry
- I2：capability token
- I3：撤权与审计

## Track D（Data/Provenance）
- D1：任务与模型元数据 schema
- D2：provenance 索引
- D3：隐私分级策略

## Track A（Agent Protocol）
- A1：MCP adapter
- A2：A2A adapter
- A3：SDK + examples

## Track E（Enterprise/Compliance）
- E1：策略引擎
- E2：审计报告自动化
- E3：企业接入 runbook

---

## 7. 里程碑与量化指标（KPI/SLO）

### 7.1 平台指标
- 任务端到端成功率 ≥ 99.5%
- 平均结算延迟 ≤ 2 区块窗口
- 争议解决 P95 ≤ 30 分钟
- 跨链结算成功率 ≥ 99%

### 7.2 工程指标
- 主分支门禁通过率 ≥ 98%
- 回滚率（月）< 5%
- 回归修复平均时长（MTTR）< 24h

### 7.3 生态指标
- 外部 SDK 月活项目数
- 参考应用部署数
- 企业试点转生产率

---

## 8. 风险与应对

1. **过度链内优化导致平台能力滞后**
   - 对策：每个迭代至少 50% 工时投入平台化 track

2. **跨链与合规复杂度上升**
   - 对策：先最小可用，再扩展；保持可回滚桥接策略

3. **身份系统与 Agent 协议碎片化**
   - 对策：先统一 capability 模型，再扩展 adapter

4. **证明成本过高**
   - 对策：proof strategy 动态选择（fraud 优先，TEE/ZK 分层）

---

## 9. 与历史 docs 的整合策略

### 9.1 归类整合
- protocol/* → 协议规范基座
- runbooks/* + operations/* → 运维与演练
- reports/* + perf/* → 证据与度量
- strategy/* + plans/* → 中长期路线
- development/* → 开发流程主指南

### 9.2 文档策略（精简后）
- 本 Master 为 Web4 平台路线图主入口与持续维护基线，不承担仓库级 release 判定
- 历史 docs 保留为专题文档，审计必需信息同步维护在本文件 Appendix A
- 新增或变更需求，优先更新本 Master，并在专题文档保持双向引用一致

---

## 10. 立即执行清单（Next 2 Weeks）

1) 建立 Web4 platform board（7 tracks）并绑定 owner。  
2) 启动 M1/V1/X1/I1/A1 的最小可用实现。  
3) 补齐平台级验收脚本（非仅链内门禁）。  
4) 输出首版企业接入 runbook 与审计模板。  
5) 每周更新本 Master：进度、风险、证据。  

### 10.1 Phase B（截至 2026-02-28）Lane XI 收口状态与下一跳
- 已完成：X2 最小结算闭环、I2 capability token 查询精确匹配与稳定 not-found 语义。
- 下一跳（高 ROI，单补丁优先）：
  - X3 预备：故障注入矩阵 + 补偿闭环可重放（timeout / duplicate / reorder / stale pending）。
  - I3 预备：撤权时序一致性（issue/renew/revoke 竞争路径）与 fail-closed 错误契约。
- XI 定向门禁（文档与实现同步约束）：
  - `./scripts/v2/x2_settlement_contract_gate.sh`
  - `./scripts/v2/i2_token_lifecycle_gate.sh`

### 10.2 前端接口文档（2026-03-03）
- 现状：前端默认走 `web4-frontend/lib/api-contract/*` 的只读查询客户端；仅在显式 `?mode=mock` 时回退到本地 snapshot fallback。
- 接口契约基线：`docs/archive/web4-history/WEB4_FRONTEND_API_INTERFACE_V0.md` 与 `web4-frontend/docs/api-contract.md`
- 约束：Dashboard 仅消费只读聚合 API，不得绕过 XI 门禁结论（X2/I2 gate）；`/api/v0/web4/*` 仅是历史草案命名，不是当前仓内 route。

### 10.3 Lane MV（2026-03-03）V2 回执契约冻结主文档锚点
- 锚点目标：把 `fraud_proof | tee_receipt | zk_receipt` 的统一回执字段固定到 Master，避免仅在专题文档生效。
- 统一字段（最小集）：`task_id/proof_type/verdict/verified_at/cost_hint`。
- fail-closed 约束：证明缺失/迟到/格式不合法时，不允许静默成功，必须进入争议或降级路径并给出稳定错误码。
- 交界约束：M2↔V2 的错误码与状态迁移表必须与 gate 用例一一映射。
- 最小错误码映射（冻结）：`proof_missing -> ERR_M2V2_PROOF_MISSING`、`proof_late -> ERR_M2V2_PROOF_LATE`、`proof_invalid -> ERR_M2V2_PROOF_INVALID`、`settlement_degraded -> ERR_M2V2_SETTLEMENT_DEGRADED`。
- 最小状态迁移映射（冻结）：`pending_proof -> disputed(proof_missing|proof_late|proof_invalid) -> downgraded(settlement_degraded)`。
- ZK 平台化冻结锚点：`docs/architecture/TRNM_ZKP_PLATFORM_V0.md`（backend 抽象、payload/public input、feature flag/config、错误分类、兼容策略）。

---

## 11. 维护规则

- 本文档是“产品 + 工程 + 运维”统一基线。
- 任一子模块发生重大变更，需在 24 小时内回写本 Master。
- 周报与发布评审默认引用本文件。

---

## Appendix A：关键审计信息（已迁移）

### A.1 v1 冻结与主线完成状态
- v1 接口冻结：已落实（状态机/字段语义/最小错误码与事件审计字段）
- 开发文档主线进度：已完成到 100%（链内口径）

### A.2 关键提交（验收窗口）
- `fc542c4` `dev(cli-rpc): serialize faucet env parsing tests to avoid env race`
- `7de5e51` `chore(release): v1 interface freeze completion report and cli fix`
- `b1ce322` `laneC: normalize quoted reliability db env paths`
- `f402792` `laneB: gate roadmap-progress metadata for pause governance`
- `6d86909` `laneA: fail-closed on uncommitted WAL tail during checkpoint recovery`

### A.3 核心门禁与结果（最近验收）
- `cargo test --workspace`：PASS（在 `fc542c4` 后收口）
- `./scripts/v2/governance_value_schema_reject_test.sh`：PASS
- `./scripts/v2/emergency_pause_drill.sh`：PASS
- `./trillionnium/scripts/run_consensus_fault_matrix.sh`：PASS（8/8）

### A.4 Web4 能力现状快照（雷达）
- Market 3/5, Verifiable 2/5, Interop 1/5, Identity 2/5, Data 2/5, Agent 2/5, Enterprise 2/5
- 结论：链内达标，平台化未达 Web4 概念标准（需进入 Phase A/B/C 平台建设）

---

## Appendix B：命令参考（当前稳定）

```bash
# 全量测试
cd trillionnium
cargo test --workspace

# 核心门禁
cd ..
./scripts/v2/governance_value_schema_reject_test.sh
./scripts/v2/emergency_pause_drill.sh
./trillionnium/scripts/run_consensus_fault_matrix.sh
```

---