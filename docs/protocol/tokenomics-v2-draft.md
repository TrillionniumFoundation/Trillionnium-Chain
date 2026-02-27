# Trillionnium Tokenomics v2 (Draft)

_Date: 2026-02-25_
_Status: Draft for internal review_

## 1. 设计目标

1. **抗女巫/抗低质供给**：提高恶意与低质量执行成本。  
2. **可持续激励**：让高质量 Worker、Verifier 有稳定收益，而非仅靠短期通缩叙事。  
3. **参数可治理**：关键经济参数可链上治理、可分阶段灰度。  
4. **风险可定价**：将风险映射到任务粒度（而不是只靠静态大额入场质押）。

---

## 2. 经济对象

- **Task Publisher**：发布任务并支付任务费用 `F`。  
- **Worker**：执行任务，承担执行风险与惩罚。  
- **Validator / Verifier**：提供验证与挑战能力。  
- **Treasury**：生态与安全预算池。  
- **Burn Pool**：通缩池（按治理配置比例）。

---

## 3. v2 核心机制

### 3.1 双押金模型

- Worker 基础质押：`S_base`
- 任务风险质押：`S_task`

建议函数：

```text
S_task = clamp(S_min, S_max,
               k1 * bounty
             + k2 * risk_level
             + k3 * failure_rate(worker)
             - k4 * reputation(worker))
```

解释：
- 任务越大、风险越高、历史失败越多 -> `S_task` 越高
- 声誉越好 -> `S_task` 适度下降（降低优质节点资本占用）

### 3.2 收益拆分（费用 F）

`F` 在四个池之间拆分：

- Worker：`F * α * Q`
- Verifier：`F * β`
- Treasury：`F * γ`
- Burn：`F * δ`

约束：`α + β + γ + δ = 1`

其中 `Q∈[0,1]` 为质量系数（基于结果一致性、时延、挑战结果、复现性等）。

### 3.3 分级惩罚

- **L1 轻微违规**（超时、非恶意失败）：罚 `S_task` 小比例
- **L2 可验证错误**（挑战成功/结果错误）：罚 `S_task` 中高比例 + `S_base` 小比例
- **L3 恶意行为**（伪造、重复作恶）：罚 `S_task` 全额 + `S_base` 高比例 + 冷却/封禁

### 3.4 挑战激励

挑战成功时，从罚没中分配：
- Challenger Reward：`λ`
- Treasury：`μ`
- Burn：`ν`

约束：`λ + μ + ν = 1`

### 3.5 动态拥塞费

发布任务费用中加入拥塞附加：

```text
F_effective = F_base * (1 + congestion_multiplier)
```

`congestion_multiplier` 由 mempool 深度、确认延迟、失败重试率共同决定。

---

## 4. 初始参数（建议 Testnet）

- 拆分比例：`α/β/γ/δ = 0.70 / 0.15 / 0.10 / 0.05`
- `S_base = 50,000 TRNM`
- `S_task ∈ [500, 20,000] TRNM`（或按 bounty 的 5%~20% 限幅）
- 挑战成功罚没分配：`λ/μ/ν = 0.20 / 0.60 / 0.20`
- 声誉衰减：每 30 天向均值回归 10%

> 注：以上仅作初始仿真参数，不是主网最终值。

---

## 5. 关键指标（KPI）

1. Worker 有效完成率（无挑战成功回滚）
2. 平均任务净成本（Publisher 侧）
3. 单位任务安全预算（Verifier + Treasury）
4. 恶意收益率（攻击者 ROI，目标 < 0）
5. 资本效率（优质 Worker 的质押占用/收益比）

---

## 6. 落地计划

### Phase A（仿真）
- 建立离线仿真（正常/拥塞/攻击三场景）
- 输出参数敏感性分析（`α,β,γ,δ,S_base,S_task`）

### Phase B（链上参数化）
- 在 `trnm-state` 增加 `tokenomics_params`
- 在 `trnm-pouw` 落地结算与惩罚计算
- 在 `trnm-rpc` 暴露查询接口

### Phase C（门禁与回归）
- 新增 tokenomics 回归脚本与 gate
- 覆盖挑战、超时、拥塞、声誉衰减场景

---

## 7. 风险与治理

- 风险：参数过激导致 Worker 流失 / 费用抬升
- 对策：
  - 参数变更走治理提案 + 冷静期
  - 每次调参限幅（如单次变更不超过 ±10%）
  - 回滚保护与审计日志保留
