# TRNM Web4 Phase B Plan (2026-02-28)

## Phase B 目标（4 周）
从“可用”推进到“可上线”，聚焦 Interop + Identity 生产化，并补齐市场与合规支撑。

### DoD（阶段完成定义）
1. **X2 双链最小结算闭环**
   - relay heartbeat → settlement confirm → failure compensation 全链路可回放
   - 至少 1 组端到端合同测试通过
2. **I2 Capability Token 生命周期**
   - issue / renew / revoke / audit query 全覆盖
   - replay/乱序/回退边界测试齐全
3. **M2 信誉与处罚模型落地**
   - 撮合策略支持信誉加权与可解释输出
   - 关键错误码与契约测试稳定
4. **Schema Lock 门禁**
   - 防止 trnm-types 与调用方再漂移
   - gate 失败即阻断合并

---

## 赛道与优先级
- **Lane XI（P0）**：X2 + I2（主线）
- **Lane MV（P1）**：M2 + V2 稳定性支撑
- **Lane DAE（P1）**：E2 审计模板产品化 + D2 溯源索引

### Lane DAE（Data / Agent / Enterprise）执行细化（高 ROI）
> 目标：把“可查询”推进到“可审计交付”，并保证每次迭代都能被一条命令复核。

#### D2（Data）— 审计索引从单点查询到可追溯包
- D2.1：补齐 `query-audit` 输出字段基线（`task_id`、proof 类型、结算状态、时间戳）
- D2.2：增加“缺失字段 fail-fast”校验脚本（防止静默降级）
- D2.3：在 runbook 固化“故障三分法”（数据缺失 / 状态不一致 / 环境配置）

**验收命令（targeted）**
```bash
./scripts/check_query_audit_smoke.sh
```

#### A2（Agent）— 审计查询可被 Agent 工作流稳定调用
- A2.1：约定查询结果错误语义（not-found / invalid-request / internal）
- A2.2：在示例调用里固定最小参数集，避免 lane 间漂移
- A2.3：沉淀“重试与幂等”说明（最多一次补偿重试）

**验收命令（targeted）**
```bash
cd trillionnium-rust
cargo test -p trnm-rpc query_audit -- --nocapture
```

#### E2（Enterprise）— 审计模板产品化
- E2.1：将 runbook 输出映射到企业审计模板（输入/步骤/证据/结论）
- E2.2：模板内置回滚命令与责任边界
- E2.3：形成“日终可投递”最小包（md + 命令回放证据）

**验收命令（targeted）**
```bash
./scripts/check_query_audit_smoke.sh && echo "[E2] audit template evidence ready"
```

#### DAE lane no-op 原因码（统一）
- `NO_ELIGIBLE_DIFF`：当前范围内无可回滚微补丁
- `GATE_RED`：定向门禁失败，必须回滚
- `BLOCKED_BY_DEP`：依赖 XI/MV 产物未就绪
- `DOC_ONLY_DEFERRED`：仅文档改动且无新增验收价值，顺延至下一轮合并

---

## 本周立即动作（Day 0~2）
1. 新增 gate：
   - `scripts/v2/x2_settlement_contract_gate.sh`
   - `scripts/v2/i2_token_lifecycle_gate.sh`
   - `scripts/v2/types_schema_lock_gate.sh`
2. 每条 lane 仅允许“单个可回滚微补丁 + 定向验证 + 绿才提交”。
3. 每日汇总：提交数、失败回滚数、阻塞与 ETA。

---

## 风险与对策
- **风险**：跨 crate 数据模型漂移再现
  - **对策**：schema lock gate + code-owner 审核
- **风险**：错误文案漂移导致脆弱断言
  - **对策**：统一 code-first 错误契约测试
- **风险**：lane 空转
  - **对策**：NO_ELIGIBLE_DIFF 原因码 + 15 分钟节奏

---

## 验收命令（阶段门禁）
```bash
cd trillionnium-rust
cargo check --workspace
cargo test --workspace
```

并补充：
```bash
./scripts/v2/x2_settlement_contract_gate.sh
./scripts/v2/i2_token_lifecycle_gate.sh
./scripts/v2/types_schema_lock_gate.sh
```
