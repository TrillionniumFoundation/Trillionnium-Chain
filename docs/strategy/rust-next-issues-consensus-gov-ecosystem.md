# Rust 下一步执行清单（按 crate + 验收标准）

更新时间：2026-02-21

## A. 共识层（P0）

### ISSUE A1: 最终性与恢复指标内建化
- 目标：在 `trnm-node` 暴露 finality/recovery 关键指标（P50/P95）。
- 触及：`crates/trnm-node`, `crates/trnm-types`
- 验收：
  - 新增指标字段可在日志与 summary 中读取
  - `testnet_preflight.sh` 可校验指标存在

### ISSUE A2: 故障注入矩阵执行入口
- 目标：新增统一脚本运行节点重启/延迟/抖动场景。
- 触及：`trillionnium-rust/scripts/`
- 验收：
  - `run_consensus_fault_matrix.sh` 产出结构化报告
  - 至少 3 类故障场景可重复复现

### ISSUE A3: 共识边界文档冻结
- 目标：补齐 `consensus-v1-freeze.md` 并和实现字段对齐。
- 触及：`docs/protocol/`
- 验收：
  - 字段、状态、错误语义与代码一致
  - CI 增加文档-实现一致性检查（最小检查）

---

## B. 治理MVP（P1）

### ISSUE B1: 提案-投票-执行状态机（最小）
- 目标：实现治理对象最小状态机。
- 触及：`crates/trnm-state`, `crates/trnm-node`
- 验收：
  - proposal -> voting -> passed/rejected -> executed
  - 非法状态迁移返回稳定错误码

### ISSUE B2: 参数治理执行器
- 目标：支持受控参数更新（白名单键）。
- 触及：`crates/trnm-node`, `crates/trnm-types`
- 验收：
  - 参数提案执行后链上状态可查询
  - 回滚提案可恢复到前一版本

### ISSUE B3: 紧急刹车（emergency pause）
- 目标：实现最小紧急开关，仅 authority/gov 路径可触发。
- 触及：`crates/trnm-node`
- 验收：
  - pause 后拒绝高风险交易类型
  - unpause 后恢复，事件完整记录

---

## C. Ecosystem Alpha（P1）

### ISSUE C1: 对外查询接口稳定化
- 目标：固定查询接口字段（任务状态、资金流、事件检索）。
- 触及：`crates/trnm-rpc`, `crates/trnm-types`
- 验收：
  - 增加 schema smoke 测试
  - 文档与输出字段一致

### ISSUE C2: SDK 示例最小三件套
- 目标：提供 create/commit/reveal + challenge 查询示例。
- 触及：`examples/`, `docs/ecosystem/`
- 验收：
  - 外部机器可按文档跑通
  - 失败场景有明确报错指引

### ISSUE C3: Alpha 反馈回路
- 目标：把外部开发者反馈结构化落盘。
- 触及：`docs/ecosystem/`
- 验收：
  - 至少包含：问题、复现、优先级、修复状态

---

## 建议执行顺序（两周）
1. A1 -> A2 -> A3（共识先收敛）
2. B1 -> B2 -> B3（治理最小闭环）
3. C1 -> C2 -> C3（生态 alpha 起步）

## 完成定义（DoD）
- 每个 ISSUE 都有：代码变更 + 自动化脚本/测试 + 文档更新 + 可复现产物路径。
