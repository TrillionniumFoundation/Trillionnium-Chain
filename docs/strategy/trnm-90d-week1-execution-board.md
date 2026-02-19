# TRNM 90D - Week1 Execution Board

日期：2026-02-19（启动）
周期：Week1（D1~D7）

## 本周目标（只盯可交付）

1. v1 协议冻结语义全对齐（状态机/错误码/事件）
2. 门禁一键化（本地+CI）
3. 并行路径稳定性快验（>=20 连跑）

## 执行清单（10 项）

- [x] `accept_task` 路径落地
- [x] `commit_result` 收紧到 `ASSIGNED -> COMMITTED`
- [x] 非法迁移矩阵 smoke 测试
- [x] `PouwError::stable_code()` + 映射文档
- [x] 事件 `event_schema=v1`
- [x] 事件字段硬门禁（含 schema）
- [x] 事件顺序回放硬门禁
- [x] 并行路径 20 连跑快验
- [x] 一键门禁脚本 `run_v1_protocol_gates.sh`
- [x] merge-gate workflow 接入 Rust v1 gates

## 验收口径

- `cargo test --workspace` 通过
- `scripts/run_v1_protocol_gates.sh` 通过
- CI: `rust-l1-nightly-health` 与 `trnm-merge-gates` 均包含 v1 协议门禁

## 风险与后手

- 风险：脚本脆弱（日志格式变更导致误报）
  - 后手：脚本加版本字段匹配 + 提供回放日志 artifact
- 风险：并行路径在不同机器上抖动
  - 后手：保留 hard gate + 增加重试/抖动统计
