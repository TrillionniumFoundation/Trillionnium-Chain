# Rust L1 Day-1 执行清单（可直接分配给 AI coder）

日期：2026-02-19
Owner：齐教授 / 发发

## 今日目标
在 24 小时内完成“可编译骨架 + 架构冻结 + 冲突检测原型”。

---

## Task A：初始化 Rust workspace（P0）

- [ ] 创建 `trillionnium-rust/` workspace
- [ ] 创建 crates：
  - [ ] `trnm-node`
  - [ ] `trnm-types`
  - [ ] `trnm-state`
  - [ ] `trnm-pouw`
  - [ ] `trnm-executor`
  - [ ] `trnm-mempool`
  - [ ] `trnm-rpc`
  - [ ] `trnm-bench`
- [ ] `cargo check --workspace` 通过

验收：
- 提交 `chore(rust-l1): bootstrap workspace skeleton`

---

## Task B：核心类型定义（P0）

在 `trnm-types` 定义：
- [ ] `ObjectRef { id, version }`
- [ ] `Tx { id, read_set, write_set, payload }`
- [ ] `TaskStatus` 枚举
- [ ] `Hash32` 类型别名

验收：
- 单测覆盖基础序列化/反序列化
- 提交 `feat(types): add object/tx canonical structs`

---

## Task C：并发冲突检测原型（P0）

在 `trnm-executor` 实现：
- [ ] `detect_conflict(tx_a, tx_b) -> bool`
- [ ] `build_conflict_groups(txs) -> Vec<Vec<Tx>>`
- [ ] 简单调度策略：冲突组串行、非冲突组并行占位

验收：
- [ ] 至少 6 个单测（rw/ww/no-conflict）
- [ ] 随机交易集回放顺序确定性测试
- 提交 `feat(executor): add rw-set conflict detector prototype`

---

## Task D：PoUW 状态机接口骨架（P1）

在 `trnm-pouw` 定义：
- [ ] `apply_create_task`
- [ ] `apply_commit_result`
- [ ] `apply_reveal_result`
- [ ] `apply_challenge`
- [ ] `apply_resolve`

验收：
- 暂可返回 `todo!()` 或明确错误码，但接口签名冻结
- 提交 `feat(pouw): freeze state transition interfaces`

---

## Task E：Node 启动骨架（P1）

在 `trnm-node`：
- [ ] 读取配置文件
- [ ] 打印节点 ID / 端口 / 网络配置
- [ ] 初始化模块占位（mempool/executor/state）

验收：
- `cargo run -p trnm-node -- --config configs/node1.toml` 可启动并输出配置
- 提交 `feat(node): boot skeleton with config loader`

---

## Day-1 关门条件（必须同时满足）

- [ ] `cargo check --workspace` 全绿
- [ ] 核心冲突检测单测全绿
- [ ] RFC-001 参数拍板（至少经济参数“先沿用旧值”确认）
- [ ] 产出 Day-1 进展记录（含 commit hash）

若未满足：不得进入 Day-2。
