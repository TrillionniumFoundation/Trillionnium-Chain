# Trillionnium Rust L1 Architecture Docs

> 面向：团队内部评审、外部技术沟通、实现对齐。

## 你应该先读什么

### 1) 想快速理解全貌（5 分钟）
- `rust-l1-repo-layout.md`
  - 仓库结构
  - 模块职责边界
  - Day-1 到 Week-1 的落地脉络

### 2) 想看业务闭环如何流转（10 分钟）
- `rust-l1-pouw-sequence.md`
  - create → accept → commit → reveal → challenge → resolve 全链路
  - 成功分支 + 失败分支（如 `CommitmentMismatch`）
  - 模块间交互（node/executor/pouw/state）

### 3) 想确认“什么不能改”（协议基线）
- `../protocol/rust-l1-v1-interface-freeze.md`
  - v1 状态机冻结
  - 接口字段语义冻结
  - 错误码最小稳定集合
  - 事件审计字段最小集合

---

## 推荐阅读路径

- **新成员 onboarding**：repo-layout → sequence → v1 freeze
- **实现评审/代码走查**：sequence → v1 freeze → 具体 crate
- **对外沟通/路演**：repo-layout（架构图景）+ sequence（业务闭环）

---

## 与代码目录映射

- `trnm-node`：节点流程、出块接线、事件输出
- `trnm-executor`：并发调度与冲突检测
- `trnm-pouw`：PoUW 状态机与规则校验
- `trnm-state`：versioned object store 与 `state_root()`
- `trnm-bench`：classic/mixed 压测与回归

---

## 文档维护规则（简版）

1. 协议语义以 freeze 文档为准；架构文档不得与其冲突。
2. 若实现变化影响可观察行为：先更新 freeze 文档，再改实现与测试。
3. 新增文档请在本 README 补一条入口，避免知识分散。
