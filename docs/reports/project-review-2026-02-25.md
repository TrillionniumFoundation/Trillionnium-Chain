# Trillionnium 项目全景回顾与代码整理建议（2026-02-25）

## 1) 当前项目状态（结论）

项目已完成从历史 Cosmos 线到 **Rust L1 主线** 的收口，核心研发重心稳定在：

- `trillionnium-rust/`（Rust workspace）
- 根目录 `scripts/`（自动化/门禁/流水线）
- 根目录 `docs/`（协议、运行、产品化文档）
- 根目录 `run/` + `data/`（运行产物与历史证据）

与长期记忆一致：当前应继续以 **Rust L1 + worker-agent + strict gate** 为唯一主线。

---

## 2) 代码结构快照（现状）

### 2.1 Rust workspace

`trillionnium-rust/Cargo.toml` 当前成员：

- `trnm-node`
- `trnm-types`
- `trnm-state`
- `trnm-pouw`
- `trnm-executor`
- `trnm-mempool`
- `trnm-rpc`
- `trnm-bench`
- `trnm-worker-agent`
- `trnm-cli`

### 2.2 仓库根目录角色划分

- `docs/`：架构、协议冻结、runbook、perf、product、automation
- `scripts/`：gate、relay、demo、自动化调度脚本（含 `v2/`）
- `run/`：近期运行记录（PR 维度、health、manual-gates 等）
- `data/`：历史验收/压测/回归产物（时间戳目录）
- `legacy/`：历史冻结归档

---

## 3) 已发现的结构问题

### 3.1 README 与当前代码现实不完全对齐

README 中仍有早期目录示例（`core/`、`tasks/`、`worker/`、`chain/`），而这些目录在当前仓库根目录已不存在。

影响：
- 新人 onboarding 容易误入旧路线
- 对外阅读时会产生“项目目录不一致”印象

### 3.2 运行产物分散，根目录有少量漂浮文件

- 已发现并处理一个根目录漂浮日志：
  - `run-auto-relay-20260220-192912.log` → `run/logs/run-auto-relay-20260220-192912.log`

---

## 4) 建议的“代码整理”执行方案

### Phase A（立即可做，低风险）

1. **README 对齐现实结构**（强烈建议）
   - 将“Project Structure / Quick Start”替换为 Rust L1 当前入口
   - 明确 legacy 已冻结，不再作为主路径

2. **统一运行产物入口**
   - 约定所有一次性日志写入 `run/logs/`
   - 脚本输出优先落在 `run/<topic>/` 或 `data/<topic>/`

3. **补一份“当前代码地图”文档**
   - 固定入口：`docs/architecture/current-codebase-map.md`
   - 包含 crate→职责、脚本→入口、门禁→workflow 映射

### Phase B（中风险，需要逐步迁移）

4. **脚本分层重排（保持兼容软链/包装脚本）**
   - `scripts/gates/`
   - `scripts/pipelines/`
   - `scripts/devtools/`
   - `scripts/ops/`

5. **run/data 保留策略**
   - 增加 retention 规则（例如 30/90 天）
   - 大目录归档到 `archives/`（或对象存储）

### Phase C（治理层）

6. **建立“单一权威入口”**
   - `make help` 或 `just` 统一命令入口（gate/bench/smoke/release）

7. **CI 对文档一致性加 gate**
   - 校验 README 提及路径必须存在
   - 校验 scripts 索引文档与实际脚本名同步

---

## 5) 我建议的优先顺序（实操版）

- P0：先改 README（当日完成）
- P1：补 `current-codebase-map.md`（当日完成）
- P2：脚本分层（1~2 天，保证兼容）
- P3：run/data retention（并行进行）

> 这样做的收益：新成员 5 分钟能看懂入口；CI 与文档一致；自动化资产更可维护。

---

## 6) 本次已执行整理动作

- [x] 根目录漂浮日志归位：
  - `run-auto-relay-20260220-192912.log` 已迁移至 `run/logs/`

