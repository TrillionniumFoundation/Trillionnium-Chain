# TRNM Hybrid Reference Crate Roadmap v0（crate-level 实施路线图）

- 状态：**Draft / implementation roadmap**
- 范围：把 `docs/architecture/TRNM_HYBRID_REFERENCE_ARCHITECTURE_V0.md` 进一步拆成 **crate 级实施路线**
- 目标：让“借鉴 Solana / Sui / Conflux”从概念表述收敛为**可分 crate 落地、可分阶段验证、可按 PR 拆分**的路线图

> 入口约定：
> - 发布口径：看根 `RELEASE_READINESS.md`
> - 当前统一开发调度：看 `docs/development/DEVELOPMENT_MASTER_UNIFIED_2026-03-04.md`
> - 分层架构原则：看 `docs/architecture/TRNM_HYBRID_REFERENCE_ARCHITECTURE_V0.md`
> - ZKP 平台边界：看 `docs/architecture/TRNM_ZKP_PLATFORM_V0.md`
>
> 本文不宣布“已经实现混合架构”，而是定义：
> **如果 TRNM 要走 Sui-like 内核、Solana-like 数据面、Conflux-inspired 排序/经济抽象，具体应该从哪些 crate 开始、按什么顺序推进。**

---

## 1. 设计红线（crate 级别）

### 1.1 不打穿 PoUW v1 冻结面
以下 crate 的改动必须优先遵守 additive-only：

- `trnm-pouw`
- `trnm-types`（协议/查询边界部分）
- `trnm-node`（事件与对外口径）

特别是：
- `OPEN → ASSIGNED → COMMITTED → REVEALED → CHALLENGED → COMPLETED/SLASHED`
- 已冻结的最小事件字段集合
- 已冻结的最小错误码集合

### 1.2 先收内核，再抬吞吐，再抬排序
crate 级顺序必须是：

1. `trnm-types` / `trnm-state` / `trnm-executor`
2. `trnm-mempool` / `trnm-rpc` / `trnm-node`
3. `trnm-worker-agent` / `trnm-oracle` / `trnm-bridge-poc`

也就是：
- **先固定 Sui-like 内核**
- **再强化 Solana-like 数据面**
- **最后再做 Conflux-inspired ordering/economics 抽象**

### 1.3 不允许双内核
TRNM 必须保持：

- **object/version 内核是唯一真内核**

因此：
- 不引入与之并列的“账户锁模型内核”
- 不在不同 crate 中混用两套冲突语义

---

## 2. crate 级总映射

| crate | 主要职责 | 主要参考 | 当前定位 | 下一阶段定位 |
|---|---|---|---|---|
| `trnm-types` | 类型、schema、事件/响应边界 | TRNM-native + Sui-like object schema discipline | 协议类型层 | 稳定对象/版本/查询 schema 层 |
| `trnm-state` | versioned object store、state_root、治理/恢复 | **Sui** | 状态内核 | 更强对象/版本语义与可证明恢复层 |
| `trnm-executor` | 冲突检测、并行分组、热点调度 | **Sui + Solana** | 并发执行骨架 | 对象冲突 + 调度优化双核 |
| `trnm-mempool` | lanes、QoS、admission、backpressure | **Solana** | 入口缓冲层 | lane-aware 数据面核心 |
| `trnm-rpc` | ingress/query 协议边界 | **Solana + TRNM-native ingress** | API 边界 | 免费提交与配额/幂等入口 |
| `trnm-node` | 区块循环、排序、恢复、执行接线 | TRNM-native + selective **Conflux** inspiration | 节点 glue 层 | ordering/finality 抽象宿主 |
| `trnm-pouw` | PoUW 状态机与经济语义 | **TRNM-native** | 协议核心 | 保持冻结面，继续 additive 扩展 |
| `trnm-worker-agent` | worker 执行、receipt、retry、flush | Solana-like ingress discipline + TRNM-native receipts | 执行代理 | 高吞吐结果回传通道 |
| `trnm-oracle` | 外部验证/评分/策略输入 | selective **Conflux-inspired economics** | 辅助验证器 | 非共识关键的风险/定价辅助层 |
| `trnm-bridge-poc` | 外部入口/结算桥接试验 | Solana-like data plane + batch settlement | bridge POC | free-ingress / batch settlement 实验层 |
| `trnm-cli` | operator UX / tx/query 入口 | TRNM-native | 操作面 | 架构变更的 operator surface |
| `trnm-bench` | workload/benchmark closeout | Solana-like perf discipline | 压测面 | 回归/容量真相源 |

---

## 3. Phase 分解

## Phase 0：固定术语与 seam（文档+接口）

### 目标
让各 crate 的“该像谁、又不该像谁”先写清楚，避免实现时来回打架。

### 交付
- `TRNM_HYBRID_REFERENCE_ARCHITECTURE_V0.md`
- 本文（crate roadmap）
- 在开发总入口里把两份文档挂上去

### DoD
- 架构表述有统一入口
- 不需要靠聊天记录维持语义

---

## Phase 1：Sui-like 内核硬化

### 目标
固定 TRNM 的唯一内核：

- object/version state
- deterministic parallel execution
- PoUW-native object lifecycle

### 主 crate
- `trnm-types`
- `trnm-state`
- `trnm-executor`
- `trnm-pouw`

### 关键任务

#### 1. `trnm-types`
- 明确对象/版本相关 schema 的稳定边界：
  - `ObjectRef`
  - `TaskObject`
  - `TaskMetadata`
  - query response structs
- 对“可恢复但未最终化”的状态对象建模给出统一命名
- 避免未来因为字段新增导致 test-target 大面积漂移

#### 2. `trnm-state`
- 继续把以下状态显式对象化/版本化：
  - pending resolve approval
  - pending governance update
  - metering snapshot（metadata 子结构或 companion object）
  - MonetaryState（如果继续推进）
- 继续强化 state_root 可观测性：
  - 对 pending slots / staged quorum / pending governance 的 root 影响必须可测
- 恢复/rollback 逻辑坚持 fail-closed，但要区分：
  - live task-bound restore
  - slot-only deterministic payload restore

#### 3. `trnm-executor`
- 统一冲突 key 口径：
  - 对象 id
  - version
  - object family / hot key bucket
- 把调度优化与冲突语义解耦：
  - 冲突判定保持保守正确
  - 调度策略可独立实验
- 新增更细粒度 metrics：
  - scanned candidates
  - group_count
  - hotspot saturation
  - replay reject / rollback pressure

#### 4. `trnm-pouw`
- 保持冻结的主状态机不变
- additive-only 扩展仍允许落在：
  - metering
  - worker settlement
  - challenge bounty / slash / rebate
  - verification backend selection / receipt schema
- 对 `ObjectRef` stale / version conflict 的优先级继续保持统一

### Phase 1 非目标
- 不引入新 VM
- 不把所有对象改造成 Move 风格 ownership 分类
- 不引入 Conflux 风格排序图结构

### Phase 1 验收
- `cargo test -p trnm-state --lib`
- `cargo test -p trnm-state --test m1_pause_resolve_escrow_invariant`
- `cargo test -p trnm-state --test state_root_regression`
- `cargo test -p trnm-pouw --lib`
- `cargo test -p trnm-executor`

---

## Phase 2：Solana-like 数据面与高并发入口

### 目标
让 TRNM 的“提交端免费 + 高并发”不只是方向，而是具体落在：

- lane-aware mempool
- QoS / admission
- backpressure
- RPC ingress contract

### 主 crate
- `trnm-mempool`
- `trnm-rpc`
- `trnm-node`
- `trnm-worker-agent`
- `trnm-cli`
- `trnm-bench`

### 关键任务

#### 1. `trnm-mempool`
- 定义 lane 分类（至少区分）：
  - critical control path（challenge/resolve/governance）
  - worker result path
  - free ingress user path
  - bulk / low-priority path
- admission policy 显式化：
  - per-lane budget
  - reserved capacity
  - fairness / anti-starvation
- backpressure 对外可返回：
  - queue saturation
  - retry-after / throttle hint
  - lane rejection reason

#### 2. `trnm-rpc`
- 固定 free-ingress 入口契约：
  - idempotency key
  - quota identity
  - lane hint
  - batch submit envelope
- query 面保持 fail-closed hardening
- 对高频入口返回结构化 admission diagnostics

#### 3. `trnm-node`
- block builder 需要感知 lane budget
- 关键路径保底：
  - challenge / resolve / timeout / governance 不能被免费洪泛饿死
- preflight / apply / rollback 继续做 deterministic 保护

#### 4. `trnm-worker-agent`
- worker receipt flush 策略与 lane budget 对齐
- retry/backoff 不能把 control path 挤爆
- 结果回传应支持更明确的 class / priority / telemetry 标签

#### 5. `trnm-cli`
- 对 operator 暴露 lane / queue / quota 可见性
- 增加对 free-ingress admission 的 query / explain surface

#### 6. `trnm-bench`
- 压测不只看 TPS，还要看：
  - lane starvation
  - control path latency
  - queue blow-up threshold
  - backpressure effectiveness

### Phase 2 非目标
- 不照抄 Solana 账户/leader/fee 模型
- 不把 free-ingress 变成“所有流量零成本且无约束”

### Phase 2 验收
- `cargo test -p trnm-mempool`
- `cargo test -p trnm-rpc`
- `cargo test -p trnm-node`
- `cargo test -p trnm-worker-agent`
- `cargo test -p trnm-cli`
- `cargo test -p trnm-bench`
- 以及专门的 free-ingress / QoS / saturation benchmark 报告

---

## Phase 3：Conflux-inspired ordering / finality / economics（选择性）

### 目标
在不打穿当前内核的前提下，把：

- finality abstraction
- sponsor / free-ingress economics
- ordering / DA / execution 解耦

做成独立增强层。

### 主 crate
- `trnm-node`
- `trnm-state`
- `trnm-oracle`
- `trnm-bridge-poc`
- `trnm-rpc`

### 关键任务

#### 1. `trnm-node`
- 引入 ordering/finality seam，而不是直接改成复杂 DAG 共识
- 最低目标：
  - block inclusion
  - execution completion
  - economic finality
  - audit finality
  这几种语义能被明确区分

#### 2. `trnm-state`
- 如果 sponsor / subsidy / ingress credit 引入链上状态，必须：
  - 可审计
  - 可 root
  - 可回滚
  - 可治理限幅

#### 3. `trnm-rpc`
- sponsor / free-ingress policy 入口
- quota / subsidy / abuse rejection diagnostics

#### 4. `trnm-oracle`
- 保持非共识关键
- 可作为：
  - risk score
  - abuse score
  - sponsor eligibility
  - price / policy suggestion
  的辅助来源
- 但不能直接让外部 oracle 成为共识真相源

#### 5. `trnm-bridge-poc`
- batch settlement / external ingress bridge
- sponsor / free ingress 的实验面
- 把重入口流量与链上结算逻辑解耦

### Phase 3 非目标
- 不承诺直接实现完整 Conflux Tree-Graph
- 不在当前阶段引入无法稳定验证的新共识复杂度

### Phase 3 验收
- finality abstraction 文档与测试
- sponsor / ingress economics 最小可行原型
- `trnm-bridge-poc` 与 `trnm-rpc` 的 batch settlement / ingress contract 验证

---

## 4. crate-by-crate 近中远期实施表

## 4.1 `trnm-types`

### 近期开工项
- 继续收口：Task / Query / Event / Governance / Metering 的稳定 schema
- 把“可 staged restore / pending update / slot payload”类对象的字段命名统一

### 中期项
- 如果 ingress/sponsor 引入新的协议类型，优先放在 `types`，不要散落到 `node/rpc`

### 验收
- 结构体字段新增后，test-target 不再出现大面积初始化漂移

---

## 4.2 `trnm-state`

### 近期开工项
- 继续做：
  - pending resolve approval
  - pending governance update
  - state_root regression
  - rollback / restore consistency
- MonetaryState 若继续推进，应作为 state 层一等对象，而不是 node 临时账本视图

### 中期项
- sponsor/quota/credit 状态对象化
- governance-sensitive 参数与 pending window root 化、事件化

### 验收
- `state_root_regression` 持续扩展而非收缩
- pending slot / staged quorum / pending governance 在 root 中可解释

---

## 4.3 `trnm-executor`

### 近期开工项
- 固定冲突判定 vs 调度优化的边界
- 热点对象 / 热点 lane 的 profiling 体系继续加强

### 中期项
- lane-aware scheduler policy interface
- executor policy traits / plugin seam

### 验收
- aggressive/adaptive 实验继续和默认路径隔离
- 回归 gate 保持 stable

---

## 4.4 `trnm-mempool`

### 近期开工项
- 明确 lane taxonomy 与 reserved capacity
- 显式化 admission / rejection reason

### 中期项
- free-ingress abuse resistance
- sponsor-aware admission class

### 验收
- control path starvation regression tests
- queue saturation / backpressure benchmark

---

## 4.5 `trnm-rpc`

### 近期开工项
- free submit contract
- idempotency / quota / lane hints
- 保持 query 面 hardening

### 中期项
- batch ingress
- sponsor diagnostics
- operator-readable explain APIs

### 验收
- contract tests
- malformed query/path smuggling tests
- ingress quota/idempotency tests

---

## 4.6 `trnm-node`

### 近期开工项
- block builder lane budgets
- rollback / recovery / preflight fail-closed
- ordering/finality seam 先抽象，不先引复杂图结构

### 中期项
- finality state machine v0
- DA / ordering / execution 更强解耦

### 验收
- replay / recovery / pending-restore regression
- finality event surface 稳定

---

## 4.7 `trnm-pouw`

### 近期开工项
- 保持 v1 主状态机冻结
- additive-only 扩展继续集中在：
  - metering
  - worker settlement
  - challenge/resolve economics
  - verifier/backend contract hardening

### 中期项
- 将更多“外围增强”通过 metadata/snapshot/policy 注入，而不是改主状态机

### 验收
- `--features real-tee-backend` 持续与默认矩阵并行守门
- invalid transition / version conflict / stale ref 优先级稳定

---

## 4.8 `trnm-worker-agent`

### 近期开工项
- receipt class / flush priority / retry policy
- 与 mempool lane 预算对齐

### 中期项
- richer telemetry
- sponsor-aware worker submission strategy

### 验收
- worker replay / retry / receipt gates
- control path 不被 worker flush 挤占

---

## 4.9 `trnm-oracle`

### 近期开工项
- 继续保持辅助验证器定位，不升格为共识真相源
- 把 observable metrics / validation schema 收平

### 中期项
- sponsor eligibility / abuse scoring shadow mode
- non-consensus advisory outputs

### 验收
- oracle failure 不影响共识安全，只影响 policy suggestion

---

## 4.10 `trnm-bridge-poc`

### 近期开工项
- batch settlement / settlement loop / compensation matrix 继续做成实验入口

### 中期项
- 作为 free-ingress 与 on-chain settlement 解耦的实验面

### 验收
- 桥接失败不污染主链状态机
- compensation/replay resilience 可测

---

## 5. 建议的 PR 栈

建议不要“一次性大迁移”，而是按以下 PR 栈推进：

### PR-1：Docs + seam declaration
- 架构草案
- crate roadmap
- 入口链接

### PR-2：State kernel hardening
- `trnm-types`
- `trnm-state`
- `trnm-state` tests

### PR-3：Executor policy seam
- `trnm-executor`
- profiling / metrics / bench support

### PR-4：Ingress & mempool contract
- `trnm-mempool`
- `trnm-rpc`
- contract tests

### PR-5：Node lane budgets & finality seam
- `trnm-node`
- event / rollback / preflight / recovery

### PR-6：PoUW additive protocol extensions only
- `trnm-pouw`
- `trnm-types`
- worker settlement / metering / verification contract

### PR-7：Worker-agent + bridge / sponsor experiment
- `trnm-worker-agent`
- `trnm-bridge-poc`
- optional `trnm-oracle` shadow-mode support

### PR-8：Economics & free-ingress closing set
- sponsor / quota / subsidy / anti-abuse
- doc + bench + operator surface closeout

---

## 6. 当前建议的 crate 优先级

### 最高优先级（先做）
1. `trnm-state`
2. `trnm-executor`
3. `trnm-mempool`
4. `trnm-rpc`
5. `trnm-node`

### 中优先级（随主线推进）
6. `trnm-pouw`
7. `trnm-worker-agent`
8. `trnm-cli`
9. `trnm-bench`

### 选择性推进（后接）
10. `trnm-oracle`
11. `trnm-bridge-poc`

---

## 7. 最终建议

如果要把这份路线图转成真实执行板，建议在下一步做两件事：

1. 把它挂到 `DEVELOPMENT_MASTER_UNIFIED_2026-03-04.md` 的入口地图里
2. 从本文抽取一版 **crate → owner/lane → gate → DoD** 的执行表

也就是：

- 本文负责“怎么分 crate 做”
- 下一版执行表负责“谁做、先做哪个、跑什么 gate、怎样算 done”

这才算从架构草案真正走到工程排期。
