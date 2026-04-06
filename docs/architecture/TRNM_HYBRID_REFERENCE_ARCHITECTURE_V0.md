# TRNM Hybrid Reference Architecture v0（Solana / Sui / Conflux 分层借鉴草案）

- 状态：**Draft / architecture option**
- 范围：定义 TRNM 如何**同时借鉴** Solana、Sui、Conflux 的分层方法；**不直接声明实现完成度，不覆盖发布口径**
- 当前适用代码面：`trillionnium/` 主线，尤其是 `trnm-state`、`trnm-executor`、`trnm-node`、`trnm-mempool`、`trnm-rpc`、`trnm-pouw`

> 入口约定：
> - 当前是否 release-ready：看仓库根 `RELEASE_READINESS.md`
> - 开发排期 / lane 调度：看 `docs/development/DEVELOPMENT_MASTER_UNIFIED_2026-03-04.md`
> - ZKP 平台边界：看 `docs/architecture/TRNM_ZKP_PLATFORM_V0.md`
>
> 本文只回答一个问题：
> **TRNM 能否同时借鉴 Solana、Sui、Conflux？如果可以，应该如何分层借，而不是把三套系统硬拼在一起？**

---

## 1. 结论先行

**可以借，但必须分层。**

TRNM 最合理的组合不是“像三条链的平均值”，而是：

- **状态 / 执行内核更像 Sui**
- **数据面 / 高并发入口更像 Solana**
- **排序 / finality / 免费入口经济抽象可选择性借鉴 Conflux**
- **PoUW、metering、worker accounting、challenge/resolve** 仍然保持 TRNM 自己的协议核心

一句话版：

> **Sui-like state kernel + Solana-like high-throughput data plane + selective Conflux-inspired ordering/economics + TRNM-native PoUW core**

---

## 2. 为什么 TRNM 适合走这条路

从当前代码主线看，TRNM 已经天然具备“分层借鉴”的条件：

- `trnm-state`：versioned object store + `state_root()`
- `trnm-executor`：冲突检测与并发分组
- `trnm-node`：出块循环、执行接线、事件输出
- `trnm-pouw`：PoUW 状态机（`OPEN → ASSIGNED → COMMITTED → REVEALED → CHALLENGED → COMPLETED/SLASHED`）
- `trnm-mempool`：lane / QoS / admission / backpressure 路线

这意味着 TRNM 已经不是“一个只有单线顺序执行的账户链壳子”，而是：

1. **有对象/版本语义**
2. **有并发执行骨架**
3. **有独立于通用转账的 PoUW 业务状态机**
4. **有高并发入口重构方向**

因此，TRNM 不是要问“像哪一条链”，而是要问：

> **每一层最值得向哪一条链学什么，哪些绝不能混。**

---

## 3. 总体分层

```text
Applications / Workers / Clients
            |
            v
Ingress / RPC / Free Submission Plane
            |
            v
Lane-Aware Mempool / QoS / Admission / Backpressure
            |
            v
Ordering / Consensus / Finality
            |
            v
Deterministic Parallel Execution
            |
            v
Versioned Object State + State Root
            |
            v
TRNM-native PoUW / Metering / Challenge / Resolve / Accounting
```

### 分层主借鉴映射

| 层 | TRNM 主借鉴对象 | 借什么 | 不借什么 |
|---|---|---|---|
| 状态模型 | **Sui** | object/version、冲突域、因果状态推进 | 不把一切都改写成 Move/Sui 原生对象语义 |
| 执行引擎 | **Sui + Solana** | object-conflict 并行 + 高吞吐调度/流水线 | 不把执行权限/账户锁定语义照抄成 Solana 账户模型 |
| mempool / ingress | **Solana** | QoS、优先级、入口工程、流水线化吞吐 | 不照搬其全部费用与 leader 假设 |
| 排序 / finality | **Conflux（选择性）** | 高吞吐排序、确认层抽象、并发确认启发 | 不直接整套照搬 Tree-Graph 共识 |
| 经济入口 | **Conflux（选择性）** | sponsor / 免费提交 / anti-abuse 启发 | 不照搬其账户经济系统 |
| 协议核心 | **TRNM 自身** | PoUW / worker accounting / metering / challenge/resolve | 不让外部参考链反客为主 |

---

## 4. TRNM 的“唯一内核”应该是什么

如果 TRNM 要成功借三家，必须先有一个**不动摇的内核**。

本文建议：

### 4.1 唯一内核

TRNM 的唯一内核应是：

- **对象/版本驱动状态**
- **可判定冲突的并行执行**
- **PoUW 状态机与结算语义为第一性业务对象**

也就是说，TRNM 不是：

- 账户链 + 顺便跑 PoUW
- 通用 VM + 外挂一个 AI 任务合约

而是：

- **PoUW-native 的对象化、并发友好型 L1**

### 4.2 为什么更偏 Sui 而不是 Solana 作为内核参考

因为从当前实现看，TRNM 更自然地站在：

- `TaskObject`
- `ObjectRef`
- `version conflict`
- `state_root()`

这套范式上。

它已经更接近：

- object/version state
- dependency-aware execution

而不是：

- 账户余额 + 程序账户锁集

所以：

> **TRNM 的底层世界观应优先固定为 Sui-like 的对象/版本世界观。**

---

## 5. 如何借 Sui

## 5.1 要借的

### A. 对象级状态
把以下实体进一步对象化、版本化、可审计化：

- `TaskObject`
- worker accounting object
- governance pending update object
- metering snapshot object（或 metadata 子结构）
- challenge / resolve pending approval object

### B. 冲突可判定并行执行
执行器应该围绕：

- 读集 / 写集
- object id / version
- deterministic dependency grouping

来判定是否并发。

### C. 因果顺序明确
例如：

- `REVEALED -> CHALLENGED`
- `CHALLENGED -> COMPLETED/SLASHED`

不是“事件碰巧发生”，而是对象版本推进的明确结果。

## 5.2 不该借的

- 不必引入 Move 作为强前提
- 不必把所有对象都强制变成 Sui 风格 ownership 分类
- 不必照搬其对象存储/认证细节实现

TRNM 借的是：

> **对象化建模与并发友好状态语义**

而不是：

> **Sui 的整套语言/runtime 绑定**

---

## 6. 如何借 Solana

## 6.1 要借的

### A. 高吞吐数据面工程
重点借：

- pipeline 化处理
- 提前校验 / 尽早丢弃
- 分 lane / 分优先级的 admission
- 高并发 ingress 路径的低开销实现

### B. QoS / 优先级 / backpressure
结合 TRNM 的免费入口目标，mempool 需要：

- critical tx 不被免费流量淹没
- worker 回执 / resolve / challenge / governance 这类关键路径有保底 lane
- backpressure 能向入口回传，而不是让节点内部爆炸

### C. 执行调度工程学
借鉴方向包括：

- 热点对象/热点 lane 的调度优化
- 批次化执行
- 更细粒度指标：队列深度、调度命中、冲突回退、热点 lane 饱和率

## 6.2 不该借的

- 不把账户+程序账户锁定模型当唯一执行模型
- 不把 fee market 直接照搬
- 不把 leader 假设、时钟假设原样搬过来

TRNM 借的是：

> **高吞吐数据面与调度工程能力**

而不是：

> **Solana 的全部执行语义**

---

## 7. 如何借 Conflux

## 7.1 要借的

### A. 高吞吐排序 / finality 启发
TRNM 可以研究并选择性吸收：

- 排序层与执行层的更强解耦
- 高吞吐下的确认层抽象
- 在高并发提交面下，如何保证最终结算语义清晰稳定

### B. 免费入口 / sponsor 经济启发
TRNM 有一个强约束：

- 提交端免费
- 交易量大
- 必须高并发

这意味着经济层必须回答：

- 免费提交如何防 spam
- 谁为入口成本买单
- 哪些交易必须保底进入
- challenge / resolve / worker settlement 如何避免被淹没

这方面可以借 Conflux 式的：

- sponsored tx / 费用抽象
- 入口经济与链上执行成本分离
- 免费入口但不免费滥用

## 7.2 不该借的

- 不直接照搬 Tree-Graph 作为当前阶段必选项
- 不在还没把状态/执行边界稳定前，就把共识复杂度拉满

TRNM 借的是：

> **排序/确认抽象与免费入口经济机制的启发**

而不是：

> **完整 Conflux 共识系统的一次性移植**

---

## 8. 映射到当前 TRNM crate

## 8.1 `trnm-state`
目标定位：**Sui-like state kernel**

继续强化：

- object/version invariants
- pending governance updates 的状态根可观测性
- pending resolve approval 的 canonical / fail-closed restore 语义
- object-level economics/accounting consistency

## 8.2 `trnm-executor`
目标定位：**Sui-like conflict detection + Solana-like scheduling heuristics**

继续强化：

- dependency grouping
- hotspot-aware scheduling
- lane-aware execution hints
- 调度指标与回归 gate

## 8.3 `trnm-mempool`
目标定位：**Solana-like high-throughput ingress/QoS plane**

继续强化：

- lane isolation
- QoS / admission policy
- anti-starvation
- reserved capacity for critical flows
- free-ingress abuse mitigation

## 8.4 `trnm-rpc`
目标定位：**TRNM ingress gateway + protocol boundary**

继续强化：

- submit-free-task / idempotency / quota
- query contract hardening
- worker / governance / challenge / resolve 的高优先入口策略

## 8.5 `trnm-node`
目标定位：**ordering/finality/execution glue**

短期：

- 维持当前 deterministic block loop
- 强化 preflight / rollback / recovery / observability

中期：

- 为 Conflux-inspired ordering/finality 抽象留接口
- 不先把 DAG/Tree-Graph 复杂度硬灌进去

## 8.6 `trnm-pouw`
目标定位：**TRNM-native protocol core**

这里最不该被“参考链拿走主导权”。

必须保持 TRNM 原生：

- `create/accept/commit/reveal/challenge/resolve`
- worker settlement
- metering snapshot
- challenge bounty / slash / rebate / completion bonus
- 审计事件稳定语义

---

## 9. 兼容性红线

## 9.1 不打穿 PoUW v1 冻结面

当前 v1 已冻结的：

- 状态迁移语义
- 核心接口字段语义
- 最小错误码集合
- 最小事件字段审计集合

因此，借鉴 Solana/Sui/Conflux 时：

- **优先改外围层**：mempool / ingress / scheduling / ordering / economics
- **不要先改冻结的 PoUW 主状态机语义**

## 9.2 不同时引入两个“主状态模型”

不能一边说：
- object/version 是核心

另一边又让：
- account/lock model 成为一等公民并与其并列

否则执行语义会失真，后续证明面会非常难收口。

## 9.3 不在没有强需求前整套引入 Conflux 共识

排序层可以抽象、预留、试验；
但在 TRNM 还处于状态/执行/入口持续收口阶段时，
不应该把共识复杂度一次性拉满。

---

## 10. 推荐的三阶段路线

## Phase 1：固定内核（现在）

目标：
- 明确 TRNM 是 **object/version + parallel execution** 内核
- 继续把 `trnm-state` / `trnm-executor` / `trnm-pouw` 收到更稳

交付：
- state/restore/canonical semantics 稳定
- executor regression gates 稳定
- PoUW / metering / worker accounting additive-only 延展稳定

## Phase 2：强化 Solana-like 数据面

目标：
- 把 free-ingress / QoS / backpressure / lane scheduling 做深

交付：
- lane-aware mempool contract
- critical path reservation
- free ingress anti-abuse policy
- RPC/ingress 协议统一

## Phase 3：选择性引入 Conflux-like ordering/finality/economics

目标：
- 在不打穿内核的前提下，提升排序/确认层与免费入口经济设计

交付：
- finality abstraction v0
- sponsored/free-ingress economic model
- 如果必要，再评估更强排序图结构

---

## 11. 当前最值得做的架构决策

如果要把本文变成真正的执行路线，建议先锁 4 件事：

### D1. 明确内核表述
建议在主架构文档里明写：

> TRNM is a Rust-native PoUW L1 with a versioned object-state kernel and deterministic parallel execution.

### D2. 明确 Solana 借鉴边界
建议写清：

- 借 data plane / scheduler / QoS
- 不借账户模型作为核心世界观

### D3. 明确 Conflux 借鉴边界
建议写清：

- 借 ordering/finality/economic abstractions
- 不承诺当前阶段引入完整 Tree-Graph

### D4. 明确 PoUW 不被参考链语义覆盖
建议写清：

- 参考链只服务于底层系统设计
- 不改写 TRNM 的 PoUW 核心协议身份

---

## 12. 最终建议

如果必须给出一句决策建议：

> **TRNM 应该采用“以 Sui 为状态内核参考、以 Solana 为高吞吐数据面参考、以 Conflux 为排序/免费入口经济参考”的混合架构路线，但必须坚持 TRNM-native PoUW 为协议主轴。**

这意味着：

- **内核单一**：object/version + parallel execution
- **吞吐工程借 Solana**
- **确认/经济策略借 Conflux**
- **业务协议仍是 TRNM 自己**

---

## 13. 非目标

本文不做以下承诺：

- 不声明“TRNM 已经实现 Solana/Sui/Conflux 混合架构”
- 不声明“TRNM 已具备某条参考链的生产级能力”
- 不声明“将直接迁移到某个参考链的完整协议栈”
- 不以本文替代 benchmark、release、readiness、security truth source

本文只是把“能不能同时借三家”这个问题，收敛成一条**可执行、可分层、可避免自相矛盾**的路线。
