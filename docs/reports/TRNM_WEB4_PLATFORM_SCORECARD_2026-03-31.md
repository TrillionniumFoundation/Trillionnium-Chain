# TRNM Web4 Platform Scorecard (2026-03-31)

适用快照：`main@9ea9e7751`

## 结论

TRNM 当前若按 **Web4 平台项目** 而不是“单 Rust L1 仓库”来评估，最准确的位置是：

> **平台 Alpha 后段，接近 Beta-prep 之前的收口阶段。**

它已经不是概念仓库，也不是拼装 demo：
- Rust L1 核心链路完整；
- Web4 前端、只读查询契约、Agent 协议文档、运维/证据/runbook 体系都已成形；
- 但真正决定“能不能对外当平台卖/发”的外围闭环仍未关掉。

因此：

> **强链核，弱平台外围；可认真推进，但不应对外宣称 production-ready Web4 platform。**

---

## 一、红黄绿评分卡

### 1. 链核（state / executor / node / mempool / rpc / worker / cli）
- **评级：黄绿（3.5/5）**
- 判断：核心状态机、执行器、mempool、RPC、worker-agent、CLI 已成体系；已明显过了“原型玩具期”。
- 仍未到绿灯的原因：缺的不是 core logic，而是 public-mainnet / platform perimeter。

### 2. Web4 只读前台 / 查询展示层
- **评级：黄色（3/5）**
- 判断：`web4-frontend` 已有独立 Next.js 工程、contract tests、release preflight、release ready 脚本。
- 限制：当前语义仍是 **readonly API client + explicit mock fallback**，不是完整业务平台前台，也不暴露写路径。

### 3. 开发者可接入性（CLI / worker / docs / contracts）
- **评级：黄色（2.5/5）**
- 判断：已有 `trnm-cli`、`trnm-worker-agent`、MCP/A2A 合约文档、较完整的 README / runbook / release discipline。
- 限制：SDK / examples / 第三方开发者接入体验还没有形成真正“平台产品”级闭环。

### 4. 可验证执行层（Fraud / TEE / ZK）
- **评级：黄偏红（2/5）**
- 判断：方向明确，抽象边界存在，`trnm-pouw` 已有验证逻辑与 proof backend 相关结构。
- 限制：距离“平台可选证明层”仍有明显工程化差距，尤其是统一成本模型、生产可运行 sidecar、稳定操作面。

### 5. 跨链 / 互操作结算
- **评级：红色（1.5/5）**
- 判断：当前仓内仍是 `trnm-bridge-poc` 口径，说明命名本身就在诚实表达成熟度。
- 限制：距离稳定 bridge / settlement / audit / relayer trust model 还很远。

### 6. 身份 / AuthZ / Agent Trust
- **评级：黄偏红（2/5）**
- 判断：`trnm-types` 已有 DID / capability / settlement / relay 相关共享类型；A2A / MCP 契约文档也在。
- 限制：更像“协议边界已定义”，而不是“平台级身份与授权系统已产品化”。

### 7. 数据层 / Provenance / Stable read-model
- **评级：黄偏红（2/5）**
- 判断：query surface、事件查询、capability audit 查询、normalized audit events 已经让平台前台有了读取基础。
- 限制：durable indexer / explorer backend / historical read-model 仍是最弱板之一。

### 8. 可观测性 / 告警 / SRE 面
- **评级：黄偏红（2/5）**
- 判断：仓内已有大量 smoke / evidence / benchmark / health / release 脚本，说明工程意识是成熟的。
- 限制：统一 metrics contract、dashboard、alerting、incident 规范还没真正形成平台级 one-plane 视图。

### 9. 运维 / Operator lifecycle / Release governance
- **评级：黄色（2.5/5）**
- 判断：RC evidence、handoff、preflight、release discipline 文档已经非常像“认真做上线”的团队，而不是写着玩的项目。
- 限制：validator lifecycle、key ceremony、rotation、disaster recovery、secure signer 仍未闭环。

### 10. 对外可发布口径
- **评级：红色（1/5）**
- 判断：当前 truth-source 仍然清晰地给出 **Not release-ready**。
- 限制：public-mainnet / public-platform claim 仍不成立。

---

## 二、总判断（平台口径）

如果把 TRNM 分三层看：

### A. 作为 Rust L1 工程项目
- **判断：强**
- 已经是严肃工程，不是 demo。

### B. 作为 Web4 平台底座
- **判断：中等偏上**
- 有清楚的主干、可继续投资的结构、真实代码与脚本基础。

### C. 作为可对外承诺的 Web4 平台
- **判断：仍弱**
- 当前更像：
  - **有强链核的 Web4 平台 Alpha**
- 还不像：
  - **production-grade Web4 platform**

---

## 三、从当前 main 到 Web4 Beta candidate 还差的 10 个关键收口项

这里不再按“抽象愿景”排，而是按**最可能改变平台成熟度感知**的顺序排。

### 1. 稳定 read-model / indexer / explorer backend
- 这是当前最弱板。
- 没有 durable read-model，Web4 前台就仍然只是“只读 client 壳”，不是可信平台入口。
- 目标：tx/block/account/task/event 的稳定历史查询面。

### 2. Secure signer / keystore / offline signing
- 没有安全签名路径，任何平台叙事都会被卡死在 operator safety。
- 目标：keystore、offline signing、rotation、compromise SOP。

### 3. Real network formation / sync / join-rejoin
- 当前离 public network/runtime 仍有距离。
- 目标：bootstrap peers、state sync、peer scoring、join/rejoin 闭环。

### 4. Integrated prelaunch rehearsal + evidence + go/no-go discipline
- 目前有 rehearsal/evidence 脚本，但还不是整个平台级一锤定音闭环。
- 目标：把链核、RPC、worker、query、frontend、operator 视角串成一轮真正可审计彩排。

### 5. Unified observability / alerting / incident plane
- 要从“很多脚本和局部指标”变成“一张平台运维图”。
- 目标：node/rpc/worker/bridge/oracle/query/frontend 的统一监控面。

### 6. Economics / anti-spam / fee boundary freeze
- 平台不是只要功能跑通；还要能定义明确的 admission / spam / fee 边界。
- 目标：对外能解释的稳定经济口径，而不是继续实验性摆动。

### 7. Validator / operator lifecycle
- 需要从 runbook 走向真正的 ceremony / rotation / DR 体系。
- 目标：genesis、bootstrap、replacement、rollback、recovery 的可执行闭环。

### 8. Web4 frontend 从“readonly dashboard”升级为“稳定平台入口层”
- 不是去加写接口，而是把它升级成真正可信的平台读取与审计入口。
- 目标：更稳定的 query contract、错误语义、状态归一化、真实运维视图。

### 9. Identity / capability / agent trust 产品化
- 当前共享类型和协议边界已经在，但“平台可用”还差一截。
- 目标：DID/capability 在真实多主体调用里可验证、可撤销、可审计。

### 10. Cross-chain / verifier 从 PoC 语义升级到可控 platform module
- 若 Day-1 不带这些，可放到 Beta 后段；
- 若平台叙事里要讲“跨链 Web4 / 可验证执行平台”，它们必须尽快脱离 PoC 口径。

---

## 四、最简执行建议

如果只允许继续推 4 个方向，建议按下面顺序：

1. **read-model / indexer / explorer**
2. **secure signer / keystore**
3. **network formation / sync / join-rejoin**
4. **integrated rehearsal + observability**

原因很简单：
- 这四项最能把项目从“强链核”推向“可信平台”；
- 它们也是最容易决定外部人是否愿意认真看待 TRNM 的部分。

---

## 五、最终一句话

> **当前 main 已经足够证明：TRNM 不是 PPT Web4。**
> **但它也还没有走到可以稳稳自称为 production-grade Web4 platform 的阶段。**
> **最准确的表述是：强链核 + 初步平台壳 + 明确外围缺口的 Alpha 后段项目。**
