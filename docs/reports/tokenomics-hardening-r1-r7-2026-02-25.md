# Tokenomics Hardening 收口报告（R1-R7）

日期：2026-02-25  
范围：Trillionnium Rust L1（`trillionnium-rust`）

## 一、已落地（按风险闭环顺序）

### R1 Revealed 活性与迟到挑战
- 已完成：
  - `Revealed` 写入 `challenge_deadline_height`
  - 超窗 challenge 拒绝
  - 未被 challenge 的 `Revealed` 超时自动 `Completed`
- 关键提交：`2dd6d11`

### R2 Resolve 权限绑定
- 已完成：
  - `apply_resolve(_at_height)` 增加 resolver 身份
  - 仅允许记录的 `challenger` 执行 resolve
- 关键提交：`d107ad1`

### R3 Worker 真实经济惩罚
- 已完成：
  - accept 时校验/锁定 worker stake（task lock）
  - 超时/裁定失责触发真实 slash
  - slash 流入 `treasury.worker_slashes`
- 关键提交：`91c6ae3`

### R4 挑战成功正收益
- 已完成：
  - challenge 成功不再仅退本，新增最小 bounty（来自 slash 资金）
- 关键提交：`d1f4b33`

### R5 Challenge spam 防护
- 已完成：
  - 引入动态最小 challenge bond（静态下限 + bounty/stake 维度）
  - 新增治理参数并纳入 schema 校验
- 关键提交：`dbc7576`

### R6 治理参数防突变
- 已完成：
  - 敏感参数 timelock
  - 单次变更限幅（bps）
  - pending governance updates 纳入状态确定性
- 关键提交：`954b031`

### R7 事件账务闭环
- 已完成：
  - `treasury_delta/challenger_delta` 改为真实状态差分
  - resolve/timeout 路径事件账务字段对齐真实资金流
- 关键提交：`c6391c0`

---

## 二、配套修正

- challenge window 默认值与治理下限对齐（20→100）：`7bf9a42`
- challenge economics 文档与 treasury forfeits 语义对齐：`f43e974`

---

## 三、当前收益（工程视角）

1. **安全性**：堵住“无限期可挑战”“任意人可 resolve”“状态惩罚无经济成本”等关键漏洞。  
2. **激励相容**：挑战成功转为正期望（最小版本），减少“只靠善意挑战”。  
3. **抗滥用**：低成本 spam challenge 门槛抬升。  
4. **治理稳态**：敏感参数不再可瞬时大幅摆动。  
5. **可审计性**：事件账务字段可直接对账，不再主要依赖推断。

---

## 四、仍建议后续推进（Phase-2）

1. **挑战奖励函数化**：从固定 bounty 升级为与风险/贡献挂钩（并设上限）。
2. **治理执行器接线**：全链路统一使用带 height 的 `set_gov_param(...)`，减少 `unchecked` 使用面。
3. **参数变更治理体验**：提供 pending 更新查询与可视化（RPC/API）。
4. **经济仿真门禁**：将 spam/拥堵/攻击仿真纳入 nightly gate。
5. **文档与规范同步**：把 R1-R7 行为写入 protocol docs + release notes，避免实现/文档漂移。

---

## 五、建议发布口径（简版）

本轮完成了 PoUW tokenomics 的第一阶段硬化：
- 从“可用”提升到“可防滥用、可审计、可治理稳态”；
- 仍保持最小改动原则，未引入大规模架构重写。
