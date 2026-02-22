# Challenge Re-exec 收口计划（模板态 -> 可复跑流程态）

更新日期：2026-02-22
范围：仅评估与流程收口，不涉及代码改动。

## 1) 当前状态评估（as-is）

### 已具备（模板态能力）
- 脚本存在且可执行：
  - `scripts/challenge_reexec_resolve_template.sh`
  - `scripts/challenge_reexec_bundle.sh`
  - `scripts/challenge_reexec_template_smoke.sh`
- 文档基线：
  - `docs/protocol/challenge-reexecution-framework-v0.1.md`
- 本地 smoke 实跑通过（2026-02-22）：
  - 输出 `[OK] challenge reexec bundle smoke`
  - 产物落地于 `data/reexec-smoke/...` 与 `data/reexec-bundles/...`

### 关键缺口（尚未形成“可复跑流程态”）
1. **主流程脚本缺失/漂移**：README 与 release note 提到的
   - `scripts/challenge_reexec_e2e_demo.sh`
   - `scripts/p0_acceptance.sh`
   - `scripts/p0_merge_gate.sh`
   当前仓库未找到，导致“文档口径 ≠ 可执行入口”。
2. **输入来源未标准化**：v0.1 文档描述了应提取的 task/challenge 元数据，但未给固定导出命令或 schema 校验步骤。
3. **authority 回写仅模板化**：`resolve-template` 可生成，但缺少“在何环境、由谁签名、失败如何回滚”的 runbook。 
4. **验收标准偏 smoke**：当前仅验证文本模板和文件存在，未验证“从 challenge 事件到 resolve 提交”的完整可追踪证据链。

---

## 2) 最小实现计划（<=6 项）

> 目标：在不引入复杂新实现的前提下，形成“固定输入 -> 固定执行 -> 固定验收 -> 固定留痕”的可复跑流程。

### T1. 冻结唯一入口与版本口径（文档层）
- 动作：明确 challenge re-exec 的**唯一主入口**（即使是手工步骤，也要单页固定），并标注脚本真值清单（现有/缺失/替代）。
- 验收标准：
  - runbook 中出现一条“唯一推荐路径”；
  - README/STATUS/BACKLOG 的入口描述与该路径一致；
  - 不再引用仓库中不存在的脚本名。

### T2. 固化输入快照规范（artifact contract）
- 动作：为 re-exec 输入定义最小 schema（task_id、result_hash、evidence_uri、challenger、trace_id 等）与目录结构。
- 验收标准：
  - 给出 `input.json` 示例与字段必填/可选；
  - 至少 1 份样例输入可被人工复核并用于后续步骤；
  - 缺字段时有明确失败判定（文档规则）。

### T3. 固化执行与产物路径（bundle contract）
- 动作：基于现有 `challenge_reexec_bundle.sh` 固定执行命令模板与产物命名（decision/resolve-template/summary）。
- 验收标准：
  - 同一输入可重复产出等价结论（`challenge_succeeded` 与 `final_result_hash` 一致）；
  - `trace_id` 在 `decision.json` 与 `resolve-template.txt` 中一致；
  - 产物目录命名规则写入 runbook。

### T4. 补齐 authority 回写操作卡（SOP）
- 动作：补一页“谁在何环境执行 `resolve-challenge`、参数如何确认、失败如何重试/回滚”。
- 验收标准：
  - 明确角色边界（reexec operator / authority signer / reviewer）；
  - 明确三类失败分支：签名失败、链上拒绝、参数不一致；
  - 每类失败都有下一步动作与留痕要求。

### T5. 建立一次端到端演练证据包（golden sample）
- 动作：选择 1 个 challenge 样本，按 T1~T4 跑完并归档“输入-决策-回写-结果”证据。
- 验收标准：
  - evidence 包含：`input.json`、`decision.json`、`resolve-template.txt`、链上交易回执（或明确因环境限制未上链的记录）；
  - 评审人可按 runbook 在新目录复跑并得到一致结论；
  - 在 `STATUS.md` 或同级文档记录本次演练结论。

### T6. 纳入 gate 口径（最小阻断条件）
- 动作：将 challenge re-exec 的最小检查接入门禁口径（可先 advisory，后 hard gate）。
- 验收标准：
  - 明确 gate 等级（advisory/hard）与触发条件；
  - 至少包含“模板 smoke + 文档入口一致性 + 样本证据存在”三项检查；
  - 未满足时在 release 决策中可见并可追责。

---

## 3) 可并行项与阻塞项

## 可并行（建议并行推进）
- **并行 A**：T1（入口口径冻结） + T2（输入 schema）
- **并行 B**：T3（bundle contract） + T4（authority SOP）
- **并行 C**：T6（gate 定义）可在 T5 演练准备阶段先写草案

## 阻塞依赖（关键路径）
- **B1（关键阻塞）**：T5 必须等待 T1~T4 完成，否则演练样本不可复用。
- **B2（环境阻塞）**：authority 可签名环境与权限不到位时，T5 只能完成“离线到模板”半链路，无法闭环到 on-chain resolve。
- **B3（口径阻塞）**：若 README/Release Note 继续引用缺失脚本，T6 gate 无法稳定执行（会出现“文档通过、执行失败”）。

---

## 4) 结论（收口定义）

当前处于**模板态已可用、流程态未闭环**。
最小收口应以 **T5 可复跑 golden sample + T6 可见 gate** 为完成标志：
- 不是“脚本能生成模板”，而是“团队能按同一 runbook 在不同时间复跑并复核同一决策”。
