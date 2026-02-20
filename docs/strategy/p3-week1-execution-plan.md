# P3 Week1 执行清单（按天可验收）

更新日期：2026-02-20  
负责人：Core Protocol / Executor / CI

---

## Week1 目标
- 建立 Aggressive Round3 的“归因 -> 优化 -> 验证”闭环。
- 不改默认策略，仅增强实验路径能力与证据链。

---

## D1（周一）Profiling 基线采集

### 任务
1. 固化 baseline 命令与参数（Original / Aggressive）。
2. 输出 3 套 workload（classic/mixed/hot-key）基线报告。
3. 记录已有指标：`candidate_groups_scanned`，补充采集模板。

### 交付
- `data/bench-baseline/<date>/...`
- `docs/strategy/p3-week1-baseline.md`

### 验收
- 三套 workload 可复现；同命令重复 3 次波动可接受（定义于报告）。

---

## D2（周二）扩展归因指标

### 任务
1. 增加指标：
   - 每 block 候选组平均扫描数
   - 每 tx 冲突检测耗时（p50/p95/p99）
   - 无效扫描占比
2. 输出 profile 汇总脚本（json -> markdown）。

### 交付
- `scripts/summarize_aggressive_profile.py`（扩展）
- `docs/perf/aggressive-round3-metrics.md`

### 验收
- 指标可在 CI 产物中读取；本地与 CI 字段口径一致。

---

## D3（周三）Round3 优化 Patch A

### 任务
1. 基于 D2 结果实施首个优化（优先减少无效扫描）。
2. 对 mixed 20000/2000 进行前后对比。

### 交付
- PR: `perf(executor): aggressive round3 patch-a`
- 对比报告（含风险说明）

### 验收
- 代表场景 >= 8% 提升；无新增测试失败。

---

## D4（周四）Round3 优化 Patch B

### 任务
1. 第二个优化（冲突判定/候选窗口策略）。
2. 增加参数保护（实验开关与默认行为隔离）。

### 交付
- PR: `perf(executor): aggressive round3 patch-b`
- 参数说明文档（默认值、范围、风险）

### 验收
- 代表场景累计 >= 15% 提升；Original 无回归。

---

## D5（周五）回归门禁接入 + 周报 ✅（已完成）

### 任务
1. 接入 Week1 指标到 nightly 产物和阈值检查。
2. 形成周报与下周计划（继续 / 回滚 / 变更方向）。

### 交付
- `scripts/check_aggressive_regression.sh`（扩展）
- `docs/perf/aggressive-round3-week1-report.md`

### 验收
- CI 能阻断明显回归。✅
- Week1 结论清晰：Go/No-Go + 下周行动项。✅

### Week2 执行结论（补记）
- Day1~Day3 已完成 deep-scan / hotspot 专项 A/B。
- 结论均为 No-Go（实验策略不进入默认路径），默认快路径继续冻结。
- 参考：
  - `docs/perf/aggressive-week2-day1-plan.md`
  - `docs/perf/aggressive-week2-day2-findings.md`
  - `docs/perf/aggressive-week2-day3-hotspot-findings.md`
  - `docs/perf/aggressive-week2-day4-decision-memo.md`

---

## 本周硬门禁

1. v1 接口冻结语义不得变化。  
2. 实验策略默认不得切换。  
3. 每个优化 PR 必须包含：
   - benchmark 数据
   - 回归结果
   - 风险说明

---

## 失败预案（任一触发即执行）

- 连续两天无有效收益：暂停代码优化，回到 profile 归因。  
- 发现一致性风险：立即回滚到上一稳定点，优先修复 correctness。  
- 指标口径不稳定：冻结结论，不做性能宣称。
