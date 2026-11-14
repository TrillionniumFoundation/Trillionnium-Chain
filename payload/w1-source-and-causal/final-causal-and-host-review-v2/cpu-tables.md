# R1 原报告 CPU 小表

所有 CPU 数值由已封原字段转换为毫秒。不同列有嵌套或不同终止边界，不是可相加的“四秒总 CPU”；详见 summary.json 和下面范围说明。

|来源|阶段|攻击线程合计|reader|Submit 客户端|History 客户端|独立 replay + confirmation|server mutation charged|其中 server full W1|
|---|---|---:|---:|---:|---:|---:|---:|---:|
|head/original|attack-free-baseline|0.000|30.114|5.872|6.009|563.313|41.533|10.381|
|head/original|from-zero-pressure|382.272|16.895|5.962|0.909|93.291|309.458|100.451|
|head/fresh|attack-free-baseline|0.000|30.208|5.778|5.727|565.146|41.532|10.239|
|head/fresh|from-zero-pressure|355.550|17.964|5.887|0.950|52.397|439.702|295.731|
|prospective/original|attack-free-baseline|0.000|37.523|5.772|6.521|579.608|42.288|10.238|
|prospective/original|from-zero-pressure|375.938|14.922|6.327|1.987|100.211|307.722|96.474|
|prospective/fresh|attack-free-baseline|0.000|36.736|6.108|6.018|568.430|43.089|10.339|
|prospective/fresh|from-zero-pressure|351.310|17.757|6.370|1.012|46.468|436.988|290.409|

## 压力攻击线程分解

|来源|实际 calls（每 worker 范围）|whole worker CPU|call.client_thread_cpu_ns 合计|solution_search_thread_cpu_ns 已知合计 / 未知项|solution_trials|fresh attacker_cpu_ns|未独立分解残差|
|---|---|---:|---:|---:|---:|---:|---:|
|head/original|331 (18–23)|382.272|297.650|13.096 / 1|77684|不适用|84.622|
|head/fresh|209 (12–14)|355.550|189.065|9.846 / 2|58854|95.293|71.192|
|prospective/original|316 (18–21)|375.938|293.113|13.774 / 1|82897|不适用|82.825|
|prospective/fresh|198 (11–13)|351.310|187.158|8.757 / 2|52835|94.587|69.565|

## 范围与不能相加的关系

- 攻击 whole worker CPU 包括 prepare/clone 或 fresh 构造、所有 client call、调用后诊断转换、compact_pressure_call 序列化及哈希、循环和记录。原包构造在 original 模式阶段前，fresh 构造在 worker 循环内。残差不是“纯 JSON 成本”。
- client_thread_cpu_ns 在身份派生前开始、结果诊断 JSON 转换前结束；solution_search_thread_cpu_ns 是其内部子区间。未知值保留未知，未补零。fresh attacker_cpu_ns 已包含在 whole worker CPU 内。
- 部分攻击调用和清理延伸到约 4.09 秒；reader 持续到原窗口；service 在 drain/shutdown 后取得。不能把这些合计除以四秒或以 0.25 CPU 供给解释为精确占比。
- independent_replay_and_confirmation_cpu_ns 包含 History RPC、replay、确认和记录；各 replay 和最后确认是内部子范围。server full W1 是 mutation charged 的内部子范围；body/response CPU 也嵌套其中。
- scalar 账本 initial credit=2 秒 CPU、refill=250ms CPU/s、reserve=100ms CPU、worker limit=2 是原账户策略，不是物理 CPU 配额测量。所有八阶段 mutation CPU refusal=0；这不能证明没有物理竞争。
- PQ authentication CPU=0 仅说明该 PQ 计量字段；它不证明经典 reactor authentication CPU 为零。
- cpu.stat 前后值覆盖整个 original+fresh 子命令及其源校验，不能分配给单次四秒 phase、某次 replay 或某个函数。
- 每个 worker 的原纳秒数、calls 与字段完整指针保存在 cpu-phases.json 和 attacker-cpu.json；完整旧派生原件保持不变。
