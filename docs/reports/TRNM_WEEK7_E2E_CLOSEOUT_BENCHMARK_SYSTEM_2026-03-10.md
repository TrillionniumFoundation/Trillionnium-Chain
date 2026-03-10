# TRNM Week 7 E2E Closeout / 对标口径 / Benchmark 体系

> 日期：2026-03-10  
> 目标：把 classic / mixed / hot-streak 的 micro-bench，桥接到更真实的系统链路指标；同时冻结可复现命令、统一结果产物、硬件/窗口/口径说明。  
> 状态：Week 7 closeout v1（先收口方法、产物、字段；不把 micro 数字冒充链级 TPS）

---

## 0. 这份 closeout 在解决什么

TRNM 现有 benchmark 资产已经足够回答：
- 调度/分组内核在 `classic / mixed / hot-streak` 三类冲突画像下是否稳定；
- 不同 grouping strategy 是否真的带来收益；
- 当冲突升高时，groups 和 elapsed 如何变化。

但它还**不能单独回答**：
- 链级 submit TPS / finalized TPS 是多少；
- P50 / P95 / P99 finality latency 是多少；
- 共识 / mempool / commit / storage 哪一段是系统主瓶颈。

所以 Week 7 closeout 的原则很明确：

1. **承认 micro 与 E2E 是两层口径**；
2. **建立桥接字段**，把 micro 结果翻译成系统预算语言；
3. **统一产物**，让后续 E2E lane 只需要往同一套 JSON 里补链路时间戳与系统指标；
4. **冻结复现命令与 benchmark profile**，避免“不同机器 / 不同窗口 / 不同热身方式”的结果混讲。

---

## 1. 口径冻结：哪些能讲，哪些不能讲

## 1.1 可以讲的（当前 closeout）

当前可以稳定输出：
- `workload`: `classic | mixed | hot-streak`
- `txs`, `keys`, `strategy`, `strategy_source`
- `groups`, `elapsed_ms`
- `candidate_groups_scanned`, `stage_*_checks/hits`（如果 profile 有）
- `micro_scheduler_ceiling_tps`
- `groups_per_ktx`
- `elapsed_ms_per_ktx`
- `scheduler_window_share[target_tps]`

这些字段回答的是：
- 同一种负载画像下，**调度器/分组器本身**有多快；
- aggressive 相对 original 是变快、持平还是退化；
- 若目标系统想跑某个 TPS，**scheduler grouping 这一段**会占用多少预算窗口。

## 1.2 不能直接讲的（必须等 E2E 数据）

以下字段**不能**由当前 micro-bench 直接宣称：
- `submit_tps`
- `finalized_tps`
- `finality_p50_ms`
- `finality_p95_ms`
- `finality_p99_ms`
- `drop_rate`
- `retry_rate`
- `rollback_rate`

原因很简单：它们属于完整系统链路，而不是 scheduler 内核。

---

## 2. classic / mixed / hot-streak 如何桥接到更真实系统链路

## 2.1 三类 workload 不是“TPS 档位”，而是“冲突画像”

- **classic**：读写集几乎同构，冲突关系最直观，适合看稳定基线；
- **mixed**：读多写少、读写扇出更接近真实业务；
- **hot-streak**：存在局部热点与连续热点段，最接近“局部热门账户/对象持续被打爆”的线上坏天气。

因此，这三类 workload 更适合作为：
- **执行内核压力画像**，不是最终业务吞吐结论；
- **E2E 压测模板**，而不是链级 TPS 标签。

## 2.2 真实系统链路的分段

为了避免口径漂移，Week 7 把系统链路统一拆成：

1. `client_submit`
2. `mempool_queue`
3. `consensus`
4. `scheduler_grouping`
5. `execution`
6. `commit`
7. `storage`
8. `finality_observation`

当前 micro-bench 只直接覆盖第 4 段；后续 E2E 只要给其余段补时间戳，就能得到统一闭环。

## 2.3 桥接字段：怎么把 micro 说成人能比较的系统预算

### A. `micro_scheduler_ceiling_tps`

定义：

```text
micro_scheduler_ceiling_tps = txs / (elapsed_ms / 1000)
```

含义：
- 是 **scheduler grouping 内核的理论上限**；
- 不是链级 TPS；
- 只能用来回答“执行内核有没有明显成为第一瓶颈”。

### B. `elapsed_ms_per_ktx`

定义：

```text
elapsed_ms_per_ktx = elapsed_ms * 1000 / txs
```

含义：
- 便于横向比较 workload 形态；
- 能直接转成“每 1000 笔交易，scheduler 需要多少 ms”。

### C. `scheduler_window_share[target_tps]`

定义：

```text
required_window_ms = txs * 1000 / target_tps
scheduler_window_share = elapsed_ms / required_window_ms
```

含义：
- 把 micro 数据翻译成“如果系统目标是 1000 / 5000 / 10000 TPS，那么 scheduler 分组单独会占掉多少预算”。
- 这就是 classic / mixed / hot-streak 与真实系统链路最关键的桥。

例子：
- 如果某 workload 在 5000 TPS 下 `scheduler_window_share = 0.18`，意思是：
  - 在该负载画像下，**scheduler grouping 本身**会吃掉约 18% 的 1 秒吞吐预算；
  - 剩下 ~82% 预算还要覆盖 mempool / consensus / execution / commit / storage / finality。

这比“直接拿 micro elapsed 算 TPS 再出去对标”诚实得多，也更有工程价值。

---

## 3. 统一结果产物：Week 7 closeout v1

本次新增脚本：
- `trillionnium-rust/scripts/render_benchmark_closeout.py`
- `trillionnium-rust/scripts/run_benchmark_closeout.sh`

统一输出目录：
- `trillionnium-rust/run/bench/closeout-<timestamp>/`

统一产物：
- `benchmark-closeout.json`
- `benchmark-closeout.md`

## 3.1 JSON 是真相源，MD 是给人读的封面

### `benchmark-closeout.json` 结构

顶层字段：
- `generated_at`
- `inputs.regression_csv`
- `git.branch`
- `git.head`
- `hardware`
- `benchmark_profile`
- `summary`
- `e2e_mapping_template`

### `benchmark_profile`

冻结以下口径：
- `profile_id`
- `measurement_window`
- `warmup_policy`
- `target_tps_windows`
- `workload_family`
- `disclaimer`

### `summary.workloads.<name>`

按 workload 输出：
- `elapsed_ms.{min,max,avg}`
- `groups.{min,max,avg}`
- `micro_scheduler_ceiling_tps.{min,max,avg}`
- `groups_per_ktx.{min,max,avg}`
- `elapsed_ms_per_ktx.{min,max,avg}`
- `aggressive_minus_original_ms.{min,max,avg}`
- `bridge_to_system.window_share_avg_original`
- `cases[]`
- `pairwise_deltas[]`

### `e2e_mapping_template`

后续 E2E lane 必须按这组字段对齐：
- `submit_tps`
- `finalized_tps`
- `finality_p50_ms`
- `finality_p95_ms`
- `finality_p99_ms`
- `drop_rate`
- `retry_rate`
- `scheduler_window_share`
- `bottleneck_segment`

这相当于给 Week 8 或后续 system benchmark 预留了稳定的落点。

---

## 4. 硬件 / 窗口 / 复现实验说明

## 4.1 硬件说明

closeout 脚本会自动记录可探测到的本机硬件信息，例如：
- platform
- machine
- processor
- python
- （在支持时）CPU 品牌、逻辑核数、物理核数、内存

注意：
- 如果某些字段探测失败，不阻塞产物生成；
- 后续若要做“对外可审”的 benchmark profile，建议补固定字段：
  - CPU 型号
  - 核数
  - RAM
  - 存储介质
  - OS 版本
  - Rust toolchain
  - 是否冷启动 / 热缓存

## 4.2 窗口说明

当前 Week 7 closeout v1 的窗口定义是：
- **single-run matrix snapshot**；
- 只允许在**同硬件 / 同 profile / 同脚本版本**下做横比；
- 不把不同日期、不同缓存状态、不同 cargo 编译状态的数据直接拼一起讲。

## 4.3 strategy source 说明

统一使用：
- `default`
- `experiment`
- 或显式传入 `STRATEGY_SOURCE`

目的是防止默认路径与实验路径的数据被混成同一类结果。

---

## 5. 可复现命令（冻结版）

在 `trillionnium-rust/` 目录执行：

```bash
# 1) 生成 classic / mixed / hot-streak 回归矩阵
./scripts/run_bench_regression_matrix.sh

# 2) 从最新 regression csv 生成 closeout 统一产物
python3 ./scripts/render_benchmark_closeout.py

# 或 shell wrapper
./scripts/run_benchmark_closeout.sh
```

如果需要明确指定输入与输出：

```bash
python3 ./scripts/render_benchmark_closeout.py \
  --csv ./run/bench/bench-regression-matrix-20260306-160428.csv \
  --out-dir ./run/bench/closeout-week7-manual \
  --profile-id week7-e2e-closeout-v1 \
  --measurement-window "single-run matrix snapshot; compare only inside same hardware/profile" \
  --warmup-policy "cargo artifacts reused; no extra warmup beyond script defaults" \
  --target-tps 1000 5000 10000
```

---

## 6. 当前 closeout 能得出的审慎结论

基于现有 regression matrix 和统一 closeout 产物，可以稳定说：

1. **TRNM 已经有足够清晰的三档冲突画像**：classic / mixed / hot-streak；
2. **它们可以不再只停留在 micro bench 文本里**，而是已经被翻译成了系统预算语言：
   - `elapsed_ms_per_ktx`
   - `micro_scheduler_ceiling_tps`
   - `scheduler_window_share[target_tps]`
3. **这套桥接口径能直接接 E2E 插桩**：
   - 一旦补上 submit / mempool / consensus / commit / finality 时间戳，
   - 就能把 micro 与 system 数据放到同一份 closeout JSON 里。
4. **当前最重要的纪律**仍然是：
   - 不把 `micro_scheduler_ceiling_tps` 宣称为链级 TPS；
   - 不把 classic/mixed/hot-streak 说成业务真实流量本身；
   - 只把它们当成“系统负载画像模板 + scheduler 预算组件”。

---

## 7. Week 7 完成定义（Done Criteria）

本周 closeout 视为完成，当且仅当：

- [x] classic / mixed / hot-streak → system budget bridge 已定义；
- [x] 统一产物（JSON + MD）已落地；
- [x] 可复现命令已冻结；
- [x] 硬件 / 窗口 / strategy source 说明已写清；
- [x] E2E 后续要补的字段模板已冻结；
- [ ] 真实 E2E finality / submit / finalized TPS 数据待下一阶段链路插桩补齐。

---

## 8. 下一步最小增量（给 Week 8 / 后续 lane）

只建议做三件事：

1. **在 E2E 路径补时间戳**：submit / mempool / consensus / execution / commit / finality；
2. **把 E2E 结果写进同一 closeout JSON**，不要另起一套字段；
3. **每个 workload 至少跑一个固定窗口**（例如 10min），产出：
   - submit TPS
   - finalized TPS
   - finality P50/P95/P99
   - drop/retry rate
   - bottleneck segment

如果后续做对外对标，优先用这套统一 JSON 做 truth source，再生成对外表格/图，不要手工摘数字。

---

## 9. 关联实现与证据

- 新增脚本：`trillionnium-rust/scripts/render_benchmark_closeout.py`
- 新增 wrapper：`trillionnium-rust/scripts/run_benchmark_closeout.sh`
- 当前输入示例：`trillionnium-rust/run/bench/bench-regression-matrix-20260306-160428.csv`
- 当前输出示例：`trillionnium-rust/run/bench/closeout-20260310-070813/benchmark-closeout.{json,md}`

---

（完）
