# TRNM vs Solana vs Sui 并发架构对比说明（对外审阅版）

> 日期：2026-03-05（2026-03-10 口径复核）  
> 范围：并发执行/冲突处理架构对比；TRNM 采用仓内最新 bench 证据（classic / mixed / hot-streak）  
> 基线：当前仓库 `main` 快照 `0b209289`；本文是**对外对标口径文档**，不承担 release-ready 判定。  
> 说明：本文不改业务代码，仅做证据归纳与路线建议。

---

## 0. 结论先行（Executive Summary）

> 入口约定：
> - 当前发布/就绪真相源：`RELEASE_READINESS.md`
> - 当前并发瓶颈图与 8 周路线：`docs/reports/TRNM_CONCURRENCY_BOTTLENECK_MAP_AND_8W_ROADMAP_2026-03-10.md`
> - 本文只回答“TRNM 相对 Solana / Sui 现在处在什么位置、该怎么说”，不回答“今天能不能发布”。

1. **TRNM 当前微基准（micro-bench）在高冲突场景下可稳定完成分组，耗时集中在 33–46ms（20k tx）区间**，表现出“冲突越高、组数越多，但耗时并未线性恶化”的特征。  
2. **策略层（original / aggressive-greedy / footprint-desc / hot-bucket-interleave）在最新数据中收益不显著，甚至部分策略退化**：
   - 最新回归矩阵中 `aggressive-greedy` 对 `original` 的差异：classic 平均 **+0.6ms**，mixed **+2.6ms**，hot-streak **-0.8ms**（基本同级）。
   - 历史完整策略对比中，`hot-bucket-interleave` 在 mixed 反而约 **+7~8ms** 慢于 original。
3. **TRNM 的优势**在于“可解释的冲突画像 + 稳定分组基线 + 可复现实验链路”；**短板**在于“尚未形成端到端 TPS（含共识/网络/持久化）口径闭环”，因此与 Solana/Sui 的公开 TPS 不能直接同表比较。  
4. **4 周追平路线**建议聚焦三件事：
   - 建立 E2E TPS 基准面（P50/P95/P99、最终性延迟、回滚/重试率）；
   - 将 scheduler 优化从“策略名义切换”升级为“冲突画像驱动 + 自适应”；
   - 对齐 Solana/Sui 对外可讲述口径：声明测试环境、负载模型、资源配置、统计窗口。

---

## 1. 仓内最新 bench 汇总（classic / mixed / hot-streak）

### 1.1 最新基线证据

- `trillionnium/run/bench/bench-matrix-20260305-032018.txt`（classic，txs=5000）
- `trillionnium/run/bench/bench-mixed-matrix-20260305-032031.txt`（mixed，txs=5000，read_fanout=3）
- `trillionnium/run/bench/bench-regression-matrix-20260304-200728.csv`（classic/mixed/hot-streak，txs=20000，strategy 对比）
- `trillionnium/run/bench/bench-strategy-compare-20260219-211113.txt`（完整策略横比）
- `trillionnium/run/bench/hot-bucket-sweep-20260220-235524.txt`（hot-streak 桶参数 sweep）

### 1.2 20k 回归矩阵（最新）要点

来自：`bench-regression-matrix-20260304-200728.csv`

- **classic**：groups 从 10（keys=2000）到 200（keys=100），elapsed_ms 33–35。  
- **mixed**：groups 从 41（keys=2000）到 669（keys=100），elapsed_ms 34–46。  
- **hot-streak**：groups 从 579（keys=2000）到 6002（keys=100），elapsed_ms 35–46。  

解读：
- workload 从 classic → mixed → hot-streak，冲突形态逐步恶化，**组数显著上升**；
- 但 elapsed 并未同比例爆炸，说明当前分组实现对冲突增长有一定韧性；
- 不同 strategy 的耗时差在该批次里接近噪声级（见下一节）。

### 1.3 策略对比结论（最新 + 历史完整）

#### A) 最新回归矩阵（20260304）
`aggressive-greedy - original`（ms）：
- classic：min -1 / max +2 / avg **+0.6**
- mixed：min -1 / max +12 / avg **+2.6**
- hot-streak：min -1 / max 0 / avg **-0.8**

结论：**没有形成稳定优势策略**；aggressive-greedy 在 mixed 场景有退化风险。

#### B) 历史完整策略横比（20260219，mixed, txs=20000）
- `footprint-desc` 基本与 `original` 持平（0~+1ms）。
- `hot-bucket-interleave` 稳定慢于 `original`（约 +7~8ms）。

#### C) hot-bucket 参数 sweep（20260220，hot-streak, txs=10000, keys=256）
- baseline `original`: **26ms**
- `hot-bucket-interleave`（buckets=8/12/16）: **29ms / 29ms / 29ms**

结论：当前 hot-bucket 方案在该热点模型下**未体现收益**。

---

## 2. micro-bench 与 end-to-end TPS 口径差异（必须分开讲）

## 2.1 micro-bench（当前证据主力）

当前 bench 数据测的是：
- 给定 tx 集合下的并发分组/冲突处理；
- 输出 `groups`、`elapsed_ms`、`conflict_hit_rate` 等内核指标；
- **不包含**完整网络传播、共识轮次、打包提交、落盘、最终性等待等系统成本。

因此它回答的问题是：
- “调度器/冲突检测本身快不快、稳不稳？”
- 而不是“链在真实网络下最终能跑多少 TPS？”

## 2.2 end-to-end TPS（对外对标必须口径）

E2E TPS 至少应包含：
- 入口流量（提交速率、突发形态）
- mempool 排队与丢弃/重试
- 共识 + 执行 + 存储全链路
- 最终性定义（soft/firm/final）
- 延迟分位（P50/P95/P99）与持续时长（如 10/30/60 分钟）

简式定义：
- **Micro Throughput** ≈ `tx_count / scheduler_elapsed`（仅执行内核）
- **E2E TPS** ≈ `最终确认 tx 数 / 观测窗口`（系统全链路）

> 结论：**micro 快 ≠ E2E TPS 一定高**。若缺少共识/网络维度，不能直接与 Solana/Sui 公布数据对比。

---

## 3. TRNM vs Solana vs Sui：并发架构层面对比

## 3.1 Solana（Sealevel 路径）

- 核心思路：交易预声明账户访问集合，调度器据此并行执行，冲突账户串行化。
- 优点：并发执行路径成熟、工程化强、吞吐展示能力高。
- 代价：调度公平性/局部热点抖动与账户锁竞争治理复杂，真实场景性能对负载形状敏感。

## 3.2 Sui（对象模型 + 因果分流）

- 核心思路：以对象（Object）为并发单元；无共享对象冲突的交易可走更快路径，共享对象走共识路径。
- 优点：天然降低冲突域，局部并发友好；“简单交易快路径”叙事清晰。
- 代价：开发模型与对象生命周期管理更复杂；共享对象热点仍会回落到更重路径。

## 3.3 TRNM（当前阶段）

- 核心思路：基于读写集冲突检测分组，已有多种策略（original/aggressive/footprint/hot-bucket）与可观测指标。
- 优点：
  1) 冲突画像清晰（classic/mixed/hot-streak）；
  2) 实验脚本与结果可复现；
  3) 在高冲突组数增长下耗时保持稳定区间。
- 短板：
  1) 策略优化收益尚不稳定；
  2) 缺少统一 E2E TPS 口径，难以对外“同口径对标”；
  3) 目前证据更偏执行内核，系统级瓶颈定位能力不足（网络/共识/存储耦合尚未量化）。

---

## 4. TRNM 当前优势 / 短板 / 4 周追平路线

## 4.1 当前优势

1. **基线稳定**：在 20k tx 回归中，classic/mixed/hot-streak 耗时均在 33–46ms 区间。  
2. **冲突建模能力强**：可通过 keys、write_every、read_fanout、workload 快速构造压力画像。  
3. **工程可复现**：已有 matrix/sweep/strategy 对照脚本与批量输出产物。

## 4.2 当前短板

1. **策略收益不确定**：替代策略多数仅与 baseline 持平或退化。  
2. **对外口径不足**：缺乏可持续更新的 E2E TPS 看板（含延迟分位与最终性）。  
3. **跨链对标叙事缺口**：尚不能回答“同等硬件/同等负载下，TRNM 到底落后多少、差在哪一段链路”。

## 4.3 4 周追平路线（文档与评测口径优先）

### Week 1：口径冻结 + 基线补齐
- 冻结 E2E 指标定义：submit TPS、final TPS、P95/P99 finality、drop/retry rate。
- 输出统一 benchmark profile（硬件/节点数/网络延迟/窗口长度）。
- 将当前 micro-bench 指标映射到 E2E 看板字段（避免双语义）。

### Week 2：链路插桩 + 首版 E2E 基线
- 在提交、入池、共识提案、执行、提交确认点打时间戳。
- 跑 classic/mixed/hot-streak 三档 E2E 压测，生成第一版对外可读图表。
- 识别 top-2 瓶颈段（例如共识轮次等待、存储 flush）。

### Week 3：针对性优化验证（不追求大改架构）
- 仅做“低风险高收益”优化：队列批处理、冲突缓存命中、热键分区策略自适应阈值。
- 每项优化必须给出 A/B：micro 改善 + E2E 改善（两者都要有）。

### Week 4：对外对标封版
- 形成 TRNM vs Solana vs Sui 的**同口径对标表**（明确“不可比项”注释）。
- 给出“当前差距区间 + 下一阶段目标区间”（例如 final TPS、P99 finality）。
- 产出可复审材料包：原始日志、脚本、汇总图、版本哈希。

---

## 5. 对外沟通建议（避免误导）

1. 不直接用 micro-bench 的 `tx/elapsed_ms` 宣称链级 TPS。  
2. 明确区分：
   - 执行内核能力（scheduler/executor）
   - 系统吞吐能力（consensus+network+storage）
3. 对 Solana/Sui 使用“架构机制对比 + 口径声明”，避免单数字 PK。

---

## 附录 A：可复现命令（本报告使用/建议）

> 在 `trillionnium/` 目录执行

```bash
# 1) classic matrix（micro）
TXS=5000 ./scripts/run_bench_matrix.sh

# 2) mixed matrix（micro）
TXS=5000 READ_FANOUT=3 ./scripts/run_bench_mixed_matrix.sh

# 3) strategy compare（mixed, 20k）
TXS=20000 ./scripts/run_bench_strategy_compare.sh

# 4) 回归矩阵（含 classic/mixed/hot-streak + strategy）
./scripts/run_bench_regression_matrix.sh

# 5) hot bucket sweep（hot-streak）
./scripts/run_hot_bucket_sweep.sh
```

### 报告内统计（示例脚本）

```bash
python3 - <<'PY'
import csv
f='run/bench/bench-regression-matrix-20260304-200728.csv'
rows=list(csv.DictReader(open(f)))
for wl in ['classic','mixed','hot-streak']:
    ds=[]
    for k in {r['keys'] for r in rows if r['workload']==wl}:
        o=[r for r in rows if r['workload']==wl and r['keys']==k and r['strategy']=='original'][0]
        a=[r for r in rows if r['workload']==wl and r['keys']==k and r['strategy']=='aggressive-greedy'][0]
        ds.append(int(a['elapsed_ms'])-int(o['elapsed_ms']))
    print(wl, 'avg_delta_ms=', sum(ds)/len(ds), 'min=', min(ds), 'max=', max(ds))
PY
```

---

## 附录 B：证据文件索引

- `trillionnium/run/bench/bench-matrix-20260305-032018.txt`
- `trillionnium/run/bench/bench-mixed-matrix-20260305-032031.txt`
- `trillionnium/run/bench/bench-regression-matrix-20260304-200728.csv`
- `trillionnium/run/bench/bench-strategy-compare-20260219-211113.txt`（完整策略对照）
- `trillionnium/run/bench/bench-strategy-compare-20260305-113531.txt`（最新但未跑完，文件末尾截断）
- `trillionnium/run/bench/hot-bucket-sweep-20260220-235524.txt`

---

（完）
