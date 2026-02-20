# P3 Week1 Baseline（D1）

日期：2026-02-20  
阶段：P3 / Week1 / Day1

---

## 1) 执行命令

在 `trillionnium-rust/` 执行：

```bash
./scripts/run_bench_regression_matrix.sh
```

产物：

- `trillionnium-rust/run/bench/bench-regression-matrix-20260220-153109.csv`

---

## 2) 基线结果（TXS=20000）

### classic
- keys=2000: original=25ms, aggressive=62ms, **2.48x**
- keys=1000: original=25ms, aggressive=61ms, **2.44x**
- keys=500: original=25ms, aggressive=62ms, **2.48x**
- keys=200: original=25ms, aggressive=57ms, **2.28x**
- keys=100: original=25ms, aggressive=56ms, **2.24x**

### mixed
- keys=2000: original=37ms, aggressive=85ms, **2.30x**
- keys=1000: original=37ms, aggressive=84ms, **2.27x**
- keys=500: original=37ms, aggressive=84ms, **2.27x**
- keys=200: original=37ms, aggressive=85ms, **2.30x**
- keys=100: original=37ms, aggressive=85ms, **2.30x**

### hot-streak
- keys=2000: original=37ms, aggressive=87ms, **2.35x**
- keys=1000: original=37ms, aggressive=86ms, **2.32x**
- keys=500: original=37ms, aggressive=85ms, **2.30x**
- keys=200: original=37ms, aggressive=83ms, **2.24x**
- keys=100: original=37ms, aggressive=80ms, **2.16x**

---

## 3) 观察结论（D1）

1. Aggressive 在三类 workload、全 key 档位均显著慢于 Original（约 **2.16x ~ 2.48x**）。
2. `candidate_groups_scanned` 在 mixed 场景整体偏高（约 21k+），与当前慢路径特征一致。
3. 该 baseline 可作为 Week1 D2 指标扩展与 D3/D4 patch 验收对照组。

---

## 4) D2 输入

- 保持相同命令与参数口径（TXS/KEYS/workload/strategy 不变）
- 扩展 profile 汇总，重点拆解：
  - 每 tx 有效扫描命中率
  - ww/wr/rw 冲突检测检查量与命中率
  - 不同 workload 下扫描-收益比
