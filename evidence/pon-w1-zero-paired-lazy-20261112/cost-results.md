# W1 zero paired × winner-only proof：当前源码原生组件观察

本节的数值来自 source `165d286b687e0a73d7fe68148d2179274fc0c0b8` 的正式六格 campaign manifest 数字摘录。独立分析验证了每格五个固定策略的实际计数、每臂八项 cohort 成本和赢家数之和，以及下表所有比值的整数分数。摘录不是完整 reader receipt；它没有 sample id，因此这里不声称独立认证跨臂逐样本配对身份。原始 reader/campaign 的完整性验证由其原始收据承载。

**本次四个成本格中，预登记的 `full-limb-sparse-lazy` 均具有五个已测固定策略里最低的 aggregate CPU 和 wall 每接受赢家成本。`zero-paired-lazy` 没有表现出更低的计时成本。** 这不证明任何策略在所有合法算法中最优；尤其不能把专用核的 152,832 次标量乘法计数直接解释为时间加速或攻击者成本下界。

## 成本口径与范围

每个表项等于同一 target、同一 horizon、同一固定策略的完整 producer 成本之和，除以接受赢家数之和。Producer 成本包括付费准备、所有真实命中/未命中尝试、失败 proof 的处置、cleanup 和 teardown。Audit/evidence 与 verifier 计时分列；search/cohort 等包含式时钟不相加。 Audit、verifier 与 producer 在同一进程中运行；分开计时仍不能消除 cache、allocator 或后续性能影响。这里也不把 pre-header material 构造、源码核验和构建费用重新归入该 producer 组件口径。

T0 为 `0x7f…ff`，T1 为 `0x07…ff`；只有在独立均匀 ticket 模型下，它们分别对应 p=1/2 和 p=1/32。H1/H8 是每次准备的搜索次数，horizon 之间含相关前缀，因此不池化。每臂每格有八个 cohort；括号中的范围仅是这八项 cohort 各自每赢家成本的最小值至最大值，没有置信区间或独立样本推断；这些范围也不能当作纯计时噪声的分布。

## 四个成本格

单位：毫秒 / 接受赢家。CPU、wall 均为 ratio-of-sums；范围来自单个 cohort。

| Target | H | 固定策略 | CPU ms/赢家 | Wall ms/赢家 | 八 cohort CPU 范围 | 八 cohort wall 范围 |
|---|---:|---|---:|---:|---:|---:|
| T0 | 1 | `full-limb-sparse-eager` | 2.017292 | 2.022982 | 1.187554–5.114603 | 1.191632–5.124345 |
| T0 | 1 | `full-limb-sparse-lazy` | 1.973125 | 1.978518 | 1.201385–4.922988 | 1.205470–4.931901 |
| T0 | 1 | `zero-paired-legacy` | 2.164616 | 2.169791 | 1.402388–5.251399 | 1.406179–5.260011 |
| T0 | 1 | `zero-paired-eager` | 2.133688 | 2.139792 | 1.281941–5.351126 | 1.285675–5.359922 |
| T0 | 1 | `zero-paired-lazy` | 2.143376 | 2.148661 | 1.276219–5.236977 | 1.280037–5.245687 |
| T0 | 8 | `full-limb-sparse-eager` | 2.467306 | 2.473526 | 1.871965–4.113341 | 1.875750–4.121854 |
| T0 | 8 | `full-limb-sparse-lazy` | 2.414077 | 2.419570 | 1.885309–3.664018 | 1.889062–3.673633 |
| T0 | 8 | `zero-paired-legacy` | 2.637589 | 2.643901 | 2.091159–4.020448 | 2.094986–4.028103 |
| T0 | 8 | `zero-paired-eager` | 2.673938 | 2.678449 | 2.070821–3.761866 | 2.074438–3.767565 |
| T0 | 8 | `zero-paired-lazy` | 2.646782 | 2.651590 | 2.114609–3.750285 | 2.118318–3.756111 |
| T1 | 1 | `full-limb-sparse-eager` | 52.572307 | 52.648454 | 11.324405–102.737212 | 11.341878–102.885053 |
| T1 | 1 | `full-limb-sparse-lazy` | 51.437078 | 51.512632 | 11.485555–98.267962 | 11.504096–98.404210 |
| T1 | 1 | `zero-paired-legacy` | 56.592507 | 56.672929 | 12.976614–103.877728 | 13.058027–104.005182 |
| T1 | 1 | `zero-paired-eager` | 56.659024 | 56.748192 | 12.214800–105.031065 | 12.232093–105.168651 |
| T1 | 1 | `zero-paired-lazy` | 56.326995 | 56.397523 | 12.026124–104.251765 | 12.042917–104.375580 |
| T1 | 8 | `full-limb-sparse-eager` | 40.583794 | 40.647993 | 23.575140–62.780484 | 23.614847–62.876933 |
| T1 | 8 | `full-limb-sparse-lazy` | 40.004135 | 40.065571 | 23.132296–62.945726 | 23.165878–63.039417 |
| T1 | 8 | `zero-paired-legacy` | 44.962674 | 45.025074 | 25.916074–70.981592 | 25.950302–71.078669 |
| T1 | 8 | `zero-paired-eager` | 44.795093 | 44.858415 | 26.256122–71.416475 | 26.291106–71.521473 |
| T1 | 8 | `zero-paired-lazy` | 44.701399 | 44.762684 | 25.740274–70.680511 | 25.776269–70.777486 |

## 预先固定的比较

下表均为“reference 每赢家成本 / `zero-paired-lazy` 每赢家成本”；大于 1 仅表示当前观察中 `zero-paired-lazy` 成本较低。没有逐样本挑选最快算法。

| Target | H | Reference | CPU 比值 | Wall 比值 |
|---|---:|---|---:|---:|
| T0 | 1 | `zero-paired-legacy` | 1.009910 | 1.009834 |
| T0 | 1 | `zero-paired-eager` | 0.995480 | 0.995872 |
| T0 | 1 | `full-limb-sparse-lazy` | 0.920569 | 0.920814 |
| T0 | 8 | `zero-paired-legacy` | 0.996527 | 0.997100 |
| T0 | 8 | `zero-paired-eager` | 1.010260 | 1.010129 |
| T0 | 8 | `full-limb-sparse-lazy` | 0.912080 | 0.912498 |
| T1 | 1 | `zero-paired-legacy` | 1.004714 | 1.004883 |
| T1 | 1 | `zero-paired-eager` | 1.005895 | 1.006218 |
| T1 | 1 | `full-limb-sparse-lazy` | 0.913187 | 0.913385 |
| T1 | 8 | `zero-paired-legacy` | 1.005845 | 1.005862 |
| T1 | 8 | `zero-paired-eager` | 1.002096 | 1.002139 |
| T1 | 8 | `full-limb-sparse-lazy` | 0.894919 | 0.895066 |

在这四格中，`zero-paired-lazy` 相对 `zero-paired-legacy` 的 aggregate CPU 比值为 0.996527–1.009910，相对 `zero-paired-eager` 为 0.995480–1.010260，方向并不完全一致。八个 cohort 的描述性观察不足以把约 ±1% 的差异宣称为统计稳定的优势。与 `full-limb-sparse-lazy` 相比，后者/zero-lazy 的 CPU 比值为 0.894919–0.920569、wall 比值为 0.895066–0.920814；同一个固定 full-limb lazy 实现在四格里均更低。

## 实际尝试、物化与控制

下表尝试/命中/未命中是**每个 arm**的实际计数；五臂的这些计数一致。Eager 三臂指 full-limb-sparse-eager、zero-paired-legacy、zero-paired-eager；lazy 两臂只在命中时物化完整 proof。

| 格子 | 每臂 attempts | 每臂 hits | 每臂 misses | 每个 eager 臂物化数 | 每个 lazy 臂物化数 | 全格 setup calls |
|---|---:|---:|---:|---:|---:|---:|
| T0/H1 | 12 | 8 | 4 | 12 | 8 | 40 |
| T0/H8 | 120 | 64 | 56 | 120 | 64 | 40 |
| T1/H1 | 324 | 8 | 316 | 324 | 8 | 40 |
| T1/H8 | 2080 | 64 | 2016 | 2080 | 64 | 40 |
| T2/H1 exhaustion-control | 24 | 0 | 24 | 24 | 0 | 40 |
| T3/H1 first-hit-control | 8 | 8 | 0 | 8 | 8 | 40 |

六格合计 240 cohorts、240 setup calls、800 searches、12,840 attempts、760 hits、12,080 misses、40 exhausted searches、8,008 份完整物化 proof、3,280 次 verifier 调用。所有数值均与各 arm 求和一致。摘录仅给出每格 setup_calls，本文不把缺失的每臂 setup_calls 字段重新构造为独立观察。

Exhaustion-control 为 0 赢家，每赢家成本保持 null；first-hit-control 验证首个尝试命中的行为。两类控制不作为成本样本，不与四个成本格池化。

## 结论边界

结果只覆盖该主机、该二进制、该零材料、这些固定策略与开发 target 下的组件观察。它支持“成本基线必须允许合法零材料、专用实现、付费准备与不构造失败 proof”的审计要求，也表明实际最快实现必须测量，不能按 FLOPs 或标量乘法次数指定。它没有证明 ticket 独立均匀、全部合法策略的最小成本、GPU/ASIC 成本、跨矿工或跨时期复用、真实任务经济需求、赞助自流量、重复奖励约束、维护任务成本或生产安全。

`cheapest_strategy_proven=false`；`production_activation=false`；该独立数值分析的 `source_execution_authenticated=false`。所有操作计数与计时结果保持各自口径。

## 身份

- Source commit: `165d286b687e0a73d7fe68148d2179274fc0c0b8`
- Source tree: `2eb4f5e888a7a02f573d72a2fdf4d5a7cfc352e0`
- Manifest: 403,864 bytes；SHA256 `1972cd517095034d809b48f509b53dd0d51d24f1b5d37a71bdd0e7c91a5373f6`
- Native binary SHA256: `106475d07ddd75e0eced90b19ec84a7658732951a207bebd764c37f10a1aace1`
- 本地数字摘录 SHA256: `d3826d35aa254d441a14315ef24319eea926d0de0c80104f4ab06a841ebf831c`
