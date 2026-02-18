# Trillionnium 主网前参数表（锁定草案）

> 原则：先给 Alpha 推荐区间，先跑数据，再在 Testnet 冻结。

## 1) 核心经济参数
| 参数 | 含义 | Alpha 推荐 | 调整依据 |
|---|---|---:|---|
| `min_worker_stake` | Worker 最低质押 | 100,000 TRNM | 与任务平均 bounty、作恶收益比值对齐 |
| `max_slash_ratio` | 单次最大惩罚比例 | 50% | 对恶意行为形成显著威慑 |
| `base_inflation` | 年化基础通胀 | 4% | 早期网络激励底盘 |
| `max_inflation` | 年化上限通胀 | 10% | 防止激励失控 |
| `fee_burn_ratio` | 手续费燃烧比例 | 100%（任务费） | 与通缩叙事一致 |

## 2) 任务执行参数
| 参数 | 含义 | Alpha 推荐 | 风险提示 |
|---|---|---:|---|
| `task_deadline_blocks` | 任务截止高度 | 300~1200 blocks | 太短影响成功率，太长拖慢资金周转 |
| `challenge_window_blocks` | 挑战窗口 | 100~600 blocks | 太短漏检，太长影响 finality |
| `max_task_compute_sec` | 单任务最大执行秒数 | 30~300s | 防止资源滥用 |
| `max_task_memory_mb` | 单任务内存上限 | 512~4096MB | 避免 OOM 干扰共识重放 |

## 3) 解质押与安全参数
| 参数 | 含义 | Alpha 推荐 | 说明 |
|---|---|---:|---|
| `unbonding_period_blocks` | 解质押冷却期 | 10,000~50,000 blocks | 覆盖争议发现与追责窗口 |
| `max_unbonding_extension` | 延长冷却上限 | 20% of base | 仅 authority 可触发 |
| `min_remaining_stake_after_slash` | 惩罚后最低剩余质押 | >= min stake 的 20% 或按实现 | 防止瞬时归零导致状态异常 |

## 4) 建议的 Slash Curve（草案）
- `轻微违规（超时/低质量）`: 1%~5%
- `可疑结果（一次挑战成功）`: 10%~20%
- `明确恶意（伪造/重复作恶）`: 30%~50%

> 备注：建议引入“近期违规次数”因子，形成递增惩罚曲线。

## 5) 主网前必须锁定的 8 个参数
1. `min_worker_stake`
2. `max_slash_ratio`
3. `challenge_window_blocks`
4. `unbonding_period_blocks`
5. `task_deadline_blocks`
6. `max_task_compute_sec`
7. `fee_burn_ratio`
8. `inflation_range`（base/max）

## 6) 参数冻结流程（建议）
1. **Alpha 周**：使用推荐区间，记录 5 场景测试数据。
2. **Testnet 第 1 周**：按实际成功率/挑战率收敛参数。
3. **Testnet 第 2 周**：冻结候选参数，仅允许安全修正。
4. **Mainnet 前**：发布参数变更报告 + 风险说明。

## 7) 数据驱动阈值（执行建议）
- 任务成功率 < 95%：延长 deadline 或放宽资源上限
- 挑战成功率 > 10%：提高验证强度并增大恶意惩罚
- 频繁超时 > 15%：下调任务复杂度上限或提高最低 bounty

---

## 结论
当前建议保持“高质押 + 强惩罚 + 有限挑战窗口 + 可观测事件”四件套，
先确保安全性与可验证性，再优化吞吐与用户体验。
