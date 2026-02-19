# Trillionnium Upgrade / Migration v1 (Draft Skeleton)

更新日期：2026-02-19
状态：Draft (P1-1)

## 1. 目标与范围

本文定义从当前链版本升级到下一版本时的标准流程，覆盖：
- 协议升级（链二进制、模块逻辑、参数）
- 数据迁移（状态字段、兼容映射）
- 回滚与应急处理

不覆盖：
- 跨链桥迁移
- 钱包 UI 细节迁移

## 2. 版本矩阵（首版）

- From: `v0.2.x`（当前 PoUW v0.2 主线）  
- To: `v0.3.0`（迁移治理与参数基线版本）  
- Upgrade Height: `治理提案确定（TBD）`
- 破坏性变更：
  - 关闭 legacy submit-result（`allow_legacy_submit_result: true -> false`，已在代码默认值执行）
  - challenge 相关参数在 dev/prod-like profile 区分管理

## 3. 迁移原则

1) 先冻结接口，再迁移实现（先文档、后代码）。  
2) 所有迁移必须可回放（脚本化、可复验）。  
3) 升级前必须满足 gate：
   - `scripts/p0_merge_gate.sh` 通过
   - `scripts/p1_negative_suite.sh` 结果满足 `fail=0`（关键 case 无 skip）

## 4. 预检查（Preflight）

### 4.1 环境
- [ ] 记录当前 commit hash
- [ ] 记录当前 `chaind version`
- [ ] 记录当前链参数快照（`workload params`）
- [ ] 记录关键状态快照（task/challenge/worker/unbonding 统计）

### 4.2 业务安全
- [ ] 无进行中的高风险治理提案
- [ ] 无待处理 challenge 裁决阻塞
- [ ] worker 侧已完成停机窗口通知

## 5. 迁移步骤（Runbook Skeleton）

### Step A: 冻结窗口
1. 宣布维护窗口（开始/预计恢复时间）
2. 停止新任务写入入口（应用层开关）

### Step B: 备份
1. 导出状态快照（genesis/export）
2. 备份节点数据目录
3. 备份配置（`config.toml`/`app.toml`/keyring）

### Step C: 执行升级
1. 部署新二进制
2. 设置 upgrade height / 参数迁移脚本
3. 重启并等待过升级高度

### Step D: 迁移后校验
1. 基础活性：出块、RPC、query 可用
2. 功能活性：PoUW 基础链路抽样检查
3. 回归：执行 P0/P1 套件

## 6. 参数迁移策略（首版草案）

当前链上参数（基线）
- workload_denom: `utrnm`
- challenge_window_blocks: `100`
- challenge_deposit: `1000000`
- challenger_slash_percent: `10`
- worker_slash_percent_on_bad_result: `20`
- reveal_window_blocks: `50`
- allow_legacy_submit_result: `false`

| Param | Old | New(v0.3.0 目标) | 策略 | 风险 |
|---|---:|---:|---|---|
| challenge_deposit | 1000000 | prod-like: 1000000 / dev-fast: 10000 | profile 化，不在同一环境混用 | 挑战门槛误判 |
| reveal_window_blocks | 50 | 50 | 保持不变 | 低 |
| challenge_window_blocks | 100 | 100 | 保持不变 | 低 |
| worker_slash_percent_on_bad_result | 20 | 20 | 保持不变（后续治理再调） | 中 |
| challenger_slash_percent | 10 | 10 | 保持不变 | 低 |
| allow_legacy_submit_result | false | false | 已完成切换（维持关闭） | 兼容路径退役风险 |

## 7. 数据迁移策略（模板）

- Task 状态字段兼容：`<TBD>`
- Challenge 结构兼容：`<TBD>`
- Legacy submit-result 兼容与退役：`<TBD>`

## 8. 回滚策略

触发条件（任一满足）：
- 连续 N 个块无法产出
- 关键交易路径不可用（create/accept/commit/reveal）
- 状态一致性检查失败

回滚动作：
1. 停止新版本节点
2. 恢复备份数据与旧二进制
3. 验证恢复链活性
4. 发布回滚公告与复盘工单

## 9. 验收标准（DoD）

- [ ] 升级 runbook 可单人执行
- [ ] 参数迁移表完整
- [ ] 回滚演练至少 1 次并有记录
- [ ] P0/P1 gate 全通过（按当期规则）

## 10. 治理提案模板（已补齐）

- 模板文件：`docs/protocol/governance-upgrade-proposal-template-v0.3.0.md`
- 包含内容：
  - upgrade 提案元信息模板
  - 参数变更 JSON 模板
  - gate 验收门槛
  - rollback 条件与计划
  - 投票与证据清单

## 11. 关联文档（双向链接已建立）

- 运维主手册：`docs/OPERATIONS.md`
- 升级执行清单：`docs/UPGRADE_MIGRATION_CHECKLIST.md`
- 治理提案模板：`docs/protocol/governance-upgrade-proposal-template-v0.3.0.md`

## 12. 待补清单（P1-1）

- [x] 补齐版本矩阵（from/to/height）
- [x] 补齐参数迁移表（首版数值）
- [x] 增加一键检查脚本（pre/post 快照 diff）：`scripts/upgrade_snapshot_diff.sh`
- [x] 与 `docs/OPERATIONS.md` 双向链接
