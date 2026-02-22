# Trillionnium Rust L1 — BFT Industrial Readiness Checklist

> 目标：把“可运行/可验证”推进到“可生产运营”。

## 结论口径
- **当前阶段**：工程化强测试态（已有 hard gates、恢复与抗重放验证）。
- **生产准入**：需要满足下述 P0 全部通过，并连续观察窗口稳定。

---

## P0（必须）

### 1) 共识安全与活性门禁（CI 必开）
- [x] 4 节点共识冒烟：`check_bft_4node_smoke.sh`
- [x] WAL 重启恢复：`check_bft_restart_recovery.sh`
- [x] 消息认证与 anti-replay：`check_bft_message_auth.sh`
- [x] round-change + 恢复活性：`check_bft_round_change.sh`
- [x] fault matrix（baseline/slow/restart）：`run_consensus_fault_matrix.sh`

### 2) 数据一致性与执行安全
- [x] apply_error / rollback 零容忍（门禁内 hard fail）
- [x] v1 事件字段冻结检查
- [x] 事件重放顺序校验

### 3) 观测与追责
- [x] 共识指标输出：`finality_p50/p95`、`bft_round_change_total`、`bft_committed_heights`
- [ ] Prometheus/Grafana 面板与报警基线
- [ ] SLO 文档化（例如 p95 finality、recovery MTTR）

### 4) 运维演练
- [ ] 灰度升级与回滚 runbook
- [ ] 节点 crash/restart 演练（周级）
- [ ] 网络抖动/短分区演练（周级）

---

## P1（强烈建议）
- [ ] 7d 连续 soak test（固定硬件+固定参数）
- [ ] 公开测试网混沌场景报告（丢包、抖动、时钟偏移）
- [ ] 外部安全审计（共识/密码学/状态机）
- [ ] 关键路径容量报告（validators × tx load × block cadence）

---

## 推荐准入阈值（可调整）
- `apply_error_total == 0`
- `rollback_total == 0`
- `recovery_error_rate == 0`
- fault matrix 全场景 `status=PASS`
- 连续 N 次 nightly（建议 N>=7）无共识门禁失败

---

## 本周落地动作（已执行）
- merge gates/nightly 已纳入 `run_consensus_fault_matrix.sh` 作为 hard gate。
- 产物上传保留 `run/health/**`（便于回溯 fault matrix 细节日志）。
