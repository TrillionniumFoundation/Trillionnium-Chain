# OpenClaw 运维微运行手册（并发 / 限流切换 / 告警收口）

> 适用范围：`TrillionniumChain` 自动迭代流程（lane 并发子任务 + 告警策略链路）。
> 
> 原则：每轮只做一个可回滚微补丁，先验证后提交，失败立即回滚。

## 1) 子任务并发（避免重入与抢占）

### 运行前检查
```bash
cd TrillionniumChain
[ -f .auto-iterate.lock ] && echo "LOCKED" || echo "UNLOCKED"
```

- `LOCKED`：已有实例在跑，禁止重复拉起。
- `UNLOCKED`：可启动新一轮。

### 并发安全基线
- 单机同一仓库只允许一个 daemon 进程写入（依赖 `.auto-iterate.lock`）。
- lane 侧如需并发，只并发“读/分析”，写操作必须串行落地（提交阶段单线程）。
- 若出现重复执行迹象，优先检查：
  1. `.auto-iterate.lock` 是否残留
  2. `run/auto-iterate/daemon.log` 是否存在多 PID 交错

---

## 2) 限流切换（rate-limit mode switch）

### 切换策略
- 正常模式：lane cadence 保持 5m，summary 每 1h。
- 触发条件：连续 2 轮出现 rate-limit / upstream error。
- 限流模式：
  - lane cadence 暂不变（避免吞吐塌陷）
  - summary 降频到 3h，并在摘要首行写明 `RATE_LIMIT_MODE=ON`

### 操作步骤（人工兜底）
```bash
cd TrillionniumChain
# 1) 观察近期失败与重试
 tail -n 80 run/auto-iterate/daemon.log

# 2) 标记进入降噪观察（可与 supervisor prompt 同步）
 echo "$(date '+%F %T') RATE_LIMIT_MODE=ON" >> run/auto-iterate/round.log
```

### 退出条件
- 最近连续 2 个 summary 周期未再出现 rate-limit/error。
- 退出时补记：`RATE_LIMIT_MODE=OFF`。

---

## 3) 告警收口（single funnel）

目标：同一故障不在多个通道重复放大，统一收口到 PR7 delivery state + dead-letter 审计。

### 快速核对
```bash
cd TrillionniumChain
python3 scripts/v2/pr7_alert_delivery.py --help >/dev/null
python3 scripts/v2/p11_policy_rollback_guard.py --help >/dev/null
```

### 收口检查（建议每轮末尾）
```bash
cd TrillionniumChain
python3 scripts/v2/p11_policy_rollback_guard.py \
  --state-file run/pr7-alert-delivery/state.json \
  --dead-letter-file run/pr7-alert-delivery/dead-letter.jsonl \
  --audit-file run/pr7-alert-delivery/audit.jsonl \
  --out run/pr11/policy-rollback-guard.txt
```

- 若输出 `NO_GO`：暂停策略推进，优先处理 dead-letter。
- 若输出 `CONDITIONAL_GO`：允许继续，但必须在下一轮摘要明确风险项。

---

## 4) 本微补丁验证命令

```bash
cd /Users/qianqi/.openclaw/workspace/TrillionniumChain
# 文档存在且关键段落齐全
grep -n "子任务并发\|限流切换\|告警收口\|本微补丁验证命令" docs/development/OPENCLAW_OPS_MICRO_RUNBOOK.md

# 告警链路关键脚本可执行（help 级）
python3 scripts/v2/pr7_alert_delivery.py --help >/dev/null
python3 scripts/v2/p11_policy_rollback_guard.py --help >/dev/null
```

## 5) 回滚说明

如需撤销本次变更：

```bash
cd /Users/qianqi/.openclaw/workspace/TrillionniumChain
git revert --no-edit HEAD
# 若尚未推送，也可用：git reset --hard HEAD~1
```

回滚后复验：

```bash
test ! -f docs/development/OPENCLAW_OPS_MICRO_RUNBOOK.md && echo "rollback ok"
```
