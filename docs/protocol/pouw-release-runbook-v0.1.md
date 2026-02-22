# PoUW Release Runbook & Rollback（v0.1）

状态：Draft-for-ops  
适用：Trillionnium Rust L1 + Agent/User PhaseA + Proof gate

## 0. 发布前硬条件（全部满足才可 GO）

1. `cargo test` 全绿。
2. one-shot 门禁全绿：
   - consensus security matrix PASS
   - proof smoke/tamper PASS
   - phaseA gate PASS
3. 最近一次冷启动演练 PASS。
4. 最近一次脏状态恢复演练 PASS。
5. 最近一次重启恢复演练 PASS。

## 1. 标准发布步骤

在仓库根目录执行：

```bash
cd trillionnium-rust
cargo test
./scripts/run_phasea_security_oneshot.sh
```

通过后记录证据目录（脚本会打印 run_root）。

建议写入发布记录：
- commit hash
- run_root
- consensus summary 路径
- proof-gate.log 路径
- agent-user-phasea gate 报告路径

## 2. 健康检查命令（运行期）

### 2.1 共识安全矩阵
```bash
./scripts/run_consensus_security_matrix.sh
```
检查：`status=PASS`。

### 2.2 PhaseA 门禁
```bash
./scripts/run_agent_user_phasea_gate.sh
```
检查：
- `status=COMMIT_QUEUED`
- `verifier_status=accepted`
- `status=PASS`

### 2.3 One-shot（推荐）
```bash
./scripts/run_phasea_security_oneshot.sh
```
检查：`[one-shot][OK] all gates passed`

## 3. 故障分级与处置

### P0（阻断发布）
- 共识安全矩阵失败
- proof tamper 测试异常通过（说明校验失效）
- phaseA gate 无法到达 `COMMIT_QUEUED`

动作：
1) 立刻停止发布。  
2) 保留 run_root 全量日志。  
3) 回滚到上一稳定 tag/commit。  
4) 修复后重新跑 one-shot。

### P1（可条件发布）
- 单项非关键波动（例如耗时上升但仍 PASS）

动作：
- 记录风险与阈值；允许 CONDITIONAL GO；需 24h 复测。

## 4. 回滚手册（最小可执行）

### 4.1 代码回滚
```bash
# 在仓库根目录
 git checkout main
 git pull --ff-only
 git log --oneline -n 20
 # 选择上一稳定 commit/tag
 git checkout <stable_commit_or_tag>
```

### 4.2 运行态清理（避免脏状态干扰）
```bash
cd trillionnium-rust
rm -rf run/consensus-wal run/message-gateway
mkdir -p run/message-gateway
```

### 4.3 回滚后验证
```bash
cargo test
./scripts/run_phasea_security_oneshot.sh
```
必须再次全绿才允许继续对外宣布恢复完成。

## 5. 证据留存规范

每次发布/回滚都保存：
- `run/health/gate-oneshot-<ts>/`
- 发布或回滚使用的 commit hash
- 触发人与时间（Asia/Shanghai）

建议将路径与摘要附到 PR/Release Notes。

## 6. 本次演练基线（2026-02-22）

- 冷启动演练 PASS：`run/health/drill-cold-start-20260222-160015/summary.txt`
- 脏状态恢复 PASS：`run/health/drill-dirty-recovery-20260222-160118/summary.txt`
- 重启恢复 PASS：`run/health/drill-restart-recovery-20260222-160218/summary.txt`
- 强制中断恢复补充 PASS：`run/health/drill-restart-interrupt-fix-20260222-160301/`
