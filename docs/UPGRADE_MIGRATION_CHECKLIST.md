# Upgrade / Migration 可执行 Checklist（P1-1）

> 目标：把升级从“文档”变成“可演练、可回滚、可审计”的标准流程。
> 约定：所有命令在仓库根目录执行；每一步产物写入 `data/upgrade-runs/<ts>/`。

---

## Run Metadata（先填）

- [ ] run_id：`YYYYMMDD-HHMMSS`
- [ ] 环境：`dev-fast` / `prod-like`
- [ ] 操作人：
- [ ] 目标版本（git sha）：
- [ ] 是否 dry-run：`yes/no`

建议初始化目录：

```bash
RUN_ID=$(date +%Y%m%d-%H%M%S)
RUN_DIR="data/upgrade-runs/$RUN_ID"
mkdir -p "$RUN_DIR"
```

---

## 0) Go/No-Go 基线门槛

- [ ] 当前分支干净：`git status --short`
- [ ] 记录版本：`git rev-parse --short HEAD | tee "$RUN_DIR/pre.sha"`
- [ ] `./scripts/p0_merge_gate.sh`
- [ ] `./scripts/p1_negative_suite.sh`（要求：`fail=0`；关键 case 不允许 `skip`）
- [ ] 将两份 summary 路径写入 `$RUN_DIR/pre-gate.txt`

> 任一失败 = **No-Go**（停止升级）

---

## 1) 升级前快照（Pre Snapshot）

- [ ] 版本快照

```bash
./build/chaind version | tee "$RUN_DIR/pre.version.txt"
```

- [ ] 参数快照

```bash
./build/chaind query workload params -o json --home ~/.chain --node tcp://127.0.0.1:26657 > "$RUN_DIR/pre.params.json"
```

- [ ] 状态快照

```bash
./build/chaind query workload list-task -o json --home ~/.chain --node tcp://127.0.0.1:26657 > "$RUN_DIR/pre.task.json"
./build/chaind query workload list-challenge -o json --home ~/.chain --node tcp://127.0.0.1:26657 > "$RUN_DIR/pre.challenge.json"
```

- [ ] 节点活性快照（高度/时间）

```bash
./build/chaind status 2>/dev/null | jq '{height:.SyncInfo.latest_block_height,time:.SyncInfo.latest_block_time}' > "$RUN_DIR/pre.liveness.json"
```

---

## 2) 备份（Rollback 必需品）

- [ ] 链数据备份

```bash
tar -czf "$RUN_DIR/backup.chain.tgz" ~/.chain
```

- [ ] genesis 备份

```bash
cp ~/.chain/config/genesis.json "$RUN_DIR/backup.genesis.json"
```

- [ ] 二进制备份（若存在）

```bash
cp ./build/chaind "$RUN_DIR/backup.chaind" || true
```

---

## 3) 执行升级（Execution）

- [ ] 停止旧进程

```bash
pkill -f "chaind start --home ~/.chain" || true
```

- [ ] 替换新二进制（记录来源）
- [ ] 执行迁移脚本（如有）
- [ ] 启动新节点

```bash
./build/chaind start --home ~/.chain --minimum-gas-prices 0stake
```

---

## 4) 升级后验证（Post Check）

- [ ] 出块恢复（连续增长）
- [ ] 版本快照

```bash
./build/chaind version | tee "$RUN_DIR/post.version.txt"
```

- [ ] post 参数/状态快照

```bash
./build/chaind query workload params -o json --home ~/.chain --node tcp://127.0.0.1:26657 > "$RUN_DIR/post.params.json"
./build/chaind query workload list-task -o json --home ~/.chain --node tcp://127.0.0.1:26657 > "$RUN_DIR/post.task.json"
./build/chaind query workload list-challenge -o json --home ~/.chain --node tcp://127.0.0.1:26657 > "$RUN_DIR/post.challenge.json"
```

- [ ] 快照差异

```bash
./scripts/upgrade_snapshot_diff.sh | tee "$RUN_DIR/snapshot.diff.txt"
```

---

## 5) 升级后回归（Gate Re-run）

- [ ] `./scripts/p0_merge_gate.sh`
- [ ] `./scripts/p1_negative_suite.sh`
- [ ] 写入 `post-gate` 结果到 `$RUN_DIR/post-gate.txt`

> 任一失败 = **触发回滚评估**

---

## 6) 回滚触发条件（明确化）

满足任一条件立即回滚：

- [ ] 节点 5 分钟内无法稳定出块
- [ ] workload 关键查询不可用（params/task/challenge）
- [ ] P0/P1 gate 任一失败
- [ ] 状态一致性检查失败（快照 diff 出现不可接受差异）

回滚步骤：

1. 停新进程
2. 恢复备份（`~/.chain` + 二进制）
3. 启动旧版本
4. 复验活性 + gate

---

## 7) 发布记录（审计留痕）

- [ ] 记录最终结论：`GO / NO-GO / ROLLBACK`
- [ ] 附 run 目录：`$RUN_DIR`
- [ ] 附 git sha、操作人、时间窗口
- [ ] 将结果摘要同步到 `STATUS.md`
