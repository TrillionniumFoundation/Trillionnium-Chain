# Upgrade / Migration 可执行 Checklist（P1-1）

> 用法：按顺序执行，逐项打勾。命令默认在仓库根目录执行。

## 0) 基线确认

- [ ] `git rev-parse --short HEAD`
- [ ] `./scripts/p0_merge_gate.sh`
- [ ] `./scripts/p1_negative_suite.sh`（要求：`fail=0`，关键 case 无 skip）
- [ ] 明确当前 profile：`dev-fast` 或 `prod-like`（必须写入发布记录）

## 1) 升级前快照

- [ ] 版本信息
```bash
./build/chaind version
```

- [ ] 参数快照
```bash
./build/chaind query workload params -o json --home ~/.chain --node tcp://127.0.0.1:26657 > data/upgrade-pre-params.json
```

- [ ] 状态快照
```bash
./build/chaind query workload list-task -o json --home ~/.chain --node tcp://127.0.0.1:26657 > data/upgrade-pre-task.json
./build/chaind query workload list-challenge -o json --home ~/.chain --node tcp://127.0.0.1:26657 > data/upgrade-pre-challenge.json
```

## 2) 备份

- [ ] 备份链目录
```bash
tar -czf data/backup-chain-$(date +%Y%m%d-%H%M%S).tgz ~/.chain
```

- [ ] 备份关键配置
```bash
cp ~/.chain/config/genesis.json data/genesis.backup.$(date +%Y%m%d-%H%M%S).json
```

## 3) 执行升级（模板）

- [ ] 停止旧进程
```bash
pkill -f "chaind start --home ~/.chain" || true
```

- [ ] 替换新二进制（按实际流程）
- [ ] 执行必要迁移脚本（如有）
- [ ] 启动新节点
```bash
./build/chaind start --home ~/.chain --minimum-gas-prices 0stake
```

## 4) 升级后验证

- [ ] 出块验证（高度持续增长）
- [ ] 参数对比（pre vs post）
- [ ] 关键查询可用
- [ ] 运行快照对比脚本并归档结果
```bash
./scripts/upgrade_snapshot_diff.sh
```

## 5) 回归测试

- [ ] `./scripts/p0_merge_gate.sh`
- [ ] `./scripts/p1_negative_suite.sh`
- [ ] 归档结果路径到发布记录

## 6) 回滚预案触发条件

- [ ] 节点无法稳定出块
- [ ] 关键交易路径不可用
- [ ] 状态一致性检查失败

若触发：立即停新版本、恢复备份、回滚二进制、复验链活性。
