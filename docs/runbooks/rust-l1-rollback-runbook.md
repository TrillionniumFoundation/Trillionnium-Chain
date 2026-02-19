# Rust L1 回滚手册（Week-1）

日期：2026-02-19
范围：Rust L1 MVP 测试网失败时，快速切回 Go/Cosmos 主线。

## 触发条件（任一满足即回滚）

1. 连续停块或频繁分叉（>10 分钟无法稳定出块）
2. 关键状态机错误（任务状态跳转非法、commit/reveal 校验异常）
3. 回放不一致（同输入不同 state root）
4. 性能明显不达标且出现错误积压

## 回滚原则

- Rust L1 Week-1 仅作为新测试网，不覆盖现有 Go 主链环境
- Go/Cosmos 链保持可随时启动
- 回滚优先恢复服务可用性，事后再做根因分析

## 回滚步骤

1. 停止 Rust devnet
```bash
cd trillionnium-rust
./scripts/devnet_down.sh
```

2. 记录失败证据（必须）
```bash
mkdir -p run/rollback-evidence
cp -R run run/rollback-evidence/run-$(date +%Y%m%d-%H%M%S)
```

3. 启动 Go/Cosmos 主线
```bash
cd ..
./build/chaind start --home ~/.chain --minimum-gas-prices 0stake
```

4. 快速健康检查
```bash
curl -sf http://127.0.0.1:26657/status >/dev/null && echo OK
```

5. 执行门禁回归（P0/P1）
```bash
./scripts/p0_merge_gate.sh
WITH_RUST_VERIFY=1 ./scripts/p1_negative_suite.sh
```

## 回滚后报告模板

- 回滚时间：
- 触发条件：
- 影响范围：
- 恢复时间（RTO）：
- 丢失风险（RPO）：
- 根因初判：
- 后续修复 owner / ETA：
