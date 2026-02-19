# Rust L1 仓库重构方案（Day-1 可执行）

日期：2026-02-19

## 目标
建立最小可扩展 monorepo 结构，支持：
- 节点进程
- 执行引擎
- 状态机模块
- 网络/共识适配层
- 基准测试与 e2e

## 建议目录

```text
trillionnium-rust/
  Cargo.toml (workspace)
  crates/
    trnm-node/              # 节点入口（二进制）
    trnm-consensus/         # 共识适配层（先接成熟实现）
    trnm-executor/          # 并发执行器（调度+冲突检测）
    trnm-state/             # 状态存储 + state root
    trnm-types/             # 共享类型（tx/object/hash）
    trnm-pouw/              # PoUW 状态机逻辑
    trnm-mempool/           # 交易池与打包策略
    trnm-rpc/               # RPC / gRPC 接口
    trnm-bench/             # 压测与基准
  scripts/
    devnet_up.sh            # 一键拉起3节点
    devnet_down.sh
    run_pouw_e2e.sh
    run_bench.sh
  configs/
    node1.toml
    node2.toml
    node3.toml
  docs/
    protocol/
    runbooks/
```

## Day-1 最小创建清单

1. 初始化 workspace + 8 个 crates（node/types/state/pouw/executor/mempool/rpc/bench）
2. `trnm-types` 定义 ObjectRef/Tx/Hash 基本结构
3. `trnm-pouw` 建立状态枚举与转移接口（先空实现）
4. `trnm-executor` 建立 read/write set 冲突检测器原型
5. `trnm-node` 打印启动参数并加载配置（占位）

## 分支建议

- 新分支：`feat/rust-l1-week1`
- 每天一里程碑 tag：`rust-l1-d1` ... `rust-l1-d7`
