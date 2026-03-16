# TRNM Node Split PR-1 Plan v0

- 状态：**Draft / first executable refactor slice**
- 上游文档：
  - `docs/development/TRNM_NODE_MODULE_SPLIT_PLAN_V0.md`
  - `docs/development/TRNM_HYBRID_REFERENCE_CRATE_ROADMAP_V0.md`
- 范围：只定义 **`trnm-node` 拆分第一刀（PR-1）**
- 目标：在**不改语义、不动协议边界、不碰 BFT/apply/rollback 逻辑**的前提下，把 `main.rs` 里最稳的一组类型和基础设施搬出去

> 本文的核心不是“长远上应该怎么拆”，而是：
>
> **如果今天真的要开第一个 refactor PR，第一步应该搬什么、怎么搬、搬完如何验证。**

---

## 1. PR-1 只做什么

PR-1 只处理以下 5 个子域：

1. `args.rs`
2. `config.rs`
3. `types.rs`
4. `wal.rs`
5. `recovery.rs`

也就是：

- CLI args / config
- 基础数据结构
- WAL / checkpoint I/O
- WAL metadata recovery

## 为什么只做这五块

因为这五块满足三个条件：

1. **边界清楚**
2. **对 live protocol 语义影响最小**
3. **和 apply / rollback / BFT / ordering 的耦合相对较低**

这意味着第一刀可以主要是：

> **搬文件 + 改 import + 跑 gate**

而不是：

> **搬文件的同时重做语义**

---

## 2. PR-1 明确不做什么

以下内容**不要放进 PR-1**：

- 不拆 `bft/`
- 不拆 `apply.rs`
- 不拆 `rollback.rs`
- 不拆 `timeout.rs`
- 不拆 `events.rs`
- 不拆 `preexec.rs`
- 不拆 `ordering.rs`
- 不迁 `#[cfg(test)]` tests
- 不改任何协议语义
- 不改日志字段/事件字段
- 不改 recovery / rollback 规则
- 不改 BFT 算法与 validator auth 逻辑

换句话说：

> PR-1 是结构 seam 建立，不是行为变更。 

---

## 3. PR-1 要迁移的具体符号

## 3.1 `args.rs`

### 搬走
- `Args`
- `WalDirMode`
- `DEFAULT_BFT_WAL_DIR`

### 保持不变
- 所有 `clap` 字段定义、默认值、注释

### 迁移后 `main.rs` 用法
```rust
mod args;
use args::{Args, WalDirMode, DEFAULT_BFT_WAL_DIR};
```

---

## 3.2 `config.rs`

### 搬走
- `NodeConfig`
- `load_config(path: &str) -> Result<NodeConfig>`

### 保持不变
- `toml::from_str` 行为
- 错误上下文字符串

### 迁移后 `main.rs` 用法
```rust
mod config;
use config::{load_config, NodeConfig};
```

---

## 3.3 `types.rs`

### 搬走
- `MockTx`
- `RoundStep`
- `VoteType`
- `BftVote`
- `SignedVote`
- `AuthRejectStats`
- `LeaderHealth`
- `BftJitterControl`
- `BftHeightResult`
- `HotObjectSummary`
- `ConsensusWal`
- `RecoveredWalState`
- `WalMetaList`
- `CheckpointMetaList`
- `DaBatch`
- `OrderingDecision`
- `RlAdviceContext`
- `RlAdvice`
- `LegacyMempoolDaProvider`
- `PreexecOrderingEngine`
- `DisabledRlAdvisor`
- `ShadowOnlyRlAdvisor`

### 注意
这一步虽然叫 `types.rs`，但允许把**与这些 struct/enum 强绑定的小 trait/impl** 也一起搬走；
但不要顺手把 `decide_order_for_commit(...)` 搬进去。

### 迁移后 `main.rs` 用法
```rust
mod types;
use types::{
    ArgsLikeMaybeNo, // 这里只是示意，实际不要重新命名
};
```

更现实的写法是：
```rust
use crate::types::{
    AuthRejectStats, BftHeightResult, BftJitterControl, BftVote, CheckpointMetaList,
    ConsensusWal, DaBatch, DisabledRlAdvisor, HotObjectSummary, LeaderHealth,
    LegacyMempoolDaProvider, MockTx, OrderingDecision, PreexecOrderingEngine,
    RecoveredWalState, RlAdvice, RlAdviceContext, RoundStep, ShadowOnlyRlAdvisor,
    SignedVote, VoteType, WalMetaList,
};
```

### 这一组搬完的收益
- `main.rs` 文件头先大幅瘦身
- BFT / ordering / rollback 等后续子模块都有公共类型落点

---

## 3.4 `wal.rs`

### 搬走
- `wal_file`
- `wal_dir_has_existing_state`
- `isolated_default_wal_dir`
- `resolve_wal_dir`
- `wal_meta_file`
- `checkpoint_file`
- `load_wal_meta_entries`
- `persist_wal_meta_entries`
- `load_checkpoint_meta`
- `persist_checkpoint_meta`
- `persist_consensus_wal`

### 依赖
会依赖：
- `Args`
- `WalDirMode`
- `ConsensusWal`
- `WalMeta`
- `CheckpointMeta`
- `WalMetaList`
- `CheckpointMetaList`

### 建议 import 组织
```rust
use crate::args::{Args, WalDirMode};
use crate::types::{CheckpointMetaList, ConsensusWal, WalMetaList};
use trnm_state::{CheckpointMeta, WalMeta};
```

### 注意
- `resolve_wal_dir(...)` 很适合放在 `wal.rs`，别挪去 `config.rs`
- 这块虽然和 runtime 关系强，但本身更像存储基础设施，不要和 recovery 混在一个文件

---

## 3.5 `recovery.rs`

### 搬走
- `recover_wal_state`
- `metadata_only_recovery_error`
- `ensure_recoverable_wal_state`

### 依赖
会依赖：
- `RecoveredWalState`
- `ConsensusWal`
- `load_wal_meta_entries`
- `load_checkpoint_meta`
- `verify_wal_and_find_checkpoint`

### 建议 import 组织
```rust
use crate::types::{ConsensusWal, RecoveredWalState};
use crate::wal::{load_checkpoint_meta, load_wal_meta_entries};
use trnm_state::verify_wal_and_find_checkpoint;
```

### 注意
- recovery 语义一行都不要改
- 错误消息也尽量保持原样，减少 test/ops 输出漂移

---

## 4. PR-1 新文件 skeleton

## 4.1 `src/main.rs` 头部期望长相（示意）

```rust
mod args;
mod config;
mod recovery;
mod types;
mod wal;

use args::{Args, WalDirMode, DEFAULT_BFT_WAL_DIR};
use config::{load_config, NodeConfig};
use recovery::{
    ensure_recoverable_wal_state, metadata_only_recovery_error, recover_wal_state,
};
use types::{
    AuthRejectStats, BftHeightResult, BftJitterControl, BftVote, CheckpointMetaList,
    ConsensusWal, DaBatch, DisabledRlAdvisor, HotObjectSummary, LeaderHealth,
    LegacyMempoolDaProvider, MockTx, OrderingDecision, PreexecOrderingEngine,
    RecoveredWalState, RlAdvice, RlAdviceContext, RoundStep, ShadowOnlyRlAdvisor,
    SignedVote, VoteType, WalMetaList,
};
use wal::{
    isolated_default_wal_dir, load_checkpoint_meta, load_wal_meta_entries,
    persist_checkpoint_meta, persist_consensus_wal, persist_wal_meta_entries,
    resolve_wal_dir, wal_dir_has_existing_state,
};
```

### 关键点
- 先别追求最优 import 美观
- 先让编译和测试保持绿
- 之后再做 import tidying

---

## 4.2 `src/args.rs` 最小骨架（示意）

```rust
use clap::{Parser, ValueEnum};

pub const DEFAULT_BFT_WAL_DIR: &str = "run/consensus-wal";

#[derive(Debug, Parser)]
#[command(...)]
pub struct Args { ... }

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum WalDirMode {
    Auto,
    Reuse,
    FailIfExists,
}
```

---

## 4.3 `src/config.rs` 最小骨架（示意）

```rust
use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
pub struct NodeConfig {
    pub node_id: String,
    pub rpc_addr: String,
    pub p2p_addr: String,
}

pub fn load_config(path: &str) -> Result<NodeConfig> { ... }
```

---

## 4.4 `src/types.rs` 最小骨架（示意）

```rust
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use trnm_types::Hash32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockTx { ... }

#[derive(Debug, Clone)]
pub struct BftVote { ... }

...
```

### 注意
- 如果某些 struct 当前只在本 crate 内部用，先全部 `pub(crate)` 即可
- 不要在 PR-1 顺手做“所有可见性最小化”工程，这会稀释目的

---

## 4.5 `src/wal.rs` 最小骨架（示意）

```rust
use anyhow::Result;
use std::path::{Path, PathBuf};
use crate::args::{Args, WalDirMode};
use crate::types::{CheckpointMetaList, ConsensusWal, WalMetaList};
use trnm_state::{CheckpointMeta, WalMeta};

pub fn wal_file(wal_dir: &Path) -> PathBuf { ... }
...
pub fn persist_consensus_wal(wal_dir: &Path, wal: &ConsensusWal) -> Result<()> { ... }
```

---

## 4.6 `src/recovery.rs` 最小骨架（示意）

```rust
use anyhow::Result;
use std::path::Path;
use crate::types::RecoveredWalState;
use crate::wal::{load_checkpoint_meta, load_wal_meta_entries};

pub fn recover_wal_state(wal_dir: &Path) -> Result<RecoveredWalState> { ... }
...
```

---

## 5. PR-1 迁移顺序（真正可执行）

## Step 1
新建空文件：
- `args.rs`
- `config.rs`
- `types.rs`
- `wal.rs`
- `recovery.rs`

并在 `main.rs` 头部加：
```rust
mod args;
mod config;
mod recovery;
mod types;
mod wal;
```

这一步先不删原定义，只验证模块 wiring 能编译。

### Gate
- `cargo check -p trnm-node`

---

## Step 2
迁移 `args.rs`：
- `Args`
- `WalDirMode`
- `DEFAULT_BFT_WAL_DIR`

删掉 `main.rs` 里对应定义，补 `use`。

### Gate
- `cargo test -p trnm-node -q`

---

## Step 3
迁移 `config.rs`：
- `NodeConfig`
- `load_config`

### Gate
- `cargo test -p trnm-node -q`

---

## Step 4
迁移 `types.rs`：
- 所有基础 struct/enum
- 不改行为代码

### Gate
- `cargo test -p trnm-node -q`
- `cargo test --workspace --all-targets`

### 为什么这里要加 workspace gate
因为很多 node tests + all-targets 会引用这些类型，最容易在这一步炸 import/path。

---

## Step 5
迁移 `wal.rs`

### Gate
- `cargo test -p trnm-node -q`
- 如果有 WAL / restart recovery 相关定点脚本，也要跑

---

## Step 6
迁移 `recovery.rs`

### Gate
- `cargo test -p trnm-node -q`
- `cargo test --workspace --all-targets`

---

## Step 7
收尾
- `cargo fmt`
- import 最小整理
- 确保 `main.rs` 头部没有旧定义残留

---

## 6. PR-1 需要特别小心的点

### 6.1 `DEFAULT_BFT_WAL_DIR`
它现在被 args 默认值直接引用。搬到 `args.rs` 后，避免再在 `main.rs` 定义第二份。

### 6.2 `WalMeta` / `CheckpointMeta`
它们不是 node 本地类型，来自 `trnm-state`。不要在 `types.rs` 里复制定义。

### 6.3 `RecoveredWalState`
这是 node 自有 recovery struct，应该留在 `types.rs`，不是 `wal.rs`。

### 6.4 RL advisor / DA provider
它们虽然看起来像行为对象，但当前第一刀先放 `types.rs`，别急着扔进 `ordering.rs`。
原因：
- PR-1 要尽量只做“符号搬家”
- 这些对象现在还没到行为分离阶段

### 6.5 `serde` derive
`WalMetaList` / `CheckpointMetaList` / `ConsensusWal` 这些 wrapper 很容易因为 derive/import 少一个而炸编译。第一刀时优先保守复制所有现有 derive。

---

## 7. PR-1 的完成标准

PR-1 完成，不看“拆了几个文件”，而看：

1. `main.rs` 去掉：
   - args/config/types/wal/recovery 的原始定义
2. 新增 5 个文件都被实际引用
3. `cargo test -p trnm-node -q` 通过
4. `cargo test --workspace --all-targets` 通过
5. 没有协议行为变化

---

## 8. PR-1 之后，下一刀接哪里

PR-1 成功后，下一刀建议接：

### PR-2
- `bft/model.rs`
- `bft/auth.rs`
- `bft/round.rs`
- `bft/height.rs`

### PR-3
- `events.rs`
- `apply.rs`
- `rollback.rs`
- `timeout.rs`

也就是说：

> **先拆“静态定义和基础设施”，再拆“活跃语义区”。**

---

## 9. 最终建议

如果下一步真的要开始改代码，不要上来就动 `apply_one()` 或 `main()` 主循环。

第一刀最稳的打法就是：

> **PR-1 只做 args/config/types/wal/recovery 的无语义搬迁。**

这一步完成后，`trnm-node` 的后续拆分才会进入“每刀都不会把整棵树一起震塌”的状态。
