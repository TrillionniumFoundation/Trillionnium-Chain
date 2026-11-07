# 历史复用控制：SQLite 计数修正与实际适用范围

**状态：修正待执行验证。** 本说明保留 `9e50ca8e1ce655ef2f4686bd0ab58120b30c4632` 的实际失败结果。下文冷、热计数是根据固定 SQLite 源码写入的精确测试预期；只有新源构建、运行后才能登记为实测通过。生产代码的引用固定在该提交，本次修正只改 `history_tests.rs`。

## 可纳入验收说明的正文

ROG 的 release/default-features 语义控制实际执行了全部 80 项，结果为 **79 通过、1 失败**。唯一失败是 `writes_restoration_and_prepare_only_schema_changes_disable_completed_history`，native exit 为 101，原验收 reader exit 为 1。原始失败必须保留；这个组件执行也不能替代 workflow 原 test profile 或 PQ/all-features 验收。

失败发生在 CREATE/DROP 后第一次历史校验的 SQL 计数断言：实际 `RUN=[3,3,0,3,2]`，旧预期为 `[2,2,0,2,1]`。固定 SQLite 3.51.3 在旧 VM 的 `OP_Init` 增加 RUN，随后发现 schema cookie 改变，重新准备、reset 并执行同一语句。因此这里多出来的是 VM 执行尝试。`SQLITE_STMTSTATUS_RUN` 不是逻辑查询数或行读取数。原失败位置后的禁用断言尚未执行，不能仅凭原日志宣称那些断言已经通过。

修正保留原始 RUN，并独立读取 `SQLITE_STMTSTATUS_REPREPARE`。五列始终依次是：native state record、block、parent block、delta rows、genesis snapshot。

| 场景 | 校验轮次 | 精确 RUN 预期 | 精确 REPREPARE 预期 |
| --- | --- | --- | --- |
| CREATE 后 DROP，旧 VM 尚未执行 | 第一次，冷 schema | `[3,3,0,3,2]` | `[1,1,0,1,1]` |
| 同一 CREATE/DROP 场景 | 第二次，热 schema | `[2,2,0,2,1]` | `[0,0,0,0,0]` |
| no-row write、先修改后恢复原 bytes、prepare-only writable_schema | 各自两次 | `[2,2,0,2,1]` | `[0,0,0,0,0]` |

测试没有在 DDL 后清缓存或预热语句，也没有把 RUN 减去 REPREPARE 来抹平差异：SQLite 还存在在进入 VM 前就发现 expired 并重新准备的路径，不能假定每次 REPREPARE 都额外增加一次 RUN。

每次负例还独立要求：`history_hits == 0`、所有 history receipt 槽为空、`scope.enabled == false`；与原始无 scope 全历史 verifier 相比，实际 progress 回调数完全相同，现有 `account_graph` 阶段观察器记录的完整账户图验证调用数恰好增加 1。原完整 fallback 和 genesis 验证没有放松。修正不更改生产历史算法、事务/写入/schema 失效规则、认证根、错误与取消边界、SLO 或任何工作预算。

## 这项生产历史复用实际覆盖什么

它复用的是**同一次原写事务内，已经完整验证到 genesis 的后缀**。最多只有 child、genesis、已经验证的 child parent、原 Node reader 提名的 active tip 四个名额。scope 在最后一次 account/record 写入之后创建；它绑定原连接、原 writer、无新写入 epoch、原 schema 和同一不可变 `Settings` 借用。成功标记不由 Node 长期持有，不跨事务、COMMIT、rollback、cold open 或另一连接存活。[scope 与四个名额](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback.rs#L86-L118)；[创建边界](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback.rs#L126-L192)。

首次生成 receipt 前仍须走完所有祖先，检查 record/block/delta/height，以及 genesis snapshot 的规范编码、与 `Settings.initial` 的相等性和原 state/account graph 验证。命中也先重读并验证当前 starting record/block/delta，检查高度和 scope，再保留末次 progress 与 scope fence。第五个未提名 block 即便走到已有 receipt 的祖先，仍完整遍历；写入发生在首次消费前则转原完整 verifier，消费后的改动由外层 fence 拒绝，早退错误也检查事务替换。[完整历史与命中顺序](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store/native_authenticated.rs#L807-L901)；[匹配/生成条件](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback.rs#L273-L328)；[失效与外层拒绝](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback.rs#L195-L230)；[错误也检查原事务](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback.rs#L412-L428)。

实际收益候选是同一 admission/append/reorg 读回过程中重复做的后缀遍历及它引出的 genesis 检查。成功复用省去已验证后缀的实际工作和对应中途 progress，不伪造旧遍历次数的进度事件。每次实际保留的 record/delta、入口、出口和外层 fence 仍执行。普通 admission 已把同一 scope 传给发布后的 parent/child/active 读回，但此事实并不证明公网 SLO 或 TPS 改善。[普通发布到提交前的接线](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store.rs#L4942-L5030)；[reorg 同事务读回](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store.rs#L5635-L5743)。

## 仍保留的完整读取、构造与验证

| 路径 | 源码上仍然存在的成本和边界 |
| --- | --- |
| 每个新 scope 的首次历史验证；未提名对象；失效后的校验 | 从 starting record 走到 genesis，逐项验证记录、区块、delta 和高度；receipt 不能跨事务消掉首次全链工作。[历史算法](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store/native_authenticated.rs#L807-L901)。 |
| 普通 `read_active` 及 active precommit | 实际从 `kv` 读取整个 slot，解析、检查规范状态；公开 `read_active_with_progress` 传 `None`。即使内部读回持有 scope，当前完整 State 和 commitment 比较仍在 graph 复用前执行。[slot 完整 SQL 读取](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store.rs#L2956-L3032)；[公开 read_active](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store.rs#L3332-L3407)；[先比较完整 commitment](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store/native_authenticated.rs#L674-L747)。 |
| 普通 `state_at` 历史查询 | 公开入口传 `None`，寻找实际 snapshot，解析/校验完整 State；无 snapshot 时倒走路径后逐个应用 delta、验证完整 commitment 和账户图。当前 snapshot 加速器与其保留策略继续使用。[state_at 与逐块回放](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store.rs#L3685-L3805)。 |
| 完整 commitment 算术 | 既有缓存按当前完整规范输入比较；命中可省重复算术，不能把当前输入扫描或实际 SQL 读取变成常数。miss 继续解析 accounts、构造完整非账户分区并检查 roots/aggregates/conservation。[完整输入缓存合同](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store/native_authenticated/arithmetic_cache.rs#L193-L251)；[完整参考计算](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/account_archive_execution/state_witness.rs#L731-L767)；[非账户分区](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/account_archive_execution/state_witness.rs#L508-L514)。 |
| cold open 与恢复 | 非 Growth cold open 显式 `read_active`、完整 `verify_history_with_cache`、replay/outbox/budget 验证、recover 后再次读回。`recover` 既有 continuous/mining unchanged 检查另有合同，本次 receipt 没有改动，也不能借此宣称所有 recover 都做同一数量的工作。[cold open](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store.rs#L2115-L2142)；[recover](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store.rs#L6256-L6330)。 |
| 基于 observed time 的历史检查 | `check_observed_history_with_progress` 仍沿祖先至 genesis 检查时间；历史 receipt 不提供可复用时钟结论。[observed-time 祖先遍历](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store.rs#L6256-L6330)。 |
| Growth V2 / PQ | `PermanentAccountGrowthV2` 是另一个明确分流的后端，普通完整 State 接口对它拒绝使用；此次 AuthenticatedV1 receipt 不等于 Growth 全面贯通。新增 12 项 history 控制使用 classical fixture；PQ 仍须其自身 all-features/provider、普通入口和必需控制的实际证据。[后端分流](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store.rs#L2115-L2142)；[完整 State 入口限制](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e50ca8e1ce655ef2f4686bd0ab58120b30c4632/trillionnium/crates/trnm-pon-node/src/store.rs#L3332-L3407)。 |

因此可登记的是一次同写事务内重复验证的有界消除，以及这次测试计数语义的修正；还不能登记为“普通热路径已无完整状态/历史成本”或可信生产 TPS 结论。

## 证据与复现标识

- 原失败日志：`history-counter-original-9e50/72-trnm-pon-node-writes_restoration_and_prepare_only_schema_changes_disable_completed_history.log`，SHA256 `387b580ce112895d615536f4ca2fd43dd3a25a08882d05b2558672db18e0f7cc`。同目录保留 reader、执行 receipt 与恢复 receipt。
- 修正文件 git blob：`80b35db4e9b26256e5aebbd1ddc26c15360fa792`；SHA256 `8140b17233097d4eb78b9de0314307a829004af9fbf5e624ed4dc3317ebd36aa`。修正不改变 12 个测试名或原 80 项清单。
- 精确补丁：`history-sqlite-reprepare-counter-fix.patch`，SHA256 `58ff0a7031d8d26462d003a19cad08d957181c5235c56b6a87ff926340193147`。
- SQLite 固定源码：`libsqlite3-sys-0.37.0/sqlite3/sqlite3.c`，SHA256 `9512509b1bccb7461f79bea8aad6280ae4699e925fa4804381b71f59e7efb0c5`；`SQLITE_SOURCE_ID = 2026-03-13 10:38:09 737ae4a34738ffa0c3ff7f9bb18df914dd1cad163f28fd6b6e114a344fe6d618`。精确主源码锚点：RUN 文档 9477–9487、保留计数/增加 REPREPARE 86958–86985、expired 的 VM 前拒绝 93173–93195、schema 重试 93325–93359、schema cookie 检查 99471–99506、OP_Init/RUN 104295–104364、prepare-time PRAGMA 与执行时 OP_Expire 143744–143785。
- 八段原文、完整来源路径/哈希、恢复证据、预期值与未执行状态：`history-sqlite-reprepare-counter-fix.json`，SHA256 `7f6a39efd59bb2d59267e4a55797603ace7b0eb7773def8be2bd194263068c51`。
- 全部生产源码锚点与逐段原文：`history-counter-correction-source-anchors.json`，SHA256 `e7e7068f4f6e8bad87bb7df155e6b7f27a9ea6c15cce7e9c6ba4e2894ac6b2e6`。19 段均核对当前生产源码与上述冻结提交字节相同。

已完成的验证限于 preflight、Rust 1.95 file-only rustfmt、diff 检查和独立源码审查。新源的失败项复验、完整 Node 及原 workflow 资格须由后续真实执行记录补充；本说明不预写通过结果。
