# SQLite journal 清理：提交源码上的有限验证记录

实现提交：[`0f6598454b0d743259579e7e193b1158e5c9353d`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/0f6598454b0d743259579e7e193b1158e5c9353d)；tree `b3cab76d5cf4321d94a6b8c64f578717d749c83e`；父提交 `44330b91eb552fd20ef6f2e69bf5e6f1e8f5c0b0`。本目录只新增执行记录，未改实现文件、注册 pins 或旧证据。

`committed-source/local-binding.json` 保留 fetch、远端 commit/tree、本地 write-tree 一致性及 `update-ref` 绑定过程。补齐原提交文件后，仓库自带 `verify_ci_source.py` 在有限检查前后均验证相同提交、相同 tree 和全部 11775 个 tracked entries（1120464907 bytes）；工作树 clean，未以 sparse/skip-worktree 豁免检查。原始身份输出见 `committed-source/source-before-identity.json` 与 `committed-source/source-after-identity.json`。

## 此次执行结果

| 检查 | 结果 | 范围 |
| --- | --- | --- |
| SQLite cleanup | 4 / 4 | 真实 SQLite 初始化异常、commit、body rollback、延迟约束导致 commit 失败；三个 PRAGMA 失败是同一测试的子用例 |
| Dependency register controls | 42 / 42 | 注册表解析与来源约束 |
| CI source controls | 43 / 43 | 源码身份验证器控制 |
| CI contract controls | 109 / 109 | CI 命令、lane、缺失/重复/跳过等约束 |
| Corpus controls | 55 / 55 | 证据来源与 corpus 结构约束 |
| 实际 dependency / CI / corpus checker | 全部 return code 0 | 分别仍为 HOLD、结构检查通过、HOLD_NO_GO；不提升资格 |
| Preflight / diff-check | 通过 | 26 packages，remote policy 未改；diff 比较实现与父提交 |

上述是普通资源/事务和来源/CI 结构检查。未重跑原生根恢复套件、攻击或压力 campaign、完整 repository-truth/protocol-contract lanes、完整 Cargo graph/lockfile/retained tests、strict Clippy/formatting、全库 Markdown links，以及当前 prospective merge/hosted mandatory gates。没有关闭 P0、授予生产权限或认证全链资格，也未将本 #837 基础的结果转记为 #835 整合验收。

## 保留的失败与中断

`working-tree/` 完整保留此前工作树观察。初次 CI/corpus 检查因 sparse checkout 缺少原有 fuzz lockfile 或 pinned evidence 失败，失败日志未覆盖；补齐输入后的结果另存。环境中断的三项旧执行只有 `UNRECORDED_COMPLETION`，不推断成功。部分恢复留下的零字节文件与 index lock 副本、原文件恢复身份、锁清理依据均保留。历史 42/42 和 hosted 0/3 未改写。

`committed-source/` 为实现提交上的新一轮记录，含 argv、时间、返回码与日志 SHA-256；`driver/` 是外部执行包装器副本。日志中的绝对路径保留原观察值，同目录归档副本按文件名对应。

首次归档目录创建曾因 overlay 空间耗尽失败，见 `committed-source/archive-copy-failure.json`。在 source-after 已通过之后，按本任务协调恢复源码子树的 sparse checkout，回收原提交历史工作副本；保留 Git objects、十个实现文件和全部 repo 外日志。回收过程观察到可用空间增加 1,109,262,336 bytes，见 `committed-source/materialization-recovery.json`。之后的 sparse 状态不声称已经通过 canonical source verifier；前后两份 PASS 只对应此前完整 materialization。

**本证据目录在执行后才生成，不属于执行前或执行后的已验证实现 tree。** 后续保存证据的提交不能冒充上述被测实现提交；本目录也不声称其自身已经通过全套 mandatory gates。
