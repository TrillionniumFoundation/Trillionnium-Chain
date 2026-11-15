# 9cd 最终截止观察快照

观察时间：`2026-11-01T17:54:12.851272+00:00`。GitHub run：[41332206071](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41332206071)。

候选源码：`9cd91ed69a0c69df42f8d7812d32d271df6e1998`。Prospective merge：`a70f0165379156da436d1c0be403e1effd3912c0`。两者 tested tree 均为 `60a521c7299febfe26a8c7d38d3420d490d07cd8`。这份快照保留自己的源码与运行标签；原 3bbc 的完整 V2 成本证据保持原标签。

## 最终 job 与 artifact 状态

14 个 job 全部结束：8 个旧成本 job success、4 个 V2 job cancelled、2 个服务 job failure。最终 API 列出 10 个 artifact，未列出 V2 artifact。本快照只下载两份服务原始 ZIP；8 个旧成本 job 的成功状态来自保存的 API，未重新下载其成本材料。

四个取消的 V2 job 日志均可读取并已保存，均包含 runner shutdown；它们没有构成完成的 V2 成本测量，不能记为 PASS，也不能将取消解释为工作无效。

| V2 job | 维度 | 结果 | 日志 |
|---|---|---|---|
| 124924488792 | W1 complete legal strategies (v2, x64, prospective-merge) | cancelled；无 artifact | `job-124924488792.log` |
| 124924488812 | W1 complete legal strategies (v2, x64, head) | cancelled；无 artifact | `job-124924488812.log` |
| 124924488958 | W1 complete legal strategies (v2, arm64, head) | cancelled；无 artifact | `job-124924488958.log` |
| 124924488974 | W1 complete legal strategies (v2, arm64, prospective-merge) | cancelled；无 artifact | `job-124924488974.log` |

## 服务报告及 SQLite 读回

每个源码分别保留原固定包压力场景与 fresh-challenge 压力场景；每个场景有 baseline 和 pressure 两个阶段。原窗口仍为 4 秒，压力仍为 16 个 worker。下表的 active height 来自 ZIP 中保留的 SQLite 的只读查询；确认数来自同一报告，并对成功确认的 observed tip/height 与数据库相互核对。

| 源码/场景 | baseline 延迟（秒） | baseline 独立 active / 确认数 | pressure 接收端 active / ACK | pressure History 页 | pressure 独立已存非 genesis 块 | pressure 独立 active / 确认数 |
|---|---:|---|---|---:|---:|---|
| head / original | 1.893324759 | 7 / 1 | 7 / 7 | 3 | 2 | 0 / 0 |
| head / fresh | 1.819485570 | 7 / 1 | 7 / 7 | 2 | 1 | 0 / 0 |
| prospective-merge / original | 1.985205149 | 7 / 1 | 7 / 7 | 2 | 1 | 0 / 0 |
| prospective-merge / fresh | 1.983003985 | 7 / 1 | 7 / 7 | 2 | 1 | 0 / 0 |

四个 pressure 阶段都记录 `PUBLIC_REQUEST_DEADLINE`，独立客户端的 active tip 仍为 genesis，确认数为 0。已存入一至两个非 genesis 块不等于 active chain 已推进，也不等于客户端已经确认。四个 baseline 均达到 height 7、depth 6 的一次交易确认；这不是确定性终局。

两条服务 job 均为 failure。原固定包测试进程 exit 0，但其独立报告验收为 `CONFIRMATION_TARGET`；fresh 测试进程 exit 101，包装器记录 `FRESH_NATIVE_PROCESS_REQUIRED`。完整失败和原输出均保留在 ZIP 内，本快照不把其改写为成功。

## 核验范围

- 两份原始 ZIP 的大小与 SHA-256 同时匹配任务指定值和保存的 artifact API。
- ZIP 外层 source-before/source-after、manifest 内层来源和 expected source 一致；merge API 的有序父提交为原 base 后接 9cd candidate。
- 本次使用的报告和 SQLite 字节与 manifest 摘要一致。SQLite 以 `mode=ro&immutable=1` 加 `PRAGMA query_only=ON` 打开临时字节副本，仅执行 active/blocks 查询，临时副本随后删除。
- 没有重新执行 native 测试，也没有独立重算全部 ticket、transcript、签名或 State 关系。跨 run 的 baseline 时间不能作为配对优化效果。
- 这份较晚 9cd 快照不能替代、重标记原 3bbc 完整 V2 测量，也不能补成 9cd 的四条已取消 V2 测量。

`summary.json` 给出机器可读来源、job 结果和服务状态；`service-phase-observations.json` 保留逐阶段数据库查询结果；`INDEX.json` 对本快照全部文件（除索引自身）记录大小与 SHA-256。原 3bbc 已取消 runtime 中实际 18 个 History PASS 的独立回执仍保留在原 `related-ci` 中，不混作 9cd 测试结果。
