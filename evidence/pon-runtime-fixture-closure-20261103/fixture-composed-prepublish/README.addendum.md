# Fixture 组合发布前证据补充草稿

快照时间：`2026-11-03T22:00:12.505361+00:00`。本目录是独立的发布前记录；后续终态应另行追加，保留本快照不变。

## 当前结论

最终 fixture 与 diagnostics 组合已完成 Cargo 构建、格式检查和严格 workspace / all-targets / all-features Clippy，退出码均为 0。选定 native 项为 **57 执行、56 通过、1 失败**；History 为 **25 通过、1 ignored**。本组合的完整 **974 项仍为 PENDING**，本快照只包含该运行的原始计划，没有读取或复制增长中的日志，也没有记录或预报终态计数。

新 fixture 的 `prepared_forks_keep_original_public_cpu_after_listener_join_and_restart` 命名控制在正式 Cargo 生成的 evaluation ELF 上真实通过，完整调用 wall 为 **215700123 ns**。同轮 paid pinned-peer 和 DAG negative 控制通过；marker 入口因真实原始 kernel 检查返回 101，保留为预期拒绝。这些有限本地控制不构成原 real-Host runtime 或服务性能通过。

唯一选定失败是 `guarded_npq6_submit_recovers_after_invalid_signature_and_independent_process_restart`：独立 witness 子进程在 ready 前退出，原始日志包含 `Os code 1 / PermissionDenied / Operation not permitted`。原始失败、退出码、reader 拒绝及全部日志保持不变。

## 精确身份

| 对象 | SHA256 |
|---|---|
| native manifest，1190 路径 | `545222b5d1baa03ca3403375170c30416b8351fdc570e5d994603c3fb2fcaa82` |
| Node libtest ELF | `34bd6631d69e093be42a35e89ce3d989d60f7cee4f7eb75d1c0f0527c43d7acf` |
| evaluation ELF | `bcfe5421a5c189f0756fb2be274c576b0b3ce127d5582c1f66f49c281af0ff21` |

Base commit 为 `8ebded733d90bf74e7d8e3adbd2458ad8b572159`。native before / after / final manifest 原字节一致，打包时 1190 个当前 native 路径逐件匹配。ELF 身份来自原 Cargo artifact 记录及选定运行的 unchanged 检查；本打包步骤没有重新执行、复制或重新散列 ELF。完整工作树的提交后 CI 资格仍须由后续精确提交证据绑定。

先前 diagnostics-only 的完整 974 项结果 **950 通过 / 1 失败 / 23 ignored**属于 manifest `22cd64ab...`、ELF `a937d88d...`。当前组合是 manifest `545222b5...`、ELF `34bd6631...`，前次计数没有移植到当前组合。

## 文件与验证

- [source-bound-summary.json](source-bound-summary.json)：精确来源、已完成范围、失败与 PENDING 边界。
- [native-source-manifest.json](native-source-manifest.json)：一份完整的原始 1190 路径 manifest。
- [completed-records.json.gz](completed-records.json.gz)：原 build / selected receipts 与日志、驱动和 reader、原选择器定义、当前完整运行 plan 的无损字节包。gzip mtime 为 0；重复 manifest 和空文件按 SHA256 去重，原路径逐项保留。
- [artifact-index.json](artifact-index.json)：本目录其余文件的字节数和 SHA256。
- [verification.json](verification.json)：原文件稳定性、receipt / log 匹配、解压逐字节回读及 scope 检查。
- [verify_bundle.py](verify_bundle.py)：只读核验目录和包内每项，不运行 native，也不写入源代码。

运行 `python3 verify_bundle.py` 可校验目录内容。包内 `entries` 的每个路径引用 `blobs` 中原始 bytes 的 base64 内容；反解后与原字节数和 SHA256 完全一致。`phase.json` 仅是构建驱动最后启动阶段的历史记录；build/fmt/Clippy 是否完成以各 terminal receipt 和 verification 为准。顶层 driver 仍等待完整 registry 子进程，本目录没有声称整个 driver 已结束。

本快照未提高原 budget，没有把 EPERM 或 marker 拒绝改为成功，也没有 service 提速、原 4 秒 / F0 / campaign 闭合或生产激活声明。
