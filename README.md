# H5DF followup evidence — 2026-11-14

本归档保存 PR #847 外部 head 变为 H5DF 之后的一组明确闭合证据。它是 data-only 审计归档，不是可运行的源码发布或合并结果。

## 固定身份

- H5DF source：`5df7ae6f482157c5f7fdcbcd52222117a965053f`，tree `6be4940d38cc88782657f2684cbefe48866f8b9f`。[固定源码](https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/5df7ae6f482157c5f7fdcbcd52222117a965053f)
- 对照 R1 source：`2a86462a1ab20c68151719ba4635e3c294391e64`，tree `5c26776f96f15fd131e85a5c2d7c5e895ad7fab4`。[R1 固定源码](https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/2a86462a1ab20c68151719ba4635e3c294391e64)
- 之前已发布的 R1 诊断归档：`ffc6e0ca4bfa7794ab6031a6e398dcd08b7a1982`。[原归档](https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/ffc6e0ca4bfa7794ab6031a6e398dcd08b7a1982)。该原归档不包含本次 H5DF followup。
- R1 stage1 诊断控制 commit：`78985d9a36761cf3ab370796f72f9b587776880c`，tree `b9999aa69ef7e148ea0760942f9b2bca6a8e6d6e`。该控制的 subject 是 R1，不是 H5DF native 测量。

拟归档 commit 的三个父节点按上述原归档、H5DF source、R1 诊断控制的顺序保留可达性。新 tree 只由固定数据文件构成，不合并三个父 tree，不修改 main 或候选 source。

## 本次实际包含什么

核心为明确核验的 **1,316 文件 / 74,351,039 B**：1,315 个原件候选与一个独立公开 actor 投影。覆盖 H5DF 的 12-blob 审阅及原 Git 读回、x64/ARM64 cross-cost 原失败、W1 同步调用链及原归因失败/纠正版、三个 service 外层日志、required head protocol 外层日志、PR 正文实际更新、ready001–004 时点观察、R1 诊断标签三次发布/恢复记录和两个 dispatch-only 失败尝试。文件真实来源和 byte/SHA 见 `metadata/archive-file-index.json`。

只在闭合记录的时点作结论：ready 系列不是之后状态或全部 CI 已结束的证明。后续新 protocol artifact、prospective 新日志、诊断第三次 dispatch 或其他新增调查没有自动纳入本固定核心。

## 原失败与资格边界

- [H5DF x64 job 132528768933](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43621754143/job/132528768933) 与 [ARM64 job 132528769087](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43621754143/job/132528769087) 分别保留原 4 秒、16 workers、0.25 CPU、7 packets、depth 6 约束。五个原 native selectors 退出成功不等于业务确认通过。x64 第二次 replay 在 Work 阶段到期；ARM64 第四次 Work 已通过，随后 commit 到期。两者不能互借失败原因。
- 两架构证据为各自严格范围取得的选定 ZIP 成员及 CRC/SHA，不是全 ZIP 校验。原获取失败和获准的续取记录没有覆盖或改标。
- 三个 service 与 required head protocol 的本核心材料只支持外层执行失败；具体内因不可由外层 child exit 推断。W1 线程 CPU / wall 与 Host spans 的不同范围不可随意相加，也没有据此证明一个安全的 4 秒性能修复。
- H5DF 的源码增量审阅和 PR body PATCH/readback 是已完成的限定工作；它们不代表 main 已合并、所有 branch 语义已激活、所有 required checks 全绿或业务资格已获得。
- R1 诊断标签已发布与 hosted 诊断已执行分开记录。原 publisher 的 UNKNOWN 保持原状；本核心两次 dispatch-only 都因 actor GET 连接失败而自然 exit1，0 POST。不能把准备稿、发布对象或 API 未发起记录写为实际诊断 PASS。

## 隐私与扫描

PR 正文 writer 的完整 `/user` 响应原件私密保留，不进入公开核心；其固定 SHA 为 `a8a2ad68fba0473e330471420f46ade969ac817a21448e34bc0e8c5967684815`。公开的 `payload/public-actor-projection.json` 是独立派生文件，只包含 login/id 与出处；不是原始响应，也不是新鲜 actor 查询。

核心 1,316 文件已完成 stable-FD 全量 SHA、初末精确文件/目录集合及身份核验。固定的五类凭据正则与九类私密响应边界检查均零命中；这不证明所有秘密类型都不存在，扫描不解压 ZIP/pack。本 README 和文件 index 另作为二文件范围固定和扫描，不宣称被核心扫描自包含。

历史 `temporary-index` 只作为不透明原始 data 文件保留，绝不用于构建或源码 Git index。构建不创建本地 tag ref，不推送，不执行任何 native/build/probe；实际 archive publication 需另有审阅和原始终态证据。各次失败、HOLD、UNKNOWN 均以原字节保全。
