# 原始 campaign baseline history 累计快照回收

本包回收 GitHub Actions run **42591962205**、artifact **13662172930** 中三份原报告，原执行源码为 `0746a462e80067b78317597f2fa4bacf5e3db958`。这次只读取既有原件，没有执行新的 campaign。原 run 的 conclusion 为 failure，原资格未由回收动作改变。

原 ZIP 为 76,441,344 字节，SHA256 `4e8a243caf2aadf4a195b4cb96dbb0229a0e001a830f0e9de2c4f853ee7dff5c`。它与 GitHub artifact digest 一致；三份 report.json 的字节长度和 SHA256 分别与原 artifact-files.json.gz 对应条目一致。提取前后 ZIP 与原成员清单摘要不变。

## 文件与原 JSON 路径

- `baseline-history-snapshots.json` 的 `runs` 数组含三份报告；每项保留原 `client_native_history_arithmetic_before` 与 `client_native_history_arithmetic_after` 的完整对象，包含 unknown、failure、CPU、wall、stage、SQL 与 in-flight 等原字段。原路径分别为 `/phases/0/client_native_history_arithmetic_before` 和 `/phases/0/client_native_history_arithmetic_after`。
- `run-N-baseline-complete.json.gz` 是无损压缩的 JSON 值副本。其 `baseline` 完整保留原 `/phases/0` 的 50 个字段，包含 history、budget_samples、上下文、时间、计数、状态、其余原观察对象；没有删减 baseline 字段。`report_root_excluding_phases` 保留原 report 除 phases 外的全部顶层字段。压缩后解码逐值相等已检查。原始字节身份由源报告 SHA256 绑定；本包 JSON 是解析后的值副本，不冒充源 report 原字节。
- `original-report-layout.json` 保存实际顶层键、baseline 字段与 JSON 路径；`original-report-manifest-selection.json` 保存三份原成员的长度和 SHA256。
- `connector-download-receipt-public.json` 保留公开回收回执；私有 `file_reference_id` 已移除，原件仍在本地。`connector-receipt-transformation.json` 记录原回执摘要与投影规则，不包含该私有引用值或短签名 URL。没有读取或复制 Library 私有保留身份。
- `mac-attempts/` 保存此前 Mac 下载超时、Range 读取前置拒绝、原 controller 回执及最终 partial 身份。它们是历史失败记录；随后成功的连接器回收独立记录在公开回执中。Mac partial 没有继续下载或拼接。

这些 before/after 对象是原 baseline 整个 phase 的累计观察，包含后续未成功的业务轮次；不能把其差值直接重标为首轮七个成功包。native stage 计时存在嵌套关系，SQL Transaction::commit API 观察也不能自动解释为物理 fsync 时间。此包保存原始观察，不单独给出瓶颈或生产资格判断。
