# 旧 C2 后续 GitHub 读回

本目录只引用候选 `cc4dd8bdd89309c635831db30b508af2f89419d7` 的 GitHub 观察。C3 本地被测提交为 `abab79dac0cb89eb2753d3f579119ac135650eb5`；本目录不提供 C3 远端 CI 资格。

## 后续快照

实际快照共 104 项：101 项已结束，3 项仍运行；82 SUCCESS、3 SKIPPED、16 FAILURE。这不是全局终态。早先封存的 76 文件 C2 读回包保持原字节，不能把两次快照的完成数混用。[summary.json](summary.json)保留这次观察的来源与范围。

## 九个失败 job 的日志

本次经正常本地 GitHub 通道仅读取 9 个 job 的 API 元数据和原始日志，各 run 的 head SHA 均实际绑定上述 C2。没有重跑 workflow、下载 artifact ZIP、执行下载的代码或改变预算。

- CodeQL export 的日志明确表示：分析及检查未能在原截止时间前完成并稳定，因此 export step exit 1。这份日志不能证明存在权限错误或代码漏洞。
- 四个 history matrix job 的构建准备记录 passed=true；随后原 public-host controller 记录 passed=false、systemd_run_exit=1、failure=null、final_host_errors=[]。步骤名称中的 4,105 块及 paid full sync 是原定目标，不能当作已完成的结果。内层 history artifact 未下载，原因尚未闭合。
- 三个 service-model job 与 x64 cost job 的失败位于各自的原始 from-zero controls 阶段。本次日志读回尚未确认其内层失败条件；更晚控制步骤中的 panic 输出没有被用来解释更早的失败。

[raw-logs.tar.gz](raw-logs.tar.gz)保留全量选定原始日志及派生 JSON；[PUBLIC-ALLOWLIST.json](PUBLIC-ALLOWLIST.json)逐文件列出来源、字节数和 SHA256；[archive-readback.json](archive-readback.json)记录全成员读回及原件未变。
