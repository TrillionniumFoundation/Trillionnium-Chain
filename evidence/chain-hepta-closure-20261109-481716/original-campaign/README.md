# 原始 0746 campaign 证据与候选 workflow 范围复核

本目录整理已有原件与读取记录。原始执行提交为 `0746a462e80067b78317597f2fa4bacf5e3db958`；它不是当前整合候选的一次新执行。整理过程没有运行 native Node、原始 campaign、训练或证明验证器。

## 原件结论

独立 build 返回 0；三次原始 campaign 均返回 101，成功 campaign 为 **0/3**，成功 phase 为 **0/9**。三次各保留 baseline、from-zero、late-product 的原始 **30 秒**窗口。全部 phase 都保留 `PUBLIC_REQUEST_DEADLINE`；没有 phase 启动错误，没有 report validation failure。读取器成功退出仅说明读取完成。

原计划分母为 **27** 个确认轮次，实际观察 **12** 个，确认 **3** 个，尚未观察的计划轮次为 **15** 个。未观察轮次没有从分母移除。`service_returned_ok` 不替代原始 phase 成功条件。

v2 报告保留 **66** 次 History import 和 **264** 个 Host 测量槽。该批原件的 measurement failures、unfinished Host calls 和 unknown CPU calls 均为 0，66 次 import 的完整 Host CPU 条件均满足。原先 CPU 数值不变。读取器在缺测、丢测、未结束或计数不一致时将完整 CPU 总量保留为 unknown，已观察部分单列；Host、page、client 等嵌套计量不相加。Host CPU 也不等同于 worker 或进程树 CPU。

这些记录未关闭原 **4 秒 Host 服务**、History/capacity/churn 各自验收、大模型完整保管、普通 daemon 学习闭环、独立运营或 WAN 门槛。同机 loopback 记录未被提升为独立故障域或长期部署证据。

## 原始身份与紧凑保存

原 ZIP 为 76,441,344 字节，SHA-256 `4e8a243caf2aadf4a195b4cb96dbb0229a0e001a830f0e9de2c4f853ee7dff5c`。磁盘耗尽后，经主任务明确授权，在重新完整计算本地 ZIP 哈希、核对远端 digest 并验证保留的 manifest、报告与 receipts 后，已删除这一份本地 ZIP 缓存；没有删除其他文件。`local-raw-zip-removal.json` 明确记录此事，本目录不包含 ZIP。GitHub 原运行、artifact ID、源码提交与 tree、保留二进制和选定原件哈希均在 `raw-evidence-hashes.json`。`remote-artifact.json` 保留删除前的最新 API 元数据：artifact `13662172930` 尚未过期，声明过期时间为 `2026-12-09T09:25:57Z`。这不是无限期可下载保证。

`artifact-files.json.gz` 解压后是原始 319,639 字节 manifest，SHA-256 `9710a213553110e9347790a34775d92d9ba20d55a7f13a5e633e78ea0d63689b`。完整 manifest 保留全部 1,765 个成员和 584,959,164 个未压缩字节的身份；大 raw report、phase-readback 和二进制未展开复制。`raw-small/` 保留原始的小型结果、源码观察和失败 stdout/stderr，均按原 manifest 逐件复核。

`campaign0746-outcomes-v2.json.gz` 解压后 SHA-256 为 `1b95b9e8bee728922480a8e40eb9730e750fc64a4c50c0e5cefe2ced1b38585a`。历史 v1 报告另存于 `history/`。所有 gzip 使用空文件名、mtime=0、level=9，并实际解压验证原字节一致。

## 全部读取尝试

`reader-attempts/` 原样保存已有 receipts、空输出及 stderr。索引是事后整理，明确区别原文件与新增说明：第一次读取退出 137，唯一原因未确立；第二次因 `/usr/bin/time` 缺失而在读取器启动前退出，原 JSON receipt 不存在，索引的 shell 127 来自保留的会话命令观察；第三次历史 v1 读取成功；v2 第一次读取成功。失败记录没有被覆盖，读取尝试没有计作新 native campaign。

## 当前候选 workflow 的范围

`workflow/` 保存本次静态复核的 workflow 原字节、观察到的提交和所有读取器输入哈希。workflow 在 head 和 prospective-merge 两条 lane 上分别运行三条 suite，共六个矩阵 job：

| Suite | 实际门槛 | 不构成的结论 |
|---|---|---|
| scope | 保留的历史学习记录和 synthetic Root profile 上的读取器约束控制 | 当前候选 daemon 训练、Root 来源认证或 FinalUse |
| proof-profile | 控制测试及固定 source/profile descriptor 绑定 | native proof verification、完整依赖闭包、PQ theorem 或生产批准 |
| campaign-reader | 人工构造的解析、分母与计量完整性控制 | 读取原 ZIP、新运行 campaign 或通过原 4 秒服务 |

证明绑定读取器的成功状态明确为 `PROFILE_BOUND_SECURITY_HOLD`，并保留关键 qualification 为 false。共同 source/preflight/diff 检查不会提升上述范围。此次复核只读取代码，没有运行 workflow，也没有检查远端 CI 最终状态；三条 suite 的通过不能替代原服务验收通过。

整理期间还保留了 workflow 版本变更导致的严格 pin 停止，以及磁盘空间耗尽的记录，见 `package-attempts/`；它们不计为 native campaign 或读取器的新执行。

`FILES.json` 和 `SHA256SUMS` 列出提交材料的大小与哈希。应在真实原件可取得、候选提交和实际 native 执行记录齐备后另行关闭对应验收项。
