# W1 C2 精确源码发布资格

本记录引用固定的候选 commit `cc4dd8bdd89309c635831db30b508af2f89419d7`、tree `161d3a4e8ab8c865869352339ec8c66f6609449a`。候选自身已经封存；本目录在独立文档分支上追加事后资格记录，不把本记录所属 commit 冒充被测试源码。

## 实际结果

| 组件 | 成功命令 | 实际通过的测试方法结果 | 备注 |
| --- | ---: | ---: | --- |
| 后端 | 13 | 22 | 原分段、递归与 retained guest 绑定 |
| Native、严格 verifier 与真实 receiver 控制 | 21 | 252 | 243 + 2 + 7 |
| Owner / M12 | 14 | 25 | Node 15 + M12 10；另 3 个 heavy 入口 ignored |
| CI | 19 | 471 | 包含 mandatory 104；0 skip |
| Publication map | 9 | 0 | 709 项冻结内容及 C1b→C2 的实际 72 项差异 |
| 聚合观察 | 4 | 0 | 源码前后绑定与实际原件核验 |
| 合计 | 80 | 770 | 组件命令 67 + map 9 + 聚合 4 |

聚合进程 `1a1b831cce2-12894-d70` 与归档进程 `1a1b833ec52-12894-d76` 均实际 succeeded / exit 0，输出完整且持久化；原终态见下方逐字记录。

所有 gate 使用其原唯一进程取得权威终态，输出完整且持久。缓存复制和隔离 target 的事实保留：这不是独立 cleanroom build，保留的 guest 未重编。原 A、C1、C1b 的证明、失败和昂贵取消各自绑定其原始源码、ELF 与进程身份；最终 C2 的检查没有重新生成完整 proof。

组件命令共 67 条（backend 13、native/receiver 21、owner/M12 14、CI 19），publication-map 另 9 条、聚合检查另 4 条，共 80 条成功命令。770 是组件实际测试结果数；owner 短测另有 3 个 heavy 入口明确 ignored。C1b 的实际昂贵取消和独立 cold 入口在其原证据中各执行一次，不计成这轮 C2 新执行的 heavy 测试。

## 文件与复核

| 文件 | 用途 | 字节 |
| --- | --- | ---: |
| [qualification.json](qualification.json) | 精确 C2 的资格、命令、测试和二进制绑定 | 226,149 |
| [qualification-raw.tar.gz](qualification-raw.tar.gz) | 533 个原件，29,229,247 解压字节 | 3,495,706 |
| [qualification-raw-index.json](qualification-raw-index.json) | 归档成员与源文件 SHA256 对照 | 343,720 |
| [archive-readback.json](archive-readback.json) | 逐成员读回及原件未变结果 | 1,790 |
| [aggregate-result.json](aggregate-result.json) | 聚合进程结果与四条观察命令 | 4,469 |
| [gate-job-statuses.json](gate-job-statuses.json) | 各 gate 的权威终态 | 5,920 |
| [raw-inventory.json](raw-inventory.json) | 完整原件清单 | 348,016 |
| [publication-receipt.json](publication-receipt.json) | 封存收据及全部关键 pin | 3,688 |
| [terminal-aggregate.raw.json](terminal-aggregate.raw.json) | 聚合进程的原始终态工具文本 | 731 |
| [terminal-archive.raw.json](terminal-archive.raw.json) | 归档进程的原始终态工具文本 | 729 |

`qualification.json` 的 SHA256 为 `01947ed12ac65cd24dc4d9364f3e12af93a6539fb6abcfac26b7b43ed3587dbb`；原始归档 SHA256 为 `c0cbda739add31b6bc887887833990038bcf0414c4e6bf93dc79f0cfdb38113c`。

[逐文件 SHA256 清单](artifact-inventory.json)覆盖本目录其余公开文件；清单自身不递归包含自己。raw 归档的索引及聚合记录保留每条命令、原 stdout/stderr、源绑定、target/cache 关系、原进程及终态。原 C1/C1b 已资格 ELF 在最终 gates 后再次按实际字节核验。

候选的[完整运行证据](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/cc4dd8bdd89309c635831db30b508af2f89419d7/evidence/pon-w1-fresh-runtime-20261107/README.md)及[机器可读结论](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/cc4dd8bdd89309c635831db30b508af2f89419d7/evidence/pon-w1-fresh-runtime-20261107/summary.json)已在 C2 内。公开证据包不包含私有数据库页或完整私有 dump。

## 结论边界

这份记录证明所列检查在固定 C2 上完成。它不赋予部署、共识激活或付款资格。两份固定输入 fresh proof、原父进程时钟观察 ROG 返回包、共同 Rayon2 ABBA、原预算失败、真实 owner 取消及 cold、资金私有副本审计的结果与限制保持候选记录原样。

部署 WAN 与中奖区块 Node admission、完整历史进程树计费与 wait/reap、昂贵任务重组/超时全路径、正向一次性 provider 付款、原业务预算、总体生成尾延迟、验证/传输部署收益及完整密码学/PQ/语义/DA/模型效用条件仍有未闭合项。GPU usage 保持 UNKNOWN；退款本金与 provider 付款、资源 credit 分开记录。
