# M6 发布材料：独立静态复核

**结论：在固定输入与明确范围内，未发现实质发布错误。总资格保持 `HOLD_NO_GO / DENY_ALL`。** 本次只读 source/Git 对象和证据文件，没有修改仓库、运行测试、native 重试、qualification reader 或网络获取。

**M6 native 与 M6 controls 的新终态不在本报告内。** 审阅过程中 root 加入了 M6 controls 文本；本报告核对其当前链接和资格边界，没有核验这批新执行的结果、日志、计数或输入清单。后续应另作增量终态复核。

## 身份与摘要链

Chain M6：`4dbeae12fa756fd662cc074390fcb628abe970ad`，tree：`1943c3e69e3a717ce99d91aabc00eba4d37516f1`。Hepta：`71738345326b98d88b738250d2b84ecbcb466eb8`，tree：`bfd8384241bf09fcf79daa94f2ef9c9438f92ee4`。

| 文件 | SHA-256 |
| --- | --- |
| candidate-profile.json | `175524d6cafe93f1f175d272bee1b9be4d22c954909be3fca6d4955362900775` |
| qualification-plan.json | `94d02a1f21b9e33b5fb22ea53fe0445433aaa8e03d5f0ca446ad3c33cd3b3df8` |
| qualification-packet.json | `30f71c34f28eeba630127859947379b4ea6eb853f53c0090686cc3694fe77463` |
| qualification-review.json | `d536c4d56b66d6ca622d7cc400205d91e6ea93a59d8012d45ba73f65fdaa0356` |
| qualification-identities.json | `9b3f1ade3bf13dd975da543df087a7a045bb9296dd95dabec373fa1a507c6681` |

九个引用边均匹配实际文件摘要，profile/plan/review 的 source pair 一致。七项资格 gate 仍为 BLOCKED/HOLD，build/load 字段均为 null，普通 daemon case roster 与完整双工作树 collector 没有升级；空 roster 没有被当作豁免。

## 字节核验

- **Chain 14 份 + Hepta 2 份选定 lock 全部匹配固定提交的本地 Git 原对象。** Hepta 717 两锁复读禁用了 lazy fetch 和 replacement objects，blob、字节数和 SHA-256 也与既有 observations 相同。它们包含研究/审计输入，不表示全部参与本次编译，更不等同完整 source/build/load collector。
- Proof manifest 与 M6 Git 字节一致；22 个选定 project/fixture 输入和 upstream snapshot 匹配。用固定声明 identity 和实际输入摘要重算 descriptor，仍为 `da0c97f1c549e10ecfc066f6b0a9721147dc3d430eab6f53d502cbc7b91dd48c`。15 项义务、寿命 null/false 和论文版本取得边界不变；native-PNW1/P3 没有替代所选 RISC0 profile。
- 原存储契约 **9,915 字节，SHA-256 `9796d49c535de01ea79dd331e1d9c6768326770b6411b76caac0f33d53fdd5a9`**，原 097、M6 Git 对象与工作区完全一致。原 Host 4 秒、独立 campaign 30 秒、至少三个独立管理故障域及至少 72 小时未变；研究 watchdog、proving 与 native runner 窗口没有替代这些门槛。
- M5 六份历史 qualification/execution 文件均匹配 retention 摘要。15:57 pending execution-status 有明确历史说明，未当作最终 native 结论，也未移名为 M6。
- 复制的 M5 native tar.gz 原件 SHA `2ad7f1189e1286301beac719dc98bb92b1c73410cecb1d0da4ad096fdcec3e16` 匹配；471 个清单文件逐一大小和摘要正确，含 manifest 共 472 个成员。完整终态仍为 **2449 passed / 1 failed / 41 ignored / 0 filtered**。旧动态 3.5.5 release **56 passed / 11 failed** 保留，未把 provider cohort 或嵌套进程成功混入填补失败。

## 展示文档与范围

15 份当前 display Markdown（排除两份冻结 research-originals）包含 46 个包内相对目标，全部存在；125 个外部目标仅作文本核验，包括 28 个 reference-style 定义，未联网检查。未发现展示稿 sandbox 目标、私人 Library ID 或签名/凭据 URL。本检查不声称已扫描所有 archive 或整个仓库的凭据。

当前文本保持 M6 源、M5 原生失败、旧 3.5.5 环境和 0746 campaign 的来源边界。首轮 21 次 import 子样本与全 baseline 30 次 import 分母保持区分，未将 account_graph 占比或可能的 CPU refill 写成已确立根因。M6 整用例 exec 隔离未被表述为原 EAGAIN 因果已经定位或生产并发 spawn 安全证明。

既有 QROM Jan→March 正面比较记录仍保留，本轮未独立复取 PDF 和 15 义务未闭合的限制仍清楚。普通 daemon、原服务、真实独立 WAN/长期运行和生产资格没有因 reader、编译、库测试或研究记录而被宣布通过。

## 本次固定快照

README SHA：`a20376e551508fd7859737d7f49dbf3521d0dc672af35301df8ddadc1cecdd2e`。execution-status SHA：`395038c6691369c1e10c81737570a6ce9298012cf686c3ef36f3dca8dbac7144`。该状态中 M6 native 仍为 `PREPARING_FRESH_FIXED_SOURCE_VALIDATION`。后来加入的 native 或 controls 结果不可套用本报告。

初次收尾捕获检测到 README/执行状态并发改变，正确停止写入；改动范围重新读取后，本次以新摘要固定，保留了这次拒绝记录。五份 qualification 核心文件没有变化，旧 static review 没有覆盖。完整输入身份、16 个锁对象、proof 输入与所有相对链接核验见 [review.json](review.json)。
