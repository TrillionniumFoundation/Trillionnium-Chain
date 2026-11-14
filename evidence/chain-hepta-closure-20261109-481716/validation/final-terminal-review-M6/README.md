# M6 最终增量审阅：源码控制与原生终态

**结论：本次冻结交付中的工程结果与原件一致，未发现范围内的实质不一致；产品、服务和生产总资格继续为 `HOLD_NO_GO / DENY_ALL`。** 这是 READY 后的只读核验，没有重跑测试、native 重试、编辑 source、联网或执行发布。

固定执行源码为 M6 `4dbeae12fa756fd662cc074390fcb628abe970ad`，tree `1943c3e69e3a717ce99d91aabc00eba4d37516f1`。以后仅保存证据的 child commit 不替代该执行身份。

## 295 项源码控制与原提交对象

59 + 176 + 11 + 23 + 26 = **295 条完整 verbose unittest 记录均为 ok**，另两条 CLI 单独计数，返回仍为 HOLD。14 份原 stdout/stderr 的大小与 SHA-256 全部匹配，各独立 result 与总 summary 一致，没有方法筛选、skip 或 timeout。1,380 项输入 before/after 的逐路径摘要相同，HEAD/tree/空 tracked status 一致；快照的观察时间不同，没有把两文件的原字节说成相同。

12 份学习 fixture 从 M6 原 Git blob 再核大小、Git OID 和 SHA-256，全部匹配。source-lineage 中 M1–M6 六份 raw commit 对象的 Git OID、SHA-256、字节数、父关系与 tree 均独立复算一致。详情见 [controls-lineage-reviewed.json](controls-lineage-reviewed.json)。

## 实际五库终态与身份关联

M6 native 日志 archive **1,022,076 字节，SHA-256 `c59397c89f1ed4e50605dfe337b77d2b63d82309f339ea7fa29f8884c99c16f9`**。完整成员名单为 180 个原件加 manifest，逐文件大小和 SHA-256 全部正确；交付目录 15 个文件、1,150,008 字节，FILES 与 SHA256SUMS 匹配。

从原 stdout 的完整行独立重算：

| Library | 顶层 roster | Passed | Failed | 顶层 ignored |
| --- | ---: | ---: | ---: | ---: |
| trnm-data-availability | 715 | 715 | 0 | 0 |
| trnm-crypto-primitives | 196 | 196 | 0 | 0 |
| trnm-release-bundle | 67 | 67 | 0 | 0 |
| trnm-protocol | 115 | 113 | 0 | 2 |
| trnm-pon-node | 1398 | 1359 | 0 | 39 |
| **合计** | **2491** | **2450** | **0** | **41** |

顶层 filtered 和 measured 均为 0。五个 actual Cargo compiler-artifact 事件的 executable 路径，分别与 direct before/after 的 path、bytes、SHA-256、cfg(test) 对齐；source M6、7 个固定 provider exports 与 inputs、test profile、精确 argv 和 package cwd 也一致。四库裸 argv，只有 node 使用 `--show-output` 保存成功输出。实际 check、Clippy `-D warnings`、fmt 均 exit 0。

这些是小包中的**身份观察记录关联**。本地没有重新读取远端 5 个 ELF 或 provider 静态库实体；本报告不把 identity 记录核对说成本地完整二进制重哈希，也不将 `cfg(test)` ELF 改称普通 daemon。

Journal 的原 child section 与交付 sidecar 逐字节相同：父测试 ok、实际 running 1 test、完整 body COMPLETE 标记及一条 `1 passed / 1397 filtered` 成功摘要均存在。其源仍要求同一 child 中完成 initialize、活 owner 拒绝控制、原 fault、drop、reopen 与原断言。M6 成功不能识别 M5 原 EAGAIN 的持锁者或证明其因果。逐包记录见 [native-byte-review.json](native-byte-review.json)。

## 41 ignored 的准确范围

**41 是顶层计数，不是“41 个 body 在任何进程里都没执行”，也不是“41 个业务 gate”。** node 顶层 39，protocol 顶层 2。原父测试显式执行了顶层 ignored 的 `held_file_substitution_child`；另外有两次非ignored migration child，M6 新增一次非ignored journal child。node 共四条 nested 摘要均单列，完全没有加进 2450 或 2491 的顶层分母。

新增 ignored-scope sidecar 绑定原 M5 README、ignored JSON 和 archive 摘要，纠正旧交接中过宽的“全部未执行／没有启用ignore”措辞。原 archive 和历史 summary 没有改写。原服务、容量、重型与发布门槛仍未据此关闭。

## 最终文本、链接与未关闭边界

最终 README SHA-256 为 `fef27c5644cf4c23dc9543c2cddc2f8551e271548695432b0e5dacd47f6cace9`；execution-status 为 `cbca1a1b4907814f164f6bdfb00243c3d3c7c9ba047040a902664c864f154dda`。两者与上述实值一致，五份 qualification 核心文件与前次静态审阅完全相同。M5 canonical 2449/1/41 失败、旧 3.5.5 release 56/11、0746 原 campaign 均仍以自己的源和环境保存。

当前 17 份 display Markdown 的 54 个包内相对链接全部存在；126 个外部链接仅作文本核对，包含 28 个 reference-style 定义。未发现展示稿 sandbox 目标、私人 Library ID 或签名 URL。未联网验证外部页面，也没有把这一检查宣称为整个仓库或所有压缩包的秘密扫描。

普通 daemon 的真实训练、评价、Selection/NoUpdate、安装、FinalUse、下一任务与 OS 冷恢复，原 Host **4 秒**与独立 campaign **30 秒**，独立管理的 **3 个故障域 / 至少72小时**部署，完整 PQ/lifetime 证明及全部合法策略 PoN 成本下界仍需要各自证据。工程 runner 时间窗没有改变这些契约。publication 字段仍是有时间标记的发布前观察，本审阅不声称后来远端 head 或 hosted checks 已确认。

完整最后输入摘要、主子分母及链接检查在 [review.json](review.json)。前两次 static review 原件保留，本报告只补齐它们当时明确排除的 M6 controls/native 终态范围。
