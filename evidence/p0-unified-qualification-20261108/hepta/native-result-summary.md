# f178 原生结果：12 个选中控制通过，采集 FAIL，资格 HOLD

在 `f1785ca15e41e4e49509a5b211a659e3cbdbf60e` / tree `f07e40dbf570539eba6b683f7569804b0eb9ae5e` 上实际重建并运行了授权的 12 个原生控制。它们通过仓库原 `just test` 入口和 nextest 0.9.103 `local` profile 执行，源码、锁、60 秒 watchdog 和一次 retry 配置未修改。三个选中作用域的原生命令退出码均为 0。

**这不是 P0 通过。本次 collector 的准确状态为 FAIL，生产资格仍为 HOLD_NO_GO。** 原 runner 的返回值和 aggregate success 不能代替下面的独立审计。

## 从完整原始流核对的结果

| 原生作用域 | 唯一选中测试 | PASS | FAIL / timeout / retry | 本作用域 skipped | nextest 测试时间 |
|---|---:|---:|---:|---:|---:|
| readback5 | 5 | 5 | 0 / 0 / 0 | 744 | 9.094 s |
| unknown_restart3 | 3 | 3 | 0 / 0 / 0 | 746 | 0.167 s |
| durable_effects4 | 4 | 4 | 0 / 0 / 0 | 43 | 0.060 s |

完整编译 registry 有 796 项：agentd 749 项、operations 47 项。累计只选中了 12 个唯一测试，784 个从未选中；其中 60 个是 registry 明确标记的 ignored，全部位于 agentd。选中测试中的 ignored 为 0。不能把三个作用域的 skipped 相加冒充唯一测试数，也不能把 final-output 对 PASS 的再次打印当成第二次 attempt。

独立 parser 对原始流逐项核对了：只有一个 Starting 和 Summary；Summary 前恰好出现预期 5/3/4 个不同测试；所有名称在原 registry 内；全部不是 ignored；PASS、skipped 与原命令退出码一致；没有观察到 FAIL、TIMEOUT 或 retry 状态行。该解析只支持本次实际观察到的格式，其他未识别状态会直接失败，不能以未出现错误字样推定通过。

主编译 registry 构建实际耗时 467.270 秒。三个 `just` 命令墙钟耗时分别为 10.466、0.971、122.572 秒，最后一组包含单包特征集合的额外编译，不能把其 0.060 秒测试时间当作端到端构建/执行时延。

## 必须保留的采集失败

原 nextest 将 store 放在 `source/codex-rs/target/nextest/local/junit.xml`，即使 Cargo target 已经外置，store 仍没有随它迁移。原 runner 只检查外部 target，因此三组 receipt 的 JUnit 字段均为空；前两份 JUnit 被后续运行覆盖，不能恢复为原始 JUnit。最后 durable4 的原始 JUnit 已完整恢复：4 tests、0 failures、0 errors，SHA256 `bd9b418ae21a9109b1294c91c1af1605028329219fa12e41b2e7a786f9185948`。

源内新增内容只有 `target/nextest/local/junit.xml` 及三个父目录。核对完整目录清单、文件 SHA256、时间、单链接、非 symlink、非 tracked 身份后，已将 `nextest` 原样移至外部 `evidence/recovered-source-generated-nextest-attempt01`，再移除空的 `target` 父目录。迁移后 HEAD 仍为 f178，tracked diff、普通 untracked、ignored 清单全部为空。该清理没有抹去本次曾违反输出外置要求的事实。

OS 进程 executable observer 没有记录到任何有效观察，加载绑定保持 `NOT_OBSERVED`。二进制存在和哈希一致不能补造已经缺失的加载观察。原 runner 没有把这类缺失和 JUnit 空值纳入自身 collector failure，因此独立 readback 明确覆盖其解释：`collector_status=FAIL`、`collector_exit=1`，原始 result 文件本身保持不改。

没有为了补 JUnit 而重新执行测试。独立 readback 仅读取完整日志和 registry、保存审计结果并迁移本轮自有生成文件。

## 新编译二进制身份

| 新 ELF | 字节数 | SHA256 | 身份范围 |
|---|---:|---|---|
| `codex_hepta_agentd-8345a11e98df03a2` | 1,082,097,112 | `01eef355434e60b371c5547aeee75b5adfacbdae629b2978f69a1bd5a9801cca` | 初始联合 registry 中的编译产物 |
| `codex_hepta_operations-591a1c18abaabe9c` | 262,719,608 | `f23fca3f6c9610d44b4d635260b78a321262bf04cb498652f88a5ea48d577189` | 初始联合 registry 中的编译产物 |
| `codex_hepta_operations-b10dc5cc3eef1337` | 260,242,360 | `6094ed5cb39ae5c806441e6454101d00f7a21cb941eb728f3bfd9edb990e4bc9` | 后续单包作用域产生的额外产物，全部字节已保留 |

第三个 ELF 说明联合 package registry 和后续单包命令可能具有不同的特征统一结果。不能把“初始两个 ELF 的哈希没有改变”写成“所有作用域都加载了这两个 ELF”。三份完整二进制保留在 remote `evidence/binaries/`，本地文本归档保留路径、大小和哈希，未把 1.6 GB 的二进制正文复制进归档。

## 资源和业务语义边界

实际工程资源为 CPUQuota 200%、memory 8 GiB、nice 10、build jobs 2；swap limit 为 `max`，pids limit 为 146420。构建中一次独立观察到 memory peak 7,666,999,296 bytes、swap current 0、oom kill 0。这不是四分之一核 / 2 GiB / 零 swap / 256 pids 公共主机资格，也不是吞吐改善证明。

readback5 使用真实 publication、journal 和 Fleet actor，但训练收据、Qualified 评价和 worker 输出由测试构造；四个导出是 retained/adopted 两个 fixture 的 pending/acked 两相。UNKNOWN 控制检查原操作不重复 dispatch 和 indeterminate 保留；恢复 matrix 的子进程使用 `exit(81/82/83)`，不能写成 SIGKILL 或断电验证。

本次只固定 Hepta source，记录中 `chain_sha=null`；没有与 root 最终 Chain 候选同时加载或链接，不能倒填 Chain SHA 声称一次双仓集成运行。原生组件结果也不能替代同一次真实训练、独立评价、付费、合格 WAN 冷取、生产安装加载和下一任务闭环。此前 #5045 等其他 source/profile 的 FAIL、ignored、timeout 不因本次选中 12 项通过而被覆盖。

## 冻结证据

外部 hostout：`rog:/home/qian-qi/work/hepta-p0-native-controls-20261108-99b5-hepta-audit`。

完整文本归档：`hepta-native-evidence-text-attempt01.tar.gz`，222,492 bytes，SHA256 `3928025df5bf71c23a11db5cf2e37c056eb9171c90e4ea62680a2254a056db8f`。通过四个版本绑定 chunk 拉回后，已独立验证总 SHA256，并解包校验 manifest 中 40 个文本文件的大小和 SHA256。

纠正后的核心审计：`native-attempt01/evidence/independent-native-readback.json`，SHA256 `04d1e39f51bedfd3795687ab472ea40902a8d85e3cfdba6d82f60c6a6b28bd84`。

原 runner：SHA256 `0efb407920ee3806c7bf9a71cc710465e17c88fc5a6b04a2075e03fd386a2a91`。原 `result.json`：SHA256 `33fde10448d642b7489f2712af0d68173880df7056280ad2aca95b98f5916d12`。这两份原始材料保留其真实内容，由独立审计解释已确认的采集缺陷，不回写成成功采集。

Gate v1 仍是同源材料记账与防假绿前置工具。它恒 `HOLD_NO_GO`，所有原始结果都标 `RAW_OUTCOME_UNVERIFIED`，不会因为本次结构测试或选中原生控制通过就授予生产 authority。
