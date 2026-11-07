# W1 v2：证明发布延迟的原始回读与可执行门槛

本轮从既有 #688 集成候选 `3d1b6507671ec694ce58e86d4063a125c8deeb66` 继续。
发布前已保留并快进吸收 `adebe0bd78e6e1bdb55a599179ffe2313997170e` 的独立 analysis-lock
修复；没有重写并行候选、覆盖其锁文件或借用其原 CI 成功。
新增的是历史阶段成本回读、严格有限样本门槛、对抗测试与异步结算接口合同。
**HOLD / NO-GO：没有新生成完整证明，没有新增出块或训练证明准入，没有关闭实际性能门。**
历史原始数据、原四秒服务确认预算、16 hostile workers、工作关系、难度和激活条件均保留。

## 1. 可重复的读数

[historical-readback.json](historical-readback.json) 来自
[新的阶段回读器](../../scripts/read_w1_proof_latency.py)，并先调用原
[完整 v2 disposition reader](../../scripts/read_w1_full_v2_disposition.py)。原固定声明绑定
13 份输入，包含实际 proof、独立 expected-artifacts、raw archive、失败和 UNKNOWN。
读回成功不表示执行了新 proof verifier。

| 原始 fresh pipeline 的互斥阶段 | 秒 |
| --- | ---: |
| 准备与完整执行进程 | 16.238464345 |
| 初始空前缀检查进程 | 10.414869301 |
| 43 个 segment 进程 | 3958.660546294 |
| 完整递归压缩进程 | 2257.781606805 |
| 独立 fresh verifier 进程 | 0.053977281 |
| controller 和阶段间隙 | 5.334642773 |
| fresh pipeline 总计 | 6248.484106799 |

43 个 segment 阶段占 63.35%，递归压缩占 36.13%。后者包括 43 次 lift、42 次串行
join；两类 API 调用分别为 1138.946912063 和 1112.044486135 秒。API 时钟包含内部
启动/初始化，不能重标成纯密码学运算。真正的既有 prefix 重验是 903 次、21.996080820 秒，
已经包含于 segment 进程，不能重复加账。初始空前缀阶段不是十秒的旧 receipt 密码学校验。

将 segment 进程时间反事实置零、其余不动，仍剩 2289.823560505 秒；将压缩进程置零，
仍剩 3990.702499994 秒；两者置零仍剩 32.041953700 秒。这些仅为原时间分解的算术，
不是可实现加速、资源公平的并行实验或更换后端后的不可突破下界。

原 `post_find_publish_seconds`、WAN、node admission、confirmation、stale rate 仍全部
为 null。新报告也没有填造 winner-to-receiver 或 prover p99。
一份完整成功、一次 7200 秒原期限失败和一次 interrupted UNKNOWN 全部保留，完整
attempt population 仍未知。decode/verify 的 30.2438 倍及 envelope 的 5.1898 倍成本否决保留。

## 2. 已实现的门槛

[Poisson illustration](poisson-illustration.json) 是明确假设的数学场景：竞争到达率
0.1/s、容许竞争到达概率 1%，得到完整路径预算 100.503358535 ms。
该文件不是网络实验或 stale-rate 测量。原十秒参数是实验 target spacing；四秒是原服务
确认约束，工具将两者分开。

[有限样本工具](../../scripts/pon_proof_latency.py) 用独立保留的 policy SHA256 固定
source/profile/statement、完整 trial roster、终点、风险假设和期限，拒绝替换、漏项、
重复 trial、倒序、重叠、跨时钟差值及重置 deadline。迟到成功的实际慢值继续进入完整
有限样本分布；失败、取消和 UNKNOWN 不得被筛掉后计算“成功者 p99”。

报告分别给 `finite_poisson_latency_screen` 和
`finite_original_confirmation_necessary_screen`，不以一项通过覆盖另一项失败。
深层 JSON 统一拒绝；短时 UNKNOWN 不被改写成已知失败；在 deadline 结束的 timeout
也不被叫作按期到达 endpoint。合成负例只测试这些规则，不成为新的性能样本。

policy hash 不能证明采集时间、独立托管、日志完整性、执行二进制身份、真实新 proof 或
到达率的网络适用性。`planned_trials` 是声明行数，不是经认证的独立证明次数。
固定 header 的当前合同用于固定语句诊断；活链 winner 采集仍需先冻结采样规则、再追加
真实发现事件的独立日志。所有输出均保留 HOLD、禁止准入和禁止激活标志。

## 3. 异步路径落实到现有 owner

[异步接口审计](../../docs/development/specs/pon/ASYNC_PROOF_SETTLEMENT_BOUNDARY_V1.md)
已定位实际 M06/Node task、model/evaluation、funding/effect 和 storage owner。
现有 ordinary task 可以表达业主接受后付款；它不等于链独立验证完整训练证明。
`ConsumptionSettlementStoreV1` 是本地单调 kernel，不能代替支持分叉回滚的规范账本。
慢任务生成可以异步；以后真正 proof-dependent 的规范交易仍必须让各节点付清验证成本。
完整 W1、质量增益、模型采用、资金授权和一次性效果保持不同判断。

## 4. 复现

```bash
python3 scripts/read_w1_proof_latency.py > /tmp/w1-historical-readback.json
cmp evidence/pon-proof-publication-latency-20261107/historical-readback.json /tmp/w1-historical-readback.json
python3 scripts/pon_proof_latency.py model \
  --competitor-rate-per-second 0.1 \
  --max-competition-probability 0.01 \
  --latency-seconds 0.1 1 10 > /tmp/w1-poisson-illustration.json
cmp evidence/pon-proof-publication-latency-20261107/poisson-illustration.json /tmp/w1-poisson-illustration.json
python3 scripts/ci/test_pon_proof_latency.py
python3 scripts/ci/test_w1_proof_latency_readback.py
python3 scripts/ci/test_w1_full_v2_disposition.py
```

两项新增测试已经各一次接入 `repository-truth`，另有 CI mutation controls 拒绝删除、
重复、注释、`true` 替换、吞错和移到错误 lane。最终验证记录按实际 source/file identity
保留，不把 Python reader 成功写成 Rust runtime、WAN 或独立证明生成成功。

详细数学推导、尾概率/抽样条件、容量/凑批界限、平衡 join 的关系义务及最新一手文献见
[完整延迟合同](../../docs/development/specs/pon/PROOF_PUBLICATION_LATENCY_V1.md)。下一道
实际门仍是相同完整关系、相同声明资源下的新证明与 winner/receiver 全路径观测。

## 5. 精确提交验证与原始失败保留

实现提交为 `baa64498b8bb47198c99f8e9382cb36829f594f4`，tree 为
`d7929f82e8e563298adc0aebc673ccac0cd11b47`。该 clean 提交上的前后完整 tracked-source
验证输出逐字节一致。随后发布仅增加本文验证记录、原始日志归档和 SDK 来源说明，
不改变被测 Python/CI/Rust 字节。

[Python validation](python-validation.json) 保留 **254 项通过**：新门槛 27、新阶段回读
11、原 v2 回读 11、CI 合同 102、PQ 源码负例 37、仓库负例 50、项目边界 16。
仓库检查另核对 26 packages、25 条正常依赖边、1169 个 Rust 文件及 3489 个本地链接；
分布式源码清单、562 个固定 blob、shell 解析和拒绝资格提升检查通过。

[Rust validation](rust-validation.json) 在同一提交上通过 locked/offline metadata、
all-features metadata、完整 formatting 和 workspace/all-targets/all-features Clippy
（`-D warnings`）。默认图 175 packages，完整 features 图 180 nodes；均 26 workspace
members。1198 个 Rust/manifest/lock 文件指纹不变。没有执行 native 测试、原业务
campaign 或新 W1 proof；这些成功不替代其原有独立门。

[完整归档索引](validation-index.json) 绑定 [原始日志归档](validation-raw.tar.gz) 的
每个成员。最初的工具链分派失败和 offline cache 缺包失败都保留；最终使用已有且与
Cargo.lock 全部 154 个 registry SHA256 匹配的本地缓存，以原 flags 完成检查。
没有变更依赖版本或 Cargo.lock。

Python 收集器的首版汇总误把两份命令元数据作前后 identity 比较，产生 false 汇总；
所有实际检查命令仍退出 0，原 source-checker stdout 中的完整 identity 逐字节相同。
原误报、所有 stdout 哈希、独立 identity 副本和机械重算说明均在归档中保留。
修正只恢复正确的日志比较，没有重标测试结果或科学观察。
