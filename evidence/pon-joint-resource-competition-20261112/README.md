# 联合 DAA、chainwork 与资源竞争证据

本证据包把固定目标对照、当前整数 DAA 镜像、完整 native W1 有限轨迹和原始执行记录放在同一审计链中。正式场景观察显示：在本轮特定资源时钟假设下，周期性目标策略与固定目标对照产生不同的已采纳量子区块信用。结论仍为 **HOLD_NO_GO**；这些有限观察不能给出真实量子攻击的成功概率、公共前缀失败界或生产启用依据。

## 1. 来源与执行边界

| 身份 | 提交与用途 |
|---|---|
| A | 43e5c9d6b668276d03e1c7a76f467ec211e1d7dc；tree beac87c2431d149dbd6d2de4a2e1eaf0617520cc。实际执行 242 项 formal tests、预先固定的 128 场景与计划内 replay、native 工具链及 4 个 DAA 原测试、独立 reader，以及原始 CI 审计。 |
| A2 | 17449baa42429ac98b55c100b1c523ff0abe40d0；实际 tree 见 [source-provenance.json](source-provenance.json)。A 的直接后继，只修复 CI 命令归属检查及其对应当前 corpus pin，并完成独立的 7 项 CI 验证。 |
| A → A2 | 只改变 scripts/ci/check_ci_contract.py 和 config/pon/pq-cross-branch-corpus-v1.json。所有其他 Git tree 路径与 blob 相同。 |

A 的前后全源检查覆盖 26,711 个 tracked entries、2,542,453,893 字节。A2 有自己的前后全源原件；A 的 native/formal 结果始终标为在 A 执行。源码等价关系不能改写原执行提交。

原 cloud 开发阶段的终态仍为 UNKNOWN。旧 archive、开发观察与失败记录单独保留，不借它们补充 A 的通过结果。创建 CI 修复工作树之前没有 common Git config 的前置哈希，因此 pre-add 不变性保持未证实；修复例程内部的前后哈希一致另有原件。

本次收集器只校验已有原件、做完整哈希回读并生成包，没有重新执行测试、模拟器或新增独立样本。

## 2. 工作假设与预先固定的实验

研究顺序是先用固定目标对照分离搜索/证明时钟，再加入当前整数 retarget、clamp、时间戳和 chainwork/fork choice 的模拟。Native 原件验证对应规则下真实 W1 packet 的合法有限轨迹。

正式 roster 的笛卡尔积如下：

| 轴 | 固定取值 |
|---|---|
| Seed | 6101、6102、6103、6104 |
| 假设量子迭代时钟 | 0.15 模拟秒、0.05 模拟秒 |
| 环境 | steady；传播延迟参数 8 模拟秒；参与容量变化；量子/经典证明成本分别 20 模拟秒/1 模拟秒 |
| 目标策略 | fixed-target；periodic-target |
| 量子矿工策略 | honest-tip；私挖并在 2,700 模拟秒释放 |
| 每场景观察区间 | 3,600 模拟秒 |
| 每场景 CPU 限制 | 10 个 Python CPU 秒；没有早停或事后放宽阈值 |

共 128 个场景、64 对策略比较。Replay 是计划内对相同 seeded 场景的第二次执行，不是另一批独立样本。每对的非策略参数及其规范 JSON 哈希相同；各方获准的容量、观察时间和模拟网络参数相同，实际付出的资源消耗会随策略和执行进程变化。

这里相等的是模型明确声明的资源预算。完整 W1 相干可逆电路的真实成本尚未绑定；物理资源公平性、实际网络字节预算均未取得资格，任务供应变化实验仍为 UNIMPLEMENTED。不能把 0.05 秒或 0.15 秒解释为已有量子硬件能力。

完整参数、每次执行结果、资源收费回读和压缩事件轨迹位于 [campaign/roster.json](campaign/roster.json)、[campaign/report.json](campaign/report.json) 与 [campaign/manifest.json](campaign/manifest.json)。该目录恰有 259 个文件：128 个 case JSON、128 个完整 JSONL gzip、roster、report、manifest。

## 3. 观察结果

比较量是 observer 最终所选分支上，量子矿工新增区块的 integer required-work 总和；每对取同一参数/seed 下的私挖策略值减去 honest-tip 策略值。下面的“更多”不是攻击成功率。

| 目标策略 | 比较对 | 私挖信用更多 | 相同 | 更少 | 信用差之和 |
|---|---:|---:|---:|---:|---:|
| fixed-target | 32 | 0 | 3 | 29 | -165,403,879 |
| periodic-target | 32 | 16 | 3 | 13 | 2,187,125,401 |

分解到假设量子时钟后：

| 秒/量子迭代 | 策略 | 比较对 | 更多 / 相同 / 更少 | 信用差之和 |
|---:|---|---:|---|---:|
| 0.05 | fixed-target | 16 | 0 / 0 / 16 | -148,780,966 |
| 0.05 | periodic-target | 16 | 16 / 0 / 0 | 2,199,728,042 |
| 0.15 | fixed-target | 16 | 0 / 3 / 13 | -16,622,913 |
| 0.15 | periodic-target | 16 | 0 / 3 / 13 | -12,602,641 |

全部 16 个正向信用差都位于本轮 0.05 秒假设。这是条件化模型观察；既没有把 seed 范围推广为未来攻击分布，也没有把信用差换算成硬件经济收益。

保留的 128 个场景共创建 53,964 个区块、记录 543,115 行轨迹，出现 16 次 probe confirmation reversal，最大 observer reorg depth 为 260。这些是完整保留样本中的描述性计数，不是 common-prefix、确认失败或全生命周期风险界。

诚实节点的快速出块没有被全面拒绝：32 个诚实 periodic-target 场景中，5 个场景实际接受了合计 5 个正跨度短 epoch；全部 128 场景合计接受 103 个此类 epoch。该计数覆盖生成并接受的区块，不限于最终 canonical chain。

[fullanalysis.json](fullanalysis.json) 原样保留 73,566 字节的完整 posthoc 分析，包括全部 64 对差值、环境/时钟分组、原始 probe 字段汇总及极值详情。它的 SHA256 为 b5139d1353e7bebe7f4702ec6931a98133143e945ee8c039b62a51ba715f3d65。Posthoc 没有删除 seed、调参或产生新样本；完整脚本、输入哈希与执行原件保留在 archive 中。

## 4. Native 有限轨迹与独立复读

A 实际执行原有 4 个 native integration tests，分别覆盖 PNH1、PGH2 以及两种时间戳安排：重复负 endpoint 跨度和严格递增的压缩跨度。每个 profile 保留 114 个实际 W1 packets，原件均通过独立 Python reader 的完整 transcript/product 复算。

| 原件 profile | 完整复核 proofs | Reader controls | 结果 |
|---|---:|---:|---|
| joint-daa / PNH1 | 114 | 22：21 pass、1 不适用 skip | PASS |
| joint-daa / PGH2 | 114 | 22 pass | PASS |
| monotone-daa / PNH1 | 114 | 26：25 pass、1 不适用 skip | PASS |
| monotone-daa / PGH2 | 114 | 26 pass | PASS |

合计 96 个 controls，94 pass、2 个保留的合法 skip。4 组原件不能作为 456 个独立攻击样本计数。

这些轨迹中，普通分支高度 65、累计 required work 130；被选择分支高度 64、累计 required work 793。严格递增安排也能保留该有限轨迹，说明只拒绝非单调时间戳不能完成联合安全性论证。这里检查的是逻辑时钟下、实际 W1 工作与原生 admission/fork choice 的合法性；它没有证明相同真实时间和硬件资源下能击败诚实网络。

独立 reader 明确保留边界：它不重放全部失败 nonce、不替代原生数据库重开、AAM1 account proof、任务资格或 M06 执行，也不认证运行主机。它给出 transcript 与原件一致性检查，而不是工作难度下界或量子攻击盈利性证明。

## 5. 本轮修复与资格检查

### 概率采样

旧模拟器用 random() < p。Python 官方文档说明默认 random() 以 2^-53 为网格；在均匀 53-bit word 前提下，p=2^-60 时仅零值被接受，概率为 2^-53，是目标概率的 128 倍。

新 helper 使用 float.as_integer_ratio() 与 getrandbits，对已经表示成 binary64 的 p 做精确 dyadic Bernoulli 采样，并处理 0/1、次正规数和非法输入。它不证明 PRNG 或硬件独立性，也不消除上游 Grover 振幅的浮点误差。相关 campaign/assumption/replay 使用新 namespace，历史原件不被改写。

出处：[Python random 文档](https://docs.python.org/3.11/library/random.html)。

### 实际完成的检查

| 来源 | 检查 | 结果 |
|---|---|---|
| A | 11 模块 formal suite | 242 个唯一 methods，全部 OK、无 skip |
| A | 固定 128 场景、64 对、计划内 replay | 全部 horizon/readback 完成；无早停 |
| A | Cargo default / all-feature / 独立 fuzz graph | 最终全部 --locked --offline 成功 |
| A | fmt；workspace/all-targets/all-features strict Clippy | PASS，保留 -D warnings |
| A | 原 4 native DAA tests、4 full readers、4 controls suites | PASS，保留两个不适用 skip |
| A | 源码完整性负向 suite；PQ corpus 负向 suite | 43 / 57 项通过 |
| A | 原始完整 CI contract suite | 169 项实际执行，2 个负向子用例失败，原件保留 |
| A2 | 未改动的完整 CI contract suite | 169 项通过，无 skip |
| A2 | 七项验证、当前 corpus、仓库与 Markdown links、前后源码检查 | PASS；915 个 current source pins，qualification 仍 HOLD_NO_GO |

Native controller 有 27 条命令观察，不能写成“27 条都首次成功”：一条初次 locked/offline metadata 命令实际非零退出（精确命令名与退出码见 [native-execution-summary-A.json](native-execution-summary-A.json)）；它的完整原始失败保留，随后仅补齐锁定依赖，并用原 locked/offline 命令复验。源锁、provider inputs 与源码前后检查均保持一致。OpenSSL 3.5.9 由原仓库脚本按固定 archive SHA 构建，保留真实 ML-DSA-65 正/负 smoke；这不是整个量子密码系统的资格结论。

A 的两个 CI 子用例暴露了真实缺口：把新增两条测试命令重复塞进 fuzz lane，原检查器没有拒绝。A2 增加全局出现次数及 repository-truth lane 归属检查，更新对应单个 corpus pin；原 169 项测试没有被删改，原失败没有被覆盖。

## 6. 文件与原件

| 路径 | 内容 |
|---|---|
| [summary.json](summary.json) | 机器可读汇总与资格边界 |
| [source-provenance.json](source-provenance.json) | A/A2 身份、精确两文件差异与执行来源 |
| [raw-archive-inventory.json](raw-archive-inventory.json) | 9 个 lossless archive 的逐原件 bytes/SHA |
| [archives/source-freeze.tar.xz](archives/source-freeze.tar.xz) | 完整 source freeze 与 precommit 原始记录 |
| [archives/development-controls.tar.xz](archives/development-controls.tar.xz) | 开发阶段原始记录，单独保留 |
| [archives/formal-validation-A.tar.xz](archives/formal-validation-A.tar.xz) | A 的六阶段计划、日志、receipts 与原始清单 |
| [archives/ci-validation-A-failed.tar.xz](archives/ci-validation-A-failed.tar.xz) | A 的完整 CI 观察，包括两个失败 |
| [archives/native-validation-A.tar.xz](archives/native-validation-A.tar.xz) | A 的全部 native 日志、tool/provider/source receipts、4 组 report/packets 与 reader 原件 |
| [archives/ci-repair-A2.tar.xz](archives/ci-repair-A2.tar.xz) | CI 修复、完整 diff、未改原 tests 的身份记录及 A2 七项验证 |
| [archives/posthoc-description-A.tar.xz](archives/posthoc-description-A.tar.xz) | 原始 posthoc 9 文件，含完整分析、脚本及输入哈希 |
| [archives/collector-v1-failed.tar.xz](archives/collector-v1-failed.tar.xz) | 第一版收集器的 FAIL、原 status、driver/helpers 与失败日志；原目录未改写 |
| [archives/collector-comparison-diagnostic.tar.xz](archives/collector-comparison-diagnostic.tar.xz) | actual/expected 递归差异与 A canonical 原文；只读 diagnostic，不作资格证据 |
| [original-attempts/cloud-development-preserved.tar.gz](original-attempts/cloud-development-preserved.tar.gz) | 原 cloud 10 文件 archive；终态 UNKNOWN 保持不变 |
| [manifest.json](manifest.json) | 本包除 manifest 自身之外每个文件的完整 bytes/SHA 清单 |

Archive 仅规范容器元数据，成员内容逐字节保留，并在打包后完整回读。构建 target、私有 Cargo cache、provider 构建/安装目录及 smoke 私钥留在受控外部工作区，不属于公开证据包。记录中的路径和哈希是可复核的运行观察，不构成可信执行环境证明。

### 收集器格式错误与修正

第一版收集器实际返回 EVIDENCE_REPORT_COMPARISON，未产生可发布 packet。原因是验证器计算 resource-premises SHA256 时漏掉了 A 的 canonical JSON 约定中的末尾 LF。只读 diagnostic 将 64 个实际 SHA 与无 LF 的旧预期逐项对照；全部差异均由该一个字节解释，pair 顺序、预算、信用数值、文案及其余 metadata 未改变。第二版只修正这一处哈希编码约定，并重新完整校验已有原件。

[collector-v1-failure-summary.json](collector-v1-failure-summary.json) 保留原 FAIL；[collector-diagnostic.json](collector-diagnostic.json) 保留实际值、旧预期与 A 源码约定。Diagnostic 的 equality override 仅用于定位差异，明确为 DIAGNOSTIC_ONLY_NOT_QUALIFICATION；最终发布条件仍是独立的严格 v2 完整回读通过。本过程没有重跑模拟器或测试，也没有改写 case/report/manifest/source。

## 7. 尚未关闭的问题

固定 profile 且每次完整 oracle 成本不随难度变化时，经典搜索成本约与 D 成正比，理想相干 Grover 搜索约与 sqrt(D) 成正比。若信用取 D^beta，对应单位资源信用率分别为 D^(beta-1) 与 D^(beta-1/2)。因此只改 chainwork 指数有条件化反例；这里没有给出针对所有共识设计的不可能定理。

要得到部署资格，仍须绑定完整可逆算术、哈希、内存、清理与搜索过程的资源成本，补足真实网络字节预算、任务供应变化、动态参与与 epoch 边界的联合分析，并给出公共前缀、链增长、链质量及确认风险的适用条件和界。

现有 Fast DAA author-slides exact-rational component 是对照研究组件；它没有实现完整 Fast DAA 协议，也没有取得适用于 W1 混合量子算力的完整定理资格。本轮全文获取仍受阻，摘要、元数据与官方解释不能替代定理条件核查。[Fast DAA 记录](https://eprint.iacr.org/2026/1116)；[Bailey–Sattath](https://arxiv.org/abs/2403.08023)。

Joint qualification 保持 18 个 unknown inputs、13 个 open proof obligations、HOLD_NO_GO，production activation=false。
