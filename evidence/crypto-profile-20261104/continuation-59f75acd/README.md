# `crypto_profile_id`：固定 59f 阶段证据

**状态：HOLD / 六域 UNQUALIFIED。** 本目录保存对固定提交
`59f75acd1d4261972b8aaa45e0c36259fcafd45c`、tree
`c0dc8282e5b2618ffb35061f108bb2fa96e9b348` 的实际观察；它不是后续发布提交或远端最新代码的测试证明。24份终结命令收据中，23项成功、1项失败；对应日志的字节数和 SHA-256 已核对，全部收据记录相同的执行前后源码身份。源码身份核验覆盖8,908个 tracked entries、944,718,751字节，本身不执行测试。

本阶段完成了配置／密码基础库验证、源码门禁与一次65／87参数观测。保留 ML-DSA-65 基线，ML-DSA-87 仍为未激活候选；没有网络激活、部署账户迁移或整链 PQ 合格声明。

## 1. 实现与信任边界

固定59f的注册表以规范编码绑定签名算法／参数／模式、编码及域隔离、按用途指定的哈希、网络／创世／协议与激活窗口、消息与累计资源限额。`crypto_profile_id` 从这些配置生成，来件只能与可信状态选出的配置比较，不能自行协商弱配置获得授权。

`CurrentCryptoProfile` 与 `HistoricalCryptoProfile` 分离；当前使用仍须重验 generation、ID 和有效高度。候选 CPQ1 的完整签名消息绑定权限字段、payload、签名人集合、网络与配置 ID，解码拒绝非规范长度及尾随数据。配置构造器只校验结构；可信状态的真实性、消息的业务授权及已接受历史记录的来源仍属于真实 owner 的责任。

候选限额为65,536 B签名消息、131,072 B完整 wire、8个签名人、64次累计验签预留、8,388,608 B累计计费；失败不退还预算，耗尽后锁定。这些候选接口的存在不表示所有账户、治理、发布、CURRENT、FinalUse及恢复 owner 已迁入。

**尚未在59f实现的历史迁移：** 最初以 `retirement_height=None` 进入 CURRENT 的配置，不能通过改成 `Some(end)` 再绑定来保留原 ID。旧历史 API 要求预先声明结束高度，因此后续退休存在失败关闭的功能缺口。独立的可信有效退休登记补丁已完成静态审阅，新增8项针对性控制，但在本阶段仍为 **UNAPPLIED / UNTESTED**；这些控制没有计入下文通过数。新补丁须在实际新源码上验证，不能继承本阶段收据。

## 2. 实际完成结果

完整 argv、环境、退出码、日志身份及前后源码见 [reproduction.json](reproduction.json) 和 [raw-observations.tar.gz](raw-observations.tar.gz)。24是命令收据数量，不是测试用例数量。

| 范围 | 本阶段真实结果 |
| --- | --- |
| `trnm-crypto-primitives`、`trnm-protocol`，原命令 `--locked --offline --all-features --lib` | **237通过，0失败，2忽略**：分别143通过及94通过／2忽略；无过滤 |
| `trnm-protocol --doc` | **2通过**，包含历史／当前类型边界的 compile-fail 控制 |
| 5个原 Python unittest suites | **106通过**：34 + 4 + 35 + 22 + 11 |
| 12项源码／CI门禁 | 全部命令成功；其中包括上述5个 unittest suites，不重复增加测试数 |
| workspace `cargo metadata --locked --offline --all-features` | 成功；180 packages／180 resolve nodes |
| 独立 fuzz workspace 的同等 locked／offline 图解析 | 首次缺少 `libfuzzer-sys`，退出101；补齐独立缓存后重试成功，147 packages／147 resolve nodes；两份收据均保留 |
| workspace formatting | 原 `cargo fmt --all -- --check` 成功 |
| release 参数程序构建、运行及独立 reader | 三条原命令均成功；32场景、288项测量、18,432个原始样本值 |

两项 ignored 是显式完整构造／状态根成本观测，不是运行通过：
`bulk_complete_construction_cost_observation` 与
`state_node_and_complete_root_paired_cost_observation`。

源码门禁包含 preflight、配置独立 oracle、inventory、source pins、claim guard、repository、CI contract及5个 unittest suites。Source pins 成功核对462个 blob，结果仍为 `HOLD_NO_GO`；claim guard 六类均保持 `UNQUALIFIED`。详见 [源码门禁汇总](current-source-gates-summary.json)。负面测试打印的预期拒绝不另算命令失败。

**本59f阶段明确未运行：** M06单元及五组集成目标、完整 Node lib-test build、Node network／continuous-owner 测试、当前49项 required controls、workspace strict Clippy、独立65／87互操作矩阵。本阶段在保存已完成证据后结束，以便对退休修复的新源码进行后续验证；这些项目不是 unknown，也没有从旧结果借用通过信用。两项成本观测仍为 ignored。

## 3. 65／87参数观测

原始 [parameter-observations.jsonl](parameter-observations.jsonl) 为296,115 B，SHA-256：
`c7c29cc69dd54e4457d22327aeb8f6f3ea27587caab54d6a5dd968b3a68c8b95`。
独立 reader 实际重算全部18,432个样本值与摘要，输出 `PASS`。矩阵为2种算法 × 4种消息长度（0／176／4096／65536 B）× 4种签名人数（1／2／4／8），每场景9种操作、每项64个样本。

| 参数集 | NIST类别 | 公钥／签名字节 | 176 B消息、1签名人的观测帧大小 | 65536 B消息、8签名人的观测帧大小 |
| --- | --- | --- | --- | --- |
| ML-DSA-65 | 3 | 1,952／3,309 | 5,456 B | 107,671 B |
| ML-DSA-87 | 5 | 2,592／4,627 | 7,414 B | 123,335 B |

参数与原始编码长度见 [FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)。NIST类别不能直接换算为整条系统的量子安全位数；[NIST IR 8547 final](https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8547.pdf)也按用途区分哈希的碰撞与原像安全分类。帧大小是实际生成的 `TRNMCPB1` 观测格式，**不是CPQ1／PNQ／NPQ交易格式**，不证明生产消息预算已经通过。多签容量仍需按真实协议的完整 metadata、payload、公钥和签名集合核算。

以176 B消息、1签名人的此次观测为例，签名＋编码＋自验＋释放的 p50 为65的262.018 μs、87的612.846 μs；观测帧 preflight＋verify 的 p50 为85.677 μs和87.489 μs。它们是具体组合操作，不能解释成独立签名或所有生产验签路径的耗时。

程序采用 Pure ML-DSA、空 FIPS context、确定性签名与固定重复 fixture；九类操作包括 keygen、key import、签名与自验、正确／错误签名验签、尺寸早拒绝、帧编码、preflight及完整观测帧验签。每项64个样本的 nearest-rank p99 等于样本最大值，不形成生产尾延迟估计。

运行环境为x86_64 Linux、rustc／Cargo 1.95.0、release opt-level 3，CPU型号AMD EPYC 9V74。容器可见9个逻辑CPU、CPU配额8核、内存上限8 GiB；共享负载未受控。程序在2026-11-05 00:44:23–00:44:51 UTC运行，进程峰值RSS为11,136 KiB。这是整个观测进程的资源记录，不是单次签名的峰值内存或网络吞吐资格。

被运行二进制为原 `pq_parameter_bench` Cargo example，766,128 B，SHA-256：
`ab27cc3c65fb0cdca4fc1d1272a67aceaaba703b3611cda0e4875044f1cb032e`。
构建 artifact、原命令收据、运行环境、stdout／stderr身份与独立 reader 结果保存在原始归档中。没有借用ad081的二进制或性能数字。

## 4. 哈希、共识与并发源码边界

逐路径 blob 与实际读取的函数范围见 [885→59f比对](current-source-comparison.md)／[JSON](current-source-comparison.json)，以及 [59f→ac240比对](current-to-publication-comparison.md)／[JSON](current-to-publication-comparison.json)。这是有界审查，不是全仓 owner 迁移或全仓哈希覆盖证明。

| 用途 | 已确认边界 |
| --- | --- |
| 注册表 ID及候选按用途 commitment | SHA-512、64 B；候选 helper 对用途、配置、长度、完整内容作绑定；不等于所有生产 owner 已采用 |
| legacy key／payload | 分别为带域前缀的 strict SPKI SHA-256／32 B及域分离 SHA-384／48 B，保持既有编码 |
| PNQ policy digest | 独立 SHA-256／32 B，不是新descriptor ID |
| M15 release／recovery owner | 未接入 `crypto_profile_id`；root identity及checkpoint为SHA-256／32 B；SHA-512／64 B签名消息摘要不把它变成HashML-DSA或注册表集成 |
| M15 content | 一般role的content是非零32 B不透明标识；只有已读NodeSoftware bundle路径明确绑定V0 SHA-256 bundle identity |
| native W1 challenge／ticket | 既有SHA-256／32 B及工作关系不变；SHA-512 work-reference不改变实际工作哈希 |

原49项 required 名单在885→59f及已审阅ac240差异中未变；这只是名单身份，不能算49项执行通过。后继ac240另修复恢复 admission／journal校验和M15 CURRENT的root generation／expiry约束；这些改动不属于59f测试源码。其独立并发记录中的4项Unix daemon失败保持原范围和状态，不从本目录237项基础库通过数中抵消，也不被覆盖。

并发分支后来发布了 [cbdd98dc 的独立 committed-source 记录](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/cbdd98dc16398d6a21e02364c71f0856742b3a72/evidence/pq-recovery-release-sdk-v1/committed-source-checks.json)。本目录的ac240审查保留其原始截面；后来的18条独立源码记录也不会转换成本目录59f的执行信用。

## 5. 历史证据与后续验收

[原ad081原始记录、归档及样本](../README.md)保持原字节和来源身份；原README只追加续接入口，其历史正文保留：26条命令记录为23成功／3失败，两次Node构建及一次Clippy出现SIGKILL，具体根因仍未确认。旧45项required、Node network和continuous-owner未执行。

885阶段未归档的续接日志已丢失；[continuation-loss-notice.json](continuation-loss-notice.json)保留事实，不能由口头进度重建结果。本目录24份收据是59f的新实际观察，不改写ad081或885历史。

后续需在应用可信有效退休登记后的真实组合源码上验证新增8项控制，并完成尚未执行的业务／原生门禁。配置或哈希用途的生产采用仍由各owner迁移规则约束；W1挑战、ticket或完整关系的变更必须形成新的工作配置及工作安全分析。本目录不授权候选上线，也不缩小[整链PQ声明约束](../../../docs/security/WHOLE_CHAIN_PQ_CLAIM_GUARD_20261031.md)。
