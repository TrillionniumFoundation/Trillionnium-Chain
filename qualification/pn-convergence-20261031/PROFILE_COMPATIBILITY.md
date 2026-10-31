# PN0 实际配置兼容矩阵

**状态：HOLD。源码组合、兼容性、原生行为和同配置联合验收是不同的事实。**
本记录延续唯一 PN0–PN6 计划，不是新的路线图、资格开关或运行时配置。
JSON 的 16 条 `current_native_evidence.result` 均为 `UNQUALIFIED_COMBINED_PAIR`；
实际日志、测试源码、二进制和配置字段仍待按保留证据填写。最终 Chain commit/tree
及锁文件摘要也须明确记录；未取得联合资格和空字段都不能按通过处理。

## 精确对象与原 pair 的边界

- Chain：官方 #632 `622f9d50f081f6807408e401b790a7c7255b8f08` 与 #634
  `6e43cae914e3fe16b6439539dc5d00ff01952f13`，以官方共同基线
  `bbc511c7942de24b75054d1b4c3e5d0e4f4a5ab3` 合入，加当前联合运行时代码。
  最终提交尚由集成 owner 填写；JSON 另保存了本次逐文件实际 Git blob/SHA-256。
- Hepta：#4497 `39775e10083ebfb3df63a587375b4be7d493b109`，为 #4491 后继。
  本次检查过程中共享源码推进到同预算后继 `3ba22376cc496d9bb1129ad0fa1146b32f1f73d8`；
  它单列为 reviewed runtime successor，保留为启动预算变更的历史范围；当前源码索引另按下述 b93 核对。
  它保持原启动预算/取消 token；本记录仍标明联合 pair 未取得资格，不继承 39775 的观察。
- 当前再检查 Hepta #4497 的明确 image-gate 后继 `b93b7c3fc58d088baad281389547264894e864ef`，tree `2bebc6dc248af4f6f0b3b358e35295794a1f8b46`。H1–H16 均逐文件核对该实际提交；
  H1 与新增 H15 含 Cell-v2 的 pre-owner image 拒绝，普通 helper dispatch 与 owner-v1 保留。
  3ba 仍是原启动预算变更的历史范围；不能由 fmt/actionlint 或旧结果推导 b93 原生准入通过。
- #4497 的原 paired CI 仍指定 Chain source
  `c16507147b65285ea94dead22d3b93c5db7295af`，base
  `1d11f875493f8125e36b9adceacb342df108e5e5`，merge lane
  `d1b8ae970bb5e014b6feaa49030823e1d8228c90`。该 pair 不是当前联合 Chain。
  来源：[固定工作流](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/39775e10083ebfb3df63a587375b4be7d493b109/.github/workflows/hepta-pon-native-pair.yml#L110)。
- 本次重读官方 [bbc…c165 compare](https://github.com/TrillionniumFoundation/Trillionnium-Chain/compare/bbc511c7942de24b75054d1b4c3e5d0e4f4a5ab3...c16507147b65285ea94dead22d3b93c5db7295af)：
  **diverged，ahead 130 / behind 189**，merge base
  `4b6b8a91b6dfe41fbd7f40f40b359d535c2c4251`。因此不能把 c165 视为 bbc
  的顺序更新，不能把旧 pair 结果当成当前组合的结果。
- Hepta PQ #4368 `a575cf03e2bc871a2f48021859c03ace806421c8` 未合入当前 pair。
  本矩阵不拼接该分支的资格记录。#4497 本身已有部分 ML-DSA API，仍须追到
  实际调用者，不能由某个模块存在推导整个普通 host 已切换。

## 配置、准入与拒绝矩阵

下表中的“有实现”只说明本次检查的代码路径。JSON 明确标记每条联合 pair 尚未取得
资格；组件运行结果应逐条绑定实际日志、源码、features 和 protected profile，不能以
`UNQUALIFIED_COMBINED_PAIR` 代替执行记录，也不能把组件通过改写为联合通过。
源码索引 C/H 对应 JSON 的 `inspected_sources`，包括确切路径、blob 和定位行。

| ID | 路径 / 实际选择 | 必需配置和 owner | 关键拒绝点 | 能够得出的范围 |
| --- | --- | --- | --- | --- |
| M01 | PNQ2 / `PqNetworkV2`；应用另选 NPQ6/PQP6 | `open_with_pq_network`，受保护 Settings、peer SPKI/policy、fresh namespace | `PQ_NETWORK_CONTEXT`、`PQ_NETWORK_BACKEND`、`PQ_ACCOUNT_REQUIRES_PQ_NETWORK_OWNER`、`PQ_NETWORK_OWNER_COMBINATION` | 明确选定的传输实现；PQ 传输可配经典 ledger，但经典传输不能因此处理 PQ account。没有生产保密或 WAN 资格。C1–C3 |
| M02 | 经典 V1/V2/V3 client、outbox、普通 sync 与 PQ owner | Settings 拒绝与实际 owner 拒绝都需要 | `AUTH_CLASSICAL_FOR_PQ_PROFILE`；即使 ledger 经典，PQ owner 仍触发 `PQ_NETWORK_REQUIRED` | 正确拒绝降级，不是经典客户端迁移完成。C1、C3 |
| M03 | native-growth / `PermanentAccountGrowthV2` | `with_permanent_account_growth_v2`；continuity-dev-v1；fresh growth context、精确 limits | `GROWTH_PROFILE_SOURCE`、`GROWTH_PROFILE_BACKEND`；opener 不带 PQ/continuous owner | **不能把 growth 与 NPQ6/PqContinuousV3 的各自通过汇成一个 backend/profile 通过。** C1、C4、C5 |
| M04 | 经典 continuous / Legacy | 原 protected launch、source/package/role pins、task/catalog、Journal、CPU owner | owner/profile/context/lease/frontier 冲突；`OWNER_MODE_AMBIGUOUS` | 保留原受限 continuous owner；没有自动得到 PQ 或通用 History 权限。C1、C6、C7 |
| M05 | 显式 PQ continuous / `PqContinuousV3` | PQ-v3 identity/launch；只含公钥的 StartupSpec 先定 genesis；恰好两个真实 OPEN/REGISTER 工作包；原 Journal/allocations | `OWNER_CONTINUOUS_PQ_FRESH_STARTUP`、`OWNER_CONTINUOUS_SETTINGS_CONTEXT`；generic opener 不接管该 namespace | 独立构造的 continuous+NPQ6 实现；不是 growth、旧库迁移或任意分叉恢复。C1、C6、C7 |
| M06 | continuous History 单页单包 extension | exclusive receiver；complete、一包、next=tip、after=current parent；原 signed validation/activation 对、generation、raw digest、nonce 授权和同一预算区间 | 多包/不完整/shared 路径：`OWNER_CONTINUOUS_HISTORY_DURABLE_REQUIRED`；另有 parent/pair/replay/native Work/M06 检查 | 窄 receiver 实现；一般发现/多页/任意分叉仍拒绝。PPH4/PPS4 的 paid History 传输与 PNQ2 SQLite replay 预算不同。C6、C8、C9、C18 |
| M07 | research authenticated archive + PQ application | 仅原支持的 application | `UnsupportedProfile`，在 SQLite/progress 前 | 此组合明确不支持；拒绝不是 archive/父恢复迁移。C10 |
| M08 | TCD retrieval / `content-cache-v1` | 显式 authentication profile；独立 TCD id/context/profile/generation/roles；finite peers；原缓存和取回预算 | 缺 profile、wrong context、非法 graph/path/membership/TCM/hash/资源边界 | 内容完整取回；marker 不授予 selection、lease、付款、CURRENT 或 FinalUse。C11–C14 |
| M09 | TCD retrieval / `cell-pq-v2` | M08 的独立 TCD pin，加 CPR2、独立 signer/key/generation/sequence/context/lifetime | 坏/过期/错绑定 CPR2 在 cache/dial 前拒绝；没有 content-cache fallback | **PQ 签名认证嵌入的 TCR1；不自动认证任意 TCD wrapper 元数据，也不认证 Hepta use。** C11–C14 |
| M10 | 普通 Linux Hepta `--host-format cell-v2` | b93 先要求实际 image 可重开且 dev/ino 一致；新严格 host schema；protected host/sidecar/TCD hash 和 operation；原 descriptor FD/CURRENT/selector；实际固定 11 对象，独立 TCD 重建 | wrong schema/pin/op/member/profile/generation；失败不回退 owner-v1；取消/错误终止原路径 | 对该窄模型 profile 的普通 host 接线；后继在排队前固定一次原 120 秒，Cell/FinalUse/load 共用 deadline/token、durable admit 仅取剩余时间；阻塞 OS read 返回后才能确认结束。匿名 image 在 dotenv/aliases/owner 前拒绝；没有新发布/学习/PQ 资格。H1–H5、H12–H15 |
| M11 | 原 installation/CURRENT/普通 inference FinalUse | v3 product bootstrap、原选择 FD/owner；resource grant、durable inference journal、独立 Unix issuer | 原 qualification/CURRENT/resource/issuer 门禁；普通 host 调 `UnixFinalUseAuthorizer::open` | **该调用读取 32-byte key 的 V1 config，实际构造 Ed25519V1。cell-v2 当前不是 PQ FinalUse。** 它消费原选定 descriptor；取回成功不发布新 artifact、不改 CURRENT。H3、H6、H7、H9、H10 |
| M12 | 独立 ML-DSA FinalUse V2 API | 显式 `open_ml_dsa65_v2`、V2 config、外部 clock/frontier/issuer roster | 错 schema、key/generation/frontier、跨 profile 签名；没有 V1 fallback | API 存在，但 M11 普通 host 没有调用它；不能引入未合并 #4368 的结果替代接线和验收。H3、H6、H8 |
| M13 | M06 → M12 → M09 retirement | 原可信 journal；exact completed claim/op/effect/window/receipt、同链 context/current height | 未完成 effect、未知意图、错 chain/source/binding 不释放容量 | 同链重组 reconciliation；不是 finality、第二账本或远端 journal 身份认证。C15、C16 |
| M14 | PN6 growth rehearsal | 原 source-preserving archive、隔离 destination、READ_ONLY cold verify | source/schema/context/readback/pending 错误拒绝；原五个 migration/activation/import flags 仍 false | 组件演练；不导入外部 M09/M12/revocation owner，不关闭前序阶段或授权部署。C17 |
| M15 | Chain producer / handoff-v2 / `sealed-elf-v1` | 独立 handoff/host/ELF/sidecar/TCD pins、原 Fleet/workspace、精确 11 文件；显式 content 或 PQ policy；Linux sealed memfd | 缺 owner/seals：`NOT_CONFIGURED`；错 pins/schema/roster/profile/context、loader env（含空值）、PQ withdrawal/过期及晚到均拒绝；Hepta b93 另在 owner 前拒绝匿名 image | 主 ELF/数据/argv 控制不等于普通宿主成功。memfd 不支持原可重开 helper 路径；此配置被原生入口明确拒绝，不自动切换 M16。C19、C20、H1、H15、H16 |
| M16 | Chain producer / handoff-v3 / `protected-installed-elf-v1` | M15 的原 owner/data pins；独立选定 root 安装 ELF；同一非零 real/effective/saved/fs UID、四类 capabilities 为零；image/祖先 root-owned 且 caller 不可写，禁 SUID/SGID/file caps；原 SHA + held FD | 错 schema/profile、凭据、权限、哈希或路径/inode 拒绝；exec 前重查；Hepta preflight 重开实际 image 并匹配 `/proc/self/exe` dev/ino；无 fallback、无 sandbox 放宽 | 可保留原 regular helper 路径的独立配置；root 安装者与版本 inode/路径生命周期属 TCB。本地 root 安装前提未满足，不是假通过；仍缺同配置真实普通 helper/sandbox、模型与安装验收。C19–C21、H1、H15、H16 |

### Producer 配置的独立边界

M15/M16 要求原 owner 在运行前独立提供完整 host、sidecar 和 TCD 的预期字节哈希、
TCD domain id、generation、loader profile 和原生 ELF 哈希。producer 只比较这些值；
它不自签 CPR2、不生成 descriptor/grant/issuer、不创建 Fleet、不改 CURRENT，
也不将原 `original-v1` 的失败边界切换为新模式。PQ 路径消费最初校验的 CPR2/SPKI
快照。M15 的主 ELF 复制并封印后再按独立哈希验证，原路径替换和同 inode 改写
不能改变该主镜像；其缺 Linux memfd/seal 能力时不会回退到原文件或 M16。

三个时间范围分别保留：原 release preparation 的 **120 秒**覆盖导出与快照/TCD
写入、fsync 和尾检查；**35 秒**传输覆盖完整取回、仅缓存物化和最后读回；原 Hepta
**120 秒**启动窗口覆盖其 Cell 复核、qualification、FinalUse 与物理加载。前一阶段
的成功不补充后一阶段预算，也不授予后续权限。

主 ELF 的密封不证明整进程或完整动态依赖。初始 producer/Python、原受保护部署目录
及 `CODEX_HOME` 配置、系统 `PT_INTERP`/共享库和宿主仍是信任前提。新模式在输入
与实际 exec 两点拒绝所有 `LD_*` / `GLIBC_TUNABLES` 键，包括会改变加载器行为的
空值；原 Fleet/HEPTA/CODEX 值保留。它不能证明更早的进程启动或原配置加载安全。

Hepta `b93b7c3f...` 在原 helper dispatch 之后、dotenv/aliases/线程/owner 之前检查
Cell-v2 image：实际可重开路径必须与 `/proc/self/exe` 的 dev/ino 一致。M15 的
匿名 memfd 因而被明确拒绝。单独改成 `/proc/<host-pid>/fd/...` 也不能自动穿过
现有 `--unshare-pid` 与新 `/proc`，不能借此宣称修复普通 sandbox 路径。

M16 用独立 v3 schema 明确选择受保护的 root 安装镜像，保留原 regular image FD；
它绝不是 memfd 失败后的回退。权限/完整性检查与 root 安装者的版本路径、inode
生命周期前提相互配合；这不承诺对受信任 root 更新的密码学不可变性。本地 `/`、
`/usr` 及测试 ELF 的实际属主不满足该安装前提，不能用模拟 stat 或旧 sealed 探针
补出部署正例。实际普通 helper/sandbox、后续任务、模型与安装均须在该具体配置
下单独验证；此处不改变 sandbox policy 或资格开关。
`handoff.json` 仍是 `transport-complete-handoff-pending` / `EXEC_REQUESTED` /
`UNVERIFIED`，installation、FinalUse、独立评价、产品与生产 flags 均保持 false；
M15/M16 与其他行一致为 `UNQUALIFIED_COMBINED_PAIR`。

## PN0 保持 HOLD 的判定

源码冻结只是确定“测了什么”。它不能证明同一个配置同时支持这些路径。当前明确的
不支持组合、普通 host 的经典 FinalUse、原 paired Chain 与联合 Chain 的分歧都必须
保留在结论中。一个二进制同时编译进多种 owner、`--all-features` 成功或多个孤立测试
通过，也不能消除各自的 namespace/profile、外部 trust pin 和 owner 边界。

集成 owner 应记录最终 pair 的 source-head 与 base-merge 两条实际来源、锁文件、二进制
摘要、protected configuration 和逐行结果。SIGKILL、失败、未执行、未知状态和主动拒绝
都保留原含义；禁止合并成 aggregate PASS。只有这份明确配置矩阵所要求的真实正反路径
完成，且既有 PN0 其他退出条件成立后，才能重新评估 PN0。本文不作该评估。
