# 两处 stale blob guards：当前材料源码独立审查与 literal-only 候选

**SOURCE_IDENTITY_ONLY_ADMISSIBLE。** 可由 root 审查整合两行精确 literal 同步，以便原检查真正验证当前已存在源码；这不判定底层存储升级、native／SQL、完整 public route 或合并已通过。未发现必须通过删 assertion／降限额才能处理的来源问题。历史源、原 guards 和实际失败必须保留。

本次锚定已提交 `7ad9c6470713e5c33b33360e8dd63efbade4931f`。审查中 root 正常提交计划与 evidence 到 `291d3d629a74c42d3a85335cfae9984408f8be10`，现为 clean；所审两源码、两 workflow 及所取相关依赖在两 commit 与当前 worktree 逐字一致。首个固定 HEAD==7ad 的保守冻结程序在该并发提交后真实 exit1，未写源或生成 payload；该观察保留。没有触碰先前 dirty 的 plan/evidence 内容，没有改 root/outputs、应用候选、Cargo／native／SQLite／测试／构建／Bazel／旧预算动作。

## 实际 source identity

| 源码 | 旧 workflow literal | 当前 Git blob | 当前 SHA256 |
| --- | --- | --- | --- |
| account_archive_prototype/native_store.rs | d4327221fe1af4d0479915371634bdbf6e9cf4c1 | 5b09b2e473dbba311a398e9ed77d2b619eaa906c | ad9e41b68379ec9e5aade1bc2339d2710c9128e142738488dec35eee20b5979f |
| store.rs | 1377aabf81a8accb87b1b2e10c5c3f243af4acde | fadc0f4c11bbead2925102cb1b18a49156d709d5 | 48e3301d9a60ed62aed976249bf7816c2df94a19ab0a72273ba275feb8448df2 |

旧 blob 均从本地 Git 对象原样冻结，完整 old→current diff 保存；当前字节同时等于 anchor、当前 HEAD 与文件内容，不是把文件名当身份。两差异已存在于 c758，writer 六 Python 机械抽取和新库存不造成这些改动。

## native_store 的材料变更

完整差异是新增66行 `materialize_accounts` 及文档，其余旧文件字节完全原样（移除该2398B新增块即还原旧 blob）。它用新的调用内 NodeReader／seen／BTreeMap 从传入 root 遍历全部实际账户图，不接收调用方“已有效”摘要代替读取；沿用旧 SQL node decoder、child路径／depth／lift规则。检查 root 的 digest／empty关系，保留65,536账户和131,071节点上限，拒绝重复图节点、重复 owner、余额溢出以及最终 count／balance失配，并调用 progress。

这是一项完整图物化功能，不是编码常量或纯 hash更新。它本身不建立独立事务，SQL读一致性与回调后再验证须由调用方的 read scope／完整 State／history fences 承担；扫描为线性完整图，不能据此宣称 bounded-W、硬件成本公平、冷加载或原2秒服务达标。原 verify/query/apply 等旧方法没有借此被改写；没有看到新的“失败转空图”fallback。

## store 的材料变更及实际依赖

完整 diff 为179增、24删。已读当前 shared_snapshot.rs／binding.rs／transaction_scope.rs 与 Node 接口和发布顺序；不能把这项变化归类为 writer 或词法修改。

- **布局与命名空间：**仅 `AuthenticatedV1 + Some(NativeIoLease)` 选 SharedAccountsV1；其他开法的 Layout 是 CanonicalJson，其 schema_id／DDL 返回原 base。Shared 使用单独 `native-io-shared-authenticated-branch-schema-v1` 域和版本表，opener仍用真实 DDL 构造的 schema／metadata检查拒绝旧或 mixed stores，没有自动转换旧数据库。growth profile 开法仍要求原 Legacy backend，不能把共享布局当更大账户资格。
- **持久化：**Shared 路径停止每块重复完整 JSON snapshot，仅 genesis保留原表；同一个真实 block transaction 中先发布 native account record，再保存 working分区／native commitment的共享快照，保持64 retained与 pending第65行校验。随后原 deltas／packet／parent和child完整 State／ancestry读回仍在 COMMIT 前执行；不得因此声称它已通过崩溃／reopen验收。
- **读回：**新 load 以实际账户图重新补全 State，运行原 continuity、full State及history验证；存在且损坏的快照错误传播，只有合法缺失的可选索引才走原历史重放。active及historical读使用同一 snapshot wrapper、ReadSet与最后无 caller callback 的再读取；附加库／TEMP同名表、schema变化、同连接写／transaction替换及 raw record变化都有源级拒绝分支。这里看到拒绝机制，不等于实际 SQL／callback 对抗结果。
- **健康与策略：**Shared storage_context重读实际 schema/layout和原 NativeIoLease sticky fault／denial／quarantine记录。`wal_autocheckpoint=64` 则作用于**所有 native_io.is_some 的开法**，并非只在 Shared布局；这是新的连接checkpoint策略，读回64页值不证明 WAL物理大小或原磁盘／时间caps得到满足。普通未带 native_io 的 CanonicalJson开法不受此策略分支影响。

当前 Node 明确依赖 exact rusqlite0.39.0 + bundled/fallible_uint；本地固定依赖源码确认 u64 FromSql 由该特性提供，所以没有把旧“缺少u64适配”误报成当前编译错误。没有解析 Cargo 图／编译／执行其实现，ABI和整个C/VFS/loader完整性仍不是本审查结果。

未在这个有限材料阅读中发现需要为**精确 source binding维护**先删除保护的具体源码缺陷。此结论不代替对整个 SharedAccountsV1、C ABI、全 T/Layout或旧003 extractor的完整安全准入。`shared_snapshot::Layout` 是当前既有本地物理布局选择；本候选没有应用任何002/003库存或 extractor，也不提升其原 NO_GO。

## 可审查的两行候选

`candidate/literal-pins-only.patch` 只把：

- pon-branch-encoding-acceptance.yml:53 的 d432… 换为当前 5b09…；
- pon-recent-batch-acceptance.yml:67 的 1377… 换为当前 fadc…。

没有改被比较的路径、`git hash-object`／`test` 形式、source verifier、原 snapshot／错误断言、期望测试数、selectors、25分钟deadline、CPU/job/thread设置、compiler版本、filters、actions、矩阵或上传。逆换这两个40hex常量后，两 workflow **每个其他字节**与 base 完全相同。原20个 literal guards保留，原两runner × head/prospective-merge × 两workflow＝8 lanes保留；原18个已匹配guard没有改动。

静态逐 blob观察显示旧表18/20匹配，而这个**未应用候选**对当前字节会是20/20匹配。这只是 counterfactual source equality，不是运行 shell assertions、workflow或native测试，更不能把原8 lane FAIL改写成PASS。workflow名称中的“unchanged source”应理解为新 frozen literal 对应的 exact source，不是声称上述功能相对旧 blob 没变。

root 若整合，仍须在编辑／提交前原 project-preflight，重新核对两 workflow payload、实际源码 blobs及最终commit/tree、原20个保护与原矩阵保留；任何后续 source漂移都使该固定 literal 候选需再审。实际 PR preview须用新head/base的真实 ordered parents/tree，各lane原source verifier继续执行。此角色没有安排重跑、取消运行或改变保护。

## 仍未资格的原要求

- 原 exact head／actual preview的所有必要 CI和这8 lane的完整 native/Clippy／migration／cold recovery结果；旧hash匹配和旧source通过不能替代新实际执行。
- 新 Shared snapshot的真实图腐败／callbacks／transaction替换／namespace／partial write／rollback／reopen读回，以及当前 SQLite3.51.3 C ABI／loader／VFS／同lease终态与原资源上限链路。
- WAL新checkpoint策略与所有原磁盘、时间、FSIZE、ledger、Unknown不退款和first-error约束的完整真实压力证据；同一source上的小型机制结果不等于whole-writer／strict-reader／public prepare。
- 超65,536账户／bounded witness、完整4,096身份耗尽后新身份持续攻击、W1最低成本和硬件／摊销、公用服务confirmation goodput、三轮模型、独立72小时WAN、安全和merge资格。

原 inventoryFAIL与旧两guard失败留在历史；root实际原generator再生并提交7ad的事实不会消除它们。952/300/90/164.257等旧预算未重启。所有 fullguard和fullT/Layout003及整体NO_GO保持。
