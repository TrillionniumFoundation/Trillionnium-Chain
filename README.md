# R1 发布后的诊断原件与当前验收边界

这是一棵闭合的增量证据树。全量分支清点、处置清单与候选整合已发布，R1 已发布，PR847 已 ready；main 尚未合并，分支清理未执行。2026-11-14 15:58:39 UTC 的完整远端读回仍为 908 个 heads，main 为 dd6e1c3cbeacbdc532b0679297835b3a0aac78f0，候选为 R1。新归档以已发布执行证据归档 0f4b8b70bde65f84139b4cc7ed9e176ed55cf1d9 为唯一 parent；旧执行证据和原始分支历史通过该 parent 保留，本树不重复复制它们，也不覆盖旧失败记录。

## 固定源与已经发表的审计

- R1：[2a86462a1ab20c68151719ba4635e3c294391e64](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/2a86462a1ab20c68151719ba4635e3c294391e64)，tree 为 5c26776f96f15fd131e85a5c2d7c5e895ad7fab4。
- [固定 R1 总审计报告](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2a86462a1ab20c68151719ba4635e3c294391e64/docs/development/BRANCH_CONSOLIDATION_AUDIT_20261114.md)。逐分支 disposition、选定移植与历史保全均以其固定证据为准；不是全仓库逐行正确性证明，也不是全部旧分支能力已经激活。
- [原执行证据归档](https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/0f4b8b70bde65f84139b4cc7ed9e176ed55cf1d9)。其本地控制通过不能替代当前 hosted 验收。

## 截至本次快照的实际结果

最新选定的 ready019 观察窗口是 **2026-11-14 16:03:12–16:03:29 UTC**。required 执行项为 6 success、2 failure、4 running；两个 fan-in 检查尚未出现。这是该时点的原始状态，不表示后续状态相同，也不表示全部 CI 已终止。

| 项目 | 可核查的实际结果与范围 |
| --- | --- |
| [required protocol head，job132481412290](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43604217412/job/132481412290) | 五个原 native 控制退出 0，随后 CONFIRMATION_TARGET 拒绝。压力阶段第一次 replay 于 3.999257347 s 被接受，第二次 History 于 3.999364226 s 发起，在 challenge 阶段以 IO11 越过原四秒窗口；不能把它写成 work 验证错误。 |
| [required protocol prospective，job132481412473](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43604217412/job/132481412473) | ready019 metadata 显示 failure；未取得该 job 内层原件，具体原因 UNKNOWN，不继承 head 的因果结论。 |
| [W1 fresh service 原运行](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43604217632) | 四个压力报告均未完成窗口内确认；fresh 原 Rust 断言失败。保留完整双 ZIP 与四份报告来源，未改变四秒、16 workers、7 包、深度 6 或 fresh Host 检查。 |
| [cross-architecture 原 workflow 运行](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43604217412) | x64 与 ARM 各自的五个原 selectors 均退出 0，业务 validator 均以 CONFIRMATION_TARGET 拒绝。x64 的最后 replay 为 PUBLIC_REQUEST_DEADLINE。ARM 原下载超时、checker 的原 HOLD 及后续完整核验分别保留，不把传输错误当成业务错误。 |
| [4105 History，job132475258347](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43604217565/job/132475258347) | 服务端按原 1800 s lifetime 退出，独立同步在 completed_import_calls=3907 后遇 ConnectionRefused。3907 是调用数，不是已持久化区块数；最终 activation/reorg 尚未进入，相关计数为 0。只有所取六个成员完成局部 CRC/来源核验，没有宣称整个大 ZIP 的 SHA 已验证。 |
| [PQ TLS witness，job132475258045](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43604217597/job/132475258045) | selected-binary 控制在第三次重启后的 replay、TLS 握手前 ingress_admission 拒绝，PQ_WITNESS_DEADLINE，约 261 ms。Current/CAS 各有独立 250 ms 限制，原计数无法确定是哪次 exchange 或哪一内层阶段。deadline_elapsed=false 是外层连接期限，BIO charge_calls=0 不是未进行耐久计费的证明。未通过放宽期限或重试掩盖问题。 |
| [三个历史预算控制原运行](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43604217513) | 三个 before 历史输入均因 IDENTICAL_GROUP_TESTS_LOCK_AND_PROFILE_REQUIRED 拒绝，native_control_processes_started=0。原输入身份不一致和原失败完整保留，不改写为预期成功或已运行的 native 反例。 |
| retained historical artifact | 原远端 artifact 不可取得：既有 API404、空 artifact 列表及有限 ZIP 清单未能确认同字节原件。不能重建内容后冒充原 retained negative-control artifact。对应固定 R1 原证据见下。 |

这些结果没有授予生产、协议性能、PQ、模型、operator 或 activation 资格。四秒故障的 wall/CPU、服务端与严格 History 的 Host 路径差异已明确记录；不同时间窗口、嵌套 CPU 和整个 job 的 cpu.stat 不直接相加。没有得到足够证据支持安全且能解决当前故障的性能补丁。

## 原件、来源和局限

payload 中所有文件由冻结清单的原 host/path、bytes、SHA256 逐项标识。failed、UNKNOWN、部分 Range 取证、环境错误和后续修正分别保留。已取得完整 ZIP 的条目以各自 CRC/SHA/manifest 证据为准；History 和 required protocol 的局部成员不冒充完整 ZIP 验证。History outer acquisition 的辅助 owner PTY 容器未定位时如实列为缺口；原三次 GET 的 argv、exit、stdout/stderr、producer 和 launcher 已保留。

credential-pattern 检查只覆盖其明确输入清单中的原始字节，不递归解压 ZIP/pack，不证明所有秘密不存在。扫描回执及本次发布终态不自我宣称已经被同一次扫描覆盖。当前发布结果须由外部实际退出、owned pre-push receipt、完整远端读回和源身份复核证明，不自循环写入本归档。

固定 R1 的 retained-artifact 证据：

- [原 retained diagnosis](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2a86462a1ab20c68151719ba4635e3c294391e64/evidence/pon-joint-state-risk-ledger-20261107/hosted-pr784/reviews/retained-historical/diagnosis.json)
- [原 unavailable manifest](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2a86462a1ab20c68151719ba4635e3c294391e64/evidence/pon-native-profile-closure-20261107/ci-source-pin-repair-v1/ci-retained-pressure-unavailable-v1.manifest.json)
- [原 missing inquiry](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2a86462a1ab20c68151719ba4635e3c294391e64/evidence/pon-business-gates-readback-20261107/ci-d26/historical-original-missing/inquiry.json)
- [原 ZIP inventory](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2a86462a1ab20c68151719ba4635e3c294391e64/evidence/pon-business-gates-readback-20261107/ci-d26/readbacks/historical-original-zip-inventory-v1.json)
