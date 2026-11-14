# C1 托管 native 失败诊断

核验对象为 PR #901 的 head `c09dbbe9921da12db8bf7240a8a95a0e9a789e50`，tree `f15a7ee4a0f5455eaf965db01dcd49e02a5f22b6`。本次仅下载、验字节与读取已有执行结果，启动的 native 测试数为 0；未修改源码、预算、窗口、判据或任何仓库设置。

## 结论

C1 的 original native campaign 是实际业务判据失败：构建、启动、源码校验、报告读取、最终证据保留和上传均成功，三次原测试均 exit 101。九个 phase 的原有限实验判据均为 false；其业务确认与攻击付费预算耗尽要求没有闭合。

另外两个 cross-arch-cost job 也已定位：每个架构的五个 native 控制都 exit 0、无 timeout，原报告的 confirmation business target 仍为 false，Python 验收正确以 `CONFIRMATION_TARGET` 拒绝。因此不能靠修 wrapper、延长原窗口或把 cargo exit 0 当成业务通过来关闭这些结果。

## 原 campaign：新 C1 数据

运行 [42955583039](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42955583039)，job [130309763995](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42955583039/job/130309763995)，`original native campaign (x64, head, release)`。

原 release build 用时 223.279356484 秒、exit 0。三次独立且预先声明的完整原 campaign 用时分别 113.743184739、113.542858490、113.394160823 秒，均 exit 101，外层 600 秒 timeout 均未触发。三个 report 的 `phase_startup_errors=[]`、`report_validation_failure=null`，最终 `finalization_failures=[]`，测试 binary 前后 SHA-256 相同；final source 为上述 C1 head/tree，27,912 tracked entries 均通过实际字节验证。

原业务要求是每 phase 30 秒，共三轮，每轮七个 blocks；业务计划 t=1、5、9 秒；History import 共用原 phase 的绝对 deadline。600 秒是运行器的外层约束，不能替换 30 秒业务判据。

以下“首轮结束”是相对 phase 起点的 `ended_ns`，不等同于纯确认延迟。未观察的后续轮不算成功。

| 完整运行 | Phase | 窗口内确认轮数 | 首轮结束（秒） | 原 verifier 错误 | 观察到 paid depletion | Receiver/client 状态相等 |
|---|---|---:|---:|---|---|---|
| 1 | baseline | 1/3 | 27.994735062 | [] | false | false |
| 1 | from-zero | 0/3 | 30.077492456 | PUBLIC_REQUEST_DEADLINE | false | false |
| 1 | late-product | 0/3 | 30.072818292 | PUBLIC_REQUEST_DEADLINE | false | false |
| 2 | baseline | 1/3 | 27.790993392 | [] | false | false |
| 2 | from-zero | 0/3 | 30.075176281 | PUBLIC_REQUEST_DEADLINE | false | false |
| 2 | late-product | 0/3 | 30.072808951 | PUBLIC_REQUEST_DEADLINE | false | false |
| 3 | baseline | 1/3 | 27.976952124 | [] | false | false |
| 3 | from-zero | 0/3 | 30.078453111 | PUBLIC_REQUEST_DEADLINE | false | false |
| 3 | late-product | 0/3 | 30.068248651 | PUBLIC_REQUEST_DEADLINE | false | false |

三个 baseline 均仅确认 1/3 轮，第二轮在窗口结束时未确认，第三轮未完成观测；baseline 的 `verifier_errors` 是空数组。六个攻击 phase 均 0/3 轮，原错误为 `PUBLIC_REQUEST_DEADLINE`。这与旧 #894 / 315 的具体错误分布不同，本诊断没有复用旧运行的 phase 结论。

所有九个 phase 的 `observer_complete=true`、service outcome 为 `Ok`。六个攻击 phase 均有 24 个已 ready 的 attacker，actor reports 正常完成且未由父进程强杀。攻击 phase 的原 `genuine_budget_depletion_observed=false`，每个保留 sample 的实际 paid depletion 字段都为 false；最低观察到的 remaining paid credit 仍约 1.979–1.984 秒 CPU credit，高于 0.1 秒 start reserve。该结论仅是本轮原观察未达到耗尽判据，不是证明所有时刻、所有攻击都不可能耗尽。

三个 report 的 `economics_complete=true`，但 `finite_experiment_criteria_met=false`。原 Rust 断言在 `public_v3_multiprocess.rs` 第 1765 行触发 `finite experiment criteria failed`，不是 Cargo 编译错误。Receiver/client 末态不相等与未完成 replay/confirmation 一起被保留；不得把它单独改称“接受了非法状态”或量子攻击证明。

## Cross-arch-cost：原确认目标未满足

运行 [42955583052](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42955583052)，arm64 job [130309764639](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42955583052/job/130309764639)，x64 job [130309764652](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42955583052/job/130309764652)。两者失败步骤均为 `Execute exact native from-zero service controls`。

每个架构的 `format_passed=true`、`source_recompiled=true`、五个 named tests 全部 pass、`native_execution_completed=true`、`finalization_completed=true`。三个报告验收阶段中，`service_report` 和 `sustained_report` 通过，`confirmation_report` 失败，原始错误仅为 `CONFIRMATION_TARGET`。前后源码和验收前后 report hashes 均相同；不是报告被替换或取错 source。

原窗口为四秒。两个压力阶段的 native protocol/accounting invariants 仍为 true，`finite_target_met=false` 是保留的真实业务结果。

| 架构 | 场景 | 窗口内确认交易数 | 实际成功确认延迟（秒） | finite_business_target_met | 失败 replay 结束时刻（秒） |
|---|---|---:|---:|---|---:|
| arm64 | attack-free-baseline | 1 | 1.782057493 | true | — |
| arm64 | from-zero-pressure | 0 | null | false | 4.039665970 |
| x64 | attack-free-baseline | 1 | 2.682193964 | true | — |
| x64 | from-zero-pressure | 0 | null | false | 4.051920272 |

arm64 压力阶段的第七次 history replay 在 4.039665970 秒以 `PUBLIC_REQUEST_DEADLINE` 返回；x64 的第四次 replay 在 4.051920272 秒以同一错误返回。两者均 `client_confirmed_before_original_window_end=false`、`full_native_state_equal=false`、`verification_errors=[PUBLIC_REQUEST_DEADLINE]`，同时 `no_attack_accepted=true`、`accounting_closed=true`、`receiver_matches_valid_honest_prefix=true`。

这解释了 native test exit 0 与原业务验收失败可以同时成立：C1 `public_v3_from_zero.rs` 的测试只 assert native invariants；文件中明确把 finite business target 单独写入报告。`run_from_zero_native.py` 则保留对 `finite_target_met` 的原验收要求，第一项失败即为 `CONFIRMATION_TARGET`。不应削弱该验收。

## 证据完整性与材料

三个原 ZIP 的 size 和 SHA-256 均与 GitHub artifacts API 相符。Original campaign 的 1,766 个 regular members 全量读取和 hash；其嵌入清单涵盖其余 1,765 个成员，每项 bytes/hash 全匹配。两份 cost ZIP 各 154 个成员全量读取和 hash；每份 `from-zero-native/manifest.json` 覆盖本作用域其余 50 个文件，逐项 hash 和完整覆盖均通过。

| Artifact | ID | ZIP bytes | ZIP SHA-256 |
|---|---:|---:|---|
| Original campaign | 13829055578 | 70,936,486 | `078f427e72d34dc1b0a96f13d16a231d78e9c949656ae57b1fe52665c91cfebe` |
| Cost arm64 | 13828821111 | 9,018,574 | `e9236a8d2bb85e343d1faa842a2b0e463593a7f7445649513eb835a369707de5` |
| Cost x64 | 13828657982 | 9,298,938 | `ceeaca9e857020eec7dc948e2a2b92ee5aa3e2bbf208270779fceb1284811946` |

`readback-1.tar.xz` 为紧凑诊断包，1,850,508 bytes，SHA-256 `90f8da399cda835849001e5c65a49d0d8cc2a4b09e191e6c8b73dddbfb275456`。包含完整 ZIP member hash 清单、原嵌入 manifest、小 raw logs/JSON、原 result/source/resource receipts、三份 campaign report 的 hash/bytes 与明确标注的字段投影。每份投影保留各 phase 原 confirmation、budget samples、窗口判据与诊断字段；被省略的大字段有名称、长度和重新编码 hash，不冒充完整原 report。

独立 verifier 再核对了诊断包内 1,838 个索引文件、完整清单覆盖、所有保留 raw members 与对应原 ZIP 字节相等、三份 ZIP 固定 size/hash、job log result 与 artifact results 完全相等，以及原 report 字段与投影相等。没有重新执行测试。

文件入口：

- `native-diagnosis-c09dbbe992.json`：结构化实际 phase/预算/确认/terminal 结果。
- `packet-independent-verification.json`：第二条只读核验记录。
- `readback-1.tar.xz` 和 `readback-1.tar.xz.sha256`：冻结的紧凑诊断包及其 hash。
- `extract_c1_native_artifacts.py`：固定 C1 artifact identity 的只读提取器。
- `verify_c1_hosted_readback.py`：对固定包和原 ZIP 的独立只读核验器。
- `original-campaign-job-130309763995.log`：GitHub connector 返回的完整 decoded job log，不冒充原始 logs ZIP 字节。
- `source-c09dbbe992/` 与 index：由 C1 Git objects 读取的原判断与运行器源码；关闭 Git replace 和 lazy fetch。

初次仅日志 readback 的 `*-preartifact-observation.json` 原样保留，它们当时的未知 phase 字段没有被覆盖。短期下载 URL 的原 transport 仅在 `download-transport-private` 留存，绝不纳入诊断包或提交材料。

## 后续范围

当前直接失败位置是原有限窗口中的客户端 history replay/confirmation，以及原 campaign 未达到 paid-credit depletion。对更底层 CPU/调度/验证成本的因果归属仍需单独性能工作；本诊断没有断言某个 PQ 算法是唯一根因。下一步若进行修复，应保持原窗口、预算、native workload、确认深度与验收判据，并由新的 exact-source 实际运行检验；这些 C1 失败原样保留。

上述 source/host/byte checks 不提供整链抗量子、独立运营者、WAN、量子挖矿、生命周期组合或发布资格。
