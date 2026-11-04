# 456d23a 原验收门结果快照（2026-11-01；v2 终局补记 2026-11-02）

**结论：原 CPU、独立业务完成、长历史及完整 PQ 验收继续 HOLD。** 本文冻结已经实际读回的结果；配套[紧凑证据 JSON](TRNM_SYSTEM_ORIGINAL_GATES_456D23A_20261101.json)保存 run/job/artifact 链接、ZIP SHA256、源码和 ELF 绑定、精确分母及缺测。不同 profile、源码和尚未完成的运行分别记录，不以局部速度或 ACK 代替业务完成。

## 1. 已测源码与观察边界

- Head：[`456d23a778d91b6f3cfee60ee997f8f51d3216bc`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/456d23a778d91b6f3cfee60ee997f8f51d3216bc)。
- 实际 prospective merge：`75e52844e3f6c6b2a11f13fb3d1266fd08f1fe48`；两者 tree 均为 `d48ee85bbb029b38b087096d1578f2dddb0abc57`。
- Base：#559 `0e9eac5d2a8cdb0a6f0cc7920f84e290e0d5d0d0`。这是源绑定的历史结果，不自动转移到下一提交。
- 本版保留已冻结 v1 的所有已测结果，并补入终局档案：required full-runtime 读回于 **2026-11-01 19:29:50 UTC**，History 读回于 **19:53:19 UTC**。后续 A+B 源码没有继承这些验收结果。

| 范围 | 实际结果 | 验收含义 |
| --- | --- | --- |
| 原完整 workspace test-profile 两项 CPU × 四格 | **0 PASS / 8 FAIL**；首项的后续 Auth 子分支四次均未执行 | 原 CPU 门未通过 |
| 同一构建的 35 个语义控制 × 四格 | **139 PASS / 1 FAIL / 0 ignored** | 不是全部 runtime suite；失败仍保留 |
| 两个 loop-exit 控制 × 四格 | **8 PASS** | 退出诊断控制通过，不证明 History 性能 |
| 原 4 秒业务的八份报告 | 无攻击均 1/1；16 producer 压力均 **7 ACK、0/1 独立确认** | 业务门失败 |
| 原 30 秒 campaign，三次 × 三 phase | 九个 phase 均 **0/3** 计划轮次完成 | 保留未完成轮次的分母 |
| 质量 head / merge | **两格实际 PASS** | 格式、供应链、doc tests、严格 Clippy 的范围 |
| default-release 两项 CPU + 两个 loop-exit × 四格 | **16 named PASS；12 个 backend CPU receipt native Ok** | 不覆盖不同原 test-profile 的失败 |
| required full-runtime head / merge | 每格 Node **849 PASS / 2 CPU FAIL / 22 ignored**；M06 **97 PASS / 0 FAIL / 6 ignored** | 另有4份 CPU 失败收据，不并入上表四格8次分母；后继命令未执行 |
| 原 4,105-block History | **0 PASS / 4 FAIL**；confirmer stored **2163/2170/2556/2556**，active 均0 | 实际服务均因原1800秒 lifetime 退出，原性能门失败 |

## 2. 原完整构建完成，原 CPU 验收实际失败

[Run 41337846694](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846694) 四格完成原 `cargo test --locked --workspace --all-targets --all-features --no-run` 构建，固定 Rust 1.95.0 和原 PQ provider 准备。Node libtest 为 opt3，M06 libtest 为 opt1；两者 debug assertions/overflow checks 均为 true，features 为 `default,pq-native-openssl`。随后执行原四个 selector，再执行选定语义控制。

下表为 **付费 dispatch 的 settled CPU 秒数**，包含 owner 与 scoped worker；不是 `/usr/bin/time` 整个测试进程 CPU，也不是嵌套阶段相加。

| 格子 | 原始档案 | 首项 Legacy CPU/s | 独立 Auth CPU/s | 语义通过 |
| --- | --- | ---: | ---: | ---: |
| x64-head | [作业 124941357628](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846694/job/124941357628) / [artifact 13096961231](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846694/artifacts/13096961231) | 2.888564170 | 3.188958797 | 35/35 |
| x64-prospective-merge | [作业 124941357567](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846694/job/124941357567) / [artifact 13096786743](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846694/artifacts/13096786743) | 2.954345838 | 2.800215398 | 35/35 |
| arm64-head | [作业 124941357584](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846694/job/124941357584) / [artifact 13097165235](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846694/artifacts/13097165235) | 2.912639848 | 3.260173456 | 35/35 |
| arm64-prospective-merge | [作业 124941357424](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846694/job/124941357424) / [artifact 13096941399](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846694/artifacts/13096941399) | 2.928074632 | 3.267142184 | 34/35 |

两项原 selector 为 `store::detached_admission::tests::admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner` 与 `store::detached_admission::tests::authenticated_large_parent_original_schedule_supplementary_denominator`。**第一项在 Legacy unwrap 失败处停止，同一函数后续 Authenticated 子分支没有运行**；第二项独立执行并失败，不能把分支缺测算通过。

八项 inner native result 均为 `Err(PUBLIC_MUTATION_CPU_BUDGET)`，native/tee/reader exits 均为 `101/0/1`。外层 metering 的 `Ok` 不代表 native 成功。原政策是 **2 秒初始 credit、每秒补充 0.25 秒、100 ms start reserve、2 workers**，不是固定总 CPU 只能消耗 2 秒；此次补充 credit 后仍被原门拒绝。失败收据中的 refusal-state/readback 为 null，不能借此宣称已经证明 rollback。

四份 ZIP 的 source-before/after、编译器 artifact 和前后 ELF digest 收据匹配。**这些 CPU ZIP 没有 ELF 本体**，不能称已从档案重新 hash 其可执行字节。

## 3. 139/140 控制与唯一实际失败

每格 35 项为 5 bounded-root、5 ASCII、6 reorg、1 current-SQL/root、3 prepared-history、15 既有 post-write 控制。x64 head/merge、ARM head 各 35/35；ARM merge 为 34/35。其失败是：

`pon_commitment::full_root_arithmetic_tests::arithmetic_parent_keeps_execution_results_cancellation_and_unlocked_callbacks`

原日志记录 `pon-exec-2` 在测试文件 331 行的 `arithmetic.0.try_lock().is_ok()` 断言失败，随后结果对照失败；退出为 `101/0/1`。这条真实失败仍留在本次分母。

只读诊断找到测试探针的竞争窗口：多个 prepare worker 并发调用 callback，成功的 `try_lock` 探针本身短暂持有 Guard，另一探针可因此失败；同一探针也作用于原 reference(None) 路径。生产 commitment 在 scoped workers 全部 join 后调用，局部数学 Guard 随函数返回释放；本审阅未发现同线程 Guard 跨 callback 的代码路径。**静态解释不是原失败已被复测消除。** 候选 A 用独立 gate 仅串行探针，并在释放 gate 前显式释放 attempted Guard，保留真实持锁负例、四线程正例及原 workers/cancellation 对照；只完成静态二审。

## 4. 原 4 秒：ACK 与独立完成仍分离

来源为 [required run 41337846779](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846779) 与 [priority run 41337846833](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846833)。八个独立档案均保持原 4 秒窗口、16 个压力 producer；每次按原分母只要求一个签名交易完成六深度独立确认。表中最后一列为压力下“按时 History RPC/尝试；窗口内 replay 接受/尝试”。

| 作业 | 来源 | 无攻击确认/s | 压力 ACK | 压力独立确认 | History；replay |
| --- | --- | ---: | ---: | ---: | --- |
| x64-required | [作业 124941357923](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846779/job/124941357923) | 2.609032630 | 7/7 | **0/1** | 3/3；2/3 |
| arm64-required | [作业 124941357898](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846779/job/124941357898) | 2.192374880 | 7/7 | **0/1** | 2/2；1/2 |
| protocol-head | [作业 124941357794](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846779/job/124941357794) | 3.295508578 | 7/7 | **0/1** | 1/1；0/1 |
| protocol-merge | [作业 124941358011](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846779/job/124941358011) | 2.493756964 | 7/7 | **0/1** | 3/3；2/3 |
| x64-merge | [作业 124941357868](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846833/job/124941357868) | 2.802229966 | 7/7 | **0/1** | 2/2；1/2 |
| x64-head | [作业 124941357957](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846833/job/124941357957) | 3.307989777 | 7/7 | **0/1** | 1/1；0/1 |
| arm64-merge | [作业 124941357982](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846833/job/124941357982) | 2.194755296 | 7/7 | **0/1** | 2/2；1/2 |
| arm64-head | [作业 124941357888](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846833/job/124941357888) | 2.101407897 | 7/7 | **0/1** | 2/3；2/2 |

七份压力报告在 client replay 触及 `PUBLIC_REQUEST_DEADLINE`。**priority ARM head 是不同的原始错误**：前两次 History 与 replay 成功；第三次 History RPC 从 `t=3.966950049s` 到 `4.000852411s`，在 `solution-body-response` 返回 `IO: Resource temporarily unavailable (os error 11)`，`returned_after_window=true`。其 `verification_errors=[]`，没有第三页 replay 记录，不能改写成 replay deadline。

八份报告的最终确认阶段均为 null。五个 named 原生控制通过只代表其注明的不变量范围，外层业务 manifest 均保留 `CONFIRMATION_TARGET`。对应原 ZIP、实际 ELF 本体、报告和日志 hash 已核；source 前后一致。实际 Host 前后为 CPU `25000 100000`、burst0、内存2GiB、swap0、pids256，Host 错误为空。八个单次观察不是饱和全链 TPS，也不建立可信 p95/p99 样本分布。

## 5. 原 30 秒：三个完整反例档案

[Run 41337846705 / job 124941357262](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846705/job/124941357262) 的 [artifact 13095859595](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846705/artifacts/13095859595) 为 49,840,757 bytes，ZIP SHA256 为 `de41c5b90124da162bfc95b2b02fc363d11f00282697cc0f13dc3949f3b231a0`。三份 `run-N-raw/report.json` 均实际取得、校验通过；没有 phase 启动错误或 reader 错误。

| 运行 | baseline | from-zero（24 attackers） | late-product（24 attackers） | 原生结果 |
| --- | ---: | ---: | ---: | --- |
| 1 | 0/3 | 0/3 | 0/3 | 0 pass / 1 fail / 0 ignored |
| 2 | 0/3 | 0/3 | 0/3 | 0 pass / 1 fail / 0 ignored |
| 3 | 0/3 | 0/3 | 0/3 | 0 pass / 1 fail / 0 ignored |

每个 phase 只有 round0 的失败记录，另两轮没有完成记录；原 `ROUNDS=3` 与 21 个 prepared business blocks 保留，不能缩为 0/1。每 phase 的第一轮均收到 7/7 ACK；baseline 的 7/7 History RPC 成功，但 import 只成功 6/7；攻击 phase 的 3/3 RPC 成功，import 只成功 2/3。末次 import 均报 `PUBLIC_REQUEST_DEADLINE`、确认 observation=null。三次 native exit101，外层 `ORIGINAL_THREE_RUN_CAMPAIGN_FAILED`，不是旧 runner shutdown 的未知结果。

## 6. 成本诊断和资源对照的边界

456d run1 baseline client 的 phase 快照差值：account_graph 为42 calls / **4.631619108s CPU**，verify_state 为57 /4.718061327s；complete_commitment64 /0.066567584s、complete_state_root23 /0.007255110s、publish7 /1.936667986s、activation1 /0.116170186s。这些是嵌套阶段，不能相加；没有独立 reorg stage，其值保留缺测。七页 import 共5.881214564s caller CPU、26.426082120s wall，最后一页未完成。receiver 的 account_graph 为49 calls /0.284054733s CPU；调用线程数字不含另外的 scoped worker。

旧5606和当前456d的业务记录、policy及Host限制相同，但旧 CPU 型号是 EPYC 9V45，当前是 EPYC 7763；旧run1已完成round0、当前未完成。旧最后一页完成激活，当前最后一页被deadline截断。因此不能从较低 activation 累计值宣称已优化完成，也不能把每页CPU差异单因果归给某个源码改动。两源共18个实际 Host before/after限制均一致且读取错误为空。controller/attackers外层仍为4 CPU、16GiB、nice10。**receiver和独立verifier是同一phase进程内的两个Node，合用一个0.25 CPU、2GiB public phase cgroup；该域独立于controller/attackers，并非两个Node各得0.25 CPU。** 原`phase()`同时打开receiver和independent-client，只把服务移入`thread::spawn`；`phase_host::entry()`调用它后记录一个phase pid/cgroup。456d run1 baseline实际phase PID4782、cgroup为`/trnmponpublic.slice/trnm-phase-41337846705-1-original-campaign-4710.service`，controller为`/system.slice/trnm-native-campaign-41337846705-1.service`，与实际Host记录一致。

## 7. 已通过范围、完整 runtime 失败与本地证据

质量 [head 124941357885](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846779/job/124941357885) 与 [merge 124941358012](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846779/job/124941358012) 的原 receipt 均为 `passed`/exit0，source前后匹配。通过范围是格式、供应链、workspace doc tests和all-targets/all-features严格Clippy；完整runtime的独立终局如下。


### 7.1 Required runtime 的额外4份 CPU 失败

[Required run 41337846779](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846779) 的两个 runtime shard 均真实运行 `cargo test --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features`，在 Node 两项原 CPU 测试失败后 exit101。不是编译失败或 runner 中断。

| 源 / 作业 | Node libtest | M06 libtest | Legacy / 独立 Auth paid CPU/s | 原 observations / shard |
| --- | --- | --- | ---: | --- |
| [head 124941357698](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846779/job/124941357698) | 849 PASS / 2 FAIL / 22 ignored | 97 PASS / 0 FAIL / 6 ignored | 2.886195714 / 2.778003109 | [13098035214](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846779/artifacts/13098035214) / [13097860524](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846779/artifacts/13097860524) |
| [merge 124941357907](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846779/job/124941357907) | 849 PASS / 2 FAIL / 22 ignored | 97 PASS / 0 FAIL / 6 ignored | 2.929145012 / 2.777113154 | [13096649487](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846779/artifacts/13096649487) / [13096564564](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846779/artifacts/13096564564) |

这是**另一组4次执行、4次 CPU FAIL**，与第2节四格的8次分母分开。两个首项均在Legacy失败处停止，其Auth子分支仍未执行；inner error仍为`PUBLIC_MUTATION_CPU_BUDGET`，refusal readback仍null。每格35个选定语义控制逐名`ok`，合计70/70；这两格没有新的callback探针失败，但不能覆盖原ARM merge的那次FAIL。

`set -euo pipefail`在这次workspace命令失败处停止，后续Python oracles、release full-capacity、growth-reference 65,537、growth-v2和complete-account-verification-cost命令未到达。因此不能称完整runtime或后继规模门已通过。四份ZIP及source-before/after、命令脚本hash均已核；本批profile证据仅为实际Cargo命令、test-profile banner与精确提交的manifest声明，**没有逐ELF编译器profile/hash JSON或ELF本体**，不能移植独立CPU矩阵的ELF绑定。

### 7.2 不同 profile 和本地子集的通过范围

[Default release run 41337846728](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846728) 四份ZIP已读回，16 named测试为1 pass/0 fail/0 ignored、退出0/0/0；12个backend收据native Ok。该构建是**package/default features/release opt3、debug0、assertions=false、overflow=false**，必须与原workspace test-profile的8项失败并列，不能替代它。其ZIP同样不含ELF本体，使用编译器记录/digest绑定收据。

本次456d也有**已实际执行的本地M06 package子集**：`pon_commitment::`为30 pass/0 fail/5个原ignored微基准，`pon_executor::root_arithmetic_tests::`为6 pass/0 fail/0 ignored；build和native均exit0，source前后为本文456d/tree d48。实际M06 profile为opt1、debug2、debug assertions/overflow=true，features为default+pq-native-openssl。final receipt SHA256为`0e03fd5ff248a8ad55e9d611ea43e891c65c34f9e4983344e85b0bae650e7856`；70,314,080B ELF执行前后及保留副本重读hash均为`3193a68eb9f5f40e9e10145a3c20abb85ff4524f1bb6127162556279de97d650`。该ELF本体已保留在本次session本地副本，不宣称永久归档。本地同名callback控制通过，**不能覆盖后来ARM merge完整workspace构建下该控制的实际FAIL**，也不能覆盖Node CPU/Host/业务门。此处与下述旧64cb未归档ELF的情况分开记录。

历史64cb的package-only M06 `pon_commitment` 29 pass/0 fail/5个原ignored微基准，以及7个Node integration控制，仍只属于旧源的有限范围。旧本地fullgraph构建有Node libtest SIGKILL；后来build-cache缺失使本地ELF本体未成功归档，保留的是执行时收据和日志。不能用该子集通过覆盖当前原profile失败或给新补丁发放验收。

## 8. 原4,105区块 History：四格终局失败，已观测真实 lifetime 退出

[Priority run 41337846833](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846833) 四格都实际运行原 `actual_v3_long_chain_public_full_sync_reopen_and_corrupt_index_refusal`，均为 **0 pass / 1 fail / 0 ignored、native exit101、log exit0**。四份原ZIP的size/SHA256与API metadata一致，source-before/after均为本文精确head/merge及tree；只读查询原SQLite，前后数据库hash不变。

| 格子 / 作业 | 原artifact | Confirmer stored / active | 从run开始的elapsed/s | 最终sync错误 |
| --- | --- | ---: | ---: | --- |
| [x64-head 124941357837](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846833/job/124941357837) | [13097514146](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846833/artifacts/13097514146) | **2163 / 0** | 3283.834094587 | Connection refused (os error 111) |
| [x64-merge 124941358018](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846833/job/124941358018) | [13097873464](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846833/artifacts/13097873464) | **2170 / 0** | 3247.359194366 | Connection refused (os error 111) |
| [arm64-head 124941357922](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846833/job/124941357922) | [13098600487](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846833/artifacts/13098600487) | **2556 / 0** | 3731.436761096 | Connection refused (os error 111) |
| [arm64-merge 124941358039](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846833/job/124941358039) | [13097498453](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41337846833/artifacts/13097498453) | **2556 / 0** | 3756.255633068 | **FRAME_EOF** |

这些是实际数据库最大stored height，不是最后一条每500块打印的进度：后者分别为2000/2000/2500/2500。四个validator均实际stored/active=4105，并保留完整1..4105 packet文件；confirmer均未激活目标链，active仍0。导入到达 pinned tip 的完整终页最后一个packet才触发activation，而且之后仍有Host/CPU与重开检查；stored高度或单独active值都不能替代整项验收。

四份`loop_exit_before_internal_shutdown`均记录`reason=lifetime_expired`、`configured_lifetime_ns=1800000000000`、`lifetime_reached_before_shutdown=true`、`stop_requested_before_shutdown=false`；实际loop elapsed约1800.000449–1800.001032秒。退出后`stop_requested_when_exited=true`属于内部shutdown之后的状态，不能倒推此前存在外部stop。**本次已直接观测服务因原1800秒lifetime退出；这不证明它解释所有成本，也不构成原性能门通过。** 延长期限不能替代原门。

表中总elapsed的计时从validator造链之前开始，包含造链与同步，**不是纯冷同步耗时**。History使用package/default release opt3、debug0、assertions/overflow=false；ZIP有原编译记录与ELF digest收据但没有ELF本体，未声称独立重hash可执行字节。完整PQ业务、WAN/独立运营者与全链确认TPS仍未验收。

## 9. 下一提交候选：A+B 与37项控制，结果 pending

A修正测试探针自身竞争；B将已有ASCII编码正文提取为private `canonical_after_validation`，仅让`root_with_arithmetic`在原全State grammar/count检查后复用。原`root`继续直接serde编码作为独立参考，`canonical_into`和原编码正文逐字节保持。B新增独立serde根的混合输入、0/2MiB、cold/warm/current-row/revert控制，并扩展晚grammar优先于早超长value的反例。

两个patch已静态二审，SHA分别为 `2d9e96c7ec97adfdcee6d32f38d8a8cd90cf4b07f696db4d4890ae2d847106ea`、`670b011fed31dd24102853385352f4be54386ad92dae76e2083a5d381b575518`。下一源计划每格37个selected controls，其native/CPU结果均pending。原预算、profile、Host限制、checkpoint频率、4秒/30秒/4105和1800秒lifetime不变；成功必须来自新精确源的原门执行，本文不作提前验收。
