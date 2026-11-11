# 第四项 Node FAIL：NPQ6 + 独立 witness + exact replay（pre-panic 后继）

这是前两组只读诊断的追加快照，前驱路径及 SHA 完整列于同名 JSON；四份前驱文件逐一重核原字节且不覆盖。源仍为 clean Z `cdd984808a088e6c2e13b1e1ae6630a94d500c89`，tree `1ed39b6ebe55cb00c238f26f6bfc9361ab93faec`。

## 实际观察及原因边界

原 job `1a1c8ba754b-135c4-1d3` 的连续原 stdout 前 `159890` bytes，SHA-256 `96c9bdbdc04c3f4b739191da1106c35c7107ebb3d1f3d0b1ceac3c1e607db778`，在 1320 行打印：

`store::pq_rollback_witness::combined_tests::guarded_npq6_valid_submit_exact_replay_and_independent_process_restart ... FAILED`

同前缀保留此前三个 FAIL；1318/1319 行的 invalid-signature restart 与 cleanup-preservation companion 各为 `ok`，不能替代本 positive。尚无该 case 的 panic、捕获诊断或外层 1402-test suite 的终态。**目前不能决定失败是在 first Submit、exact replay、checkpoint/cleanup、independent restart、cold Node reopen 或最终余额/计数断言。** 未运行实际 base 对照。

以下路径相对 `trillionnium/crates/trnm-pon-node/src/`；M06 路径另行标明。

## 配置、独立 child 与真实授权入口

`store/pq_rollback_witness/combined_tests.rs:38–65` 的 `settings_and_policy(genesis)` 使用三个真实 ML-DSA seeded accounts，显式 `Settings::native_pq_application_v6`、两个 evaluator、public evaluation 与原 linear model；对应 network policy 使用独立 server/peer keys。NPQ6 constructor 继承 devnet 三个正确 development scope 字段，未被 fixture 改写。所有 profile 选择来自实际 constructor，不从入站 frame 或 child env 推断。

`Process::start`（175–188）实际启动相同 `current_exe()`，仅选择：

`--exact store::pq_rollback_witness::combined_tests::independent_witness_process_child --nocapture`

传递四个 env：fixture 目录、genesis timestamp、外部保留 checkpoint 的 sequence 和 root。**没有 account-profile env 或自动 downgrade 选择。** child（304–374）以同一 `settings_and_policy(genesis)` 重建 policy，随后只调用 `DurableWitness::open_existing`，不打开 Node、不重新 register witness。恢复 checkpoint 来自 parent 预先认证保留的值，不能从被恢复 SQLite 自行赋予 authority。独立 PID/ready 文件在 200–228 校验；child stdout/stderr 写私有 regular files，停止后截断上限检查 64 KiB，子 libtest summary 不作为父测试成功证据输出。

parent（489–524）先 register 一个新的独立 witness，启动 child，再 `Node::create_with_pq_witness`，构造实际 PQP6 block。真实 transfer 固定给第二账户增加 42（`ingress/pq_network/canonical_tests.rs:306–346` 显式 ApplicationV6 signing core/statement）。`create/open_with_pq_witness` 都经 `store/pq_network.rs:182–213` 的实际 policy/witness binding 检查、`StateBackend::PqWitnessV4`、common opener 及 ledger 校验。入站 native dispatch 从实际 Node 克隆 Settings，传 `packet_settings: Some(&settings)`（`ingress/pq_network.rs:1020–1053`），不会用经典 Packet 默认 decoder 代替 NPQ6。

## 原预算必须分别理解

| 约束 | 源码位置与实际范围 |
| --- | --- |
| 第一次 Submit、exact replay 各 10 秒 | combined fixture 581–586、632–638。两次独立 `sender.send`，并非前两项 recovery 的同一个 10 秒 campaign。client 从 connect 到 framing/响应 ML-DSA verify/final live check共用原 end（`ingress/pq_network.rs:684–699,802–819`）。 |
| PNQ2 signed expiry 为 prepare 时 now+60 秒 | fixture 545–553；replay 使用同一 prepared wire，不重签。内层账户 transaction expiry 为 genesis+200（canonical_tests 322），是另一约束。 |
| Node listener 30 秒、每连接 min(end,now+10 秒) | fixture 541；`ingress/pq_network.rs:1095–1103`。此独占 Node listener 先检查 owner，再创建 lifetime end，不能混同 shared listener 的启动计时。 |
| **每个 WitnessClient Current/CAS 硬封顶 250 ms** | `pq_rollback_witness.rs:76,330–342`：`min(original optional deadline, now+MAX_EXCHANGE)`；覆盖 challenge、request signing+self-verify、Unix exchange、reply context/ML-DSA verify、final check（348–449）。 |
| child 每次 serve_one 最多 10 秒，整个运行 60 秒 | combined fixture 338–348；这不是给 client 的 250 ms 续期。独立 child 的 request verify、SQLite CAS/read、signed reply、write 在其原 until 内（`pq_rollback_witness.rs:658–812`）。 |
| 每次 child startup 10 秒 | combined fixture 200–221；若 child 先退出，则保留 stderr 后独立 panic。 |
| 最后 node join → 保留 authenticated checkpoint → child stop 共用 10 秒 | fixture 643–658；只有完成后才 restart 并 cold open。send 失败时 cleanup 也用一个单独 10 秒区间，不能延长失败业务调用（435–464）。 |

本 PNQ2/witness路径没有第三项 large-parent 的 `ServiceMutationCpuDomain` 预算；phase recorder 的 calling-thread CPU 是观测，不能当成 CPU credit 或把嵌套区间相加。

## 本轮 guard 的可达范围与错误传播

新增 common opener guard（`store.rs:1814`）覆盖 create 与 cold reopen；native server startup（`ingress/pq_network.rs:1095`）通过 `check_pq_network_policy → namespace` 命中新完整 config digest。每个 connection/bytes/signature 的 durable ingress charge（`store/pq_network.rs:309–328`）、request begin（449–460）、finish（530–545）再次验证实际 owner。begin 中 `ready()` 与 `check_pq_network_policy()` 各经 namespace；M06 root 仍有前报告所列相邻重复 owner digest；激活和冷开恢复也交叉新增 guard。

因此不能用 witness fixture/服务文件未改来声称本 case 与本轮隔离。可是 **WitnessClient::request 的 250 ms 内层函数不调用 Node/Config guard**：它只处理已有 binding、signer、transport 和 response。Node guard 通常发生在进入 Current/CAS 前；它可以消耗外层 deadline 或间接影响调度，但没有实际 phase 数据不能直接解释一次内层 250 ms expiry，更不能宣布已证性能回归。

实际 mutation owner 在 `store/pq_rollback_witness.rs:172–240` 读 local checkpoint、向独立 witness 做 Current，再检查 protected root；commit（259–302）先原 live check，再外部 CAS，认证匹配 receipt 后必须与 local commit 配对，最后才能报告 late live-use 错误。`WitnessClient::request` 在 transport 前的失败不 poison client，在 transport 已进入后的错误会 fail closed（380–449）；mutation 会把失效 witness 的 execution epoch 设为 0（157–165）。所以 EOF、deadline、revocation、unavailable 不能互相替代解释；失败也不自动证明之前无远端或本地 effect。

scope/owner 检查在已经打开的 namespace 路径映射为 `LocalStructure`（`store.rs:2909–2912`），保留本地 owner-stop 语义；startup 则直接返回原错误。`PqServer::response` 可将 dispatch error 序列化成 signed `ok=false`（`ingress/pq_network.rs:899–914`），但更早的 read/charge/begin 或更晚的 finish 失败可能使该连接直接拒绝，client 只看到 EOF/transport error。字符串经网络出现并不会凭空获得本地完整性分类（`error.rs:235–242,277–279,343–353`）。必须同时看 server phase、client panic 与是否发出 authenticated response，不能靠单个诊断文本断因。

## 原断言与待取的现成证据

`SubmitControl::ValidOnly`（480–481）要求：首次 `.unwrap()` 在 586、`first.ok` 在 587、block ID 在 588；第二次发送后 638 要求完整 `first == replay`；643–658 要求真正 join、保留 witness checkpoint、成功 stop，metrics accepted=2/refused=0；659–667 独立 child restart + cold Node reopen；668–684 验 active tip、recipient balance `1_000_000_042`、native records=1、签名尝试及连接数均2、plaintext status、witness sequence增加；686 要求最终独立 child 成功停止。

原 recorder 已提供无需重跑的定位材料：`TRNM_PQ_PHASE_DIAGNOSTIC` / schema `pon-pq-test-phase-observation-v1`（`pq_rollback_witness/test_observation.rs:22,483–499`）带 parent/child process ID、last failure/service/TCP failure、last phase、wall/calling-thread CPU、original/effective remaining、transport entered、CAS/local commit attempt/committed、matching CAS receipt、unfinished/overwritten/incomplete 标记。child 保存首个非普通 EOF failure snapshot，parent 在 stop/failed stop/startup early-exit forward；scope Drop 也发原观测。缺失或 invalid snapshot 本身必须保留 unknown，不能补成完整 child 结果。

若 sender 返回 Err，`preserve_send_error`（444–464）在不替换原错误的情况下输出 `TRNM_PQ_FIXTURE_CLEANUP`：worker join、child exit、成功状态和各 cleanup error。若收到 `Ok(PqResponse {ok:false})`，则由 587 的 assertion 打印 `first.value`，不等于同一种 cleanup 路径。应完整保留原 panic 与这两类诊断行，不只摘最后一个 EOF。

## 对照及只读承诺

同名 JSON 保存 14 项 base→Z object 对照。combined fixture、witness service/client/observations、PQ network ingress/store owner、canonical transfer、error分类、NPQ6 constructor、devnet、Cargo.lock 均未变；`store.rs`/M06 executor 变化且可达。没有实际 base 执行，也没有定因或资格提升。

本次只读源及已回收 prefix、create-only 写后继诊断。未改 source、raw、前驱报告、预算或 flags；未跑测试、启动或重启远端 job，也未接触已清理的本地 target。继续等待该原 job 真正产生的 panic 与父 suite 终态。
