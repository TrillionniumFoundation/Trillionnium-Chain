# 第三项 Node FAIL：large-parent 原 schedule / CPU owner（pre-panic 后继）

这是 `diagnostic_node_recovery_readonly.md`（SHA-256 `fa813f91f3e27694258eddcf196a25dbff0df7a1b8f85dee677ee1e249e1d983`）及其同名 JSON（`04e0ccb41f8e00f6921e52a2bf12b48b805b2a6024a01ab0fc8e45fcac621c64`）的**新增观察补充**，两份前驱原字节已重核且不覆盖。此补充也没有实际 panic 或终态结论。

## 新观察及边界

同一原 `/data` job `1a1c8ba754b-135c4-1d3`、同一 Z `cdd984808a088e6c2e13b1e1ae6630a94d500c89` Node lib 的连续前缀 `data-node-stdout-observed-prefix-0-111603.log` 为 111603 bytes，SHA-256 `1a9aa38f74c9055d08ed5ff7f0caa129e0479066fa13012e3f65b545c1978019`。931 行新增：

`store::detached_admission::tests::admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner ... FAILED`

前两个 NPQ6 FAIL 仍保留。932 行的 `authenticated_large_parent_original_schedule_supplementary_denominator ... ok` 是实际独立单项成功，它调用相同 helper 的 authenticated 分支；不能反推出失败一定在 legacy 分支，也不能抵消原测试失败。prefix 中若干 `1 passed; 1401 filtered` 是受控子进程结果，不是原 1402-test 父 suite 的总计。当前没有父 suite panic/summary。

## 这次是合法经典 development，不是 PQ config digest 热路径

下列源码路径均位于 `trillionnium/crates/trnm-pon-node/src/`，除非另行注明。

`store/detached_admission/tests.rs:796–799` 按 `[false,true]` 顺序对 legacy、authenticated 两个 backend 调用 helper；helper 的配置起点为 `Settings::development(Some(1))`（915）。测试只向 `settings.initial` 加入 2100 个各 4080-byte 的字符串 cell（916–920），然后重算 state root 和 genesis（922–931）；没有改 app.params。`lib.rs:335–415` 构造经典 development config，继承 devnet 三个正确 scope 值；M06 `pon_executor.rs:1102–1104` 私有 PQ owners 均为 None。

因此新 `check_account_profile` 在本 case 中执行 scope 字段检查、经典 selector 存在性/`native_pq_` key scan，**不会进入 PQ config_digest，也不会扫描或 canonicalize 8 MiB 的 initial State**。State 本来的 root/读取工作仍存在；不能把前两项 NPQ6 的“每次 namespace 增加完整 config digest”原样套用到这里。

新 guard 仍然可达：common open、`read_active`/namespace、admission 的 Node::ready/namespace、`root_for_config`、激活与冷开恢复。经典 `prepare`/execute 原已调用的 checker 也增加了 scope/selector 判断。其增量耗时没有实测，既不能据此确认性能回归，也不能仅凭较轻而排除边界影响。

## 实际流程、预算与精确待定位断言

helper（910–1084）先在待测 Node 和 reference 各真实 admit/activate 一笔签名 seed block；再构造含四笔签名 transfer 的 candidate（934–939）。检查 actual parent payload 超出原 8 MiB snapshot 上限后，`prepare_shared_admission` 必须返回 `HeldForSnapshotCapacity`，其 observed lower bound 大于上限且不超过实际 payload（946–965）。释放 lease 后 active State 必须未变（967–968）。这不是绕开 M06 的执行能力。

原 metered 路径在 969–987 行绑定单个 `ServiceMutationCpuDomain::standalone()`，并在调用前设 **10 秒绝对 wall deadline**。`ingress/metered_work_facts.rs:78–114` 在原 Node 锁内绑定同 domain 并 `begin()`，然后每个 checked callback 同时检查 caller deadline 与 live CPU；一次完整 W1、held M06 和 scoped workers 都用这一 accounting。即使 native 返回 Err，仍结算真实 CPU tail，再返回外层 `Ok { native, cpu }`；所以 `attempt.is_ok()` 不代表 native 接受。

原 CPU owner 在 `ingress/public_v3/scalar_cpu.rs:17–20,184–198,975–1009` 使用 **2 CPU 秒 burst、每 wall 秒 0.25 CPU 秒 refill、0.1 CPU 秒 start reserve、并发上限 2**；这是 CPU 资源账本，不能与 10 秒 wall deadline 混称。`ingress.rs:1328–1355` 另有 2 秒 admission owner/lease wait 上限。没有任何预算被本轮改变。

held 分支是 `ingress.rs:1374–1391` → `store/detached_admission.rs:333–355`（重验 namespace/storage/current owner）→ `store.rs:4953–5067`（当前 header/parent epoch 验证后执行原 M06），随后沿原 submit result 激活。新 guard 正位于这些 Node/root 边界；完整 config digest 不在这个经典 profile 分支中。

**最有价值的下一份证据是原 captured stdout，而非重跑：** 原 fixture 在严格 acceptance unwrap **之前**已经打印：

- 1018–1039：`native-large-parent-original-dispatch-diagnostic-v1`，含实际 `authenticated_backend`、dispatch elapsed、外层与 native 结果、CPU before/after 与 actual flow、arithmetic before/after、拒绝后的 active-state readback 或明确 readback error。
- 1043–1045：`native-large-parent-arithmetic-stages-v1`，保留拒绝时实际 stage counts。
- 1049 的 outer `attempt.unwrap()`；1052 的 `native-large-parent-schedule-parity-v1` 仅在 outer 成功后打印。
- 1054–1057 的 CPU accounting/worker/positive CPU 断言；1058 的 `result.native.unwrap()`；1060–1084 的 block ID、reference admit/activate、同 CPU domain、in_flight=0、完整 State/packet equality 与 cold reopen parity。

还可能在此前的 open、custom root、seed、Held 判定或 domain bind unwrap 失败。不能从测试名称或源码里已有“CPU-budget failure”注释来决定本次原因。只有捕获的 backend 字段、panic 行、实际 `Err` 和 accounting 明细才能区分 CPU 拒绝、wall deadline、unknown accounting、owner/State/schema 错误或最终 parity 失败；readback 缺失也不能算 unchanged。

## Base 对照与未做事项

同名 JSON 逐项绑定 base `df927b6ffaecff293b9e9428e3ba516f47cd101a` 与 Z 的 Git object。detached admission owner/全部 tests subtree、ingress.rs、metered W1、scalar CPU、Settings constructor、devnet 和 Cargo.lock 完全相同；store.rs 与 M06 executor 变化且在调用链上。没有完整依赖隔离结论，**也没有实际运行 base**，不称“历史失败已复现”。

本地读前后均为 clean Z。仅写 coordination 后继说明；未改原 pre-panic snapshot、source、raw、阈值或 flags，未运行 Cargo、触碰或重启远端作业。继续等待原 panic 后用新后继文件收窄结论。
