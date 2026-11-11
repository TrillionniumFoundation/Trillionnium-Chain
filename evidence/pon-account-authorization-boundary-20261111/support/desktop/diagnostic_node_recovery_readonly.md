# Node NPQ6 recovery 两个 FAIL 的只读诊断

## 当前可成立的结论

源固定为 `cdd984808a088e6c2e13b1e1ae6630a94d500c89`（Z），tree `1ed39b6ebe55cb00c238f26f6bfc9361ab93faec`；本地只读检查时工作树 clean。`/data` 原 job `1a1c8ba754b-135c4-1d3` 的实际 Node lib 已打印 1402 tests 和下列两个 FAIL，但本次读到的连续 stdout 前 71666 bytes **仍无 panic、失败汇总或完整 lane 终态**。

- `actual_npq6_lost_ack_and_cold_resume_reuse_exact_wire_without_history_consuming_sequence`
- `actual_npq6_plain_parent_recovery_and_cold_membership_keep_one_original_campaign`

这两个 fixture 的 NPQ6 配置按源码是合法正例，未发现缺失 scope 字段或主动修改 profile 的路径；**本轮新增 Node/M06 guard 确实进入它们的执行链，重复完整 PQ config digest 对既有时间预算的影响仍未排除**。不能用 TLS/recovery 文件未改来认定无关，也不能在实际 panic 出现前认定是本轮回归、环境问题或既有失败。没有实际运行 base 对照。

同一个已读 prefix 中，该文件的 hybrid TLS positive、call-cap、repeated-EOF、signed-expiry-label 四项均已打印 `ok`；这些单项结果不能代替两项失败诊断或整包成功。前缀未出现 `ACCOUNT_DEVELOPMENT_SCOPE_REQUIRED` 等文字不能排除该原因：Rust 仍未输出捕获的 panic。

## 精确 fixture 与断言

以下行号均针对 Z。路径前缀 `node/` 指 `trillionnium/crates/trnm-pon-node/src/`，`m06/` 指 `trillionnium/crates/trnm-mvcc-fee/src/`。完整 Git object 对照及原 prefix SHA 位于同名 JSON。

| Case | 实际行为与必须保持的断言 | 尚待 panic 定位 |
| --- | --- | --- |
| plain positive | `node/ingress/pq_network/tls/shared_tests/recovery_cases.rs:33–141`：两块真实 NPQ6；先发 target 得 `UNKNOWN_PARENT`，恢复 parent 后再发 target，native sequence 应为 `[1,2,3]`，三张 receipt 均持久化；创建成功断言在 56–60，保留字节与账本条数为 3；再冷开 producer、用同一 journal Resume，130–134 要求成功，135–141 要求零 native 重发、epoch/binding/operations 不变且仍三条 native record。入口 144–145。 | 可能在 fixture 建立、reopen、Create/Resume unwrap、成功/顺序/字节断言或 server Drop；目前不能选择其中一个。 |
| lost ACK | 同文件 153–238：一块真实 NPQ6；代理第一次转发实际请求并读取原生签名 receipt 后丢弃，第二次返回完整非法 frame 长度；首次应 uncertain，pending sequence/attempts `(1,2)`，两次 native attempt 都为 sequence 1，无本地 receipt；176–197 核这些断言及 remote 已真正执行一次。冷开 Resume 后 209–213 要求成功，216–237 要求恰好一次 sequence 1 重发、原 expires_at/wire SHA 不变、三次传输逐字节相同、native records 仍为 1。 | 首次“预期失败”断言不等于测试预期失败；是否发生在首次故障模型、Resume 或最终 replay 断言，必须看 panic 行和值。 |

`recovery_cases/fixture.rs:96–117` 使用 `Settings::native_pq_application_v6`，实际开两个 PQ network Node，生产者执行签名交易、admit、activate（122–139）；`reopen`（261–271）只冷开 producer，保持相同 Settings clone 与 policy，远端 owner 为共享的原 Node。代理故障在 `recovery_cases/proxy.rs:54–74`；它不伪造授权成功，首次读取真实响应才丢 ACK。fixture/proxy 的 Drop 在未已有 panic 时会 unwrap worker 返回值，因此需保留 panic 完整位置，不能只检索 recovery outcome。

## 合法配置与本轮实际交叉

配置链为 `node/pq_application_v6.rs:43–56` → `m06/pon_executor/pq_accounts_v2/application_v6.rs:24–35,53–87` → `Config::installed_with_model_profiles`（`m06/pon_executor.rs:531–538`）。加载的 `config/pon/devnet-v1.json` 在 4/22/52 行分别给出 `not_mainnet=true`、`coin_atomic_unit="test-unit-no-market-value"`、`production_activation=false`。NPQ6 constructor 后续写入自身 selector、context 和私有 owner（`pq_accounts_v2.rs:297–304,325–389,423–427`），fixture 之后没有改 params。合法 NPQ6 在新 `check_account_profile`（`pon_executor.rs:1144–1170`）进入 `pq_accounts_v2::check_config` 并立即返回，不走经典 selector 拒绝分支。该事实排除了明显固定字段缺失，但不等于测得运行时无任何配置损坏。

**新增调用不是仅三个布尔/字符串比较。** `pq_accounts_v2.rs:51–82` 的 `policy` 每次重做 `config_digest`：canonical params、model registry、fees、evaluators，并绑定 network/parameters/family/plan。这里没有缓存 verdict。

| 可从源码确定的新工作 | 精确调用链及计数边界 |
| --- | --- |
| 每个 `Session::ready` 新增一次直接完整 config digest | `public_submit/pq/recovery/observations.rs:8–16` → `PinnedPqRecoveryClient::validate_for_node/compute_context`（`public_submit/pq.rs:149–178`）→ `Node::check_pq_network_policy`（`store/pq_network.rs:216–238`）→ `namespace` 新 guard（`store.rs:2905–2912`）。 |
| 正常完成一次 history_call 的直接新增检查至少四次 | `observations.rs:53,61,88` 的三次 ready，加 `read_history` 在 `public_submit/pq.rs:262` 自身的 validate；不包含 journal 内部、远端 history owner 或其余 Node 读操作。 |
| 正常完成一次 send_packet 的直接 ready 新增检查五次 | `recovery/delivery.rs:27,44,46,70,121`；未把编码时原来已有的 PQ owner 检查误算成新加，也未计 journal/远端执行。 |
| 每次有效 NPQ6 state_root 增加一次直接 digest | `node/lib.rs:596–597` → `m06/pon_executor.rs:493–495` 先新 check，再原 `validate_state`；后者在 `pq_accounts_v2.rs:450–454` 本来就调用 policy。两次直接 digest 替代原一次。`observations.rs:128,166` 明确调用 state_root，重放/读 active 内部还可能调用。 |
| 冷开、warm reads、恢复与激活继续命中新检查 | common open `store.rs:1814`，其恢复调用 2304；`read_active` 在 3615 调 namespace；恢复 6631–6649 先 check 后 namespace/activate；activate 在 6160–6171 先 check 再 namespace。`Node::ready` 在 3657–3658 调 namespace，admission 在 4300 调 Node::ready。 |

这些是**源码中固定成功分支的直接调用点**，不是记录到的总次数或耗时。中间拒绝、重试、journal 调用和远端路径会改变实际次数；没有 profile 或计时日志，无法算出它们是否把此次请求推过限额。旧 prepare/execute 的 `check_account_profile` 调用点已经存在；本轮修改其内容并新增 root/Node 等调用，不能把所有现有检查都当新代码。

## 原预算确实覆盖冷开与 Resume

- `recovery_cases.rs:17–18` 每个 campaign 只有 10 秒。positive 在 40 行创建 plan 后才 41 行 reopen；lost ACK 在 163 行创建 plan 后才 164 行 reopen。后续 Resume 使用相同 journal，不新建 plan。
- `public_submit.rs:37–49` 默认每包最多 3 次 submit、16 次总调用、最多 1 parent、100 ms retry pause。`journal.rs:89–106` 持久化同一 BOOTTIME 绝对 deadline，`478–505` 冷开只减少剩余时间。`observations.rs:8–16` 取旧 deadline 与当前读回值的 min，且前后检查 alive。
- Native signed request 的 expires_at 由剩余时间的**整秒下取整**生成，保留原 prepared bytes（`delivery.rs:32–43`）；native send deadline 是 campaign deadline 与 now+10 秒的 min（71–78）。该独立签名失效约束也可能在 cold resume 时相关，但没有 panic 不能宣称实际过期。
- 实际 pinned History Head readiness 有独立 5 秒并在 campaign 前完成（fixture 222–232）；两个服务 lifetime 为 30 秒（fixture 162–201）。共享 native server startup 和每连接最多 10 秒且受原 30 秒 end 约束（`pq_network/shared.rs:99–111`）。代理同样 30 秒总寿命、每连接 min(end,now+10 秒)（proxy 30–35）。这些并非可互换或自动续期的预算。

## Base→Z 对照与最小下一步

Git object 校验确认 recovery case、fixture/proxy subtree、public_submit 文件及 subtree、NPQ6 constructor、PQ owner private config digest、PQ network ingress subtree、devnet 配置、Node/M06 manifests、workspace manifest/lock、crypto/protocol trees均与 base `df927b6ffaecff293b9e9428e3ba516f47cd101a` 相同。但 Node `store.rs` 和 M06 `pon_executor.rs` 明确变化且在上述实际链上，**不具备 DA 两失败那样的源码依赖隔离结论**。所有完整 object ID 在同名 JSON；未在 base 实际运行。

当前最小有意义动作是收齐**原 job** 捕获的 panic/file/line/断言值或 outcome.failure、完整 summary，以及最终 context/result/source-after（只有实际产生才可记录）。优先区分启动/冷开 owner 错误、Create vs Resume 的 deadline/签名过期、CPU/调用/attempt 上限、代理 framing、receipt/sequence/state 断言和 worker join。若 panic 仅给 deadline，还需要已有 observation 的 elapsed/remaining/error 字段才能缩小到具体阶段；目前 stdout 没有这些失败对象明细。是否需要后继受控诊断应由完整 panic 决定，不能靠改 deadline/quota/skip/优化 flags 把原失败改绿。

本报告仅做本地只读源/原日志分析；未运行 Cargo、未接触远端 record、未改 source/raw/阈值或重启 job。它不授予 Z、将来的 E 或 hosted CI 任何新的资格。
