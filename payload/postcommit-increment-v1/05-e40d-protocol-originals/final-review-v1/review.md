# e40d 两个 protocol-contract 原失败审阅

两条失败均为原 4 秒业务确认目标未达成。原五个具名 native 子测试完成并返回 0；随后 Python 对原报告的业务验收以 CONFIRMATION_TARGET 拒绝。两份完整 artifact 现已核对原上传/API SHA256，各 105 个成员完成 CRC 与 SHA256 验证。此结论仅绑定这两个原执行，不替代 dc42 的新 CI。

## 原运行和精确时间

Run 43551533528，attempt 1；候选 e40d7071c4724e6600deef8a2820bf35c1982289，base dd6e1c3cbeacbdc532b0679297835b3a0aac78f0。两个实际测试提交不同，但测试 tree 都是 6c6e1a3b1e3239a7cb95290485c1942ce22ef8a6，前后源码身份一致。

| 项目 | Head | Prospective merge |
|---|---|---|
| Job | 132340218588 | 132340218496 |
| 实际源码 | e40d7071c4724e6600deef8a2820bf35c1982289 | 7b8c580981d6fed6323ec968df660831759030bf |
| Job 开始 | 05:03:28 UTC | 05:03:28 UTC |
| 失败 step | 8: Run actual protocol-contract checks | 12: Execute the same lane on the prospective merge |
| Step 起止 | 05:06:05 → 05:59:06 UTC | 05:06:42 → 06:10:37 UTC |
| Job 完成 | 05:59:15 UTC | 06:10:46 UTC |
| Outer controller / exit 行 | 1405 / 1406 | 1419 / 1420 |
| Artifact | 14101871015 | 14102052271 |

日期全部为 2026-11-14。以上为 GitHub 原绝对时间；下表时间为各原 phase 的相对时钟，不把两个时钟混为一个时间线。

## 原始业务观测

两个无攻击 baseline 都达成 1/1 独立确认，延迟分别 1.481603063 秒和 3.088432160 秒，深度均为 6。两个压力 phase 都保留 16 workers、4,000,000,000 ns 原窗口；业务分别于窗口开始后 15,997,154 ns 和 96,066,340 ns 启动，没有在开始前耗尽窗口。

| 压力 phase 项目 | Head | Prospective merge |
|---|---:|---:|
| Signed submit ACK / 尝试 | 7 / 7 | 7 / 7 |
| History 返回成功 / 尝试 | 7 / 7 | 3 / 3 |
| 独立 page replay 接受 / 尝试 | 6 / 7 | 2 / 3 |
| Head 返回成功 / 尝试 | 29 / 30 | 22 / 23 |
| 窗口内独立确认 / 目标 | 0 / 1 | 0 / 1 |
| verification_errors | PUBLIC_REQUEST_DEADLINE | PUBLIC_REQUEST_DEADLINE |
| finite_business_target_met | false | false |
| invariant_target_met | true | true |

未确认延迟下界分别为 3,984,002,846 ns 和 3,903,933,660 ns，覆盖业务开始到原窗口结束的剩余时间；没有伪造成功延迟。独立最终确认对象为 null。保留有效前缀与完整最终状态不同：压力 phase 的 receiver_matches_valid_honest_prefix=true，full_native_state_equal=false，未据前者宣称完整链同步。

## 直接失败链

1. 原 Host controller 正常准备并调用 python3 scripts/ci/run_from_zero_native.py。两个 outer receipt 都为 systemd_run_exit=1、passed=false；failure=null、final_host_errors=[]，不能将其解释为 Host setup 失败。
2. 原 runner 的五次具名 native 子进程均 exit0、timed_out=false。格式与构建通过。service_report 与 sustained_report 验收通过。
3. 两个原 from-zero-native/manifest.json 第 230 行都保留 CONFIRMATION_TARGET；对应 confirmation/report.json 第 4 行都是 finite_target_met=false。
4. e40d 的 scripts/ci/run_from_zero_native.py 第 833 行调用 flags，要求根 finite_target_met、invariant_target_met、same_packet_sequence_in_both_runs 全为 true。第 499 行因第一个布尔值为 false 抛出 CONFIRMATION_TARGET。这是直接退出原因。之后的 confirmation packet/phase 严格检查未完成；本审阅不声称报告获得完整验收。
5. native collector 第 1770 行明确通过范围只是协议/记账不变量，第 1782 行只 assert invariants_passed；有限业务结果另行保留。故 native exit0 与 required CI 失败并不矛盾。

## dc42 是否已经修复

对 e40d 与 dc42 的精确 Git blob 比对显示，run_from_zero_native.py 的全部 23 个顶层函数/类 AST 相同，所选 validator、phase validator、run、flags 所在类的原始定义字节也相同。runner 文件变化只是加入三个 SP27 格式化模块。原 public_v3_from_zero.rs 完整字节在当前仍保留，唯一新增为九行 SP27 模块声明。三份完整 diff 与内容地址身份、逐定义证明随附。

当前 Rust 生产源码另外包含已审的 reactor/worker 等变更，这些变化可能影响实际时序。因此，未改变验收谓词并不能证明当前必败，也不能证明已经修复。需要 dc42 及其 prospective merge 在原限制下的真实 required CI 结果。没有用旧 cost 两份 artifact 的轨迹替代本次两条 protocol 轨迹，也没有新测试去归因某一个具体性能瓶颈。

## 完整性与取得范围

两次普通 GET 在 300 秒下载预算到时终止，原前缀和原失败回执保持。随后仅下载缺失区间，包含 64 KiB 重叠并核对一致；拼接全文件的大小与 SHA256 与 GitHub 原 metadata 及 outer 上传日志完全相同。各 105 个成员均读取并核对 CRC/SHA；先前用于初步诊断的 51 个完整 local members 逐一与最终 ZIP 对齐。

- Head ZIP：7,086,592 B；a9376da2bb9b73bcd1e0778b437bd44a7a264a8f791ed3e285658a844bd9092b。
- Prospective ZIP：6,791,534 B；5ed2193a574cb45206e0ac8b541f9c9d980fad5896c3ae85ea6e6fcb005babe0。

整个过程只读 GitHub 原日志/两个对应 artifact 和固定本地 Git 对象。未取消任务、未 dispatch、未重跑 native/CI、未修改源码或 refs。所有网络能力、激活与性能资格保持 false。完整 ZIP 独立保存；小凭据包保存索引、精确源码差异、原 outer log、原具名执行日志及本审阅，不重复嵌套两个 ZIP。
