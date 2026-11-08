# 唯一 F0 原生运行：精确 bb，真实失败，HOLD

[GitHub run 42509669473](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42509669473)，workflow 399731485，job 128819775064，attempt 1。由 ProfHepta 对固定分支合法 dispatch 一次；本审计只读，没有 rerun、第二次 dispatch、伪造 CI 或本地 provision。

## 已观察到的结论

真实 selector 已执行 **73.538234190 秒，exit 101，0 passed / 1 failed**。准备工作、release build 和七个原生 source controls 都完成，但 pair 的原性能条件未通过：

- execution failure：`NATIVE_F0_FAILED`；
- 原 report reader 拒绝：`BASELINE_MUST_PASS`；
- 独立调用同一来源的 placement/timing reader，拒绝：`F0_ALL_SIX_SCHEDULED_FOUR_SECOND_TARGETS_REQUIRED`；
- 六个预登记确认槽严格四秒成功 **0/6**；一个在原 30 秒阶段内确认，两个已观察槽失败，三个槽未观察；
- 两阶段均有 `PUBLIC_REQUEST_DEADLINE`，`receiver_client_state_equal=false`，没有付费 credit 耗尽观察；
- 最终三项服务均通过 exact ownership 复核、已知为空、failure 为 null，未执行额外 cleanup。finalization 的 exit 1 正确保留 native/确认失败，**不是一个新发现的清理错误**。

[artifact-audit.json](artifact-audit.json) 包含完整回算、全部六槽/42 packet exposures、资源、源码、ELF 和原件哈希。[audit_original_artifact.py](audit_original_artifact.py) 只调用固定来源的纯 reader，不执行 native workload 或服务管理。

## 严格保留六槽和 42 个 packet exposures

工作负载仍为 seed 1024 transfers / 4 blocks；每阶段同一准备好的 21 个业务包，baseline 与 valid-work-root 各 30 秒；调度 t=1、5、9 秒，确认深度 6，24 个 hostile 进程，1 个 M06 worker。21 个包是三个“一个含交易区块 + 六个维护区块”的序列，不是 21 笔确认交易。

| phase / round | 调度秒 | 实际开始秒 | 实际结束秒 | 从调度到结束秒 | 结果 |
| --- | ---: | ---: | ---: | ---: | --- |
| baseline / 0 | 1 | 1.000387714 | 23.602926924 | 22.602926924 | depth 6，30 秒内确认；超出四秒 |
| baseline / 1 | 5 | 23.602937360 | 30.000761514 | 25.000761514 | 已观察失败 |
| baseline / 2 | 9 | null | null | null | 未观察，仍计入分母 |
| valid-work-root / 0 | 1 | 1.000453796 | 30.078096535 | 29.078096535 | 已观察失败 |
| valid-work-root / 1 | 5 | null | null | null | 未观察，仍计入分母 |
| valid-work-root / 2 | 9 | null | null | null | 未观察，仍计入分母 |

42 个 planned packet exposures 全部保留：21 个有实际请求、28 次总请求尝试、21 个窗内 network ACK。ACK 不是确认；没有删掉另外 21 个未观察 exposure。这里的失败耗时不是成功确认延迟，不能与唯一成功槽合成“合格尾延迟”。

`qualified_goodput=null`、`qualified_tail_latency=null`。上述 0/6 是这个预登记有限 workload 的结果，不是总体吞吐容量定理，也不是原三次 campaign 的替代记录。

## 来源、build 与实际执行文件

| 项 | 原始身份 |
| --- | --- |
| Chain head | `bb026697a972521009bc133ae6ed2b653e18e931` |
| tree | `18175756871bf341586fc37be1b17a00ef1dd099` |
| workflow path | `.github/workflows/pon-fixed-host-root-f0.yml` |
| runner SHA-256 | `abf75f729dcb54d7c2bebf2c54c253c5164e801b7ebcc642bb8ba58290518cca` |
| prepared manifest SHA-256 | `b52907bd9ea4b0d34a00bf0d1d27391deb895fd4cc09595372835ad4abdac59e` |
| 实际 retained ELF | `prepared/public_v3_multiprocess.bin`，12,391,424 bytes |
| 实际 ELF SHA-256 | `e38433c515bf93f0edfb6f4e61cefabf8d7266bcb425a596c788e183444e79e1` |
| 原 report SHA-256 | `a504afd7c75c081d974f78a20c17983c65ac8b12a22fe8e68f59e6080a9db3df` |

六份 CI source receipts 在整个 workflow、preparation、execution 的 before/after 完全一致，均为完整 23,515 文件 / 2,382,494,143 bytes。审计时的 pure readers 来自完整 clean bb clone，并在审计前后分别调用原 `verify_ci_source.py` 重新核对全部 tracked bytes；[before](reader-source-before.json) 与 [after](reader-source-after.json) 均为 SHA-256 `326ae5e61f108651760b3a27b42ae0d5091ec224be724d96fc622498e55a34aa`。

Rust 1.95.0、locked graph、release opt-level 3、debug assertions false、overflow checks false、debuginfo 0。实际 compiler artifact 与 retained ELF 元数据、controller intent/live receipt、两个 phase job 的 SHA-256 绑定一致。七个指定 source controls 都是每次实际 1 passed，尚未执行业务 selector 时的 `selector_invocation_attempted=false` 仍被保留。随后独立实际执行 selector，并在失败后分别完成 binary/source/resources 的 post-observation。

此 ELF 与原 campaign 的 ELF 是分别构建并分别记录的产物；不因为同一 commit 就把两个 binary hash 合并。这里验证的是原 CI 的实际文件和进程回执，不等于外部独立运营方的托管证明或完整动态加载闭包。

## 原资源和服务归属未改变

- controller 实际 `cpu.max=400000 100000`、16 GiB memory ceiling、nice 10、affinity 四 CPU；上下祖先没有更低 CPU/内存限制。16 GiB 是限额，不声称保留了对应独占物理资源。
- 两个 public phase 都保持 `cpu.max=25000 100000`、burst 0、2 GiB、swap 0、pids 256、uid/gid 1001、无 capabilities、NoNewPrivs。六份 before/after/outside 原 Host 样本经固定来源 validator 无错误。
- controller 由真实已声明 systemd service 承载，MainPID/boot/start/cgroup/intent/live receipt 一致，RuntimeMax 实测 10min，native 外层预算仍为 540 秒。
- 六个 controller boundary samples（每 phase before-launch / actors-ready / after-reap）经过原 parser 完整重算，与 execution/finalization 的 summary 相等。hostile 24 个进程全部就绪并被原 controller 记录回收，未混入 receiver 的 public Host。
- 两 phase launcher 的 `passed=true` 只表示 Host 与进程退出/归属链有效；其 `service_or_depletion_criteria_met=false` 原样保留，不转作业务通过。

ROOT 侧还保留了实际的 hostile packets live/cold 不出现、cold state equal、whole-domain paid settlement 等组件观察；`expected_legal_counts_and_tip=false` 和 `criteria_met=false` 同样保留，不能只挑正项关闭总体性能门。

## 原件与完整核对

原 artifact **13629594740**：

- [f0-bb026697-attempt-1.zip](f0-bb026697-attempt-1.zip)
- **17,336,784 bytes**
- SHA-256 **`b11e386e99d56722090bf3a31be0a575d053deb58458fcc8e77fa7c98b29157d`**
- 444 members / 69,854,604 uncompressed bytes
- 443 个 manifest 成员的 bytes/SHA-256 全部核对，manifest 本身由 ZIP digest 绑定；333 个 execution nested inventory 成员全部核对。
- [selected-original](selected-original/) 保存 118 份便于复核的原文件，6,217,966 bytes；原 report、完整 SQLite、ELF 等仍完整保存在 ZIP，没有全包解压或重压缩。
- 原失败 job 全日志、terminal GitHub metadata 另存；旧 queued/404/no-run/handoff 观察不被覆盖。
- 原 finalizer 的 `final_report` 在临时只读证据副本上重算，结果与原 denominator 完全相同；不调用 service finalization/cleanup。临时副本随后删除，原 ZIP 保留。
- 独立审计完成不表示原生 PASS；结论始终为 HOLD。

所有六项资格仍明确为 false：`original_campaign_qualified`、`work_profile_qualified`、`independent_operators`、`wan_qualified`、`production_candidate`、`production_activation`。此处没有 F1、新工作预算、外部资金效果、独立 WAN 或生产启用。
