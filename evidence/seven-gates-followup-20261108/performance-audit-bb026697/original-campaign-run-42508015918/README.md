# 原 campaign 42508015918：三个真实失败的完整只读核验

**原生结果：三次均失败，九个 phase 全部未达合同；性能保持 HOLD。** 本目录没有重跑 native workload。构建成功、资源回执完整、原始记录完整，都没有被当作业务合同通过。

## 原生来源与保留物

- [GitHub run 42508015918](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42508015918)：原 PR 触发，attempt 1；2026-11-08T18:25:05Z 完成，conclusion=failure。
- 实际 Chain head：`bb026697a972521009bc133ae6ed2b653e18e931`；tree：`18175756871bf341586fc37be1b17a00ef1dd099`。八份 source 回执均为 head，同一完整来源，`prospective_merge=null`，23,515 entries / 2,382,494,143 tracked bytes。
- 原 artifact：`13629305491`；`pon-native-campaign-x64-head-release-bb026697a972521009bc133ae6ed2b653e18e931-1`。
- 原 ZIP：`original-campaign-bb026697-attempt-1.zip`，**71,966,725 bytes**，SHA256 **c696c8430a27d6c8a2ef5767c4e1f5dcfd4a48ee42fc044c8b0e966221ac3c43**。这是唯一下载副本，没有再次压缩或搬到 desktop。
- ZIP 1,766 个成员。原 `artifact-files.json` 列出的 **1,765/1,765 个文件、530,903,872 bytes** 全部通过长度和 SHA256 流式复核；文件集正好等于 manifest 加 manifest 自身，无遗漏替代。
- Manifest SHA256：`9fca857f830ac5ad3b499452d0c0000c44f4bde2b3894612806c77aa67cb37cd`。

原始 ZIP、GitHub job log、终态 API 元数据都保留。快速查阅用的 source/resource/result/readback 文件在 `selected-original/`，这些是从 ZIP 复制的原字节；该目录本身是明确的摘取集合，**没有冒充完整 artifact**。

## 三次执行，不以 build 代替运行

release build 实际成功，耗时 199.833776931 秒。编译器 artifact 为 opt-level 3、debug assertions false、overflow checks false、debuginfo 0。原生 ELF 大小 12,391,392 bytes：

```text
/home/runner/work/_temp/target-native-campaign/release/deps/public_v3_multiprocess-f2ec8cfbb025f448
sha256 9dfc5783ca20e453091cf7942f68840d69d83d9ee8bb8c14c51b62c5d71e216f
```

保留 binary payload SHA256、before/after 值、Cargo compiler artifact 和三次 stderr 的实际 Running executable 路径一致；各 phase job 的 binary SHA256 也相同。原三次命令都调用相同 selector：

`separate_process_work_and_signed_confirmation_campaign`

| Native attempt | 原退出码 | 实际耗时 | 原 stdout 结果 | economics | 有限 campaign |
| --- | ---: | ---: | --- | --- | --- |
| 1 | 101 | 113.345704638 秒 | 0 passed / 1 failed / 0 ignored | true | false |
| 2 | 101 | 113.083389905 秒 | 0 passed / 1 failed / 0 ignored | true | false |
| 3 | 101 | 113.018614029 秒 | 0 passed / 1 failed / 0 ignored | true | false |

三次没有 outer timeout、截断或 report validation failure，phase startup error 列表均为空；失败标签保留为 **ORIGINAL_THREE_RUN_CAMPAIGN_FAILED**。finalization failures 为空。它们不是编译失败或“没有启动”的占位结果。

## 原分母与具体失败

预登记 3 个 runs × 3 个 phases × 3 个确认槽，共 **27 槽**。每 phase 计划 21 个包，包含三笔业务交易所在块及其各自六个后继维护块；189 是包暴露总分母，不是业务交易数。

| Phase 类型（跨三次） | 计划确认槽 | 30 秒窗口内确认观察 | 已观察失败 | 未观察槽 | 严格四秒内确认 |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline | 9 | 3 | 3 | 3 | 0 |
| from-zero | 9 | 0 | 3 | 6 | 0 |
| late-product | 9 | 0 | 3 | 6 | 0 |
| 合计 | **27** | **3** | **9** | **15** | **0** |

三次 baseline 只有首轮达到 depth 6，从 t=1 秒的预定 offset 到确认分别为：

- 26.505864255 秒；
- 26.496085309 秒；
- 26.591701396 秒。

这些是匹配 fixture 的确认观察，不能当作三个独立真实业务成交。原 campaign 的接受条件只检查整个 30 秒窗口；本审计额外按原 t=1/5/9 计划投影出 **0/27 严格四秒成功**，没有修改原 predicate。失败或未观察槽未被删除，也没有变成零延迟。

全部九个 phase 都记录 `PUBLIC_REQUEST_DEADLINE`、`receiver_client_state_equal=false`、`finite_phase_criteria_met=false`；`observer_complete=true`。六个 hostile phase 都有 24 个 ready actors，actor 记录完整且未达调用 cap，但 **0/6 观察到 paid-credit depletion**。详细逐槽原值见 `phase-failure-projection.json`。

`qualified_goodput` 和完整业务确认尾延迟仍未建立；不能用三个迟到确认、ACK 数量、所有已终结请求的经验 p99 或剩余片段推算合格 TPS。`sustainable_business_tps`、`whole_request_population_p99_ns` 的原 reader scope 保持 null。

## 原资源合同确实保留

使用完整 clean bb clone `/workspace/scratch/3a200666069f/hepta_cell/chain-native` 的原验证器，只读验证了：

- 八份 controller 回执：`cpu.max=400000 100000`、16 GiB、nice 10、4 个 affinity CPUs；全部祖先限制通过原检查，cgroup 一致。
- 九个 phase 各四份 public Host 回执，共 36 份：`cpu.max=25000 100000`、burst 0、2 GiB、swap 0、256 PIDs。
- 原 root-owned parent 身份、unit bytes、非 root 执行 UID/GID、NoNewPrivileges、空 capability set、真实 service membership、before/after identity 都通过原 Host reader。
- 原 caller/resource profile、接收端与 verifier owner、业务 deadline 及 scalar policy 的“未改变”字段成立。
- 三份保留的 phase readback 由该精确 bb 源码重新派生，逐字段与原文件相同。

这些是对原内核读取回执与原记录的完整性验证，不是新的 native 运行或外部 host custody attestation。资源合同未被放宽，原业务失败仍然成立。

最终完整来源核验记录：`archive-verification-v3.json`。审计器执行前后又调用原 `verify_ci_source.py`，完整来源回执逐字段一致，保存在 `reader-full-source-before.json` / `reader-full-source-after.json`。

保留的较早审计尝试也不改写：v1 因当时 root 本地 checkout 已前进到 evidence-only ed947aa 而在入口拒绝；v2 仅用六个固定 bb 纯 reader 文件做独立数据核验，未冒充 native 全来源。v3 按 root 指定的完整 clean bb clone 重新核完。**上述是审计工具自身的来源记录，不增加原 CI 的失败次数。**

## 有原生观察支持的源码瓶颈线索

run 1 baseline 的首个单包 History import：

| 原观察项 | 数值 |
| --- | ---: |
| client import wall | 2.886510245 秒 |
| importer thread CPU | 590.478223 ms |
| Host checkpoint calls | 9,261 |
| Host checkpoint invoking-thread CPU | 510.971958 ms |

此原嵌套观察的完整投影和源 report SHA256 在 `baseline-first-import-projection.json`。三次 baseline 的八个 import 记录（七个成功、一个失败）各累计约 **24.32–24.39 秒 import wall**、**83,934–84,154 次 Host checkpoint**；hostile phases 的普通 History import 也消耗约 25.09–25.28 秒。详见 `history-cost-projection.json`。

这些数值是成本定位线索。Host CPU 汇总每个实际调用线程，importer CPU 排除 scoped workers；它们不是相同 CPU 范围。Host、import 和 admission/commit 阶段又相互嵌套，不能相加或直接算成完整 CPU 占比。失败 import 的已消耗 wall 也不是完成确认的尾延迟。

精确 bb 中已核到的高频路径：

1. [ingress.rs 的 observed History importer](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/bb026697a972521009bc133ae6ed2b653e18e931/trillionnium/crates/trnm-pon-node/src/ingress.rs#L2589) 将 resource closure 绑定到 `HistoryHostPhase::Checkpoint -> kernel.verify()`。
2. [store.rs 的持久化 state merge](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/bb026697a972521009bc133ae6ed2b653e18e931/trillionnium/crates/trnm-pon-node/src/store.rs#L5199) 对每个完整 State key 先执行 progress，再检查 unchanged 并 continue。
3. [native_store.rs 的账户图验证](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/bb026697a972521009bc133ae6ed2b653e18e931/trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_store.rs#L537) 对每个 popped leaf/fork 执行 progress。
4. [host_kernel_parent.rs 的 KernelBudget::check](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/bb026697a972521009bc133ae6ed2b653e18e931/trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs#L336) 每次读取 boot ID、线程 cgroup、五个资源限制，并检查 parent metadata/identity。
5. [scalar_cpu.rs 的受控信用等待](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/bb026697a972521009bc133ae6ed2b653e18e931/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs#L685) 也会在每次观察及每 5 ms refill wait 边界调用 resource。观测包装函数本身只执行一次 action。

上述调用链支持优先定位逐 State key、账户图节点和等待边界的完整 Host 读回成本；目前没有按调用来源细分 9,261 次的贡献，更没有证明某个修改能改善多少。后续优化必须保留完整 State/交易语义、当前 Host 资源与取消检查、原 CPU 信用、depth6、四秒和全部失败分母。本轮没有改任何契约或源码。

## 文件入口

- `archive-verification-v3.json`：最终完整来源、manifest、binary、资源与派生复核。
- `phase-failure-projection.json`：9 phases / 27 slots 的失败与缺失分母。
- `history-cost-projection.json`、`baseline-first-import-projection.json`：原成本和观测范围。
- `selected-original/results.json` 及 `selected-original/run-*-result.json`：原 native 返回与失败。
- `selected-original/run-*-phase-readback.json`：原请求阶段统计。
- `selected-original/*source*.json`、`*resource*.json` 及各 phase Host 四份回执：可直接复核的原身份和资源。
- `github-job-128814764770.log`、`terminal-github-observation.json`：真实 CI 终态。
- 原 ZIP 内保存全部原数据库、报告、raw producer/attack、可执行文件与剩余记录；大包未重复传输。

