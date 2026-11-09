# 原始 campaign、QROM 工作流与 History 观测回读（2026-11-09）

**总体状态：HOLD。** 本组证据细化了三份已经失败的原始 campaign，并修正 QROM 工作流把历史固定输入与当前源码混在一起的诊断边界。三份 artifact 共九次原始 campaign，整体通过次数仍为 **0 / 9**；没有新增原始 campaign 通过、吞吐资格、密码学 soundness、量子工作、生产或发布资格。

本目录保存原始字节、离线派生报告及明确的省略清单。完整原始 ZIP 的离线重读、Python reader 控制、QROM 分项本地验证与本轮最终源码的全仓／托管 CI 验证各自记录；最终 commit、push、托管结果尚待主代理补入本页第 8 节。未完成或缺少记录的项目不能据此成为成功。

## 1. 原始运行与源码身份

以下三份 ZIP 均按 GitHub artifact 的外部 SHA-256 校验；每份 ZIP 的原始 manifest 列出 1,765 个其他成员，连同 manifest 共 1,766 个成员。最终离线 reader 读取并核对了全部列出成员的字节数及 SHA-256，再核对原始 source-before/source-after、构建步骤、二进制、资源记录和三轮报告。此项为证据一致性校验，不重新执行 ZIP 内的程序，也不单独证明执行宿主的可信性。

| Actions run | Artifact ID | 实际 head commit | 实际 source tree |
|---|---:|---|---|
| [42575267109](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42575267109) | 13655237880 | `e2a02f9271b49f146e70806c8a66e161b5973971` | `86d2014b560659106b3af6e6c19e1f82a290a60e` |
| [42579873262](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42579873262) | 13656714263 | `097f59f505f8ec42f72e3b8255e6cb7822a70646` | `4b1eb80fa88b0b8f98d216247f7b8bce2df73f20` |
| [42591962205](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42591962205) | 13662172930 | `0746a462e80067b78317597f2fa4bacf5e3db958` | `03c69f3120a84f49fd7a76d9564bba4ef0c4b24e` |

| Actions run | 完整 ZIP 字节数 | 完整 ZIP SHA-256 |
|---|---:|---|
| 42575267109 | 75,991,850 | `2ebd97384564cf6d491f1f09ba3f11d0b1aba79f6feb19b327c3b06d8ae0cc9f` |
| 42579873262 | 70,035,072 | `1fd9e41eb0f2c47b3ad7009cf1106fbefb9ab5185a34952d02d379e602e499b7` |
| 42591962205 | 76,441,344 | `4e8a243caf2aadf4a195b4cb96dbb0229a0e001a830f0e9de2c4f853ee7dff5c` |

直接来源为各运行的 [#835 metadata](raw/run-42575267109/original-artifact-metadata.json)、[原 #836 metadata](raw/run-42579873262/original-artifact-metadata.json) 和 [最新 #836 metadata](raw/run-42591962205/original-artifact-metadata.json)。最新 #836 的记录补充原先两条运行，不能替换或改写原先失败记录。

三组原始输入保持一致：每轮含 baseline、from-zero、late-product 三个 30 秒 phase，进程数为 0 / 24 / 24；准备 1,024 个实际签名 seed transfers、4 个 seed blocks 和 21 个 business blocks。每个 phase 计划三个确认轮次。构建成功，`phase_startup_errors=[]`，源码与二进制身份均有记录。资源记录及其 ancestor 链通过已有严格 resource reader，不能统一套用早期缺少 cgroup 前提的解释。资源上限记录为 `cpu.max=400000 100000`、`memory.max=17179869184`、nice 10；物理硬件观察不等同于保留给该任务的资源承诺。

## 2. 全部 27 个 phase 的真实确认与观察数

“已观察”表示原始报告包含对应确认轮次；“已确认”要求在原始压力窗口内真实 confirmed；“未观察”是计划轮次中缺少观察的数量。未观察不补成成功，也不补成零成本。这里的分母是确认轮次，不是业务块数量。

| Actions run | Campaign | Phase | 计划轮次 | 已观察 | 已确认 | 未观察 | 原始 verifier 错误／补充失败 |
|---|---:|---|---:|---:|---:|---:|---|
| 42575267109 | 1 | baseline | 3 | 2 | 1 | 1 | PUBLIC_REQUEST_DEADLINE |
| 42575267109 | 1 | from-zero | 3 | 1 | 0 | 2 | PUBLIC_REQUEST_DEADLINE |
| 42575267109 | 1 | late-product | 3 | 1 | 0 | 2 | PUBLIC_REQUEST_DEADLINE |
| 42575267109 | 2 | baseline | 3 | 2 | 1 | 1 | PUBLIC_REQUEST_DEADLINE |
| 42575267109 | 2 | from-zero | 3 | 1 | 0 | 2 | PUBLIC_REQUEST_DEADLINE |
| 42575267109 | 2 | late-product | 3 | 1 | 0 | 2 | PUBLIC_REQUEST_DEADLINE |
| 42575267109 | 3 | baseline | 3 | 2 | 1 | 1 | PUBLIC_REQUEST_DEADLINE |
| 42575267109 | 3 | from-zero | 3 | 1 | 0 | 2 | PUBLIC_REQUEST_DEADLINE |
| 42575267109 | 3 | late-product | 3 | 1 | 0 | 2 | PUBLIC_REQUEST_DEADLINE |
| 42579873262 | 1 | baseline | 3 | 2 | 1 | 1 | []；后续提交发生 IO 错误 |
| 42579873262 | 1 | from-zero | 3 | 1 | 0 | 2 | PUBLIC_REQUEST_DEADLINE |
| 42579873262 | 1 | late-product | 3 | 1 | 0 | 2 | PUBLIC_REQUEST_DEADLINE |
| 42579873262 | 2 | baseline | 3 | 2 | 1 | 1 | []；后续提交发生 IO 错误 |
| 42579873262 | 2 | from-zero | 3 | 1 | 0 | 2 | PUBLIC_REQUEST_DEADLINE |
| 42579873262 | 2 | late-product | 3 | 1 | 0 | 2 | PUBLIC_REQUEST_DEADLINE |
| 42579873262 | 3 | baseline | 3 | 2 | 1 | 1 | []；后续提交发生 IO 错误 |
| 42579873262 | 3 | from-zero | 3 | 1 | 0 | 2 | PUBLIC_REQUEST_DEADLINE |
| 42579873262 | 3 | late-product | 3 | 1 | 0 | 2 | PUBLIC_REQUEST_DEADLINE |
| 42591962205 | 1 | baseline | 3 | 2 | 1 | 1 | PUBLIC_REQUEST_DEADLINE |
| 42591962205 | 1 | from-zero | 3 | 1 | 0 | 2 | PUBLIC_REQUEST_DEADLINE |
| 42591962205 | 1 | late-product | 3 | 1 | 0 | 2 | PUBLIC_REQUEST_DEADLINE |
| 42591962205 | 2 | baseline | 3 | 2 | 1 | 1 | PUBLIC_REQUEST_DEADLINE |
| 42591962205 | 2 | from-zero | 3 | 1 | 0 | 2 | PUBLIC_REQUEST_DEADLINE |
| 42591962205 | 2 | late-product | 3 | 1 | 0 | 2 | PUBLIC_REQUEST_DEADLINE |
| 42591962205 | 3 | baseline | 3 | 2 | 1 | 1 | PUBLIC_REQUEST_DEADLINE |
| 42591962205 | 3 | from-zero | 3 | 1 | 0 | 2 | PUBLIC_REQUEST_DEADLINE |
| 42591962205 | 3 | late-product | 3 | 1 | 0 | 2 | PUBLIC_REQUEST_DEADLINE |

每份 artifact 的总数均为 **计划 27、已观察 12、已确认 3、未观察 15**。三份合计为计划 81、已观察 36、已确认 9、未观察 45。每轮 baseline 确认了 1 / 3，另外两个 phase 为 0 / 3；因此不能写成 baseline 也完全没有确认。所有原始步骤仍为 exit 101，各原始 campaign 的 `complete_success=false`，各 phase 的原始有限标准仍未满足。

证据分别见 [#835 逐轮派生记录](raw/run-42575267109/diagnostic-readback.json)、[原 #836 逐轮派生记录](raw/run-42579873262/diagnostic-readback.json)、[最新 #836 逐轮派生记录](raw/run-42591962205/diagnostic-readback.json)。每项派生记录绑定被读取原始报告和原始 phase-readback 的哈希，并与仓库已有 phase derivation 全量比较。

### 失败签名不能混为同一种

#835 与最新 #836 的全部九个 phase 均有 `PUBLIC_REQUEST_DEADLINE`。原 #836 的六个压力 phase 也有该错误；其三个 baseline 的 `verifier_errors=[]`，但后续提交记录了 `IO: Resource temporarily unavailable (os error 11)`，且 `returned_after_window=true`。空 verifier 错误数组不能证明整个 phase 成功。

三组记录中 observer_complete 与 economics_complete 并没有把失败变成通过；未观察到 genuine paid budget depletion，receiver/client 的最终状态也不相同。deadline 所在的最后一个 span 是“错误被观察到的位置”，不能单独充当累计费用的唯一根因。详见上述 JSON 内的 `submission_failures`、`history`、`packet_failures`、原始 verdict 和阶段时钟。

## 3. 相同二进制与不同硬件的比较边界

| Actions run | 原始 CPU 型号 | 可见逻辑 CPU | 二进制字节数 | native 二进制 SHA-256 |
|---|---|---:|---:|---|
| 42575267109 | AMD EPYC 9V74 80-Core Processor | 4 | 12,601,232 | `a1b0c4e61d46e5e59187b3fd2620cdc24f66fb8905d1c43ab81b619055601205` |
| 42579873262 | AMD EPYC 7763 64-Core Processor | 4 | 12,646,984 | `3afe1ecc5953bb4e5b3066fe07fb11b68a74faac787f4f81c5c15209a97a86f1` |
| 42591962205 | AMD EPYC 9V74 80-Core Processor | 4 | 12,646,984 | `3afe1ecc5953bb4e5b3066fe07fb11b68a74faac787f4f81c5c15209a97a86f1` |

原 #836 与最新 #836 的 native 二进制完全相同，但记录的 CPU 型号不同。下面是真实 baseline 第一轮确认时间，不能据其差异声称新版二进制优化已经生效，也不能据型号信息单独断言硬件是唯一原因。

| Actions run | Campaign 1（秒） | Campaign 2（秒） | Campaign 3（秒） |
|---|---:|---:|---:|
| 42575267109 | 23.597130044 | 23.842943780 | 23.796008243 |
| 42579873262 | 28.281750522 | 28.082411371 | 27.996195472 |
| 42591962205 | 23.588896450 | 23.601849088 | 23.606087135 |

这些时间来自各报告的 `confirmations[].ended_ns`；二进制与硬件身份来自同份 readback 的 `binary` 和 `hardware` 字段。三个 phase 的压力进程数和实际执行窗口保持原始定义。

## 4. History Host 费用热点与新增观测的限度

原始记录足以指出需要继续拆分的累计费用。例如原 #836 三轮 baseline 的第七次 History import 均记录 **29,954 次 Host checkpoint**；该次 import wall 分别为 9.009516723、9.001825180、8.992421593 秒，importer-thread CPU 分别为 2.032775309、2.025538200、2.013055151 秒，checkpoint 的 invoking-thread CPU 分别为 1.664923970、1.660569225、1.647512571 秒。原始 Host 调用和整个 import 的时钟范围相互重叠，不能相加或直接算作同一 CPU 分母下的根因占比。数据保存在 [原 #836 readback](raw/run-42579873262/diagnostic-readback.json) 的 baseline History 第七条导入观测中。

源码路径经过 `history_import::admit_packet`、`ServiceMutationCpuOperation::history_checkpoint`、`LiveRequestCpu::observe_with_control`、`Control::check`、`HostKernelBudget::verify` 和 `KernelBudget::check`。这些检查仍涉及当次调用线程和当时真实内核状态；本轮没有用缓存旧 Host 读数代替它们，也没有提高 deadline、降低确认标准或跳过状态图检查。源码入口见 [history_import.rs](../../trillionnium/crates/trnm-pon-node/src/ingress/history_import.rs)、[scalar_cpu.rs](../../trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs) 与 [host_kernel_parent.rs](../../trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs)。

本轮 Rust 变更增加可选嵌套 `pon-local-history-host-phase-attribution-v1`：十九个既有 owner phase 加一个 unknown 槽，共二十个固定槽，复用原始 Host 调用时钟与原有观测互斥锁。分类发生在实际 checkpoint 进入时；worker 的调用归属到当时 owner phase，但 CPU 仍属于实际调用线程。该归属不能解释成 owner 自身 CPU，也不是全部 worker CPU。新增的桶与原始 aggregate 重叠，wall 累计也可能跨线程重叠。

`all_checkpoint_calls_attributed` 只表示 observer measurement_failures 为零、unknown 调用为零且已归属调用数守恒。它不表示所有调用都 accepted、全部时钟已知、整个服务完成或获得共识权限。零调用也可以满足该分类条件。计数和时钟缺失保持未知；原始 action、deadline、取消、预算、错误和 panic 传播不得因观测改变。

源文件为 [History observation](../../trillionnium/crates/trnm-pon-node/src/ingress/history_import/observation.rs) 和 [request observation](../../trillionnium/crates/trnm-pon-node/src/ingress/public_v3/request_observation.rs)。这两文件的最终编译、测试和完整源码身份由第 8 节的最终验证记录补齐。**该变更目前没有获得性能改善或原始 campaign 资格。**

三份历史 artifact 分别有 64 / 46 / 66 条 History native observation，均未记录新扩展；新 reader 明确输出 `availability: "absent"`，不对旧数据事后补造阶段归属。已有 aggregate 可定位费用热点，但精确阶段费用、因果主次及任何优化收益仍需要新证据。

## 5. 失败诊断 reader：成功读取不授予验收通过

新增 [read_failed_native_campaign_zip.py](../../scripts/read_failed_native_campaign_zip.py) 复用已有 [read_original_native_campaign.py](../../scripts/read_original_native_campaign.py) 的严格 JSON、路径、摘要、source、resource、步骤和 phase derivation 逻辑。原 positive acceptance reader 未改动；原始 exit 101 仍被其“步骤必须成功”条件拒绝。诊断 reader 记录该拒绝，不能覆盖它。

诊断 reader 以有界、固定文件描述符读取整个 ZIP，不解压或执行 payload；拒绝外部摘要不符、成员摘要不符、路径逃逸、重复成员、重复 JSON key、nonfinite 值、遗漏 manifest 成员、源码身份漂移、计数冲突和回归。完整原始 phase derivation 必须相等。输出写入新文件，不能覆盖已有结果。成功 campaign 必须交还原 acceptance reader，不由失败诊断入口赋予资格。

[27 个离线控制](../../scripts/ci/test_read_failed_native_campaign_zip.py) 已全部通过，包括上述 archive/source/resource/计数边界及七个新归属控制。新归属控制涵盖旧数据 absent、有效桶保真、unknown 与 observer failure、未知 CPU 保持 null、固定槽顺序、严格整数与已知时钟守恒、零调用分类语义。这些是合成 parser fixture，不是 native campaign 通过。

| 已冻结文件 | SHA-256 |
|---|---|
| `scripts/read_failed_native_campaign_zip.py` | `14879a3aca2933420be47932edf6d10052b90648f371929cb440b4e645088ff4` |
| `scripts/ci/test_read_failed_native_campaign_zip.py` | `2b67d25512a9dd5964b2e0ad03e9174b8842b5cb499cc9c55526e148c739a364` |

最终冻结 reader 已重读三个完整原始 ZIP，全部输出 `evidence_read_success=true`、`native_campaign_complete_success=false`、`qualification_granted=false`。退出码 0 仅表示此证据读取一致。

| 最终派生报告 | SHA-256 |
|---|---|
| [42575267109](raw/run-42575267109/diagnostic-readback.json) | `278c8c3df453bceade8c023f9980383890d92728aa80025c12f32b129388b4e3` |
| [42579873262](raw/run-42579873262/diagnostic-readback.json) | `6a2af9796161f52ad8ae7a598b58451791c1c8df2a241ee8a78cd2ab52c08d93` |
| [42591962205](raw/run-42591962205/diagnostic-readback.json) | `ff279e3fe02f781c6a5b99b7e67059840082b37c0093b7c88320907b24dd0889` |

## 6. 53 个保留成员与 1,713 个省略成员

每份子集保留所有顶层原始成员（除 `public_v3_multiprocess.bin`）以及三个 `run-N-raw/report.json`，共 **53 个原始成员，包含原 manifest**。另加入 retention、omission inventory、API metadata、diagnostic readback 四个派生成员，故 tar 内总计 57 个成员。

每个 tar 已重新逐成员读取并核对字节与摘要，再使用原 reader 的 `SubsetBundle` 验证 **52 个由原 manifest 列出的保留文件**。每份原 manifest 的另外 **1,713 个文件**均在 `omitted-original-files.json` 列出路径、字节数与 SHA-256。省略的原始字节分别为 430,943,674、381,389,531、433,513,871；没有以只保留成功行的方式删除失败观察。

| 保留归档／验证收据 | 字节数 | `retained-original-members.tar.gz` SHA-256 |
|---|---:|---|
| [42575267109](raw/run-42575267109/retention-receipt.json) | 10,669,796 | `1c7fb03b50aed4eb106918ee210fe0e00de642a93347b79d7e448ac247ce67ca` |
| [42579873262](raw/run-42579873262/retention-receipt.json) | 9,101,630 | `a7818050d5c5e6b419d85e303a9e950573e65d97a108eed79822aee550e8ddb5` |
| [42591962205](raw/run-42591962205/retention-receipt.json) | 10,762,788 | `370731a2a9dcfef17ba76376823aa992e670657e1b62fe1f81f24c3a10345aef` |

三份归档合计 **30,534,214 字节**。每个 `raw/run-<id>/` 目录另有独立可读的 `diagnostic-readback.json`、`original-artifact-metadata.json`、`retention.json`、`omitted-original-files.json`、`retention-receipt.json`。生成采用 gzip level 9、mtime 0、排序 USTAR、uid/gid/mtime 0 和 mode 0644；本次 Python 3.12.14／zlib 1.3.2。不同 zlib 版本不承诺压缩流逐位相同，保留原始成员的字节身份由摘要固定。

**子集只重新验证被保留字节。** 本轮已经完成过完整 ZIP 校验，但未来若需重做“全部原始成员已验证”，仍必须取得第 1 节指定的完整 ZIP 及外部摘要。子集不能重新验证被省略的 native 二进制、数据库或其他成员，也不能替代新完整 ZIP reader 的输入。GitHub artifact 的原始 expires_at 见各 metadata；此目录保留的子集不会使远端完整 ZIP 永久可用。

只读复核入口为：

```bash
python3 -m unittest -v scripts/ci/test_read_failed_native_campaign_zip.py

python3 scripts/read_failed_native_campaign_zip.py /path/to/pon-native-campaign-42575267109.zip \
  --archive-sha256 2ebd97384564cf6d491f1f09ba3f11d0b1aba79f6feb19b327c3b06d8ae0cc9f \
  --expected-head e2a02f9271b49f146e70806c8a66e161b5973971 \
  --expected-tree 86d2014b560659106b3af6e6c19e1f82a290a60e \
  --run-id 42575267109 --artifact-id 13655237880 \
  --output /path/to/new-readback-42575267109.json
```

另外两份使用第 1 节各自固定的 ZIP、head、tree、run 和 artifact 身份。以上命令只读取证据或运行合成 reader 控制，不启动原始 native workload。

## 7. QROM：历史固定输入拒绝与当前映射必须分开

[原 QROM run 42575267240](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42575267240) 的 head 为 `e2a02f9271b49f146e70806c8a66e161b5973971`，prospective merge 为 `459eb070e8c631bb387b5d4ac362c3e43e945af1`，两者 tree 均为 `86d2014b560659106b3af6e6c19e1f82a290a60e`。原始拒绝准确为：

```text
input exceeds bound: formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs
```

这里的 bound 是历史 V1 合约 pin 住的该文件 **9,233 字节**，当前记录为 **11,172 字节**。该拒绝属于历史固定源码身份与当前源码漂移；不能据此宣布密码学 soundness 被破坏，也不能仅调大上限就把当前源码写成原历史合约通过。V1 继续保留原始 exit 2 和 false；当前合约另记录 verifier 与 `pon_wire.rs` 两个准确 source pin 差异。

原始 ZIP、job logs、run/jobs metadata、诊断与验证包已放入 [qrom 分项目录](qrom/README.md)，以 [qrom/manifest.json](qrom/manifest.json) 和 [SHA256SUMS](qrom/SHA256SUMS) 为索引。主报告引用该目录的原始证据，不把以下不同范围的计数相加：

| 证据层 | 绑定范围与已观察结果 | 不能据此声称 |
|---|---|---|
| 历史 V1 正向重读 | 固定 `0c830e0be8939ce80c8443c9ad68021b87343a00`／tree `273d0c1c69cd9bdfb85dc027bfdd8a49c2121c2c`；原名单 81 个注册／开始／成功，before/after 完整源码相同 | 当前 candidate 或当前 prospective merge 已通过 |
| 当前组件验证 | `current-validation-4` 中 75 个注册／开始／成功；V2 mapping PASS/HOLD；V1-on-current exit 2、false、两个准确 pin 差异；四份 QROM 冻结文件 before/after 哈希相同 | 完整 committed worktree 身份、托管 CI 或密码学资格 |
| 中断验证 | `interrupted-validation-3` 只有两个前置文件，没有 completion；保留 `UNKNOWN_EXECUTOR_UNAVAILABLE` | 已完成、成功或重复执行后被追溯替换 |

工作流修复见 [.github/workflows/pon-w1-qrom-implementation.yml](../../.github/workflows/pon-w1-qrom-implementation.yml)。历史 lane 固定原源码及原 81 名控制；当前 lane 在 head 和 prospective-merge 各自保留完整 tracked-byte before/after 身份，并执行 [独立 75 名 roster](../../config/pon/w1-qrom-current-required-tests-v1.json)。[当前 CI verifier](../../scripts/ci/w1_qrom_current_ci.py) 核对实际注册、实际开始、实际成功与无 skip/error，不能只用总数代替名单；保留原始 V1 拒绝进程输出摘要与两个准确 pin 差异，其他拒绝不能冒充已解释的 source drift。

当前 source mapping、历史正向复核、native proof execution、QROM 实例化、量子安全位数、共识准入继续分开。上述记录不建立新的 proof verification、complete W1 soundness、quantum work、PQ signature、production 或 consensus qualification。最终全仓和托管结果仍见下一节的待补记录。

## 8. 最终整合验证与发布记录

本节由主代理在最终固定源码上补齐；引用不存在或没有 completion 的项保持 PENDING。组件成功不自动成为整合成功，HOLD 不因提交或托管工作流绿色而自行解除。

| 项目 | 本页冻结时状态 | 最终证据引用／待补信息 |
|---|---|---|
| 27 个失败 reader 离线控制 | PASS，27 / 27；冻结文件摘要见第 5 节 | 最终整合日志仍由主代理补入 |
| 三份完整原始 ZIP 的最终 reader 回读 | PASS，仅证据读取；原 campaign 全部 false | 第 1、2、5 节及三个 diagnostic readback |
| 三份保留归档／SubsetBundle | PASS，53 原始成员／52 manifest 成员，各 1,713 省略成员 | 三个 retention receipt |
| QROM 历史 81 与当前组件 75 | 分项本地观察已保存，范围见第 7 节 | [QROM 分项说明](qrom/README.md) |
| 最终固定源码的 QROM 全仓／hosted CI | **PENDING** | 待补完整 source identity、最终日志、run/artifact URL |
| Rust observer 最终编译及 focused tests | **PENDING** | 待补实际完成日志、源码身份、选择器和结果；不将未完成记为通过 |
| 全局 CI contract／corpus／source inventory／policy gates | **PENDING** | 待补最终固定源码的完整验证结果 |
| 最终 commit | **PENDING** | 待补 commit SHA、tree SHA 与 clean source 身份 |
| Push／远端分支／PR | **PENDING** | 待补远端观察；尚未以本页声称完成 |
| 本轮新的原始 native campaign | **未由本回读执行** | 旧三组失败不能被 reader、observer 或 QROM 修复覆盖 |
| 生产、发布、量子工作、密码学和共识资格 | **HOLD／未授予** | 必须由各自规定的完整证据独立建立 |

主开发计划仍以 [TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md) 为准。本页是可追溯证据报告，不替代计划、原验收条件、required checks 或独立复核。

