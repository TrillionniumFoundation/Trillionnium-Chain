# 原生 campaign 与长 History CI：原始失败、完整分母及 Host 接线边界

## 结论

原 Chain `0c804e9f5bcf6e972bbb4524c744d4b3c8801c34` / tree `ebd3545aac5815260ec1f94a2b9a2f383e8dd051` 的 hosted A03 确实执行了三个完整尝试，结果为 **0/3**。这与此前本地因硬件/资源预检拒绝而未执行的 0/3 是两组不同证据。三次 hosted 尝试都产生完整原生报告，分别在 96.104、96.180、96.306 秒以 101 退出；没有用满或修改原 600 秒外层超时。

这三次失败包含两个分别未满足的原始条件：独立 History 导入全部被固定 Host parent 检查拒绝，导致业务无法确认；六个压力阶段也都未观测到原判据所要求的 CPU 预算耗尽。修复前者不能视为后者已通过。

**A03 当前进程布局的资源约束存在直接冲突，单纯换一个 CI wrapper 无法保留两套原契约同时通过。** 独立 verifier 是 A03 测试进程中的一个 `Node`；它在本线程调用严格公共 History 导入。该进程被原实验要求处于 400% CPU / 16 GiB 的层级，而公共导入要求实际线程处于唯一的 25% CPU / 2 GiB 固定 parent 之内。下文给出精确来源和可审查的后续边界。

本诊断固定原 source。随后发布的新 Chain `ac469237422d43805845e8b9a6839ad14e1028e7` 是另一版本；本包不把旧失败直接作为其新运行结果，也不将 wrapper 修复写成新 CI 已通过。整体验收仍为 **HOLD**，M06 继续独立。

## 1. 原 A03：完整分母

来源为 [原 campaign run 40490734602](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40490734602)、job `122143727380`、artifact `12728453436`。原输入保持：每次三个 30 秒阶段，模式为 baseline / from-zero / late-product；攻击进程分别为 0 / 24 / 24；四个种子块、1,024 个真实签名种子转账；每阶段计划 21 个业务块和三个确认轮次。

| 项目 | 实际结果 | 必须保留的完整分母 |
| --- | ---: | --- |
| 原 campaign | 0 次成功 | 3 次预声明尝试均执行 |
| 原阶段 | 0 次通过 | 9 个阶段均执行 |
| 业务确认 | 0 次确认 | 27 个计划轮次；实际观测 9 个首轮，后 18 轮未观测 |
| 原计划业务块 | 63 次 Submit ACK | 189 个计划块；实际尝试 63 个，另外 126 个未尝试 |
| 实际 Submit 请求 | 63/63 按时 ACK | ACK 不等于独立确认 |
| History 网络响应 | 576/576 按时成功 | 本地导入仍为 0/576 |
| 本地导入 | 576 次 `PUBLIC_HOST_KERNEL_PARENT` | 每阶段 64 次；九个阶段相同 |
| 压力 actor | 144/144 ready，144/144 正常完成 | 六个压力阶段各 24 个；无强杀、无达到调用上限 |
| 攻击请求 | 22,881 次 | 22,737 次工作拒绝，144 次错误，0 次接受 |
| 预算耗尽 | 六个压力阶段均未观测到 | 不能将提交 ACK 或攻击拒绝当作耗尽证明 |

每阶段第一次提交七个块后，执行最多 64 次 History 获取；网络页成功，但严格导入失败使 verifier 仍停留在原种子 tip。首轮无法确认后，原代码 `if !confirmed { break; }` 停止后两轮。因此 63/63 的实际 ACK 既不是 189/189 的全部计划业务完成，也不是 27/27 的独立确认。

来源：[原 `phase` 中固定轮次和导入逻辑](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs#L935-L1083)。三个完整原始总报告和各自原 phase-reader 输出都已保留；本次另从原始总报告交叉核对这些分母。

### 预算观测单独列出

| 尝试 | 阶段 | 实际计入 mutation CPU（秒） | 阶段末剩余 credit（秒） | CPU 预算拒绝 |
| --- | --- | ---: | ---: | ---: |
| 1 | baseline | 0.368988273 | 1.742222309 | 0 |
| 1 | from-zero | 6.464571013 | 1.998730606 | 0 |
| 1 | late-product | 7.290661600 | 1.998637771 | 0 |
| 2 | baseline | 0.391445756 | 1.725243924 | 0 |
| 2 | from-zero | 6.589442537 | 1.998674339 | 0 |
| 2 | late-product | 7.771374445 | 1.728520599 | 0 |
| 3 | baseline | 0.427201385 | 1.699955733 | 0 |
| 3 | from-zero | 6.599477138 | 1.998436360 | 0 |
| 3 | late-product | 7.620262575 | 1.872814786 | 0 |

原报告共保留 5,337 次预算采样，全部有成功 meter 结果，无采样错误；所有阶段的 `genuine_budget_depletion_observed` 为 false，`mutation_cpu_refusals` 和 `mutation_cpu_clock_failures` 均为零。压力阶段的原验收明确要求耗尽，并要求耗尽与诚实确认在原轮次中发生，不能删掉这些条件。

来源：[原 common / pressure predicates](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs#L1126-L1194)。这些有限观测不构成独立 WAN、公网吞吐量、绝对诚实公平或 work hardness 资格证明。

## 2. History：已生成 4,105 个 packet，公共全量同步未通过

四个 priority History lane 的失败状态来自 root 保存的完整 64-check 读取。本次下载、逐成员核验的是其中 **1/4**：x64 / head 的 job `122143728623`，run `40490734711`，artifact `12729187078`。没有将这个单样本的内部细节冒称已逐一下载了四个 lane 的 artifact。

此 artifact 包含 **4,105 个原 packet 文件**，日志最后一个周期性进度打印为 height 4000；原程序总耗时 378.88 秒，user CPU 196.69 秒、system CPU 178.16 秒，随后在公共导入返回 `PUBLIC_HOST_KERNEL_PARENT` 后于 `ancestry_long_sync.rs:360` unwrap 失败。原 test result 是 0 passed / 1 failed / 0 ignored；native exit 为 101、日志管道 exit 为 0。

`long-history/summary.json` 明确 `passed:false`，不是完成了 4,105 页公共 full sync。生成端的长链工作、日志成功收集与独立端的同步确认必须区分。

原 workflow 记录了执行前的 native binary SHA-256：

```text
4db5c96c75f7cf9b9823599eddb4712a7e7d3fa68b2ec9e6ef6178acc4e86255
```

这个 History ZIP 没有保留该测试 executable 的实际字节。原 `test "${codes[0]}" -eq 0 ...` 在第 302 行失败，所以第 303 行的执行后 `sha256sum -c` 未到达。保留这个身份验证边界，不把执行前哈希当作已完成前后重验。

来源：[原 History build / execution / acceptance steps](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/.github/workflows/pon-priority-acceptance.yml#L269-L319)。

## 3. 固定 Host 与 A03 为什么无法用同一个 wrapper 同时满足

| 原约束 | 精确要求 |
| --- | --- |
| A03 当前 cgroup | `cpu.max = 400000 100000`、`memory.max = 17179869184`、nice 10、至少四个 affinity CPU |
| A03 全部 ancestor | 任一有限 CPU quota 都至少为 period 的四倍；任一有限 memory cap 至少 16 GiB |
| 严格公共 History | 调用线程实际位于唯一 `/sys/fs/cgroup/trnmponpublic.slice` 或其后代 |
| 固定公共 parent | CPU quota 不超过 period 的四分之一，RAM 不超过 2 GiB，swap 0，tasks 不超过 256；固定路径、root ownership、boot / inode / quota 不能变 |

原 hosted A03 的 `resource-before-build.json`、每次 before/after 以及 `resource-after-native.json` 记录了原 400% / 16 GiB / nice10 profile，因此此次不是本地硬件预检拒绝。它位于 `/system.slice/trnm-native-campaign-40490734602-1.service`。同一测试进程同时持有 receiver 和 verifier；`phase` 在本线程调用 `receive_public_page_from_before`。

来源：[A03 resource validator](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/scripts/run_pon_w1_native_campaign.py#L115-L129)、[verifier 所属进程](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs#L775-L823)、[强制固定 Host 的公共导入](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/src/ingress.rs#L2286-L2318)、[固定限额](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs#L69-L125)、[实际线程成员关系复核](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs#L226-L255)。

由此得到三个明确边界：

1. **只创建固定 parent 不够。** 原 A03 线程仍在 `system.slice`，严格检查将继续拒绝实际 membership；不能把“目录存在”当成符合 Host。
2. **把整个 A03 放入 25% / 2 GiB parent 会改变原实验并违反它自身的校验。** 即便再建一个写着 400% / 16 GiB 的 child，原 validator 会发现 ancestor 过低。把固定 parent 改为 400% / 16 GiB 则违反原公共 Host 检查。两边不能任选一边放宽。
3. **不能用更弱的 loopback import、假 membership、临时迁移线程、多个新 parent 或新增 CPU credit 规避冲突。** 这也不能由恢复 hashcash、PoS、白名单或委员会解决。

现有 artifact 记录了错误类别，但没有捕获固定 parent 的原始 canonicalization / ownership / inode 状态。不能从 `PUBLIC_HOST_KERNEL_PARENT` 进一步断言具体是哪一个条件缺失。即使该具体缺失条件修复，同进程布局与两套资源约束的冲突仍然存在。

### 可审查的后续设计，不能冒充原 A03 修复已通过

可研究把现有 verifier **搬到一个持续存在的独立原生进程**，由管理员预先置于原固定 public Host parent；A03 producer、receiver、attackers 保留在原 400% / 16 GiB 域。该 importer 每个原阶段只创建一次 Node / CPU 生命周期，保留原 seed、tip、page、签名验证、durable debt、原绝对 deadline 和同样确认判据；不能每页重启补信用，不能重置已到期请求。IPC 只携带本次真实请求和结果，不能赋予任意提交能力或更换目标。

但是，这改变了进程拓扑与核算边界：原 `whole_parent_phase_cpu_ns` 不再覆盖 verifier，原 child usage 会增加一个不同角色，两个 sibling cgroup 的 aggregate ceiling 也不再等于原单一 A03 域。必须分别记录 A03 域、固定 public 域、importer 和 controller 的真实资源，并重新证明整体限制及 deadline 归属。**它应作为单独版本、单独验收的新实验，保留原 A03 0/3；不能只修改 wrapper 后把新布局结果贴回原标签。** 如果要求原 A03 的单进程/单 aggregate 资源契约完全不变，这个公共导入入口下没有纯 CI 接线解法。

## 4. 长 History 的最小修复范围

priority History 没有 A03 那套强制 400% / 16 GiB 资格，因此可以先单独解决其明确接线缺口：继续在测量外编译原 `ancestry_long_sync` target；只允许已由原 Cargo JSON 识别、哈希绑定的 executable 和原 selector / argv 进入固定 Host；仍用原 `/usr/bin/time -v` 测量该 native binary，保留原 flags、原输出目录、原断言和前后哈希。新增 wrapper mode 应是这个固定用法的窄 allowlist，不开放任意 shell command，也不把编译阶段无声计入已有 native time/RSS。

当前参考 wrapper 是本地 commit `8148f53f23b5510bb51964adbc050612cb337c38` 的 `run_from_zero_host.py` / `public_host_ci_observation.py`。它只接受四个原 from-zero argv；不会透传 `TRNM_INDEX_EVIDENCE_DIRECTORY`；首次要求固定 parent 不存在，退出仅停止自己的 service，保留 parent。因此不能直接复制它的调用用于第二个 History 子进程。

**protocol-contract 需要精确区分现有执行事实。** 原 `ci_job.sh:62` 的大 Cargo 命令虽然列出 `--test ancestry_long_sync`，但没有 `--ignored`；该文件唯一测试带 `#[ignore]`。这里不会执行 4,105-block 实验。该重实验真正由 priority workflow 的显式 selector 运行。不要仅因 target 名字出现在脚本中，就把整个 protocol-contract 迁移到 25% / 2 GiB。

来源：[原 protocol-contract 子命令](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/scripts/ci/ci_job.sh#L42-L64)、[原 ignored selector](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/tests/ancestry_long_sync.rs#L332-L361)。

若后续明确要在 protocol job 中增加一个实际公共 History 调用，应只拆出那个原 selector 的独立子进程，其他 crypto/protocol/model 控制仍在原环境。此前 from-zero 已留下固定 parent 时，有两种可审查范围：使用新的独立 job 获得干净首次 provision，或设计一个同 job 的 provision-once controller / 严格复用生命周期。后一种至少必须复核同一 root-owned unit bytes、无 drop-in、同 boot/dev/inode/quotas、counter 不回退、同 run/attempt/job/source 归属；每次仅创建唯一 child service，保持原 UID/GID、NNP、空 CapBnd、窄 env/argv allowlist；不删除、重建、重设或扩大已有 parent。当前 wrapper 没有这段复用实现，不能假定已解决。

## 5. 证据内容、完整性与未执行范围

两个原 ZIP 均已逐字保存于本地取证目录；本后续文档包不重复包含这两份 ZIP。它们的 GitHub artifact digest 匹配：

| 原 artifact | ZIP 字节 | SHA-256 | 全部成员 |
| --- | ---: | --- | ---: |
| campaign `12728453436` | 64,330,038 | `dbc342fbfe1cc8b6a53190864579e9dc6b417d1c892198b4dc07e9da8a7dd4de` | 914 |
| History `12729187078` | 38,101,611 | `9f96e0d95bb4cf1ed3f3eef3383ff6a1a5b8d564148db185c5ec199c9c954ab4` | 4,120 |

全部 **5,034 个成员**重新核验 CRC、大小和 SHA-256；原 campaign 的 `artifact-files.json` 所列 **913/913 文件**也逐项匹配。原 campaign retained executable 的实际字节 hash 与原 before/after 相同：`5b2f02908126c1a6d9a510ab7f6dcb2afce32cc2a716810b49c152603a66e01e`。

最终 readbacks archive 内的 `native-host/selected/`（本地取证目录为 `selected/`）是 **66 个明确列出的原始成员，共 144,165,873 字节**：包含三个完整总报告、attempt stdout/stderr、source/resource/binary metadata、原 runner、原 manifest，以及 History 的小型原始记录。它**不等于两个完整 ZIP**。大 campaign executable、History SQLite / 4,105 个 packet、单独的重复 phase/actor sidecar 文件仍在原 ZIP，未重复抽取进这个 selected 集合。完整成员清单、原 archive SHA 和精确选取清单使这些边界可复核。

没有改源代码、native acceptance、timeout、admission 或资源配额；没有执行 native binary、重跑 CI、dispatch、cancel 或远端写。一个直接 job GET 被 connector allowlist 拒绝，原错误已保存；随后使用已知的 run artifact collection 与专用下载工具读取。封包辅助脚本第一次把 `resource` 文件误匹配为 `source`，在字段读取时报 KeyError；已保留该元数据准备失败记录，修正匹配后完成原物复核。该失败不是 native test 结果，也没有改变任何原 artifact。

机器可读完整诊断见 readbacks archive 中的 `native-host/diagnosis.json`；分母、九阶段数据和资源域边界均在其中。下一次候选的 CI 必须独立观察；本包只保留这次原始失败和可执行的修复边界。
