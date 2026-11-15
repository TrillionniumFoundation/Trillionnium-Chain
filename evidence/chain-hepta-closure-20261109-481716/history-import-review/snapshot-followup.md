# 原 baseline 的 native / SQL 快照补充

恢复原件后，新增测量给出一个明确的范围判断：**在这三个原 baseline、已观察的四个 SQL site 内，`Transaction::commit` API 区间合计分别只有 60.487131、22.715299、124.194664 毫秒，不能解释此前完整持久化和激活中的数秒耗时。** 这不等于排除全部 SQL 读写或其他 IO。

另一组原始计量把下一处待分离范围收窄到实际 `account_graph`：每个完整 baseline 新增 73 次该 scope 的记录，wall 分别为 **18.138435、18.667194、18.420762 秒**。它仍包含 SQL 图读取、校验/算术、原 progress/Host/CPU 检查点及可能的 refill 等待；本补充没有把其中任何一项定为主因，也没有据此提出删检查或扩缓存的安全改动。

这是 **0746 原运行的补充读取**，没有运行新 campaign、修改仓库或改变资格。首轮 21 包的 [README.md](README.md) 与 [review.json](review.json) 保持原字节；完整纳秒数、所有 16 stage / 4 SQL 差值、校验结果及输入哈希见 [snapshot-followup.json](snapshot-followup.json)。

## 原件与固定身份

原 artifact `13662172930`，run `42591962205`，于 **2026-11-09 16:16:13 UTC** 重新取回，ZIP **76,441,344 字节**，SHA-256：

`4e8a243caf2aadf4a195b4cb96dbb0229a0e001a830f0e9de2c4f853ee7dff5c`

本补充独立重新计算 ZIP 哈希，读取下列三份完整 report 并核对保留的原 manifest。没有把新导出的 JSON 序列化哈希当作原 report 的身份。

| 原 member | 原字节数 | 原 SHA-256 |
| --- | ---: | --- |
| run-1-raw/report.json | 48614177 | `39c4098846dbbb802f962989a0774d09c95a80c0db3b04a69923adfce8b5c307` |
| run-2-raw/report.json | 48774711 | `43c8fb8fa28c560522be595b58e98e483c62631a76766f42efa24f088e366822` |
| run-3-raw/report.json | 48449148 | `5699de385790f39f3e5684140b97fb81ebba892036442295a3628591de9e0156` |

提取物来自冻结的 `public-original-snapshots` 小包：`baseline-history-snapshots.json` **85,002 字节**，SHA-256 `453c1d085a4a689110e931235464cd471f68e9b59311bbbdd1172ae70d4c78ec`；`extraction-manifest.json` **14,711 字节**，SHA-256 `93d025ac399fe868856cbd21f34b11157c362cb212f9ca70c5eeaa76b11eb5be`。本补充把三份 complete-baseline gzip 解压后的 **50 个 baseline 字段**、报告其余顶层字段，以及两个完整 snapshot 对象，逐值与原 report 比较，全部一致。三个 gzip 的压缩/解压完整哈希也写入补充 JSON。

测量源仍是 `0746a462e80067b78317597f2fa4bacf5e3db958`，原二进制 SHA-256 `3afe1ecc5953bb4e5b3066fe07fb11b68a74faac787f4f81c5c15209a97a86f1`。新定位涉及的四份源码已分别与 M5 `3ad605ecdac4b3b123dff83c1cb7458430acd776` 比较，均字节相同；这只固定调用边界，不把原性能视为 M5 新实测。

## whole-phase 范围与首轮记录的关系

原字段位于各 report 的 `/phases/0/client_native_history_arithmetic_before` 和对应 `after`。before 在 independent verifier 的 seed replay 后、服务开始前；after 在原服务结束/清理后、最终 `read_active` 前。两者之差覆盖该 verifier 在整个 baseline 的工作，**包含失败尾段以及独立 confirmation**，不是首个七包 round。

每个 baseline 都有 10 次 import：9 成功，1 次在 Work 阶段失败；另有 1 次独立的成功 client confirmation。成功 admission/commit 各 9 次，activation 只有 1 次。下表为同一原 v2 中完整 baseline 的外层计量，用于对齐分母；不能与其内部 native stage 相加。

| Run | Import 总数 / 成功 / 失败 | Import wall 合计（秒） | 9 次 packet commit wall（秒） | 唯一 activation 外层 wall（秒） |
| --- | --- | ---: | ---: | ---: |
| 1 | 10 / 9 / 1 | 25.056737 | 12.458972 | 5.435483 |
| 2 | 10 / 9 / 1 | 24.842031 | 11.975075 | 5.397492 |
| 3 | 10 / 9 / 1 | 24.832898 | 12.156368 | 5.299740 |

三 run 共 **30 次 import、27 成功、3 失败、3 次独立 confirmation**。本补充逐条核对原 report 与原 v2 的 client 起止、wall、CPU、结果和错误字段，全部一致；对应 **498 个实际进入的 page/packet span** 均完成，CPU/wall 已知，native measurement_failures 为 0。它们包括失败调用实际走过的阶段。

## 四类 SQL API 的实际差值

下表为 before/after 之差，wall 单位为**毫秒**。各 run 的新增调用数相同。

| SQL site | 每 run 新增调用 | Run 1 wall | Run 2 wall | Run 3 wall |
| --- | ---: | ---: | ---: | ---: |
| admission_persistence | 9 | 20.885039 | 18.852357 | 120.043387 |
| atomic | 0 | 未进入新调用 | 未进入新调用 | 未进入新调用 |
| reorg_step | 9 | 39.602092 | 3.862942 | 4.151277 |
| reorg_termination | 0 | 未进入新调用 | 未进入新调用 | 未进入新调用 |
| 已进入调用合计 | 18 | 60.487131 | 22.715299 | 124.194664 |

三 run 的这些 SQL 调用线程 CPU 合计分别为 **9.541012、9.369318、8.971295 毫秒**。

24 个 site 端点（3 run × before/after × 4 site）均满足：

- `started = returned + abandoned + in_flight`，且 `returned = succeeded + failed`；
- 已关闭调用数等于 CPU known + unknown；
- `observation_failed=false`，failed、abandoned、unwinding、CPU/wall unknown、in-flight 均为 0。

每个 run 新增的 18 次 SQL API 调用全部返回成功。**这个局部事实不改变失败的 campaign 结果**；每个 baseline 的另一条 import 在 Work 阶段失败，未因此虚构一个 SQL 失败或成功调用。

`atomic` 的累计值前后不变，表示本区间没有新调用；`reorg_termination` 的原时间字段前后都是 null，表示从未进入该 site。本补充把二者的“本区间实测时间”都保留为 null，没有称为测得 0。对于 `reorg_step`，before 无调用且时间 null，after 新增 9 次完整调用；只有在严格确认 before 计数全零后，才使用加法初始值计算这 9 次真实调用的合计。原端点和算术差同时保留。

因为整个 baseline 包含首轮，以上 SQL API 合计也给出首轮相同四个 site 的保守上界。相对首轮已测的 commit + activation 外层和，上界分别约 **0.3985%、0.1549%、0.8472%**。这足以限定“数秒都耗在这些 SQL COMMIT API 里”的解释，**不能用来排除事务内 SELECT/INSERT、其他 IO 或整个存储路径，更不能把 API 时间等同物理 fsync**。原 API observer 见 [SqlCommitObservation](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-pon-node/src/store/native_authenticated/history_arithmetic.rs#L473)。

## 全部 16 类 native stage 差值

下表 wall 单位为秒。“调用数”是每个 run 新增的 Drop 记录数，不是图节点数；三 run 数量一致。**这些 scope 互相嵌套，表内各行不能相加。** 每行完整 CPU 与其他计数保留在补充 JSON。

| Native stage | 每 run 新增调用数 | Run 1 wall | Run 2 wall | Run 3 wall |
| --- | ---: | ---: | ---: | ---: |
| record | 557 | 0.004784 | 0.004202 | 0.081397 |
| packet | 310 | 0.009736 | 0.086163 | 0.086576 |
| delta | 301 | 0.485328 | 0.248532 | 0.327053 |
| verify_state | 100 | 18.943573 | 18.930400 | 18.609825 |
| verify_history | 27 | 0.503638 | 0.495998 | 0.653002 |
| publish | 9 | 8.663643 | 8.957817 | 8.962065 |
| read_active | 5 | 1.311469 | 1.385431 | 1.342044 |
| state_at | 27 | 5.029199 | 4.569159 | 4.653747 |
| execute | 9 | 0.015144 | 0.169889 | 0.092625 |
| admission | 9 | 17.059694 | 16.579661 | 16.919757 |
| activation | 1 | 5.435240 | 5.397226 | 5.299476 |
| complete_commitment | 109 | 0.530498 | 0.146305 | 0.071524 |
| complete_state_root | 40 | 0.086478 | 0.010038 | 0.010518 |
| account_graph | 73 | 18.138435 | 18.667194 | 18.420762 |
| persisted_state_root | 81 | 0.169768 | 0.015986 | 0.092525 |
| execution_parent_binding | 9 | 0.002933 | 0.078949 | 0.079935 |

`account_graph` 的调用线程 CPU 分别为 **4.214791、4.201383、4.202290 秒**。它被包在 `verify_state` 里，后者又可处于 publish、state_at、read_active、admission、activation 等范围内。不能把这些嵌套 CPU 相加，也不能把 `account_graph` 的 whole-phase wall 直接归到首轮七包。

96 个 stage 端点（3 × 2 × 16）的 roster 完整，所有计数均为无饱和的非负整数，前后单调；`calls = cpu_known_calls + cpu_unknown_calls`，CPU unknown 与 unwinding 均为 0，`stage_observation_failed=false`。

Stage observer 本身只在 Drop 时记累计 calls，没有独立的 started/in-flight roster，也没有逐次普通错误返回计数。这里证明的是 **已记录调用的一致性及已知 CPU**，不能把它表述成独立枚举了所有曾开始的 stage。完整 import 生命周期另由上述原 page/packet 观察及调用返回位置核对。源码边界见 [StageObservation 的实际记录语义](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-pon-node/src/store/native_authenticated/history_arithmetic.rs#L740)。

## 现在可行动的具体定位

[verify_state_with_readback 中的 AccountGraph scope](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-pon-node/src/store/native_authenticated.rs#L674) 在需要实际图校验时，调用原 scoped-readback verifier 或普通完整 verifier。普通路径的 [verify_account_values](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_store.rs#L510) 在遍历每个实际节点前调用原 `progress()`，仍读取和比较实际 SQL 图、节点身份/边界及最终完整账户内容。[scoped-readback 的真实遍历](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_scoped_readback.rs#L185) 同样保留每个真实节点的原 progress；已有匹配/复用栅栏也继续生效。

所以现在有依据把后续正常 profiling 放在 **AccountGraph scope 内的实际 SQL 节点读取、解码/算术、原 progress callback，以及已定位的 refill 等待分支**。这些分量目前没有独立实测值：不能从 wall 减 CPU 得到 sleep，不能从调用占比推出检查点是主因，也不能据此跳读 SQL、减少 Host/签名/控制检查或扩大缓存复用范围。本轮补充止于已有原件与源码定位，不新增 profiling 实现或执行。

## 授权措辞与资格边界

本轮任务已包含正常 baseline profiling、修复和按原门槛验收，**不需要用户重复授权，也不引入新的确认流程**。此前 README 的“若之后获准”应理解为实现、证据与运行资源就绪后的后续工作；[AUTHORIZATION_NOTE.md](AUTHORIZATION_NOTE.md) 已单独记录该措辞修正，旧记录保持不覆盖。

原 **0/3 campaign、0/9 phase 达标**结论没有改变。Host **4 秒**与独立 **30 秒** campaign 门槛没有改变。原件恢复、reader 成功、源文件相同、SQL 局部调用成功均不能替代新的候选二进制原验收；低层主因和可安全实施的源码优化仍未证明。
