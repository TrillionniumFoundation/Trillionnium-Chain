# W1 完整前缀的代数复算审查

## 结论与范围

**挑战掩码使矩阵变密，不等于完整 transcript 不能合法重排或不能利用原材料结构。** 本次以精确有限域运算，分别用直接密集累积和四项代数展开，复算了保留记录中 5 个任务各自的一个获胜挑战。总计 2,560 个原顺序 tile、163,840 个字段值逐字相同，5 个完整 trace 均匹配对应原生 PNW1 proof 的末尾 32 字节；完整 product、proof 和 ticket 也保持相同。

本次列出的**具体通用展开调度**在这些材料上没有标量乘法优势。它每挑战需要 361,080–371,856 次标量乘法；直接密集调度为 327,680 次。这不能证明其他展开、配对、整数或结构专用算法没有优势，更不能证明全局最便宜合法工作。第 5 个单坐标 bias 材料有一个更窄的合法候选：经典调度为 301,056 次，复用已有整数配对零材料核心时可构造 154,376 次的调度。这里的计数均不是 wall time、CPU time 或硬度下界；该 bias 候选没有加入 Rust、没有运行新原生基准，也不进入本轮冻结 campaign 的测量结论。

审查源码冻结在 `eeedfe33f9c7cd27a1855b865e7faa458047dcd1`。复算输入是此前保留的 `/workspace/scratch/8de1bcb09af8/cell-frozen-t0-full-limb`，其 manifest 记录执行源码为 `59321c326313b78640b2df11122e00b3c7cfd71f`、输入材料来源为 `ef1fa4d48ab9894f3d7a4b1c797ca9e7e490b155`。这几个来源没有混称。脚本没有生成新原生 proof，没有修改仓库，没有把保留执行当作新源码性能复跑。

机器可读的全部来源 hash、每个 prefix 与 tile 的 hash、逐项乘法计数及一致性断言见 `transcript-prefix-factorization.json`；具体输入、源码和脚本均有 SHA-256 绑定。

## 1. 必须复原的是每个累积前缀

所有运算都在 `F_q`，其中 `q = 4,294,967,291`。原材料 `A,B` 是 `64×64`。四个挑战数组为：

| 因子 | 维度 |
|---|---:|
| `E_L` | `64×8` |
| `E_R` | `8×64` |
| `F_L` | `64×8` |
| `F_R` | `8×64` |

记 `A′ = A + E_L E_R`，`B′ = B + F_L F_R`。第 `bk` 个内层块之后，`K = 8(bk+1)`，其累积矩阵是：

\[
C_K=A'_{:,:K}B'_{:K,:},\quad K\in\{8,16,24,32,40,48,56,64\}.
\]

展开需保留相同前缀，而不能把所有 `K` 都替换成最终 `AB`：

\[
\begin{aligned}
S_K&=A_{:,:K}B_{:K,:} &&(64\times64),\\
U_K&=A_{:,:K}F_{L,:K,:} &&(64\times8),\\
V_K&=E_{R,:,:K}B_{:K,:} &&(8\times64),\\
M_K&=E_{R,:,:K}F_{L,:K,:} &&(8\times8),\\
C_K&=S_K+U_KF_R+E_L\bigl(V_K+M_KF_R\bigr)\pmod q.
\end{aligned}
\]

从 `K-8` 到 `K`，四个中间量只加入对应 8 个内坐标的乘积。`S_K` 与挑战无关，可以在同一材料真正存活期间预计算；另三个含有挑战因子，必须按实际挑战重新计算。

输出仍严格按 `bi,bj,bk,i,j` 顺序，写入 canonical little-endian `u32`。每挑战包含 512 个 `8×8` tile，即 32,768 个词、131,072 字节的字段数据，前面仍是 `TRNM-PON-TRACE1\0` 和原挑战。可以流式计算和哈希，不必保存所有 `64×64×8` 的结果；不能省略其中某个前缀或改顺序。

展开在有限域中精确成立。原生实现需要在中间乘法之间规范约减，以维持既有整数累加器的界限。把四个因子的所有未约减乘积直接塞入 `u128` 并不等价于已经证明没有溢出。整数配对也必须先拓宽到 33 位和、在减去精确行列因子后再进入既有 reducer。

## 2. 对保留材料的逐字结果与计数

秩由模 `q` 的高斯消元算得，未使用浮点秩。前四个 A 都只有 15 个活动输出行，剩余 49 行为零；掩码之后不能直接把这 49 行的 transcript 删掉。

| 任务 index | `nnz(A)` | `nnz(B)` | `rank(A)` | `rank(B)` | 完整 B 的不同列数 | 固定 `AB` 非零乘积数 | 通用展开的挑战乘法数 |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 | 944 | 482 | 15 | 59 | 63 | 7,160 | 371,856 |
| 1 | 933 | 401 | 15 | 52 | 60 | 5,908 | 371,120 |
| 2 | 942 | 363 | 15 | 52 | 62 | 5,362 | 370,888 |
| 3 | 936 | 426 | 15 | 51 | 62 | 6,321 | 371,344 |
| 4 | 15 | 64 | 1 | 1 | 1 | 960 | 361,080 |

固定 setup 的非零乘积合计是 25,711，密集 setup 的位置总数是 1,310,720。这是 setup 的机会，不能当作挑战完整 transcript 的实际成本或普通执行必要 MAC 数。新实现的 `Preparation::Sparse` 只优化固定 `AB`，仍验证全部输入词并执行全部挑战 tile。

上表通用展开采用右侧分组，固定 `S_K` 的预计算单独收费。令 A 活动行数 `m=15`，每挑战乘法计数分解为：

| 步骤 | 标量乘法数 |
|---|---:|
| 增量更新全部 `M_K` | `64×8² = 4,096` |
| 稀疏增量更新全部 `U_K` | `8×nnz(A)` |
| 稀疏增量更新全部 `V_K` | `8×nnz(B)` |
| 所有 `M_K F_R` | `8×8²×64 = 32,768` |
| 所有 `E_L(V_K + M_KF_R)` | `8×64²×8 = 262,144` |
| 活动行的所有 `U_K F_R` | `8×15×8×64 = 61,440` |

直接密集挑战需计算两个噪声矩阵 `2×64²×8 = 65,536`，再完成 transcript 内积 `64³ = 262,144`，合计 327,680。掩码秩 8 恰好等于原 transcript 内块宽度 8，因而低秩重构全部输出前缀不自动降低总乘法数。这个具体调度的负结果不能排除混合调度、配对、重复列计划、Strassen 或更细结构的收益。

所有计数都排除了输入验证、结构识别、索引与转置、内存分配、模加法与约减、噪声哈希、完整 trace 哈希、proof/ticket 构造、取消检查、验证者、传输和加载等成本。即使单列乘法数更少，原生整数位宽、访存和约减也可能使 CPU 更慢。这里没有时间倍率或安全结论。

## 3. 第 5 个 bias 的候选窄域

实际第 5 个材料严格满足：

\[
A=u e_0^T,\qquad B=e_0(8\mathbf1)^T.
\]

所有输出前缀都满足 `K≥8`，所以均包含唯一非零内坐标 0。令

\[
g=E_LE_{R,:,0},\quad h=F_{L,0,:}F_R,\quad
D_{ij}=8(u_i+g_i)+u_i h_j.
\]

则每个输出前缀都满足：

\[
C_K=D+E_LM_KF_R\pmod q.
\]

`D` 每挑战只计算一次，在同一个挑战的全部 8 个前缀中复用。它仍随挑战变化，不能跨新挑战免费复用。复算脚本独立检查了这个窄域恒等式的全部 8 个前缀，并再次匹配 512 个 tile 和原生 trace。

已有经典零材料核心 `E_L M_K F_R` 使用 299,008 次乘法。加入 `g` 的 512 次、`h` 的 512 次、64 次乘 8、15 个活动行的 `u_i h_j` 共 960 次，总计 **301,056**。相对上述密集 327,680 的算术计数少 8.125%，但还要增加 32,768 次输出词的模加法及其他管理成本。这不是测得的速度提升。

已有整数配对零材料核心的源码计数为：中间前缀 2,560、左因子 16,896、输出 133,376，合计 152,832。若在同一挑战中复用其已经计费的 `E_L` 行因子与 `F_R` 列因子，则 `g` 另需 `64×4+4=260` 次，`h` 同为 260 次，再加 64 和 960，候选共 **154,376** 次。作参考，仓库通用 field-paired 挑战调度包含因子在内是 168,960 次乘法。这些不同内核还存在约减方式和位宽差异，不能直接换算为运行时间比。

可存完整 `D` 的 16 KiB，或存 15×64 个活动外积加 64 个行偏移，共 4 KiB；识别、建立和存取均需收费。固定 `C=AB` 自身还可对 15 个活动行各乘一次 8 后复制列，但仍须付完整验证、识别和写出成本。

此域不能仅凭“两个矩阵都是 rank one”就接受。任意 `u a^T` 与 `b v^T` 的截断内积随 `K` 变化；上述常量 `D` 的证明依赖唯一坐标和第一个已输出前缀已覆盖它。现有零材料构造器正确拒绝非零 A/B。实现候选时必须使用一个明确的新研究 arm，保留真实 A/B/C proof prefix 和 task，不能把非零 bias 伪装成零材料调用。

## 4. 已有源码说明结构优化可以合法存在

下列文件都在 `trillionnium/crates/trnm-crypto-primitives/src/pon_work/`。本记录 JSON 保存了被审查的每个文件 hash。

| 源码位置 | 已有算法及适用边界 |
|---|---|
| `structured.rs` 的 `zero_proof`（343 起） | 对 `A=B=0` 复用每个 `M_K`，完整输出每个前缀。其他 zero/identity/diagonal/rank-one 识别主要优化固定 product；非零 `Kernel::Product` 仍调用普通 `PreparedTask::prove`。 |
| `blocked_zero.rs` 的 `middle_prefixes`、`left_prefixes`、`trace`（49、70、86 起） | 完整零材料的分块重排；仅存 2 KiB 中间前缀及当前 8 行的 2 KiB 左前缀，仍计算/哈希全部 32,768 词。经典调度 299,008 次乘法。 |
| `blocked_zero_paired.rs` 的相同阶段（124、172、211 起） | 零材料结合精确整数配对，源码明确计数 152,832；有实际边界上的取消观察，不声称与另一个算法的 checkpoint 顺序相同。 |
| `blocked_one_zero.rs` 构造器与 `transcript`（23、65 起） | 恰好一侧为零、另一侧为非零 rank one。保留每个前缀的 rank-middle 与 noise-middle；拒绝双方非零、双方零及不支持材料。 |
| `maintenance_prefix.rs` 的 `MaintenancePrefixPreparedTask`（206 起） | 对严格识别的公开 maintenance B，使用 `A′B` 的周期前缀和，加上 `(A′F_L)F_R`；利用结构进入每个挑战，而非只优化 setup。 |
| `paired_product.rs` 的 `prove_with_progress`（78 起） | 通用 field-paired 完整挑战，全部 prefix 和 proof 相同。 |
| `integer_paired.rs` 的 `factor`、`dot`（5、19 起） | 精确整数配对；先拓宽，精确减因子后约减，避免把未证明范围的和交给 reducer。 |
| `structured.rs` 的 `TiledPreparedTask` / `TileKernel::StrassenOneLevel` | 对原始 8×8 transcript 叶块采用另外一种乘法调度，保留原累积前缀。 |

零材料、one-zero-rank-one 和 maintenance-prefix 专用域都不直接接受本次前四个模型材料。第 5 个也不是零材料或 one-zero 材料。既有算法证明“挑战密化后仍可合法利用结构”，但不能作为本次材料已获得该收益的证据。

## 5. 合法复用、输入边界与后续反例

固定 A/B 的完整 `C`、所有 `S_K`、稀疏索引、秩分解和列计划，可以在真实材料生命周期内复用。扫描、构建、存储、重启重建和实际驱逐均须进入成本。缓存须绑定完整输入及版本；数学缓存没有父状态、准入或 `VerifiedWork` 权限。

四个噪声数组、`U_K/V_K/M_K`、`D`、变换后矩阵以及挑战相关的配对因子都属于该挑战。新 seed、nonce 或其他挑战绑定产生新挑战时，必须重新计算。确实相同的挑战可以复用数学结果，但不能因此重复记为新的抽签、独立有用模型输出或额外收益。同一挑战内跨 `bk` 累积、跨输出 tile 复用因子是合法的，已计费用不能重复删除或重复领取。

若下一轮实现 bias arm，至少需以下针对性反例和完整差分，且不能改本轮已冻结源码：

- 完整 8,192 个 A/B 词的长度与 canonical field 校验，包括本可被零乘积隐藏的坏词；严格验证单坐标支持和常量 B 行。
- 正常材料、全域极值、接近模数的负整数编码，对所有 512 个 tile 逐字比较，再比较完整 proof、task、challenge、ticket 和原生 verifier 结果。
- 在其他内坐标放置非零值、改变单个 B 列、一般 rank-one A/B、错误的固定 prefix：必须拒绝专用识别或按正确一般前缀计算，不能沿用常量 `D`。
- 任意新挑战重算噪声并维持原拒绝采样及每 label 128 hash chunks 的预算；不缩减 transcript、不修改目标边界。
- 在新算法真正的有界工作之前设置取消检查，覆盖中间 prefix、外因子、输出 tile 和 proof 之前；取消后不得留下可冒充完成结果的对象，重试从正确挑战状态开始。不能先算完整 transcript 再补发旧算法的回调来伪装取消语义。
- 普通执行拥有同等预处理权利。对同一批材料继续计入失败抽签、重复挑战、真实全验证 replay、传输、模型加载、重试、陈旧块及实际生命周期。

这些要求不改变原 4 秒 / 16 个 hostile 挑战 / 0.25 CPU / 2 GiB / depth 6 门禁。没有推导新的采用资格；既有 `not_adopted` 与 `model_reward=0` 边界保持。5 个匹配 transcript 说明这一代数恒等式正确，不能证明模型持续改进或完整系统净计算收益。

## 6. 复算命令与保留记录

精确命令的 argv 还保存在 `recompute-command.json`：

```bash
python /workspace/scratch/708bcecd45db/audit-notes/recompute_transcript_prefix_factorization.py \
  --input-root /workspace/scratch/8de1bcb09af8/cell-frozen-t0-full-limb \
  --repo /workspace/scratch/708bcecd45db/chain \
  --output /workspace/scratch/708bcecd45db/audit-notes/transcript-prefix-factorization.json
```

脚本拒绝覆盖输出；复跑时指定新的输出路径。它要求所审查 repo 为干净的 `eeedfe33`，后续若分支合并前进，需要对该 SHA 的干净 checkout 复跑，不能修改预期 SHA 来冒称同一审查。运行使用 Python 3.12.14、NumPy 2.3.5、`dtype=object` 任意精度整数，不使用浮点或溢出的固定宽度矩阵乘法。输入和源码在计算前后再次核验。

| 文件 | 内容 |
|---|---|
| `recompute_transcript_prefix_factorization.py` | 完整可复算程序，包括原 hash framing、拒绝采样、prefix 顺序、模秩、proof/ticket 及逐 tile 检查。 |
| `transcript-prefix-factorization.json` | 所有输入/源码 hash、5 个结果、2,560 个匹配 tile hash、prefix hash 和计数分解。 |
| `recompute-command.json`、`recompute.log` | 实际命令与退出前 PASS 输出。 |
| `exact-source-rust-validation.json` | 最终冻结源码的 Rust 验证记录，包含环境、命令、日志 hash、前后源码与 binary hash。 |
| `exact-source-crypto-lib-tests.log` | 138 库测试通过，0 failed / ignored / filtered out。 |
| `exact-source-native-example-tests.log` | 9 个 example 测试通过，0 failed / ignored / filtered out。 |
| `exact-source-native-strict-clippy.log` | 原范围 `--lib --tests --example pon_shared_material_v1 -- -D warnings` 通过。 |

Rust 重验使用 `cargo +1.95.0`、`--locked --offline`、默认 features、jobs 1，以及 `CARGO_PROFILE_DEV_DEBUG=0`、`CARGO_PROFILE_TEST_DEBUG=0`、`CARGO_INCREMENTAL=0`；没有扩大为全 workspace 构建。两个 Rust 文件与此前通过验证的 hash 一致。release 二进制未重建，hash 精确保持 `5e9ad2da5319b645dc6325d4466c4e822cf7ebc07ab116cdc04c18d3c14fcf7f`。该记录明确只证明 `eeedfe33`，不把后续 merge 后源码称为已经跑过本轮 campaign。
