# 密码配置与 ML-DSA 参数观测证据

最新结果见[可信退休与固定 53a90ad6 源码验证](retirement-53a90ad6/README.md)：原始配置 ID 在可信退休后保持不变；245 项密码／协议测试、59 项账户测试、2 项 doctest、106 项 Python 测试和完整严格 Clippy 通过，另有新的 65／87 参数观测与真实双向互操作。Node 测试构建未成功，现行 49 项控制及 network／continuous owner 未执行，状态仍为 **HOLD**。该目录绑定自己的精确 commit、tree、成功／失败／未知原始记录，不能将组件结果当作整链验收。

The [fixed 59f continuation](continuation-59f75acd/README.md) preserves its separate raw records, source comparison and parameter observations. The original ad081 observations below remain historical. Neither earlier phase supplies execution credit to the later retirement source.

本目录保存[密码配置安全契约](../../docs/security/CRYPTO_PROFILE_V1_20261104.md)
对应的实现观测、命令记录和独立重算工具。本轮确实完成了核心组件、M06、源码检查和
ML-DSA-65/87 参数实测；在 `ad081` 源码上，Node 测试构建及 workspace Clippy 未完成验收。
总状态保持 **HOLD**，`native_acceptance_complete=false`，六项整链门槛仍为
**UNQUALIFIED**。这些结果不激活 ML-DSA-87，也不构成整链 PQ 安全或生产性能声明。

## 源码身份与组合边界

| 身份 | 精确值 |
| --- | --- |
| 本目录运行记录实际测试的 code commit | `ad081dac8d2c1bccdf463bad82b9db7bd92477d3` |
| 该提交的 Git tree | `4a552f0cf554718fae8bddd7cf1344999cb4fd29` |
| 父提交，PR #698 基线 | `5a5ddbd4577207af7f7771a4a50c76620f32940f` |
| 组合源码采用的远端基线 | `04be4748e653a30fae2d66275b4bed83e6eabb8b` |

每条命令的 receipt 均记录执行前后的同一源码身份，并核对受跟踪工作区的实际字节。
归档中的旧名单属于上述 `ad081` 提交，包含 **45** 项 required controls。
组合源码采用的 `04be` 基线继承了 `7eba9107c0246c657ddab52cfed176d223789248`
中的现行[49 项名单](../../config/pon/pq-system-required-tests-v1.json)。
45 项旧记录不能替代 49 项现行名单，也不能因复制到组合分支就成为组合源码通过的证据。
`reproduction.json` 明确记录
`later_combined_commit_tested_by_these_commands=false`；后续组合提交的结果须另行记录，
绑定其自身 commit、tree、命令和实际执行日志。

`reproduction.json` 中的 `cargo_graph`、`unchanged_contracts` 和二进制身份仅对应 `ad081`。
`04be` 组合基线已继承 Linux `sha2/asm`、`sha2-asm 0.6.4`、`serde_json` 常规依赖，
并修正独立的 `tests/fuzz/Cargo.lock`。必须按组合提交重新验证当前 workspace 和独立 fuzz
的 locked graph；旧记录中的依赖未变结论不适用于组合版，旧 benchmark 也不能替代新依赖图下的结果。

## 已保留的实际结果

[reproduction.json](reproduction.json) 共包含 **26 条真实命令 receipt：23 条成功、3 条失败**。
下表来自实际进程退出状态和保留日志中的测试终结行；计数是各命令的执行次数，
不是跨过滤范围去重后的独立测试总数。

| 范围 | receipt 数 | 实际结果 |
| --- | ---: | --- |
| Source 检查 | 16 | 全部成功；其中 Python unittest 合计执行 105 次 |
| Protocol / crypto，全部 features 的 lib 测试 | 1 | crypto 141 passed；protocol 92 passed、2 ignored；0 failed |
| Protocol doctest | 1 | 2 passed |
| M06 `pq_accounts_v2` 单元测试 | 1 | 15 passed、93 filtered out |
| M06 五个集成测试目标 | 1 | 44 passed |
| Benchmark build / run / independent reader | 3 | 全部成功；原始样本重算通过 |
| Node lib-test 构建及单 CPU 重试 | 2 | 均 exit 101；日志记录编译器进程 SIGKILL |
| 全 workspace / all targets / all features Clippy | 1 | exit 101；日志记录 Clippy 编译器进程 SIGKILL |

两项 ignored 是原有显式运行的完整构造/完整 root 成本观测，未计为通过。
三条失败命令分别为 `node-build`、`node-build-retry1`、`clippy`，原始 receipt 和日志全部保留。
日志可证明编译器进程遭 SIGKILL；根因记为 **unknown**，没有把它判定为 OOM 或任何已确认原因。

两次 Node 构建均未产生可用于本轮验收的测试可执行文件，因此下列检查明确为 **not_run**：

- `node-network`：全部 `ingress::pq_network` 测试。
- `required-controls`：旧提交的 45 项，`required=45`、`executed=0`，没有 `passed` 计数或伪造执行 receipt。
- `node-continuous-owner`：实际连续运行 owner 的 cold-reopen 精确测试。

collector 仅通过显式 `--blocked-native` 收集此种阻断：必须核对三条真实失败、
其余核心成功记录和全部 benchmark 原始样本；缺失任意核心命令、running 状态、
缺失 benchmark 或残留的部分 Node 执行记录均会拒绝。默认完整模式的必需记录没有放宽。
旧日志和中断尝试作为独立观测保留，不能补足 `ad081` 源码上尚未执行的检查。

## 文件与完整性

| 文件 | 字节数 | SHA-256 |
| --- | ---: | --- |
| [reproduction.json](reproduction.json) | 147,593 | `db91344982a4264766b0090549abed4d2f4f837be4c278ad54530a9ab85feadc` |
| [raw-observations.tar.gz](raw-observations.tar.gz) | 271,371 | `5d28b2ca4cd8e2339820d6d219867ecae8ddfe4dc303442ddc6a45efec9aa379` |
| [parameter-observations.jsonl](parameter-observations.jsonl) | 295,215 | `de49e106baa808103cefe4cb320bdb3f245bf86aef04de9018ff73d76c1c1036` |

归档包含 93 个成员、1,869,597 字节解压内容；`artifact-manifest.json` 为其余成员记录
字节数与 SHA-256。归档保留命令 receipt、日志、原始 benchmark、运行环境、源码契约、
外部 runner/collector 和独立的既往观测。此处单独提供的 JSONL 与归档中
`final-validation/parameter-observations.jsonl` 逐字节相同。

运行时记录的 benchmark 二进制为 751,984 B，SHA-256 为
`0bafd91bb8caa6709af344f1034a76e194525cf5d2aa29a8cfe50800d3d22285`。
其构建 receipt、Cargo artifact 及运行前后哈希保留在记录中；collector 收集时该二进制已不再保留，
故 `verification_at_collection=unknown`。本目录不打包二进制或构建缓存，
也未将这一事后复核状态写成 matched。

无需重新运行原生代码即可重算已保留的全部原始样本：

```bash
python3 evidence/crypto-profile-20261104/recompute_benchmark.py \
  evidence/crypto-profile-20261104/parameter-observations.jsonl
```

reader 的 PASS 只确认该记录内部的样本集合、统计和长度一致性；真实运行身份还须结合
source receipt、实际 exit status、日志哈希和二进制运行记录判断。

## 有界参数观测

本次使用 Rust 1.95.0、锁定的依赖图和 release `opt-level=3` 构建。
运行时间为 2026-11-04 13:10:05 至 13:10:24 UTC；完整精度见归档中的 `parameter-run.json`。
宿主 CPU 型号为 AMD EPYC 9V74，允许的逻辑 CPU 为 0–8，cgroup CPU 配额为 8 核等量，
内存上限为 8 GiB。`shared_load_controlled=false`；一分钟负载从 4.499 增至 5.029。
原始记录保留内核、CPU、内存、前后负载和 cgroup 计数。

观测覆盖两种算法、消息长度 0 / 176 / 4,096 / 65,536 B、签名者数量 1 / 2 / 4 / 8，
共 32 个场景，每场景 9 个独立测量阶段。每阶段先执行一次未计时预热，再记录 64 个样本：
**288 条测量、18,432 个原始样本，连同起始和完成哨兵共 290 条 JSONL 记录**。
固定显式 seed 和消息在各样本重复，签名使用 Pure ML-DSA、空 FIPS context 和确定性模式，
没有隐藏随机来源。每个场景按固定顺序先运行 65，再运行 87。

独立 reader 拒绝缺失场景、重复组合、被改动的统计、错误帧长度和缺失完成哨兵。
分位数使用 nearest-rank；**64 个样本的 p99 等于样本最大值**。
它不代表密钥/消息总体的尾延迟，也不构成网络或生产 p99。

### 两组代表结果

下表单位为 **ms/整组签名者**，每格依次为 **p50 / p95**，由对应原始纳秒样本重算。
八签表中的每个样本包括整组八次操作，不能当成单个请求延迟。

**4,096 B 消息、1 名签名者：**

| 操作 | ML-DSA-65：p50 / p95 | ML-DSA-87：p50 / p95 |
| --- | ---: | ---: |
| 签名、编码、自验并释放结果 | 0.290920 / 0.556286 | 0.508238 / 0.564233 |
| 有效签名验证 | 0.070597 / 0.140923 | 0.163467 / 0.186321 |
| 进入算术后的无效签名拒绝 | 0.093221 / 0.160803 | 0.159682 / 0.191910 |
| 完整观测帧解析、预检和验证 | 0.071518 / 0.862614 | 0.162816 / 0.197669 |
| 单独导入、展开公钥并释放 | 0.087442 / 0.190358 | 0.264630 / 0.304390 |

**65,536 B 消息、8 名签名者：**

| 操作 | ML-DSA-65：p50 / p95 | ML-DSA-87：p50 / p95 |
| --- | ---: | ---: |
| 八次签名、编码、自验并释放结果 | 10.379457 / 12.302824 | 13.148382 / 13.974120 |
| 八个有效签名验证 | 2.414078 / 4.687845 | 2.968456 / 3.438126 |
| 八个进入算术后的无效签名拒绝 | 2.708494 / 3.621389 | 2.852461 / 3.175139 |
| 完整观测帧解析、预检和八签验证 | 2.708614 / 3.328962 | 2.353727 / 3.232676 |
| 单独导入、展开八个公钥并释放 | 1.051639 / 2.587040 | 1.912991 / 2.256160 |

签名阶段包含编码、自验和结果释放。各验证阶段使用已经展开的可信公钥，
公钥导入成本单独列出；不能相加不同阶段的分位数后称为实测端到端分位数。
无效输入只修改挑战值 `c_tilde`，保留可解析的签名语法，且必须得到实际算术拒绝
`SignatureRejected`；八签无效组付出了八次拒绝成本，没有在首个失败后提前结束。

这些数据保留了实际出现的逆序结果：八签完整帧验证的 87 p50 是 65 的约 **0.869 倍**，
同一场景单独有效验签却是约 **1.230 倍**。单签完整帧的 65 p95 也明显高于 87，
尽管其 p50 更低。共享负载、固定顺序和重复输入使这轮观测无法隔离算法成本与运行环境影响；
不能据此宣称 87 稳定更快，也不能给出适用于所有场景的固定性能倍率。

### 观测帧字节与协议边界

`TRNMCPB1` 有实际 serializer/parser，布局为：

```text
magic[8] || suite[1] || message_len:u32be || signer_count:u16be || message ||
(raw_pk_len:u16be || raw_pk || sig_len:u16be || signature) * signer_count
```

实际帧长度为 `15 + message_bytes + signer_count * (4 + raw_pk_bytes + signature_bytes)`。
公钥/签名分别使用 65 的 1,952 / 3,309 B 和 87 的 2,592 / 4,627 B 原始编码。

| 场景 | ML-DSA-65 | ML-DSA-87 | 增加 |
| --- | ---: | ---: | ---: |
| 4,096 B、1 签 | 9,376 B | 11,334 B | 1,958 B，20.883106% |
| 65,536 B、8 签 | 107,671 B | 123,335 B | 15,664 B，14.548021% |

`TRNMCPB1` 是候选 primitive 的观测帧；`CPQ1` 是安全契约另行定义的密码配置绑定信封，
PNQ2 和 NPQ6 又有各自的传输/业务语义。本节耗时和字节值不能冒充 CPQ1 授权路径、
PNQ2 接入或 NPQ6 交易的实测结果。每条测量的 `production_message_budget_pass` 保持 `null`，
未据此确认生产消息预算、业务确认时间或吞吐量。本次观测不改变配置激活、证明关系或工作/哈希参数。

### RSS 的实际含义

benchmark 完整二进制运行耗时 **19.154723512 秒**，子进程峰值 RSS 为
**11,136 KiB（10.875 MiB）**。保留的 `run_parameter_observation.py` 在独立 Python 进程中
直接启动已经构建好的 benchmark，随后读取 `RUSAGE_CHILDREN`；这段测量没有启动 Cargo。
因此 RSS 属于整轮 32 场景的二进制子进程，未计入构建过程；它不是某一参数集、
一次验签的内存增量，也不是经证明的最坏内存上限。

## 复现入口与尚待完成的验证

使用仓库固定的 Rust 1.95.0 与待测源码自身的 `Cargo.lock`。默认 RustCrypto 候选测试不需要
OpenSSL provider；完整原有 feature 集需要已固定的 OpenSSL 3.5.9 安装及其环境契约。
组合版须重新核对当前 workspace 及独立 fuzz 锁图，不能套用 `ad081` 的旧依赖检查结论。
保留原有 profile、debug assertions 和 overflow 设置，不通过改优化参数或放宽运行预算获得通过。
以下为复现入口，是否在某个提交上实际执行并通过，以该提交的命令 receipt 为准。

```bash
bash scripts/project-preflight.sh
cargo metadata --locked --offline --all-features --manifest-path trillionnium/Cargo.toml --format-version 1
cargo metadata --locked --offline --manifest-path tests/fuzz/Cargo.toml --format-version 1
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-protocol -p trnm-crypto-primitives --all-features --lib
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-protocol --doc
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib ingress::pq_network
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-mvcc-fee --all-features --lib pq_accounts_v2
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-mvcc-fee --all-features --test pq_account_owner --test pq2_authority_capacity --test pq3_quota_authority --test pq4_task_authority --test pq5_task_renewal
cargo clippy --locked --offline --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features -- -D warnings
python3 evidence/crypto-profile-20261104/recompute_profile_ids.py
python3 scripts/refresh_distributed_source_inventory.py --check
python3 scripts/ci/check_pq_research_integration.py
python3 -m unittest discover -s scripts/ci -p 'test_pq_research_integration.py' -v
python3 -m unittest discover -s scripts/ci -p 'test_ci_source_integrity.py' -v
python3 -m unittest discover -s scripts/ci -p 'test_pq_chain_claim_guard.py' -v
python3 scripts/ci/check_repository.py
```

独立 Python profile encoder 使用显式 grammar 值与 `hashlib`，不导入 Rust 实现，
重现原生测试中断言的固定 profile/message 向量。Node required selectors 必须按待测提交的
现行名单逐条 `--exact` 执行，并由 `check_required_native_test.py` 核对实际命名执行；
不能从过滤器命令退出 0 推断未运行的测试通过。

重新测量参数时，记录准确的 HEAD/tree、受跟踪字节、Rust/Cargo 版本、依赖图/lock 哈希、
二进制哈希、CPU/内存/内核及其他负载。保留完整 stdout、stderr 和真实退出状态，
包括未完成或拒绝的运行。原有便捷运行入口为：

```bash
cargo run --locked --offline --release --manifest-path trillionnium/Cargo.toml \
  -p trnm-crypto-primitives --example pq_parameter_bench -- --samples 64 \
  > pq-parameter-bench.jsonl
python3 evidence/crypto-profile-20261104/recompute_benchmark.py pq-parameter-bench.jsonl
```

如需像本轮一样观测二进制 RSS，应先单独构建，再直接运行产出的二进制，
分别记录构建与执行，避免把 Cargo/编译器内存计入 benchmark。
上述命令及本目录结果均不声明完整 Node runtime 套件、四秒业务确认、4,105-block History、
独立 WAN、恢复组合、治理/发布或共识安全验收通过。
