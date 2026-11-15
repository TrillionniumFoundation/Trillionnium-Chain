# W1、DAA、时间戳与累计链权重联合证据

本目录分别记录用户指定基线上的运行、读取器修复前后的控制，以及合并后的候选源码验证。完整工作关系、合法分支和选链观察均不构成实际量子成本或整链安全证明；整链决策保持 **HOLD_NO_GO**。

## 来源、归档与结果身份

原生实现基线固定为 `b5c655ebe9611b3d62cf739e61e6867decc053e3`。本次新增的 Rust 实验、Python reader 和 CI 接线各有自己的源码身份；基线提交本身不代表已经包含这些新增文件。

归档保留原文件名和子目录层级，包括成功、失败、修复前控制及源码快照：

| 文件 | 用途 |
| --- | --- |
| [native-run-01.json](native-run-01.json)、[stdout](native-run-01.stdout)、[stderr](native-run-01.stderr) | 固定 b5 基线上的首次原生联合实验回执与原始输出 |
| [native-run-01.source.rs](native-run-01.source.rs) | 首次原生实验实际使用的测试源码快照 |
| [native-run-02.json](native-run-02.json)、[stdout](native-run-02.stdout.log)、[stderr](native-run-02.stderr.log) | 增强 changed-header／完整 transcript 控制后的原生实验 |
| [reader-checks-02.json](reader-checks-02.json) | 首轮两个 profile 的完整 Python W1 重算及 reader 控制结果 |
| [reader-before-profile-binding.py](reader-before-profile-binding.py)、[reader-tests-before-profile-binding.py](reader-tests-before-profile-binding.py) | profile 目录绑定修复前的 reader 与控制测试源码 |
| [profile-control-before.json](profile-control-before.json)、[profile-control-after.json](profile-control-after.json) | 同一类 profile 误标反例在修复前后的真实执行回执；配套 stdout／stderr 按原名保留 |
| [source-checks-02.json](source-checks-02.json) | 当前源码检查回执；具体命令和结果按回执逐项解释 |
| [source-transfer-02.json](source-transfer-02.json)、[source-transfer-03.json](source-transfer-03.json) | 文件传输与源码摘要记录，供运行身份交叉核对 |
| [joint-boundaries.json](joint-boundaries.json) | 精确整数 DAA／work 边界及显式条件成本模型的输出 |
| [baseline-validation.json](baseline-validation.json) | 最初 locked/offline Cargo graph 与既有 DAA 测试编译的回执 |
| [integration-preview.json](integration-preview.json) | 实际 merge-tree 预检查，记录了 2 处 pin 冲突 |
| [merged-source.json](merged-source.json)、[integration-context.json](integration-context.json) | 普通合并的真实父提交、tree、冲突和精确源码指纹更新 |
| [native-checks-02.json](native-checks-02.json)、[baseline-cli-serial.json](baseline-cli-serial.json) | 保留原生回归、初次全特性 Clippy 和认证 CLI 单线程复跑的原始结果 |
| [source-before.json](source-before.json) | 合并后已提交源码的全部 tracked 字节、模式及 Git 对象检查 |
| [provider-reuse-verification-v1.json](pq-provider-final/provider-reuse-verification-v1.json)、[source-provider-v3.json](pq-provider-final/source-provider-v3.json) | 当前 OpenSSL 3.5.9 安装复核与原始成功构建回执；后者不是本次重新构建的结果 |

新增实现先形成 `314b87c36a6612b87f4a3ccff70771fdac6632ad`，然后通过普通合并保留集成分支的 `62d2d90c9e1f4c8450c89843f1e08360a24283ce`。最终测试源码为 `06cb1834de5dc4a42bd54eba0f5a4491686b9cb0`，tree 为 `e881dd7cf318a562b09de38ff7774a508724fa18`；父提交顺序为上述实现提交、集成提交。

两处冲突均是固定源码指纹。合并保留完整 store 变更和原回归控制，只更新实际合并字节对应的 pin。合并后的 store blob 为 `20181ce2072f530296b4cda95c931ea3c0691902`；`consensus.rs` 仍为 `989ac5f08b8e4f707cda613617fd5245eb6a6463`。每份旧 b5 运行仍绑定原始输入和源码，不能重新标注为最终合并源码的执行。

## 已确认的运行结果

| 阶段 | 已确认结果 | 解释 |
| --- | --- | --- |
| `native-run-01` | 2 个原生测试通过；每个 profile 各 114 个 packet | PNH1 authenticated 与 PGH2 growth 的首次实际 W1、admission、分支调整和链选择实验 |
| `native-run-02` | 2 个原生测试通过；每个 profile 各 114 个 packet；Rust 测试输出耗时 50.74 s | 增强绑定控制，包括使用非共识的 permissive filter 隔离完整 transcript 拒绝；该耗时不是量子攻击成本 |
| 首轮 PNH1 reader | 114 个完整 W1 proof 独立重算；Ran 21，20 passed、1 skipped | 被跳过的是只适用于 PGH2 的 witness 控制；suite 为 `OK (skipped=1)` |
| 首轮 PGH2 reader | 114 个完整 W1 proof 独立重算；21 个控制全部通过 | 包括 PGH2 witness commitment 控制 |
| profile 误标控制，修复前 | 真实进程 exit 0 | 合法 PNH1 内容放入另一个 profile 名称的目录后仍被接受，实际暴露覆盖完整性缺口 |
| profile 误标控制，修复后 | 真实进程 exit 2，符合预期 | 固定 reader 要求导出目录名称与报告 `backend` 一致；错误 profile 目录被拒绝 |
| CI 契约测试 | 110 项通过 | 固定 b5 远端工作区上的 CI 契约与 mutation 测试结果，不替代完整 native／Clippy 验证 |
| 精确算术测试 | 12 项通过 | 验证整数 target、跨度夹紧、记账 work 与条件成本模型的边界 |
| Rust formatting | PASS | 对应源码上的 `cargo fmt --check` |
| 既有 consensus 单元测试 | 10 passed | Cargo job 共 682.6 s，主要为编译；测试本体 0.05 s。二者均不作为造链成本 |
| 原有 DAA fixture | 2 passed | 既有 median／future、夹紧、累计 work 和恢复控制仍实际执行 |
| 原有 `native_node`，默认并发 | 29 passed、1 failed、1 ignored helper | 认证 CLI 第二次 push 遇到 `Connection refused`；原始失败保留 |
| 同一认证 CLI，单线程复跑 | 1 failed | 首次 push 遇到 `Connection reset by peer`；未修改原四秒服务窗口，不能把失败归因于并发 |
| 初次全特性 strict Clippy | exit 101 | 系统 OpenSSL 缺少 `PKey::private_key_from_seed`；保留原始错误，后续使用仓库固定提供者另行验证 |
| 最终源码运行前身份检查 | PASS | 精确核对 16,745 个 tracked entries、1,734,008,089 字节；身份检查本身不执行测试 |

每个“114”是对应单次运行、单个 profile 的 packet／proof 数。不同运行之间的重复验证不累加成新的独立攻击样本。首轮两个 reader 的控制结果也不能写成“42 项全部通过”：PNH1 明确保留了 1 项适用范围跳过。

Clippy 的修正环境使用已存在的隔离静态 OpenSSL 3.5.9。当前 CLI、两个头文件、两个静态库与原成功回执的摘要全部一致；源码包仍匹配仓库的固定摘要，准备脚本也完全一致。本次只读复核版本和算法可用性，没有重新生成签名 smoke 或运行上游完整测试，也没有改变系统 OpenSSL。初次 provider 检索超时和历史下载失败继续由复用回执引用。

### profile 误标控制为何单独归档

修复前的 reader 按 JSON 自报的 `backend/header_profile` 选择验证逻辑；控制测试也依赖自报 profile。两条 CI 调用因此可能都验证 PNH1 内容，而没有建立 PGH2 覆盖。正确的报告摘要只确认字节，没有建立调用方预期 profile 的绑定。

修复后的检查要求 canonical 导出子目录与报告中的 backend 相符。`profile-control-before.json` 的 exit 0 保留为已观察到的缺口；`profile-control-after.json` 的 exit 2 保留为该负向输入被拒绝的结果。旧 reader 和测试源码快照使修复前结果仍可追溯。

### 一个容易混淆的回执标签

某次 wrapper 将 `test_evidence_sources.py` 的回执命名为 `source-integrity-negative`。该项应解释为 **evidence-source negatives**，对应 [test_evidence_sources.py](../../scripts/ci/test_evidence_sources.py)，不能当作 [test_ci_source_integrity.py](../../scripts/ci/test_ci_source_integrity.py) 的执行结果。

最终候选另行实际执行了 `test_ci_source_integrity.py` 的 43 项和 `test_ci_execution.py` 的 77 项，均通过，原始日志见下表。后者包含导入的前者测试，因此两组数量不能相加当作 120 个互不重复控制。

## 这些证据支持的结论及边界

本次实验联合覆盖了实际 W1 关系、分支自身历史的 retarget、逐块 MTP／未来偏移检查以及线性累计 required work。固定轨迹中，普通分支到高度 65、累计 work 为 130；改变时间戳安排的分支到高度 64、累计 work 为 793，并被原生链选择接受。三个负端点跨度为 `-42`、`-199`、`-356`。

这些数值来自有界 development 实验。实验使用显式逻辑时钟；完整 W1 的生成与验证是真实执行，但逻辑时间间隔不测量实际出块节奏、攻击者资源占比、公开网络传播或攻击收益。它没有建立量子攻击的实际可行性或盈利性，也没有测量 W1 的量子电路成本。

Python reader 独立重算：

- PNH1／PGH2 各自的 header challenge 和 block ID 域。
- 114 个完整 PNW1 transcript 与 product。
- 真实父节点形成的分支历史、retarget、MTP／未来偏移及线性累计 work。
- PGH2 witness 字节的有界 framing 与 commitment hash。
- 报告中的链选择、generation 和冷重启观察是否与所选 header／分数一致。

Python reader 没有重放 AAM1 账户证明有效性、原生任务资格、M06 状态执行、SQL admission 或原生数据库冷重启。这些属于外部 native runner 的观察；相应 reader authority flags 保持 `False`。PNH1 的 `activate_observed` 时钟接口与 PGH2 的 activation 接口也分别记录，不能把 PNH1 的接口性质归给 PGH2。

nonce 推导出的尝试数不等于 reader 已重放所有失败 nonce。数学模块中的平方根成本是假设，不是 W1 实测成本；target 改变时 challenge 随之改变，不能把旧 ticket 重新套阈值。

### 报告摘要、源码摘要与执行来源

`--expected-report-sha256` 固定所读取报告的字节身份；报告内的 packet 摘要再绑定实际 packet。完整 W1 重算说明这些 packet 满足 reader 检查的关系。以上均不自动证明运行主机、编译产物或源码提交身份。

源码／传输回执、测试源码快照、运行命令和原始日志共同用于核对执行来源。reader 明确不承担 host/source provenance 验证。最终合并源码须有自己的执行回执，不能仅沿用本目录早期报告的摘要。

## 使用 fresh 输出目录复现当前实现

在包含本次测试、reader 及其依赖的完整 checkout 中运行。仓库 `rust-toolchain.toml` 固定 Rust 1.95.0；历史运行的确切 argv、编译模式与环境以各自回执为准。只 checkout 原始 b5 基线不会自动得到本次新增文件。

以下命令创建新的输出根目录，不复用归档中的 profile 目录：

~~~bash
set -euo pipefail

bash scripts/project-preflight.sh
joint_run_root="$(mktemp -d /tmp/trnm-joint-daa.XXXXXX)"
export TRNM_JOINT_DAA_EVIDENCE_DIR="$joint_run_root/native"

test ! -e "$TRNM_JOINT_DAA_EVIDENCE_DIR"
test ! -L "$TRNM_JOINT_DAA_EVIDENCE_DIR"

cargo test --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --test daa_joint_consensus \
  -- --nocapture --test-threads=1 \
  2>&1 | tee "$joint_run_root/native.stdout-stderr.log"

unset TRNM_JOINT_DAA_EVIDENCE_DIR

for joint_profile in pnh1-authenticated pgh2-growth; do
  joint_raw_dir="$joint_run_root/native/$joint_profile"
  joint_report_sha="$(sha256sum "$joint_raw_dir/joint-daa.json" | cut -d ' ' -f 1)"

  python3 -B scripts/pon_joint_daa_reader.py \
    --raw-dir "$joint_raw_dir" \
    --expected-report-sha256 "$joint_report_sha" \
    > "$joint_run_root/reader-$joint_profile.json"

  python3 -B scripts/ci/test_pon_joint_daa_reader.py \
    --raw-dir "$joint_raw_dir" \
    2>&1 | tee "$joint_run_root/reader-tests-$joint_profile.log"
done

printf '%s\n' "$joint_run_root"
~~~

相应的算术、CI 契约和 formatting 检查：

~~~bash
python3 -B formal/pon-nakamoto-v1/test_joint_consensus_boundaries.py -v
python3 -B scripts/ci/check_ci_contract.py
python3 -B scripts/ci/test_ci_contract.py
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
~~~

以实际输出的测试数量、跳过数量、退出码和源码身份填写新的验证记录。修复后的 reader 控制包含 profile 误标反例；最终套件结果以新日志为准，不能套用首轮 21 项的统计。

## 本地早期 CI 观察的来源说明

本地 authoring checkout 的 Git 基础为较早的 `b66`，随后覆盖了精确 b5 的三个 CI 文件。该不完整本地组合首次执行 CI 契约套件时，110 项中 107 项通过、3 项因缺失既有 b5 文件 `test_useful_cell_execution_v2.py` 而报错。

**该次本地执行没有保存原始日志文件。** 此段是保留的 provenance note，不能表示存在可重新读取的 raw local log，也不能将该结果归为远端精确 b5 checkout 的失败。远端 b5 的 CI 契约 110 项通过结果单独记录。

## 最终合并源码验证

以下运行全部绑定 `06cb1834de5dc4a42bd54eba0f5a4491686b9cb0`。Rust 测试使用 Rust 1.95.0、locked/offline dependencies 和单线程测试参数；编译并发为 2。完整 argv、退出码与 wrapper 墙钟耗时保留在 [final-native-checks.json](final-native-checks.json)、[final-python-checks.json](final-python-checks.json)、[final-reader-checks.json](final-reader-checks.json)、[final-retained-readers-and-markdown-controls.json](final-retained-readers-and-markdown-controls.json) 及 [final-strict-clippy.json](final-strict-clippy.json)。机器可读结论见 [summary.json](summary.json)，目录内容摘要见 [manifest.sha256](manifest.sha256)。

| 检查 | 最终实际结果 | 原始输出 |
| --- | --- | --- |
| 新联合 native fixture | 2 passed；PNH1、PGH2 各 114 个不同 packet；测试本体 64.10 s | [native-run-03.stdout.log](native-run-03.stdout.log) |
| PNH1 完整独立 reader | 114 个完整 proof；130 → 793 链权重观察一致 | [reader-final-pnh1-authenticated.stdout.log](reader-final-pnh1-authenticated.stdout.log) |
| PNH1 reader 控制 | Ran 22；21 passed、1 PGH2-only skipped | [reader-final-negative-pnh1-authenticated.stderr.log](reader-final-negative-pnh1-authenticated.stderr.log) |
| PGH2 完整独立 reader | 114 个完整 proof；130 → 793 链权重观察一致 | [reader-final-pgh2-growth.stdout.log](reader-final-pgh2-growth.stdout.log) |
| PGH2 reader 控制 | 22 passed | [reader-final-negative-pgh2-growth.stderr.log](reader-final-negative-pgh2-growth.stderr.log) |
| 既有 DAA fixture | 2 passed | [final-native-retained.stdout.log](final-native-retained.stdout.log) |
| 既有 DAA 独立 reader | 85 observations、84 个不同完整 proof、83 个已接纳 packet 观察、2 个时间规则拒绝；10 个 reader 控制通过 | [reader output](reader-final-retained-daa.stdout.log)、[controls](reader-final-retained-daa-negative.stderr.log) |
| `native_node` 目标 | **28 passed、2 failed、1 ignored helper；exit 101** | [final-native-retained.stdout.log](final-native-retained.stdout.log) |
| legacy reorg 单元测试 | 5 passed | [final-legacy-reorg.stdout.log](final-legacy-reorg.stdout.log) |
| reorg readback 单元测试 | 6 passed | [final-reorg-readback.stdout.log](final-reorg-readback.stdout.log) |
| consensus 单元测试 | 10 passed | [final-consensus-unit.stdout.log](final-consensus-unit.stdout.log) |
| canonical repository check | PASS；26 workspace packages、25 normal dependency edges、1,199 Rust files、4,234 local links | [final-repository.stdout.log](final-repository.stdout.log) |
| 固定源码 corpus 及其控制 | PASS；37 个控制通过 | [check](final-corpus.stdout.log)、[controls](final-corpus-negative.stderr.log) |
| 真正的 source-integrity 控制 | 43 passed | [final-source-integrity-negative.stderr.log](final-source-integrity-negative.stderr.log) |
| CI execution 控制 | 77 passed，其中包含 source-integrity 控制 | [final-ci-execution-negative.stderr.log](final-ci-execution-negative.stderr.log) |
| CI contract 控制 | 110 passed | [final-ci-contract-negative.stderr.log](final-ci-contract-negative.stderr.log) |
| 精确算术边界 | 12 passed | [final-arithmetic.stderr.log](final-arithmetic.stderr.log) |
| native inventory／Rust formatting／whitespace | PASS | [final-python-checks.json](final-python-checks.json) |
| workspace strict Clippy | PASS；`--workspace --all-targets --all-features -- -D warnings` | [final-strict-clippy.stderr.log](final-strict-clippy.stderr.log) |
| 已有 Git-tree Markdown checker 控制 | 12 passed：8 个负向、4 个正向／scope 控制 | [markdown-controls.stderr.log](markdown-controls.stderr.log) |
| 运行前、运行后完整源码身份 | 均 PASS；16,745 tracked entries、1,734,008,089 字节，完全相同的 commit/tree | [source-before.json](source-before.json)、[source-after-native.json](source-after-native.json) |

canonical repository check 的计数属于测试源码提交 06 的实际输出。最终只添加证据文件的发布提交，需另行进行精确 Git-tree Markdown 链接检查；不能把这些计数标成后续提交的结果。Clippy 覆盖全部 workspace 的编译／lint，本轮 native 执行覆盖上表指定目标；并未声称执行并通过整个 workspace 的所有测试。

### 发布时的并行集成变化

最终测试结束后，集成 review base 从 `62d2d90c9e1f4c8450c89843f1e08360a24283ce` 前进到 `96a241bf43f6a46d35dfb3d4ced9594ed8ceca75`。增量为 History stage diagnostic 的测试、runner、workflow、host-runner 接线和 corpus 指纹，共 6 个路径。最初归档前置检查因此停止，尚未复制或提交证据；随后单独读取该增量并进行了真实 `git merge-tree` 预检查。

已测试的 06 与该新 base 可无冲突组合，预期合并 tree 为 `c48fa8a24ba2975312cecaa4f2adb959c15e1fa4`，见 [publication-base-observation.json](publication-base-observation.json)。发布保留已测试源码身份，把更新后的集成分支作为 Draft PR 的 review destination；**上述 native 运行没有在该 prospective merge 上执行**。无冲突合并预检查不等于新组合的测试通过。之后的证据文件会改变完整 Git tree，最终 head/base/merge 身份和 Markdown 检查结果由 PR 的发布回读单独记录。

### 两项最终失败，分别保留

`test_authenticated_cli_push_and_sync_share_one_durable_outbox_owner` 在 `native_node.rs:1590` 的 `sync` 成功断言失败，输出 `PUBLIC_HOST_KERNEL_PARENT`。这与旧 b5 的 first／replay push 连接错误是不同阶段、不同错误，不能并为一次已解释的失败。

`test_full_transaction_pages_use_byte_limits_and_recover_all_native_state` 在 `native_node.rs:1407` 对完整页的 `sync_from` 结果执行 unwrap 时，得到 `PublicMutationCpuBudget`／`PUBLIC_MUTATION_CPU_BUDGET`；随后 `1432` 的 `result.unwrap()` 再次抛出 `catch_unwind` 捕获的失败。这不是第二次独立的 server join 失败；后续 state root、height、cold reopen 断言尚未执行。错误说明当前执行没有完成该用例的恢复契约，不能仅凭错误代码认定是 DAA 问题、CPU 竞争或服务窗口导致。

只读检查还确认认证 CLI fixture 的三个顺序调用共用四秒服务 deadline；`listening` 输出发生在绑定之后、进入 serve loop 与启动 accept workers 之前。现有失败日志不足以建立完整的服务端 readiness、请求阶段时间和退出原因。串行基线也曾失败，因此不能写成“只是默认并发”。本次没有放宽四秒窗口、删除断言或把这些用例标成通过。

完整 native 回归的失败与整链工作成本论证的未完成是两个分别存在的限制。所有成功测试、完整关系重放、源码检查和数学边界都不解除 **HOLD_NO_GO**。归档继续保留早期运行、reader 修复前后控制、失败环境和最终合并验证的各自身份。
