# TCP cancellation evidence — historical dirty 73ab candidate

本包固定记录 **native input map `f56cc35bd9c9462c931776cc4e08fedeeaa7c73df5f00b2907cc2a057bc81381` / ELF `dd6a1dee07568ba26022ccd690933af13788696e1925e442fe3ba471927f856f`** 的结果。基底为 `73ab6e9a83bcc836e261d93f9bb23ceafe556758`，执行时有未提交的协作修改，因而这不是裸 `73ab` 的测试结果。后来修改过的源码或 ELF 需要独立验证。

机器可读入口：[summary.json](summary.json)。完整复制校验记录：[copy-verification.json](copy-verification.json)。

## 观测与范围

| 阶段 | 实际结果 | 原始记录 |
|---|---|---|
| 旧 helper 独立 Rust / localhost TCP 反例 | 编译 0；断言失败退出 101 | [源码](old-helper/original-half-close.rs)、[编译输出](old-helper/compile.log)、[失败输出](old-helper/negative.log)、[receipt](old-helper/receipt.json)、[命令](old-helper/commands.json) |
| Node attempt 1 | 编译退出 101；未执行 Node 测试 | [终态](native/build-attempt-1/build-result.json)、[原始 stdout gzip](native/build-attempt-1/build.stdout.jsonl.gz)、[stderr](native/build-attempt-1/build.stderr)、[诊断摘录](native/build-attempt-1/error-diagnostics.json) |
| Node attempt 2 | 原 test profile、完整 Node lib、all-features、no-run 编译成功 | [终态](native/build-attempt-2/build-result.json)、[原始 stdout gzip](native/build-attempt-2/build.stdout.jsonl.gz)、[stderr](native/build-attempt-2/build.stderr) |
| 同一 ELF 的五个指定原生控制 | 5/5 通过；五次 required-selector reader 均通过 | [原始逐项结果](native/test-results.json)、[最终 receipt](native/receipt.json) |

旧反例的生产函数逐字节核对了 [40a5 的 public_v3.rs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/40a5ba25e40fd5eda5b04fc1c3811320d438de11/trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs)。函数 SHA256 是 `05d73f62f6fe1887a70fe2f7b0583e493f2e8b341f29cdf02b70d291b2326657`。harness 只用标准库 Result 别名包住该函数，实际建立 TCP 连接、发送一个字节并半关闭。**没有在完整旧 Node 上运行新增网络负例，不能把此记录称作完整旧入口的红对照。**

Attempt 1 的失败是 `pre_write_tests.rs` 缺少 `use crate::ensure`，产生三个 E0425。它是实际编译失败。此失败及其输入身份均保留；修正后的 attempt 2 没有覆盖它。

五个控制使用本地普通 development classical V3、真实签名请求及原生提交。覆盖：

1. body 已完整时拒绝尾字节，同时不消费 pending 阶段的合法下一帧。
2. 八个 mutation grants 已满时提前发送合法完整 body；释放 grant 后读取原有缓冲内容并完成原生提交。
3. 每臂八个已付费请求，在“追加字节保持开放”和“追加字节后半关闭”两臂取消；检查原 CPU flow 恒等式、结算及资源归还，再以同一合法数据包正常提交。
4. 原有 signed submit 半关闭/断开、等待 owner 或排队时不启动工作的控制。
5. 原有满队列下 paid requests 断开取消、不启动工作的控制。

新增测试允许入队任务与取消发生真实调度竞态，CPU 账户按实际执行结算；没有把固定线程调度次数当作正确性条件。原测试、资源额度和业务 deadline 保留。

| 编号 | 原始 stdout | 原始 stderr | 独立 required-selector reader |
|---|---|---|---|
| 1 | [test-1.stdout](native/tests/test-1.stdout) | [test-1.stderr](native/tests/test-1.stderr) | [结果](native/tests/test-1-required.stdout) |
| 2 | [test-2.stdout](native/tests/test-2.stdout) | [test-2.stderr](native/tests/test-2.stderr) | [结果](native/tests/test-2-required.stdout) |
| 3 | [test-3.stdout](native/tests/test-3.stdout) | [test-3.stderr](native/tests/test-3.stderr) | [结果](native/tests/test-3-required.stdout) |
| 4 | [test-4.stdout](native/tests/test-4.stdout) | [test-4.stderr](native/tests/test-4.stderr) | [结果](native/tests/test-4-required.stdout) |
| 5 | [test-5.stdout](native/tests/test-5.stdout) | [test-5.stderr](native/tests/test-5.stderr) | [结果](native/tests/test-5-required.stdout) |

实际 libtest registry 列出了 **1029 项，28 ignored，1001 unignored**：[统计](native/registry-counts.json)、[全部名字 gzip](native/registry-all.txt.gz)、[ignored 名字](native/registry-ignored.txt)。本轮只执行上述五项，**没有执行完整 1001 项套件**。本包也没有重跑 hosted F0/campaign、四秒 SLO、0.25 CPU Host 或 WAN 吞吐实验，不能据此宣布这些业务门槛闭合。

## 输入身份与精简

- [Attempt 1 manifest](native/source-attempt-1.json.gz)：`e11653cd7fb5633c85bf9d6e4cb4f478e094fcbad0aad81d8f93b573f2a92950`。
- [Attempt 2 manifest](native/source-attempt-2.json.gz)：`f56cc35bd9c9462c931776cc4e08fedeeaa7c73df5f00b2907cc2a057bc81381`。
- [原生编译环境](native/compiler-environment.json)：正常 rustup shim、1.95.0、真实 feature/environment 记录；未显式设置 RUSTC。
- [重复观测对应关系](native/source-observations.json)：两个不同输入身份各保留一份 manifest；原始 before/after 文件实际逐字节相同后才去重。
- [成功候选相对 73ab 的 native patch](native/tested-native-from-73ab.patch.gz) 与 [恢复 attempt 1 的单文件 delta](native/attempt2-to-attempt1.patch.gz)。
- [Patch 校验](native/patch-verification.json)：仅在一次性 scratch 树中使用 git apply，并逐项核对修改文件与历史 manifest；整理证据没有编译或运行原生测试。

Manifest 覆盖记录的 1194 个 workspace 原生输入/fixtures 及源码直接 include 的外部数据。它不声称整个仓库冻结；当时 workflow/docs 允许并行修改。

成功 patch 包含合作模块的全部 18 个 native 修改，目的是重建实际接受五项测试的候选。Attempt 1 只比 attempt 2 少一个 ensure 导入和两项后来加入的 RESET 控制；其恢复文件 SHA 精确匹配当时失败 manifest 的 `c575cf761cc1719d226005a184fa614741db18174252210b5265b00f0d40ca9f`。

原始日志保留观测时的绝对路径。下列复现使用仓库相对路径，不依赖那些旧 workspace 目录。ELF 字节哈希用于识别本次实际测量产物；重建时目录和工具链依赖环境可能影响新的 ELF 字节。

## 校验与复现

以下是供后续人工复现的命令，整理本包时没有执行这些编译/测试命令。先从仓库根目录记录证据位置：

```bash
tcp_evidence="$PWD/evidence/pon-throughput-continuation-20261104/parent-and-tail/tcp"
(cd "$tcp_evidence" && sha256sum --check SHA256SUMS)
```

复制记录同时给出压缩 payload 和解压后原始内容的 SHA256。原始零字节 stderr/compile.log 也保留并校验。

### 独立旧 helper

```bash
tcp_old_output="$(mktemp -d)"
rustc +1.95.0 --edition=2021 "$tcp_evidence/old-helper/original-half-close.rs" -o "$tcp_old_output/original-half-close"
tcp_old_exit=0
"$tcp_old_output/original-half-close" > "$tcp_old_output/stdout" 2> "$tcp_old_output/stderr" || tcp_old_exit=$?
test "$tcp_old_exit" -eq 101
```

### 完整候选输入与 Node 控制

在独立干净 checkout 中选择 `73ab6e9a83bcc836e261d93f9bb23ceafe556758`，然后应用成功候选 patch。不要把 patch 叠加到已经含有同一修改的树上。

```bash
gzip -dc "$tcp_evidence/native/tested-native-from-73ab.patch.gz" | git apply -
python3 - "$tcp_evidence/native/source-attempt-2.json.gz" <<'PY'
import gzip, hashlib, json, pathlib, sys
manifest=json.loads(gzip.decompress(pathlib.Path(sys.argv[1]).read_bytes()))
for name, expected in manifest["native_input_files"].items():
    assert hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()==expected, name
canonical=json.dumps(manifest["native_input_files"],sort_keys=True,separators=(",",":")).encode()
assert hashlib.sha256(canonical).hexdigest()==manifest["manifest_sha256"]
print(manifest["manifest_sha256"])
PY
bash scripts/project-preflight.sh
```

使用正常 rustup shim 和仓库原 profile。all-features 的 PQ provider 按仓库既有 [prepare_pq_provider.sh](../../../../scripts/ci/prepare_pq_provider.sh) 设置，下面给出隔离环境形式；其下载、源码 hash 和 smoke 检查仍由原脚本执行：

```bash
rustup toolchain install 1.95.0 --profile minimal --component clippy --component rustfmt
tcp_runner_temp="$(mktemp -d)"
tcp_provider_env="$(mktemp)"
RUNNER_TEMP="$tcp_runner_temp" GITHUB_ENV="$tcp_provider_env" TRNM_CI_RECEIPT_DIR="$tcp_runner_temp/provider-receipt" CARGO_BUILD_JOBS=2 bash scripts/ci/prepare_pq_provider.sh
set -a
. "$tcp_provider_env"
set +a
unset RUSTC RUSTDOC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 RUST_TEST_THREADS=1
export CARGO_TARGET_DIR="$tcp_runner_temp/target"
bash scripts/project-preflight.sh
cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib --all-features --no-run --message-format=json > "$tcp_runner_temp/build.jsonl" 2> "$tcp_runner_temp/build.stderr"
```

从 Cargo 输出取得实际 test ELF，再只执行本包的五个 selector：

```bash
tcp_node_binary="$(python3 - "$tcp_runner_temp/build.jsonl" <<'PY'
import json,sys
rows=[json.loads(line) for line in open(sys.argv[1])]
executables=[r["executable"] for r in rows if r.get("reason")=="compiler-artifact" and r.get("target",{}).get("name")=="trnm_pon_node" and r.get("profile",{}).get("test") and r.get("executable")]
assert len(executables)==1
print(executables[0])
PY
)"
python3 - "$tcp_evidence/summary.json" > "$tcp_runner_temp/selectors.txt" <<'PY'
import json,sys
for row in json.load(open(sys.argv[1]))["native_execution"]["tests"]:
    print(row["selector"])
PY
tcp_index=0
while IFS= read -r tcp_selector; do
    tcp_index=$((tcp_index + 1))
    tcp_exit=0
    "$tcp_node_binary" "$tcp_selector" --exact --nocapture --format pretty --test-threads=1 > "$tcp_runner_temp/test-$tcp_index.stdout" 2> "$tcp_runner_temp/test-$tcp_index.stderr" || tcp_exit=$?
    printf '%s
' "$tcp_exit" > "$tcp_runner_temp/test-$tcp_index.exit"
    python3 scripts/ci/check_required_native_test.py "$tcp_runner_temp/test-$tcp_index.stdout" --test "$tcp_selector"
    test "$tcp_exit" -eq 0
done < "$tcp_runner_temp/selectors.txt"
```

若需精确重建保留的 attempt 1 编译失败，在已应用成功 patch 的独立树上再应用 [attempt2-to-attempt1.patch.gz](native/attempt2-to-attempt1.patch.gz)，用 attempt 1 manifest 逐文件核对，再运行相同 no-run 编译命令。预期是缺失 ensure 导入的三个 E0425 和退出 101。此故障复现不得写入正常候选或用来替代原生功能控制。

## 独立的 40a5 hosted 历史记录

这是另一套 source/lane 结果，仅作为背景：[run 41785836298](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41785836298)，PR head 为 `40a5ba25e40fd5eda5b04fc1c3811320d438de11`，在 2026-11-04 07:13:32 UTC 已观察到四条终态成功：

| lane | 官方 job | Node 结果 | 严格 Clippy step |
|---|---|---|---|
| x64 head | [126427665244](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41785836298/job/126427665244) | 983 passed / 0 failed / 27 ignored / 0 filtered | success |
| x64 prospective merge | [126427664953](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41785836298/job/126427664953) | 同上 | success |
| ARM head | [126427665192](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41785836298/job/126427665192) | 同上 | success |
| ARM prospective merge | [126427665343](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41785836298/job/126427665343) | 同上 | success |

这些事实来自本次会话对 GitHub 原始 job logs 和 step metadata 的读取。**本包没有下载并本地校验这四条 job 的 ZIP，也不在这里断言两条 prospective merge 的实际 merge SHA。** 此历史记录不能替代 dirty f56 候选或其后继版本的完整 CI 结果。
