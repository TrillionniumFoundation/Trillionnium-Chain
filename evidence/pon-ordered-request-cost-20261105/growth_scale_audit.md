# Growth 规模观察独立审计

## 结论

原运行保持 **失败且不完整**：exit 101，完成 2/9 组、16 个测量区块、34 条真实阶段返回；第三组 A=64/H=128 只保留 warmup index 0–104，缺少该组完成记录和 run_completed。正式 reader 返回 `REFUSED: exact cohort file set`。原失败根因仍为 **UNKNOWN**，不能把截断日志改写成 W1、admit、ENOSPC 或已确认回归。

唯一诊断重跑在相同 source、binary、9 组输入和原限制下完整 exit 0；正式 reader 返回 `COMPLETE_LOCAL_OBSERVATION`。实际完成 **9 组、72 个测量区块、153 条阶段返回（144 accepted、9 deliberately cancelled）、9 次冷重开**。这次完成验证了本地观察记录完整性；外部 statvfs monitor 增加了开销，因此两次运行不是配对性能比较，也不构成 F0、p99、CPU 或确认 TPS 验收。

## 来源与二进制绑定

- Source commit: `657bf2a462ff13a6101ebcb4fbe0fb91c515c972`
- Source tree: `7ce7ac50f788dd421e7cc0c9ddb957ade3e8df73`
- 实际重新计算的 binary SHA-256: `8253f1421239e28a4cbf9c520b23bbfa36f95942f94437045e4558ae41fc528c`；文件 181,809,040 bytes，计算期间 size/mtime 稳定。
- Profile: `opt-level=3`, `debug=0`, `debug_assertions=true`, `overflow_checks=true`, `test=true`；features 为 `default,pq-native-openssl`；原构建 artifact `fresh=false`。
- 原命令、重跑命令及两次正式 reader 的 before/after source identity 相同；所有对应 log 的长度和 SHA-256 已重新计算匹配收据。
- 本审计只读取既有原生运行和源码，并写这两份 staged 文件，没有另起 Cargo、native binary 或实验。

## 两次运行分列

| 项目 | 原失败运行 | 唯一诊断重跑 |
|---|---|---|
| 命令收据 | `validation/growth-scale-final.json` | `validation/growth-scale-diagnostic-retry.json` |
| Native exit | 101 | 0 |
| Libtest | 0 passed / 1 failed / 0 ignored | 1 passed / 0 failed / 0 ignored |
| Libtest wall time | 7.26 s | 336.95 s |
| Recorder elapsed（含 source identity 验证） | 18.948242854 s | 346.289460979 s |
| 完成组数 / 测量区块 | 2 / 16 | 9 / 72 |
| 已返回阶段 / accepted / cancelled | 34 / 32 / 2 | 153 / 144 / 9 |
| 完成冷重开 | 2 | 9 |
| 正式 reader | REFUSED, exact cohort file set; exit 1 | COMPLETE_LOCAL_OBSERVATION; exit 0 |
| run_completed | 缺失 | 存在 |

重跑的 432 个真实 empty-maintenance warmup 区块与 72 个测量区块共形成 504 次成功 admission；warmup 的 make/admit/activate 使用单独汇总计时。153 条返回专指 72 次测量 admission、72 次 activation 和 9 次故意取消，不把 warmup、冷重开或未返回调用伪装为这些阶段的 return receipt。

## 原失败位置与相同前缀

`append` 的代码顺序为 JSONL serialize → newline → `sync_all` → `eprintln` → 返回 warmup 循环 → make → admit/activate。原 a64h128 JSONL 末行完整，记录 index 104 和 parent；同一条 stderr 镜像在 parent 的尾部截断，随后直接出现 `FAILED`。首次 `FAILED` 的零起始 byte offset 为 **110592 = 27 × 4096**。recorder 用 create-only 普通文件承接 stdout/stderr，没有截断上限或内容过滤。

- 最后完整 parent: `68c251e65e50a4210ac7d1578442ce4a66c2547677f257eb3ccbe97260eda623`。
- 镜像缺失的末尾为 `23"}` 加换行；原日志没有可辨认的 panic 原因或 OS errno。
- 原失败 cohort 的 **完整 12,059 bytes** 是重跑同 cohort 的逐字节前缀；SHA-256 为 `299999fe8d0935cceeb8025ad8ebc73d98eb5efadf98329f108b7824e63dbc3c`。这包含同一条 cohort_started 和 **105 条 warmup 记录（indices 0–104）**，不只是对比最后一条 parent。
- 重跑 index 105 parent 为 `712185c3e36fabfd427684e7b0647843759cdf0e8202e58e1b7f767c17dfab11`，随后完成全部 128 warmup、8 个测量区块、取消与冷重开。

stderr 写入短时失败与这些事实相容，属于最有根据的解释候选。[Rust 官方 eprintln 文档](https://doc.rust-lang.org/std/macro.eprintln.html)说明 stderr 写失败可触发 panic；panic 输出本身可能同样写不出，而栈展开后临时目录释放或其他活动可能改变文件系统余量。这段因果链没有 syscall/errno 证据，必须保留为推断。workspace Rust crates 中未发现 `set_hook` / `take_hook`，所查 scale/warmup 路径没有 `catch_unwind`；该检索不等于对标准库及每个依赖的运行时 hook 做了观测。

没有发现必须在该输入点触发的 fixture/截止错误：timestamp 为 `1 + height × 10`，admit now 为 100000，测量最高 height 136，取消候选最高 height 137，classic expiry 为 2000；16-header retarget 的 observed 与 desired 均为 150 秒。W1 尝试上限仍为 4096，History 上限仍为 128。成功重跑的精确前缀反驳“这个相同输入必然在 index 104 失败”，但不能排除间歇性环境或实现故障。

## 完整重跑逐组观测

每组 8 个测量样本。中位区间取排序后第 4 与第 5 个值，保留两端，既不是置信区间也不是 p99。计时单位在下表为 ms，JSON 保留原始 ns 及每个样本。

| Accounts | Warmup blocks | Measurements | Admission median interval (ms) | Activation median interval (ms) | Admission max (ms) | Separate query point reads | Cold reopen (ms) |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 64 | 0 | 8 | 8.778785–9.268424 | 2.314625–2.464808 | 10.544242 | 16–16 | 53.678893 |
| 64 | 16 | 8 | 14.595312–14.901117 | 4.048685–4.054585 | 15.554469 | 16–16 | 173.730833 |
| 64 | 128 | 8 | 15.137123–15.578394 | 3.653662–4.196896 | 27.867851 | 16–16 | 1152.014959 |
| 1,024 | 0 | 8 | 11.035384–11.229189 | 2.682738–2.792883 | 13.415049 | 30–30 | 131.531867 |
| 1,024 | 16 | 8 | 14.060967–14.852959 | 3.839382–3.929085 | 101.685812 | 30–30 | 279.023402 |
| 1,024 | 128 | 8 | 16.521277–17.625623 | 4.309322–5.091969 | 24.658880 | 30–30 | 1218.866162 |
| 16,384 | 0 | 8 | 14.240019–14.795942 | 2.764099–2.847164 | 23.997091 | 37–37 | 1836.394357 |
| 16,384 | 16 | 8 | 17.414278–17.993540 | 4.726168–4.815644 | 20.606878 | 37–37 | 2097.381269 |
| 16,384 | 128 | 8 | 16.340131–18.434229 | 4.237683–4.581897 | 35.066426 | 37–37 | 2813.242488 |

原运行已完成的两组也单独保留；这些数值不能与上表作控制变量一致的速度比较：

| Accounts | Warmup blocks | Measurements | Admission median interval (ms) | Activation median interval (ms) | Admission max (ms) | Separate query point reads | Cold reopen (ms) |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 64 | 0 | 8 | 9.582737–9.911832 | 2.426569–3.143696 | 11.963342 | 16–16 | 58.871907 |
| 64 | 16 | 8 | 15.809709–16.875212 | 4.233535–4.619475 | 22.564885 | 16–16 | 201.589379 |
| 64 | 128 | 0; incomplete | — | — | — | — | — |

### Point reads 与 header callback

所有 72 个测量区块的实际 witness owners 都是同一组 3 个 owner。独立 successor multiproof query 的 archive point reads 在 A=64 / 1024 / 16384 时分别恒为 **16 / 30 / 37**，对应 witness bytes 为 **917 / 1841 / 2303**，expanded witness allocation 全部为 **0**。这些数值只覆盖该独立查询，不能替代 admission 的总 SQL 或总工作量。

逐个核对的 admission `header_ancestors` 均为 **3 × min(parent_height, 16)**：H=0 的八个样本为 `[0,3,6,9,12,15,18,21]`；H=16 与 H=128 的八个样本均为 48。取消 admission 在 H=0 为 24，其余为 48；activation 的 header callbacks 为 0。该 contract 仅统计 HeaderAncestor callbacks，不包括 epoch/schema guard、其他 SQL 或 CPU。

### 冷重开与独立 journal 对照

九次冷重开全部保持 active generation、全量 State commitment、账户 nonce 及 SQL 行计数一致。下表 journal 对照在 open 之后单独计时；其 typed 与 semantic events 相等，每组 latest_steps=1、latest_events=1、peak_event_rows=2。这里的 peak 只属于该 journal verifier 的保留行，不表示整个 open 的峰值内存。

| Accounts | Warmup blocks | Cold reopen (ms) | Post-open journal differential (ms) | Typed = semantic events |
|---:|---:|---:|---:|---:|
| 64 | 0 | 53.678893 | 0.245516 | 8 |
| 64 | 16 | 173.730833 | 0.892850 | 24 |
| 64 | 128 | 1152.014959 | 7.824129 | 136 |
| 1,024 | 0 | 131.531867 | 0.254611 | 8 |
| 1,024 | 16 | 279.023402 | 0.621183 | 24 |
| 1,024 | 128 | 1218.866162 | 8.136882 | 136 |
| 16,384 | 0 | 1836.394357 | 0.472032 | 8 |
| 16,384 | 16 | 2097.381269 | 1.237201 | 24 |
| 16,384 | 128 | 2813.242488 | 29.131712 | 136 |

重开后每组 WAL 的文件长度点样本为 0，主 DB 文件从 696,320 到 15,429,632 bytes；各组 before-close/after-reopen 的 DB/WAL/SHM 原值保留在 JSON。这是文件大小的点观测，不是峰值磁盘、峰值 WAL、RSS 或设备内存。

## statvfs 采样边界

外部 monitor 只包裹这次重跑，记录 **6,592 个样本**，请求间隔为 0.05 s。相邻实际采样间隔 min/median/max 为 0.633222 / 50.212314 / 88.703534 ms；首末样本间隔为 337.031179641 s。

| 边界 | free_bytes（f_bfree × f_frsize） | available_bytes（f_bavail × f_frsize） | Monitor offset (ns) |
|---|---:|---:|---:|
| First | 2,159,104,000 | 0 | 19,449 |
| Minimum free | 1,567,744,000 | 0 | 131,294,946,427 |
| Maximum free | 2,159,104,000 | 0 | 19,449 |
| Last | 1,646,338,048 | 0 | 337,031,199,090 |

全部 6,592 个样本的 available_bytes 都是 0，但每个采样点的 free_bytes 都为正，最小 1,567,744,000 bytes；命令仍成功结束。因此单独的 available=0 不足以证明 ENOSPC。没有原失败发生当时的 statvfs trace，也没有写入 errno。采样对象是 validation 目录所在的整个文件系统，包含其他进程活动；约 50 ms 的间隔可能漏过更短的容量变化，不能按阶段归因或称为瞬时峰值。cohort JSONL 没有与 monitor 共享的绝对 monotonic 时间戳，未把样本强行映射到特定 cohort。

## 计时与验收边界

- Native stage timers measure inclusive wall time only; thread_cpu_ns and process_cpu_ns are null. Nested offsets and intervals must not be summed.
- The eight-observation median interval is the fourth and fifth sorted observations; it is neither a confidence interval nor a p99 estimate.
- Packet/signature/full-W1 construction, setup, complete-State reference diagnostics and journal append/fsync are outside each native admission/activation timer but remain campaign cost.
- The diagnostic retry adds an external Python process and statvfs polling. There is no randomized, paired or otherwise controlled performance comparison against the failed attempt; no speedup or regression is inferred from their timings.
- The debug=0 package override preserves opt-level=3, overflow checks and debug assertions for functional validation, but does not establish the original debug-info profile or F0 performance acceptance.
- Archive point reads are from the separate successor multiproof query; header_ancestors counts callbacks. Neither is a count of all SQL, epoch/schema fences, CPU work or total admission work.
- The fixture preallocates 64/1024/16384 accounts and retains real 0/16/128-block warmup histories. It does not replace the separate 65,536 signed account-growth gate.
- This is direct native Node validation, not public ingress, WAN, client inclusion/independent confirmation, confirmation TPS, production activation or whole-chain PQ qualification.
- The original failed run remains failed and incomplete. A successful retry does not identify the original root cause or remove that failure from the record.

## 原始文件 SHA-256

下面的路径均相对于 `/workspace/scratch/add353b13222`。JSON 另外保留 command/reader receipts、monitor、binary binding 和所查源码的 fingerprint。

### 两次运行日志

| Raw file | Bytes | SHA-256 |
|---|---:|---|
| `validation/growth-scale-final.log` | 110832 | `711abd1369ec89ad9a7cb3f247e803848c3bb7354ca492b4f7c8381b0aa5af4f` |
| `validation/growth-scale-diagnostic-retry.log` | 479797 | `88da1199bba94a4076ec4489dc7f63183f7524d46d17a4bb2ee4c85c09697e54` |

### 原失败运行 JSONL

| Raw file | Bytes | SHA-256 |
|---|---:|---|
| `validation/growth-scale-final-657bf2a/cohort-a64-h0.jsonl` | 47227 | `f700ac55b56b2de10c3cdbba972373154868f0fafcf66539cd5c13da82624895` |
| `validation/growth-scale-final-657bf2a/cohort-a64-h128.jsonl` | 12059 | `299999fe8d0935cceeb8025ad8ebc73d98eb5efadf98329f108b7824e63dbc3c` |
| `validation/growth-scale-final-657bf2a/cohort-a64-h16.jsonl` | 49371 | `fc4e04ba2f6df88e70a8253e3c5eb35edd8eca63731d4d5e7e96e747540e56b1` |
| `validation/growth-scale-final-657bf2a/run.jsonl` | 1811 | `7f83947d84ae9ac0edff9d1983525f57147af248845df4bf72cfcf5ef29ef2d7` |

### 完整重跑 JSONL

| Raw file | Bytes | SHA-256 |
|---|---:|---|
| `validation/growth-scale-retry-657bf2a/cohort-a1024-h0.jsonl` | 47310 | `4722ee361a50178aede150fc447a9a67085a111ba0c8cd873131c920dc714002` |
| `validation/growth-scale-retry-657bf2a/cohort-a1024-h128.jsonl` | 62378 | `e1decbebc6619f6cb1a30cd9b5ed92a4f467fe02aac15db8d4e472b5015caf31` |
| `validation/growth-scale-retry-657bf2a/cohort-a1024-h16.jsonl` | 49428 | `03553581a2948bd3f0ace68ac28227b65a3f34ea5a11ec7db75434b5a085dc86` |
| `validation/growth-scale-retry-657bf2a/cohort-a16384-h0.jsonl` | 47395 | `33367142009bfae171676fe4900d90e98414e745dbfe8c37149af08ef919f586` |
| `validation/growth-scale-retry-657bf2a/cohort-a16384-h128.jsonl` | 62417 | `d1e7840f97e430386166762e7e4c970d7e2582be385f2bb3278a8795834074a4` |
| `validation/growth-scale-retry-657bf2a/cohort-a16384-h16.jsonl` | 49502 | `5154b045987d40d73e008d43375ea4e2834a751e71d6df586d5cddf05e0cfa7f` |
| `validation/growth-scale-retry-657bf2a/cohort-a64-h0.jsonl` | 47215 | `5f7f74aed4b25f12d2fa475de87de2165d8712f2b1f18f7cf14f1a484ec55311` |
| `validation/growth-scale-retry-657bf2a/cohort-a64-h128.jsonl` | 62292 | `855c63ccd0e68b5ec6ba6fd4f2a659c8258c752eac9ae2b8603a4c69485cc69c` |
| `validation/growth-scale-retry-657bf2a/cohort-a64-h16.jsonl` | 49361 | `14109aab998f468868d4aaadb5a3e2e5313799f2f36ac2d529204ef81ef86461` |
| `validation/growth-scale-retry-657bf2a/run.jsonl` | 2266 | `1d03f5567e0bf4d3fa426403249fe2bbb711d763324504ae6bb7905afccbf307` |

### 正式 reader 与文件系统采样

| Raw file | Bytes | SHA-256 |
|---|---:|---|
| `validation/growth-scale-original-reader.log` | 56 | `589f8b83fa640ceabe46a5766ef13580ed750aae6ba2300eaad36bc970fa91aa` |
| `validation/growth-scale-retry-reader.log` | 7502 | `52c1a1622c6a67d3c9ebb6e3f7908c6a15f1b2ba0f37e2560ceecf7349ac5f3a` |
| `validation/growth-scale-retry-space.json` | 690677 | `2f16e9f6592ba462170d37b02bd775bbd64c198e93cb7211969824efc587821f` |
| `monitor_growth_scale.py` | 1286 | `51dd98b7d52714be54e2af31fc19fb48f7a408c46b14152359deaf180b1bd9be` |

本审计没有重写任何原始收据或失败记录。最终解释依赖既有 source/binary 绑定、原生命令退出状态、原始 JSONL 和正式 reader 四层证据；原失败和重跑成功分别成立。
