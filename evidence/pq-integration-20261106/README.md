# PQ 整合：当前实现、真实终态与未闭合边界

**结论：HOLD / NO-GO。当前整合已纳入具体授权修复、TLS witness V2 接线和初始发布根材料复用；仍不能认定整链抗量子，也不能据此批准生产部署或持续公网运行。**

本轮代码固定为 `c07e8b9cce4621c5ef6f61256482bfe94e5a622f`，tree `35125592c14098385eab8693bbf05df0506d3610`。有序父提交是 `d6ec50bb4c9f92656c3b95430ca305896012e69c` 与 `5bb29d6ae39fa0c71f9151f3dce31fa1a3ab1800`，保留了原集成工作、发布证据、witness owner 和并发发布根改动的历史。当次 target 是 `513e92dfc27044ef3e0c9d62e7ae504fa5bea38f`。

这是从已发布 ca4 原件、完整终态原始记录及独立审读生成的新 V6 报告。原 ca4 README 在末尾全文保留，机器文件也完整嵌入当时的 qualification 与 source map；其中“current”“publication parent”和旧 CLI 描述只属于历史阶段。当前事实由本报告前半部分和机器文件的 `current_phase` 给出。准备期间不可取的草稿只登记已观察到的身份，不能冒充已恢复原件。

## 1. 全链授权面与当前边界

| 安全面 | 当前实现与核查 | 尚未成立的资格 |
|---|---|---|
| 交易、账户与应用授权 | 显式 PQ profile 有真实 ML-DSA-65；ApplicationV6 覆盖注册、轮换、任务及应用授权。 | 旧账户不会自动迁移；须在经典身份仍可信时完成 PQ 绑定，并逐一覆盖真实生产入口。 |
| 父状态恢复 | 经典恢复入口先检查节点网络 profile，拒绝 PQ 策略节点通过恢复组合路径签发经典凭据。 | 该拒绝检查不能代替完整 PQ 父状态恢复协议与 owner。 |
| 节点 TLS 与身份 | 保留 TLS 1.3 混合密钥协商、ML-DSA 双向认证、内外签名者绑定及禁止降级；启动前核本地证书时间、用途、SAN、单一 pinned CA 与两证书链。 | 私密任务的全路径覆盖、实际公网监听、托管与撤销、恶意握手成本和长期 WAN 运行尚未合格。 |
| 普通 CLI witness V2 | `pq-tls-serve` 的 V2 明确选择带 PqWitnessV4 的 create/open_existing，绑定 writer/service 身份并在 ready 前核 Current。 | 仅保护 PNQ2 resource/peer/request 三表；首个二进制端到端控制本次失败，不能宣称其后续重开与整目录回滚断言通过。 |
| 发布、治理与 Cell 当前授权 | M15 保留 checkpoint、可信时间、根/发布寿命、授权代际及 CellActivation→CellManifest 检查；新增不可变初始根 key material 复用。 | `check_current` 是只读检查，不推进每次观察的持久化 time_floor；真正安装/配置生效/Cell 激活的最终效果边界仍未贯通。 |
| Cell V3 传输 | persistent-rarest-v3 的普通 TCP TCQ3/TCS3 公开缓存路径保留内容、帧、连接、字节与期限约束。 | 它不经过 Node PQ TLS；内容验证不等同于私密任务认证与保密。 |
| 恢复与防回滚 | witness、journal、checkpoint 与 effect-context 各自在限定域中提供检查。 | PNQ2、账户、块、History、M15、CURRENT 及跨仓库状态没有共同获得全目录防回滚资格；新鲜锚点仍需独立保存。 |
| 最终性 | 未激活的 release-finality 可执行参考仍使用 Ed25519。 | 不能据此声称已部署 PQ 确定性最终性；这也不是现有主网已被攻破的证据。 |
| PoN 工作与链选择 | 固定工作关系、SHA-256 challenge/ticket、矩阵与数据访问需要独立分析。 | 量子 oracle、可逆实现、内存与清理成本、DAA、扣块及分叉经济性仍未闭合；不接受整链统一“128/256 位抗量子”标签。 |

主要源码与边界文档：

- [原生 PQ 密码实现](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/c07e8b9cce4621c5ef6f61256482bfe94e5a622f/trillionnium/crates/trnm-crypto-primitives/src/pq_auth.rs)
- [父状态恢复入口](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/c07e8b9cce4621c5ef6f61256482bfe94e5a622f/trillionnium/crates/trnm-pon-node/src/public_submit.rs)
- [TLS 本地身份校验](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/c07e8b9cce4621c5ef6f61256482bfe94e5a622f/trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/context.rs)
- [V2 witness CLI](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/c07e8b9cce4621c5ef6f61256482bfe94e5a622f/trillionnium/crates/trnm-pon-node/src/pq_tls_cli_witness.rs)
- [发布授权内核](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/c07e8b9cce4621c5ef6f61256482bfe94e5a622f/trillionnium/crates/trnm-release-bundle/src/pq_release.rs)
- [授权面审计](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/c07e8b9cce4621c5ef6f61256482bfe94e5a622f/docs/security/PQ_AUTHORITY_SURFACE_AUDIT_20261031.md)
- [量子工作与 DAA 边界](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/c07e8b9cce4621c5ef6f61256482bfe94e5a622f/docs/security/PQ_QUANTUM_DAA_SENSITIVITY_20261031.md)

### V1/V2、见证服务与恢复

V1 仍使用不带 witness 的 owner，拒绝 V2 字段和 writer-key 参数。V2 要求匹配的 ML-DSA writer 私钥、固定的 witness/writer SPKI、非零 generation、规范策略、绝对 Unix socket 路径，以及显式 create 或 open_existing。错误输入、缺失/拥塞端点和错误服务身份按各自边界拒绝，不能转成 V1 或明文 fallback。create 不重开已有 owner，open_existing 不创建、注册、重置或修复 witness。

单次非阻塞 Unix 连接保留原 250 ms I/O 期限，没有自动重试；该期限不是所有密码计算的抢占式 CPU 上界。认证 Current 不是排他 writer 租约，也不能自行证明服务从未回滚。丢失 CAS 确认仍是不确定效果，不授权退款、重放或重置。服务自身恢复需要独立保管的精确新鲜 checkpoint。

测试 fixture 是实际普通 Node 子进程、独立数据库及测试服务线程。它没有证明独立部署的 witness daemon、托管、撤销、服务自身灾难恢复、WAN 或全节点恢复资格。三表 witness 不扩展为账户、块、History、M15、CURRENT 或 Hepta 状态保护。旧 Node 快照场景设计保留了活跃 witness 数据库；本轮首个控制在到达该场景之前已经失败。

### 初始发布根材料复用

[PqInitialRootKeyMaterialV1](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/c07e8b9cce4621c5ef6f61256482bfe94e5a622f/trillionnium/crates/trnm-release-bundle/src/pq_release/initial_root_material.rs) 保存 private 完整 root、其 digest 和不可变公开验签 key map 的 Arc。完整 root 仍包含 expires_at。它不缓存 signature/quorum 成功、checkpoint、当前许可或 owner 的可变状态，也不把准备时的时钟下限带到新的 owner。

每次 bootstrap 在本次可信 initialized_at 上校验完整 root 等值、独立 pin、规范编码 digest、初始 generation=1 和 previous=0。不同合法 root 也不能被 fallback 接受；原 bootstrap 分支只保留 malformed-input 的错误优先级。每个新 authority 的 checkpoint、time_floor、versions、current、history、retired 和 event count 独立。根轮换仍在旧、新两组 quorum 都验证成功后替换本 owner 的 Arc；共享公开 key map 不等于全局撤回广播。

原 37 个 release 测试全部保留，加 6 个新控制后为 43 个名字。六项检查完整 root/pin、本次时间与独立 owner、签名/quorum 不可复用、历史初始化与当前使用寿命的区分、双 quorum/退役/兄弟 owner 隔离，以及限制和错误优先级。它们不授予 final-use installer、独立 checkpoint 托管、持久恢复、并发运行或性能资格。实际最终使用仍需新鲜独立 checkpoint、可信 now，以及与最终效果绑定的当前授权检查。

## 2. c07 的实际终态

### 源码与依赖

20 条原有限 source 命令全部通过，实际 Python 测试为 **232 = 104 + 43 + 38 + 22 + 25**。六份原 `--locked --offline` 图实际解析到 175 / 69 / 193 / 306 / 191 / 191 个 packages。格式、inventory、source/corpus/claim guards、仓库链接与差异检查都保留原条件。

隔离材料验证环境使用 hash-pinned packaging 26.3，保留原 `--isolated --only-binary=:all: --require-hashes --report` 安装及实际环境记录。源检查的 Rust/native 测试数为 0；它不替代下一节的原生执行。

### 原生补充

完整原生批次 durable exit **1**，无 timeout/cancellation：**77 个命令/reader 观察 = 74 succeeded + 1 failed + 2 blocked**。命令、登记表、判定器与基准样本不作为额外独立业务测试计数。

| 当前 Node 定向控制 | 通过 | 失败 | 未成功观察 |
|---|---:|---:|---:|
| TLS library 13项 | 13 | 0 | 0 |
| 普通CLI 4项 | 4 | 0 | 0 |
| feature-off 1项 | 1 | 0 | 0 |
| V2 witness 5项 | 4 | 1 | 0 |

完整 checkpoint/release component 原命令保留：

```text
cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml -p trnm-checkpoint-store -p trnm-release-bundle --all-targets --no-fail-fast --message-format=json -- --test-threads=1
```

实际五个 harness summary 分别为 **11 / 15 / 15 / 6 / 43 passed**，均 0 failed / 0 ignored。release 43 个名字的完整实际执行读回、实际登记表和六个新 initial-root exact 的原 reader 均通过；六次 exact 与这 43 个名字重叠，不能写成 49 个独立 release 用例。checkpoint 各目标按原观察分别列出，不推断唯一业务测试总数：

```json
[
  {
    "failed": 0,
    "filtered_out": 0,
    "ignored": 0,
    "local_elf_body_rehashed": false,
    "measured": 0,
    "named_ok_tests": [
      "tests::activation_and_key_boundaries_remain_closed",
      "tests::authority_exact_cas_rejects_replay_and_reopens",
      "tests::bound_anchor_replacement_fails_closed_before_load",
      "tests::bound_lock_replacement_fails_closed_before_load",
      "tests::bound_log_replacement_fails_closed_before_load",
      "tests::bound_parent_directory_replacement_fails_closed_before_load",
      "tests::journal_truncation_and_byte_edit_fail_closed",
      "tests::oversized_checkpoint_head_read_is_bounded_and_refused",
      "tests::pinned_recovery_rejects_head_deleted_after_precheck",
      "tests::replayed_record_fails_closed",
      "tests::unix_client_round_trip_uses_separate_thread_authority"
    ],
    "original_cargo_elf_identity": {
      "binding": "artifact advertised by this Cargo invocation; hashed immediately afterward",
      "bytes": 10585408,
      "captured_unix_ns": 1793973444447378017,
      "fresh": false,
      "package_id": "path+file:///tmp/chain-pq-independent-desktop-20261106-quantum-work-v1/witness-owner-integration-20261106-v1/source/trillionnium/crates/trnm-checkpoint-store#0.1.0",
      "path": "/tmp/chain-pq-independent-desktop-20261106-quantum-work-v1/witness-owner-integration-20261106-v1/native-target-original-profile/debug/deps/trnm_checkpoint_store-680c505f2df06e62",
      "profile": {
        "debug_assertions": true,
        "debuginfo": 2,
        "opt_level": "0",
        "overflow_checks": true,
        "test": true
      },
      "sha256": "2452e9c210ca6bf4db0cdbe664816509406821324aaf9c995a02c2fd8e204a4f",
      "target": {
        "crate_types": [
          "lib"
        ],
        "doc": true,
        "doctest": true,
        "edition": "2021",
        "kind": [
          "lib"
        ],
        "name": "trnm_checkpoint_store",
        "src_path": "/tmp/chain-pq-independent-desktop-20261106-quantum-work-v1/witness-owner-integration-20261106-v1/source/trillionnium/crates/trnm-checkpoint-store/src/lib.rs",
        "test": true
      }
    },
    "package_id": "path+file:///tmp/chain-pq-independent-desktop-20261106-quantum-work-v1/witness-owner-integration-20261106-v1/source/trillionnium/crates/trnm-checkpoint-store#0.1.0",
    "passed": 11,
    "raw_banner": "     Running unittests src/lib.rs (/tmp/chain-pq-independent-desktop-20261106-quantum-work-v1/witness-owner-integration-20261106-v1/native-target-original-profile/debug/deps/trnm_checkpoint_store-680c505f2df06e62)",
    "raw_summary": "test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.24s",
    "running": 11,
    "target": {
      "crate_types": [
        "lib"
      ],
      "doc": true,
      "doctest": true,
      "edition": "2021",
      "kind": [
        "lib"
      ],
      "name": "trnm_checkpoint_store",
      "src_path": "/tmp/chain-pq-independent-desktop-20261106-quantum-work-v1/witness-owner-integration-20261106-v1/source/trillionnium/crates/trnm-checkpoint-store/src/lib.rs",
      "test": true
    }
  },
  {
    "failed": 0,
    "filtered_out": 0,
    "ignored": 0,
    "local_elf_body_rehashed": false,
    "measured": 0,
    "named_ok_tests": [
      "node_commit_ledger_v1::tests::abandoned_partial_temp_converges_to_source",
      "node_commit_ledger_v1::tests::coherent_rewritten_prefix_with_higher_head_is_rejected_v1",
      "node_commit_ledger_v1::tests::cold_rollback_below_supplied_expected_source_is_rejected_v1",
      "node_commit_ledger_v1::tests::corrupted_older_record_fences_owner_without_cleanup_v1",
      "node_commit_ledger_v1::tests::durable_successor_reopens_exactly",
      "node_commit_ledger_v1::tests::exact_target_retry_is_read_only_and_does_not_append_v1",
      "node_commit_ledger_v1::tests::expected_context_mismatch_preserves_journal_ahead_and_temp_evidence_v1",
      "node_commit_ledger_v1::tests::journal_ahead_of_head_recovers_to_exact_target",
      "node_commit_ledger_v1::tests::live_coherent_anchor_rewrite_and_head_rollback_are_rejected_v1",
      "node_commit_ledger_v1::tests::live_root_records_lock_and_anchor_replacements_fail_closed_v1",
      "node_commit_ledger_v1::tests::missing_record_and_head_ahead_fail_before_repair_v1",
      "node_commit_ledger_v1::tests::record_and_temp_links_are_rejected_without_deleting_targets_v1",
      "node_commit_ledger_v1::tests::third_state_is_rejected",
      "node_commit_ledger_v1::tests::unknown_root_and_noncanonical_temp_names_are_retained_and_rejected_v1",
      "node_commit_ledger_v1::tests::valid_extension_preserves_the_observed_live_prefix_v1"
    ],
    "original_cargo_elf_identity": {
      "binding": "artifact advertised by this Cargo invocation; hashed immediately afterward",
      "bytes": 10238280,
      "captured_unix_ns": 1793973444377524057,
      "fresh": false,
      "package_id": "path+file:///tmp/chain-pq-independent-desktop-20261106-quantum-work-v1/witness-owner-integration-20261106-v1/source/trillionnium/crates/trnm-checkpoint-store#0.1.0",
      "path": "/tmp/chain-pq-independent-desktop-20261106-quantum-work-v1/witness-owner-integration-20261106-v1/native-target-original-profile/debug/deps/trnm_external_node_checkpoint_v2-d15ad50e2e19d4c1",
      "profile": {
        "debug_assertions": true,
        "debuginfo": 2,
        "opt_level": "0",
        "overflow_checks": true,
        "test": true
      },
      "sha256": "af220e8a7b27aa31e4e7b911bafa380cb658a796bce06f5126623faecfa63403",
      "target": {
        "crate_types": [
          "bin"
        ],
        "doc": true,
        "doctest": false,
        "edition": "2021",
        "kind": [
          "bin"
        ],
        "name": "trnm-external-node-checkpoint-v2",
        "src_path": "/tmp/chain-pq-independent-desktop-20261106-quantum-work-v1/witness-owner-integration-20261106-v1/source/trillionnium/crates/trnm-checkpoint-store/src/main.rs",
        "test": true
      }
    },
    "package_id": "path+file:///tmp/chain-pq-independent-desktop-20261106-quantum-work-v1/witness-owner-integration-20261106-v1/source/trillionnium/crates/trnm-checkpoint-store#0.1.0",
    "passed": 15,
    "raw_banner": "     Running unittests src/main.rs (/tmp/chain-pq-independent-desktop-20261106-quantum-work-v1/witness-owner-integration-20261106-v1/native-target-original-profile/debug/deps/trnm_external_node_checkpoint_v2-d15ad50e2e19d4c1)",
    "raw_summary": "test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.21s",
    "running": 15,
    "target": {
      "crate_types": [
        "bin"
      ],
      "doc": true,
      "doctest": false,
      "edition": "2021",
      "kind": [
        "bin"
      ],
      "name": "trnm-external-node-checkpoint-v2",
      "src_path": "/tmp/chain-pq-independent-desktop-20261106-quantum-work-v1/witness-owner-integration-20261106-v1/source/trillionnium/crates/trnm-checkpoint-store/src/main.rs",
      "test": true
    }
  },
  {
    "failed": 0,
    "filtered_out": 0,
    "ignored": 0,
    "local_elf_body_rehashed": false,
    "measured": 0,
    "named_ok_tests": [
      "cold_recovery_rejects_self_consistent_old_complete_image",
      "export_is_exact_new_domain_and_cannot_overwrite_an_external_pin",
      "external_mismatch_is_rejected_before_stale_local_head_repair",
      "extra_record_is_rejected_before_hash_replay",
      "full_journal_pin_covers_removal_of_another_scope",
      "healthy_existing_journal_reopens_with_exact_external_checkpoint",
      "impossible_external_count_is_rejected_without_replay_or_repair",
      "live_same_inode_head_rollback_is_rejected_without_repair",
      "live_same_inode_rollback_cannot_export_or_extend_cached_history",
      "live_same_length_prefix_edit_cannot_export_a_cached_journal_pin",
      "pinned_reopen_never_reseeds_missing_existing_files",
      "register_new_rejects_existing_even_empty_namespaces",
      "same_count_different_root_is_not_a_fresh_recovery",
      "structural_open_cannot_serve_or_export_a_freshness_claim",
      "structural_reopen_cannot_bypass_recovery_through_direct_owner_methods"
    ],
    "original_cargo_elf_identity": {
      "binding": "artifact advertised by this Cargo invocation; hashed immediately afterward",
      "bytes": 10138376,
      "captured_unix_ns": 1793973444413335931,
      "fresh": false,
      "package_id": "path+file:///tmp/chain-pq-independent-desktop-20261106-quantum-work-v1/witness-owner-integration-20261106-v1/source/trillionnium/crates/trnm-checkpoint-store#0.1.0",
      "path": "/tmp/chain-pq-independent-desktop-20261106-quantum-work-v1/witness-owner-integration-20261106-v1/native-target-original-profile/debug/deps/cold_recovery-97615ddc70ceebe9",
      "profile": {
        "debug_assertions": true,
        "debuginfo": 2,
        "opt_level": "0",
        "overflow_checks": true,
        "test": true
      },
      "sha256": "f9f333dd376403e46958e008036f8295676a94325ec0089d6e65b6b0b53e893f",
      "target": {
        "crate_types": [
          "bin"
        ],
        "doc": false,
        "doctest": false,
        "edition": "2021",
        "kind": [
          "test"
        ],
        "name": "cold_recovery",
        "src_path": "/tmp/chain-pq-independent-desktop-20261106-quantum-work-v1/witness-owner-integration-20261106-v1/source/trillionnium/crates/trnm-checkpoint-store/tests/cold_recovery.rs",
        "test": true
      }
    },
    "package_id": "path+file:///tmp/chain-pq-independent-desktop-20261106-quantum-work-v1/witness-owner-integration-20261106-v1/source/trillionnium/crates/trnm-checkpoint-store#0.1.0",
    "passed": 15,
    "raw_banner": "     Running tests/cold_recovery.rs (/tmp/chain-pq-independent-desktop-20261106-quantum-work-v1/witness-owner-integration-20261106-v1/native-target-original-profile/debug/deps/cold_recovery-97615ddc70ceebe9)",
    "raw_summary": "test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.53s",
    "running": 15,
    "target": {
      "crate_types": [
        "bin"
      ],
      "doc": false,
      "doctest": false,
      "edition": "2021",
      "kind": [
        "test"
      ],
      "name": "cold_recovery",
      "src_path": "/tmp/chain-pq-independent-desktop-20261106-quantum-work-v1/witness-owner-integration-20261106-v1/source/trillionnium/crates/trnm-checkpoint-store/tests/cold_recovery.rs",
      "test": true
    }
  },
  {
    "failed": 0,
    "filtered_out": 0,
    "ignored": 0,
    "local_elf_body_rehashed": false,
    "measured": 0,
    "named_ok_tests": [
      "cli_missing_expected_and_legacy_implicit_start_fail_without_repair",
      "cli_rejects_complete_old_image_before_attempting_transport",
      "cli_second_process_cannot_open_while_the_owner_holds_its_lock",
      "competing_owner_cannot_reopen_or_reregister_a_live_namespace",
      "daemon_cold_restart_requires_external_pin_and_rejects_complete_snapshot_rollback",
      "standalone_daemon_is_cross_process_and_rejects_truncated_log"
    ],
    "original_cargo_elf_identity": {
      "binding": "artifact advertised by this Cargo invocation; hashed immediately afterward",
      "bytes": 10214248,
      "captured_unix_ns": 1793973444318327319,
      "fresh": false,
      "package_id": "path+file:///tmp/chain-pq-independent-desktop-20261106-quantum-work-v1/witness-owner-integration-20261106-v1/source/trillionnium/crates/trnm-checkpoint-store#0.1.0",
      "path": "/tmp/chain-pq-independent-desktop-20261106-quantum-work-v1/witness-owner-integration-20261106-v1/native-target-original-profile/debug/deps/cross_process-7649af5be9b8bb55",
      "profile": {
        "debug_assertions": true,
        "debuginfo": 2,
        "opt_level": "0",
        "overflow_checks": true,
        "test": true
      },
      "sha256": "33108d92a9d61f40fb9d5448102dbf9a10bfc83d8f4e3ae229473d3b3ae12c01",
      "target": {
        "crate_types": [
          "bin"
        ],
        "doc": false,
        "doctest": false,
        "edition": "2021",
        "kind": [
          "test"
        ],
        "name": "cross_process",
        "src_path": "/tmp/chain-pq-independent-desktop-20261106-quantum-work-v1/witness-owner-integration-20261106-v1/source/trillionnium/crates/trnm-checkpoint-store/tests/cross_process.rs",
        "test": true
      }
    },
    "package_id": "path+file:///tmp/chain-pq-independent-desktop-20261106-quantum-work-v1/witness-owner-integration-20261106-v1/source/trillionnium/crates/trnm-checkpoint-store#0.1.0",
    "passed": 6,
    "raw_banner": "     Running tests/cross_process.rs (/tmp/chain-pq-independent-desktop-20261106-quantum-work-v1/witness-owner-integration-20261106-v1/native-target-original-profile/debug/deps/cross_process-7649af5be9b8bb55)",
    "raw_summary": "test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.34s",
    "running": 6,
    "target": {
      "crate_types": [
        "bin"
      ],
      "doc": false,
      "doctest": false,
      "edition": "2021",
      "kind": [
        "test"
      ],
      "name": "cross_process",
      "src_path": "/tmp/chain-pq-independent-desktop-20261106-quantum-work-v1/witness-owner-integration-20261106-v1/source/trillionnium/crates/trnm-checkpoint-store/tests/cross_process.rs",
      "test": true
    }
  }
]
```

严格 Clippy 的原范围是整个 workspace、all-targets、all-features、`-D warnings`：

```json
{
  "argv": [
    "cargo",
    "+1.95.0",
    "clippy",
    "--locked",
    "--manifest-path",
    "trillionnium/Cargo.toml",
    "--workspace",
    "--all-targets",
    "--all-features",
    "--",
    "-D",
    "warnings"
  ],
  "elapsed_seconds": 128.315971997,
  "exit_code": 0,
  "log": {
    "bytes": 7221,
    "member": "quantum-current-c07-terminal-v1/payload/native-witness-release-c07e8b9c-v2/strict-workspace-clippy.log",
    "path": "/workspace/scratch/chain-pq-root-recovery-20261106-v1/quantum-current-c07-terminal-v1/payload/native-witness-release-c07e8b9c-v2/strict-workspace-clippy.log",
    "sha256": "a249c39a1f05009a95cbfa60acbd5f15c415b94089029d06dcca6c931c11bbe0"
  },
  "raw_command_status": "succeeded",
  "receipt": {
    "bytes": 4694,
    "member": "quantum-current-c07-terminal-v1/payload/native-witness-release-c07e8b9c-v2/strict-workspace-clippy.json",
    "path": "/workspace/scratch/chain-pq-root-recovery-20261106-v1/quantum-current-c07-terminal-v1/payload/native-witness-release-c07e8b9c-v2/strict-workspace-clippy.json",
    "sha256": "6ee5646f87e88da5f9df04fe299330b80e6d11585f248782b786280deb9f1438"
  },
  "scope": "workspace/all-targets/all-features -D warnings",
  "status": "PASS"
}
```

原 Rust 1.95.0、OpenSSL 3.5.9 provider、两 build jobs、关闭 incremental、单线程测试、优化/debug/assertion/overflow 设置和每命令 1500 秒上限保持不变。实际源码前后均为 **10,842 tracked entries / 1,090,618,849 bytes**，tree 未变。70 个 native owned process groups 在终态为空；缓存与 source 的另外 30 个组也在封存时检查为空。

12 个当前 ELF（合计 1,356,549,040 B）在独立开发环境留存并由原 owner/封存器按字节复验。文字包保留实际 Cargo-advertised harness、普通 Node executable 与这些摘要记录；审读端没有下载整批 ELF 正文，不能声称在本地再次独立计算了全部 ELF 哈希。

### 本轮唯一原生失败的定位与证明限制

失败测试是 `witness_selected_binary_dispatches_replays_reopens_and_rejects_old_database`。原 Cargo exit 101，**0 passed / 1 failed**，Rust summary 为 4.67 秒。第一个请求已返回 receipt.ok 且 height=0；第 71 行在第二次通过新 TLS 连接发送同一签名请求时，收到 `Connection reset by peer (os error 104)`。

因此，后续 accepted=2、跨进程 reopen 后重放、完整旧 Node 目录恢复后的拒绝断言均尚未到达。不能将该控制的后半段计为通过。它的原单项 reader 与 required-controls 汇总 reader 都 blocked；其余 22 个 Node 定向控制的独立实际通过仍按自身范围保留。

fixture 的服务期限为原 2 秒、send 期限为原 5 秒，witness I/O 为原 250 ms。本次没有延长这些期限，也没有重跑或修改用例以替换失败。总时长与服务期限只提供待检假设，不足以确认根因。原日志没有提供 server 最终指标或 witness 错误码；Node stdout 被 fixture 收入内存后在 panic 的 Drop 路径丢弃，不能从已退出进程补造该记录。

实际独立诊断：

```json
[
  {
    "actual_native_exit_code": 101,
    "actual_test_result": {
      "failed": 1,
      "filtered_out": 4,
      "ignored": 0,
      "passed": 0
    },
    "assertions_not_reached": [
      "Equality of the second response to the first receipt.",
      "Running::finish report and metrics.accepted == 2 for this child.",
      "External witness sequence/root advancement after those two accepted requests.",
      "Replay of the identical receipt after a later real process reopen.",
      "Restoration of the entire closed Node directory and rejection before listener readiness.",
      "External witness checkpoint unchanged after the old-directory refusal."
    ],
    "child_stderr": {
      "additional_server_or_witness_error_line_present": false,
      "disposition": "Inherited into the complete original native log."
    },
    "child_stdout": {
      "disposition": "Collected into an in-memory Vec by the test support thread; panic Drop joins and discards it.",
      "ready_or_final_metrics_raw_bytes_saved_in_this_log": false,
      "separate_persisted_stdout_path_defined_by_fixture": false
    },
    "deadline_hypothesis": "The server bounds a connection by its original two-second service end. Overall timing is compatible with that limit, but the original log does not expose the actual server refusal reason or per-exchange timing.",
    "earlier_assertions_reached": [
      "The create child published the required ready event and ended successfully through Running::finish.",
      "The closed Node snapshot was nonempty; an external witness Current was read.",
      "The open_existing child published ready with witness selected and whole-node/production flags false.",
      "The first send returned a verified receipt with receipt.ok true and height 0."
    ],
    "evidence": [
      {
        "member": "integration-review/tls-audit-recovery-v2/first-witness-failure/tls-witness-cli-00.log",
        "bytes": 133815,
        "sha256": "f7ccec6999a36da0202d0a17438d8a9882621957af0c7b6055fa62bfafdd5c39"
      },
      {
        "member": "integration-review/tls-audit-recovery-v2/first-witness-failure/tls-witness-cli-00.json",
        "bytes": 7488,
        "sha256": "b048ad4c75a521034dde6078c5fe45648706a8ea23bd284fcda6dd6e9aa21dd7"
      }
    ],
    "fixture_directories": "Temporary Node and witness directories are owned by TempDir and ordinarily removed during panic unwinding; no broad filesystem search or reconstruction was performed.",
    "label": "tls-witness-cli-00",
    "later_reopen_or_rollback_claim_qualified_by_this_failed_control": false,
    "limits_or_workload_changed": false,
    "minimal_budget_preserving_implementation_fix_established": false,
    "original_error": {
      "error_code": null,
      "kind": "Transport",
      "message": "IO: Connection reset by peer (os error 104)",
      "os_error": 104
    },
    "original_limits": {
      "child_serve_seconds": 2,
      "each_client_send_seconds": 5,
      "outer_command_seconds": 1500,
      "witness_exchange_milliseconds": 250
    },
    "panic": {
      "column": 14,
      "file": "trillionnium/crates/trnm-pon-node/tests/pq_tls_witness_cli.rs",
      "line": 71
    },
    "root_cause_established": false,
    "server_side_refusal_cause": null,
    "source": "c07e8b9cce4621c5ef6f61256482bfe94e5a622f",
    "stage": "Second fresh TLS send of the same prepared Request::Head to the first open_existing child.",
    "test": "witness_selected_binary_dispatches_replays_reopens_and_rejects_old_database",
    "timings": {
      "command_receipt_elapsed_ns": 6683393539,
      "individual_child_or_exchange_timestamps_recorded": false,
      "libtest_reported_seconds": 4.67
    }
  }
]
```

## 3. 中间失败与并发整合均保留

d6 的原 source20 仍是 **exit 1：16 pass / 4 fail**，232 个 Python 测试通过，native 从未派发。四条原离线图失败分别涉及未缓存的 borsh-derive 1.8.1、缺少 lazy-regex registry 条目和两个 guest 的固定 RustCrypto `244dc3…` checkout。完整 102 原件、20 份 receipt/log/controller、setup、pip 报告及原调度 stdout/stderr 均已有完整读回。早期 partial 的已观察失败状态与身份继续登记；部分控制端派生文件未恢复时，不以新的 full binding 冒称已恢复旧原件。

c07 上单独执行的四条 `cargo fetch --locked` 仅准备依赖缓存，四条成功不等于测试资格。原 manifests、locks、Git revision、offline source commands 和预算没有放宽，d6 的原失败没有被改写。

合成 5bb 的第一次准备被原 `git diff --cached --check` 拒绝：工作流第 173 行含十个空格，job exit 1 / diff guard exit 2，尚未创建该候选或执行 native。resume 只移除这十个空格，并更新已核对三方 union 中对应 workflow pin。三段 inline reader 正文逐字不变；600 pinned blobs / 519 required paths 的 union 保留双方的独立改动。原失败日志、两次 summary 和终态记录均保留。

历史 f85 的 desktop full-Node 原 1500 秒超时、FAILED 进度行及缺失的最终 panic 仍是该源码的观察。同源 GHA 的成功不能改写它。冻结于 2026-11-06 10:19:27 UTC 的 CI snapshot 仍为 73 success / 12 failure / 1 skipped，另有 baseline pending、零 jobs；它不是本次 c07 的 CI 资格。原四秒确认、三轮 campaign、完整 4105-block History 和导出期限失败都保留。

ebd 的命名原生补充仍为 13 pass / 1 fail；44 个观察为 40 success / 1 fail / 3 blocked。认证成本中 67 个样本在原累积 CPU 预算下被拒绝，不等于 67 次错误验签。本轮没有重跑其成本、旧 full-Node 或 campaigns，也没有抬高预算来改变结论。

## 4. 发布、恢复材料与下一资格边界

新 publication 只添加证据、更新当前三件报告和唯一开发计划；直接代码父提交是 c07。publication 本身没有新的 native 执行，精确提交身份及其 source-only 检查在 PR #723 的本轮记录中给出。11 对代码元数据映射保留原 9 对并新增 d6/c07；790 是单列的历史 evidence/plan publication。

原 retained 与 terminal 两包保持原字节，新的 witness/release/recovery 增量见 `witness/publication/archive-index.json`。压缩包自己的 SHA 和包含它的 Git commit SHA 均在外部记录，避免自指。各阶段原命令、原预算、原日志、reader、源码及 ELF 身份、完整失败和 blocked 状态分别绑定。封包哈希验证只证明材料完整性。

控制端临时目录切换没有重新派发正在运行的源或原生批次。稳定工作目录中的恢复件、工具会话保存的实际原响应以及独立开发环境原件，均按各自原 SHA 核对；没有原字节的准备草稿只登记已观察身份。V6 是新 formatter，不伪称重建失联的 V3/V4/V5 方法。其 SHA-256 为 `aa83025245cc110b16f405c25be0a6a6a6709cdb62d71472811fa80ab52ac166`。

后续资格仍包括：真实安装和 Cell 激活效果边界的当前授权；全部生产入口的显式密码 profile；旧账户的可信 PQ 迁移；独立恢复锚点、托管与撤销；私密任务完整传输、长时间 WAN 和恶意成本；PQ 最终性；量子工作、DAA 与分叉经济性。离线恢复根的密码多样性可以单列评估，但这里没有新增 SLH-DSA 恢复根或宣称完成该资格。

关键冻结输入：

- `quantum-current-c07-terminal-v1/payload/manifest.json` — SHA-256 `bfa63c02b548e625c63d0f0c8bcdeba41ed4864212d1863e37bbf38cdaa48763`。
- `quantum-current-c07-terminal-v1/payload/native-witness-release-c07e8b9c-v2/summary.json` — SHA-256 `fddc4dbc5844c329eb7bb267a7abdc3186f2c5993394a0c9ac4eed8c586a977a`。
- `quantum-current-c07-terminal-v1/payload/source-gates-c07e8b9c-v3/summary.json` — SHA-256 `6a9e24b1b3e6ee25a4be0d7ca46f47b5688718cc479ddec97b705eac346611b8`。
- `integration-review/root-c07-whole-terminal-readback-v1/readback.json` — SHA-256 `38c74882df2ea19fb959be00da296675384b812425e1eec581684f03b87951a8`。
- `integration-review/tls-audit-recovery-v2/c07-node-provider-clippy-readback-v1.json` — SHA-256 `fe01d61410cc45a5007a70a3a7b7d800a210a3f4e08c12b47143f6bfe516cfe8`。
- `integration-review/tls-audit-recovery-v2/first-witness-failure/failure-stage-readback.json` — SHA-256 `9ca5f660928125d5f220666a8298c5ac8d782002dfff37ef640357ce6f3f20ea`。
- `integration-review/c07-terminal-reader-recovery-v2/terminal-readback-attempt-v2.json` — SHA-256 `cb026091273729884a30f83d62760cfb5c7e1c6403b71ef817440697053752a1`。
- `integration-review/d6-source20-full-readback-recovery-v1/full-readback.json` — SHA-256 `6b4a90d5db5f050ce7cc7ea175e6191d34b977627c5e33fced1ae9aee69d4b8d`。
- `integration-review/final-mapping-readback-v1/mapping-recovery-readback.json` — SHA-256 `d939a518112c7ce54db73e48c5e261357b786e0aef15bd6f2ce790e7740e3ba1`。

---

# 历史附录：ca4 阶段原 README 全文

以下原文保持 29,821 字节的连续原内容，SHA-256 `ab7e0f2fa2f549e6fdb9371d96d163f4915031b9cc00f5abcc8a1e317d51f326`。其“current/latest/publication parent”和 V1 owner 描述限定于历史阶段，不替代上面的 c07 实际终态。

# PQ integration, actual validation and remaining qualification gates

This report concerns the existing draft [PR #723](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/723).
The latest combined code is `ca4e2fb9160d3e388e131624f7b3350ae4f5d56b`,
tree `ba691b8b5f06a0cfeb062261d6a33f0c086f06b0`. Its ordered parents are
the expiry-accounting candidate `ebd3c06da7d5f2bd136b7a24f24604508d420279`
and the later actual target `513e92dfc27044ef3e0c9d62e7ae504fa5bea38f`.
The target's Python marker compatibility change has been composed with the
strict supported-version policy and tested separately on this exact new source.

**Current conclusion: concrete authorization and validation defects have been
repaired and integrated. Whole-chain PQ, public-WAN operation, quantum-work
economics and production activation remain unqualified.**

The source with the broad validation below remains
`f85fea4e8da02404d513d074ceb35ad5292b017b`, tree
`0c1da9d2c13052b30af600e2a32a5eb286e985de`, integrated with the then-current
target `56897f125df27994efa1dda935f2c62eceb36de9`.
Its actual prospective merge `56ec6d4b9a429968cdb0dfa244c195b4551b7882`
has the same tree. A matching tree does not create a second execution.
The later ebd candidate has tree `367b4cadbf5d9ec0f3e4cfcbb0de4e6fc91a2895`
and f85 as its only parent; its completed native supplement retains its own
failure and source identity. Neither native campaign is relabelled as execution
of the newest combined source. Its changed corpus is an embedded provenance
input, so unchanged Rust bodies do not establish identical native inputs or ELF.

The publication commit containing this report has ca4e2fb9 as its direct code
parent and adds only evidence and plan observations. Its exact published
identity is recorded in the current PR update; this report cannot embed the
hash of its own containing commit. The earlier frozen EBD report and its
source/publication map remain historical archive members, not current claims
about this containing publication.

## 1. What changed and why

### TLS startup now rejects an unusable local identity before creating the owner

Previously the native TLS context checked the ML-DSA certificate/key and direct
CA signature but did not perform the local current-time, role and server-name
checks before opening the Node or announcing readiness. This was a startup and
availability defect. It is not evidence that a remote peer with an invalid
identity completed a successful authenticated session.

The repaired constructor validates against the single pinned CA, uses the
server/client purpose appropriate to the owner, and applies the configured DNS
name to server certificates with wildcards and subject-CN fallback forbidden.
It requires the exact two-certificate chain ending at the pinned CA. Invalid
profiles return `PQ_TLS_LOCAL_CERTIFICATE_PROFILE` before creating the Node or
listening. The client certificate does not acquire a server-name requirement.

The patch retains the existing handshake-time checks, TLS 1.3 hybrid exchange,
ML-DSA mutual identity, outer-TLS/inner-signer binding and original budgets.
The new negative controls cover wrong SAN, CN-only identity, wildcard identity,
expired and future certificates, inappropriate EKU, and root-as-leaf misuse.
The ordinary CLI control checks the refusal message, empty stdout and absence of
the Node directory. The role-specific positive control proves constructor
acceptance; it is not a new independent WAN handshake qualification.

Source:
[local TLS profile validation](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f85fea4e8da02404d513d074ceb35ad5292b017b/trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/context.rs),
[library controls](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f85fea4e8da02404d513d074ceb35ad5292b017b/trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/tests.rs),
[ordinary CLI controls](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f85fea4e8da02404d513d074ceb35ad5292b017b/trillionnium/crates/trnm-pon-node/tests/pq_tls_cli.rs).

### The original authorization fixes are now in the combined candidate

`submit_with_verified_parent_recovery` checks the classical network profile
before classical recovery I/O. This rejects the forbidden combination of a PQ
network owner with a classical recovery credential. It does not implement a new
PQ parent-state recovery protocol.

M15 `check_current` rechecks the expected checkpoint, the recorded time lower
bound, current root and publication expiry, role/content/generation and the live
Cell manifest needed for activation. Its read-only interface does not persist a
new time floor after every successful read. The embedding owner still needs
trusted current time and an independently fresh checkpoint.

The current tree has real ApplicationV6 account registration, rotation, task and
application owners. It must not be described as only a transfer prototype.
Neither those owners nor valid publication signatures supply a missing final-use
installer or activation consumer.

Source:
[parent recovery](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f85fea4e8da02404d513d074ceb35ad5292b017b/trillionnium/crates/trnm-pon-node/src/public_submit.rs),
[current release authority](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f85fea4e8da02404d513d074ceb35ad5292b017b/trillionnium/crates/trnm-release-bundle/src/pq_release.rs),
[full authority map](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f85fea4e8da02404d513d074ceb35ad5292b017b/docs/security/PQ_AUTHORITY_SURFACE_AUDIT_20261031.md).

### Dependency and CI failures were corrected without weakening the gates

Five independent W1 lockfiles had drifted from the current shared crypto graph.
The actual Cargo 1.95 resolutions retain reviewed versions and checksums while
bringing the native-cost, verifier, zkVM host and both guest graphs into agreement.
Their locked graphs contain 69, 193, 306, 191 and 191 packages respectively.
The main workspace and fuzz locks were unchanged. A repaired guest dependency
graph is not a rebuilt guest image or a newly generated proof.

The repository-truth material verifier used
`packaging.Marker.evaluate(context="metadata")` with an environment whose API
did not support that argument. Both truth lanes now install the already reviewed
packaging 26.3 wheel in an isolated verifier environment, with its exact hash,
binary-only policy and install report. The verifier rejects unsupported versions
even for marker-free wheels. Explicit metadata-marker semantics and complete
declared environments remain unchanged. The original hosted packaging version
was not recorded; the controlled 24.2 replay demonstrates the API failure but
does not establish that the original host used 24.2.

The actual full-workspace registry contained 25 postwrite controls while its
reader required 23. The repaired reader selects all 25 and the original nine other
groups, for 60 unique selectors, preserving full compilation, actual ELF
identity, exact nonempty execution, and original time/resource limits. Reader
replay and a historical test log are never treated as a new native execution.

### Concurrent target changes were preserved

The real target advanced while `2e9deaf1` was being checked. Both histories were
merged into the earlier fixed f85 source, preserving both histories.
The combined corpus contains 592 pinned blobs and 511 required paths; the native
source inventory contains 1,269 entries. Complete tracked-source verification
covers 10,748 entries and 1,031,966,791 bytes.

The target adds Cell persistent transport and custody-window preparation,
storage/replay ownership checks and new controls. Pending/Done retain/repair
readback must match the original native context and owner generation before any
mutation. It does not reacquire funding or authorize redispatch of an already
completed effect.

Cell V3 uses ordinary public TCP and the `TCQ3/TCS3` wire contract. Its inventory
is a hint and payload validation remains mandatory; request and payload activity
share the original budgets. This transport does not provide PQ peer identity or
private-task confidentiality.

## 2. How the TLS regression was established

The tests-only source `7957a144312eece4e59837176191eb5dab247f09` was actually
compiled and executed on the independent desktop using Rust 1.95.0 and the
original profiles, two build jobs and single-threaded tests. The library reported
one pass and two failures; the ordinary CLI control reported one failure.
Both Cargo commands returned 101. The wrapper's successful exit means the
expected failures were reproduced, not that the old product behavior passed.

The first wrong-SAN assertion stops the failing CLI control. It would be false
to claim that every later negative was separately observed to fail on the old
code. The complete raw source matched before and after, and the actual
Cargo-advertised library harness, CLI harness and ordinary Node ELF hashes were
recorded. The pinned OpenSSL 3.5.9 provider was built from the exact source archive
using the original preparation script and exercised with real ML-DSA sign/verify
and wrong-message refusal.

Two earlier local builds were killed before tests ran, including a separate
reduced-debug attempt. They remain failed/incomplete observations and supply no
native verdict. The later `2e9deaf1` desktop batch was cancelled when the target
advanced, before any native compilation or test. Its preparation failures,
completed Python controls and cancellation/source readback remain separately
retained.

## 3. Source-specific validation

The following are observed executions. Nested child-test summaries, repeated
exact selectors, Python reader checks, benchmark samples and process-command
observations are separate quantities. An ignored test is counted only when its
exact invocation actually executes it. No grand total across overlapping scopes
is presented.

### Integrated source f85

| Scope | Actual observation | Interpretation |
| --- | --- | --- |
| Local locked dependency/material checks | Five locked/offline graphs; 23 material-verifier tests in isolated packaging 26.3 | Complete source before/after equality; no new guest image or proof |
| Independent desktop full-library attempt | Original 1,500-second ceiling; SIGTERM/exit -15 after 1,502.206865663 seconds; no parent test summary | Incomplete; retain the single paid-pending FAILED progress row without inventing its missing panic |
| GitHub x64/head complete Node library | 1,160 passed, 31 ignored, zero failed; the paid-pending test is explicitly ok in this separate execution | Three nested one-test summaries are not added; this result does not erase or diagnose the desktop observation |
| Independent desktop batch | 271 command/phase observations: 269 succeeded, one library timeout, one dependent readback blocked | These are not 271 unique tests; the overall durable job correctly exits 1 |
| Original native and TLS controls | 52 original exact controls; TLS 13 library / 4 CLI / 1 feature-off, all executed and checked by their original readers | Current-source repaired behavior; exact selectors overlap the complete library |
| Recovery and transaction ownership | Public-submit recovery suite 25 passed; its PQ-owner selector also checked; 13 transaction-scope exact controls passed | A repeated selector remains a subset, not an additional unique protocol case |
| Checkpoint/release/Cell components | Nonempty harnesses: checkpoint 11 / CLI 15 / cold 15 / cross-process 6; release 37; Cell current-authority 5 and one API doctest | Actual current-source component execution; no final-use installer or whole-store rollback qualification |
| New target controls | 26 additional exact executions: 16 Cell-library, 3 Cell-CLI, 7 example controls; original readers passed | The seven example controls are not the full V4 cost campaign |
| Seven new Node target controls | Desktop dependent readback remains blocked; all seven are explicitly ok in the same-source GitHub full-library log | Evidence is attributed to the GitHub execution, not retrofitted into the desktop batch |
| Strict Clippy | Independent desktop: all workspace targets/features, exit 0; GitHub full-PQ job: Node library/tests/all features, exit 0 | Preserve the different command scopes |
| Actual workspace semantic registry | Four architecture/head-or-merge lanes each execute the same 65 named controls: 60 semantics, 4 CPU/exit, 1 growth | All 25 postwrite controls execute; four repeated lanes are not 260 different tests |
| Four original ignored cost controls | History 64 complete calls; authentication 512 samples; root 408 observations; M06 216 timed samples and 1,728 bindings | All four exact controls and original readers pass under original parameters; samples are not test counts or quantum-economic qualification |

The f85 desktop source remains exactly 10,748 tracked entries and 1,031,966,791
bytes before and after the whole batch. Its original provider, profiles,
Cargo-advertised executable identities, process groups and raw logs are retained.
The complete GitHub PQ artifact has 107 original command receipts with matched
source/log/exit records and 310 indexed members. Its text artifact does not
contain Node/M06 ELF bytes, and three cost controls lack individual ELF SHA
receipts. The authentication cost report includes its actual binary SHA. Those
limits are retained rather than described as independent rehashing of all four
executables.

All four CPQ1 architecture/head-or-merge positions also have original source-bound
readback: the same 32 cases, 352 measurement rows and 64 samples per row in each
lane. The exact original reader reproduces the saved output byte for byte, and
the original 25 negative reader controls execute in each lane. These finite
observations do not establish quantum work or fork-economic security.

Four actual independent-C lanes also retain 20 fixed-seed signature comparisons,
391 C and 396 Rust verification observations per lane, including the 210-vector
Wycheproof corpus. Uploaded C executables were rehashed; the Rust oracle identity
comes from its original execution record. Four actual SDK lanes each retain 18
metadata pairs and 66 SDK plus 66 Rust verification observations. Five signatures
valid to the SDK exceed the product scope and are rejected by Rust. These checks
do not establish generic ML-DSA dispatch, a full TUF updater or final-use authority.
The SDK's cryptography/OpenSSL provider is distinct from the Node TLS provider;
its exact-version install report is not installation-time hash enforcement.

### Later expiry-accounting candidate ebd

Independent review found an observation gap: a stage can cross its original
deadline after the reactor's outer scan and refuse at an inner check, while the
generic error owner omits the expiry counters. This finding is separate from the
unresolved desktop FAILED progress row.

The correction preserves the original terminal error, pending closure, generic
errors and connection removal. Only an exact deadline/cookie error observed after
the original connection deadline can add an expiry count. A monotonic stop takes
precedence for deadline errors so a delayed error handler does not recategorize
an earlier shutdown. This is conservative observation, not reconstruction of
every concurrent shutdown/expiry ordering.

The original real-socket test is byte-for-byte unchanged. Four added controls use
real sockets, accepted-connection ownership, the original pending/cookie refusal
functions and actual removal/Drop. They check supported expiry, early shutdown,
EOF and cancellation, exact retained errors, one pending close, released
connection slots, unchanged deadlines and absent body/work effects. The
behavior-preserving helper-extraction red design was not executed; it is neither
an observed failure nor unmodified f85.

On committed ebd, 13 source gates have completed successfully, including 207
Python observations (104 CI-contract, 43 source-integrity, 38 corpus, 22 claim
guard). Every original command recorder verifies all 10,748 tracked entries and
1,031,980,491 bytes before and after. The native supplement completed with durable exit 1: 44 command/check
observations comprise 40 successes, one native failure and three blocked readers.
All ten R4 exact controls (four new and six retained) pass, as do their original
readers. The original History, root-digest and M06 cost controls each execute and
pass; strict Clippy for the whole workspace, all targets and all features also
returns zero. The complete tracked source is identical before and after, and
all owned process groups are reaped. The supplement does not repeat the full
Node library or the campaigns.

The authentication cost control records the native failure: Cargo exit 101,
zero passing and one failing exact test. Its original 512-sample export is
complete, with 67 unexpected outcomes/accounting observations and zero unknown
thread-CPU measurements. The original assertion at
`verifier_cache_tests.rs:437` fails. The original named-test reader and the two
dependent aggregate readers correctly remain blocked.

All 67 refusals occur in the sixteen-key-churn case and report
`PUBLIC_MUTATION_CPU_BUDGET`: 34 cached-arm and 33 original-arm samples.
The first refused sample is cached input 30, immediately after the 61st successful
timed call in that case. Each refused sample records zero additional charged
CPU, zero cache hits and zero key expansions. The other three cases conform to
their original expected outcomes, including the expected invalid signatures.

The unchanged owner has a cumulative two-second authentication thread-CPU budget
per case. Cookie signing, warm-up and both sampled arms share that owner. The
last admitted sample's accounting check rules out unavailable CPU measurement;
the source-bounded attempt and byte totals remain below their separate caps. The observed error and
unchanged control flow therefore identify the cumulative CPU gate as the refusal
point. These are refusals before verification and reservation, not 67 incorrect
cryptographic verification decisions or established product under-accounting.
The original cost acceptance condition remains unmet.

The raw timing rows do not separately export setup/warm-up CPU. Their sums are
not the entire case's accumulated charge. The passing f85 CI execution and this
failed ebd desktop execution differ in source, host and dynamically constructed
cookie/wire inputs, so they do not isolate why measured cost differs. The authentication implementation and the relevant
owner functions are unchanged; no evidence attributes this outcome to the R4
accounting correction. No budget is enlarged, sample removed, or failed run
replaced by a rerun.

### Later marker-contract composition ca4e2fb9

At final publication inspection, the actual target ref had advanced from 56897
to `513e92dfc27044ef3e0c9d62e7ae504fa5bea38f`, while the PR metadata still
reported the old base. The direct ref and exact Git object determine this scope.
The new target changes only the Python marker caller, two tests, their corpus
pins and six historical compatibility-evidence files. Both histories are kept.

The combined caller invokes `Marker.evaluate` once without the optional
`context` keyword. Actual fixed packaging 26.3 and the reviewed official 25.0
implementation default that parameter to `metadata`. The caller still supplies
the complete pinned environment and explicit empty/selected extra; marker
errors propagate without retry. Missing packaging and every version below 25.0
are still refused, including marker-free materials. The isolated 26.3 wheel,
hash enforcement and both CI installation paths are unchanged.

The original 23 and new target's 22 test-method sets have an exact 25-method
union. The effective-context control binds actual call arguments to the real
signature and applies its defaults. It also checks the real empty-extra metadata
behavior and preserves lock-file-only variable refusal. The new legacy-shaped
wrapper is a call-shape control on the supported installed library; it does not
authorize an actual 24.x verifier. The target's preserved historical 24.x success
logs describe that target's earlier contract, not this combined caller.

On this exact committed combined source, all 20 finite recorded commands pass:
207 source/CI/corpus/claim Python tests and 25 actual material-verifier tests,
six locked/offline dependency graphs, formatting, inventory, repository links,
truth and diff checks. The W1 graph sizes remain 69 / 193 / 306 / 191 / 191;
the main workspace graph has 175 packages. All command recorders and the batch
source-before/source-after observations agree on 10,754 tracked entries and
1,031,991,037 bytes. These are 232 Python test observations on this source;
they are not a cross-version total or native test executions.

Rust bodies, Cargo manifests/locks, workflows and native limits are unchanged
from ebd, but three changed corpus pins are compiled through the native source
inventory. No native Rust test, strict native Clippy, guest image or new proof
was executed for ca4e2fb9. The original f85 and ebd native failures, timings and
qualified component scopes therefore remain attached to those original commits.

Source: [combined verifier](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/ca4e2fb9160d3e388e131624f7b3350ae4f5d56b/scripts/llm_runtime_release.py)
and [25-method controls](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/ca4e2fb9160d3e388e131624f7b3350ae4f5d56b/scripts/test_llm_runtime_release.py).
The exact recipe, raw logs, source identities, official-library readbacks and
independent reviews are retained in the terminal evidence increment.

### Business and operational gates remain unaccepted

The original four-second, six-depth service confirmation gate still refuses the
f85 source under its original worker and Host limits. A named native test
or process exit can pass while its independent confirmation reader correctly
rejects `CONFIRMATION_TARGET`; those are separate observations.

The original three-attempt, thirty-second native campaign also fails after a
successful release build. Each baseline confirms only one of three rounds; all
six pressure stages confirm zero of three and accept only seven of the required
21 work items. Final receiver/client states disagree. Accounting is available and
balance identity holds, but genuine paid-budget depletion is not observed in the
pressure stages. No actor cap/forced kill or outer startup timeout explains these
results.

The exact errors differ. The first two attempts and the third baseline reach
client History import and report `PUBLIC_REQUEST_DEADLINE`. The third attempt's
from-zero pressure ends at the challenge with `FRAME_DEADLINE`; its late-product
pressure ends at solution/body/response with `FRAME_DEADLINE`. Those two records
have no client-import entry. Missing import evidence is not successful import.
No supported, semantics-preserving small performance repair follows from these
reports alone. All original deadlines, workers and CPU/memory limits remain.

The original 4,105-block History control uses the classical public_v2 owner and
fails in all four architecture and head-or-merge positions. Both x64 servers reach their original 1,800-second
lifetime, after 3,325 and 2,799 completed returns respectively; the next History
request sees connection refusal. Both ARM runs record 4,104 successful import returns and receive a last-page
reply with `advertised_complete=true`, but the original import call reaches
its deadline with `PUBLIC_REQUEST_DEADLINE`. A final advertised page is not a
successfully confirmed client state. These are failures inside the original
control, not an outer command timeout. Their original host reports have no
recorded errors or OOM event; the 25%-CPU and 2-GiB configuration is unchanged.
No evidence attributes these four failures to the TLS constructor repair or the
later R4 accounting change.

The f85 CodeQL export also misses its observation deadline with empty
analysis/check collections. That is incomplete export evidence, not a reported
code finding and not a successful security scan. The final CI snapshot records
its timestamp and every unfinished or failed check explicitly.

At the frozen 2026-11-06 10:19:27 UTC cutoff, metadata shows 73 successful,
12 failed and one skipped check; workflow runs show ten successful, four failed
and one pending. The repository-truth baseline remains pending with zero jobs.
Its two CI lanes therefore provide no execution qualification for the packaging
fix, even though the separately source-bound local 23-test verifier run passed.
The readback covers 31 original jobs, 34 fully indexed artifacts (23,014 members)
and 4,319 losslessly retained text members. It verifies the full x64/head PQ
artifact; the other three full-PQ job successes are metadata only for their later
whole-library and cost phases. Earlier inspected stages remain explicitly partial.

## 4. Authority boundaries that remain open

| Surface | What exists at the tested source | Remaining acceptance condition |
| --- | --- | --- |
| Accounts and application authorization | Native pinned ML-DSA account/application owners, generations and nonce checks under explicit profiles | Complete legacy migration with prior PQ commitments and all production entrypoints bound to the intended profile |
| Parent recovery | Classical network-profile refusal before recovery work | A complete PQ parent-state recovery protocol and owner path |
| Node identity and private transport | Explicit loopback hybrid TLS with ML-DSA mutual identity and signer binding | Actual private listeners/clients, deployed certificate custody and revocation, malicious-handshake costs and sustained WAN qualification |
| Software/configuration release | M15 role quorums, root rotation, current-check kernel and bundle checks | A real final-use product consumer, atomic effect binding and a current independent checkpoint/time source |
| Cell release and activation | CPR2 current publisher checks, M15 manifest/activation rules and real Cell acquisition | Installation/CURRENT selection/activation boundary invoking current authorization; acquisition alone is insufficient |
| Recovery and rollback | Durable PNQ2 witness component and transactional current/CAS checks | Ordinary CLI witness wiring, protected independent custody and a domain that actually covers the stores being claimed |
| Finality | Nonactivating Ed25519 reference and read-only native certificate observation | A specified, implemented, tested PQ finality path and its real activation rules |
| PoN work and chain selection | Native work relation, finite strategy measurements and quantum/DAA research | Cheapest legal quantum work, reversible computation/data-access costs, difficulty and adversarial fork economics |

The PNQ2 witness protects exactly the resource, peer and request tables included
in its root. It does not cover account state, blocks, History, CURRENT or Hepta.
The M03 checkpoint daemon uses a different domain, root and wire contract.
Neither service can be substituted for the other. Restoring a local journal,
head and adjacent checkpoint file from one old snapshot cannot prove freshness.

The ordinary `pq-tls-serve` CLI still uses `open_with_pq_network` without an
independent witness. The library's ability to carry a witness-backed Node is a
component capability, not deployed CLI wiring or exclusive writer/recovery
qualification.

No statement in this report promotes classical-plus-PQ OR authentication, an
old valid signature, same-disk rollback metadata, a finite benchmark or a saved
proof to current production authorization.

## 5. Evidence and reproducibility

The frozen retained-history package contains 1,844 original files in 1,848 archive
members. Ten parts reconstruct the 14,283,750-byte zstd archive, SHA-256
`78142ab292525bcd911029ee07177bbad1630d74b512c0152125afbf0f89ab0f`.
It preserves the old failures and their original source identities. Its successful
verification means archive integrity and coverage; it is not a native-test verdict.

[Retained archive guide](retained/publication/README.md) and
[member/part index](retained/publication/archive-index.json) provide the exact
transport and review instructions. The terminal increment is separate so the
earlier snapshot is not silently rewritten into a successful final result.
The [terminal archive guide](terminal/publication/README.md) and
[terminal member/part index](terminal/publication/archive-index.json) preserve the
actual f85 and ebd outcomes, the later ca4e2fb9 Python/source gates, the fixed
CI cutoff, original failures, raw cost exports and independent readbacks. The separate index records its transport
hashes; this report is itself an archived member and does not embed a circular
hash of its containing archive.

The [source and publication map](source-publication-map.json) records all nine
local/server code-commit pairs and their independently checked identical trees. It
does not transfer executions between those commits. Documentation/archive-only
publication changes do not manufacture native results for the containing commit.
The [machine-readable disposition](qualification.json) keeps each pass, failure,
timeout and incomplete gate attached to its actual source and scope.

## 6. Disposition

The PR remains a reviewable draft. Original service deadlines, CPU and memory
quotas, worker counts, anti-downgrade rules, source-integrity checks and failed
observations remain intact. No protected-main merge or production activation is
performed as part of this continuation.

