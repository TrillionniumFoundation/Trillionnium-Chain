# M01 Strict identity and exact neural-work verification

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Actual strict native signatures and unchanged experimental transcript verification.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M01.VerifyWork

Check length/magic/field bounds; recompute TaskId; apply cheap ticket filter; replay challenge-noised tiled transcript and exact decoded product; return no verified type on any mismatch.

**Atomic/commit boundary:** No authoritative store; cache key must include complete context.

### M01.VerifyTransactionSignature

Strict Ed25519 over H(tx-sign,unsigned). Reject weak/malformed keys or mismatching signatures before copying mutations into a committed state. Signed scores remain attestations, not work.

**Atomic/commit boundary:** No key material copied from fixtures into deployment.

## M01.VerificationAuthority

**Invariant:** Bad signatures reject the whole block without mutating parent state; altered work output or context never yields verified work. Both verification languages reject small-order public keys/R, noncanonical points and scalars outside the group-order bound.

**Scope:** Actual strict native signatures and unchanged experimental transcript verification.

**Atomic boundary:** Signature verification precedes speculative patches; only full transcript verification creates work authority.

**Failure schedule:** Bad signature at every worker count; Changed transcript, product and challenge; Small-order sender with R identity and zero scalar; Noncanonical point or S plus group order; Weak quota consumer identity.

**Expected result:** Bad signatures reject the whole block without mutating parent state; altered work output or context never yields verified work. Both verification languages reject small-order public keys/R, noncanonical points and scalars outside the group-order bound.

**Resource and retention rule:** 49188-byte work certificate; failed proof still requires substantial computation.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_bad_signature_rejects_entire_block_without_parent_mutation`

`formal/pon-nakamoto-v1/test_interop.py::InteropTests.test_native_rejects_changed_context_and_output`

`formal/pon-nakamoto-v1/test_work_backend.py::NativeWorkBridgeTests.test_proof_bytes_and_verified_product_equal_oracle`

`formal/pon-nakamoto-v1/test_work_backend.py::NativeWorkBridgeTests.test_wrong_statement_and_bad_trace_reject_without_fallback`

`formal/pon-nakamoto-v1/test_strict_signature.py::StrictSignatureTests.test_native_and_reference_reject_weak_sender_without_state_change`

`formal/pon-nakamoto-v1/test_strict_signature.py::StrictSignatureTests.test_weak_consumer_cannot_authorize_quota`

`formal/pon-nakamoto-v1/test_strict_signature.py::StrictSignatureTests.test_rfc8032_known_vector`

`formal/pon-nakamoto-v1/test_strict_signature.py::StrictSignatureTests.test_all_declared_order_eight_points_reject`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Cheap forgery amplification, structured-input shortcuts, hardware advantage and weak-key disagreement.

The native work bridge and structured-input costs are executable; fastest-adversary cost, public proof admission and independent work security are still unqualified.

## Current source and verification

- [`trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs`](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs).
- [`trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs`](../../trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs).
- [`formal/pon-nakamoto-v1/work_backend.py`](../../formal/pon-nakamoto-v1/work_backend.py).
- [`trillionnium/crates/trnm-crypto-primitives/examples/pon_work_io.rs`](../../trillionnium/crates/trnm-crypto-primitives/examples/pon_work_io.rs).
- [`formal/pon-nakamoto-v1/strict_signature.py`](../../formal/pon-nakamoto-v1/strict_signature.py).
- [`trillionnium/crates/trnm-crypto-primitives/src/lib.rs`](../../trillionnium/crates/trnm-crypto-primitives/src/lib.rs).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.

## Executed evidence and scope

[Responsibility-level evidence navigation](README.md#responsibility-and-evidence) reads
measured commits from immutable receipts. The module's entries in
[module-maturity-v1.json](../../config/pon/module-maturity-v1.json) identify actual callable
owners, controlled entrypoints, backends, persistence and exact observed test selectors.
Run `python3 scripts/ci/report_module_evidence.py --module M01` from the repository
root to see subject-byte and complete recorded-runtime matches separately, plus scenarios
not observed in each package. A byte match is not a new test run or product acceptance.
Historical v1/v3/v4 results are never repinned. The sole plan selects further work.

## Block-scoped execution continuation

The existing native executor now bounds thread creation per block and preserves a private
verified main envelope across canonical state replay. This is a computational fact, not
work validity or local permission. Capacity/range state transitions remain ordered and
consumer signatures still bind actual quota state. See the exact algorithm, errors and
counterexamples in [EXECUTION_PARALLEL](../protocol/pon-nakamoto-v1/details/EXECUTION_PARALLEL.md).
Complete-state root construction, full native node assembly and Hepta ownership remain
separate work; worker counts do not establish throughput or independent acceptance.

## Native cache / receiver continuation

The exact continuation is specified in [native execution](../protocol/pon-nakamoto-v1/details/EXECUTION_PARALLEL.md), [admission](../protocol/pon-nakamoto-v1/details/ADMISSION_SECURITY.md) and [client/recovery](../protocol/pon-nakamoto-v1/details/NETWORK_CLIENT.md). It does not promote native persistence, independent acceptance or public-network capacity. Exact additional counterexamples:

- `formal/pon-nakamoto-v1/test_work_precheck.py::WorkPrecheckTests.test_bad_field_and_task_reject_before_state_replay_or_full_verification`.
- `formal/pon-nakamoto-v1/test_work_precheck.py::WorkPrecheckTests.test_forged_passing_ticket_does_not_become_verified_work`.

## Current work-cost applicability

[Native-session-source cost observations](../../evidence/pon-native-session-v1/work-cost/README.md)
carry their own measured commit, binary, source inventory and same-target samples.
The old cost package remains historical. Neither collection establishes a fastest-
adversary lower bound, public admission fairness or independent work qualification.

## Native development continuation and remaining scope

PreparedTask is now a valid producer-side fixed-task optimization, not a new work relation or verified capability. The original full verification relation remains unchanged. Paired cost measurements distinguish setup, search, narrower targets, slower samples and the still-open invalid-proof admission problem.

The current callable mappings remain in `config/pon/module-maturity-v1.json`.
Exact native entry, storage and work behavior is specified by N3 in NETWORK_CLIENT,
the native continuation in STATE_RECOVERY and the prepared-producer section in WORK_PROFILE.
No historical receipt is relabelled as executing this source.

## Exact optimized verifier and structural producer comparison

The ordinary native verifier now uses the same complete W1 relation with transposed arithmetic and tile-batched hashing. The explicit scalar verifier, retained Python oracle, error/progress equivalence and real structural producer comparisons are specified in [W1 implementation comparison](../protocol/pon-nakamoto-v1/details/W1_IMPLEMENTATION_COMPARISON.md). This changes verification cost without reducing the proof relation or granting a work-cost lower bound.


## 本轮来源绑定（Round 10）

本节补充 `M01.VerificationAuthority` 的当前来源绑定。`BlockedZeroPairedPreparedTask`
仅接受完整、规范的双零材料，以分块重结合和整数配对生成全部原有 W1 transcript、
证明字节和 ticket；不支持的材料明确拒绝，不授予当前父分支、签发方、租约或验证权限。
独立标量／Python 比较、极值前缀和真实取消点分别约束字节等价与失败行为，具体关系见
[W1 实现比较](../protocol/pon-nakamoto-v1/details/W1_IMPLEMENTATION_COMPARISON.md)。

五种完整 zero producer 的 cold／reused 成本关系必须保留 setup、全部失败尝试和相同
target 下的完整证明流。源码中的优化结构不声明实测优势、最低生成成本、W1 硬度或
公开入口拒绝成本；默认验证关系与已有 profile 含义保持不变。以下仅登记真实测试定义，
执行结论仍须由相同精确源码的实际日志建立，`independent_accepted=false`。

对应完整回归 selector：

- `trillionnium/crates/trnm-crypto-primitives/src/pon_work/blocked_zero_paired.rs::complete_canonical_zero_detection_never_substitutes_another_material`.
- `trillionnium/crates/trnm-crypto-primitives/src/pon_work/blocked_zero_paired.rs::full_proof_and_ticket_match_scalar_generic_zero_and_paired_across_reuse`.
- `trillionnium/crates/trnm-crypto-primitives/src/pon_work/blocked_zero_paired.rs::every_extreme_prefix_word_matches_the_original_scalar_relation`.
- `trillionnium/crates/trnm-crypto-primitives/src/pon_work/blocked_zero_paired.rs::actual_checkpoint_order_cancels_without_retaining_challenge_state`.
- `formal/pon-nakamoto-v1/test_zero_work.py::ZeroWorkOracleTests.test_all_five_complete_zero_producers_match_original_python_bytes`.
- `formal/pon-nakamoto-v1/test_zero_work.py::ZeroWorkOracleTests.test_general_controls_are_actually_supported_by_generic_and_paired`.
- `formal/pon-nakamoto-v1/test_zero_work.py::ZeroWorkOracleTests.test_zero_only_operations_refuse_complete_canonical_nonzero_material`.
- `formal/pon-nakamoto-v1/test_zero_work.py::ZeroWorkOracleTests.test_all_operations_check_complete_extent_canonical_fields_and_arguments`.
- `formal/pon-nakamoto-v1/test_zero_work.py::ZeroWorkOracleTests.test_missing_and_unknown_operations_are_errors_with_empty_stdout`.
